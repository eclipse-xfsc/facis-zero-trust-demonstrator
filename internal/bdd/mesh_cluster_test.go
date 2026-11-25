package bdd

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// The mesh rows (ZT-23, ZT-25, ZT-61, ZT-62, ZT-26) against an installed participant zone. Four of them are
// decided from one run of the plane-separation verifier (scripts/verify-plane-separation/verify.sh), whose
// ALLOW rows probe every data -> management lane with the legitimate caller (served over mutual TLS and
// counted by its proxy), an impostor (the row's labels under another identity: 403 RBAC and a denial line
// naming both SPIFFE IDs) and an unlabelled caller (dropped by the network policy, Hubble's drop cited), and
// whose DENY rows send plain text without an identity to meshed pods behind a probe-scoped opening (reset
// under mutual TLS STRICT). ZT-25 adds the address check (scripts/ci/check-policy-addresses.sh) over the
// zone file's render and over the live policies of the zone's plane namespaces. ZT-26 runs the Connector
// routing proof (scripts/verify-connector-routing/verify.sh) in the role the zone holds.
//
//	KUBECONFIG, KUBE_CONTEXT, ZTD_CONFIRM_CLUSTER   the zone, as for ZT-55
//	BDD_ZONE_FILE                                   the zone file the zone was installed with
//	BDD_TARGET, BDD_RUN_ID                          name the target and the run in the evidence
//	ROLE and the other inputs of verify-connector-routing (its README)   ZT-26 only, passed through
//
// The verifier's record goes to bundles/bdd/evidence/bdd-mesh/<target>/<run>/plane-separation (git-ignored)
// and each row writes its decision to bundles/bdd/evidence/bdd-zt-0xx/<target>/<run>/decision.txt.
// In the cluster dry run every step is skipped.

// planeRuns holds the plane-separation run of this test process per target and run id: the four rows read
// one record rather than probing the zone four times. godog runs scenarios one at a time.
var planeRuns = map[string]*planeRun{}

type planeRun struct {
	dir    string
	exit   int
	output string
}

// planeLine is one line of the verifier's matrix.csv, with the columns a mesh row decides on.
type planeLine struct{ row, namespace, probe, layer, evidence, verdict string }

func readPlaneLines(r io.Reader) ([]planeLine, error) {
	records, err := csv.NewReader(r).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("matrix.csv: %w", err)
	}
	if len(records) == 0 || strings.Join(records[0], ",") != strings.Join(planeMatrixColumns, ",") {
		return nil, errors.New("matrix.csv: the header is not the verifier's")
	}
	lines := make([]planeLine, 0, len(records)-1)
	for _, rec := range records[1:] {
		lines = append(lines, planeLine{row: rec[0], namespace: rec[2], probe: rec[3], layer: rec[9], evidence: rec[10], verdict: rec[12]})
	}
	return lines, nil
}

var (
	countedOverMTLS = regexp.MustCompile(`counted [1-9][0-9]* request\(s\) to destination_principal spiffe://`)
	denialBothIDs   = regexp.MustCompile(`"destination":"spiffe://[^"]+".*rbac_access_denied.*"source":"spiffe://[^"]+"`)
)

// meshCheck is one class of probe a row requires: at least one line matches, and every matching line passed
// on its layer with its evidence.
type meshCheck struct {
	what     string
	match    func(planeLine) bool
	layer    string
	evidence []string // every one must be in the line's evidence
	pattern  *regexp.Regexp
}

func probeIs(prefix string) func(planeLine) bool {
	return func(l planeLine) bool { return strings.HasPrefix(l.probe, prefix) && l.verdict != "n/a" }
}

var (
	legitimateCaller = meshCheck{what: "the legitimate caller is served over mutual TLS, counted by its proxy to the destination's SPIFFE ID",
		match: probeIs("legitimate caller"), layer: "control channel", pattern: countedOverMTLS}
	impostorRefused = meshCheck{what: "the impostor (the row's labels, another identity) is refused by the destination's proxy with a denial line naming both SPIFFE IDs",
		match: probeIs("impostor ("), layer: "mesh", pattern: denialBothIDs}
	unlabelledDropped = meshCheck{what: "the unlabelled caller is dropped by the default-deny network policy, Hubble's policy drop cited",
		match: probeIs("unlabelled ("), layer: "network", evidence: []string{"Hubble drop:", "Policy denied DROPPED"}}
	proxyLessDropped = meshCheck{what: "a proxy-less pod's connection to a management-plane or data-plane endpoint is dropped by the network policy",
		match: probeIs("TCP, proxy-less"), layer: "network"}
	plainTextReset = meshCheck{what: "plain text without an identity, let through by the network, is reset by the destination's proxy under mutual TLS STRICT",
		match: probeIs("plain text, no identity"), layer: "mesh", evidence: []string{"FORWARDED", "mutual TLS mode in force: STRICT"}}
)

// decideMesh applies the checks to the matrix: each yields one report line; any check that matches no line,
// or a matching line that failed, is on another layer or lacks its evidence, fails the decision.
func decideMesh(lines []planeLine, checks ...meshCheck) ([]string, error) {
	var report, problems []string
	for _, c := range checks {
		n := 0
		for _, l := range lines {
			if !c.match(l) {
				continue
			}
			n++
			bad := l.verdict != "pass" || l.layer != c.layer || (c.pattern != nil && !c.pattern.MatchString(l.evidence))
			for _, e := range c.evidence {
				bad = bad || !strings.Contains(l.evidence, e)
			}
			if bad {
				problems = append(problems, fmt.Sprintf("%s from %s, %s: %s on layer %s (%s)", l.row, l.namespace, l.probe, l.verdict, l.layer, l.evidence))
			}
		}
		report = append(report, fmt.Sprintf("%s: %d line(s)", c.what, n))
		if n == 0 {
			problems = append(problems, "no line: "+c.what)
		}
	}
	if len(problems) > 0 {
		return report, errors.New(strings.Join(problems, "; "))
	}
	return report, nil
}

// impostorRows are the ALLOW rows that have an impostor: ZT-62 needs a target with one permitted and one
// non-permitted identity, which the export row (every identity admitted) does not give.
func impostorRows(lines []planeLine) map[string]bool {
	rows := map[string]bool{}
	for _, l := range lines {
		if impostorRefused.match(l) {
			rows[l.row] = true
		}
	}
	return rows
}

// keepRows keeps the lines of the rows keep selects; a nil keep keeps every line.
func keepRows(lines []planeLine, keep func([]planeLine) map[string]bool) []planeLine {
	if keep == nil {
		return lines
	}
	rows := keep(lines)
	kept := lines[:0:0]
	for _, l := range lines {
		if rows[l.row] {
			kept = append(kept, l)
		}
	}
	return kept
}

type meshProof struct {
	dryRun   bool
	zoneFile string
	target   string
	run      string
	plane    *planeRun
	routing  string // the Connector routing proof's run directory
	rExit    int
	rOutput  string
}

func (m *meshProof) zoneIsMeshed(ctx context.Context) error {
	if m.dryRun {
		return godog.ErrSkip
	}
	for _, name := range []string{"KUBECONFIG", "BDD_ZONE_FILE", "BDD_TARGET", "BDD_RUN_ID"} {
		if os.Getenv(name) == "" {
			return fmt.Errorf("the mesh proof needs %s", name)
		}
	}
	m.zoneFile = os.Getenv("BDD_ZONE_FILE")
	if _, err := os.Stat(m.zoneFile); err != nil {
		return fmt.Errorf("BDD_ZONE_FILE: %w", err)
	}
	safe := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	m.target = safe.ReplaceAllString(os.Getenv("BDD_TARGET"), "-")
	m.run = safe.ReplaceAllString(os.Getenv("BDD_RUN_ID"), "-")
	// The mesh is installed: istiod available, the zone's mesh default deny in place, the data plane injected.
	for _, read := range [][]string{
		{"-n", "istio-system", "get", "deploy", "istiod", "-o", "jsonpath={.status.availableReplicas}"},
		{"-n", "istio-system", "get", "authorizationpolicy", "default-deny", "-o", "name"},
		{"get", "ns", "-l", "ztd.facis.io/plane=data,istio-injection=enabled", "-o", "name"},
	} {
		out, err := m.kubectl(ctx, read...)
		if err != nil || strings.TrimSpace(out) == "" || strings.TrimSpace(out) == "0" {
			return fmt.Errorf("the zone's mesh is not installed (kubectl %s): %s", strings.Join(read, " "), strings.TrimSpace(out))
		}
	}
	return nil
}

func (m *meshProof) kubectl(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "kubectl", append([]string{"--context", envOr("KUBE_CONTEXT", "kind-ztd")}, args...)...).CombinedOutput()
	return string(out), err
}

// planeSeparationRuns runs the verifier once per target and run id in this process.
func (m *meshProof) planeSeparationRuns(ctx context.Context) error {
	if m.dryRun {
		return godog.ErrSkip
	}
	key := m.target + "/" + m.run
	if run, ok := planeRuns[key]; ok {
		m.plane = run
		return nil
	}
	run := &planeRun{dir: repoPath(filepath.Join("bundles/bdd/evidence/bdd-mesh", m.target, m.run, "plane-separation"))}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, repoPath("scripts/verify-plane-separation/verify.sh"))
	cmd.Env = append(os.Environ(), "ZTD_EVIDENCE_DIR="+run.dir, "ZONE_VALUES="+m.zoneFile)
	out, err := cmd.CombinedOutput()
	run.output = string(out)
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		run.exit = exitErr.ExitCode()
	} else if err != nil {
		return fmt.Errorf("the plane-separation verifier did not run: %w", err)
	}
	if run.exit == 125 {
		return fmt.Errorf("the plane-separation verifier refused to run: %s", lastLines(run.output, 3))
	}
	planeRuns[key] = run
	m.plane = run
	return nil
}

// decidePlane decides a row from the run's matrix.csv with the given checks, restricted to the rows keep
// selects (nil: every row), and writes the decision beside the row's evidence.
func (m *meshProof) decidePlane(rowID string, keep func([]planeLine) map[string]bool, extra []string, checks ...meshCheck) error {
	if m.dryRun {
		return godog.ErrSkip
	}
	f, err := os.Open(filepath.Join(m.plane.dir, "matrix.csv"))
	if err != nil {
		return fmt.Errorf("the verifier wrote no matrix (exit %d): %w; %s", m.plane.exit, err, lastLines(m.plane.output, 3))
	}
	defer func() { _ = f.Close() }()
	lines, err := readPlaneLines(f)
	if err != nil {
		return err
	}
	report, err := decideMesh(keepRows(lines, keep), checks...)
	if err == nil && m.plane.exit != 0 {
		err = fmt.Errorf("%d check(s) of the verifier's run failed", m.plane.exit)
	}
	return m.writeDecision(rowID, append(append(report, extra...), "plane-separation record: "+m.plane.dir), err)
}

func (m *meshProof) writeDecision(rowID string, report []string, decided error) error {
	dir := repoPath(filepath.Join("bundles/bdd/evidence", "bdd-"+strings.ToLower(rowID), m.target, m.run))
	verdict := "PASS"
	if decided != nil {
		verdict = "FAIL: " + decided.Error()
	}
	body := strings.Join(append([]string{rowID + " on " + m.target + ", run " + m.run}, append(report, verdict)...), "\n") + "\n"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "decision.txt"), []byte(body), 0o644); err != nil {
		return err
	}
	fmt.Print(body)
	if decided != nil {
		return fmt.Errorf("%s: %w; decision %s", rowID, decided, dir)
	}
	return nil
}

// noAddressInPolicies is ZT-25's "without relying on IP-address identity": the address check over the zone
// file's render, and over every NetworkPolicy, CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy and
// AuthorizationPolicy the zone holds in its plane namespaces (ztd.facis.io/plane) or cluster-wide. The
// Connector's two declared edge hops are reported EDGE by the check, not failed.
func (m *meshProof) noAddressInPolicies(ctx context.Context) ([]string, error) {
	script := repoPath("scripts/ci/check-policy-addresses.sh")
	rendered, err := exec.CommandContext(ctx, "bash", script, m.zoneFile).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("the address check of %s failed: %s", m.zoneFile, lastLines(string(rendered), 5))
	}
	planes, err := m.kubectl(ctx, "get", "ns", "-l", "ztd.facis.io/plane", "-o", "jsonpath={.items[*].metadata.name}")
	if err != nil || strings.TrimSpace(planes) == "" {
		return nil, fmt.Errorf("no plane namespace: %s", planes)
	}
	in := map[string]bool{"": true}
	for _, ns := range strings.Fields(planes) {
		in[ns] = true
	}
	raw, err := m.kubectl(ctx, "get", "networkpolicies,ciliumnetworkpolicies,ciliumclusterwidenetworkpolicies,authorizationpolicies", "-A", "-o", "json")
	if err != nil {
		return nil, fmt.Errorf("reading the live policies: %s", lastLines(raw, 3))
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		return nil, err
	}
	dir := repoPath(filepath.Join("bundles/bdd/evidence/bdd-zt-025", m.target, m.run))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	// The policies a connector-gateway release owns (Helm's release annotations, the release's chart
	// from helm list) are checked as that chart's render, where the check declares its two edge hops
	// in their exact shape; every other live policy is checked strictly.
	gateways, err := m.gatewayReleases(ctx)
	if err != nil {
		return nil, err
	}
	var plane, gateway []map[string]any
	for _, item := range list.Items {
		meta, _ := item["metadata"].(map[string]any)
		ns, _ := meta["namespace"].(string)
		if !in[ns] {
			continue
		}
		delete(meta, "managedFields")
		delete(item, "status")
		ann, _ := meta["annotations"].(map[string]any)
		rel, _ := ann["meta.helm.sh/release-name"].(string)
		relNS, _ := ann["meta.helm.sh/release-namespace"].(string)
		if gateways[relNS+"/"+rel] {
			gateway = append(gateway, item)
		} else {
			plane = append(plane, item)
		}
	}
	results := []string{"address check of the zone file's render: " + lastLines(string(rendered), 1)}
	for _, set := range []struct {
		name, mode string
		items      []map[string]any
	}{{"live-policies.yaml", "--manifest", plane}, {"live-gateway-policies.yaml", "--edge-manifest", gateway}} {
		if len(set.items) == 0 {
			continue
		}
		path := filepath.Join(dir, set.name)
		if err := writeManifest(path, set.items); err != nil {
			return nil, err
		}
		live, err := exec.CommandContext(ctx, "bash", script, set.mode, "live-"+m.target, path).CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("the address check of %s failed: %s", set.name, lastLines(proofMask(string(live)), 10))
		}
		results = append(results, fmt.Sprintf("address check of %d live policies (%s, %s): %s", len(set.items), set.name, set.mode,
			strings.ReplaceAll(proofMask(strings.TrimSpace(string(live))), "\n", "; ")))
	}
	return results, nil
}

// gatewayReleases is the set of namespace/release of the connector-gateway releases on the target.
func (m *meshProof) gatewayReleases(ctx context.Context) (map[string]bool, error) {
	out, err := exec.CommandContext(ctx, "helm", "--kube-context", envOr("KUBE_CONTEXT", "kind-ztd"), "list", "-A", "-o", "json").Output()
	if err != nil {
		return nil, fmt.Errorf("listing the Helm releases: %w", err)
	}
	var rels []struct{ Name, Namespace, Chart string }
	if err := json.Unmarshal(out, &rels); err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, r := range rels {
		if strings.HasPrefix(r.Chart, "connector-gateway-") {
			set[r.Namespace+"/"+r.Name] = true
		}
	}
	return set, nil
}

// writeManifest writes items as a multi-document YAML file (JSON documents are YAML).
func writeManifest(path string, items []map[string]any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, item := range items {
		doc, _ := json.Marshal(item)
		if _, err := fmt.Fprintf(w, "---\n%s\n", doc); err != nil {
			return errors.Join(err, f.Close())
		}
	}
	return errors.Join(w.Flush(), f.Close())
}

var ipv4 = regexp.MustCompile(`\b[0-9]{1,3}(\.[0-9]{1,3}){3}\b`)

// proofMask writes every IPv4 address of a participant cluster's output as <address>, as the proofs do.
func proofMask(s string) string { return ipv4.ReplaceAllString(s, "<address>") }

func (m *meshProof) unaffiliatedBlockedWithoutAddresses(ctx context.Context) error {
	if m.dryRun {
		return godog.ErrSkip
	}
	addresses, err := m.noAddressInPolicies(ctx)
	if err != nil {
		return m.writeDecision("ZT-25", addresses, err)
	}
	return m.decidePlane("ZT-25", nil, addresses, legitimateCaller, impostorRefused, unlabelledDropped, proxyLessDropped)
}

// connectorRoutingRuns runs the ZT-26 proof in the role the zone holds (ROLE and its inputs from the
// environment, as its README gives them per zone).
func (m *meshProof) connectorRoutingRuns(ctx context.Context) error {
	if m.dryRun {
		return godog.ErrSkip
	}
	if os.Getenv("ROLE") == "" {
		return errors.New("the Connector routing proof needs ROLE (egress or ingress) and the inputs of its README")
	}
	m.routing = repoPath(filepath.Join("bundles/bdd/evidence/bdd-zt-026", m.target, m.run, "connector-routing"))
	ctx, cancel := context.WithTimeout(ctx, 60*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, repoPath("scripts/verify-connector-routing/verify.sh"))
	cmd.Env = append(os.Environ(), "ZTD_EVIDENCE_DIR="+m.routing, "ZONE_VALUES="+m.zoneFile, "PROOF_ALLOW_IGNORED_RUN_DIR=1")
	out, err := cmd.CombinedOutput()
	m.rOutput = string(out)
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		m.rExit = exitErr.ExitCode()
	} else if err != nil {
		return fmt.Errorf("the Connector routing proof did not run: %w", err)
	}
	if m.rExit == 125 {
		return fmt.Errorf("the Connector routing proof refused to run: %s", lastLines(m.rOutput, 3))
	}
	return nil
}

// decideRouting reads the Connector routing record (evidence.md): the role's section, the direct paths and
// the exemptions are all there, every check passed, each direct path is dropped with Hubble's policy drop,
// and the record's result is 0 failed checks.
func decideRouting(record, role string) ([]string, error) {
	sections := map[string][]string{}
	current := ""
	result := ""
	for _, line := range strings.Split(record, "\n") {
		switch {
		case strings.HasPrefix(line, "## "):
			current = strings.TrimPrefix(line, "## ")
		case strings.HasPrefix(line, "- PASS: "), strings.HasPrefix(line, "- **FAIL**: "):
			sections[current] = append(sections[current], line)
		case strings.HasPrefix(line, "Result: "):
			result = line
		}
	}
	routed := map[string]string{"egress": "egress-route", "ingress": "entry"}[role]
	if routed == "" {
		return nil, fmt.Errorf("ROLE %q: want egress or ingress", role)
	}
	var report, problems []string
	for _, s := range []string{routed, "direct-path", "exemptions"} {
		report = append(report, fmt.Sprintf("%s: %d check(s)", s, len(sections[s])))
		if len(sections[s]) == 0 {
			problems = append(problems, "no check in section "+s)
		}
	}
	for s, lines := range sections {
		for _, l := range lines {
			if strings.HasPrefix(l, "- **FAIL**") {
				problems = append(problems, s+": "+strings.TrimPrefix(l, "- **FAIL**: "))
			}
		}
	}
	exempt := strings.Join(sections["exemptions"], "\n")
	for _, want := range []string{"PASS: DNS (declared bypass", "PASS: observability export (declared bypass"} {
		if !strings.Contains(exempt, want) {
			problems = append(problems, "exemptions: no "+want)
		}
	}
	if result != "Result: 0 failed check(s)." {
		problems = append(problems, "the record's result: "+result)
	}
	if len(problems) > 0 {
		return report, errors.New(strings.Join(problems, "; "))
	}
	return report, nil
}

func (m *meshProof) routedThroughTheConnector() error {
	if m.dryRun {
		return godog.ErrSkip
	}
	// The proof prints its run directory as its last line; on a host without GNU realpath (macOS) it does not
	// take ZTD_EVIDENCE_DIR and writes under ~/.local/state, so the record is read from there and copied in.
	record, err := os.ReadFile(filepath.Join(m.routing, "evidence.md"))
	if printed := strings.TrimSpace(lastLines(m.rOutput, 1)); err != nil && filepath.IsAbs(printed) {
		if record, err = os.ReadFile(filepath.Join(printed, "evidence.md")); err == nil {
			err = errors.Join(os.MkdirAll(m.routing, 0o755), os.WriteFile(filepath.Join(m.routing, "evidence.md"), record, 0o644))
		}
	}
	if err != nil {
		return fmt.Errorf("the Connector routing proof wrote no record (exit %d): %w; %s", m.rExit, err, lastLines(m.rOutput, 3))
	}
	// Each direct path's denial is cited from the evidence line under its PASS line.
	drops := strings.Count(string(record), "Policy denied DROPPED")
	report, err := decideRouting(string(record), os.Getenv("ROLE"))
	if err == nil && drops == 0 {
		err = errors.New("no direct path's drop is cited from Hubble")
	}
	if err == nil && m.rExit != 0 {
		err = fmt.Errorf("the proof exited %d", m.rExit)
	}
	report = append(report, fmt.Sprintf("Hubble policy drops cited: %d", drops), "role "+os.Getenv("ROLE")+", record: "+m.routing)
	return m.writeDecision("ZT-26", report, err)
}

func registerMeshProof(ctx *godog.ScenarioContext, dryRun bool) {
	m := &meshProof{}
	ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
		*m = meshProof{dryRun: dryRun}
		return c, nil
	})
	step := func(text string, fn any) { ctx.Step("^"+regexp.QuoteMeta(text)+"$", fn) }

	// ZT-23
	step("each target Kubernetes cluster with the selected Istio- or Cilium-based service mesh installed", m.zoneIsMeshed)
	step("services communicate within a cluster", m.planeSeparationRuns)
	step("the mesh is present in every cluster and service traffic is routed through it AND traffic attempting to bypass the mesh data path is not delivered.",
		func() error { return m.decidePlane("ZT-23", nil, nil, legitimateCaller, plainTextReset) })
	// ZT-25
	step("related and unrelated workloads in the service mesh", m.zoneIsMeshed)
	step("east-west communication is attempted", m.planeSeparationRuns)
	step("policy-related workloads communicate according to configured trust policy AND unaffiliated workloads are blocked by the default-deny network policy without relying on IP-address identity.",
		m.unaffiliatedBlockedWithoutAddresses)
	// ZT-61
	step("a microservice participating in the configured mesh", m.zoneIsMeshed)
	step("it communicates with another service", m.planeSeparationRuns)
	step("its service communication traverses the service-mesh data path and is subject to the configured identity and policy controls.",
		func() error {
			return m.decidePlane("ZT-61", nil, nil, legitimateCaller, impostorRefused, unlabelledDropped)
		})
	// ZT-62
	step("one identity explicitly permitted to communicate with a target service and one identity not permitted", m.zoneIsMeshed)
	step("both attempt the connection", m.planeSeparationRuns)
	step("the permitted identity communicates successfully AND the non-permitted identity is blocked by mesh policy.",
		func() error { return m.decidePlane("ZT-62", impostorRows, nil, legitimateCaller, impostorRefused) })
	// ZT-26
	step("application traffic, DNS traffic and an observability/admin endpoint", m.zoneIsMeshed)
	step("each traffic type leaves or enters a cluster", m.connectorRoutingRuns)
	step("protected inter-cluster application traffic is routed through the ZT Connector AND explicitly exempt infrastructure/admin traffic uses its separately controlled ingress/egress path.",
		m.routedThroughTheConnector)
}
