package bdd

import (
	"bufio"
	"context"
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

// workloadIdentityProof runs ZT-24, ZT-57, ZT-59 and ZT-60, and the mesh rows ZT-01 and ZT-58 that the
// same record decides, on a cluster: it runs the mesh identity proof
// (scripts/verify-mesh-identity/verify.sh) once per test process and decides each row from the sections
// of the evidence.md that proof records (scripts/verify-mesh-identity/README.md, "What a run shows"), so
// that a row's result is the record's. Every input comes from the environment; a missing one fails the
// scenario and is named.
//
//	KUBE_CONTEXT          the verifier's context (default kind-ztd): a kind cluster, or zerotrust-a/-b
//	                      with ZTD_CONFIRM_CLUSTER (and ZONE_VALUES); the verifier refuses any other
//	BDD_TARGET, BDD_RUN_ID name the target and the run in the evidence
//
// The proof is DESTRUCTIVE: it uninstalls the zone, installs it from the empty cluster twice and tears it
// down (on a participant cluster unless ZTD_KEEP_ZONE). The record is written to
// bundles/bdd/evidence/workload-identity/<target>/<run> (git-ignored), and each row's decision to
// bundles/bdd/evidence/bdd-zt-0xx/<target>/<run>/decision.txt. In the cluster dry run every step is
// skipped, so a pull request lists the rows as not run and can never report them passed.
type workloadIdentityProof struct {
	dryRun bool
	row    string
}

// identityRun is the one run of the verifier a test process makes; every row decides from its record.
var identityRun *identityRunResult

type identityRunResult struct {
	evidence, target, run string
	exit                  int
	output                string
	err                   error
}

// The sections of evidence.md (by their number) and the checks (a part of the title of a PASS line)
// each row is decided on. Sections 0 to 2 (preconditions, clean slate, the zone installed from the empty
// cluster) hold for every row: a row cannot pass on a zone that did not install.
var identityRows = map[string]struct {
	sections []string
	checks   []string
}{
	"ZT-24": {[]string{"0", "1", "2", "4", "6", "8", "9", "12", "14"}, []string{
		"every SPIRE agent is attested by the server",
		"the SPIRE server and the mesh run with the zone's trust domain",
		"the SPIRE server lists an entry for the labelled pod, created from the ClusterSPIFFEID",
		"the proxy's workload certificate (default) has O = SPIRE",
		"the proxy holds a root bundle under ROOTCA, and it is the SPIRE server's CA",
		"the SPIRE server lists no entry for the two unlabelled pods",
		"an unlabelled pod's fetch over the mounted socket returns no SVID",
		"the unlabelled pod's proxy holds no workload certificate",
		"registration-inventory:",
	}},
	"ZT-57": {[]string{"0", "1", "2", "4", "6"}, []string{
		"every SPIRE agent is attested by the server",
		"one per-node SVID stand-in is Ready on every node with a SPIRE agent",
		"the SVID fetched over the node's mounted socket by svid-on-",
		"that SVID chains to the SPIRE server's CA",
		"the labelled pod mounts the csi.spiffe.io volume",
	}},
	"ZT-59": {[]string{"0", "1", "2", "6", "8", "10"}, []string{
		"the SPIRE server lists an entry for the labelled pod, created from the ClusterSPIFFEID",
		"the SVID fetched over the mounted socket carries the SPIFFE ID of the pod's service account",
		"the SVID chains to the SPIRE server's CA",
		"the proxy's workload certificate (default) has O = SPIRE",
		"the peer sees the caller's own SPIFFE identity in X-Forwarded-Client-Cert",
	}},
	"ZT-60": {[]string{"0", "1", "2", "6", "9"}, []string{
		"the SPIRE server lists no entry for the two unlabelled pods",
		"an unlabelled pod's fetch over the mounted socket returns no SVID",
		"the unlabelled pod's proxy holds no workload certificate",
		"the SPIRE agent refuses its proxy over SDS",
		"its application container never starts",
		"is refused in the handshake: the peer accepts mTLS only (STRICT)",
		"the peer's proxy wrote no denial line naming it",
		"the labelled pod's call to the same peer succeeds",
	}},
	// ZT-01: the same call from a meshed pair (served, mutual TLS, the caller's identity seen by the peer)
	// and from workloads outside the mesh (the proxy-less probe and the pod without a certificate): refused
	// by the peer's STRICT listener and written to its denial log with the caller's address.
	"ZT-01": {[]string{"0", "1", "2", "5", "8", "9", "10"}, []string{
		"the proxy's workload certificate (default) has O = SPIRE",
		"the labelled pod's call to the same peer succeeds",
		"the labelled pod's served call left no line in the peer's denial log",
		"the peer sees the caller's own SPIFFE identity in X-Forwarded-Client-Cert",
		"both proxies counted the request (istio_requests_total)",
		"the peer's proxy records the requests as mutual_tls",
		"the call of the proxy-less pod probe, a workload outside the mesh, to the meshed peer is refused",
		"the peer's proxy logged the refused out-of-mesh call",
		"is refused in the handshake: the peer accepts mTLS only (STRICT)",
		"the peer's proxy logged the refused connection of the unlabelled pod",
	}},
	// ZT-58: the control plane serves every proxy, the capture layer (the Istio CNI plugin) is chained on
	// every node, and on every node with a SPIRE agent a meshed stand-in holds a SPIRE-issued certificate
	// and calls the next node's over mutual TLS. A node whose check failed fails its section.
	"ZT-58": {[]string{"0", "1", "2", "4", "7", "10", "11", "12"}, []string{
		"every SPIRE agent is attested by the server",
		"the SPIRE server and the mesh run with the zone's trust domain",
		"istio-proxy is an init container with restartPolicy Always (a native sidecar)",
		"lists the Istio plugin after Cilium",
		"runs on the node and is Ready, and its proxy's certificate is issued by the SPIRE CA with its own SPIFFE ID",
		"crosses nodes, the receiver sees the caller's own SPIFFE ID, the caller's proxy saw the receiver's own, and both proxies count it as mutual TLS",
		"the registered proxies reach istiod through the meshControlPlane opening and report SYNCED for every xDS type",
	}},
}

var sectionHeading = regexp.MustCompile(`^## (\d+)\. `)

// decideIdentityRow decides one row from an evidence.md: every section the row names is in the record
// with at least one check and no failed one, and every check the row names is a PASS line of those
// sections. It returns the PASS lines it relied on.
func decideIdentityRow(r io.Reader, row string) ([]string, error) {
	spec, ok := identityRows[row]
	if !ok {
		return nil, fmt.Errorf("no decision for row %s", row)
	}
	want := map[string]bool{}
	for _, s := range spec.sections {
		want[s] = true
	}
	checks := map[string]int{}
	var passed, failed []string
	current := ""
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		line := sc.Text()
		if m := sectionHeading.FindStringSubmatch(line); m != nil {
			current = m[1]
			continue
		}
		if strings.HasPrefix(line, "## ") {
			current = "" // a section without a number (the CNI as found) decides no row
			continue
		}
		if !want[current] {
			continue
		}
		switch {
		case strings.HasPrefix(line, "- PASS: "):
			checks[current]++
			passed = append(passed, "§"+current+" "+strings.TrimPrefix(line, "- PASS: "))
		case strings.HasPrefix(line, "- **FAIL**: "):
			checks[current]++
			failed = append(failed, "§"+current+" "+strings.TrimPrefix(line, "- **FAIL**: "))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("evidence.md: %w", err)
	}
	var problems []string
	for _, s := range spec.sections {
		if checks[s] == 0 {
			problems = append(problems, "section "+s+" holds no check")
		}
	}
	for _, c := range spec.checks {
		found := false
		for _, p := range passed {
			if strings.Contains(p, c) {
				found = true
				break
			}
		}
		if !found {
			problems = append(problems, "no PASS line: "+c)
		}
	}
	if len(failed) > 0 {
		problems = append(problems, "failed: "+strings.Join(failed, " | "))
	}
	if len(problems) > 0 {
		return passed, errors.New(strings.Join(problems, "; "))
	}
	return passed, nil
}

func (p *workloadIdentityProof) clusterIsReady(row string) func(context.Context) error {
	return func(ctx context.Context) error {
		p.row = row
		if p.dryRun {
			return godog.ErrSkip
		}
		for _, name := range []string{"BDD_TARGET", "BDD_RUN_ID"} {
			if os.Getenv(name) == "" {
				return fmt.Errorf("the workload identity proof needs %s", name)
			}
		}
		out, err := exec.CommandContext(ctx, "kubectl", "--context", envOr("KUBE_CONTEXT", "kind-ztd"), "get", "nodes",
			"-o", `jsonpath={range .items[*]}{.metadata.name}={.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}`).CombinedOutput()
		if err != nil || len(strings.TrimSpace(string(out))) == 0 {
			return fmt.Errorf("the cluster is not reachable: %s", strings.TrimSpace(string(out)))
		}
		for _, n := range strings.Fields(string(out)) {
			if !strings.HasSuffix(n, "=True") {
				return fmt.Errorf("node not Ready: %s", n)
			}
		}
		return nil
	}
}

func (p *workloadIdentityProof) proofRuns(ctx context.Context) error {
	if p.dryRun {
		return godog.ErrSkip
	}
	if identityRun != nil {
		return identityRun.err
	}
	clean := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	r := &identityRunResult{
		target: clean.ReplaceAllString(os.Getenv("BDD_TARGET"), "-"),
		run:    clean.ReplaceAllString(os.Getenv("BDD_RUN_ID"), "-"),
	}
	identityRun = r
	r.evidence = repoPath(filepath.Join("bundles/bdd/evidence/workload-identity", r.target, r.run))
	ctx, cancel := context.WithTimeout(ctx, 120*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, repoPath("scripts/verify-mesh-identity/verify.sh"))
	// bundles/ is git-ignored, which the verifier accepts as a run directory only when told so.
	cmd.Env = append(os.Environ(), "ZTD_EVIDENCE_DIR="+r.evidence, "PROOF_ALLOW_IGNORED_RUN_DIR=1")
	out, err := cmd.CombinedOutput()
	r.output = string(out)
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		r.exit = exitErr.ExitCode()
	case err != nil:
		r.err = fmt.Errorf("the verifier did not run: %w", err)
	}
	if r.exit == 125 {
		r.err = fmt.Errorf("the verifier refused to run: %s", lastLines(r.output, 3))
	}
	_ = os.WriteFile(filepath.Join(r.evidence, "verify.log"), out, 0o644)
	return r.err
}

func (p *workloadIdentityProof) rowHolds(ctx context.Context) error {
	if p.dryRun {
		return godog.ErrSkip
	}
	r := identityRun
	if r == nil || r.err != nil {
		return errors.New("the verifier did not run")
	}
	f, err := os.Open(filepath.Join(r.evidence, "evidence.md"))
	if err != nil {
		return fmt.Errorf("the verifier wrote no record (exit %d): %w; %s", r.exit, err, lastLines(r.output, 3))
	}
	defer func() { _ = f.Close() }()
	passed, decideErr := decideIdentityRow(f, p.row)
	verdict := "passed"
	if decideErr != nil {
		verdict = "failed: " + decideErr.Error()
	}
	dir := repoPath(filepath.Join("bundles/bdd/evidence", "bdd-zt-0"+strings.TrimPrefix(p.row, "ZT-"), r.target, r.run))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	decision := fmt.Sprintf("row %s\nrecord %s\nverifier exit %d (failed checks of the whole run)\nresult %s\n\nPASS lines decided on:\n%s\n",
		p.row, r.evidence, r.exit, verdict, strings.Join(passed, "\n"))
	if err := os.WriteFile(filepath.Join(dir, "decision.txt"), []byte(decision), 0o644); err != nil {
		return err
	}
	if decideErr != nil {
		return fmt.Errorf("%s not held: %w; record %s", p.row, decideErr, r.evidence)
	}
	fmt.Printf("%s held on %d checks (verifier exit %d); record %s\n", p.row, len(passed), r.exit, r.evidence)
	return nil
}

func registerWorkloadIdentityProof(ctx *godog.ScenarioContext, dryRun bool) {
	p := &workloadIdentityProof{}
	ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
		*p = workloadIdentityProof{dryRun: dryRun}
		return c, nil
	})
	// ZT-24
	ctx.Step(`^each target Kubernetes cluster is running$`, p.clusterIsReady("ZT-24"))
	ctx.Step(`^SPIRE node and workload registration is applied$`, p.proofRuns)
	ctx.Step(`^SPIRE is deployed in every cluster, all mesh services obtain SPIRE-backed identities and the service mesh uses those identities AND a workload that cannot attest does not receive an identity\.$`, p.rowHolds)
	// ZT-57
	ctx.Step(`^the target Kubernetes nodes are ready$`, p.clusterIsReady("ZT-57"))
	ctx.Step(`^SPIFFE/SPIRE is installed and workloads are registered$`, p.proofRuns)
	ctx.Step(`^each relevant microservice has access to a SPIRE Agent on its node and can request workload identity\.$`, p.rowHolds)
	// ZT-59
	ctx.Step(`^a correctly registered microservice satisfying SPIRE attestation$`, p.clusterIsReady("ZT-59"))
	ctx.Step(`^it requests its workload identity$`, p.proofRuns)
	ctx.Step(`^SPIRE attests the workload successfully and issues the expected identity, which is then usable by the mesh\.$`, p.rowHolds)
	// ZT-60
	ctx.Step(`^a workload cannot satisfy SPIRE attestation$`, p.clusterIsReady("ZT-60"))
	ctx.Step(`^it requests a workload identity and attempts mesh communication$`, p.proofRuns)
	ctx.Step(`^no identity is issued and all service communication is denied\.$`, p.rowHolds)
	// ZT-01
	ctx.Step(`^the service mesh is deployed in each target cluster with workload identities issued$`, p.clusterIsReady("ZT-01"))
	ctx.Step(`^two in-mesh services communicate and a workload outside the mesh attempts the same call$`, p.proofRuns)
	ctx.Step(`^the in-mesh call is carried over the mesh under mutual TLS AND the out-of-mesh call is blocked and logged\.$`, p.rowHolds)
	// ZT-58
	ctx.Step(`^SPIRE-backed identities and the target clusters$`, p.clusterIsReady("ZT-58"))
	ctx.Step(`^the service mesh/control plane and traffic-capture layer are enabled$`, p.proofRuns)
	ctx.Step(`^service traffic is captured on each node and protected with workload-certificate-based mutual TLS\.$`, p.rowHolds)
}
