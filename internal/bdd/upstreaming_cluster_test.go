package bdd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// upstreamingProof runs ZT-73 against a zone where the guarded path is installed (Participant in token
// mode -> guard, with the policy evaluator and the token store -> protected resource, every hop inside
// the SPIRE-backed mesh). It runs scripts/verify-guard-bypass/verify.sh, which changes no object of the
// zone (its probe Jobs are its own and are removed), and decides the row from the records the script
// writes, not from its exit status alone. The trusted channel of this row is the zone's mesh: mutual TLS
// between SPIFFE identities, with DPoP-bound tokens on top. It is not the attested inter-zone channel.
// Every input comes from the environment; a missing one fails the scenario and is named.
//
//	KUBECONFIG              kubeconfig of the zone's cluster
//	KUBE_CONTEXT            its context; the script refuses any other current context
//	BDD_UPSTREAM_NAMESPACE  namespace of the guarded path
//	BDD_UPSTREAM_URL        public base URL of the Participant, BDD_UPSTREAM_CA the CA file of its certificate
//	BDD_PROBE_IMAGE         an image the zone admits that has bash, for the probes
//	BDD_TARGET, BDD_RUN_ID  name the target and the run in the evidence
//
// The record is written to bundles/bdd/evidence/bdd-zt-073/<target>/<run>, which git ignores. In the
// cluster dry run every step is skipped, so a pull request lists the row as not run.
type upstreamingProof struct {
	dryRun   bool
	ns       string
	evidence string
	exit     int
	output   string
}

var upstreamingInputs = []string{"KUBECONFIG", "KUBE_CONTEXT", "BDD_UPSTREAM_NAMESPACE", "BDD_UPSTREAM_URL", "BDD_UPSTREAM_CA", "BDD_PROBE_IMAGE", "BDD_TARGET", "BDD_RUN_ID"}

func (p *upstreamingProof) pathIsDeployed(ctx context.Context) error {
	if p.dryRun {
		return godog.ErrSkip
	}
	for _, name := range upstreamingInputs {
		if os.Getenv(name) == "" {
			return fmt.Errorf("the upstreaming proof needs %s", name)
		}
	}
	safe := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	p.ns = os.Getenv("BDD_UPSTREAM_NAMESPACE")
	p.evidence = repoPath(filepath.Join("bundles/bdd/evidence/bdd-zt-073",
		safe.ReplaceAllString(os.Getenv("BDD_TARGET"), "-"), safe.ReplaceAllString(os.Getenv("BDD_RUN_ID"), "-")))
	// The Participant, the guard and the resource are rolled out; whether the Participant is registered
	// and holds a token is the script's first record (state.json).
	out, err := exec.CommandContext(ctx, "kubectl", "--context", os.Getenv("KUBE_CONTEXT"), "-n", p.ns, "get", "deployment",
		"ztd-participant", "ztd-guard", "ztd-protected-resource", "-o", `jsonpath={range .items[*]}{.metadata.name}={.status.availableReplicas} {end}`).CombinedOutput()
	if err != nil {
		return fmt.Errorf("the guarded path is not in %s: %s", p.ns, lastLines(string(out), 3))
	}
	for _, field := range strings.Fields(string(out)) {
		if name, available, _ := strings.Cut(field, "="); available == "" || available == "0" {
			return fmt.Errorf("deployment %s of %s has no available replica", name, p.ns)
		}
	}
	return nil
}

func (p *upstreamingProof) backendCalls(ctx context.Context) error {
	if p.dryRun {
		return godog.ErrSkip
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	// The script refuses an existing record directory, so a run id decides one record only.
	cmd := exec.CommandContext(ctx, repoPath("scripts/verify-guard-bypass/verify.sh"), "--namespace", p.ns,
		"--url", os.Getenv("BDD_UPSTREAM_URL"), "--ca", os.Getenv("BDD_UPSTREAM_CA"),
		"--probe-image", os.Getenv("BDD_PROBE_IMAGE"), "--out", p.evidence)
	cmd.Env = append(os.Environ(), "ZTD_CONFIRM_CONTEXT="+os.Getenv("KUBE_CONTEXT"))
	out, err := cmd.CombinedOutput()
	p.output = string(out)
	p.exit = 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		p.exit = exitErr.ExitCode()
	} else if err != nil {
		return fmt.Errorf("the verifier did not run: %w", err)
	}
	if p.exit == 125 {
		return fmt.Errorf("the verifier refused to run: %s", lastLines(p.output, 3))
	}
	return nil
}

func (p *upstreamingProof) authorizedServedUnauthorizedRefused() error {
	if p.dryRun {
		return godog.ErrSkip
	}
	summary, err := decideUpstreaming(p.evidence)
	if err != nil {
		return fmt.Errorf("%w; verifier exit %d: %s; record %s", err, p.exit, lastLines(p.output, 3), p.evidence)
	}
	if p.exit != 0 {
		return fmt.Errorf("the row's records hold but %d check(s) of the run failed; record %s", p.exit, p.evidence)
	}
	fmt.Printf("ZT-73: %s; record %s\n", summary, p.evidence)
	return nil
}

// decideUpstreaming decides ZT-73 from a record directory of scripts/verify-guard-bypass/verify.sh and
// returns one line naming what it found.
//
// Authorized: the Participant's state shows it presented, acquired its token and is ready; its guarded
// call answered 200 with the resource's data; the guard recorded an allowed decision with the rule that
// permitted it; the resource recorded that request under the token store's client; and the RBAC allowed
// counter rose at the guard's and at the resource's sidecar, whose policies admit one SPIFFE identity
// each, so both hops were authenticated by mutual TLS.
//
// Unauthorized: the Participant's identity without a token was refused by the guard with 401 and the
// code of a missing token (TOK-MISSING; token_absent from a guard older than the reason-code registry),
// with a denied decision event of that code under the correlation id the caller received; the same identity calling
// the resource past the guard was refused by the resource's sidecar, whose denial line names both SPIFFE
// identities; neither answer carries resource data and the resource application logged nothing meanwhile.
func decideUpstreaming(dir string) (string, error) {
	read := func(name string) (string, error) {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return "", fmt.Errorf("the verifier wrote no %s: %w", name, err)
		}
		return string(raw), nil
	}
	// lastJSON decodes the last line of a JSON-lines record.
	lastJSON := func(name string, into any) error {
		text, err := read(name)
		if err != nil {
			return err
		}
		lines := strings.Split(strings.TrimSpace(text), "\n")
		if err := json.Unmarshal([]byte(lines[len(lines)-1]), into); err != nil {
			return fmt.Errorf("%s holds no record: %w", name, err)
		}
		return nil
	}

	// Authorized.
	stateText, err := read("state.json")
	if err != nil {
		return "", err
	}
	var state struct {
		Mode, State string
		History     []struct{ State string }
	}
	if err := json.Unmarshal([]byte(stateText), &state); err != nil {
		return "", fmt.Errorf("state.json: %w", err)
	}
	var steps []string
	for _, h := range state.History {
		steps = append(steps, h.State)
	}
	if state.Mode != "token" || state.State != "ready" || !strings.Contains(strings.Join(steps, " "), "presenting acquiring_token ready") {
		return "", fmt.Errorf("the Participant is not a token-mode backend that presented, acquired its token and is ready: mode %s, state %s, history %v", state.Mode, state.State, steps)
	}
	status, err := read("guarded-status.txt")
	if err != nil {
		return "", err
	}
	responseText, err := read("guarded-response.json")
	if err != nil {
		return "", err
	}
	var response struct {
		RequestID, Outcome, ReasonCode string
		SafeData                       struct{ Report, Summary struct{ ID string } }
	}
	if err := json.Unmarshal([]byte(responseText), &response); err != nil {
		return "", fmt.Errorf("guarded-response.json: %w", err)
	}
	data := response.SafeData.Report.ID + response.SafeData.Summary.ID
	if strings.TrimSpace(status) != "200" || response.Outcome != "success" || data == "" || response.RequestID == "" {
		return "", fmt.Errorf("the authorized call was not served: status %s, outcome %s %s, data %q", strings.TrimSpace(status), response.Outcome, response.ReasonCode, data)
	}
	var allowed guardDecision
	if err := lastJSON("guarded-guard-record.jsonl", &allowed); err != nil {
		return "", err
	}
	if allowed.Payload.State != "allowed" || allowed.Payload.RuleID == "" {
		return "", fmt.Errorf("the guard's event for the authorized call is %q under rule %q, want allowed under a rule", allowed.Payload.State, allowed.Payload.RuleID)
	}
	var served struct {
		RequestID string `json:"requestId"`
		Outcome   string `json:"outcome"`
		ClientID  string `json:"client_id"`
	}
	if err := lastJSON("guarded-resource-record.jsonl", &served); err != nil {
		return "", err
	}
	// The resource must have served the token store's substituted token, the client the run names
	// (expected-store-client.txt, from the zone's seeded clients), not the Participant's own token.
	store, err := read("expected-store-client.txt")
	if err != nil {
		return "", err
	}
	store = strings.TrimSpace(store)
	if store == "" {
		return "", errors.New("the run names no expected token-store client")
	}
	if served.RequestID != response.RequestID || served.Outcome != "success" || served.ClientID != store {
		return "", fmt.Errorf("the resource did not record request %s as served for the token store's client %q: %+v", response.RequestID, store, served)
	}
	for _, hop := range []string{"guard", "resource"} {
		before, err := rbacAllowed(dir, "guarded-stats-"+hop+"-before.txt")
		if err != nil {
			return "", err
		}
		after, err := rbacAllowed(dir, "guarded-stats-"+hop+"-after.txt")
		if err != nil {
			return "", err
		}
		if after <= before {
			return "", fmt.Errorf("the %s's sidecar admitted no identity during the authorized call (rbac.allowed %d -> %d)", hop, before, after)
		}
	}

	// Unauthorized, through the guard.
	tokenless, err := read("tokenless-response.txt")
	if err != nil {
		return "", err
	}
	id := regexp.MustCompile(`(?mi)^x-request-id: *(\S+)`).FindStringSubmatch(tokenless)
	code := regexp.MustCompile(`"reason_code":"(TOK-MISSING|token_absent)"`).FindStringSubmatch(tokenless)
	if !strings.HasPrefix(tokenless, "HTTP/1.1 401") || code == nil || id == nil {
		return "", fmt.Errorf("the tokenless call was not refused 401 for its missing token under a correlation id: %.200q", tokenless)
	}
	denials, err := read("tokenless-guard-record.jsonl")
	if err != nil {
		return "", err
	}
	var denied *guardDecision
	scanner := bufio.NewScanner(strings.NewReader(denials))
	for scanner.Scan() {
		var event guardDecision
		if json.Unmarshal(scanner.Bytes(), &event) == nil && event.CorrelationID == id[1] {
			denied = &event
		}
	}
	if denied == nil || denied.Payload.State != "denied" || denied.Payload.ReasonCode != code[1] {
		return "", fmt.Errorf("the guard recorded no denied %s event under %s", code[1], id[1])
	}

	// Unauthorized, past the guard.
	meshed, err := read("meshed-response.txt")
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(meshed, "HTTP/1.1 403") || !strings.Contains(meshed, "RBAC: access denied") {
		return "", fmt.Errorf("the direct call was not refused 403 RBAC: %.200q", meshed)
	}
	var line struct{ Detail, Source, Destination string }
	if err := lastJSON("meshed-receiver-log.txt", &line); err != nil {
		return "", err
	}
	spiffe := regexp.MustCompile(`^spiffe://[^/]+/ns/[^/]+/sa/[^/]+$`)
	if !strings.HasPrefix(line.Detail, "rbac_access_denied") || !spiffe.MatchString(line.Source) || !spiffe.MatchString(line.Destination) ||
		!strings.HasSuffix(line.Source, "/sa/ztd-participant") || !strings.HasSuffix(line.Destination, "/sa/ztd-protected-resource") {
		return "", fmt.Errorf("the resource's sidecar logged no RBAC denial naming the Participant and the resource: %+v", line)
	}
	for name, answer := range map[string]string{"tokenless": tokenless, "meshed": meshed} {
		if strings.Contains(answer, "safeData") || (response.SafeData.Report.ID != "" && strings.Contains(answer, response.SafeData.Report.ID)) {
			return "", fmt.Errorf("the %s answer carries resource data", name)
		}
	}
	if reached, err := read("resource-app-log-during-probes.txt"); err != nil {
		return "", err
	} else if strings.TrimSpace(reached) != "" {
		return "", errors.New("the resource application logged a request while the unauthorized calls ran")
	}
	return fmt.Sprintf("authorized call %s 200 %s, guard allowed under %s, resource served client %s; tokenless call 401 %s (guard event %s); direct call 403 RBAC, %s -> %s",
		response.RequestID, response.ReasonCode, allowed.Payload.RuleID, served.ClientID, code[1], id[1], line.Source, line.Destination), nil
}

// guardDecision is a decision event of the guard's log.
type guardDecision struct {
	CorrelationID string `json:"correlation_id"`
	Payload       struct {
		State      string `json:"state"`
		ReasonCode string `json:"reason_code"`
		RuleID     string `json:"rule_id"`
	} `json:"payload"`
}

// rbacAllowed reads the inbound RBAC allowed counter from a sidecar stats record.
func rbacAllowed(dir, name string) (int, error) {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return 0, fmt.Errorf("the verifier wrote no %s: %w", name, err)
	}
	var n int
	for _, l := range strings.Split(string(raw), "\n") {
		if _, err := fmt.Sscanf(l, "http.inbound_0.0.0.0_8080;.rbac.allowed: %d", &n); err == nil {
			return n, nil
		}
	}
	return 0, fmt.Errorf("%s holds no rbac.allowed counter", name)
}

func registerUpstreamingProof(ctx *godog.ScenarioContext, dryRun bool) {
	p := &upstreamingProof{}
	ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
		*p = upstreamingProof{dryRun: dryRun}
		return c, nil
	})
	ctx.Step(`^a registered participant backend with valid authorization and an available protected resource$`, p.pathIsDeployed)
	ctx.Step(`^the backend calls through the Zero Trust Connector$`, p.backendCalls)
	ctx.Step(`^the request is authorized, traverses the trusted channel and receives the policy-permitted protected-resource response AND an unauthorized request does not return protected data\.$`, p.authorizedServedUnauthorizedRefused)
}
