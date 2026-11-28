package bdd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// guardingProof runs ZT-20 on a throwaway kind cluster: it runs the guarding proof
// (scripts/verify-guard-catalogue/verify.sh --tsa) and decides the row from the cases.jsonl the proof
// records. The proof installs the guard chart in the mesh in front of the protected resource, REST route
// and gRPC method, with the policy evaluator deciding through the XFSC TSA policy service and a Rego
// bundle signed for the run; a participant then sends, over each protocol, an entitled request, an
// unentitled one and one that needs a credential presentation.
//
//	BIN         a directory holding a linux cosign (scripts/tools/install.sh <dir> cosign)
//	BDD_TARGET  target name, BDD_RUN_ID run identifier
//	GUARD_CATALOGUE_KIND_CLUSTER, GUARD_CATALOGUE_REGISTRY_NAME, GUARD_CATALOGUE_HOST_REGISTRY
//	            the verifier's own names, when its defaults are taken
//
// The verifier creates and removes its own cluster and keeps its own kubeconfig: no existing cluster or
// context is touched. The record is written to bundles/bdd/evidence/bdd-zt-020/<target>/<run>, which git
// ignores. In the cluster dry run every step is skipped, so a pull request lists the row as not run.
type guardingProof struct {
	dryRun   bool
	evidence string
	exit     int
	output   string
}

// guardingCase is one line of cases.jsonl (scripts/verify-guard-catalogue/guarding.sh).
type guardingCase struct {
	Case            string         `json:"case"`
	Protocol        string         `json:"protocol"`
	HTTPStatus      string         `json:"http_status"`
	GRPCStatus      string         `json:"grpc_status"`
	ReasonCode      string         `json:"reason_code"`
	CorrelationID   string         `json:"correlation_id"`
	OID4VPLink      string         `json:"oid4vp_link"`
	ResourceReached bool           `json:"resource_reached"`
	GuardEvent      *guardingEvent `json:"guard_event"`
	PolicyEvent     *guardingEvent `json:"policy_event"`
	Verdict         string         `json:"verdict"`
}

type guardingEvent struct {
	CorrelationID string `json:"correlation_id"`
	Payload       struct {
		State          string `json:"state"`
		ReasonCode     string `json:"reason_code"`
		RuleID         string `json:"rule_id"`
		BundleRevision string `json:"bundle_revision"`
	} `json:"payload"`
}

// decideGuarding decides the row from the proof's cases, for the REST route and the gRPC method alike:
// the authorized request passed the guard (PEP) and the policy (PDP) under one correlation id and reached
// the resource; the unauthorized one and the one that needs a presentation were denied with the guard's
// and the policy's denied events under the id the caller received, never reaching the resource, the
// second answered with an OID4VP link. Every policy event names its rule and revision, the revision of
// the Rego bundle the TSA had active. It returns one line per case.
func decideGuarding(r io.Reader, revision string) ([]string, error) {
	cases := map[string]guardingCase{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1<<16), 1<<22)
	for scanner.Scan() {
		var c guardingCase
		if err := json.Unmarshal(scanner.Bytes(), &c); err != nil {
			return nil, fmt.Errorf("cases.jsonl: %w", err)
		}
		cases[c.Case] = c
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if revision == "" {
		return nil, errors.New("the run names no bundle revision")
	}
	var lines, bad []string
	for _, protocol := range []string{"rest", "grpc"} {
		for _, want := range []struct{ name, state, code string }{
			{"authorized", "allowed", ""},
			{"unauthorized", "denied", "POL-RULE-DENY"},
			{"presentation-required", "denied", "POL-PRESENTATION-REQUIRED"},
		} {
			name := protocol + "-" + want.name
			c, ok := cases[name]
			problem := ""
			switch g, p := c.GuardEvent, c.PolicyEvent; {
			case !ok:
				problem = "not in the record"
			case c.Protocol != protocol || c.Verdict != "yes" || c.CorrelationID == "":
				problem = "the proof did not hold it"
			case g == nil || g.CorrelationID != c.CorrelationID || g.Payload.State != want.state || g.Payload.ReasonCode != want.code:
				problem = "no " + want.state + " guard event under " + c.CorrelationID
			case p == nil || p.CorrelationID != c.CorrelationID || p.Payload.State != want.state || p.Payload.ReasonCode != want.code || p.Payload.RuleID == "":
				problem = "no " + want.state + " policy event with its rule under " + c.CorrelationID
			case p.Payload.BundleRevision != revision:
				problem = "decided under revision " + p.Payload.BundleRevision + ", not the TSA's bundle " + revision
			case c.ResourceReached != (want.state == "allowed"):
				problem = fmt.Sprintf("resource reached: %v", c.ResourceReached)
			case want.state == "denied" && c.ReasonCode != want.code:
				problem = "answered " + c.ReasonCode
			case want.name == "presentation-required" && !isOID4VPLink(c.OID4VPLink):
				problem = "answered without an OID4VP link"
			}
			if problem != "" {
				bad = append(bad, name+": "+problem)
				continue
			}
			lines = append(lines, fmt.Sprintf("%s %s by %s (%s)", name, want.state, c.PolicyEvent.Payload.RuleID, c.CorrelationID))
		}
	}
	if len(bad) > 0 {
		return lines, errors.New(strings.Join(bad, "; "))
	}
	return lines, nil
}

func isOID4VPLink(link string) bool {
	u, err := url.Parse(link)
	return err == nil && (u.Scheme == "openid4vp" || u.Scheme == "https")
}

func (p *guardingProof) resourceIsGuarded() error {
	if p.dryRun {
		return godog.ErrSkip
	}
	for _, name := range []string{"BIN", "BDD_TARGET", "BDD_RUN_ID"} {
		if os.Getenv(name) == "" {
			return fmt.Errorf("the guarding proof needs %s", name)
		}
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("BIN"), "cosign")); err != nil {
		return fmt.Errorf("BIN holds no cosign: %w", err)
	}
	safe := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	p.evidence = repoPath(filepath.Join("bundles/bdd/evidence/bdd-zt-020",
		safe.ReplaceAllString(os.Getenv("BDD_TARGET"), "-"), safe.ReplaceAllString(os.Getenv("BDD_RUN_ID"), "-")))
	return os.MkdirAll(p.evidence, 0o755)
}

func (p *guardingProof) requestsAreExecuted(ctx context.Context) error {
	if p.dryRun {
		return godog.ErrSkip
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, repoPath("scripts/verify-guard-catalogue/verify.sh"), "--tsa", "--out", p.evidence)
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	p.output, p.exit = string(out), 0
	// The verifier empties its output directory first: its own log is written after it ran.
	if werr := os.WriteFile(filepath.Join(p.evidence, "verify.log"), out, 0o644); werr != nil {
		return werr
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		p.exit = exitErr.ExitCode()
	} else if err != nil {
		return fmt.Errorf("the verifier did not run: %w", err)
	}
	return nil
}

func (p *guardingProof) authorizedPassesUnauthorizedDenied() error {
	if p.dryRun {
		return godog.ErrSkip
	}
	var env struct {
		BundleRevision string `json:"bundle_revision"`
	}
	raw, err := os.ReadFile(filepath.Join(p.evidence, "environment.json"))
	if err != nil || json.Unmarshal(raw, &env) != nil {
		return fmt.Errorf("the verifier did not finish (exit %d): %s", p.exit, lastLines(p.output, 3))
	}
	f, err := os.Open(filepath.Join(p.evidence, "cases.jsonl"))
	if err != nil {
		return fmt.Errorf("the verifier wrote no cases (exit %d): %w; %s", p.exit, err, lastLines(p.output, 3))
	}
	defer func() { _ = f.Close() }()
	lines, err := decideGuarding(f, env.BundleRevision)
	report := strings.Join(lines, "; ")
	if err != nil {
		return fmt.Errorf("%w (held: %s); record %s", err, report, p.evidence)
	}
	if p.exit != 0 {
		return fmt.Errorf("every case held (%s) but %d check(s) of the run failed; record %s", report, p.exit, p.evidence)
	}
	fmt.Printf("ZT-20 cases under bundle %s: %s; record %s\n", env.BundleRevision, report, p.evidence)
	return nil
}

func registerGuardingProof(ctx *godog.ScenarioContext, dryRun bool) {
	p := &guardingProof{}
	ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
		*p = guardingProof{dryRun: dryRun}
		return c, nil
	})
	ctx.Step(`^a protected resource behind the Connector guard$`, p.resourceIsGuarded)
	ctx.Step(`^a request with matching authorization and a request without matching authorization are executed$`, p.requestsAreExecuted)
	ctx.Step(`^the authorized request passes the PEP/PDP policy chain AND the unauthorized request is denied before the protected resource returns data\.$`, p.authorizedPassesUnauthorizedDenied)
}
