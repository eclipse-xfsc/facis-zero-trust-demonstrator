package bdd

import (
	"context"
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

// observabilityProof runs ZT-27 on a cluster: it runs the observability proof
// (scripts/verify-observability/verify.sh) and decides the row from the checks of the record.json that
// proof writes (scripts/verify-observability/README.md, "Checks"). Every input comes from the environment.
//
//	KUBE_CONTEXT                          a kind cluster holding the zone and the demonstrator role, or
//	ZONE_CONTEXT, DEMONSTRATOR_CONTEXT    a zone and the demonstrator cluster, with ZTD_CONFIRM_CLUSTER and
//	                                      ZONE_VALUES (the verifier's README); the verifier refuses any other
//	BDD_TARGET, BDD_RUN_ID                name the target and the run in the evidence
//
// The proof stops and restores components of the zone (the SPIRE server, an agent, a node collector, the
// gateway's egress, the entry) to show buffering and alerts. Its record is copied to
// bundles/bdd/evidence/bdd-zt-027/<target>/<run> (git-ignored), with the decision in decision.txt. In the
// cluster dry run every step is skipped.
type observabilityProof struct {
	dryRun   bool
	evidence string
	exit     int
	output   string
}

// The workloads the row's Given names, by the prefix of their name: the node collectors and the zone
// gateway (the Collector), the entry they export to, Prometheus and the tracing backend.
var observabilityWorkloads = []string{"otel-node-agent", "otel-gateway", "otel-entry", "prometheus-server", "jaeger"}

// The checks of the record each clause of the row's Then is decided on; every one must have passed.
var observabilityClauses = []struct {
	clause string
	checks []string
}{
	{"traces and metrics are exported from the cluster through the Collector", []string{
		"spire-agents-scraped", "spire-server-scraped", "workload-otlp-accepted", "prometheus-scrapes-no-zone"}},
	{"logs of the traffic and of the IF-01 events are exported through the Collector", []string{
		"pod-logs-collected", "if01-fields-kept", "logs-exported"}},
	{"metrics are retained in Prometheus", []string{"metrics-survive-restart"}},
	{"traces are queryable in the tracing backend", []string{"correlated-trace"}},
	{"a component emitting no telemetry is visible as a gap in the correlated trace", []string{"silent-component-is-a-gap"}},
}

// decideObservability decides ZT-27 from a record.json: every check a clause names is in the record as
// passed. It returns one line per clause with the checks' details.
func decideObservability(r io.Reader) ([]string, error) {
	var record struct {
		Checks []struct{ Check, Result, Detail string }
	}
	if err := json.NewDecoder(r).Decode(&record); err != nil {
		return nil, fmt.Errorf("record.json: %w", err)
	}
	result := map[string]string{}
	detail := map[string]string{}
	for _, c := range record.Checks {
		// A check recorded twice (an alert check per target) holds only when every entry passed.
		if prev, seen := result[c.Check]; !seen || prev == "passed" {
			result[c.Check] = c.Result
			detail[c.Check] = c.Detail
		}
	}
	var held, problems []string
	for _, clause := range observabilityClauses {
		for _, name := range clause.checks {
			switch result[name] {
			case "passed":
				held = append(held, clause.clause+": "+name+": "+detail[name])
			case "":
				problems = append(problems, name+" is not in the record")
			default:
				problems = append(problems, name+" "+result[name]+": "+detail[name])
			}
		}
	}
	if len(problems) > 0 {
		return held, errors.New(strings.Join(problems, "; "))
	}
	return held, nil
}

func (p *observabilityProof) contexts() []string {
	if z, d := os.Getenv("ZONE_CONTEXT"), os.Getenv("DEMONSTRATOR_CONTEXT"); z != "" || d != "" {
		return []string{z, d}
	}
	return []string{envOr("KUBE_CONTEXT", "kind-ztd")}
}

func (p *observabilityProof) backendsAreDeployed(ctx context.Context) error {
	if p.dryRun {
		return godog.ErrSkip
	}
	for _, name := range []string{"BDD_TARGET", "BDD_RUN_ID"} {
		if os.Getenv(name) == "" {
			return fmt.Errorf("the observability proof needs %s", name)
		}
	}
	clean := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	p.evidence = repoPath(filepath.Join("bundles/bdd/evidence/bdd-zt-027",
		clean.ReplaceAllString(os.Getenv("BDD_TARGET"), "-"), clean.ReplaceAllString(os.Getenv("BDD_RUN_ID"), "-")))
	var ready string
	for _, kc := range p.contexts() {
		out, err := exec.CommandContext(ctx, "kubectl", "--context", kc, "get", "deployments,daemonsets", "-A", "-o",
			`jsonpath={range .items[*]}{.metadata.name}={.status.readyReplicas}{.status.numberReady}/{.spec.replicas}{.status.desiredNumberScheduled}{"\n"}{end}`).CombinedOutput()
		if err != nil {
			return fmt.Errorf("the cluster %s is not reachable: %s", kc, strings.TrimSpace(string(out)))
		}
		ready += string(out)
	}
	for _, want := range observabilityWorkloads {
		found := false
		for _, line := range strings.Fields(ready) {
			name, counts, _ := strings.Cut(line, "=")
			have, of, _ := strings.Cut(counts, "/")
			if strings.HasPrefix(name, want) {
				if have == "" || have == "0" || have != of {
					return fmt.Errorf("%s is not ready (%s)", name, counts)
				}
				found = true
			}
		}
		if !found {
			return fmt.Errorf("no deployment or daemon set %s* on the cluster", want)
		}
	}
	return nil
}

func (p *observabilityProof) trafficAndDecisionsOccur(ctx context.Context) error {
	if p.dryRun {
		return godog.ErrSkip
	}
	// The verifier refuses a run directory inside the repository: it writes outside and the record is copied.
	tmp, err := os.MkdirTemp("", "bdd-zt-027-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	ctx, cancel := context.WithTimeout(ctx, 60*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, repoPath("scripts/verify-observability/verify.sh"))
	cmd.Env = append(os.Environ(), "ZTD_EVIDENCE_DIR="+tmp)
	out, err := cmd.CombinedOutput()
	p.output = string(out)
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		p.exit = exitErr.ExitCode()
	} else if err != nil {
		return fmt.Errorf("the verifier did not run: %w", err)
	}
	if p.exit == 125 {
		return fmt.Errorf("the verifier refused to run or stopped before its checks: %s", lastLines(p.output, 3))
	}
	if err := os.RemoveAll(p.evidence); err != nil {
		return err
	}
	return os.CopyFS(p.evidence, os.DirFS(tmp))
}

func (p *observabilityProof) rowHolds(context.Context) error {
	if p.dryRun {
		return godog.ErrSkip
	}
	f, err := os.Open(filepath.Join(p.evidence, "record.json"))
	if err != nil {
		return fmt.Errorf("the verifier wrote no record (exit %d): %w; %s", p.exit, err, lastLines(p.output, 3))
	}
	defer func() { _ = f.Close() }()
	held, decideErr := decideObservability(f)
	verdict := "passed"
	if decideErr != nil {
		verdict = "failed: " + decideErr.Error()
	}
	decision := fmt.Sprintf("row ZT-27\nrecord %s\nverifier exit %d (failed checks of the whole run)\nresult %s\n\nChecks decided on:\n%s\n",
		p.evidence, p.exit, verdict, strings.Join(held, "\n"))
	if err := os.WriteFile(filepath.Join(p.evidence, "decision.txt"), []byte(decision), 0o644); err != nil {
		return err
	}
	if decideErr != nil {
		return fmt.Errorf("ZT-27 not held: %w; record %s", decideErr, p.evidence)
	}
	fmt.Printf("ZT-27 held on %d checks (verifier exit %d); record %s\n", len(held), p.exit, p.evidence)
	return nil
}

func registerObservabilityProof(ctx *godog.ScenarioContext, dryRun bool) {
	p := &observabilityProof{}
	ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
		*p = observabilityProof{dryRun: dryRun}
		return c, nil
	})
	ctx.Step(`^the OpenTelemetry Collector, Prometheus and the OTel-compatible tracing backend are deployed$`, p.backendsAreDeployed)
	ctx.Step(`^demonstrator traffic and security decisions occur$`, p.trafficAndDecisionsOccur)
	ctx.Step(`^traces and metrics are exported from the cluster through the Collector, metrics are retained in Prometheus and traces are queryable in the tracing backend AND a component emitting no telemetry is visible as a gap in the correlated trace\.$`, p.rowHolds)
}
