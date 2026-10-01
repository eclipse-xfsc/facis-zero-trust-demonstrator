package bdd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cucumber/godog"
)

// chartGate runs TDR-BDD-11 in the release workflow's chart gate: every chart passes lint, render and a
// server dry-run against a disposable cluster, each negative chart fails at the stage it targets, and
// the release workflow builds no candidate unless the gate passed.
//
//	KUBECONFIG              the disposable gate cluster, with the Cilium and Gatekeeper CRDs installed
//	BDD_TARGET, BDD_RUN_ID  name the target and the run in the evidence
//
// In the cluster dry run every step is skipped, so a pull request lists the row as not run.
type chartGate struct {
	dryRun   bool
	target   string
	run      string
	evidence string
	exits    map[string]int // release | lint-fails | dry-run-fails -> exit status of the gate script
	outputs  map[string]string
}

type chartResult struct {
	Chart, Version, Path, Dependencies, Lint, Template, ServerDryRun string
}

var negativeCharts = []string{"lint-fails", "dry-run-fails"}

func (g *chartGate) aReleaseCandidate() error {
	if g.dryRun {
		return godog.ErrSkip
	}
	for _, tool := range []string{"helm", "kubectl"} {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("the chart gate needs %s", tool)
		}
	}
	if out, err := exec.Command("kubectl", "version").CombinedOutput(); err != nil {
		return fmt.Errorf("the chart gate needs a reachable cluster: %s", strings.TrimSpace(string(out)))
	}
	g.target = envOr("BDD_TARGET", "local")
	g.run = envOr("BDD_RUN_ID", "local")
	g.evidence = repoPath(filepath.Join("bundles/bdd/evidence/bdd-tdr-011", g.target, "chart-gate"))
	return os.MkdirAll(g.evidence, 0o755)
}

func (g *chartGate) itsChartEntersTheGate() error {
	if g.dryRun {
		return godog.ErrSkip
	}
	g.exits, g.outputs = map[string]int{}, map[string]string{}
	runs := map[string][]string{"release": nil}
	for _, name := range negativeCharts {
		runs[name] = []string{repoPath(filepath.Join("features/fixtures/broken-charts", name))}
	}
	for name, charts := range runs {
		// A result left by an earlier run must not count for this one.
		if err := os.RemoveAll(filepath.Join(g.evidence, name)); err != nil {
			return err
		}
		args := append([]string{"--server-dry-run", "--evidence", filepath.Join(g.evidence, name)}, charts...)
		cmd := exec.Command(repoPath("scripts/ci/check-charts.sh"), args...)
		cmd.Dir = repoRoot
		out, err := cmd.CombinedOutput()
		g.outputs[name] = string(out)
		var exit *exec.ExitError
		switch {
		case err == nil:
			g.exits[name] = 0
		case errors.As(err, &exit):
			g.exits[name] = exit.ExitCode()
		default:
			return err
		}
	}
	return nil
}

func (g *chartGate) lintAndDryRunPassBeforePromotion() error {
	if g.dryRun {
		return godog.ErrSkip
	}
	var problems []string
	release, err := g.results("release")
	if err != nil {
		return err
	}
	if g.exits["release"] != 0 {
		problems = append(problems, "the release charts did not pass the gate:\n"+g.outputs["release"])
	}
	if len(release) == 0 {
		problems = append(problems, "the gate checked no chart")
	}
	for _, r := range release {
		if r.Lint != "passed" || r.Template != "passed" || r.ServerDryRun != "passed" {
			problems = append(problems, fmt.Sprintf("%s: lint %s, render %s, server dry-run %s", r.Chart, r.Lint, r.Template, r.ServerDryRun))
		}
	}
	// Each negative chart must be refused, and refused by the check it targets.
	want := map[string]func(chartResult) bool{
		"lint-fails":    func(r chartResult) bool { return r.Lint == "failed" },
		"dry-run-fails": func(r chartResult) bool { return r.Lint == "passed" && r.Template == "passed" && r.ServerDryRun == "failed" },
	}
	for _, name := range negativeCharts {
		results, err := g.results(name)
		if err != nil {
			return err
		}
		if g.exits[name] == 0 || len(results) != 1 || !want[name](results[0]) {
			problems = append(problems, fmt.Sprintf("negative chart %s was not refused by the check it targets: %+v", name, results))
		}
	}
	problems = append(problems, releaseWorkflowGated()...)
	if err := g.writeEvidence(problems); err != nil {
		return err
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
}

func (g *chartGate) results(name string) ([]chartResult, error) {
	files, err := filepath.Glob(filepath.Join(g.evidence, name, "*.json"))
	if err != nil {
		return nil, err
	}
	var out []chartResult
	for _, f := range files {
		var r chartResult
		content, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(content, &r); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// releaseWorkflowGated reads release.yml: the candidate job must need the chart gate, and the gate must
// run this row in cluster mode without anything that would let a failure pass.
func releaseWorkflowGated() []string {
	content, err := os.ReadFile(repoPath(".github/workflows/release.yml"))
	if err != nil {
		return []string{err.Error()}
	}
	text := string(content)
	var problems []string
	candidate, gate := jobBlock(text, "candidate"), jobBlock(text, "chart-gate")
	if !regexp.MustCompile(`(?m)^    needs: \[?[^\n]*\bchart-gate\b`).MatchString(candidate) {
		problems = append(problems, "release.yml: the candidate job does not need chart-gate")
	}
	if gate == "" || !strings.Contains(gate, "BDD_MODE=cluster ") || !strings.Contains(gate, "-godog.tags=@TDR-BDD-11") {
		problems = append(problems, "release.yml: the chart-gate job does not run TDR-BDD-11 in cluster mode")
	}
	if strings.Contains(gate, "continue-on-error") || strings.Contains(gate, "|| true") {
		problems = append(problems, "release.yml: the chart-gate job lets a failure pass")
	}
	return problems
}

// jobBlock returns the lines of one job under `jobs:` in a workflow, up to the next job.
func jobBlock(workflow, name string) string {
	start := regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(name) + `:\s*$`).FindStringIndex(workflow)
	if start == nil {
		return ""
	}
	rest := workflow[start[1]:]
	if next := regexp.MustCompile(`(?m)^  [a-z0-9-]+:\s*$`).FindStringIndex(rest); next != nil {
		rest = rest[:next[0]]
	}
	return rest
}

func (g *chartGate) writeEvidence(problems []string) error {
	record, _ := json.MarshalIndent(map[string]any{
		"label":    "disposable kind cluster with the Cilium and Gatekeeper CRDs; server dry-run proves render, API discovery and schemas, not runtime",
		"target":   g.target,
		"run":      g.run,
		"exits":    g.exits,
		"problems": problems,
	}, "", "  ")
	if err := os.WriteFile(filepath.Join(g.evidence, "gate.json"), record, 0o644); err != nil {
		return err
	}
	scenario, _ := json.MarshalIndent(map[string]any{
		"row": "TDR-BDD-11", "target": g.target, "run": g.run,
		"chart": "every chart under deployment/helm and features/fixtures/charts", "fixture": false,
	}, "", "  ")
	return os.WriteFile(filepath.Join(g.evidence, "scenario.json"), scenario, 0o644)
}

func registerChartGate(ctx *godog.ScenarioContext, dryRun bool) {
	g := &chartGate{}
	ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
		*g = chartGate{dryRun: dryRun}
		return c, nil
	})
	ctx.Step(`^a release candidate$`, g.aReleaseCandidate)
	ctx.Step(`^its Helm chart enters the CI quality gate$`, g.itsChartEntersTheGate)
	ctx.Step(`^helm lint and helm dry-run both pass before the release can be promoted\.$`, g.lintAndDryRunPassBeforePromotion)
}
