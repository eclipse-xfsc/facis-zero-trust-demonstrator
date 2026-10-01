package bdd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cucumber/godog"
)

// secretsBaseline decides TDR-BDD-08 in the release workflow's log-audit job, once both halves of the
// proof exist for the same run: the secrets-baseline job's evidence (restart.json and scan.json from
// scripts/secrets/baseline.sh on a disposable cluster) and this job's audit of that job's published
// log (log-audit.json from scripts/secrets/log_audit.py). Missing or mismatched evidence fails.
//
//	BDD_SECRETS_EVIDENCE    directory holding the three files
//	BDD_TARGET, BDD_RUN_ID  name the target and the run; every file must name the same run
//
// In the cluster dry run every step is skipped, so a pull request lists the row as not run.
type secretsBaseline struct {
	dryRun   bool
	target   string
	run      string
	source   string
	evidence string
	scan     struct {
		Run         string
		Stages      []string
		Result      string
		Errors      []string
		Baseline    []json.RawMessage
		Credentials struct {
			HeldInSecrets []string
		}
		NegativeControl struct {
			Detected bool
		}
	}
	restart struct {
		Run       string
		Persisted bool
	}
	audit struct {
		Run             string
		Result          string
		CanaryHits      *int
		ControlRedacted bool
	}
}

func (s *secretsBaseline) theDeployedReleaseAndCILogs() error {
	if s.dryRun {
		return godog.ErrSkip
	}
	s.source = os.Getenv("BDD_SECRETS_EVIDENCE")
	if s.source == "" {
		return errors.New("the secrets baseline needs BDD_SECRETS_EVIDENCE")
	}
	// The test binary runs in its own package directory; a relative path is the repository's.
	if !filepath.IsAbs(s.source) {
		s.source = repoPath(s.source)
	}
	s.target = envOr("BDD_TARGET", "local")
	s.run = envOr("BDD_RUN_ID", "local")
	for _, name := range []string{"scan.json", "restart.json", "log-audit.json"} {
		if _, err := os.Stat(filepath.Join(s.source, name)); err != nil {
			return fmt.Errorf("missing evidence %s: %w", name, err)
		}
	}
	return nil
}

func (s *secretsBaseline) storageAndLogsInspected() error {
	if s.dryRun {
		return godog.ErrSkip
	}
	for name, into := range map[string]any{"scan.json": &s.scan, "restart.json": &s.restart, "log-audit.json": &s.audit} {
		content, err := os.ReadFile(filepath.Join(s.source, name))
		if err != nil {
			return err
		}
		if err := json.Unmarshal(content, into); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func (s *secretsBaseline) credentialsInSecretsAndNoPlaintextInLogs() error {
	if s.dryRun {
		return godog.ErrSkip
	}
	var problems []string
	for name, run := range map[string]string{"scan.json": s.scan.Run, "restart.json": s.restart.Run, "log-audit.json": s.audit.Run} {
		if run != s.run {
			problems = append(problems, fmt.Sprintf("%s is from run %q, not %q", name, run, s.run))
		}
	}
	if s.scan.Result != "clean" || len(s.scan.Baseline) > 0 || len(s.scan.Errors) > 0 {
		problems = append(problems, fmt.Sprintf("canary scan: %s, %d finding(s), %d error(s)", s.scan.Result, len(s.scan.Baseline), len(s.scan.Errors)))
	}
	// The proof needs both scans: after the install, before anything is replaced, and at the end.
	if stages := strings.Join(s.scan.Stages, ","); !strings.Contains(","+stages+",", ",install,") || !strings.Contains(","+stages+",", ",final,") {
		problems = append(problems, fmt.Sprintf("canary scan: stages %q, want install and final", stages))
	}
	if !s.scan.NegativeControl.Detected {
		problems = append(problems, "canary scan: the negative control was not detected, so a clean result proves nothing")
	}
	held := strings.Join(s.scan.Credentials.HeldInSecrets, " ")
	for _, want := range []string{"ztd-openbao-bootstrap:unseal-key", "ztd-openbao-bootstrap:verify-token", "secret/ztd-canary-probe:credential"} {
		if !strings.Contains(held, want) {
			problems = append(problems, "not held in a Kubernetes Secret: "+want)
		}
	}
	if !s.restart.Persisted {
		problems = append(problems, "OpenBao did not keep its data across a restart and manual unseal")
	}
	if s.audit.Result != "clean" || s.audit.CanaryHits == nil || *s.audit.CanaryHits != 0 || !s.audit.ControlRedacted {
		problems = append(problems, fmt.Sprintf("pipeline log audit: %s", s.audit.Result))
	}
	if err := s.writeEvidence(problems); err != nil {
		return err
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
}

func (s *secretsBaseline) writeEvidence(problems []string) error {
	s.evidence = repoPath(filepath.Join("bundles/bdd/evidence/bdd-tdr-008", s.target, "secrets-baseline"))
	if err := os.MkdirAll(s.evidence, 0o755); err != nil {
		return err
	}
	for _, name := range []string{"scan.json", "restart.json", "log-audit.json"} {
		content, err := os.ReadFile(filepath.Join(s.source, name))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(s.evidence, name), content, 0o644); err != nil {
			return err
		}
	}
	verdict, _ := json.MarshalIndent(map[string]any{"run": s.run, "problems": problems}, "", "  ")
	if err := os.WriteFile(filepath.Join(s.evidence, "verdict.json"), verdict, 0o644); err != nil {
		return err
	}
	scenario, _ := json.MarshalIndent(map[string]any{
		"row": "TDR-BDD-08", "target": s.target, "run": s.run,
		"chart": "ztd (umbrella with OpenBao) on a disposable kind cluster, synthetic canary", "fixture": false,
	}, "", "  ")
	return os.WriteFile(filepath.Join(s.evidence, "scenario.json"), scenario, 0o644)
}

func registerSecretsBaseline(ctx *godog.ScenarioContext, dryRun bool) {
	s := &secretsBaseline{}
	ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
		*s = secretsBaseline{dryRun: dryRun}
		return c, nil
	})
	ctx.Step(`^the deployed release and CI/CD logs$`, s.theDeployedReleaseAndCILogs)
	ctx.Step(`^secret storage and log output are inspected$`, s.storageAndLogsInspected)
	ctx.Step(`^required credentials are held in Kubernetes Secrets and no plaintext secret value is present in logs\.$`, s.credentialsInSecretsAndNoPlaintextInLogs)
}
