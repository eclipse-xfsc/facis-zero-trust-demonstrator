package bdd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cucumber/godog"
)

type viewerDecision struct {
	Case       string `json:"case"`
	Status     int    `json:"status"`
	Dispatched int    `json:"dispatched"`
	Event      struct {
		Kind          string `json:"event"`
		CorrelationID string `json:"correlation_id"`
		State         string `json:"state"`
		Reason        string `json:"reason_code"`
	} `json:"event"`
}

func decideViewer(raw []byte) error {
	var record struct {
		Discovery bool             `json:"discovery"`
		Cases     []viewerDecision `json:"cases"`
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return err
	}
	if !record.Discovery {
		return errors.New("Keycloak discovery was not reached")
	}
	expected := map[string]struct {
		status, dispatched int
		state, reason      string
	}{
		"operator start":         {200, 1, "allowed", "UI-AUTHORISED"},
		"observer start":         {403, 0, "denied", "UI-NOT-AUTHORISED"},
		"observer configuration": {403, 0, "denied", "CFG-NOT-AUTHORISED"},
		"logged out operator":    {401, 0, "denied", "LOGGED_OUT"},
		"expired observer":       {401, 0, "denied", "EXPIRED"},
	}
	seen := map[string]bool{}
	for _, c := range record.Cases {
		want, ok := expected[c.Case]
		if !ok || c.Status != want.status || c.Dispatched != want.dispatched || c.Event.Kind != "ui.authorization" || c.Event.State != want.state || c.Event.Reason != want.reason || c.Event.CorrelationID == "" || seen[c.Event.CorrelationID] {
			return fmt.Errorf("missing or inconsistent viewer decision for %q", c.Case)
		}
		seen[c.Event.CorrelationID] = true
		delete(expected, c.Case)
	}
	if len(expected) != 0 {
		return errors.New("viewer proof is missing cases")
	}
	return nil
}

func registerKeycloakProof(ctx *godog.ScenarioContext, dryRun bool) {
	p := &servicesProof{}
	ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
		*p = servicesProof{dryRun: dryRun}
		return c, nil
	})
	ctx.Step(`^the target Keycloak, policy and token services are reachable$`, func() error {
		if err := p.setUp("bdd-tdr-005"); err != nil {
			return err
		}
		for _, name := range []string{"FACIS_OIDC_ISSUER", "FACIS_UI_ORIGIN", "BDD_OPERATOR_PASSWORD", "BDD_OBSERVER_PASSWORD", "KEYCLOAK_GUARD_TOKEN_FILE"} {
			if os.Getenv(name) == "" {
				return fmt.Errorf("the Keycloak proof needs %s", name)
			}
		}
		commit := exec.Command("git", "rev-parse", "HEAD")
		commit.Dir = repoRoot
		sha, err := commit.Output()
		if err != nil {
			return err
		}
		metadata, err := json.MarshalIndent(map[string]string{
			"target": os.Getenv("BDD_TARGET"), "run_id": os.Getenv("BDD_RUN_ID"),
			"commit": strings.TrimSpace(string(sha)), "kube_system_uid": "not-applicable-local-services",
			"execution": "working tree; real Keycloak and Go services, UIAuth in a Node harness; no mesh",
		}, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(p.evidence, "target.json"), append(metadata, '\n'), 0o600)
	})
	ctx.Step(`^a valid and an invalid access flow are executed$`, func(c context.Context) error {
		if dryRun {
			return godog.ErrSkip
		}
		cmd := exec.CommandContext(c, "node", repoPath("scripts/verify-keycloak/viewer.cjs"))
		cmd.Dir = repoRoot
		cmd.Env = append(os.Environ(), "KEYCLOAK_RECORD="+filepath.Join(p.evidence, "viewer.json"))
		// Do not capture a failing runtime's credentials in the evidence bundle.
		if err := cmd.Run(); err != nil {
			return errors.New("Keycloak viewer proof failed; no credentials logged")
		}
		// The successful proof created this file exclusively; never remove a pre-existing path.
		defer func() { _ = os.Remove(os.Getenv("KEYCLOAK_GUARD_TOKEN_FILE")) }()
		if err := p.run(c, pkgStoreServer, []string{testGuard}, "GUARD_CATALOGUE_OUT="+p.evidence); err != nil {
			return err
		}
		return p.run(c, pkgRenew, []string{testEndToEnd}, p.e2eRecord())
	})
	ctx.Step(`^the valid flow is authorized and the invalid flow is denied with traceable evidence\.$`, func() error {
		if dryRun {
			return godog.ErrSkip
		}
		raw, err := os.ReadFile(filepath.Join(p.evidence, "viewer.json"))
		if err != nil {
			return err
		}
		if err := decideViewer(raw); err != nil {
			return err
		}
		if err := p.passed(testGuard, testEndToEnd); err != nil {
			return err
		}
		cases, err := p.catalogue()
		if err != nil {
			return err
		}
		if _, err := allowedControl(cases); err != nil {
			return err
		}
		if err := denied(cases, "Keycloak viewer token", 401, "TOK-INVALID"); err != nil {
			return err
		}
		if err := denied(cases, "insufficient scope", 403, "POL-RULE-DENY"); err != nil {
			return err
		}
		policy := cases["insufficient scope"]
		if policy.PolicyEvent == nil || policy.PolicyEvent.CorrelationID != policy.CorrelationID || policy.PolicyEvent.Payload.State != "denied" || policy.PolicyEvent.Payload.ReasonCode != "POL-RULE-DENY" {
			return errors.New("no correlated policy refusal for insufficient scope")
		}
		return p.lines("vp-e2e.txt", linePresented, lineIssued, lineCalled, lineRevoked)
	})
}
