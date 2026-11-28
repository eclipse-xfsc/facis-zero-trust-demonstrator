package bdd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cucumber/godog"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
)

const applicationFeedTest = "TestApplicationFeedEndToEnd"

// ZT-75 uses the local-services cluster target: real Connector/PostgreSQL/OpenBao, participant,
// token verifier, protected resource and IF-01 bridge. A skipped test cannot satisfy the row.
// ZT-74 needs the trusted channel, which this target does not have: participant_mock_cluster_test.go.
func registerApplicationMockProofs(ctx *godog.ScenarioContext, dryRun bool) {
	p := &servicesProof{}
	ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
		*p = servicesProof{dryRun: dryRun}
		return c, nil
	})
	ctx.Step(`^the protected-resource mock exposes responses for different access roles$`, func() error { return p.setUp("bdd-zt-075") })
	run := func(c context.Context) error {
		return p.run(c, pkgParticipant, []string{applicationFeedTest}, "APPLICATION_FEED_RECORD="+filepath.Join(p.evidence, "feed.json"))
	}
	ctx.Step(`^requests with different authorized and unauthorized roles are executed$`, run)
	check := func() error {
		if p.dryRun {
			return godog.ErrSkip
		}
		if err := p.passed(applicationFeedTest); err != nil {
			return err
		}
		raw, err := os.ReadFile(filepath.Join(p.evidence, "feed.json"))
		if err != nil {
			return err
		}
		var events []hook.Event
		if err := json.Unmarshal(raw, &events); err != nil {
			return err
		}
		return checkApplicationFeed(events)
	}
	ctx.Step(`^role-appropriate responses are returned and visualized AND unauthorized roles do not receive protected content\.$`, check)
}

func checkApplicationFeed(events []hook.Event) error {
	required := map[string]bool{
		"participant-a/registration/registered":                      false,
		"participant-a/registration/failed_registration":             false,
		"participant-a/status/ready":                                 false,
		"participant-a/request/success":                              false,
		"participant-a/request/denied":                               false,
		"protected-resource-b/access role=reader/success":            false,
		"protected-resource-b/access role=viewer/success":            false,
		"protected-resource-b/access role=reader_and_viewer/success": false,
		"protected-resource-b/access role=unauthorized/denied":       false,
		"protected-resource-b/access role=not_evaluated/denied":      false,
	}
	accesses := 0
	for _, event := range events {
		if event.Version != 2 || event.Kind != "step" || event.CorrelationID == "" {
			return fmt.Errorf("invalid application feed record")
		}
		key := event.Source + "/" + event.Payload.Detail + "/" + event.Payload.State
		if _, ok := required[key]; ok {
			required[key] = true
		}
		if event.Source == "protected-resource-b" {
			accesses++
		}
		if key == "participant-a/request/denied" || key == "protected-resource-b/access role=unauthorized/denied" {
			reason := "APP-RESOURCE-SCOPE-INSUFFICIENT"
			if event.Source == "participant-a" {
				reason = "APP-TOKEN-FORBIDDEN"
			}
			if event.CorrelationID != "outsider" || event.Payload.ReasonCode != reason {
				return fmt.Errorf("scope refusal lost correlation or reason")
			}
		}
		if key == "participant-a/registration/failed_registration" && event.Payload.ReasonCode != "APP-REGISTRATION-REJECTED" {
			return fmt.Errorf("registration refusal lost reason")
		}
	}
	for key, seen := range required {
		if !seen {
			return fmt.Errorf("feed missing %s", key)
		}
	}
	if accesses != 9 {
		return fmt.Errorf("feed contains %d accesses, want all 9", accesses)
	}
	return nil
}
