package bdd

import (
	"context"
	"fmt"

	"github.com/cucumber/godog"
)

// registerPolicyProofs decides ZT-06 from the guard test with the real connector, policy evaluator, token
// store, PostgreSQL and OpenBao (servicesProof, authorization_cluster_test.go): two participants log in
// through the verified-presentation grant, one whose outcome carries a role the policy entitles to the
// resource and one whose role maps to an unrelated scope; the first is allowed by the policy, the second
// refused by the policy's rule, with the guard's and the policy's events under the caller's correlation id.
func registerPolicyProofs(ctx *godog.ScenarioContext, dryRun bool) {
	p := &servicesProof{}
	ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
		*p = servicesProof{dryRun: dryRun}
		return c, nil
	})
	ctx.Step(`^one participant backend with the required credential attributes and one without them$`, func() error { return p.setUp("bdd-zt-006") })
	ctx.Step(`^both request the same protected resource$`, func(c context.Context) error {
		return p.run(c, pkgStoreServer, []string{testGuard}, "GUARD_CATALOGUE_OUT="+p.evidence)
	})
	ctx.Step(`^the authorized request is permitted according to credential/policy evaluation AND the request without matching attributes/authorization is denied and evidenced\.$`, func() error {
		if p.dryRun {
			return godog.ErrSkip
		}
		if err := p.passed(testGuard); err != nil {
			return err
		}
		cases, err := p.catalogue()
		if err != nil {
			return err
		}
		allowed, err := allowedControl(cases)
		if err != nil {
			return err
		}
		if allowed.PolicyEvent.Payload.RuleID != "m3-report-summary" {
			return fmt.Errorf("allowed request: policy rule %q, want m3-report-summary", allowed.PolicyEvent.Payload.RuleID)
		}
		const name, rule = "insufficient scope", "m3-scope-required"
		if err := denied(cases, name, 403, "POL-RULE-DENY"); err != nil {
			return err
		}
		c := cases[name]
		if c.RuleID != rule || c.PolicyEvent == nil || c.PolicyEvent.CorrelationID != c.CorrelationID ||
			c.PolicyEvent.Payload.State != "denied" || c.PolicyEvent.Payload.RuleID != rule {
			return fmt.Errorf("%s: no denied policy event with rule %s under %s", name, rule, c.CorrelationID)
		}
		return nil
	})
}
