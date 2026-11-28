package bdd

import (
	"context"
	"os"
	"path/filepath"

	"github.com/cucumber/godog"
)

// The API dock rows (docs/api-dock.md), on the local-services target of servicesProof: the real
// connector binary on PostgreSQL and OpenBao, the Participant and the Resource built as their binaries
// build them.
//
// ZT-07 is decided with a local stand-in docked as the cloud API. ZT-77 needs the real provider:
// API_DOCK_LIVE_TOKEN_FILE names a file holding its token. Without that file the row is skipped, so
// it is reported not run; it is never decided from the stand-in.
const (
	pkgConnector     = "services/connector"
	pkgResource      = "services/protectedresource"
	testDockJourney  = "TestAPIDockJourney"
	testDockLive     = "TestAPIDockLive"
	testRegistration = "TestServeBootstrapsTheRegistrarAndIssuesVerifiableTokens"
	dockRecord       = "api-dock.txt"
	liveTokenFileEnv = "API_DOCK_LIVE_TOKEN_FILE"
)

var dockResourceTests = []string{"TestCloudDock", "TestCloudScopeBoundary", "TestCloudSettingsRejected", "TestCloudInterfaceCheck"}

// dockLines are the record lines of a journey with both mocks replaced, on the named upstream.
func dockLines(upstream string) []string {
	return []string{
		`^baseline: supplied participant -> Connector token -> supplied resource mock -> 200 RESOURCE_REPORT_RETURNED `,
		`^resource dock: cloud-api adapter on the ` + upstream + ` accepted by the configuration-time interface check$`,
		`^journey: supplied participant -> Connector token -> docked resource \(` + upstream + `\) -> 200 RESOURCE_REPORT_RETURNED report CLOUD-DATACENTERS: \d+ data centers `,
		`^participant dock: replacement participant backend registered through DCR -> verified-presentation token -> docked resource \(` + upstream + `\) -> 200 RESOURCE_REPORT_RETURNED report CLOUD-DATACENTERS$`,
		`^core unchanged: one Connector process, JWKS digest \S+ and resource trust settings digest \S+ before and after the dock$`,
	}
}

func registerAPIDockProofs(ctx *godog.ScenarioContext, dryRun bool) {
	p := &servicesProof{}
	ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
		*p = servicesProof{dryRun: dryRun}
		return c, nil
	})
	record := func() string { return "API_DOCK_RECORD=" + filepath.Join(p.evidence, dockRecord) }

	// ZT-07: the stand-in docked behind the Resource and a second participant backend, both serving the
	// journey on one unchanged Connector; a non-conforming API refused when the Resource is configured,
	// a non-conforming participant backend refused when it is registered at the Connector.
	ctx.Step(`^the documented participant-backend and protected-resource interfaces$`, func() error {
		if err := p.setUp("bdd-zt-007"); err != nil {
			return err
		}
		_, err := os.Stat(repoPath("docs/api-dock.md"))
		return err
	})
	ctx.Step(`^a replacement API is docked in place of the supplied mock$`, func(c context.Context) error {
		if err := p.run(c, pkgParticipant, []string{testDockJourney}, record()); err != nil {
			return err
		}
		if err := p.run(c, pkgResource, dockResourceTests); err != nil {
			return err
		}
		return p.run(c, pkgConnector, []string{testRegistration})
	})
	ctx.Step(`^it serves the demonstrator flow with no change to Connector, policy or trust configuration AND an API that does not satisfy the documented interface is rejected at configuration time\.$`, func() error {
		if p.dryRun {
			return godog.ErrSkip
		}
		if err := p.passed(append([]string{testDockJourney, testRegistration}, dockResourceTests...)...); err != nil {
			return err
		}
		return p.lines(dockRecord, append(dockLines("local stand-in"),
			`^rejected at configuration time: an API answering another interface -> CLOUD_INTERFACE_REJECTED cause CLOUD_RESPONSE_INVALID, recorded, resource not started$`,
			`^rejected at configuration time: an adapter name the resource does not know$`)...)
	})

	// ZT-77: the same journey with the provider's own API docked. Skipped without the token file.
	ctx.Step(`^the participant-backend and protected-resource mocks in the running demonstrator$`, func() error {
		if _, err := os.Stat(os.Getenv(liveTokenFileEnv)); err != nil {
			return godog.ErrSkip
		}
		return p.setUp("bdd-zt-077")
	})
	ctx.Step(`^each is replaced by a real-world API through the documented interface$`, func(c context.Context) error {
		return p.run(c, pkgParticipant, []string{testDockLive}, record())
	})
	ctx.Step(`^the demonstrator journey completes against the real API with no change to the Zero Trust core AND the replacement is demonstrated end to end at least once\.$`, func() error {
		if p.dryRun {
			return godog.ErrSkip
		}
		if err := p.passed(testDockLive); err != nil {
			return err
		}
		return p.lines(dockRecord, dockLines("live provider")...)
	})
}
