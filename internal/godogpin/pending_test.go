// Package godogpin pins the godog behaviour the catalogue run relies on: with Strict off, a
// scenario whose step returns godog.ErrPending does not fail the suite; with Strict on it does.
// It lives apart from internal/bdd, whose TestMain runs the suite and never runs Test functions.
package godogpin

import (
	"io"
	"testing"

	"github.com/cucumber/godog"
)

func runPending(strict bool) int {
	return godog.TestSuite{
		ScenarioInitializer: func(ctx *godog.ScenarioContext) {
			ctx.Step(`^a clause not implemented yet$`, func() error { return godog.ErrPending })
		},
		Options: &godog.Options{
			Format: "progress",
			Output: io.Discard,
			Strict: strict,
			FeatureContents: []godog.Feature{{Name: "pin.feature", Contents: []byte(
				"Feature: pin\n\n  @pending\n  Scenario: a pending row\n    Given a clause not implemented yet\n")}},
		},
	}.Run()
}

func TestPendingPassesWhenNotStrict(t *testing.T) {
	if status := runPending(false); status != 0 {
		t.Fatalf("non-strict run with a pending step exited %d, want 0", status)
	}
}

func TestPendingFailsWhenStrict(t *testing.T) {
	if status := runPending(true); status == 0 {
		t.Fatal("strict run with a pending step exited 0, want a failure")
	}
}
