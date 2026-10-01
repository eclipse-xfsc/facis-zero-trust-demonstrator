// Package bdd runs the Go side of the acceptance suite with godog and emits
// cucumber-JSON, so its results merge with the JavaScript runner's into one
// report and one traceability sheet.
//
//	go test ./internal/bdd                      # run every scenario
//	go test ./internal/bdd -godog.tags=@ZT-56    # run one Annex row
package bdd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cucumber/godog"
	"github.com/cucumber/godog/colors"
)

// The two runners own separate directories. godog reads a directory
// recursively, so pointing it at features/ would make it load the JavaScript
// scenarios too, report their steps as undefined, and - with Strict off - still
// pass, marking their Annex rows covered by scenarios that never ran.
var opts = godog.Options{
	Format: "pretty",
	Paths:  []string{"../../features/go"},
	Strict: true,
	Output: colors.Colored(os.Stdout),
}

func init() {
	godog.BindFlags("godog.", flag.CommandLine, &opts)
}

func TestMain(m *testing.M) {
	testing.Init()
	flag.Parse()

	// The cucumber formatter writes to a file so the report survives the run and
	// can be merged; without it the human-readable format stays on stdout.
	closeReport := func() error { return nil }
	if path := os.Getenv("GODOG_CUCUMBER_OUT"); path != "" {
		// The test binary runs in its own package directory; a relative report
		// path is resolved against the repository root so it lands where the
		// pipeline and a developer both expect it.
		if !filepath.IsAbs(path) {
			path = repoPath(path)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		file, err := os.Create(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		closeReport = file.Close
		opts.Format = "cucumber"
		opts.Output = file
	}

	status := godog.TestSuite{
		Name:                "facis-ztd",
		ScenarioInitializer: InitializeScenario,
		Options:             &opts,
	}.Run()

	// os.Exit skips deferred calls, so the report is closed here - a failure to
	// flush it would otherwise leave a truncated report looking like a clean run.
	if err := closeReport(); err != nil {
		fmt.Fprintln(os.Stderr, "closing the report:", err)
		os.Exit(1)
	}
	os.Exit(status)
}

type hygieneCheck struct {
	output   string
	exitCode int
}

func (h *hygieneCheck) theRepositoryWorkflows() error {
	if _, err := os.Stat(repoPath(".github/workflows")); err != nil {
		return fmt.Errorf("no workflow directory: %w", err)
	}
	return nil
}

func (h *hygieneCheck) theWorkflowHygieneCheckRuns() error {
	cmd := exec.Command(repoPath("scripts/check-workflow-hygiene.sh"))
	cmd.Dir = repoPath(".")
	output, err := cmd.CombinedOutput()
	h.output = string(output)
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		h.exitCode = exit.ExitCode()
		return nil
	}
	return err
}

func (h *hygieneCheck) itReportsNoUnpinnedActionAndNoWildcardWriteScope() error {
	if h.exitCode != 0 {
		return fmt.Errorf("the hygiene check failed:\n%s", h.output)
	}
	return nil
}

func InitializeScenario(ctx *godog.ScenarioContext) {
	check := &hygieneCheck{}
	ctx.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		*check = hygieneCheck{}
		return ctx, nil
	})
	ctx.Step(`^the repository workflows$`, check.theRepositoryWorkflows)
	ctx.Step(`^the workflow hygiene check runs$`, check.theWorkflowHygieneCheckRuns)
	ctx.Step(`^it reports no unpinned action and no wildcard write scope$`, check.itReportsNoUnpinnedActionAndNoWildcardWriteScope)

	initializeChartSteps(ctx)
}

// repoRoot is resolved once. Failing to locate it is a setup failure like any
// other in this file, and is reported the same way rather than as a panic.
var repoRoot = func() string {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot resolve the repository root:", err)
		os.Exit(1)
	}
	return root
}()

// repoPath resolves a path against the repository root and returns it absolute,
// so a scenario runs the same way from `go test ./...` and from the pipeline.
// os/exec resolves a relative command path against the command's own directory,
// which is why this cannot stay relative.
func repoPath(rel string) string {
	return filepath.Join(repoRoot, rel)
}
