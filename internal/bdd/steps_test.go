// Package bdd runs the Go side of the acceptance suite with godog and emits
// cucumber-JSON, so its results merge with the JavaScript runner's into one
// report and one traceability sheet.
//
//	go test ./internal/bdd                          # strict: implemented, non-cluster scenarios
//	BDD_MODE=catalogue go test ./internal/bdd       # the @pending rows, reported as not run
//	BDD_MODE=cluster go test ./internal/bdd         # the @cluster rows, against a real cluster
//	BDD_MODE=cluster-dryrun go test ./internal/bdd  # the @cluster rows listed, every step skipped
//	go test ./internal/bdd -godog.tags=@regression  # narrow either mode further
package bdd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// modes are the filters and strictness of each run. The filter lives here, not on the command line,
// because the shared go-test job runs this package with no arguments: unset means strict.
var modes = map[string]struct {
	tags   string
	strict bool
}{
	"":          {"~@pending&&~@cluster", true},
	"strict":    {"~@pending&&~@cluster", true},
	"catalogue": {"@pending", false},
	// The cluster rows need a real cluster and its identities (admission_cluster_test.go). The dry run
	// lists them in a pull request's sheet as not run; only a cluster job can report them passed.
	"cluster":        {"@cluster&&~@pending", true},
	"cluster-dryrun": {"@cluster&&~@pending", false},
}

// withMode narrows a -godog.tags filter to the mode: godog reads "," as or and "&&" as and, so the
// mode's conjunction is added to every alternative.
func withMode(user, mode string) string {
	if user == "" {
		return mode
	}
	alternatives := strings.Split(user, ",")
	for i, alternative := range alternatives {
		alternatives[i] = alternative + "&&" + mode
	}
	return strings.Join(alternatives, ",")
}

func TestMain(m *testing.M) {
	testing.Init()
	flag.Parse()
	os.Exit(m.Run())
}

// TestFeatures runs the godog suite as an ordinary test, next to the package's plain unit tests (the
// matrix.csv decider of the ZT-55 scenario), in every mode. Running it inside the test binary's
// test log, not before it, matters to the go command's test cache: the environment it reads
// (BDD_MODE, GODOG_CUCUMBER_OUT, the cluster variables) and the feature files it opens are recorded
// as the run's inputs, so a run with another mode is never answered from the result of the last
// one. A run that writes a report is never cached at all: the report is a file of the module the
// test opened and has just written, which the go command refuses as a cache input - a cached result
// would leave no report behind.
func TestFeatures(t *testing.T) {
	mode, ok := modes[os.Getenv("BDD_MODE")]
	if !ok {
		t.Fatalf("BDD_MODE=%q: want strict (the default), catalogue, cluster or cluster-dryrun", os.Getenv("BDD_MODE"))
	}
	suiteOpts := opts
	suiteOpts.Tags = withMode(opts.Tags, mode.tags)
	suiteOpts.Strict = mode.strict

	// The cucumber formatter writes to a file so the report survives the run and
	// can be merged; without it the human-readable format stays on stdout.
	if path := os.Getenv("GODOG_CUCUMBER_OUT"); path != "" {
		// The test binary runs in its own package directory; a relative report
		// path is resolved against the repository root so it lands where the
		// pipeline and a developer both expect it.
		if !filepath.IsAbs(path) {
			path = repoPath(path)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		// A failure to flush the report would otherwise leave a truncated
		// report looking like a clean run.
		defer func() {
			if err := file.Close(); err != nil {
				t.Errorf("closing the report: %v", err)
			}
		}()
		suiteOpts.Format = "cucumber"
		suiteOpts.Output = file
	}

	if status := (godog.TestSuite{
		Name:                "facis-ztd",
		ScenarioInitializer: InitializeScenario,
		Options:             &suiteOpts,
	}.Run()); status != 0 {
		t.Errorf("godog suite exited with status %d", status)
	}
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

// planeSeparationCheck asserts that the plane-separation section of the
// architecture document satisfies the invariants it states about its own tables.
// It proves the design, not reachability: no cluster is involved.
type planeSeparationCheck struct {
	output   string
	exitCode int
}

func (p *planeSeparationCheck) thePlaneSeparationSectionOfTheArchitectureDocument() error {
	if _, err := os.Stat(repoPath("docs/architecture.md")); err != nil {
		return fmt.Errorf("no architecture document: %w", err)
	}
	return nil
}

func (p *planeSeparationCheck) thePlaneSeparationConformanceCheckRuns() error {
	cmd := exec.Command(repoPath("scripts/check-plane-separation.sh"))
	cmd.Dir = repoPath(".")
	output, err := cmd.CombinedOutput()
	p.output = string(output)
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		p.exitCode = exit.ExitCode()
		return nil
	}
	return err
}

func (p *planeSeparationCheck) itReportsNoRowThatBreaksAnInvariantTheSectionStates() error {
	if p.exitCode != 0 {
		return fmt.Errorf("the plane-separation check failed:\n%s", p.output)
	}
	return nil
}

func InitializeScenario(ctx *godog.ScenarioContext) {
	check := &hygieneCheck{}
	planes := &planeSeparationCheck{}
	ctx.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		*check = hygieneCheck{}
		*planes = planeSeparationCheck{}
		return ctx, nil
	})
	ctx.Step(`^the repository workflows$`, check.theRepositoryWorkflows)
	ctx.Step(`^the workflow hygiene check runs$`, check.theWorkflowHygieneCheckRuns)
	ctx.Step(`^it reports no unpinned action and no wildcard write scope$`, check.itReportsNoUnpinnedActionAndNoWildcardWriteScope)
	ctx.Step(`^the plane-separation section of the architecture document$`, planes.thePlaneSeparationSectionOfTheArchitectureDocument)
	ctx.Step(`^the plane-separation conformance check runs$`, planes.thePlaneSeparationConformanceCheckRuns)
	ctx.Step(`^it reports no row that breaks an invariant the section states$`, planes.itReportsNoRowThatBreaksAnInvariantTheSectionStates)
	dryRun := os.Getenv("BDD_MODE") == "cluster-dryrun"
	registerAdmissionProof(ctx, dryRun)
	registerChartGate(ctx, dryRun)
	registerSecretsBaseline(ctx, dryRun)
	registerPlaneSeparationProof(ctx, dryRun)
	registerPending(ctx)
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
