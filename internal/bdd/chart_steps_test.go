package bdd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cucumber/godog"
)

// chartCheck drives scripts/check-charts.sh the way the release job does and
// records what it produced, so the scenarios assert on the package directory
// rather than on the script's wording.
type chartCheck struct {
	charts     []string // chart directories named on the command line; none means the repository set
	expected   int      // release charts the positive scenario expects packaged
	version    string
	workDir    string
	packageDir string
	output     string
	exitCode   int
}

func (c *chartCheck) theReleaseCharts() error {
	matches, err := filepath.Glob(repoPath("deployment/helm/*/Chart.yaml"))
	if err != nil {
		return err
	}
	if len(matches) == 0 {
		return errors.New("no release chart under deployment/helm")
	}
	c.expected = len(matches)
	return nil
}

// The failing charts are written for the scenario rather than kept under
// features/fixtures: every chart there is linted by the pipeline, and a chart
// meant to fail would fail it.
func (c *chartCheck) aChartWhoseTemplateDoesNotRender() error {
	return c.writeChart("broken-render",
		"apiVersion: v2\nname: broken-render\nversion: 0.1.0\n",
		"{{ .Values.missing.key }}\n")
}

func (c *chartCheck) aChartWhoseMetadataDoesNotLint() error {
	// Chart.yaml without a name is a lint error, not a render error.
	return c.writeChart("broken-lint",
		"apiVersion: v2\nversion: 0.1.0\n",
		"kind: ConfigMap\n")
}

func (c *chartCheck) writeChart(name, chartYAML, template string) error {
	dir, err := c.scratch()
	if err != nil {
		return err
	}
	chart := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Join(chart, "templates"), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(chart, "Chart.yaml"), []byte(chartYAML), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(chart, "templates", "resource.yaml"), []byte(template), 0o644); err != nil {
		return err
	}
	c.charts = append(c.charts, chart)
	return nil
}

func (c *chartCheck) theChartCheckPackagesAtVersion(version string) error {
	dir, err := c.scratch()
	if err != nil {
		return err
	}
	c.version = version
	c.packageDir = filepath.Join(dir, "packages")

	args := append([]string{"--package", c.packageDir, "--version", version}, c.charts...)
	cmd := exec.Command(repoPath("scripts/check-charts.sh"), args...)
	cmd.Dir = repoPath(".")
	output, err := cmd.CombinedOutput()
	c.output = string(output)
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		c.exitCode = exit.ExitCode()
		return nil
	}
	return err
}

func (c *chartCheck) everyReleaseChartIsPackagedAtThatVersion() error {
	if c.exitCode != 0 {
		return fmt.Errorf("the chart check failed:\n%s", c.output)
	}
	packages, err := c.packages()
	if err != nil {
		return err
	}
	if len(packages) != c.expected {
		return fmt.Errorf("%d release chart(s) but %d package(s):\n%s", c.expected, len(packages), c.output)
	}
	for _, pkg := range packages {
		if !strings.HasSuffix(pkg, "-"+c.version+".tgz") {
			return fmt.Errorf("%s does not carry version %s", filepath.Base(pkg), c.version)
		}
	}
	if _, err := os.Stat(filepath.Join(c.packageDir, "SHA256SUMS")); err != nil {
		return fmt.Errorf("no checksum file beside the packages: %w", err)
	}
	return nil
}

func (c *chartCheck) theCheckFailsAndNoPackageIsProduced() error {
	if c.exitCode == 0 {
		return fmt.Errorf("the chart check passed a chart that must fail:\n%s", c.output)
	}
	packages, err := c.packages()
	if err != nil {
		return err
	}
	if len(packages) != 0 {
		return fmt.Errorf("%d package(s) produced for a failing chart: %v", len(packages), packages)
	}
	return nil
}

func (c *chartCheck) packages() ([]string, error) {
	return filepath.Glob(filepath.Join(c.packageDir, "*.tgz"))
}

// scratch is the scenario's temporary directory, created on first use and
// removed after the scenario.
func (c *chartCheck) scratch() (string, error) {
	if c.workDir == "" {
		dir, err := os.MkdirTemp("", "chart-check-")
		if err != nil {
			return "", err
		}
		c.workDir = dir
	}
	return c.workDir, nil
}

func initializeChartSteps(ctx *godog.ScenarioContext) {
	check := &chartCheck{}
	ctx.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		*check = chartCheck{}
		return ctx, nil
	})
	ctx.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		if check.workDir == "" {
			return ctx, nil
		}
		return ctx, os.RemoveAll(check.workDir)
	})
	ctx.Step(`^the release charts$`, check.theReleaseCharts)
	ctx.Step(`^a chart whose template does not render$`, check.aChartWhoseTemplateDoesNotRender)
	ctx.Step(`^a chart whose metadata does not lint$`, check.aChartWhoseMetadataDoesNotLint)
	ctx.Step(`^the chart check packages (?:them|it) at version "([^"]+)"$`, check.theChartCheckPackagesAtVersion)
	ctx.Step(`^every release chart is packaged at that version$`, check.everyReleaseChartIsPackagedAtThatVersion)
	ctx.Step(`^the check fails and no package is produced$`, check.theCheckFailsAndNoPackageIsProduced)
}
