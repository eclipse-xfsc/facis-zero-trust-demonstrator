package bdd

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cucumber/godog"
)

// caseScript is a shell script under scripts/ that prints one "PASS <id> ..." or "FAIL <id> ..."
// line per case. It runs once per test binary, when its switch variable is set to 1, and the steps
// of a regression feature read the line of each case they stand for. The two zone manager features
// use it: the image cases run in Docker, the chart cases on a throwaway kind cluster; both need
// tools and minutes a plain `go test` does not have, so without the switch every step is skipped,
// as the cluster scenarios are in a pull request.
type caseScript struct {
	path     string // relative to the repository root
	evidence string // relative to the repository root
	switchOn string // the environment variable that enables the run

	once   sync.Once
	err    error
	output string
	result map[string]string // case id -> its PASS or FAIL line
}

func (c *caseScript) run() (map[string]string, error) {
	c.once.Do(func() {
		evidence := repoPath(c.evidence)
		if err := os.MkdirAll(filepath.Dir(evidence), 0o755); err != nil {
			c.err = err
			return
		}
		cmd := exec.Command(repoPath(c.path))
		cmd.Dir = repoRoot
		cmd.Env = append(os.Environ(), "EVIDENCE="+evidence)
		out, err := cmd.CombinedOutput()
		c.output = string(out)
		c.result = map[string]string{}
		scanner := bufio.NewScanner(strings.NewReader(c.output))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 2 && (fields[0] == "PASS" || fields[0] == "FAIL") {
				c.result[fields[1]] = strings.TrimSpace(scanner.Text())
			}
		}
		// A non-zero exit means at least one FAIL line, which the steps report case by case; any
		// other error is the script not having run at all.
		var exit *exec.ExitError
		if err != nil && !errors.As(err, &exit) {
			c.err = fmt.Errorf("running %s: %w\n%s", c.path, err, c.output)
		}
	})
	return c.result, c.err
}

func (c *caseScript) enabled() bool { return os.Getenv(c.switchOn) == "1" }

func (c *caseScript) hasRun() error {
	if !c.enabled() {
		return godog.ErrSkip
	}
	_, err := c.run()
	return err
}

// cases passes when every named case has a PASS line.
func (c *caseScript) cases(ids ...string) error {
	if !c.enabled() {
		return godog.ErrSkip
	}
	result, err := c.run()
	if err != nil {
		return err
	}
	for _, id := range ids {
		line, ok := result[id]
		if !ok {
			return fmt.Errorf("case %s has no result line; %s printed:\n%s", id, c.path, c.output)
		}
		if strings.HasPrefix(line, "FAIL") {
			return errors.New(line)
		}
	}
	return nil
}

// register binds the "have run" step and one step per group of case ids.
func (c *caseScript) register(ctx *godog.ScenarioContext, ranStep string, steps map[string][]string) {
	ctx.Step(ranStep, c.hasRun)
	for pattern, ids := range steps {
		ctx.Step(pattern, func() error { return c.cases(ids...) })
	}
}

var zoneManagerImage = &caseScript{
	path:     "scripts/train-zone-manager/image_test.sh",
	evidence: "bundles/bdd/evidence/regression/train-zone-manager/image-cases.md",
	switchOn: "ZTD_IMAGE_TEST",
}

var zoneManagerChart = &caseScript{
	path:     "scripts/train-zone-manager/chart_test.sh",
	evidence: "bundles/bdd/evidence/regression/train-zone-manager/chart-cases.md",
	switchOn: "ZTD_CHART_TEST",
}

func registerZoneManager(ctx *godog.ScenarioContext) {
	zoneManagerImage.register(ctx, `^the zone manager image cases have run$`, map[string][]string{
		`^the image records the pinned upstream commit$`:              {"1a"},
		`^a patch that no longer applies fails the build$`:            {"1b"},
		`^the container is ready after its first start$`:              {"2a"},
		`^the DS is printed once$`:                                    {"2b"},
		`^the SOA is answered authoritatively over UDP and over TCP$`: {"2c", "2d"},
		`^the upstream base fails at import ldns$`:                    {"2e"},
		`^the container is ready again after a restart$`:              {"3a"},
		`^the zone is served with the same DNSKEY set$`:               {"3b", "3c"},
		`^the readiness command refuses a server with no zone$`:       {"3d"},
		`^the resign command exits 0$`:                                {"4a"},
		`^the SOA signature dates and the serial move forward$`:       {"4b", "4c"},
		`^a resign against a missing database fails$`:                 {"4d"},
		`^the image is linux/amd64$`:                                  {"5a"},
	})
	zoneManagerChart.register(ctx, `^the zone manager chart cases have run$`, map[string][]string{
		`^the release installs and the pod is ready$`:                           {"1a"},
		`^the zone answers from outside the cluster over UDP and TCP$`:          {"1b"},
		`^the DS is recorded and matches the served key$`:                       {"1c"},
		`^a server that stops serving the zone is pulled from the Service$`:     {"1d"},
		`^helm uninstall keeps both volumes$`:                                   {"2a"},
		`^a reinstall on the kept volumes serves the same key$`:                 {"2b"},
		`^the keeper takes a backup$`:                                           {"3a"},
		`^a fresh state volume is restored from the backup with the same key$`:  {"3b"},
		`^with both volumes gone a new key is created and the old DS is wrong$`: {"3c"},
		`^the keeper's resign moves the served signature$`:                      {"4a"},
		`^a resign against a missing database fails loudly$`:                    {"4b"},
		`^the daily run is scheduled$`:                                          {"4c"},
		`^the DNS Service carries UDP and TCP 53 on one address$`:               {"5a"},
		`^the release namespace is the management plane$`:                       {"5b"},
		`^the API answers a management-plane pod$`:                              {"5c"},
		`^the API is refused to a data-plane pod$`:                              {"5d"},
		`^the chart gate passes the chart$`:                                     {"6a"},
	})
}
