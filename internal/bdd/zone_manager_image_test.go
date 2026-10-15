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

// zoneManagerImage runs the @image regression feature: the TRAIN DNS zone manager image cases of
// scripts/train-zone-manager/image_test.sh, once per test binary, and reads each case's PASS or FAIL
// line. The script builds the image and drives it in Docker, so it needs docker, dig and a few
// minutes; it runs only when ZTD_IMAGE_TEST=1 and every step is skipped otherwise, as the cluster
// scenarios are in a pull request.
type zoneManagerImage struct{}

const imageCasesSwitch = "ZTD_IMAGE_TEST"

var imageCases struct {
	once   sync.Once
	err    error
	output string
	result map[string]string // case id (1a, 2b, ...) -> its PASS or FAIL line
}

func runImageCases() (map[string]string, error) {
	imageCases.once.Do(func() {
		evidence := repoPath("bundles/bdd/evidence/regression/train-zone-manager/image-cases.md")
		if err := os.MkdirAll(filepath.Dir(evidence), 0o755); err != nil {
			imageCases.err = err
			return
		}
		cmd := exec.Command(repoPath("scripts/train-zone-manager/image_test.sh"))
		cmd.Dir = repoRoot
		cmd.Env = append(os.Environ(), "EVIDENCE="+evidence)
		out, err := cmd.CombinedOutput()
		imageCases.output = string(out)
		imageCases.result = map[string]string{}
		scanner := bufio.NewScanner(strings.NewReader(imageCases.output))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 2 && (fields[0] == "PASS" || fields[0] == "FAIL") {
				imageCases.result[fields[1]] = strings.TrimSpace(scanner.Text())
			}
		}
		// A non-zero exit means at least one FAIL line, which the steps report case by case; any
		// other error is the script not having run at all.
		var exit *exec.ExitError
		if err != nil && !errors.As(err, &exit) {
			imageCases.err = fmt.Errorf("running the image cases: %w\n%s", err, imageCases.output)
		}
	})
	return imageCases.result, imageCases.err
}

func (z *zoneManagerImage) theCasesHaveRun() error {
	if os.Getenv(imageCasesSwitch) != "1" {
		return godog.ErrSkip
	}
	_, err := runImageCases()
	return err
}

// cases passes when every named case has a PASS line.
func (z *zoneManagerImage) cases(ids ...string) error {
	if os.Getenv(imageCasesSwitch) != "1" {
		return godog.ErrSkip
	}
	result, err := runImageCases()
	if err != nil {
		return err
	}
	for _, id := range ids {
		line, ok := result[id]
		if !ok {
			return fmt.Errorf("case %s has no result line; the script printed:\n%s", id, imageCases.output)
		}
		if strings.HasPrefix(line, "FAIL") {
			return errors.New(line)
		}
	}
	return nil
}

func registerZoneManagerImage(ctx *godog.ScenarioContext) {
	z := &zoneManagerImage{}
	ctx.Step(`^the zone manager image cases have run$`, z.theCasesHaveRun)
	for pattern, ids := range map[string][]string{
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
	} {
		ctx.Step(pattern, func() error { return z.cases(ids...) })
	}
}
