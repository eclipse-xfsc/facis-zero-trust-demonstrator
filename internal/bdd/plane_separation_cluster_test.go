package bdd

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// planeSeparationProof runs ZT-55 against an installed zone: it runs the reachability verifier
// (scripts/verify-plane-separation/verify.sh) and decides the row from the matrix.csv the verifier records,
// row by row, so that the row's result is the record's. Every input comes from the environment; a missing
// one fails the scenario and is named.
//
//	KUBECONFIG     kubeconfig of the cluster the zone runs on
//	BDD_ZONE_FILE  the zone file the zone was installed with
//	BDD_TARGET     target name (default local), BDD_RUN_ID run identifier
//	KUBE_CONTEXT   the verifier's context (default kind-ztd); a participant cluster needs ZTD_CONFIRM_CLUSTER too
//
// The record is written to bundles/bdd/evidence/bdd-zt-055/<target>/<run>, which git ignores. In the
// cluster dry run (BDD_MODE=cluster-dryrun) every step is skipped, so a pull request lists the row as not
// run and can never report it as passed.
type planeSeparationProof struct {
	dryRun   bool
	zoneFile string
	evidence string
	exit     int
	output   string
}

// reverseRow is the row of section 6's management plane -> data plane table, the direction the verifier
// probes from the management-plane namespaces.
const reverseRow = "management-to-data"

// The columns of matrix.csv, in order (scripts/verify-plane-separation/README.md).
var planeMatrixColumns = []string{"row", "role", "namespace", "probe", "caller", "destination", "port", "expected", "outcome", "layer", "evidence", "kind", "verdict"}

// decidePlaneMatrix decides each row of a matrix.csv: failed when one of its probes failed (or carries a
// verdict the verifier does not write), declared when one is a declared opening and none failed, green
// otherwise. It returns the rows' verdicts, one line each in row order, and an error naming every row that
// is not green or declared; an empty matrix, a header that is not the verifier's, or a matrix that lacks
// either direction (the row management-to-data, or every other row) is an error too.
func decidePlaneMatrix(r io.Reader) ([]string, error) {
	records, err := csv.NewReader(r).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("matrix.csv: %w", err)
	}
	if len(records) == 0 || strings.Join(records[0], ",") != strings.Join(planeMatrixColumns, ",") {
		return nil, errors.New("matrix.csv: the header is not the verifier's")
	}
	verdict := map[string]string{}
	var order []string
	for _, rec := range records[1:] {
		row, v := rec[0], rec[len(rec)-1]
		cur, seen := verdict[row]
		if !seen {
			order = append(order, row)
			cur = "green"
		}
		switch {
		case v == "fail" || (v != "pass" && v != "n/a" && v != "declared"):
			cur = "failed"
		case v == "declared" && cur == "green":
			cur = "declared"
		}
		verdict[row] = cur
	}
	if len(order) == 0 {
		return nil, errors.New("matrix.csv holds no probe, so it decides no row")
	}
	lines := make([]string, 0, len(order))
	var failed []string
	for _, row := range order {
		lines = append(lines, row+" "+verdict[row])
		if verdict[row] == "failed" {
			failed = append(failed, row)
		}
	}
	// Both planes are tested: the row of the management plane -> data plane direction and at least one row
	// of the data plane -> management plane direction must be in the matrix.
	if _, ok := verdict[reverseRow]; !ok {
		return lines, errors.New("matrix.csv holds no line of the row " + reverseRow + ": the management plane -> data plane direction was not probed")
	}
	if len(order) == 1 {
		return lines, errors.New("matrix.csv holds no row of the data plane -> management plane direction")
	}
	if len(failed) > 0 {
		sort.Strings(failed)
		return lines, fmt.Errorf("rows not held: %s", strings.Join(failed, ", "))
	}
	return lines, nil
}

func (p *planeSeparationProof) zoneIsDeployed(ctx context.Context) error {
	if p.dryRun {
		return godog.ErrSkip
	}
	for _, name := range []string{"KUBECONFIG", "BDD_ZONE_FILE", "BDD_TARGET", "BDD_RUN_ID"} {
		if os.Getenv(name) == "" {
			return fmt.Errorf("the plane-separation proof needs %s", name)
		}
	}
	p.zoneFile = os.Getenv("BDD_ZONE_FILE")
	if _, err := os.Stat(p.zoneFile); err != nil {
		return fmt.Errorf("BDD_ZONE_FILE: %w", err)
	}
	run := regexp.MustCompile(`[^a-zA-Z0-9._-]`).ReplaceAllString(os.Getenv("BDD_RUN_ID"), "-")
	target := regexp.MustCompile(`[^a-zA-Z0-9._-]`).ReplaceAllString(os.Getenv("BDD_TARGET"), "-")
	p.evidence = repoPath(filepath.Join("bundles/bdd/evidence/bdd-zt-055", target, run))
	// The plane namespaces exist: the verifier finds the data plane by its label.
	out, err := exec.CommandContext(ctx, "kubectl", "--context", envOr("KUBE_CONTEXT", "kind-ztd"),
		"get", "ns", "-l", "ztd.facis.io/plane", "-o", "name").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "namespace/") {
		return fmt.Errorf("no plane namespace on the cluster: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *planeSeparationProof) reachabilityIsTested(ctx context.Context) error {
	if p.dryRun {
		return godog.ErrSkip
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, repoPath("scripts/verify-plane-separation/verify.sh"))
	cmd.Env = append(os.Environ(), "ZTD_EVIDENCE_DIR="+p.evidence, "ZONE_VALUES="+p.zoneFile)
	out, err := cmd.CombinedOutput()
	p.output = string(out)
	p.exit = 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		p.exit = exitErr.ExitCode()
	} else if err != nil {
		return fmt.Errorf("the verifier did not run: %w", err)
	}
	if p.exit == 125 {
		return fmt.Errorf("the verifier refused to run: %s", lastLines(p.output, 3))
	}
	return nil
}

func (p *planeSeparationProof) onlyControlChannelsReach(ctx context.Context) error {
	if p.dryRun {
		return godog.ErrSkip
	}
	f, err := os.Open(filepath.Join(p.evidence, "matrix.csv"))
	if err != nil {
		return fmt.Errorf("the verifier wrote no matrix (exit %d): %w; %s", p.exit, err, lastLines(p.output, 3))
	}
	defer func() { _ = f.Close() }()
	rows, err := decidePlaneMatrix(f)
	report := strings.Join(rows, "; ")
	if err != nil {
		return fmt.Errorf("%w (%s); record %s", err, report, p.evidence)
	}
	if p.exit != 0 {
		return fmt.Errorf("every row held (%s) but %d check(s) of the run failed; record %s", report, p.exit, p.evidence)
	}
	fmt.Printf("ZT-55 rows: %s; record %s\n", report, p.evidence)
	return nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

func registerPlaneSeparationProof(ctx *godog.ScenarioContext, dryRun bool) {
	p := &planeSeparationProof{}
	ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
		*p = planeSeparationProof{dryRun: dryRun}
		return c, nil
	})
	ctx.Step(`^management-plane services and application/data-plane workloads are deployed$`, p.zoneIsDeployed)
	ctx.Step(`^reachability is tested from both planes$`, p.reachabilityIsTested)
	ctx.Step(`^management services are reachable only through dedicated control channels and are separated by network-policy and service-mesh controls AND data-plane compromise/reachability does not provide access to management-plane endpoints\.$`, p.onlyControlChannelsReach)
}
