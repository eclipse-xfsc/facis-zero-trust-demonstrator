package bdd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// servicesProof runs the integration tests of the token path against the real PostgreSQL and OpenBao
// they need - the real connector, verification-service and token-store binaries, the guard runtime,
// the policy evaluator and the token verifier, wired in one process tree - and decides a row from the
// tests' results and the records they write. It is the cluster mode's local-services target: no
// Kubernetes cluster and no mesh are involved (the tests set the header a sidecar would set), which is
// why every record names where it ran. Every input comes from the environment; a missing one fails
// the scenario and is named.
//
//	TOKEN_STORE_TEST_DATABASE_URL  a PostgreSQL the tests may create databases in
//	TRANSIT_TEST_ADDR, TRANSIT_TEST_TOKEN  an OpenBao with the transit engine at transit/
//	BDD_TARGET, BDD_RUN_ID  name the target and the run in the evidence
//
// The evidence - each package's go test -json log and the tests' records - is written to
// bundles/bdd/evidence/<row>/<target>/<run>, which git ignores. A test that is skipped, missing or
// failed fails the row: the tests skip without their inputs, and a skip proves nothing. In the cluster
// dry run every step is skipped, so a pull request lists the rows as not run.
type servicesProof struct {
	dryRun   bool
	row      string
	evidence string
	results  map[string]string // top-level test -> pass | fail | skip
	logs     []string
}

var servicesInputs = []string{"TOKEN_STORE_TEST_DATABASE_URL", "TRANSIT_TEST_ADDR", "TRANSIT_TEST_TOKEN", "BDD_TARGET", "BDD_RUN_ID"}

func (p *servicesProof) setUp(row string) error {
	if p.dryRun {
		return godog.ErrSkip
	}
	for _, name := range servicesInputs {
		if os.Getenv(name) == "" {
			return fmt.Errorf("the %s proof needs %s", row, name)
		}
	}
	safe := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	p.row = row
	p.evidence = repoPath(filepath.Join("bundles/bdd/evidence", row,
		safe.ReplaceAllString(os.Getenv("BDD_TARGET"), "-"), safe.ReplaceAllString(os.Getenv("BDD_RUN_ID"), "-")))
	p.results = map[string]string{}
	if err := os.RemoveAll(p.evidence); err != nil {
		return err
	}
	return os.MkdirAll(p.evidence, 0o755)
}

// run runs the named top-level tests of one package and keeps its -json log as evidence. extra is added
// to the environment (the records' paths). A test failure is not an error here: it is decided by passed.
func (p *servicesProof) run(ctx context.Context, pkg string, tests []string, extra ...string) error {
	if p.dryRun {
		return godog.ErrSkip
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-json", "-timeout", "15m",
		"-run", "^("+strings.Join(tests, "|")+")$", "./"+pkg)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), extra...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	log := filepath.Join(p.evidence, strings.ReplaceAll(pkg, "/", "_")+".jsonl")
	p.logs = append(p.logs, log)
	if werr := os.WriteFile(log, append(out, stderr.Bytes()...), 0o644); werr != nil {
		return werr
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return fmt.Errorf("go test %s did not run: %w", pkg, err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 1<<20), 1<<24)
	for scanner.Scan() {
		var e struct{ Action, Test string }
		if json.Unmarshal(scanner.Bytes(), &e) == nil && e.Test != "" && !strings.Contains(e.Test, "/") &&
			(e.Action == "pass" || e.Action == "fail" || e.Action == "skip") {
			p.results[e.Test] = e.Action
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(p.results) == 0 && stderr.Len() > 0 {
		return fmt.Errorf("go test %s: %s", pkg, lastLines(stderr.String(), 5))
	}
	return nil
}

// passed fails unless every named test ran and passed.
func (p *servicesProof) passed(tests ...string) error {
	var bad []string
	for _, test := range tests {
		if got := p.results[test]; got != "pass" {
			if got == "" {
				got = "not run"
			}
			bad = append(bad, test+" "+got)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("%s: %s; logs %s", p.row, strings.Join(bad, ", "), strings.Join(p.logs, " "))
	}
	return nil
}

// lines checks that the record holds a line matching each pattern, in any order.
func (p *servicesProof) lines(record string, patterns ...string) error {
	raw, err := os.ReadFile(filepath.Join(p.evidence, record))
	if err != nil {
		return fmt.Errorf("%s: the tests wrote no %s: %w", p.row, record, err)
	}
	for _, pattern := range patterns {
		if !regexp.MustCompile(`(?m)` + pattern).Match(raw) {
			return fmt.Errorf("%s: %s holds no line matching %q", p.row, filepath.Join(p.evidence, record), pattern)
		}
	}
	return nil
}

// guardCase is one row of the catalogue TestGuardWithRealConnectorStorePolicyPostgresAndOpenBao writes.
type guardCase struct {
	Case          string         `json:"case"`
	Status        int            `json:"status"`
	ReasonCode    string         `json:"reason_code"`
	RuleID        string         `json:"rule_id"`
	CorrelationID string         `json:"correlation_id"`
	GuardEvent    *decisionEvent `json:"guard_event"`
	PolicyEvent   *decisionEvent `json:"policy_event"`
	Forwarded     *string        `json:"forwarded_request_id"`
}

type decisionEvent struct {
	CorrelationID string `json:"correlation_id"`
	Payload       struct {
		State      string `json:"state"`
		ReasonCode string `json:"reason_code"`
		RuleID     string `json:"rule_id"`
	} `json:"payload"`
}

func (p *servicesProof) catalogue() (map[string]guardCase, error) {
	path := filepath.Join(p.evidence, "catalogue.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: the guard test wrote no catalogue: %w", p.row, err)
	}
	var rows []guardCase
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cases := map[string]guardCase{}
	for _, row := range rows {
		cases[row.Case] = row
	}
	return cases, nil
}

// denied checks a refusal as the catalogue recorded it: its status and reason code, and the guard's own
// decision event under the correlation id the caller received, denied with the same code.
func denied(cases map[string]guardCase, name string, status int, code string) error {
	c, ok := cases[name]
	switch {
	case !ok:
		return fmt.Errorf("the catalogue holds no case %q", name)
	case c.Status != status || c.ReasonCode != code:
		return fmt.Errorf("%s: %d %s, want %d %s", name, c.Status, c.ReasonCode, status, code)
	case c.GuardEvent == nil || c.GuardEvent.CorrelationID != c.CorrelationID || c.GuardEvent.Payload.State != "denied" || c.GuardEvent.Payload.ReasonCode != code:
		return fmt.Errorf("%s: no denied guard event with %s under %s", name, code, c.CorrelationID)
	}
	return nil
}

// allowedControl checks the catalogue's allowed request: forwarded under its correlation id, with the
// guard's and the policy's allowed events under that same id.
func allowedControl(cases map[string]guardCase) (guardCase, error) {
	c, ok := cases["allowed (control)"]
	switch {
	case !ok:
		return c, errors.New("the catalogue holds no allowed request")
	case c.Status != 200 || c.Forwarded == nil || *c.Forwarded != c.CorrelationID:
		return c, fmt.Errorf("allowed request: status %d, not forwarded under %s", c.Status, c.CorrelationID)
	case c.GuardEvent == nil || c.GuardEvent.Payload.State != "allowed" || c.GuardEvent.CorrelationID != c.CorrelationID:
		return c, fmt.Errorf("allowed request: no allowed guard event under %s", c.CorrelationID)
	case c.PolicyEvent == nil || c.PolicyEvent.Payload.State != "allowed" || c.PolicyEvent.CorrelationID != c.CorrelationID:
		return c, fmt.Errorf("allowed request: no allowed policy event under %s", c.CorrelationID)
	}
	return c, nil
}

// The tests each row runs, by package.
const (
	pkgAuthelia    = "services/connector/internal/oauth2provider/authelia"
	pkgRenew       = "services/token-store/internal/renew"
	pkgStoreServer = "services/token-store/internal/server"
	pkgParticipant = "services/participant"
	testEndToEnd   = "TestEndToEndPresentationGrantTokenProtectedCallAndRenewal"
	testGuard      = "TestGuardWithRealConnectorStorePolicyPostgresAndOpenBao"
	testRevoked    = "TestARevokedCredentialEndsRenewalAtTheStore"
)

var (
	zt21Connector = []string{"TestRegistration_RegisteredClientObtainsBoundToken", "TestRegistration_RequiresAnAuthorisedToken",
		"TestVP_ChallengeThenOutcomeIssuesABoundSignedToken", "TestVP_EveryOutcomeRefusalCarriesItsCode",
		"TestVP_ClientNotAllowedTheGrantIsRefused", "TestDPoP_ValidProofIssuesBoundToken",
		"TestDPoP_BoundClientWithoutProofIsRefused", "TestInterface_TokenEndpointStatuses"}
	zt22Renewal = []string{testEndToEnd, "TestEveryRenewalPresentsTheCredentialAgainWithoutAPerson", testRevoked,
		"TestIssuerDownFailsTheTokenAndSubstitutionHasNoUpstream"}
	zt22Store = []string{testGuard, "TestSubstitute_ValidTokenYieldsTheAuthorizationAndAFreshProofAcceptedByB",
		"TestSubstitute_ExpiredOrFailedOnlyIsNoUpstream"}
)

// The lines of the end-to-end record (VP_E2E_RECORD) the rows decide on.
const (
	linePresented = `^acquisition: presentation verified, outcome \S+ signed by \S+`
	lineIssued    = `^acquisition: zone B consumed outcome \S+ for the verified-presentation grant and issued token \S+`
	lineCalled    = `^acquisition: protected call \S+ \S+ with the DPoP-bound token -> 200 `
	lineRevoked   = `^revoked credential: record = .* revoked CRED-REVOKED .*the store refused the outcome .*zone B consumed nothing`
	lineRepresent = `^renewal: fresh presentation for a new challenge, outcome \S+ \(first was \S+\)`
	lineRenewed   = `^renewal: zone B consumed outcome \S+ and issued token \S+; previous token \S+ is retired`
	lineRecalled  = `^renewal: protected call \S+ \S+ with the DPoP-bound token -> 200 `
)

func (p *servicesProof) e2eRecord() string {
	return "VP_E2E_RECORD=" + filepath.Join(p.evidence, "vp-e2e.txt")
}

func registerAuthorizationProofs(ctx *godog.ScenarioContext, dryRun bool) {
	p := &servicesProof{}
	ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
		*p = servicesProof{dryRun: dryRun}
		return c, nil
	})

	// ZT-21: DCR, the verified-presentation grant and DPoP binding at the connector's conformance suite,
	// and a real OID4VP presentation verified by the verification service and exchanged at the real
	// connector binary; a revoked credential, a refused outcome, an unknown client and a client without
	// the grant obtain nothing.
	ctx.Step(`^a registered participant backend and a valid OID4VP presentation$`, func() error { return p.setUp("bdd-zt-021") })
	ctx.Step(`^the Connector OAuth2 server processes the respective flows$`, func(c context.Context) error {
		if err := p.run(c, pkgAuthelia, zt21Connector); err != nil {
			return err
		}
		return p.run(c, pkgRenew, []string{testEndToEnd}, p.e2eRecord())
	})
	ctx.Step(`^it issues the appropriate DPoP-bound access tokens AND an invalid presentation or unregistered/unauthorized client does not receive a usable access token\.$`, func() error {
		if p.dryRun {
			return godog.ErrSkip
		}
		if err := p.passed(append(zt21Connector, testEndToEnd)...); err != nil {
			return err
		}
		return p.lines("vp-e2e.txt", linePresented, lineIssued, lineCalled, lineRevoked)
	})

	// ZT-22: the guard with the real connector, policy evaluator, token store, PostgreSQL and OpenBao:
	// the participant's token and proof checked, the store's upstream token substituted; the
	// renewal worker presenting again without a person; refusals for an invalid proof, an expired
	// token and a route the store cannot renew.
	ctx.Step(`^a participant-backend token and a stored counter-connector resource token$`, func() error { return p.setUp("bdd-zt-022") })
	ctx.Step(`^the backend calls the protected resource through the Connector$`, func(c context.Context) error {
		if err := p.run(c, pkgStoreServer, zt22Store, "GUARD_CATALOGUE_OUT="+p.evidence); err != nil {
			return err
		}
		return p.run(c, pkgRenew, zt22Renewal, p.e2eRecord())
	})
	ctx.Step(`^the backend token and DPoP proof are validated and the correct counter-side token is used upstream AND an invalid DPoP proof or expired/unrenewable token causes the request to be denied\.$`, func() error {
		if p.dryRun {
			return godog.ErrSkip
		}
		if err := p.passed(append(zt22Store, zt22Renewal...)...); err != nil {
			return err
		}
		cases, err := p.catalogue()
		if err != nil {
			return err
		}
		if _, err := allowedControl(cases); err != nil {
			return err
		}
		for _, refusal := range []struct {
			name string
			code string
		}{
			{"missing proof", "TOK-PROOF-INVALID"},
			{"proof signed by the wrong key", "TOK-JKT-MISMATCH"},
			{"replayed proof", "TOK-REPLAY"},
			{"expired token", "TOK-EXPIRED"},
		} {
			if err := denied(cases, refusal.name, 401, refusal.code); err != nil {
				return err
			}
		}
		return p.lines("vp-e2e.txt", lineIssued, lineRepresent, lineRenewed, lineRecalled)
	})

	// ZT-76: two credential roles mapped by the real connector into JWTs with different scopes and
	// answered differently by the resource; a real SD-JWT credential verified and exchanged; a revoked
	// credential and unmapped claims refused.
	ctx.Step(`^credentials that map to different application roles and a credential that is invalid/revoked$`, func() error { return p.setUp("bdd-zt-076") })
	ctx.Step(`^they are exchanged/verified and used to access the protected resource$`, func(c context.Context) error {
		if err := p.run(c, pkgParticipant, []string{"TestTokenPathEndToEnd"}); err != nil {
			return err
		}
		if err := p.run(c, pkgAuthelia, []string{"TestVP_UnmappedClaimsAreDenied"}); err != nil {
			return err
		}
		return p.run(c, pkgRenew, []string{testEndToEnd, testRevoked}, p.e2eRecord())
	})
	ctx.Step(`^valid credentials are mapped into the intended JWT/role authorization and return the permitted response AND invalid/revoked credentials do not grant protected access\.$`, func() error {
		if p.dryRun {
			return godog.ErrSkip
		}
		if err := p.passed("TestTokenPathEndToEnd", "TestVP_UnmappedClaimsAreDenied", testEndToEnd, testRevoked); err != nil {
			return err
		}
		return p.lines("vp-e2e.txt", linePresented, lineIssued, lineCalled, lineRevoked)
	})
}
