package bdd

import (
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

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/trustlist"
)

// allowListProof runs ZT-18 on the cluster mode's local-services target: the verifier
// scripts/verify-train-allow-list/verify.sh starts our TSPA image and Keycloak on Docker, publishes a
// trust list naming one counter-connector, and sends requests through two counter-connectors (the
// connector-gateway chart's egress role, one certificate each) to an entry (its ingress role with the
// allow list, `connector admit-peers` beside it). The row is decided from the verifier's record: the
// trust list the TSPA served, and per attempt the status, the reason code and the decision event
// `connector admit-peers` wrote. No Kubernetes cluster is involved, which the record states.
//
//	BDD_TARGET, BDD_RUN_ID  name the target and the run in the evidence
//
// The record is written to bundles/bdd/evidence/bdd-zt-018/<target>/<run>, which git ignores. In the
// cluster dry run every step is skipped.
type allowListProof struct {
	dryRun   bool
	evidence string
	exit     int
	output   string
	cases    map[string]allowListCase
}

// permittedPeer is the counter-connector the verifier's trust list names (its `listed`).
const permittedPeer = "did:web:connector-a.facis-ztd.local"

// allowListCase is one attempt of the verifier's record.json.
type allowListCase struct {
	Case     string `json:"case"`
	Status   int    `json:"status"`
	Reason   string `json:"reason_code"`
	Upstream int    `json:"upstream_requests"`
	Event    *struct {
		Kind    string `json:"kind"`
		Payload struct {
			State      string `json:"state"`
			ReasonCode string `json:"reason_code"`
			Detail     string `json:"detail"`
		} `json:"payload"`
	} `json:"event"`
}

func readAllowListRecord(path string) (map[string]allowListCase, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("the verifier wrote no record: %w", err)
	}
	var rows []allowListCase
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cases := map[string]allowListCase{}
	for _, row := range rows {
		cases[row.Case] = row
	}
	return cases, nil
}

// admitted checks an attempt that was served: forwarded to the upstream once, with the allowed decision
// event that names the peer and the trust list it was found in.
func admitted(cases map[string]allowListCase, name string) error {
	c, ok := cases[name]
	switch {
	case !ok:
		return fmt.Errorf("the record holds no case %q", name)
	case c.Status != 200 || c.Upstream != 1:
		return fmt.Errorf("%s: status %d, %d request(s) at the upstream; want 200 and 1", name, c.Status, c.Upstream)
	case c.Event == nil || c.Event.Kind != "decision" || c.Event.Payload.State != "allowed" ||
		!strings.Contains(c.Event.Payload.Detail, "peer="+permittedPeer+" listed active in the trust list of "):
		return fmt.Errorf("%s: no allowed decision event naming %s and its trust list", name, permittedPeer)
	}
	return nil
}

// refusedPeer checks a refusal as recorded: the status and reason code of the answer, the denied
// decision event with the same code, and nothing forwarded to the upstream.
func refusedPeer(cases map[string]allowListCase, name string, status int, code string) error {
	c, ok := cases[name]
	switch {
	case !ok:
		return fmt.Errorf("the record holds no case %q", name)
	case c.Status != status || c.Reason != code:
		return fmt.Errorf("%s: %d %q, want %d %s", name, c.Status, c.Reason, status, code)
	case c.Upstream != 0:
		return fmt.Errorf("%s: %d request(s) reached the upstream", name, c.Upstream)
	case c.Event == nil || c.Event.Kind != "decision" || c.Event.Payload.State != "denied" || c.Event.Payload.ReasonCode != code:
		return fmt.Errorf("%s: no denied decision event with %s", name, code)
	}
	return nil
}

// decideAllowList decides the row's Then from the record.
func decideAllowList(cases map[string]allowListCase) error {
	return errors.Join(
		admitted(cases, "listed peer"),
		refusedPeer(cases, "unlisted peer", 403, "CHAN-ZONE-UNKNOWN"),
		// The admission follows the list, and fails closed without it.
		refusedPeer(cases, "withdrawn peer", 403, "CHAN-ZONE-UNKNOWN"),
		admitted(cases, "peer listed again"),
		refusedPeer(cases, "trust list unavailable", 503, "CHAN-TRUST-UNREACHABLE"),
	)
}

// trustListNamesThePeer runs the verifier and checks the list the TSPA served for it.
func (p *allowListProof) trustListNamesThePeer(ctx context.Context) error {
	if p.dryRun {
		return godog.ErrSkip
	}
	for _, name := range []string{"BDD_TARGET", "BDD_RUN_ID"} {
		if os.Getenv(name) == "" {
			return fmt.Errorf("the allow-list proof needs %s", name)
		}
	}
	safe := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	p.evidence = repoPath(filepath.Join("bundles/bdd/evidence/bdd-zt-018",
		safe.ReplaceAllString(os.Getenv("BDD_TARGET"), "-"), safe.ReplaceAllString(os.Getenv("BDD_RUN_ID"), "-")))
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, repoPath("scripts/verify-train-allow-list/verify.sh"), "--out", p.evidence)
	out, err := cmd.CombinedOutput()
	p.output = string(out)
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		p.exit = exitErr.ExitCode()
	} else if err != nil {
		return fmt.Errorf("the verifier did not run: %w", err)
	}
	raw, err := os.ReadFile(filepath.Join(p.evidence, "trust-list.json"))
	if err != nil {
		return fmt.Errorf("the TSPA served no trust list (verifier exit %d): %s", p.exit, lastLines(p.output, 3))
	}
	var list any
	if err := json.Unmarshal(raw, &list); err != nil || !trustlist.ListsActive(list, permittedPeer) {
		return fmt.Errorf("the TSPA's trust list does not name %s as an active service; record %s", permittedPeer, p.evidence)
	}
	return nil
}

func (p *allowListProof) connectionsAreAttempted() error {
	if p.dryRun {
		return godog.ErrSkip
	}
	var err error
	if p.cases, err = readAllowListRecord(filepath.Join(p.evidence, "record.json")); err != nil {
		return fmt.Errorf("%w; %s", err, lastLines(p.output, 3))
	}
	for _, name := range []string{"listed peer", "unlisted peer"} {
		if c, ok := p.cases[name]; !ok || c.Status == 0 {
			return fmt.Errorf("no answered attempt from the %s; record %s", name, p.evidence)
		}
	}
	return nil
}

func (p *allowListProof) listedAdmittedUnlistedRefused() error {
	if p.dryRun {
		return godog.ErrSkip
	}
	if err := decideAllowList(p.cases); err != nil {
		return fmt.Errorf("%w; record %s", err, p.evidence)
	}
	if p.exit != 0 {
		return fmt.Errorf("the cases held but the verifier failed (exit %d): %s; record %s", p.exit, lastLines(p.output, 3), p.evidence)
	}
	fmt.Printf("ZT-18: listed peer admitted, unlisted and withdrawn refused, list unavailable refused; record %s\n", p.evidence)
	return nil
}

func registerTrustListProofs(ctx *godog.ScenarioContext, dryRun bool) {
	p := &allowListProof{}
	ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
		*p = allowListProof{dryRun: dryRun}
		return c, nil
	})
	ctx.Step(`^a TRAIN trust list naming the permitted counter-connector$`, p.trustListNamesThePeer)
	ctx.Step(`^connections are attempted from a listed and from an unlisted counter-connector$`, p.connectionsAreAttempted)
	ctx.Step(`^the listed peer is admitted on the basis of the retrieved trust list AND the unlisted peer is refused\.$`, p.listedAdmittedUnlistedRefused)
}
