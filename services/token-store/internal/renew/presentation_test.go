package renew

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/oid4vp"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt/sdjwtfixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/statuslist"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationclient/fixtureholder"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationtest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire/acquiretest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/substitute"
)

// These tests put the presentation hook on the route in place of the fixture signer: a holder
// presents a credential, a verification service judges it with the real policy and signs the
// outcome with the key zone B and the store trust, and the real connector issues the token.

type presented struct {
	*env
	verifier *verificationtest.Verifier
	status   *verificationtest.Status
	grants   *atomic.Int32 // token requests the store sent to zone B, granted or refused
}

// grantCounter counts the store's requests to zone B's token endpoint as they leave.
type grantCounter struct{ n atomic.Int32 }

func (g *grantCounter) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, "/oauth2/token") {
		g.n.Add(1)
	}
	return http.DefaultTransport.RoundTrip(req)
}

func newPresented(t *testing.T) presented {
	t.Helper()
	e := newEnv(t)
	status := &verificationtest.Status{}
	v := verificationtest.Start(t, verificationtest.Options{Issuer: acquiretest.VPIssuer, Kid: acquiretest.VPKid, Key: e.issuer,
		Policy: verificationtest.Policy(status)})
	holder, err := fixtureholder.New(verificationtest.Credential(t, acquiretest.VPRole, acquiretest.VPEntitle, time.Now()), sdjwtfixture.TestHolderKey(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e.route.Outcomes = &verificationclient.Client{BaseURL: v.URL, Holder: holder}
	e.loaded.Routes[e.route.Name] = e.route
	counter := &grantCounter{}
	e.a.HTTPClient = &http.Client{Transport: counter, Timeout: 10 * time.Second}
	return presented{env: e, verifier: v, status: status, grants: &counter.n}
}

// consumedAtB are the outcomes zone B's connector consumed for a grant.
func (p presented) consumedAtB() map[string]bool {
	p.t.Helper()
	rows, err := p.poolB.Query(p.ctx, `SELECT outcome_id::text FROM verified_outcome WHERE consumed_at IS NOT NULL`)
	if err != nil {
		p.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			p.t.Fatal(err)
		}
		out[id] = true
	}
	return out
}

func (p presented) audited(code, replaces string) int {
	return p.count(p.poolA, `SELECT count(*) FROM audit_event WHERE reason_code = $1 AND detail->>'replaces' = $2`, code, replaces)
}

// auditedCause counts the attempts to replace a row whose audit row names cause. An empty cause
// counts the attempts whose row has no cause member at all, so a row that carried an empty one
// would be counted by neither.
func (p presented) auditedCause(cause, replaces string) int {
	if cause == "" {
		return p.count(p.poolA, `SELECT count(*) FROM audit_event WHERE detail->>'replaces' = $1 AND NOT jsonb_exists(detail, 'cause')`, replaces)
	}
	return p.count(p.poolA, `SELECT count(*) FROM audit_event WHERE detail->>'replaces' = $2 AND detail->>'cause' = $1`, cause, replaces)
}

// renewalFailed is the reason code and the cause of the row's renewal.failed audit row; the cause
// is nil when the row has no such member.
func (p presented) renewalFailed(id string) (code string, cause *string) {
	p.t.Helper()
	if err := p.poolA.QueryRow(p.ctx, `SELECT reason_code, detail->>'cause' FROM audit_event
		WHERE kind = 'renewal.failed' AND token_id = $1`, id).Scan(&code, &cause); err != nil {
		p.t.Errorf("no single renewal.failed row for %s: %v", id, err)
	}
	return code, cause
}

// names reports whether an audit row's cause is want: the member with that value, or no member
// when want is empty.
func names(cause *string, want string) bool {
	if want == "" {
		return cause == nil
	}
	return cause != nil && *cause == want
}

// notACredential is a holder that presents something no verification can read.
type notACredential struct{}

func (notACredential) Present(context.Context, oid4vp.Request) (string, error) {
	return "not-a-presentation", nil
}

func TestEveryRenewalPresentsTheCredentialAgainWithoutAPerson(t *testing.T) {
	p := newPresented(t)
	w := p.worker("w1")
	old := p.due()
	const renewals = 3
	for cycle := range renewals {
		w.Cycle(p.ctx)
		if s := p.state(old); s != "retired" {
			t.Fatalf("renewal %d: the renewed row is %s; want retired", cycle, s)
		}
		next := p.active()
		if next == old {
			t.Fatalf("renewal %d: no new active row", cycle)
		}
		old = next
		p.makeDue(old)
	}

	outcomes, presentations := p.verifier.Outcomes(), p.verifier.Presentations()
	if len(outcomes) != renewals+1 || len(presentations) != renewals+1 {
		t.Fatalf("%d outcomes for %d presentations; want %d of each (one acquisition, %d renewals)", len(outcomes), len(presentations), renewals+1, renewals)
	}
	consumed := p.consumedAtB()
	ids, tokens, challenges := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, o := range outcomes {
		if o.Status != if03.StatusVerified || o.Claims.Role != acquiretest.VPRole || o.Claims.Entitlement != acquiretest.VPEntitle {
			t.Errorf("outcome %d: %+v", i, o)
		}
		if !consumed[o.OutcomeID] {
			t.Errorf("outcome %d (%s) was not the one zone B issued a token for", i, o.OutcomeID)
		}
		ids[o.OutcomeID], challenges[o.Challenge], tokens[presentations[i]] = true, true, true
	}
	if len(ids) != renewals+1 || len(challenges) != renewals+1 || len(tokens) != renewals+1 {
		t.Errorf("%d outcome ids, %d challenges, %d presentations; each renewal must have its own", len(ids), len(challenges), len(tokens))
	}
	if len(consumed) != renewals+1 {
		t.Errorf("zone B consumed %d outcomes; want %d", len(consumed), renewals+1)
	}
	if n := p.grants.Load(); n < renewals+1 {
		t.Errorf("the store asked zone B for %d grants; at least one per presentation is expected", n)
	}
}

// A revoked credential ends the renewal at the first attempt: the verification service signs
// "revoked" for this very request, so the store refuses the outcome, records why, and does not
// present the same credential twice more. Nothing is asked of zone B, and the route has no upstream
// token afterwards.
func TestARevokedCredentialEndsRenewalAtTheStore(t *testing.T) {
	p := newPresented(t)
	id := p.due()
	before, asked, presented := len(p.consumedAtB()), p.grants.Load(), len(p.verifier.Presentations())
	p.status.Set(statuslist.Invalid, nil)

	p.worker("w1").Cycle(p.ctx)

	if s := p.state(id); s != "failed" {
		t.Errorf("the row is %s; want failed", s)
	}
	if n := p.audited(if03.CodeNotVerified, id); n != 1 {
		t.Errorf("%d attempts audited %s; want 1: a revoked credential is not presented again", n, if03.CodeNotVerified)
	}
	if n := p.auditedCause(if03.CodeRevoked, id); n != 1 {
		t.Errorf("%d attempts name the cause %s; want 1", n, if03.CodeRevoked)
	}
	if code, cause := p.renewalFailed(id); code != if03.CodeNotVerified || !names(cause, if03.CodeRevoked) {
		t.Errorf("renewal.failed audited %q, cause named %v; want %s with cause %s", code, cause != nil, if03.CodeNotVerified, if03.CodeRevoked)
	}
	if n := len(p.verifier.Presentations()) - presented; n != 1 {
		t.Errorf("the credential was presented %d times for the renewal; want once", n)
	}
	if record := `"cause":"` + if03.CodeRevoked + `"`; strings.Count(p.logs.String(), record) != 2 {
		t.Errorf("the store's records name %s %d times; want 2 (the attempt and the failed renewal)", record, strings.Count(p.logs.String(), record))
	}
	if n := p.count(p.poolA, `SELECT count(*) FROM upstream_token WHERE state = 'active'`); n != 0 {
		t.Errorf("%d active rows after a revoked credential", n)
	}
	if n := len(p.consumedAtB()); n != before {
		t.Errorf("zone B consumed %d more outcomes after the revocation", n-before)
	}
	if n := p.grants.Load(); n != asked {
		t.Errorf("the store asked zone B for %d grants with a revoked outcome; it refuses the outcome itself and asks for none", n-asked)
	}
	last := p.verifier.Outcomes()
	if o := last[len(last)-1]; o.Status != if03.StatusRevoked || o.ReasonCode != if03.CodeRevoked {
		t.Errorf("the verifier's last outcome: %+v", o)
	}

	// Failed closed: the route has no token. A call that needs one acquires on demand, which
	// presents the credential again, is refused for the same cause, and gets none; that attempt
	// and the substitution's own record name the cause too.
	svc := &substitute.Service{DB: p.poolA, Signer: p.kv, Secrets: p.kv, Routes: p.loaded, Acquirer: p.a,
		Log: slog.New(slog.NewJSONHandler(p.logs, nil))}
	_, err := svc.Substitute(p.ctx, substitute.Request{PeerZone: "zone-b", Audience: acquiretest.Audience, Method: "GET",
		TargetURI: acquiretest.Audience + "/v1/items"})
	if !errors.Is(err, substitute.ErrNoUpstream) {
		t.Errorf("substitution after the revocation: %v; want no upstream token", err)
	}
	if n := len(p.verifier.Presentations()) - presented; n != 2 {
		t.Errorf("%d presentations after the renewal and one substitution; want 2: the on-demand acquisition presents again", n)
	}
	if n := p.count(p.poolA, `SELECT count(*) FROM audit_event WHERE kind = 'upstream.refused' AND reason_code = $1
		AND detail->>'cause' = $2 AND NOT jsonb_exists(detail, 'replaces')`, if03.CodeNotVerified, if03.CodeRevoked); n != 1 {
		t.Errorf("%d on-demand attempts audited with the cause %s; want 1", n, if03.CodeRevoked)
	}
	onDemand := false
	for line := range strings.SplitSeq(p.logs.String(), "\n") {
		if strings.Contains(line, "on-demand acquisition refused or failed at the peer") {
			onDemand = strings.Contains(line, `"cause":"`+if03.CodeRevoked+`"`) && strings.Contains(line, `"reason_code":"`+if03.CodeNotVerified+`"`)
		}
	}
	if !onDemand {
		t.Errorf("the substitution's record does not name %s as the cause of %s", if03.CodeRevoked, if03.CodeNotVerified)
	}
	if n := p.grants.Load(); n != asked {
		t.Errorf("the store asked zone B for %d grants after the revocation", n-asked)
	}
}

func TestRenewalFailsClosedWithoutAnOutcome(t *testing.T) {
	for name, c := range map[string]struct {
		behave  verificationtest.Behaviour
		stuck   bool  // the holder takes the request and never answers
		junk    bool  // the holder presents something that is not a credential
		revoked bool  // the status list says the credential is revoked
		status  error // the status list cannot be read
		code    string
		cause   string // what the signed outcome the store refused gives as its reason
		stage   string // what the store's record names as the failed step, for a failure of the hook
	}{
		"verification service refusing": {behave: verificationtest.Behaviour{RefuseRequests: true}, code: acquire.CodeOutcomeSource, stage: "request"},
		"verification service silent":   {behave: verificationtest.Behaviour{Hang: true}, code: acquire.CodeOutcomeSource, stage: "response"},
		"holder never answering":        {stuck: true, code: acquire.CodeOutcomeSource, stage: "holder"},
		"status list unavailable":       {status: statuslist.ErrUnavailable, code: if03.CodeNotVerified, cause: if03.CodeStatusUnavailable},
		"outcome for another audience":  {behave: verificationtest.Behaviour{Audience: "https://other.zone-b.test"}, code: if03.CodeMismatch},
		// Only a revocation signed for this request ends a renewal early. One signed for another
		// audience names no cause, and a presentation the verification cannot accept may be its
		// side passing: both keep the three attempts.
		"revoked outcome for another audience":  {behave: verificationtest.Behaviour{Audience: "https://other.zone-b.test"}, revoked: true, code: if03.CodeNotVerified},
		"presentation that is not a credential": {junk: true, code: if03.CodeNotVerified, cause: if03.CodeInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			p := newPresented(t)
			id := p.due() // the acquisition that must succeed runs with the hook's own timeout
			hook := p.route.Outcomes.(*verificationclient.Client)
			if c.behave.Hang || c.stuck {
				// Only a silent service or holder is waited for; a short wait keeps the three attempts brief.
				hook.Timeout = 500 * time.Millisecond
			}
			switch {
			case c.stuck:
				hook.Holder = verificationtest.StuckHolder(t)
			case c.junk:
				hook.Holder = notACredential{}
			}
			before, asked, presented := len(p.consumedAtB()), p.grants.Load(), len(p.verifier.Presentations())
			p.verifier.Set(c.behave)
			listed := statuslist.Valid
			if c.revoked {
				listed = statuslist.Invalid
			}
			p.status.Set(listed, c.status)

			started := time.Now()
			p.worker("w1").Cycle(p.ctx)

			if s := p.state(id); s != "failed" {
				t.Errorf("the row is %s; want failed", s)
			}
			if n := p.audited(c.code, id); n != DefaultAttempts {
				t.Errorf("%d attempts audited %s; want %d", n, c.code, DefaultAttempts)
			}
			if n := p.auditedCause(c.cause, id); n != DefaultAttempts {
				t.Errorf("%d attempts name the cause %q; want %d", n, c.cause, DefaultAttempts)
			}
			if code, cause := p.renewalFailed(id); code != c.code || !names(cause, c.cause) {
				t.Errorf("renewal.failed audited %q, cause named %v; want %s with cause %q", code, cause != nil, c.code, c.cause)
			}
			if took := time.Since(started); took > 20*time.Second {
				t.Errorf("the renewal took %s; its attempts are bounded", took)
			}
			if n := len(p.verifier.Presentations()) - presented; c.stuck && n != 0 {
				t.Errorf("%d presentations reached the service from a holder that never answered", n)
			}
			// The holder is left at the first attempt's deadline and not asked for the other two.
			if n := strings.Count(p.logs.String(), `"busy":true`); c.stuck && n != DefaultAttempts-1 || !c.stuck && n != 0 {
				t.Errorf("%d attempts were recorded as finding the holder still at work", n)
			}
			if n := len(p.consumedAtB()); n != before {
				t.Errorf("zone B issued %d tokens without a verified outcome", n-before)
			}
			if n := p.grants.Load(); n != asked {
				t.Errorf("the store asked zone B for %d grants without an outcome it accepts", n-asked)
			}
			if record := `"stage":"` + c.stage + `"`; c.stage != "" && strings.Count(p.logs.String(), record) != DefaultAttempts {
				t.Errorf("the store's records name the step %s %d times; want %d", record, strings.Count(p.logs.String(), record), DefaultAttempts)
			}
			if c.stage == "" && strings.Contains(p.logs.String(), "outcome source failed") {
				t.Error("a signed outcome the store refused was recorded as a failure of the outcome source")
			}
		})
	}
}

// Eligibility is the route's configuration: a route is renewed unattended because it names an
// outcome source, and one that names none is not. Its token cannot be replaced without a person,
// so the worker fails the row at once and tries nothing: no challenge, no presentation, no grant.
// The other side of the rule is TestEveryRenewalPresentsTheCredentialAgainWithoutAPerson.
func TestARouteWithoutAnOutcomeSourceIsNotRenewed(t *testing.T) {
	p := newPresented(t)
	id := p.due()
	before, asked, presented := len(p.consumedAtB()), p.grants.Load(), len(p.verifier.Presentations())
	route := p.loaded.Routes[p.route.Name]
	route.Outcomes = nil // the configuration no longer names an outcome source for the route
	p.loaded.Routes[p.route.Name] = route

	started := time.Now()
	p.worker("w1").Cycle(p.ctx)

	if s := p.state(id); s != "failed" {
		t.Errorf("the row is %s; want failed", s)
	}
	if code, cause := p.renewalFailed(id); code != CodeNotAutomated || cause != nil {
		t.Errorf("renewal.failed audited %q, cause named %v; want %s and no cause", code, cause != nil, CodeNotAutomated)
	}
	named := false
	for line := range strings.SplitSeq(p.logs.String(), "\n") {
		if strings.Contains(line, `"reason_code":"`+CodeNotAutomated+`"`) {
			named = strings.Contains(line, `"route":"`+p.route.Name+`"`)
		}
	}
	if !named {
		t.Errorf("the store's record of %s does not name the route %s", CodeNotAutomated, p.route.Name)
	}
	if n := p.count(p.poolA, `SELECT count(*) FROM audit_event WHERE detail->>'replaces' = $1`, id); n != 0 {
		t.Errorf("%d acquisition attempts were audited for a route that is not eligible; want none", n)
	}
	if n := len(p.verifier.Presentations()) - presented; n != 0 {
		t.Errorf("the credential was presented %d times", n)
	}
	if n := p.grants.Load(); n != asked {
		t.Errorf("the store asked zone B for %d grants", n-asked)
	}
	if n := len(p.consumedAtB()); n != before {
		t.Errorf("zone B consumed %d more outcomes", n-before)
	}
	if n := p.count(p.poolA, `SELECT count(*) FROM upstream_token WHERE state IN ('active', 'renewing')`); n != 0 {
		t.Errorf("%d live rows on a route that cannot be renewed", n)
	}
	if took := time.Since(started); took > 5*time.Second {
		t.Errorf("failing a route that is not eligible took %s; it waits for nothing", took)
	}
}
