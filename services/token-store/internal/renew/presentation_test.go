package renew

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt/sdjwtfixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/statuslist"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationclient/fixtureholder"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationtest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire/acquiretest"
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

func TestARevokedCredentialEndsRenewalAtTheStore(t *testing.T) {
	p := newPresented(t)
	id := p.due()
	before, asked := len(p.consumedAtB()), p.grants.Load()
	p.status.Set(statuslist.Invalid, nil)

	p.worker("w1").Cycle(p.ctx)

	if s := p.state(id); s != "failed" {
		t.Errorf("the row is %s; want failed", s)
	}
	if n := p.audited(if03.CodeNotVerified, id); n != DefaultAttempts {
		t.Errorf("%d attempts audited %s; want %d", n, if03.CodeNotVerified, DefaultAttempts)
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
}

func TestRenewalFailsClosedWithoutAnOutcome(t *testing.T) {
	for name, c := range map[string]struct {
		behave verificationtest.Behaviour
		status error
		code   string
		stage  string // what the store's record names as the failed step, for a failure of the hook
	}{
		"verification service refusing": {behave: verificationtest.Behaviour{RefuseRequests: true}, code: acquire.CodeOutcomeSource, stage: "request"},
		"verification service silent":   {behave: verificationtest.Behaviour{Hang: true}, code: acquire.CodeOutcomeSource, stage: "response"},
		"status list unavailable":       {status: statuslist.ErrUnavailable, code: if03.CodeNotVerified},
		"outcome for another audience":  {behave: verificationtest.Behaviour{Audience: "https://other.zone-b.test"}, code: if03.CodeMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			p := newPresented(t)
			id := p.due() // the acquisition that must succeed runs with the hook's own timeout
			if c.behave.Hang {
				// Only the silent service is waited for; a short wait keeps the three attempts brief.
				p.route.Outcomes.(*verificationclient.Client).Timeout = 500 * time.Millisecond
			}
			before, asked := len(p.consumedAtB()), p.grants.Load()
			p.verifier.Set(c.behave)
			p.status.Set(statuslist.Valid, c.status)

			p.worker("w1").Cycle(p.ctx)

			if s := p.state(id); s != "failed" {
				t.Errorf("the row is %s; want failed", s)
			}
			if n := p.audited(c.code, id); n != DefaultAttempts {
				t.Errorf("%d attempts audited %s; want %d", n, c.code, DefaultAttempts)
			}
			var code string
			if err := p.poolA.QueryRow(p.ctx, `SELECT reason_code FROM audit_event WHERE kind = 'renewal.failed' AND token_id = $1`, id).Scan(&code); err != nil || code != c.code {
				t.Errorf("renewal.failed audited %q (%v); want %s", code, err, c.code)
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
