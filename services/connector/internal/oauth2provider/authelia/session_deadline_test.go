package authelia

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/dpoptest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

// The deadline counts the lifespan from the verification, never from the grant when the
// verification is older, and is cut to the whole second; it is refused when less than
// minAccessRemaining is left.
func TestAccessDeadline(t *testing.T) {
	at := time.Date(2026, 11, 18, 12, 0, 0, 400_000_000, time.UTC)
	for _, tc := range []struct {
		name       string
		verifiedAt time.Time
		lifespan   time.Duration
		want       time.Time
		ok         bool
	}{
		{"verified now", at, 5 * time.Minute, time.Date(2026, 11, 18, 12, 5, 0, 0, time.UTC), true},
		{"verified 100 s ago", at.Add(-100 * time.Second), 5 * time.Minute, time.Date(2026, 11, 18, 12, 3, 20, 0, time.UTC), true},
		{"verified ahead of the clock", at.Add(20 * time.Second), 5 * time.Minute, time.Date(2026, 11, 18, 12, 5, 0, 0, time.UTC), true},
		{"verified as long ago as the lifespan", at.Add(-time.Minute), time.Minute, time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC), false},
		{"verified longer ago than the lifespan", at.Add(-100 * time.Second), time.Minute, time.Date(2026, 11, 18, 11, 59, 20, 0, time.UTC), false},
		{"less than the minimum left", at.Add(-58 * time.Second), time.Minute, time.Date(2026, 11, 18, 12, 0, 2, 0, time.UTC), false},
		{"more than the minimum left", at.Add(-57 * time.Second), time.Minute, time.Date(2026, 11, 18, 12, 0, 3, 0, time.UTC), true},
		{"exactly the minimum left", at.Truncate(time.Second).Add(-58 * time.Second), time.Minute, time.Date(2026, 11, 18, 12, 0, 2, 0, time.UTC), true},
		{"a nanosecond less than the minimum", at.Truncate(time.Second).Add(-58 * time.Second), time.Minute, time.Date(2026, 11, 18, 12, 0, 2, 0, time.UTC), false},
	} {
		// The two boundary cases grant at a whole second, and a nanosecond after it.
		at := at
		switch {
		case strings.HasPrefix(tc.name, "exactly"):
			at = at.Truncate(time.Second)
		case strings.HasPrefix(tc.name, "a nanosecond"):
			at = at.Truncate(time.Second).Add(time.Nanosecond)
		}
		got, ok := accessDeadline(at, tc.verifiedAt, tc.lifespan)
		if !got.Equal(tc.want) || ok != tc.ok {
			t.Errorf("%s: %s %v, want %s %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

// A token granted on an outcome verified some time before the grant expires one lifespan after the
// verification. (The grant issues signed tokens only: a provider without a signer refuses it.) An
// outcome whose verification is as old as the lifespan grants nothing: it is refused as expired,
// nothing is consumed and nothing is signed.
func TestVP_AccessEndsOneLifespanAfterTheVerification(t *testing.T) {
	t.Run("a verification 100 s old", func(t *testing.T) {
		const lifespan = 5 * time.Minute
		h := newVPHarness(t, func(c *oauth2provider.Config) { c.AccessTokenLifespan = lifespan })
		h.seedVPClient(vpClient)

		challenge := h.newChallenge(vpClient, resourceAudience)
		o := verifiedOutcome(vpClient, challenge, resourceAudience)
		verifiedAt := time.Now().UTC().Add(-100 * time.Second).Truncate(time.Second)
		o["verified_at"] = verifiedAt.Format(time.RFC3339)
		o["expires_at"] = verifiedAt.Add(115 * time.Second).Format(time.RFC3339)
		got := h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), h.sign(o), challenge, resourceAudience)
		if got.status != http.StatusOK {
			t.Fatalf("grant: status %d, body %v", got.status, got.body)
		}
		deadline := verifiedAt.Add(lifespan)
		expiresIn, _ := got.body["expires_in"].(float64)
		if remaining := time.Until(deadline).Seconds(); expiresIn > remaining+1 || expiresIn < remaining-2 {
			t.Errorf("expires_in %v; the verification allows %.0f s", expiresIn, remaining)
		}
		var claims struct {
			Exp int64 `json:"exp"`
		}
		decodePart(t, strings.Split(got.str("access_token"), ".")[1], &claims)
		if claims.Exp != deadline.Unix() {
			t.Errorf("exp %d, want the verification plus the lifespan, %d", claims.Exp, deadline.Unix())
		}
	})

	t.Run("a verification as old as the lifespan", func(t *testing.T) {
		const lifespan = 90 * time.Second
		h := newVPHarness(t, func(c *oauth2provider.Config) { c.AccessTokenLifespan = lifespan })
		h.seedVPClient(vpClient)

		challenge := h.newChallenge(vpClient, resourceAudience)
		o := verifiedOutcome(vpClient, challenge, resourceAudience)
		verifiedAt := time.Now().UTC().Add(-lifespan).Truncate(time.Second)
		o["verified_at"] = verifiedAt.Format(time.RFC3339)
		o["expires_at"] = verifiedAt.Add(119 * time.Second).Format(time.RFC3339)
		compact := h.sign(o)
		before := h.signer.signed.Load()
		wantRefused(t, "an exhausted verification", h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), compact, challenge, resourceAudience),
			http.StatusBadRequest, oauth2provider.CodeCredOutcomeExpired, o, compact)
		if h.signer.signed.Load() != before {
			t.Error("a token was signed")
		}
		stored, err := h.stores.Challenges.GetChallenge(t.Context(), challenge)
		if err != nil || !stored.ConsumedAt.IsZero() {
			t.Errorf("challenge after the refusal: %+v, %v; want unconsumed", stored, err)
		}
	})
}

// The deadline is judged again inside the issuing transaction: a request that passed its first
// checks and then waited behind another transaction holding the challenge, long enough to use up
// the access its verification allows while the outcome and the challenge are still valid, is
// refused; nothing is signed, consumed or recorded.
func TestVP_DeadlineIsJudgedAgainInTheTransaction(t *testing.T) {
	const lifespan = 30 * time.Second
	h := newVPHarness(t, func(c *oauth2provider.Config) { c.AccessTokenLifespan = lifespan })
	if h.pool == nil {
		// Only PostgreSQL shows that the request is waiting inside the transaction, after its first
		// checks; without that, moving the clock could fail the first check instead.
		t.Skip("observes the lock wait in PostgreSQL")
	}
	h.seedVPClient(vpClient)

	challenge := h.newChallenge(vpClient, resourceAudience)
	o := verifiedOutcome(vpClient, challenge, resourceAudience)
	now := time.Now().UTC().Truncate(time.Second)
	o["verified_at"], o["expires_at"] = now.Format(time.RFC3339), now.Add(110*time.Second).Format(time.RFC3339)
	compact := h.sign(o)

	release := h.holdChallenge(t, challenge)
	results := make(chan result, 1)
	go func() {
		results <- h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), compact, challenge, resourceAudience)
	}()
	h.waitForLockWait(t)

	// 29 s on: the outcome (110 s) and the challenge (120 s) are valid; the access is not.
	h.advanceClock(lifespan - time.Second)
	release()

	got := waitFor(t, "the waiting request", func() result { return <-results })
	wantRefused(t, "deadline used up while waiting", got, http.StatusBadRequest, oauth2provider.CodeCredOutcomeExpired, o, compact)
	h.wantNothingIssued(t, challenge)
}

// The deadline is judged once more after the token is signed: a signature that uses up what is left
// refuses the grant and rolls back the consumption and the token record.
func TestVP_DeadlineIsJudgedAfterSigning(t *testing.T) {
	const lifespan = 30 * time.Second
	h := newVPHarness(t, func(c *oauth2provider.Config) { c.AccessTokenLifespan = lifespan })
	h.seedVPClient(vpClient)

	challenge := h.newChallenge(vpClient, resourceAudience)
	o := verifiedOutcome(vpClient, challenge, resourceAudience)
	now := time.Now().UTC().Truncate(time.Second)
	o["verified_at"], o["expires_at"] = now.Format(time.RFC3339), now.Add(110*time.Second).Format(time.RFC3339)
	compact := h.sign(o)

	h.signer.during = func() { h.advanceClock(lifespan - time.Second) }
	got := h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), compact, challenge, resourceAudience)
	h.signer.during = nil
	wantRefused(t, "deadline used up while signing", got, http.StatusBadRequest, oauth2provider.CodeCredOutcomeExpired, o, compact)
	if n := h.signer.signed.Load(); n != 1 {
		t.Errorf("%d signatures, want the one that used up the time", n)
	}
	if stored, err := h.stores.Challenges.GetChallenge(t.Context(), challenge); err != nil || !stored.ConsumedAt.IsZero() {
		t.Errorf("challenge: %+v, %v; want unconsumed", stored, err)
	}
	h.wantNothingCommitted(t)
}

// The stored token record carries the same expiry as the signed token's exp.
func TestVP_StoredExpiryIsTheSignedExpiry(t *testing.T) {
	h := newVPHarness(t, func(c *oauth2provider.Config) { c.AccessTokenLifespan = 5 * time.Minute })
	if h.pool == nil {
		t.Skip("reads the token record from PostgreSQL")
	}
	h.seedVPClient(vpClient)
	challenge := h.newChallenge(vpClient, resourceAudience)
	o := verifiedOutcome(vpClient, challenge, resourceAudience)
	got := h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), h.sign(o), challenge, resourceAudience)
	if got.status != http.StatusOK {
		t.Fatalf("grant: %d %v", got.status, got.body)
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	decodePart(t, strings.Split(got.str("access_token"), ".")[1], &claims)
	var stored time.Time
	if err := h.pool.QueryRow(t.Context(), `SELECT expires_at FROM oauth2_token WHERE outcome_id = $1`, o["outcome_id"]).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored.Unix() != claims.Exp {
		t.Errorf("stored expiry %s, signed exp %d", stored, claims.Exp)
	}
}

// holdChallenge holds the challenge in a PostgreSQL transaction, with a row lock. The returned
// function releases it; the test's cleanup releases it too, so a failure never leaves it held.
func (h *vpHarness) holdChallenge(t *testing.T, challenge string) func() {
	t.Helper()
	tx, err := h.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release := func() { once.Do(func() { _ = tx.Rollback(context.Background()) }) }
	t.Cleanup(release)
	if _, err = tx.Exec(t.Context(), `SELECT 1 FROM oauth2_challenge WHERE challenge = $1 FOR UPDATE`, challenge); err != nil {
		t.Fatal(err)
	}
	return release
}

// waitForLockWait returns once a request is waiting on a lock in this test's database.
func (h *vpHarness) waitForLockWait(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for waiting := 0; waiting == 0; {
		if time.Now().After(deadline) {
			t.Fatal("the request never waited on the challenge lock")
		}
		// Scoped to this test's database: the server is shared with other tests.
		if err := h.pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&waiting); err != nil {
			t.Fatalf("reading the lock waits: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// wantNothingCommitted checks that, on PostgreSQL, no outcome and no outcome token was committed.
func (h *vpHarness) wantNothingCommitted(t *testing.T) {
	t.Helper()
	if h.pool == nil {
		return
	}
	var ledger, tokens int
	if err := h.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM verified_outcome), (SELECT count(*) FROM oauth2_token WHERE outcome_id IS NOT NULL)`).Scan(&ledger, &tokens); err != nil {
		t.Fatalf("reading the committed rows: %v", err)
	}
	if ledger != 0 || tokens != 0 {
		t.Errorf("%d ledger rows and %d outcome tokens committed, want none", ledger, tokens)
	}
}

// wantNothingIssued checks that no token was signed, the challenge is unconsumed and nothing was
// committed.
func (h *vpHarness) wantNothingIssued(t *testing.T, challenge string) {
	t.Helper()
	if n := h.signer.signed.Load(); n != 0 {
		t.Errorf("%d tokens signed", n)
	}
	if stored, err := h.stores.Challenges.GetChallenge(t.Context(), challenge); err != nil || !stored.ConsumedAt.IsZero() {
		t.Errorf("challenge: %+v, %v; want unconsumed", stored, err)
	}
	h.wantNothingCommitted(t)
}
