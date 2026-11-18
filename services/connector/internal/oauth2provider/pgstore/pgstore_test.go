package pgstore

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/pgtest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

func newPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	pool, err := pgxpool.New(t.Context(), pgtest.MigratedURL(t, "pgstore"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	return pool
}

func TestClients_RoundTripAndNotFound(t *testing.T) {
	ctx := t.Context()
	stores := New(newPool(t), nil)

	registered := oauth2provider.Client{
		ID: "registered", SecretHash: []byte("$2a$hash"), GrantTypes: []string{"client_credentials"},
		Scopes: []string{"resource.read"}, Audience: []string{"https://b.example"}, DPoPBound: true,
		Metadata: json.RawMessage(`{"client_name":"participant"}`),
	}
	provisioned := oauth2provider.Client{ID: "provisioned"}

	for _, c := range []oauth2provider.Client{registered, provisioned} {
		if err := stores.Clients.CreateClient(ctx, c); err != nil {
			t.Fatal(err)
		}
	}

	got, err := stores.Clients.GetClient(ctx, "registered")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != registered.ID || string(got.SecretHash) != string(registered.SecretHash) || !got.DPoPBound ||
		len(got.Scopes) != 1 || got.Audience[0] != "https://b.example" || string(got.Metadata) != `{"client_name": "participant"}` {
		t.Errorf("got %+v", got)
	}

	if got, err := stores.Clients.GetClient(ctx, "provisioned"); err != nil || got.Metadata != nil || got.GrantTypes == nil {
		t.Errorf("provisioned client: %+v, %v (want no metadata, empty grant types)", got, err)
	}

	registered.Scopes = []string{"resource.read", "resource.write"}
	if err := stores.Clients.UpdateClient(ctx, registered); err != nil {
		t.Fatal(err)
	}
	if got, _ := stores.Clients.GetClient(ctx, "registered"); len(got.Scopes) != 2 {
		t.Errorf("scopes after update = %v", got.Scopes)
	}

	for name, err := range map[string]error{
		"get":    func() error { _, err := stores.Clients.GetClient(ctx, "absent"); return err }(),
		"update": stores.Clients.UpdateClient(ctx, oauth2provider.Client{ID: "absent"}),
		"delete": stores.Clients.DeleteClient(ctx, "absent"),
	} {
		if !errors.Is(err, oauth2provider.ErrNotFound) {
			t.Errorf("%s of an absent client: %v, want ErrNotFound", name, err)
		}
	}
}

// Access and registration tokens share a table and never see each other's rows; deleting a client
// takes its tokens with it.
func TestTokens_KindsAreSeparateAndFollowTheirClient(t *testing.T) {
	ctx := t.Context()
	stores := New(newPool(t), nil)

	if err := stores.Clients.CreateClient(ctx, oauth2provider.Client{ID: "c"}); err != nil {
		t.Fatal(err)
	}

	record := oauth2provider.TokenRecord{
		RequestID: "r", ClientID: "c", RequestedAt: time.Now(), Session: []byte(`{"v":1}`),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := stores.AccessTokens.CreateToken(ctx, "sig", record); err != nil {
		t.Fatal(err)
	}

	if _, err := stores.RegistrationTokens.GetToken(ctx, "sig"); !errors.Is(err, oauth2provider.ErrNotFound) {
		t.Errorf("registration store saw an access token: %v", err)
	}

	got, err := stores.AccessTokens.GetToken(ctx, "sig")
	if err != nil || got.ClientID != "c" || !got.ExpiresAt.Equal(record.ExpiresAt.Truncate(time.Microsecond)) {
		t.Errorf("got %+v, %v", got, err)
	}

	if err := stores.Clients.DeleteClient(ctx, "c"); err != nil {
		t.Fatal(err)
	}
	if _, err := stores.AccessTokens.GetToken(ctx, "sig"); !errors.Is(err, oauth2provider.ErrNotFound) {
		t.Errorf("token outlived its client: %v", err)
	}

	if err := stores.AccessTokens.DeleteToken(ctx, "sig"); err != nil {
		t.Errorf("deleting an absent token: %v, want idempotent", err)
	}
}

func TestTokens_ExpiryIsRequired(t *testing.T) {
	ctx := t.Context()
	stores := New(newPool(t), nil)

	if err := stores.Clients.CreateClient(ctx, oauth2provider.Client{ID: "c"}); err != nil {
		t.Fatal(err)
	}

	err := stores.AccessTokens.CreateToken(ctx, "sig", oauth2provider.TokenRecord{RequestID: "r", ClientID: "c", Session: []byte("{}")})
	if err == nil {
		t.Fatal("stored a token without an expiry")
	}
}

// Nonce validity follows the stores' clock, not the database's, so tests move one clock.
func TestNonces_ValidityFollowsTheClock(t *testing.T) {
	ctx := t.Context()
	now := time.Now()
	stores := New(newPool(t), func() time.Time { return now })

	if err := stores.DPoPNonces.CreateNonce(ctx, "n", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	if ok, err := stores.DPoPNonces.IsNonceValid(ctx, "n"); err != nil || !ok {
		t.Fatalf("fresh nonce: %v, %v", ok, err)
	}

	now = now.Add(2 * time.Minute)
	if ok, _ := stores.DPoPNonces.IsNonceValid(ctx, "n"); ok {
		t.Error("expired nonce accepted")
	}

	if ok, _ := stores.DPoPNonces.IsNonceValid(ctx, "never-issued"); ok {
		t.Error("unknown nonce accepted")
	}
}

func TestSweep_RemovesOnlyExpiredRows(t *testing.T) {
	ctx := t.Context()
	pool := newPool(t)
	stores := New(pool, nil)
	now := time.Now()

	if err := stores.Clients.CreateClient(ctx, oauth2provider.Client{ID: "c"}); err != nil {
		t.Fatal(err)
	}
	for sig, exp := range map[string]time.Time{"old": now.Add(-time.Minute), "live": now.Add(time.Hour)} {
		if err := stores.AccessTokens.CreateToken(ctx, sig, oauth2provider.TokenRecord{
			RequestID: sig, ClientID: "c", RequestedAt: now, Session: []byte("{}"), ExpiresAt: exp,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := stores.DPoPNonces.CreateNonce(ctx, "old", now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}

	n, err := Sweep(ctx, pool, now)
	if err != nil || n != 2 {
		t.Fatalf("swept %d, %v; want 2", n, err)
	}
	if _, err := stores.AccessTokens.GetToken(ctx, "live"); err != nil {
		t.Errorf("live token swept: %v", err)
	}
}

// A grant transaction is all or nothing: rolled back, the challenge is unconsumed and neither the
// outcome nor the token exists; committed, all three persist and a second consumption is refused.
func TestTransactions_ConsumeChallengeOutcomeAndTokenTogether(t *testing.T) {
	ctx := t.Context()
	stores := New(newPool(t), nil)
	now := time.Now()

	if err := stores.Clients.CreateClient(ctx, oauth2provider.Client{ID: "c"}); err != nil {
		t.Fatal(err)
	}
	if err := stores.Challenges.CreateChallenge(ctx, oauth2provider.Challenge{
		Value: "challenge-0123456789", ClientID: "c", Audience: "https://b.example", ExpiresAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	outcome := oauth2provider.VerifiedOutcome{
		ID: "00000000-0000-4000-8000-000000000001", Issuer: "https://v.example", ClientID: "c",
		Challenge: "challenge-0123456789", Audience: "https://b.example", Claims: json.RawMessage(`{"role":"r"}`),
		CredentialRefs: []string{"urn:ref:1"}, VerifiedAt: now, ExpiresAt: now.Add(time.Minute),
	}

	grant := func(commit bool) error {
		txCtx, err := stores.Transactions.BeginTx(ctx)
		if err != nil {
			return err
		}
		err = stores.Challenges.ConsumeChallenge(txCtx, outcome.Challenge, "c", outcome.Audience, now)
		if err == nil {
			err = stores.Outcomes.ConsumeOutcome(txCtx, outcome, now)
		}
		if err == nil {
			err = stores.AccessTokens.CreateToken(txCtx, "sig", oauth2provider.TokenRecord{
				RequestID: "r", ClientID: "c", RequestedAt: now, Session: []byte("{}"), ExpiresAt: now.Add(time.Minute),
				OutcomeID: outcome.ID, GrantType: oauth2provider.VerifiedPresentationGrantType,
			})
		}
		if err != nil || !commit {
			if rbErr := stores.Transactions.Rollback(txCtx); rbErr != nil {
				t.Fatal(rbErr)
			}
			return err
		}
		return stores.Transactions.Commit(txCtx)
	}

	if err := grant(false); err != nil {
		t.Fatal(err)
	}
	if c, err := stores.Challenges.GetChallenge(ctx, outcome.Challenge); err != nil || !c.ConsumedAt.IsZero() {
		t.Errorf("challenge after rollback: %+v, %v", c, err)
	}
	if _, err := stores.AccessTokens.GetToken(ctx, "sig"); !errors.Is(err, oauth2provider.ErrNotFound) {
		t.Errorf("token after rollback: %v", err)
	}

	if err := grant(true); err != nil {
		t.Fatal(err)
	}
	if got, err := stores.AccessTokens.GetToken(ctx, "sig"); err != nil || got.OutcomeID != outcome.ID {
		t.Errorf("token after commit: %+v, %v", got, err)
	}

	if err := stores.Challenges.ConsumeChallenge(ctx, outcome.Challenge, "c", outcome.Audience, now); !errors.Is(err, oauth2provider.ErrConsumed) {
		t.Errorf("second challenge consumption: %v, want ErrConsumed", err)
	}
	if err := stores.Outcomes.ConsumeOutcome(ctx, outcome, now); !errors.Is(err, oauth2provider.ErrConsumed) {
		t.Errorf("second outcome consumption: %v, want ErrConsumed", err)
	}
	if err := stores.AccessTokens.CreateToken(ctx, "sig2", oauth2provider.TokenRecord{
		RequestID: "r2", ClientID: "c", RequestedAt: now, Session: []byte("{}"), ExpiresAt: now.Add(time.Minute), OutcomeID: outcome.ID,
		GrantType: oauth2provider.VerifiedPresentationGrantType,
	}); err == nil {
		t.Error("a second token on one outcome id was stored")
	}
}

// A challenge is consumed only by its client, for its audience, before it expires.
func TestChallenges_ConsumptionChecksBindingAndExpiry(t *testing.T) {
	ctx := t.Context()
	now := time.Now()
	stores := New(newPool(t), nil)

	if err := stores.Clients.CreateClient(ctx, oauth2provider.Client{ID: "c"}); err != nil {
		t.Fatal(err)
	}
	if err := stores.Challenges.CreateChallenge(ctx, oauth2provider.Challenge{
		Value: "ch", ClientID: "c", Audience: "aud", ExpiresAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	for name, args := range map[string][2]string{"other client": {"x", "aud"}, "other audience": {"c", "x"}} {
		if err := stores.Challenges.ConsumeChallenge(ctx, "ch", args[0], args[1], now); !errors.Is(err, oauth2provider.ErrConsumed) {
			t.Errorf("%s: %v, want refused", name, err)
		}
	}

	if err := stores.Challenges.ConsumeChallenge(ctx, "ch", "c", "aud", now.Add(2*time.Minute)); !errors.Is(err, oauth2provider.ErrConsumed) {
		t.Errorf("expired: %v, want refused", err)
	}
	if _, err := stores.Challenges.GetChallenge(ctx, "absent"); !errors.Is(err, oauth2provider.ErrNotFound) {
		t.Errorf("absent challenge: %v", err)
	}
}

// Sweep removes expired unconsumed challenges and keeps consumed ones, which guard against replay.
func TestSweep_KeepsConsumedChallenges(t *testing.T) {
	ctx := t.Context()
	pool := newPool(t)
	now := time.Now()
	stores := New(pool, nil)

	if err := stores.Clients.CreateClient(ctx, oauth2provider.Client{ID: "c"}); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"unused", "used"} {
		if err := stores.Challenges.CreateChallenge(ctx, oauth2provider.Challenge{Value: v, ClientID: "c", Audience: "a", ExpiresAt: now.Add(-time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := stores.Challenges.ConsumeChallenge(ctx, "used", "c", "a", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	if _, err := Sweep(ctx, pool, now); err != nil {
		t.Fatal(err)
	}
	if _, err := stores.Challenges.GetChallenge(ctx, "unused"); !errors.Is(err, oauth2provider.ErrNotFound) {
		t.Errorf("expired unconsumed challenge kept: %v", err)
	}
	if c, err := stores.Challenges.GetChallenge(ctx, "used"); err != nil || c.ConsumedAt.IsZero() {
		t.Errorf("consumed challenge: %+v, %v; want kept", c, err)
	}
}

// The database holds a verified-presentation token to its outcome: one without an outcome, or an
// outcome on any other token, is refused by a constraint, through the store and in plain SQL.
func TestTokens_VerifiedPresentationTokenNeedsItsOutcome(t *testing.T) {
	ctx := t.Context()
	pool := newPool(t)
	stores := New(pool, nil)
	now := time.Now()

	if err := stores.Clients.CreateClient(ctx, oauth2provider.Client{ID: "c"}); err != nil {
		t.Fatal(err)
	}

	record := oauth2provider.TokenRecord{
		RequestID: "r", ClientID: "c", RequestedAt: now, Session: []byte("{}"), ExpiresAt: now.Add(time.Minute),
		GrantType: oauth2provider.VerifiedPresentationGrantType,
	}
	if err := stores.AccessTokens.CreateToken(ctx, "vp-no-outcome", record); err == nil {
		t.Error("store: a verified-presentation token without an outcome was stored")
	}

	if _, err := pool.Exec(ctx, `INSERT INTO oauth2_token (kind, signature, request_id, client_id, requested_at, session,
		expires_at, grant_type) VALUES ('access', 'raw', 'r', 'c', now(), '{}', now() + interval '1 minute', $1)`,
		oauth2provider.VerifiedPresentationGrantType); err == nil {
		t.Error("SQL: a verified-presentation token without an outcome was inserted")
	}

	if _, err := pool.Exec(ctx, `INSERT INTO verified_outcome (outcome_id, issuer, client_id, challenge, audience, status,
		claims, verified_at, expires_at) VALUES ('00000000-0000-4000-8000-000000000009', 'i', 'c', 'ch', 'a', 'verified',
		'{}', now(), now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO oauth2_token (kind, signature, request_id, client_id, requested_at, session,
		expires_at, grant_type, outcome_id) VALUES ('access', 'cc', 'r', 'c', now(), '{}', now() + interval '1 minute',
		'client_credentials', '00000000-0000-4000-8000-000000000009')`); err == nil {
		t.Error("SQL: a client_credentials token carrying an outcome was inserted")
	}
}

// The provider keeps an empty port ("host:") in its normalised htu; the adapter records the form
// the other consumers of the shared record use, so both spellings are one proof.
func TestReplay_RecordsTheSharedNormalForm(t *testing.T) {
	ctx := t.Context()
	pool := newPool(t)
	stores := New(pool, nil)
	use := oauth2provider.DPoPProofUse{
		Thumbprint: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I", Method: "POST",
		URI: "https://example.test:/token", ID: "j-port", NotAfter: time.Now().Add(time.Minute),
	}
	if used, err := stores.DPoPReplay.MarkUsed(ctx, use); err != nil || used {
		t.Fatalf("first use: used=%v err=%v", used, err)
	}
	fresh, err := replay.NewPostgres(pool).TryUse(ctx, replay.Use{
		JKT: use.Thumbprint, Method: "POST", URI: "https://example.test/token", JTI: "j-port", NotAfter: use.NotAfter,
	})
	if err != nil || fresh {
		t.Fatalf("the Connector's use was not seen under the shared form: fresh=%v err=%v", fresh, err)
	}
	use.ID, use.URI = "j-bad", "ftp://example.test/token"
	if _, err := stores.DPoPReplay.MarkUsed(ctx, use); err == nil {
		t.Fatal("a URI outside the shared form was recorded")
	}
}
