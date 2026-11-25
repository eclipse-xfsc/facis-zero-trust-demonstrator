package schema

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The store's queries, run against the migrated schema. These are the statements the service's
// paths are built on: the replay check, outcome consumption, the substitution lookup, the
// single-flight renewal claim and the connector's client and token records. Each test states the
// invariant the schema has to carry, not an implementation detail.

const uniqueViolation = "23505"

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == uniqueViolation
}

func seedKeyAndOutcome(t *testing.T, c *pgx.Conn, outcome string, audience string, expires time.Time) {
	t.Helper()
	ctx := context.Background()
	if _, err := c.Exec(ctx, `INSERT INTO signing_key (key_ref, jkt, alg, state) VALUES ('transit:store-1:v1', 'jkt-store-1', 'ES256', 'active')
		ON CONFLICT (key_ref) DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, `INSERT INTO verified_outcome
		(outcome_id, issuer, client_id, challenge, audience, status, claims, verified_at, expires_at)
		VALUES ($1, 'https://verifier.example', 'client-a', 'challenge', $2, 'verified', '{"role":"member"}', now(), $3)`,
		outcome, audience, expires); err != nil {
		t.Fatal(err)
	}
}

// consume takes the outcome and inserts the token it authorises in one transaction. It returns
// false, nil when the outcome is not consumable: already consumed, expired, or for another audience.
func consume(ctx context.Context, c *pgx.Conn, outcome, audience, token string) (bool, error) {
	tx, err := c.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `UPDATE verified_outcome SET consumed_at = now()
		WHERE outcome_id = $1 AND audience = $2 AND status = 'verified' AND consumed_at IS NULL AND expires_at > now()`,
		outcome, audience)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO upstream_token
		(token_id, peer_zone, audience, tenant, outcome_id, token_ref, key_ref, state, issued_at, expires_at, renew_after)
		VALUES ($1, 'zone-b', $2, '', $3, 'kv/upstream/' || $1::uuid::text, 'transit:store-1:v1', 'active', now(), now() + interval '1 hour', now() + interval '45 minutes')`,
		token, audience, outcome); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

func TestReplayCheckAdmitsExactlyOneOfConcurrentIdenticalProofs(t *testing.T) {
	db := newTestDatabase(t)
	c := db.migrated()
	const callers = 12
	conns := make([]*pgx.Conn, callers)
	for i := range conns {
		conns[i] = db.conn()
	}
	fresh := make([]bool, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tag, err := conns[i].Exec(context.Background(), `INSERT INTO proof_jti (jkt, htm, htu, jti, not_after)
				VALUES ('jkt-a', 'POST', 'https://zone-b.example/token', 'jti-1', now() + interval '90 seconds')
				ON CONFLICT DO NOTHING`)
			errs[i] = err
			fresh[i] = err == nil && tag.RowsAffected() == 1
		}()
	}
	wg.Wait()
	admitted := 0
	for i := range callers {
		if errs[i] != nil {
			t.Errorf("caller %d: %v", i, errs[i])
		}
		if fresh[i] {
			admitted++
		}
	}
	if admitted != 1 {
		t.Errorf("%d of %d concurrent identical proofs were admitted, want exactly 1", admitted, callers)
	}
	// A different htu with the same jti is another proof, not a replay.
	tag, err := c.Exec(context.Background(), `INSERT INTO proof_jti (jkt, htm, htu, jti, not_after)
		VALUES ('jkt-a', 'POST', 'https://zone-b.example/other', 'jti-1', now() + interval '90 seconds') ON CONFLICT DO NOTHING`)
	if err != nil || tag.RowsAffected() != 1 {
		t.Errorf("same jti for another target refused: %v, %d rows", err, tag.RowsAffected())
	}
}

func TestReplayRecordsAreKeptUntilNotAfterAndSwept(t *testing.T) {
	db := newTestDatabase(t)
	c := db.migrated()
	ctx := context.Background()
	if _, err := c.Exec(ctx, `INSERT INTO proof_jti (jkt, htm, htu, jti, not_after)
		VALUES ('jkt-a', 'GET', 'https://zone-b.example/r', 'jti-old', now() - interval '1 second')`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, `INSERT INTO proof_jti (jkt, htm, htu, jti, not_after)
		VALUES ('jkt-a', 'GET', 'https://zone-b.example/r', 'jti-live', now() + interval '60 seconds')`); err != nil {
		t.Fatal(err)
	}
	tag, err := c.Exec(ctx, `DELETE FROM proof_jti WHERE not_after <= now()`)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("sweep removed %d rows, %v; want 1", tag.RowsAffected(), err)
	}
	var live int
	if err := c.QueryRow(ctx, `SELECT count(*) FROM proof_jti`).Scan(&live); err != nil || live != 1 {
		t.Errorf("%d records after the sweep, %v; want 1", live, err)
	}
}

func TestAnOutcomeIsConsumedExactlyOnce(t *testing.T) {
	db := newTestDatabase(t)
	c := db.migrated()
	ctx := context.Background()
	const outcome = "11111111-1111-4111-8111-111111111111"
	seedKeyAndOutcome(t, c, outcome, "https://zone-b.example/api", time.Now().Add(2*time.Minute))

	ok, err := consume(ctx, c, outcome, "https://zone-b.example/api", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	if err != nil || !ok {
		t.Fatalf("first consumption: ok=%v err=%v", ok, err)
	}
	ok, err = consume(ctx, c, outcome, "https://zone-b.example/api", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	if err != nil || ok {
		t.Errorf("second consumption: ok=%v err=%v; want refused", ok, err)
	}
	var tokens int
	if err := c.QueryRow(ctx, `SELECT count(*) FROM upstream_token WHERE outcome_id = $1`, outcome).Scan(&tokens); err != nil || tokens != 1 {
		t.Errorf("%d token rows for the outcome, %v; want 1", tokens, err)
	}
	// Even a path that skips the consumption check cannot add a second token for the outcome.
	_, err = c.Exec(ctx, `INSERT INTO upstream_token
		(token_id, peer_zone, audience, tenant, outcome_id, token_ref, key_ref, state, issued_at, expires_at, renew_after)
		VALUES ('cccccccc-cccc-4ccc-8ccc-cccccccccccc', 'zone-b', 'https://zone-b.example/api', '', $1, 'kv/x', 'transit:store-1:v1', 'active', now(), now() + interval '1 hour', now())`, outcome)
	if !isUniqueViolation(err) {
		t.Errorf("second token for one outcome: %v; want a unique violation", err)
	}
}

func TestAnOutcomeForAnotherAudienceOrPastItsExpiryIsRefused(t *testing.T) {
	db := newTestDatabase(t)
	c := db.migrated()
	ctx := context.Background()
	const mismatch = "22222222-2222-4222-8222-222222222222"
	const expired = "33333333-3333-4333-8333-333333333333"
	seedKeyAndOutcome(t, c, mismatch, "https://zone-b.example/api", time.Now().Add(2*time.Minute))
	seedKeyAndOutcome(t, c, expired, "https://zone-b.example/api", time.Now().Add(-time.Second))

	if ok, err := consume(ctx, c, mismatch, "https://zone-c.example/api", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"); err != nil || ok {
		t.Errorf("audience mismatch: ok=%v err=%v; want refused", ok, err)
	}
	if ok, err := consume(ctx, c, expired, "https://zone-b.example/api", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"); err != nil || ok {
		t.Errorf("expired outcome: ok=%v err=%v; want refused", ok, err)
	}
	var consumed int
	if err := c.QueryRow(ctx, `SELECT count(*) FROM verified_outcome WHERE consumed_at IS NOT NULL`).Scan(&consumed); err != nil || consumed != 0 {
		t.Errorf("%d outcomes marked consumed, %v; want 0", consumed, err)
	}
}

func TestSubstitutionFindsTheValidTokenOfARoute(t *testing.T) {
	db := newTestDatabase(t)
	c := db.migrated()
	ctx := context.Background()
	const live, stale = "44444444-4444-4444-8444-444444444444", "55555555-5555-4555-8555-555555555555"
	seedKeyAndOutcome(t, c, live, "https://zone-b.example/api", time.Now().Add(time.Minute))
	seedKeyAndOutcome(t, c, stale, "https://zone-b.example/api", time.Now().Add(time.Minute))
	if _, err := c.Exec(ctx, `INSERT INTO upstream_token
		(token_id, peer_zone, audience, tenant, outcome_id, token_ref, key_ref, state, issued_at, expires_at, renew_after) VALUES
		('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'zone-b', 'https://zone-b.example/api', '', $1, 'kv/live',  'transit:store-1:v1', 'active', now() - interval '1 hour', now() + interval '1 hour', now()),
		('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'zone-b', 'https://zone-b.example/api', '', $2, 'kv/stale', 'transit:store-1:v1', 'retired', now() - interval '3 hours', now() - interval '1 hour', now() - interval '2 hours')`,
		live, stale); err != nil {
		t.Fatal(err)
	}
	// The route's live token: active, or claimed for renewal and still the route's token until its
	// replacement commits (migration 4 allows one live row per route).
	const lookup = `SELECT token_ref FROM upstream_token
		WHERE peer_zone = $1 AND audience = $2 AND tenant = $3 AND state IN ('active', 'renewing') AND expires_at > now()
		ORDER BY expires_at DESC LIMIT 1`
	var ref string
	if err := c.QueryRow(ctx, lookup, "zone-b", "https://zone-b.example/api", "").Scan(&ref); err != nil || ref != "kv/live" {
		t.Errorf("lookup returned %q, %v; want kv/live", ref, err)
	}
	// Another tenant, another zone, another audience: no token, which the API reports as
	// TOK-NO-UPSTREAM rather than guessing.
	for _, route := range [][3]string{
		{"zone-b", "https://zone-b.example/api", "tenant-x"},
		{"zone-c", "https://zone-b.example/api", ""},
		{"zone-b", "https://zone-b.example/other", ""},
	} {
		err := c.QueryRow(ctx, lookup, route[0], route[1], route[2]).Scan(&ref)
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Errorf("route %v: %v; want no rows", route, err)
		}
	}
	// A row being renewed is still the route's token.
	if _, err := c.Exec(ctx, `UPDATE upstream_token SET state = 'renewing', claimed_at = now(), claimed_by = 'w' WHERE token_ref = 'kv/live'`); err != nil {
		t.Fatal(err)
	}
	if err := c.QueryRow(ctx, lookup, "zone-b", "https://zone-b.example/api", "").Scan(&ref); err != nil || ref != "kv/live" {
		t.Errorf("renewing: lookup returned %q, %v; want kv/live", ref, err)
	}
	// A second live row for the route is refused by the schema.
	if _, err := c.Exec(ctx, `UPDATE upstream_token SET state = 'active' WHERE token_ref = 'kv/stale'`); !isUniqueViolation(err) {
		t.Errorf("second live row: %v; want a unique violation", err)
	}
	// With only the stale token left, the route has no valid token; a failed or retired one never
	// counts.
	if _, err := c.Exec(ctx, `UPDATE upstream_token SET state = 'retired' WHERE token_ref = 'kv/live'`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, `UPDATE upstream_token SET state = 'active' WHERE token_ref = 'kv/stale'`); err != nil {
		t.Fatal(err)
	}
	if err := c.QueryRow(ctx, lookup, "zone-b", "https://zone-b.example/api", "").Scan(&ref); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("expired-only route: %v; want no rows", err)
	}
	if _, err := c.Exec(ctx, `UPDATE upstream_token SET state = 'failed', expires_at = now() + interval '1 hour' WHERE token_ref = 'kv/stale'`); err != nil {
		t.Fatal(err)
	}
	if err := c.QueryRow(ctx, lookup, "zone-b", "https://zone-b.example/api", "").Scan(&ref); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("failed-only route: %v; want no rows", err)
	}
}

func TestRenewalClaimIsSingleFlight(t *testing.T) {
	db := newTestDatabase(t)
	c := db.migrated()
	ctx := context.Background()
	const outcome = "66666666-6666-4666-8666-666666666666"
	seedKeyAndOutcome(t, c, outcome, "https://zone-b.example/api", time.Now().Add(time.Minute))
	if _, err := c.Exec(ctx, `INSERT INTO upstream_token
		(token_id, peer_zone, audience, tenant, outcome_id, token_ref, key_ref, state, issued_at, expires_at, renew_after)
		VALUES ('dddddddd-dddd-4ddd-8ddd-dddddddddddd', 'zone-b', 'https://zone-b.example/api', '', $1, 'kv/due', 'transit:store-1:v1', 'active', now() - interval '50 minutes', now() + interval '10 minutes', now() - interval '5 minutes')`,
		outcome); err != nil {
		t.Fatal(err)
	}
	const claim = `SELECT token_id FROM upstream_token
		WHERE state = 'active' AND claimed_at IS NULL AND renew_after <= now()
		ORDER BY renew_after FOR UPDATE SKIP LOCKED LIMIT 1`

	first, second := db.conn(), db.conn()
	tx1, err := first.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx1.Rollback(ctx) }()
	var id string
	if err := tx1.QueryRow(ctx, claim).Scan(&id); err != nil {
		t.Fatalf("first worker found no due token: %v", err)
	}
	// While the first worker holds its row, a second worker sees nothing to do.
	tx2, err := second.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var other string
	if err := tx2.QueryRow(ctx, claim).Scan(&other); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("second worker: %q, %v; want no rows", other, err)
	}
	_ = tx2.Rollback(ctx)
	if _, err := tx1.Exec(ctx, `UPDATE upstream_token SET state = 'renewing', claimed_at = now(), claimed_by = 'worker-1', updated_at = now() WHERE token_id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if err := tx1.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// Once claimed, the token is off the due list for every worker.
	if err := second.QueryRow(ctx, claim).Scan(&other); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("after the claim: %q, %v; want no rows", other, err)
	}
	// The staleness sweep releases a claim older than the window; the token is due again.
	tag, err := second.Exec(ctx, `UPDATE upstream_token SET state = 'active', claimed_at = NULL, claimed_by = NULL, updated_at = now()
		WHERE state = 'renewing' AND claimed_at <= now() - $1::interval`, "0 seconds")
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("sweep released %d claims, %v; want 1", tag.RowsAffected(), err)
	}
	if err := second.QueryRow(ctx, claim).Scan(&other); err != nil || other != id {
		t.Errorf("after the sweep: %q, %v; want %q", other, err, id)
	}
	// A claim without a claimant, or a claimant without a claim, is refused by the schema.
	if _, err := c.Exec(ctx, `UPDATE upstream_token SET claimed_at = now(), claimed_by = NULL WHERE token_id = $1`, id); err == nil {
		t.Error("a claim without claimed_by was accepted")
	}
}

func TestClientAndTokenRecordsRoundTrip(t *testing.T) {
	db := newTestDatabase(t)
	c := db.migrated()
	ctx := context.Background()
	if _, err := c.Exec(ctx, `INSERT INTO oauth2_client (client_id, secret_hash, grant_types, scopes, audience, dpop_bound, metadata)
		VALUES ('client-a', '\x2432612431302e2e2e'::bytea, '{client_credentials}', '{read,write}', '{https://zone-b.example/api}', true,
		        '{"client_name":"participant a","grant_types":["client_credentials"]}')`); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"access", "registration"} {
		// The same signature may exist once per kind; a second row of one kind is a replay of the
		// store's own record and is refused.
		if _, err := c.Exec(ctx, `INSERT INTO oauth2_token
			(kind, signature, request_id, client_id, requested_at, granted_scopes, granted_audience, session, expires_at)
			VALUES ($1, 'sig-1', 'req-1', 'client-a', now(), '{read}', '{https://zone-b.example/api}', '\x00'::bytea, now() + interval '5 minutes')`, kind); err != nil {
			t.Fatalf("token of kind %s: %v", kind, err)
		}
	}
	_, err := c.Exec(ctx, `INSERT INTO oauth2_token
		(kind, signature, request_id, client_id, requested_at, session, expires_at)
		VALUES ('access', 'sig-1', 'req-2', 'client-a', now(), '\x00'::bytea, now() + interval '5 minutes')`)
	if !isUniqueViolation(err) {
		t.Errorf("duplicate access token signature: %v; want a unique violation", err)
	}
	var scopes []string
	var bound bool
	if err := c.QueryRow(ctx, `SELECT scopes, dpop_bound FROM oauth2_client WHERE client_id = 'client-a'`).Scan(&scopes, &bound); err != nil {
		t.Fatal(err)
	}
	if len(scopes) != 2 || !bound {
		t.Errorf("client read back as scopes=%v dpop_bound=%v", scopes, bound)
	}
	// Deleting a client takes its tokens with it: a removed registration leaves no usable record.
	if _, err := c.Exec(ctx, `DELETE FROM oauth2_client WHERE client_id = 'client-a'`); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := c.QueryRow(ctx, `SELECT count(*) FROM oauth2_token`).Scan(&left); err != nil || left != 0 {
		t.Errorf("%d tokens left after deleting the client, %v; want 0", left, err)
	}
}

func TestNoncesExpire(t *testing.T) {
	db := newTestDatabase(t)
	c := db.migrated()
	ctx := context.Background()
	if _, err := c.Exec(ctx, `INSERT INTO oauth2_dpop_nonce (nonce, expires_at) VALUES
		('fresh', now() + interval '60 seconds'), ('spent', now() - interval '1 second')`); err != nil {
		t.Fatal(err)
	}
	const valid = `SELECT EXISTS (SELECT 1 FROM oauth2_dpop_nonce WHERE nonce = $1 AND expires_at > now())`
	for nonce, want := range map[string]bool{"fresh": true, "spent": false, "unknown": false} {
		var got bool
		if err := c.QueryRow(ctx, valid, nonce).Scan(&got); err != nil || got != want {
			t.Errorf("nonce %q valid = %v, %v; want %v", nonce, got, err, want)
		}
	}
}

func TestAuditEventsAreOrderedAndReferenceTheirSubject(t *testing.T) {
	db := newTestDatabase(t)
	c := db.migrated()
	ctx := context.Background()
	const outcome, token = "77777777-7777-4777-8777-777777777777", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	seedKeyAndOutcome(t, c, outcome, "https://zone-b.example/api", time.Now().Add(time.Minute))
	if ok, err := consume(ctx, c, outcome, "https://zone-b.example/api", token); err != nil || !ok {
		t.Fatalf("consume: ok=%v err=%v", ok, err)
	}
	if _, err := c.Exec(ctx, `INSERT INTO audit_event (kind, correlation_id, client_id, outcome_id, token_id, reason_code, detail) VALUES
		('registration.refused', 'corr-1', 'client-x', NULL, NULL, 'TOK-CALLER-DENIED', '{"requested":["admin"]}'),
		('outcome.consumed', 'corr-2', 'client-a', $1, $2, NULL, NULL),
		('renewal.failed', 'corr-3', NULL, $1, $2, 'TOK-NO-UPSTREAM', '{"attempt":1}')`, outcome, token); err != nil {
		t.Fatal(err)
	}
	rows, err := c.Query(ctx, `SELECT kind FROM audit_event ORDER BY event_id`)
	if err != nil {
		t.Fatal(err)
	}
	kinds, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(kinds) != 3 || kinds[0] != "registration.refused" || kinds[2] != "renewal.failed" {
		t.Errorf("events read back as %v, %v", kinds, err)
	}
	// The events of one token, and of one outcome, are found by their reference.
	var byToken, byOutcome int
	if err := c.QueryRow(ctx, `SELECT count(*) FROM audit_event WHERE token_id = $1`, token).Scan(&byToken); err != nil || byToken != 2 {
		t.Errorf("%d events for the token, %v; want 2", byToken, err)
	}
	if err := c.QueryRow(ctx, `SELECT count(*) FROM audit_event WHERE outcome_id = $1`, outcome).Scan(&byOutcome); err != nil || byOutcome != 2 {
		t.Errorf("%d events for the outcome, %v; want 2", byOutcome, err)
	}
	if _, err := c.Exec(ctx, `UPDATE audit_event SET event_id = 99 WHERE event_id = 1`); err == nil {
		t.Error("an identity column accepted an explicit value")
	}
}

// One active version per signing key (migration 5): rotation activates the next version only once
// the previous one is retired, and the database refuses a second active version of the same key
// name whatever path tried to insert it. Another key's active version is not affected.
func TestOneActiveVersionPerSigningKey(t *testing.T) {
	db := newTestDatabase(t)
	c := db.migrated()
	ctx := context.Background()
	insert := func(ref, jkt string) error {
		_, err := c.Exec(ctx, `INSERT INTO signing_key (key_ref, jkt, alg, state) VALUES ($1, $2, 'ES256', 'active')`, ref, jkt)
		return err
	}
	if err := insert("transit:store-a:v1", "jkt-a1"); err != nil {
		t.Fatal(err)
	}
	if err := insert("transit:store-a:v2", "jkt-a2"); !isUniqueViolation(err) {
		t.Fatalf("a second active version of the same key: %v; want unique violation", err)
	}
	if err := insert("transit:store-b:v1", "jkt-b1"); err != nil {
		t.Fatalf("another key's active version: %v", err)
	}
	if _, err := c.Exec(ctx, `UPDATE signing_key SET state = 'retired', retired_at = now() WHERE key_ref = 'transit:store-a:v1'`); err != nil {
		t.Fatal(err)
	}
	if err := insert("transit:store-a:v2", "jkt-a2"); err != nil {
		t.Fatalf("the next version once the previous one is retired: %v", err)
	}
	var active int
	if err := c.QueryRow(ctx, `SELECT count(*) FROM signing_key WHERE state = 'active' AND split_part(key_ref, ':', 2) = 'store-a'`).Scan(&active); err != nil || active != 1 {
		t.Fatalf("%d active versions of store-a, %v; want 1", active, err)
	}
}
