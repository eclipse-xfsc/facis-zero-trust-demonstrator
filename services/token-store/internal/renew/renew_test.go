package renew

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/pgtest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire/acquiretest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/substitute"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/testsupport"
)

// These tests run renewal against real infrastructure: a zone-A database, OpenBao for transit and
// KV, and zone B as the real connector binary (acquiretest). They skip without
// TOKEN_STORE_TEST_DATABASE_URL, TRANSIT_TEST_ADDR and TRANSIT_TEST_TOKEN.

func TestMain(m *testing.M) {
	code := m.Run()
	acquiretest.Cleanup()
	os.Exit(code)
}

// secrets follows the values written, so a test can find the one a discarded renewal wrote.
type secrets struct {
	transit.Secrets
	mu      sync.Mutex
	created []string
}

func (s *secrets) Create(ctx context.Context, path string, v []byte) error {
	if err := s.Secrets.Create(ctx, path, v); err != nil {
		return err
	}
	s.mu.Lock()
	s.created = append(s.created, path)
	s.mu.Unlock()
	return nil
}

func (s *secrets) last() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.created[len(s.created)-1]
}

type env struct {
	t       *testing.T
	ctx     context.Context
	poolA   *pgxpool.Pool
	poolB   *pgxpool.Pool
	kv      *transit.Client
	secrets *secrets
	b       acquiretest.ZoneB
	a       *acquire.Acquirer
	loaded  acquire.Loaded
	route   acquire.Route
	logs    *testsupport.Buffer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	addr, token := os.Getenv("TRANSIT_TEST_ADDR"), os.Getenv("TRANSIT_TEST_TOKEN")
	if addr == "" || token == "" {
		t.Skip("TRANSIT_TEST_ADDR and TRANSIT_TEST_TOKEN not set")
	}
	if os.Getenv(pgtest.DatabaseEnv) == "" {
		t.Skipf("%s not set", pgtest.DatabaseEnv)
	}
	e := &env{t: t, ctx: t.Context(), logs: &testsupport.Buffer{}}
	var err error
	if e.poolA, err = pgxpool.New(e.ctx, pgtest.MigratedURL(t, "ren_a")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.poolA.Close)
	dsnB := pgtest.MigratedURL(t, "ren_b")
	if e.poolB, err = pgxpool.New(e.ctx, dsnB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.poolB.Close)
	if e.kv, err = transit.New(transit.Config{Addr: addr, Token: func(context.Context) (string, error) { return token, nil }}); err != nil {
		t.Fatal(err)
	}
	e.secrets = &secrets{Secrets: e.kv}
	issuer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	e.b = acquiretest.StartConnector(t, dsnB, addr, token, &issuer.PublicKey)
	e.route = acquire.Route{Name: "zone-b-api", PeerZone: "zone-b", Audience: acquiretest.Audience, ConnectorURL: e.b.Base,
		ClientID: e.b.ClientID, ClientSecretFile: acquiretest.WriteFile(t, "secret", e.b.ClientSecret+"\n"),
		Outcomes: acquire.Fixture{Issuer: acquiretest.VPIssuer, Kid: acquiretest.VPKid, Key: issuer,
			Claims: if03.Claims{Role: acquiretest.VPRole, Entitlement: acquiretest.VPEntitle}}}
	e.loaded = acquire.Loaded{SigningKey: "ren-a-" + acquiretest.RandHex(6), Routes: map[string]acquire.Route{e.route.Name: e.route}}
	e.a = &acquire.Acquirer{DB: e.poolA, Signer: e.kv, Secrets: e.secrets, KeyName: e.loaded.SigningKey,
		Trusted: if03.Issuers{acquiretest.VPIssuer: {acquiretest.VPKid: &issuer.PublicKey}},
		Log:     slog.New(slog.NewJSONHandler(e.logs, nil)), Prefix: "ztd/token-store-test/" + acquiretest.RandHex(6)}
	return e
}

func (e *env) worker(instance string) *Worker {
	return &Worker{DB: e.poolA, Acquirer: e.a, Routes: e.loaded, Instance: instance, Backoff: 10 * time.Millisecond,
		StaleAfter: time.Second, Log: slog.New(slog.NewJSONHandler(e.logs, nil))}
}

// due acquires the route's token and makes it due for renewal; it returns the token id.
func (e *env) due() string {
	e.t.Helper()
	tok, err := e.a.Acquire(e.ctx, e.route)
	if err != nil {
		e.t.Fatal(err)
	}
	e.makeDue(tok.ID)
	return tok.ID
}

func (e *env) makeDue(id string) {
	e.t.Helper()
	if _, err := e.poolA.Exec(e.ctx, `UPDATE upstream_token SET renew_after = now() - interval '1 second' WHERE token_id = $1`, id); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) count(pool *pgxpool.Pool, sql string, args ...any) int {
	e.t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *env) acquisitions() int {
	return e.count(e.poolB, `SELECT count(*) FROM verified_outcome WHERE consumed_at IS NOT NULL`)
}

func (e *env) state(id string) string {
	e.t.Helper()
	var s string
	if err := e.poolA.QueryRow(e.ctx, `SELECT state FROM upstream_token WHERE token_id = $1`, id).Scan(&s); err != nil {
		e.t.Fatal(err)
	}
	return s
}

// active is the route's one active row; the test fails unless there is exactly one.
func (e *env) active() string {
	e.t.Helper()
	var id string
	if err := e.poolA.QueryRow(e.ctx, `SELECT token_id::text FROM upstream_token WHERE state = 'active'`).Scan(&id); err != nil {
		e.t.Fatalf("no single active row: %v", err)
	}
	return id
}

func TestTwoWorkersRenewADueTokenExactlyOncePerCycle(t *testing.T) {
	e := newEnv(t)
	w1, w2 := e.worker("w1"), e.worker("w2")
	old := e.due()
	for cycle := range 3 {
		before := e.acquisitions()
		start := make(chan struct{})
		var wg sync.WaitGroup
		for _, w := range []*Worker{w1, w2} {
			wg.Go(func() { <-start; w.Cycle(e.ctx) })
		}
		close(start)
		wg.Wait()
		if n := e.acquisitions() - before; n != 1 {
			t.Fatalf("cycle %d: %d renewal attempts reached B; want exactly 1", cycle, n)
		}
		if n := e.count(e.poolA, `SELECT count(*) FROM audit_event WHERE detail->>'replaces' = $1`, old); n != 1 {
			t.Errorf("cycle %d: %d audited attempts for the token; want 1", cycle, n)
		}
		if s := e.state(old); s != "retired" {
			t.Errorf("cycle %d: the renewed row is %s; want retired", cycle, s)
		}
		next := e.active()
		if next == old {
			t.Fatalf("cycle %d: no new active row", cycle)
		}
		old = next
		e.makeDue(old)
	}
}

// TestAClaimSkipsARowAnotherWorkerIsClaiming: a worker never waits for a row another worker holds
// locked mid-claim; it finds nothing to do at once.
func TestAClaimSkipsARowAnotherWorkerIsClaiming(t *testing.T) {
	e := newEnv(t)
	id := e.due()
	tx, err := e.poolA.Begin(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(e.ctx, `SELECT 1 FROM upstream_token WHERE token_id = $1 FOR UPDATE`, id); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(e.ctx, time.Second)
	defer cancel()
	claims, err := e.worker("w2").claim(ctx, 1)
	if err != nil || len(claims) != 0 {
		t.Fatalf("claim while another worker holds the row: %v, %v; want nothing, at once", claims, err)
	}
	_ = tx.Rollback(e.ctx)
	if claims, err := e.worker("w2").claim(e.ctx, 1); err != nil || len(claims) != 1 || claims[0].Fence.TokenID != id {
		t.Fatalf("claim after the lock: %v, %v", claims, err)
	}
}

func TestIssuerDownFailsTheTokenAndSubstitutionHasNoUpstream(t *testing.T) {
	e := newEnv(t)
	id := e.due()
	e.b.Stop()
	w := e.worker("w1")
	w.Attempts = 3
	w.Cycle(e.ctx)
	if s := e.state(id); s != "failed" {
		t.Fatalf("after the bounded attempts the token is %s; want failed", s)
	}
	if n := e.count(e.poolA, `SELECT count(*) FROM audit_event WHERE kind = 'upstream.failed' AND detail->>'replaces' = $1`, id); n != 3 {
		t.Errorf("%d audited attempts; want 3", n)
	}
	var code string
	if err := e.poolA.QueryRow(e.ctx, `SELECT reason_code FROM audit_event WHERE kind = 'renewal.failed' AND token_id = $1`, id).Scan(&code); err != nil || code != acquire.CodeChallenge {
		t.Errorf("renewal.failed reason %q, %v; want %s", code, err, acquire.CodeChallenge)
	}
	// Failed is terminal: a later cycle leaves it alone, and substitution never falls back to it.
	w.Cycle(e.ctx)
	if s := e.state(id); s != "failed" {
		t.Errorf("a later cycle changed the failed token to %s", s)
	}
	svc := &substitute.Service{DB: e.poolA, Signer: e.kv, Secrets: e.kv, Routes: e.loaded, Acquirer: e.a}
	_, err := svc.Substitute(e.ctx, substitute.Request{PeerZone: "zone-b", Audience: acquiretest.Audience, Method: "GET",
		TargetURI: acquiretest.Audience + "/v1/items"})
	if !errors.Is(err, substitute.ErrNoUpstream) {
		t.Errorf("substitution: %v; want TOK-NO-UPSTREAM", err)
	}
}

func TestACrashedWorkersClaimIsReleasedAndTheNextWorkerRenews(t *testing.T) {
	e := newEnv(t)
	id := e.due()
	// w1 claims and dies.
	if claims, err := e.worker("w1").claim(e.ctx, 1); err != nil || len(claims) != 1 {
		t.Fatalf("claim: %v %v", claims, err)
	}
	w2 := e.worker("w2")
	w2.Cycle(e.ctx)
	if s := e.state(id); s != "renewing" {
		t.Fatalf("a fresh claim was released: %s", s)
	}
	time.Sleep(w2.StaleAfter + 200*time.Millisecond)
	before := e.acquisitions()
	w2.Cycle(e.ctx)
	if s := e.state(id); s != "retired" || e.acquisitions()-before != 1 {
		t.Fatalf("after the sweep window: old row %s, %d renewals; want retired, 1", s, e.acquisitions()-before)
	}
	if n := e.count(e.poolA, `SELECT count(*) FROM audit_event WHERE kind = 'renewal.released' AND token_id = $1 AND reason_code = $2`, id, CodeClaimStale); n != 1 {
		t.Errorf("%d release audits; want 1", n)
	}
	e.active()

	// A stale claim on a token that has expired meanwhile is failed, not renewed.
	id = e.active()
	e.makeDue(id)
	if claims, err := e.worker("w1").claim(e.ctx, 1); err != nil || len(claims) != 1 {
		t.Fatalf("claim: %v %v", claims, err)
	}
	if _, err := e.poolA.Exec(e.ctx, `UPDATE upstream_token SET expires_at = now() - interval '1 second', renew_after = now() - interval '2 seconds' WHERE token_id = $1`, id); err != nil {
		t.Fatal(err)
	}
	time.Sleep(w2.StaleAfter + 200*time.Millisecond)
	before = e.acquisitions()
	w2.Cycle(e.ctx)
	if s := e.state(id); s != "failed" || e.acquisitions() != before {
		t.Errorf("stale claim on an expired token: %s, %d renewals; want failed, 0", s, e.acquisitions()-before)
	}
}

// TestASlowWorkersCompletionIsRejectedByTheFence: w1 claims and stalls; its claim goes stale and is
// taken by w2. Whether w2 has already renewed or is still renewing, w1's late completion and its late
// failure are both refused, its new value is deleted, and w2's outcome stands.
func TestASlowWorkersCompletionIsRejectedByTheFence(t *testing.T) {
	e := newEnv(t)
	w1, w2 := e.worker("w1"), e.worker("w2")
	stale := func() Claim {
		t.Helper()
		claims, err := w1.claim(e.ctx, 1)
		if err != nil || len(claims) != 1 {
			t.Fatalf("w1 claim: %v %v", claims, err)
		}
		time.Sleep(w1.StaleAfter + 200*time.Millisecond)
		return claims[0]
	}
	lateCompletion := func(c Claim) {
		t.Helper()
		_, err := e.a.Replace(e.ctx, e.route, c.Fence)
		var ae *acquire.Error
		if !errors.As(err, &ae) || ae.Code != acquire.CodeClaimLost {
			t.Fatalf("w1's late completion: %v; want %s", err, acquire.CodeClaimLost)
		}
		if _, err := e.kv.Read(e.ctx, e.secrets.last()); !errors.Is(err, transit.ErrNotFound) {
			t.Errorf("w1's discarded value: %v; want deleted", err)
		}
	}

	// Taken over and already renewed by w2.
	old := e.due()
	c1 := stale()
	w2.Cycle(e.ctx)
	renewed := e.active()
	if renewed == old {
		t.Fatal("w2 did not renew")
	}
	lateCompletion(c1)
	if got := e.active(); got != renewed {
		t.Errorf("the active row is %s; want w2's %s", got, renewed)
	}

	// Taken over by w2, which has not completed yet.
	e.makeDue(renewed)
	c1 = stale()
	if err := w2.releaseStale(e.ctx); err != nil {
		t.Fatal(err)
	}
	claims, err := w2.claim(e.ctx, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("w2 claim: %v %v", claims, err)
	}
	lateCompletion(c1)
	w1.fail(e.ctx, c1, "TEST-LATE-FAILURE")
	if s := e.state(renewed); s != "renewing" {
		t.Fatalf("w1's late completion or failure touched w2's claim: %s", s)
	}
	if _, err := e.a.Replace(e.ctx, e.route, claims[0].Fence); err != nil {
		t.Fatalf("w2's completion: %v", err)
	}
	if s := e.state(renewed); s != "retired" {
		t.Errorf("after w2's completion the old row is %s; want retired", s)
	}
	e.active()
	if n := e.count(e.poolA, `SELECT count(*) FROM audit_event WHERE reason_code = 'TEST-LATE-FAILURE'`); n != 0 {
		t.Errorf("w1's late failure was audited as a failure %d times", n)
	}
}

// TestTheRouteAlwaysHasExactlyOneLiveRow: while renewals retire and insert, a sampler never sees
// the route with no live row or with two, nor two active rows; the unique index refuses a second
// live row outright.
func TestTheRouteAlwaysHasExactlyOneLiveRow(t *testing.T) {
	e := newEnv(t)
	e.due()
	var bad atomic.Int64
	var samples atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			var live, active int
			if err := e.poolA.QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE state IN ('active', 'renewing')),
				count(*) FILTER (WHERE state = 'active') FROM upstream_token`).Scan(&live, &active); err != nil {
				continue
			}
			samples.Add(1)
			if live != 1 || active > 1 {
				bad.Add(1)
			}
		}
	})
	w := e.worker("w1")
	for range 3 {
		w.Cycle(e.ctx)
		id := e.active()
		e.makeDue(id)
	}
	close(stop)
	wg.Wait()
	if bad.Load() != 0 || samples.Load() < 10 {
		t.Errorf("%d of %d samples saw no live row, two live rows or two active rows", bad.Load(), samples.Load())
	}
	_, err := e.poolA.Exec(e.ctx, `UPDATE upstream_token SET state = 'active' WHERE state = 'retired' AND token_id IN
		(SELECT token_id FROM upstream_token WHERE state = 'retired' LIMIT 1)`)
	if err == nil {
		t.Error("a second live row for the route was accepted")
	}
}

// TestRunRenewsAndSweepsOrphans: Run schedules both. The acquirer's clock runs past the orphan age
// only once the renewal is done, since the renewal checks its token against that clock.
func TestRunRenewsAndSweepsOrphans(t *testing.T) {
	e := newEnv(t)
	id := e.due()
	orphan := e.a.Prefix + "/" + "00000000-0000-4000-8000-000000000001"
	if err := e.kv.Create(e.ctx, orphan, []byte("x")); err != nil {
		t.Fatal(err)
	}
	var offset atomic.Int64
	e.a.Now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	w := e.worker("w1")
	w.Every, w.OrphanEvery = 50*time.Millisecond, 50*time.Millisecond
	ctx, cancel := context.WithTimeout(e.ctx, 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); w.Run(ctx) }()
	for ctx.Err() == nil && e.state(id) != "retired" {
		time.Sleep(20 * time.Millisecond)
	}
	offset.Store(int64(acquire.OrphanAge + time.Minute))
	for ctx.Err() == nil {
		if _, err := e.kv.Read(e.ctx, orphan); errors.Is(err, transit.ErrNotFound) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if s := e.state(id); s != "retired" {
		t.Errorf("Run did not renew: %s", s)
	}
	if _, err := e.kv.Read(e.ctx, orphan); !errors.Is(err, transit.ErrNotFound) {
		t.Errorf("Run did not sweep the orphan: %v", err)
	}
	e.active()
}
