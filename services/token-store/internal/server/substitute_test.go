package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/pgtest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/tokenverify"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire/acquiretest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/caller"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/keys"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/testsupport"
)

// These tests run substitution against real infrastructure: a zone-A database, OpenBao for transit
// and KV, and zone B as the real connector binary (acquiretest). They skip without
// TOKEN_STORE_TEST_DATABASE_URL, TRANSIT_TEST_ADDR and TRANSIT_TEST_TOKEN.

const (
	guardID = "spiffe://zone-a.example/ns/ztd-mgmt/sa/guard"
	target  = acquiretest.Audience + "/v1/items"
)

// countingBao counts every OpenBao call the store makes, and fails or stalls transit signing or KV
// writes on demand: fault is "", "fail-sign", "hang-sign", "fail-create" or "hang-create". A
// stalled call returns only when its context ends.
type countingBao struct {
	*transit.Client
	calls  atomic.Int64
	fault  atomic.Value
	onSign atomic.Value // func(), called before every transit signature when set
}

func (c *countingBao) faulty(ctx context.Context, op string) error {
	f, _ := c.fault.Load().(string)
	switch f {
	case "fail-" + op:
		return errors.New("injected " + op + " failure")
	case "hang-" + op:
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func (c *countingBao) Sign(ctx context.Context, k transit.KeyVersion, in []byte) ([]byte, error) {
	c.calls.Add(1)
	if f, _ := c.onSign.Load().(func()); f != nil {
		f()
	}
	if err := c.faulty(ctx, "sign"); err != nil {
		return nil, err
	}
	return c.Client.Sign(ctx, k, in)
}

func (c *countingBao) PublicKey(ctx context.Context, k transit.KeyVersion) (*ecdsa.PublicKey, error) {
	c.calls.Add(1)
	return c.Client.PublicKey(ctx, k)
}

func (c *countingBao) EnsureKey(ctx context.Context, name string) (transit.KeyVersion, error) {
	c.calls.Add(1)
	return c.Client.EnsureKey(ctx, name)
}

func (c *countingBao) Read(ctx context.Context, path string) ([]byte, error) {
	c.calls.Add(1)
	return c.Client.Read(ctx, path)
}

func (c *countingBao) Create(ctx context.Context, path string, v []byte) error {
	c.calls.Add(1)
	if err := c.faulty(ctx, "create"); err != nil {
		return err
	}
	return c.Client.Create(ctx, path, v)
}

type subEnv struct {
	t       *testing.T
	dsnA    string
	poolA   *pgxpool.Pool
	poolB   *pgxpool.Pool
	b       acquiretest.ZoneB
	bao     *countingBao
	loaded  acquire.Loaded
	prefix  string
	logs    *testsupport.Buffer
	servers []*Server
	refused []string // every refusal body, for the canary
}

// newSubEnv makes zone A's database and configuration; withB starts zone B and points the route at
// it, otherwise the route's connector is an address nothing listens on.
func newSubEnv(t *testing.T, withB bool) *subEnv {
	t.Helper()
	addr, token := os.Getenv("TRANSIT_TEST_ADDR"), os.Getenv("TRANSIT_TEST_TOKEN")
	if addr == "" || token == "" {
		t.Skip("TRANSIT_TEST_ADDR and TRANSIT_TEST_TOKEN not set")
	}
	if os.Getenv(pgtest.DatabaseEnv) == "" {
		t.Skipf("%s not set", pgtest.DatabaseEnv)
	}
	e := &subEnv{t: t, logs: &testsupport.Buffer{}, prefix: "ztd/token-store-test/" + acquiretest.RandHex(6)}
	e.dsnA = testDatabaseURL(t)
	migrate(t, e.dsnA)
	var err error
	if e.poolA, err = pgxpool.New(t.Context(), e.dsnA); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.poolA.Close)
	kv, err := transit.New(transit.Config{Addr: addr, Token: func(context.Context) (string, error) { return token, nil }})
	if err != nil {
		t.Fatal(err)
	}
	e.bao = &countingBao{Client: kv}
	issuer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	connector, clientID, secret := "http://127.0.0.1:1", "unused", "unused"
	if withB {
		dsnB := pgtest.MigratedURL(t, "sub_b")
		if e.poolB, err = pgxpool.New(t.Context(), dsnB); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(e.poolB.Close)
		e.b = acquiretest.StartConnector(t, dsnB, addr, token, &issuer.PublicKey)
		connector, clientID, secret = e.b.Base, e.b.ClientID, e.b.ClientSecret
	}
	// The route without a tenant, and seven tenant routes to the same peer: eight distinct routes.
	e.loaded = acquire.Loaded{
		SigningKey: "sub-a-" + acquiretest.RandHex(6),
		Trusted:    if03.Issuers{acquiretest.VPIssuer: {acquiretest.VPKid: &issuer.PublicKey}},
		Routes:     map[string]acquire.Route{},
	}
	secretFile := acquiretest.WriteFile(t, "secret", secret+"\n")
	var subs []caller.Route
	for _, tenant := range tenants {
		name := "zone-b-api"
		if tenant != "" {
			name += "-" + tenant
		}
		e.loaded.Routes[name] = acquire.Route{Name: name, PeerZone: "zone-b", Audience: acquiretest.Audience, Tenant: tenant,
			ConnectorURL: connector, ClientID: clientID, ClientSecretFile: secretFile,
			Outcomes: acquire.Fixture{Issuer: acquiretest.VPIssuer, Kid: acquiretest.VPKid, Key: issuer,
				Claims: if03.Claims{Role: acquiretest.VPRole, Entitlement: acquiretest.VPEntitle}}}
		subs = append(subs, caller.Route{Callers: []string{guardID}, PeerZone: "zone-b", Audience: acquiretest.Audience,
			Tenant: tenant, Methods: []string{"GET", "POST"}, TargetPrefix: acquiretest.Audience + "/v1"})
	}
	if e.loaded.Substitution, err = caller.NewRoutes(subs); err != nil {
		t.Fatal(err)
	}
	return e
}

var tenants = []string{"", "t1", "t2", "t3", "t4", "t5", "t6", "t7"}

// server starts one more store on zone A's database, without its renewal worker.
func (e *subEnv) server() (*Server, string) {
	e.t.Helper()
	return e.serverWith(false)
}

func (e *subEnv) serverWith(renewal bool) (*Server, string) {
	e.t.Helper()
	cfg := localConfig(e.dsnA, fakeOpenBao(e.t).URL)
	cfg.Callers = headerCaller{}
	cfg.ReplayCallers = []string{connectorID}
	cfg.Acquisition = &e.loaded
	cfg.OpenBao = e.bao
	s, err := New(context.Background(), cfg, testLogger(e.logs))
	if err != nil {
		e.t.Fatal(err)
	}
	s.substitute.Acquirer.Prefix = e.prefix
	if !renewal {
		s.renewal = nil // renewal is tested in internal/renew; here it would race the rows the tests set up
	}
	startServer(e.t, s)
	select {
	case <-s.keyStarted:
	case <-time.After(10 * time.Second):
		e.t.Fatal("startup key provisioning did not finish")
	}
	e.servers = append(e.servers, s)
	return s, "http://" + s.Addr().String() + "/internal/substitute"
}

func subRequest(over map[string]any) map[string]any {
	m := map[string]any{"peer_zone": "zone-b", "audience": acquiretest.Audience, "method": "GET",
		"target_uri": target + "?page=2", "correlation_id": "corr-1"}
	for k, v := range over {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return m
}

type subAnswer struct {
	status int
	header http.Header
	body   map[string]string
	raw    string
}

func (e *subEnv) post(url, who string, body any) subAnswer {
	e.t.Helper()
	raw, ok := body.(string)
	if !ok {
		b, _ := json.Marshal(body)
		raw = string(b)
	}
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(raw))
	if who != "" {
		req.Header.Set("X-Test-Caller", who)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	a := subAnswer{status: resp.StatusCode, header: resp.Header, raw: string(data)}
	_ = json.Unmarshal(data, &a.body)
	if a.status != http.StatusOK {
		e.refused = append(e.refused, a.raw)
	}
	return a
}

func (e *subEnv) count(pool *pgxpool.Pool, sql string, args ...any) int {
	e.t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// acquisitions is how many outcomes zone B consumed: one per acquisition that reached the grant.
func (e *subEnv) acquisitions() int {
	return e.count(e.poolB, `SELECT count(*) FROM verified_outcome WHERE consumed_at IS NOT NULL`)
}

func part(t *testing.T, jws string, i int) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(jws, ".")[i])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m
}

type memReplay struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (m *memReplay) TryUse(_ context.Context, u replay.Use) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := u.JKT + u.Method + u.URI + u.JTI
	if m.seen[k] {
		return false, nil
	}
	m.seen[k] = true
	return true, nil
}

func TestSubstitute_ValidTokenYieldsTheAuthorizationAndAFreshProofAcceptedByB(t *testing.T) {
	e := newSubEnv(t, true)
	_, url := e.server()

	first := e.post(url, guardID, subRequest(nil))
	if first.status != http.StatusOK {
		t.Fatalf("first: %d %s", first.status, first.raw)
	}
	if got := first.header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control %q; want no-store", got)
	}
	second := e.post(url, guardID, subRequest(map[string]any{"method": "POST", "upstream_nonce": "nonce-from-b"}))
	if second.status != http.StatusOK {
		t.Fatalf("second: %d %s", second.status, second.raw)
	}
	if n := e.acquisitions(); n != 1 {
		t.Errorf("%d acquisitions; want 1 (on demand, then the active row)", n)
	}
	var tokenID, ref, jkt string
	var expires time.Time
	if err := e.poolA.QueryRow(t.Context(), `SELECT u.token_id::text, u.token_ref, k.jkt, u.expires_at
		FROM upstream_token u JOIN signing_key k USING (key_ref) WHERE u.state = 'active'`).Scan(&tokenID, &ref, &jkt, &expires); err != nil {
		t.Fatal(err)
	}
	value, err := e.bao.Client.Read(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	token := string(value)
	ath := sha256.Sum256(value)
	for _, a := range []subAnswer{first, second} {
		if a.body["authorization"] != "DPoP "+token {
			t.Error("authorization is not DPoP + the active row's token")
		}
		if a.body["expires_at"] != expires.UTC().Format(time.RFC3339) {
			t.Errorf("expires_at %s; want %s", a.body["expires_at"], expires.UTC().Format(time.RFC3339))
		}
		h := part(t, a.body["dpop"], 0)
		jwkJSON, _ := json.Marshal(h["jwk"])
		var jwk jose.JWK
		_ = json.Unmarshal(jwkJSON, &jwk)
		if got, _ := jwk.Thumbprint(); h["typ"] != "dpop+jwt" || got != jkt {
			t.Errorf("proof header %v: not the store key %s", h, jkt)
		}
	}
	p1, p2 := part(t, first.body["dpop"], 1), part(t, second.body["dpop"], 1)
	if p1["htm"] != "GET" || p1["htu"] != target || p1["ath"] != base64.RawURLEncoding.EncodeToString(ath[:]) || p1["nonce"] != nil {
		t.Errorf("first proof claims %v", p1)
	}
	if p2["htm"] != "POST" || p2["htu"] != target || p2["nonce"] != "nonce-from-b" {
		t.Errorf("second proof claims %v", p2)
	}
	if p1["jti"] == "" || p1["jti"] == p2["jti"] {
		t.Errorf("jtis %v and %v; want two distinct ones", p1["jti"], p2["jti"])
	}

	// End to end: B's resource verifier accepts the token with each minted proof.
	verifier, err := tokenverify.New(tokenverify.Config{Issuer: acquiretest.BIssuer, JWKSURL: e.b.Base + "/.well-known/jwks.json",
		Audience: acquiretest.Audience, PublicBaseURL: acquiretest.Audience, Scopes: []string{acquiretest.VPScope},
		Replay: &memReplay{seen: map[string]bool{}}})
	if err != nil {
		t.Fatal(err)
	}
	for method, a := range map[string]subAnswer{"GET": first, "POST": second} {
		req, _ := http.NewRequest(method, target+"?page=2", nil)
		req.Header.Set("Authorization", a.body["authorization"])
		req.Header.Set("DPoP", a.body["dpop"])
		if id, err := verifier.Verify(req); err != nil || id.JKT != jkt {
			t.Errorf("%s: B's verifier refused the substitution: %+v %v", method, id, err)
		}
	}

	// Canary: no token, proof or client secret in a record or a refusal body.
	e.post(url, guardID, subRequest(map[string]any{"method": "DELETE"}))
	e.post(url, "", subRequest(nil))
	haystack := e.logs.String() + strings.Join(e.refused, "\n")
	for _, n := range []string{token, first.body["dpop"], second.body["dpop"], e.b.ClientSecret} {
		for i := 0; i+24 <= len(n); i += 24 {
			if strings.Contains(haystack, n[i:i+24]) {
				t.Fatal("a credential piece leaked into the records or a refusal")
			}
		}
	}
	if !strings.Contains(e.logs.String(), tokenID) {
		t.Error("the substitution left no record naming the token id")
	}
}

func TestSubstitute_ExpiredOrFailedOnlyIsNoUpstream(t *testing.T) {
	e := newSubEnv(t, true)
	_, url := e.server()
	if a := e.post(url, guardID, subRequest(nil)); a.status != http.StatusOK {
		t.Fatalf("acquiring: %d %s", a.status, a.raw)
	}
	// Zone B goes away, so no new token can be had, and the only row expires.
	e.b.Stop()
	if _, err := e.poolA.Exec(t.Context(), `UPDATE upstream_token SET issued_at = now() - interval '10 minutes',
		expires_at = now() - interval '1 second', renew_after = now() - interval '2 seconds'`); err != nil {
		t.Fatal(err)
	}
	if a := e.post(url, guardID, subRequest(nil)); a.status != http.StatusConflict || a.body["reason_code"] != "TOK-NO-UPSTREAM" {
		t.Fatalf("expired-only: %d %s; want 409 TOK-NO-UPSTREAM", a.status, a.raw)
	}
	// A failed or retired row is never a fallback, however long it would still be valid.
	for _, state := range []string{"failed", "retired"} {
		if _, err := e.poolA.Exec(t.Context(), `UPDATE upstream_token SET state = $1, expires_at = now() + interval '5 minutes',
			renew_after = now() + interval '4 minutes'`, state); err != nil {
			t.Fatal(err)
		}
		if a := e.post(url, guardID, subRequest(nil)); a.status != http.StatusConflict || a.body["reason_code"] != "TOK-NO-UPSTREAM" {
			t.Errorf("%s-only: %d %s; want 409 TOK-NO-UPSTREAM", state, a.status, a.raw)
		}
	}
}

func TestSubstitute_DeniesCallersAndRoutesBeforeAnyRead(t *testing.T) {
	e := newSubEnv(t, false)
	s, url := e.server()
	// Nothing below may touch the database or OpenBao: the pool is closed, so a read would answer
	// 503, and OpenBao counts its calls.
	s.pool.Close()
	before := e.bao.calls.Load()

	for name, who := range map[string]string{"unauthenticated": "", "not on any route": strangerID, "replay caller only": connectorID} {
		if a := e.post(url, who, subRequest(nil)); a.status != http.StatusForbidden || a.body["reason_code"] != "TOK-CALLER-DENIED" {
			t.Errorf("%s: %d %s; want 403 TOK-CALLER-DENIED", name, a.status, a.raw)
		}
	}
	for name, body := range map[string]any{
		"wrong method":            subRequest(map[string]any{"method": "DELETE"}),
		"wrong target":            subRequest(map[string]any{"target_uri": acquiretest.Audience + "/admin"}),
		"target escaping prefix":  subRequest(map[string]any{"target_uri": acquiretest.Audience + "/v1/../admin"}),
		"wrong peer zone":         subRequest(map[string]any{"peer_zone": "zone-c"}),
		"wrong audience":          subRequest(map[string]any{"audience": "https://other.zone-b.test"}),
		"wrong tenant":            subRequest(map[string]any{"tenant": "t9"}),
		"unknown field":           subRequest(map[string]any{"extra": 1}),
		"no correlation id":       subRequest(map[string]any{"correlation_id": nil}),
		"method outside the enum": subRequest(map[string]any{"method": "TRACE"}),
		"empty nonce":             subRequest(map[string]any{"upstream_nonce": ""}),
		"trailing data":           `{"peer_zone":"zone-b","audience":"` + acquiretest.Audience + `","method":"GET","target_uri":"` + target + `","correlation_id":"c"} {}`,
		"not JSON":                "peer_zone=zone-b",
		"over the size limit":     subRequest(map[string]any{"correlation_id": strings.Repeat("c", 10<<10)}),
		"correlation id too long": subRequest(map[string]any{"correlation_id": strings.Repeat("c", 129)}),
	} {
		if a := e.post(url, guardID, body); a.status != http.StatusForbidden || a.body["reason_code"] != "TOK-ROUTE-DENIED" {
			t.Errorf("%s: %d %s; want 403 TOK-ROUTE-DENIED", name, a.status, a.raw)
		}
	}
	if n := e.bao.calls.Load() - before; n != 0 {
		t.Errorf("%d OpenBao calls while refusing; want none", n)
	}
	// The control: an authorized request does read, and with the pool closed fails closed.
	if a := e.post(url, guardID, subRequest(map[string]any{"tenant": nil})); a.status != http.StatusServiceUnavailable ||
		a.body["reason_code"] != "TOK-STORE-UNAVAILABLE" {
		t.Errorf("authorized request with the database gone: %d %s; want 503 TOK-STORE-UNAVAILABLE", a.status, a.raw)
	}
	// Refusals echo nothing the caller sent.
	for _, r := range e.refused {
		if strings.Contains(r, "zone-c") || strings.Contains(r, "/admin") || strings.Contains(r, "TRACE") {
			t.Errorf("a refusal echoes the request: %s", r)
		}
	}
}

// TestSubstitute_OnDemandAcquisitionIsSingleFlight: with no live row (only an expired one), many
// concurrent substitutions on two store replicas sharing the database acquire exactly once; every
// caller gets that token, the expired row is retired in the same transaction, and the route ends with
// one live row.
func TestSubstitute_OnDemandAcquisitionIsSingleFlight(t *testing.T) {
	e := newSubEnv(t, true)
	_, url1 := e.server()
	_, url2 := e.server()
	if a := e.post(url1, guardID, subRequest(nil)); a.status != http.StatusOK {
		t.Fatalf("acquiring: %d %s", a.status, a.raw)
	}
	if _, err := e.poolA.Exec(t.Context(), `UPDATE upstream_token SET issued_at = now() - interval '10 minutes',
		expires_at = now() - interval '1 second', renew_after = now() - interval '2 seconds'`); err != nil {
		t.Fatal(err)
	}
	before := e.acquisitions()
	const n = 12
	answers := make([]subAnswer, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		url := url1
		if i%2 == 1 {
			url = url2
		}
		wg.Go(func() {
			<-start
			answers[i] = e.post(url, guardID, subRequest(nil))
		})
	}
	close(start)
	wg.Wait()
	for i, a := range answers {
		if a.status != http.StatusOK || a.body["authorization"] != answers[0].body["authorization"] {
			t.Fatalf("caller %d: %d %s; want the one acquired token", i, a.status, a.raw)
		}
	}
	if got := e.acquisitions() - before; got != 1 {
		t.Errorf("%d acquisitions for %d concurrent callers; want exactly 1", got, n)
	}
	if live := e.count(e.poolA, `SELECT count(*) FROM upstream_token WHERE state IN ('active', 'renewing')`); live != 1 {
		t.Errorf("%d live rows; want 1", live)
	}
	if retired := e.count(e.poolA, `SELECT count(*) FROM upstream_token WHERE state = 'retired' AND expires_at < now()`); retired != 1 {
		t.Errorf("%d retired expired rows; want 1", retired)
	}
}

// TestServe_RunsRenewal: a store started with routes runs the renewal worker, which renews a due
// token at once.
func TestServe_RunsRenewal(t *testing.T) {
	e := newSubEnv(t, true)
	_, url := e.server()
	if a := e.post(url, guardID, subRequest(nil)); a.status != http.StatusOK {
		t.Fatalf("acquiring: %d %s", a.status, a.raw)
	}
	if _, err := e.poolA.Exec(t.Context(), `UPDATE upstream_token SET renew_after = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	e.serverWith(true)
	deadline := time.Now().Add(10 * time.Second)
	for e.count(e.poolA, `SELECT count(*) FROM audit_event WHERE kind = 'upstream.renewed'`) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("the served store did not renew the due token")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n := e.count(e.poolA, `SELECT count(*) FROM upstream_token WHERE state = 'retired'`); n != 1 {
		t.Errorf("%d retired rows; want 1", n)
	}
}

// TestSubstitute_ColdRoutesDoNotStarveThePool: eight different routes without a token, substituted
// at once, each acquire their own token within the deadline, while the replay check keeps answering
// promptly: the cold routes never hold every pooled connection.
func TestSubstitute_ColdRoutesDoNotStarveThePool(t *testing.T) {
	e := newSubEnv(t, true)
	s, url := e.server()
	replayURL := "http://" + s.Addr().String() + "/internal/replay-check"
	answers := make([]subAnswer, len(tenants))
	elapsed := make([]time.Duration, len(tenants))
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, tenant := range tenants {
		wg.Go(func() {
			<-start
			begin := time.Now()
			answers[i] = e.post(url, guardID, subRequest(map[string]any{"tenant": tenant}))
			elapsed[i] = time.Since(begin)
		})
	}
	done := make(chan struct{})
	var slowest time.Duration
	var replayFailures int
	go func() {
		defer close(done)
		<-start
		for i := 0; ; i++ {
			<-time.After(20 * time.Millisecond)
			begin := time.Now()
			status, _ := postReplay(t, replayURL, connectorID, proofUse(fmt.Sprintf("cold-%d", i), time.Now()))
			slowest = max(slowest, time.Since(begin))
			if status != http.StatusOK {
				replayFailures++
			}
			if e.count(e.poolA, `SELECT count(*) FROM upstream_token`) == len(tenants) || i > 500 {
				return
			}
		}
	}()
	close(start)
	wg.Wait()
	<-done
	for i, a := range answers {
		if a.status != http.StatusOK || elapsed[i] > substituteTimeout {
			t.Errorf("route %q: %d after %v: %s", tenants[i], a.status, elapsed[i], a.raw)
		}
	}
	if replayFailures != 0 || slowest > time.Second {
		t.Errorf("the replay check during the cold start: %d failures, slowest %v", replayFailures, slowest)
	}
	if n := e.acquisitions(); n != len(tenants) {
		t.Errorf("%d acquisitions; want %d, one per route", n, len(tenants))
	}
}

// TestSubstitute_TheDeadlineBoundsAnOnDemandAcquisition: a KV write or a transit signature that
// hangs, or an activation blocked in the database, ends with the request's deadline: 503, no live
// row, no value, no advisory lock left behind, and the route acquires normally once the fault is gone.
func TestSubstitute_TheDeadlineBoundsAnOnDemandAcquisition(t *testing.T) {
	for _, fault := range []string{"hang-create", "hang-sign", "activation blocked"} {
		t.Run(fault, func(t *testing.T) {
			e := newSubEnv(t, true)
			s, url := e.server()
			s.subTimeout = 2 * time.Second
			var unblock func()
			if fault == "activation blocked" {
				tx, err := e.poolA.Begin(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(t.Context(), `LOCK TABLE upstream_token IN EXCLUSIVE MODE`); err != nil {
					t.Fatal(err)
				}
				unblock = func() { _ = tx.Rollback(context.Background()) }
				defer unblock()
			} else {
				e.bao.fault.Store(fault)
			}
			begin := time.Now()
			a := e.post(url, guardID, subRequest(nil))
			took := time.Since(begin)
			if a.status != http.StatusServiceUnavailable || a.body["reason_code"] != "TOK-STORE-UNAVAILABLE" {
				t.Errorf("%d %s; want 503 TOK-STORE-UNAVAILABLE", a.status, a.raw)
			}
			if took > s.subTimeout+time.Second {
				t.Errorf("answered after %v; the deadline is %v", took, s.subTimeout)
			}
			if unblock != nil {
				unblock()
			}
			e.bao.fault.Store("")
			if n := e.count(e.poolA, `SELECT count(*) FROM upstream_token WHERE state IN ('active', 'renewing')`); n != 0 {
				t.Errorf("%d live rows after the failed acquisition", n)
			}
			if vals, err := e.bao.List(t.Context(), e.prefix); err != nil || len(vals) != 0 {
				t.Errorf("values left: %v %v", vals, err)
			}
			locks := -1
			for range 50 {
				if locks = e.count(e.poolA, `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`); locks == 0 {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if locks != 0 {
				t.Errorf("%d advisory locks left behind", locks)
			}
			// The recovery request gets the server's own deadline back: a whole acquisition through the
			// peer connector can take longer than the 2 s the fault was given, on a loaded runner.
			s.subTimeout = substituteTimeout
			if a := e.post(url, guardID, subRequest(nil)); a.status != http.StatusOK {
				t.Errorf("after the fault: %d %s", a.status, a.raw)
			}
		})
	}
}

// TestSubstitute_StoreFailuresAre503AndAPeerRefusalIs409: a failing database, transit or KV during
// an on-demand acquisition is the store's unavailability, not an absent token; the peer refusing the
// grant is.
func TestSubstitute_StoreFailuresAre503AndAPeerRefusalIs409(t *testing.T) {
	e := newSubEnv(t, true)
	_, url := e.server()
	for name, inject := range map[string]func() func(){
		"transit": func() func() { e.bao.fault.Store("fail-sign"); return func() { e.bao.fault.Store("") } },
		"KV":      func() func() { e.bao.fault.Store("fail-create"); return func() { e.bao.fault.Store("") } },
		"database": func() func() {
			if _, err := e.poolA.Exec(t.Context(), `CREATE FUNCTION refuse() RETURNS trigger LANGUAGE plpgsql AS
				$$BEGIN RAISE EXCEPTION 'injected database failure'; END$$;
				CREATE TRIGGER refuse BEFORE INSERT ON verified_outcome FOR EACH ROW EXECUTE FUNCTION refuse()`); err != nil {
				t.Fatal(err)
			}
			return func() {
				if _, err := e.poolA.Exec(t.Context(), `DROP TRIGGER refuse ON verified_outcome; DROP FUNCTION refuse()`); err != nil {
					t.Fatal(err)
				}
			}
		},
	} {
		undo := inject()
		if a := e.post(url, guardID, subRequest(nil)); a.status != http.StatusServiceUnavailable || a.body["reason_code"] != "TOK-STORE-UNAVAILABLE" {
			t.Errorf("%s failure: %d %s; want 503 TOK-STORE-UNAVAILABLE", name, a.status, a.raw)
		}
		undo()
	}
	// The peer refuses the outcome: signed by a key the store trusts and the peer does not.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	e.loaded.Trusted[acquiretest.VPIssuer]["other"] = &other.PublicKey
	r := e.loaded.Routes["zone-b-api"]
	f := r.Outcomes.(acquire.Fixture)
	f.Kid, f.Key = "other", other
	r.Outcomes = f
	e.loaded.Routes["zone-b-api"] = r
	if a := e.post(url, guardID, subRequest(nil)); a.status != http.StatusConflict || a.body["reason_code"] != "TOK-NO-UPSTREAM" {
		t.Errorf("peer refusal: %d %s; want 409 TOK-NO-UPSTREAM", a.status, a.raw)
	}
	if !strings.Contains(e.logs.String(), "CRED-OUTCOME-SIGNATURE") {
		t.Error("the peer's refusal reason was not logged")
	}
}

// Readiness resolves every active signing_key reference through transit (D9): a reference to a
// real version with its thumbprint is ready; a version transit does not have, or another
// thumbprint, is not; references with no transit key configured are not either.
func TestReadyz_ResolvesActiveSigningKeys(t *testing.T) {
	e := newSubEnv(t, true)
	s, _ := e.server()
	ctx := t.Context()
	signing := func() string {
		t.Helper()
		rep := s.ready.run(ctx)
		if rep.Ready != (rep.Checks.SigningKey == checkOK) {
			t.Fatalf("ready %v with signing_key %q: %+v", rep.Ready, rep.Checks.SigningKey, rep.Checks)
		}
		return rep.Checks.SigningKey
	}
	if w := signing(); w != checkOK {
		t.Fatalf("no active reference: %q", w)
	}
	kv, jkt, err := keys.Keys{Signer: e.bao, Name: e.loaded.SigningKey}.Ensure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.poolA.Exec(ctx, `INSERT INTO signing_key (key_ref, jkt, alg, state) VALUES ($1, $2, 'ES256', 'active')`,
		kv.Ref(), jkt); err != nil {
		t.Fatal(err)
	}
	if w := signing(); w != checkOK {
		t.Fatalf("a valid reference: %q", w)
	}
	set := func(sql string, args ...any) {
		t.Helper()
		if _, err := e.poolA.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	set(`UPDATE signing_key SET jkt = $1`, strings.Repeat("A", 43))
	if w := signing(); w != checkMismatch {
		t.Errorf("another thumbprint: %q, want %q", w, checkMismatch)
	}
	set(`UPDATE signing_key SET jkt = $1, key_ref = $2`, jkt, transit.KeyVersion{Name: kv.Name, Version: kv.Version + 7}.Ref())
	if w := signing(); w != checkMissing {
		t.Errorf("a version transit does not have: %q, want %q", w, checkMissing)
	}
	set(`UPDATE signing_key SET key_ref = $1`, kv.Ref())
	if w := signing(); w != checkOK {
		t.Fatalf("restored: %q", w)
	}
	s.cfg.Acquisition = nil
	if w := signing(); w != checkUnconfigured {
		t.Errorf("no transit key configured: %q, want %q", w, checkUnconfigured)
	}
	set(`UPDATE signing_key SET state = 'retired', retired_at = now()`)
	if w := signing(); w != checkOK {
		t.Errorf("only a retired reference: %q", w)
	}
}

// Expiry is judged again when the answer leaves: a token that expires, or comes within the margin
// of expiring, while its value is read and its proof signed is not handed out.
func TestSubstitute_ATokenThatExpiresDuringSigningIsNoUpstream(t *testing.T) {
	e := newSubEnv(t, true)
	s, url := e.server()
	if a := e.post(url, guardID, subRequest(nil)); a.status != http.StatusOK {
		t.Fatalf("acquiring: %d %s", a.status, a.raw)
	}
	var expires time.Time
	if err := e.poolA.QueryRow(t.Context(), `SELECT expires_at FROM upstream_token WHERE state = 'active'`).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	var skew atomic.Int64 // how far the store's clock is ahead of the real one
	s.substitute.Now = func() time.Time { return time.Now().Add(time.Duration(skew.Load())) }
	for name, at := range map[string]time.Time{"past expiry": expires.Add(time.Second), "within the margin": expires.Add(-time.Second / 2)} {
		skew.Store(0)
		e.bao.onSign.Store(func() { skew.Store(int64(time.Until(at))) })
		a := e.post(url, guardID, subRequest(nil))
		if a.status != http.StatusConflict || a.body["reason_code"] != "TOK-NO-UPSTREAM" ||
			strings.Contains(a.raw, "authorization") || strings.Contains(a.raw, "dpop") {
			t.Errorf("%s: %d %q; want 409 TOK-NO-UPSTREAM and no credential", name, a.status, a.body["reason_code"])
		}
	}
	e.bao.onSign.Store(func() {})
	skew.Store(0)
	if a := e.post(url, guardID, subRequest(nil)); a.status != http.StatusOK {
		t.Errorf("the clock back: %d %s", a.status, a.raw)
	}
	if n := e.acquisitions(); n != 1 {
		t.Errorf("%d acquisitions; the discarded token must not be reacquired synchronously", n)
	}
}

// Real Connector/OpenBao public material is authoritative even without active rows.
func TestReadyz_RefusesSharedConnectorKeyMaterial(t *testing.T) {
	e := newSubEnv(t, true)
	if _, err := e.bao.EnsureKey(t.Context(), e.loaded.SigningKey); err != nil {
		t.Fatal(err)
	}
	s, _ := e.server()
	distinct := e.loaded.SigningKey
	if state := s.checkSigningKey(t.Context()); state != checkOK {
		t.Fatalf("distinct keys: %s", state)
	}
	e.loaded.SigningKey = e.b.SigningKey
	if state := s.checkSigningKey(t.Context()); state != checkSharedIssuerKey {
		t.Fatalf("shared key: %s", state)
	}
	oldRef, oldJKT, err := (keys.Keys{Signer: e.bao, Name: e.b.SigningKey}).Ensure(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, strings.TrimRight(os.Getenv("TRANSIT_TEST_ADDR"), "/")+"/v1/transit/keys/"+e.b.SigningKey+"/rotate", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", os.Getenv("TRANSIT_TEST_TOKEN"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal("rotation request failed")
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		t.Fatalf("rotation status %d", resp.StatusCode)
	}
	if state := s.checkSigningKey(t.Context()); state != checkOK {
		t.Fatalf("new latest key must differ from published older Connector key: %s", state)
	}
	if _, err := e.poolA.Exec(t.Context(), `INSERT INTO signing_key (key_ref,jkt,alg,state) VALUES ($1,$2,'ES256','active')`, oldRef.Ref(), oldJKT); err != nil {
		t.Fatal(err)
	}
	if state := s.checkSigningKey(t.Context()); state != checkSharedIssuerKey {
		t.Fatalf("shared older active version: %s", state)
	}
	if _, err := e.poolA.Exec(t.Context(), `DELETE FROM signing_key WHERE key_ref=$1`, oldRef.Ref()); err != nil {
		t.Fatal(err)
	}
	e.loaded.SigningKey = distinct
	if state := s.checkSigningKey(t.Context()); state != checkOK {
		t.Fatalf("restored separation: %s", state)
	}
	e.b.Stop()
	if state := s.checkSigningKey(t.Context()); state != checkOK {
		t.Fatalf("fresh cached result: %s", state)
	}
	s.issuerCache.mu.Lock()
	s.issuerCache.expires = time.Time{}
	s.issuerCache.mu.Unlock()
	if state := s.checkSigningKey(t.Context()); state != checkUnreachable {
		t.Fatalf("expired cache with unavailable issuer: %s", state)
	}
}
