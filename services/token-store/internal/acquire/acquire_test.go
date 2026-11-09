package acquire

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/pgtest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/tokenverify"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire/acquiretest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/keys"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/testsupport"
)

// These tests run zone A's acquisition against real infrastructure: a zone-A database, a zone-B
// Connector run as the real connector binary on a separate database (connector_test.go), and
// OpenBao for transit and KV. They skip without TOKEN_STORE_TEST_DATABASE_URL, TRANSIT_TEST_ADDR and
// TRANSIT_TEST_TOKEN.

const (
	vpIssuer  = acquiretest.VPIssuer
	vpKid     = acquiretest.VPKid
	bIssuer   = acquiretest.BIssuer
	audience  = acquiretest.Audience
	clientID  = "zone-a-token-store" // config test only; the Connector assigns the real id
	vpRole    = acquiretest.VPRole
	vpEntitle = acquiretest.VPEntitle
	vpScope   = acquiretest.VPScope
)

// hook sits between A and B: it records what A sends, can change a token request before B sees it
// and can replace or cut B's 200 answer to it.
type hook struct {
	mu          sync.Mutex
	onToken     func(form url.Values)
	onResponse  func(body []byte) ([]byte, error)
	tokenStatus []int
	sent        []string // every outcome, proof and access token that crossed, for the canary
}

func (h *hook) RoundTrip(req *http.Request) (*http.Response, error) {
	if !strings.HasSuffix(req.URL.Path, "/oauth2/token") {
		return http.DefaultTransport.RoundTrip(req)
	}
	raw, _ := io.ReadAll(req.Body)
	form, _ := url.ParseQuery(string(raw))
	h.mu.Lock()
	h.sent = append(h.sent, form.Get("outcome"), req.Header.Get("DPoP"))
	onToken, onResponse := h.onToken, h.onResponse
	h.mu.Unlock()
	if onToken != nil {
		onToken(form)
	}
	out := req.Clone(req.Context())
	body := form.Encode()
	out.Body = io.NopCloser(strings.NewReader(body))
	out.ContentLength = int64(len(body))
	resp, err := http.DefaultTransport.RoundTrip(out)
	if err != nil {
		return nil, err
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	h.mu.Lock()
	h.tokenStatus = append(h.tokenStatus, resp.StatusCode)
	var tr tokenResponse
	if json.Unmarshal(b, &tr) == nil && tr.AccessToken != "" {
		h.sent = append(h.sent, tr.AccessToken)
	}
	h.mu.Unlock()
	if resp.StatusCode == http.StatusOK && onResponse != nil {
		if b, err = onResponse(b); err != nil {
			return nil, err // the connection was cut after B answered, so after B committed
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(b))
	resp.ContentLength = int64(len(b))
	resp.Header.Del("Content-Length")
	return resp, nil
}

func (h *hook) set(f func(h *hook)) { h.mu.Lock(); defer h.mu.Unlock(); f(h) }

// clock is real time plus an offset a test moves.
type clock struct{ offset atomic.Int64 }

func (c *clock) Now() time.Time          { return time.Now().Add(time.Duration(c.offset.Load())) }
func (c *clock) Advance(d time.Duration) { c.offset.Add(int64(d)) }

// secrets wraps the real KV client so a test can fail or follow a write.
type secrets struct {
	transit.Secrets
	createErr   error
	afterCreate func(path string)
	created     []string
}

func (s *secrets) Create(ctx context.Context, path string, value []byte) error {
	if s.createErr != nil {
		return s.createErr
	}
	if err := s.Secrets.Create(ctx, path, value); err != nil {
		return err
	}
	s.created = append(s.created, path)
	if s.afterCreate != nil {
		s.afterCreate(path)
	}
	return nil
}

type env struct {
	token   string // the test's own OpenBao token, a canary for the records
	dsnA    string
	t       *testing.T
	ctx     context.Context
	a       *Acquirer
	route   Route
	poolA   *pgxpool.Pool
	poolB   *pgxpool.Pool
	kv      *transit.Client
	secrets *secrets
	hook    *hook
	clock   *clock
	logs    *testsupport.Buffer
	issuer  *ecdsa.PrivateKey
	bBase   string
	secret  string
	errs    []string
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
	ctx := t.Context()
	dsnA, dsnB := pgtest.MigratedURL(t, "acq_a"), pgtest.MigratedURL(t, "acq_b")
	poolA, err := pgxpool.New(ctx, dsnA)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(poolA.Close)
	poolB, err := pgxpool.New(ctx, dsnB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(poolB.Close)
	// The acquirer gets a token of its own, minted from the test token: a long random value that
	// the canary test can look for in the records, which the two-letter CI token is not.
	own := mintToken(t, addr, token)
	kv, err := transit.New(transit.Config{Addr: addr, Token: func(context.Context) (string, error) { return own, nil }})
	if err != nil {
		t.Fatal(err)
	}

	issuer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b := startConnector(t, dsnB, addr, token, &issuer.PublicKey)
	bBase, secret := b.base, b.clientSecret
	secretFile := filepath.Join(t.TempDir(), "client-secret")
	if err := os.WriteFile(secretFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &env{token: own, dsnA: dsnA, t: t, ctx: ctx, poolA: poolA, poolB: poolB, kv: kv, hook: &hook{}, clock: &clock{},
		logs: &testsupport.Buffer{}, issuer: issuer, bBase: bBase, secret: secret}
	e.secrets = &secrets{Secrets: kv}
	e.a = &Acquirer{
		DB: poolA, Signer: kv, Secrets: e.secrets, KeyName: "acq-a-" + randHex(6),
		Trusted:    if03.Issuers{vpIssuer: {vpKid: &issuer.PublicKey}},
		HTTPClient: &http.Client{Transport: e.hook, Timeout: 10 * time.Second},
		Log:        slog.New(slog.NewJSONHandler(e.logs, nil)),
		Now:        e.clock.Now,
		Prefix:     "ztd/token-store-test/" + randHex(6),
	}
	e.route = Route{Name: "zone-b-api", PeerZone: "zone-b", Audience: audience, ConnectorURL: bBase,
		ClientID: b.clientID, ClientSecretFile: secretFile,
		Outcomes: Fixture{Issuer: vpIssuer, Kid: vpKid, Key: issuer, Claims: if03.Claims{Role: vpRole, Entitlement: vpEntitle}, Now: e.clock.Now}}
	return e
}

// mintToken creates a child token of the test token with the same policies, so it is as able as
// the test token and as random as any real credential. The test token must be allowed to create
// child tokens (the default policy's auth/token/create; the dev root token in CI is).
func mintToken(t *testing.T, addr, token string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, strings.TrimSuffix(addr, "/")+"/v1/auth/token/create",
		strings.NewReader(`{"ttl":"30m","no_default_policy":false}`))
	req.Header.Set("X-Vault-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal("minting a test token failed")
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || len(out.Auth.ClientToken) < 24 {
		t.Fatalf("minting a test token: status %d", resp.StatusCode)
	}
	return out.Auth.ClientToken
}

func (e *env) acquire() (Token, error) {
	tok, err := e.a.Acquire(e.ctx, e.route)
	if err != nil {
		e.errs = append(e.errs, err.Error())
	}
	return tok, err
}

func (e *env) mustAcquire() Token {
	e.t.Helper()
	tok, err := e.acquire()
	if err != nil {
		e.t.Fatalf("acquire: %v", err)
	}
	return tok
}

func (e *env) wantCode(err error, code string) {
	e.t.Helper()
	var ae *Error
	if !errors.As(err, &ae) || ae.Code != code {
		e.t.Fatalf("error %v; want code %s", err, code)
	}
}

func count(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// state is what an acquisition may have left behind in A.
type state struct{ rows, receipts, unconsumed, values int }

func (e *env) state() state {
	vals, err := e.kv.List(e.ctx, e.a.kvPrefix())
	if err != nil {
		e.t.Fatal(err)
	}
	return state{
		rows:       count(e.t, e.poolA, `SELECT count(*) FROM upstream_token`),
		receipts:   count(e.t, e.poolA, `SELECT count(*) FROM verified_outcome`),
		unconsumed: count(e.t, e.poolA, `SELECT count(*) FROM verified_outcome WHERE consumed_at IS NULL`),
		values:     len(vals),
	}
}

func (e *env) lastAudit() (kind, code string) {
	e.t.Helper()
	var c *string
	if err := e.poolA.QueryRow(e.ctx, `SELECT kind, reason_code FROM audit_event ORDER BY event_id DESC LIMIT 1`).Scan(&kind, &c); err != nil {
		e.t.Fatal(err)
	}
	if c != nil {
		code = *c
	}
	return kind, code
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// resign changes the outcome's payload and signs it again with key.
func resign(t *testing.T, outcome string, key *ecdsa.PrivateKey, edit func(map[string]any)) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(outcome, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	_ = json.Unmarshal(raw, &p)
	edit(p)
	payload, _ := json.Marshal(p)
	s, err := jose.Sign(context.Background(), jose.Header{Typ: if03.Typ, Kid: vpKid}, payload, func(_ context.Context, in []byte) ([]byte, error) {
		return signES256(key, in)
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// claimsOf decodes a JWT payload.
func claimsOf(t *testing.T, token string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
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

func TestAcquireActivatesABoundTokenAfterOneNonceRetry(t *testing.T) {
	e := newEnv(t)
	tok := e.mustAcquire()

	// One nonce challenge, then the grant.
	if got := e.hook.tokenStatus; len(got) != 2 || got[0] != http.StatusBadRequest || got[1] != http.StatusOK {
		t.Fatalf("token request statuses %v; want [400 200] (nonce challenge, then the grant)", got)
	}
	var ref, keyRef, state, jkt string
	var expires, renew time.Time
	if err := e.poolA.QueryRow(e.ctx, `SELECT u.token_ref, u.key_ref, u.state, u.expires_at, u.renew_after, k.jkt
		FROM upstream_token u JOIN signing_key k USING (key_ref) WHERE token_id = $1`, tok.ID).
		Scan(&ref, &keyRef, &state, &expires, &renew, &jkt); err != nil {
		t.Fatalf("no committed row: %v", err)
	}
	if state != "active" || ref != e.a.kvPrefix()+"/"+tok.ID || !renew.Before(expires) || !expires.Equal(tok.ExpiresAt) {
		t.Errorf("row: state %s ref %s renew %v expires %v", state, ref, renew, expires)
	}
	if !strings.HasPrefix(keyRef, "transit:"+e.a.KeyName+":v") {
		t.Errorf("key_ref %s", keyRef)
	}
	if n := count(t, e.poolA, `SELECT count(*) FROM verified_outcome WHERE consumed_at IS NOT NULL`); n != 1 {
		t.Errorf("%d consumed receipts; want 1", n)
	}
	value, err := e.kv.Read(e.ctx, ref)
	if err != nil {
		t.Fatalf("KV value: %v", err)
	}
	token := string(value)
	cnf, _ := claimsOf(t, token)["cnf"].(map[string]any)
	if cnf["jkt"] != jkt {
		t.Errorf("cnf.jkt %v; want the store's %s", cnf["jkt"], jkt)
	}
	if kind, code := e.lastAudit(); kind != "upstream.acquired" || code != "" {
		t.Errorf("audit %s %s", kind, code)
	}
	if n := count(t, e.poolB, `SELECT count(*) FROM verified_outcome WHERE consumed_at IS NOT NULL`); n != 1 {
		t.Errorf("B consumed %d outcomes; want 1", n)
	}

	// The token works at a B resource with a proof minted by the store key through transit.
	verifier, err := tokenverify.New(tokenverify.Config{Issuer: bIssuer, JWKSURL: e.bBase + "/.well-known/jwks.json",
		Audience: audience, PublicBaseURL: audience, Scopes: []string{vpScope}, Replay: &memReplay{seen: map[string]bool{}}})
	if err != nil {
		t.Fatal(err)
	}
	key, err := LoadKey(e.ctx, e.poolA, e.kv, e.a.KeyName)
	if err != nil {
		t.Fatal(err)
	}
	ath := sha256.Sum256(value)
	proof, err := dpopproof.Build(e.ctx, key, dpopproof.Claims{HTM: http.MethodGet, HTU: audience + "/resource", ATH: base64.RawURLEncoding.EncodeToString(ath[:])})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, audience+"/resource", nil)
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set("DPoP", proof)
	id, err := verifier.Verify(req)
	if err != nil || id.JKT != jkt || id.ClientID != e.route.ClientID {
		t.Fatalf("B's verifier refused the upstream token: %+v %v", id, err)
	}
}

func TestLoadKeyIsIdempotentAndRefusesAConflictingRow(t *testing.T) {
	e := newEnv(t)
	k1, err := LoadKey(e.ctx, e.poolA, e.kv, e.a.KeyName)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadKey(e.ctx, e.poolA, e.kv, e.a.KeyName)
	if err != nil || k2.Ref() != k1.Ref() || k2.JKT() != k1.JKT() {
		t.Fatalf("second load: %v", err)
	}
	if n := count(t, e.poolA, `SELECT count(*) FROM signing_key`); n != 1 {
		t.Errorf("%d signing_key rows; want 1", n)
	}
	other := "acq-x-" + randHex(6)
	if _, err := e.poolA.Exec(e.ctx, `INSERT INTO signing_key (key_ref, jkt, alg, state) VALUES ($1, 'not-the-thumbprint', 'ES256', 'active')`,
		"transit:"+other+":v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(e.ctx, e.poolA, e.kv, other); err == nil {
		t.Error("a signing_key row with another thumbprint was accepted")
	}
}

func TestPeerRefusalActivatesNothingAndLeavesTheReceipt(t *testing.T) {
	e := newEnv(t)
	// A successful grant whose form a later test replays for CRED-OUTCOME-CONSUMED.
	var first url.Values
	e.hook.set(func(h *hook) { h.onToken = func(f url.Values) { first = f } })
	e.mustAcquire()
	untrusted, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	for code, edit := range map[string]func(url.Values){
		if03.CodeSignature: func(f url.Values) {
			f.Set("outcome", resign(t, f.Get("outcome"), untrusted, func(map[string]any) {}))
		},
		if03.CodeNotVerified: func(f url.Values) {
			f.Set("outcome", resign(t, f.Get("outcome"), e.issuer, func(p map[string]any) { p["status"] = "failed"; p["reason_code"] = "CRED-TEST" }))
		},
		if03.CodeMismatch: func(f url.Values) { f.Set("challenge", randHex(24)) },
		if03.CodeExpired: func(f url.Values) {
			f.Set("outcome", resign(t, f.Get("outcome"), e.issuer, func(p map[string]any) {
				p["verified_at"] = time.Now().Add(-200 * time.Second).UTC().Format(time.RFC3339)
				p["expires_at"] = time.Now().Add(-100 * time.Second).UTC().Format(time.RFC3339)
			}))
		},
		if03.CodeConsumed: func(f url.Values) {
			f.Set("outcome", first.Get("outcome"))
			f.Set("challenge", first.Get("challenge"))
		},
	} {
		t.Run(code, func(t *testing.T) {
			before := e.state()
			e.hook.set(func(h *hook) { h.onToken = edit })
			_, err := e.acquire()
			e.wantCode(err, code)
			after := e.state()
			if after.rows != before.rows || after.values != before.values {
				t.Errorf("refusal activated something: %+v -> %+v", before, after)
			}
			if after.receipts != before.receipts+1 || after.unconsumed != before.unconsumed+1 {
				t.Errorf("receipt not recorded unconsumed: %+v -> %+v", before, after)
			}
			if kind, got := e.lastAudit(); kind != "upstream.refused" || got != code {
				t.Errorf("audit %s %s", kind, got)
			}
		})
	}
}

func TestOutcomeRefusedByAIsNeverSent(t *testing.T) {
	e := newEnv(t)
	untrusted, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := e.route.Outcomes.(Fixture)
	f.Key = untrusted
	e.route.Outcomes = f
	_, err := e.acquire()
	e.wantCode(err, if03.CodeSignature)
	if len(e.hook.tokenStatus) != 0 {
		t.Errorf("the grant was sent %d times", len(e.hook.tokenStatus))
	}
	if s := e.state(); s.receipts != 0 || s.rows != 0 {
		t.Errorf("state %+v", s)
	}
	if kind, code := e.lastAudit(); kind != "upstream.refused" || code != if03.CodeSignature {
		t.Errorf("audit %s %s", kind, code)
	}
}

func TestLostPeerResponseIsTerminalForTheOutcome(t *testing.T) {
	e := newEnv(t)
	for _, cut := range []func([]byte) ([]byte, error){
		func([]byte) ([]byte, error) { return nil, io.ErrUnexpectedEOF }, // connection cut after B committed
		func(b []byte) ([]byte, error) { return b[:len(b)/2], nil },      // unreadable answer
	} {
		e.hook.set(func(h *hook) { h.onResponse = cut })
		_, err := e.acquire()
		e.wantCode(err, CodePeerLost)
		if kind, code := e.lastAudit(); kind != "upstream.failed" || code != CodePeerLost {
			t.Errorf("audit %s %s", kind, code)
		}
	}
	if s := e.state(); s.rows != 0 || s.values != 0 || s.unconsumed != 2 {
		t.Fatalf("after two lost answers: %+v", s)
	}
	e.hook.set(func(h *hook) { h.onResponse = nil })
	e.mustAcquire()
	// B consumed all three outcomes; none was reused, nothing was reset.
	if n := count(t, e.poolB, `SELECT count(*) FROM verified_outcome WHERE consumed_at IS NOT NULL`); n != 3 {
		t.Errorf("B consumed %d outcomes; want 3", n)
	}
	if n := count(t, e.poolB, `SELECT count(DISTINCT outcome_id) FROM oauth2_token WHERE outcome_id IS NOT NULL`); n != 3 {
		t.Errorf("B issued on %d outcomes; want 3", n)
	}
	if s := e.state(); s.rows != 1 || s.values != 1 || s.receipts != 3 || s.unconsumed != 2 {
		t.Errorf("after the retry: %+v", s)
	}
}

func TestKVFailureActivatesNothing(t *testing.T) {
	e := newEnv(t)
	e.secrets.createErr = errors.New("kv down")
	_, err := e.acquire()
	e.wantCode(err, CodeKVWrite)
	if s := e.state(); s.rows != 0 || s.values != 0 || s.unconsumed != 1 {
		t.Errorf("state %+v", s)
	}
	if kind, code := e.lastAudit(); kind != "upstream.failed" || code != CodeKVWrite {
		t.Errorf("audit %s %s", kind, code)
	}
}

func TestRefusedTransactionDeletesTheValue(t *testing.T) {
	e := newEnv(t)
	// The receipt expires between the KV write and the transaction.
	e.secrets.afterCreate = func(string) { e.clock.Advance(5 * time.Minute) }
	_, err := e.acquire()
	e.wantCode(err, CodeActivationRefused)
	if _, err := e.kv.Read(e.ctx, e.secrets.created[0]); !errors.Is(err, transit.ErrNotFound) {
		t.Errorf("value after a refused transaction: %v; want deleted", err)
	}
	if s := e.state(); s.rows != 0 || s.unconsumed != 1 {
		t.Errorf("state %+v", s)
	}
	if kind, code := e.lastAudit(); kind != "upstream.failed" || code != CodeActivationRefused {
		t.Errorf("audit %s %s", kind, code)
	}
}

// poolWith opens a pool on A's database whose sessions default to isolation level iso.
func (e *env) poolWith(iso string) *pgxpool.Pool {
	e.t.Helper()
	cfg, err := pgxpool.ParseConfig(e.dsnA)
	if err != nil {
		e.t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["default_transaction_isolation"] = iso
	pool, err := pgxpool.NewWithConfig(e.ctx, cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(pool.Close)
	return pool
}

func TestUnknownCommitOutcomeIsReconciledByTheRow(t *testing.T) {
	lost := errors.New("connection reset by peer")
	for name, tc := range map[string]struct {
		setup     func(e *env)
		commit    func(e *env) func(context.Context, pgx.Tx) error
		wantState string // SQLSTATE the real COMMIT must have answered, when set
		wantCode  string // "" when the token must be kept
		minWait   time.Duration
	}{
		"committed, acknowledgement lost": {commit: func(*env) func(context.Context, pgx.Tx) error {
			return func(ctx context.Context, tx pgx.Tx) error {
				if err := tx.Commit(ctx); err != nil {
					return err
				}
				return lost
			}
		}},
		// A FATAL termination that arrives after COMMIT took effect is a server error that undoes
		// nothing.
		"committed, then FATAL": {commit: func(*env) func(context.Context, pgx.Tx) error {
			return func(ctx context.Context, tx pgx.Tx) error {
				if err := tx.Commit(ctx); err != nil {
					return err
				}
				return &pgconn.PgError{Severity: "FATAL", Code: "57P01", Message: "terminating connection due to administrator command"}
			}
		}},
		"rolled back, acknowledgement lost": {commit: func(*env) func(context.Context, pgx.Tx) error {
			return func(ctx context.Context, tx pgx.Tx) error {
				_ = tx.Rollback(ctx)
				return lost
			}
		}, wantCode: CodeActivationFailed},
		// A real deferred unique violation, raised by COMMIT itself.
		"deferred constraint at COMMIT": {
			setup: func(e *env) {
				if _, err := e.poolA.Exec(e.ctx, `CREATE TABLE acq_deferred (id int,
					CONSTRAINT acq_deferred_once UNIQUE (id) DEFERRABLE INITIALLY DEFERRED)`); err != nil {
					e.t.Fatal(err)
				}
			},
			commit: func(*env) func(context.Context, pgx.Tx) error {
				return func(ctx context.Context, tx pgx.Tx) error {
					if _, err := tx.Exec(ctx, `INSERT INTO acq_deferred VALUES (1), (1)`); err != nil {
						return lost // not the case under test; the assertion on wantState fails
					}
					return tx.Commit(ctx)
				}
			},
			wantState: "23505", wantCode: CodeActivationFailed,
		},
		// A real serialization failure at COMMIT: write skew between activation and another
		// SERIALIZABLE transaction that commits first.
		"serialization failure at COMMIT": {
			setup: func(e *env) {
				e.a.DB = e.poolWith("serializable")
				if _, err := e.poolA.Exec(e.ctx, `CREATE TABLE acq_ser (k int)`); err != nil {
					e.t.Fatal(err)
				}
			},
			commit: func(e *env) func(context.Context, pgx.Tx) error {
				return func(ctx context.Context, tx pgx.Tx) error {
					if _, err := tx.Exec(ctx, `SELECT count(*) FROM acq_ser WHERE k = 1`); err != nil {
						return lost
					}
					if _, err := tx.Exec(ctx, `INSERT INTO acq_ser VALUES (2)`); err != nil {
						return lost
					}
					other, err := e.poolA.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
					if err != nil {
						return lost
					}
					_, err1 := other.Exec(ctx, `SELECT count(*) FROM acq_ser WHERE k = 2`)
					_, err2 := other.Exec(ctx, `INSERT INTO acq_ser VALUES (1)`)
					if err1 != nil || err2 != nil || other.Commit(ctx) != nil {
						_ = other.Rollback(ctx)
						return lost
					}
					return tx.Commit(ctx)
				}
			},
			wantState: "40001", wantCode: CodeActivationFailed,
		},
		// COMMIT never reached the server: the transaction stays open until the server's
		// idle-in-transaction timeout ends it, and reconciliation waits for that. The test hands
		// the connection back only after the server has ended the session.
		"never arrived": {commit: func(*env) func(context.Context, pgx.Tx) error {
			return func(_ context.Context, tx pgx.Tx) error {
				time.AfterFunc(idleTimeout+5*time.Second, func() { _ = tx.Rollback(context.Background()) })
				return lost
			}
		}, wantCode: CodeActivationFailed, minWait: idleTimeout - time.Second},
		// Reconciliation on a database whose default is REPEATABLE READ, with the activation
		// committing while reconciliation waits for its lock: the check must read after the wait.
		"committed while reconciliation waits, REPEATABLE READ default": {
			setup: func(e *env) { e.a.DB = e.poolWith("repeatable read") },
			commit: func(*env) func(context.Context, pgx.Tx) error {
				return func(_ context.Context, tx pgx.Tx) error {
					time.AfterFunc(500*time.Millisecond, func() { _ = tx.Commit(context.Background()) })
					return lost
				}
			},
			minWait: 400 * time.Millisecond,
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			if tc.setup != nil {
				tc.setup(e)
			}
			var commitErr error
			inner := tc.commit(e)
			e.a.commit = func(ctx context.Context, tx pgx.Tx) error {
				commitErr = inner(ctx, tx)
				return commitErr
			}
			start := time.Now()
			tok, err := e.acquire()
			if time.Since(start) < tc.minWait {
				t.Errorf("reconciliation did not wait for the open transaction to end (%v)", time.Since(start))
			}
			if tc.wantState != "" {
				var pgErr *pgconn.PgError
				if !errors.As(commitErr, &pgErr) || pgErr.Code != tc.wantState {
					t.Fatalf("COMMIT answered %v; want SQLSTATE %s", commitErr, tc.wantState)
				}
			}
			path := e.secrets.created[0]
			_, readErr := e.kv.Read(e.ctx, path)
			rows := count(t, e.poolA, `SELECT count(*) FROM upstream_token`)
			if tc.wantCode == "" {
				if err != nil || readErr != nil || rows != 1 || path != e.a.kvPrefix()+"/"+tok.ID {
					t.Fatalf("committed: err %v, value %v, rows %d; want the token kept", err, readErr, rows)
				}
				return
			}
			e.wantCode(err, tc.wantCode)
			if !errors.Is(readErr, transit.ErrNotFound) || rows != 0 {
				t.Fatalf("not committed: value %v, rows %d; want deleted and none", readErr, rows)
			}
		})
	}
}

func TestOrphanSweepDeletesOnlyOldValuesWithoutARow(t *testing.T) {
	e := newEnv(t)
	tok := e.mustAcquire()
	referenced := e.a.kvPrefix() + "/" + tok.ID
	oldOrphan, youngOrphan := e.a.kvPrefix()+"/"+newUUID(), e.a.kvPrefix()+"/"+newUUID()
	if err := e.kv.Create(e.ctx, oldOrphan, []byte("x")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := e.kv.Create(e.ctx, youngOrphan, []byte("y")); err != nil {
		t.Fatal(err)
	}
	cOld, err1 := e.kv.CreatedTime(e.ctx, oldOrphan)
	cYoung, err2 := e.kv.CreatedTime(e.ctx, youngOrphan)
	if err1 != nil || err2 != nil || !cOld.Before(cYoung) {
		t.Fatalf("created times %v %v %v %v", cOld, cYoung, err1, err2)
	}
	// Now is past OrphanAge for the old orphan (and the referenced value), not for the young one.
	now := cOld.Add(OrphanAge + cYoung.Sub(cOld)/2)
	e.a.Now = func() time.Time { return now }
	n, err := e.a.SweepOrphans(e.ctx)
	if err != nil || n != 1 {
		t.Fatalf("sweep deleted %d, %v; want 1", n, err)
	}
	for path, wantKept := range map[string]bool{referenced: true, youngOrphan: true, oldOrphan: false} {
		_, err := e.kv.Read(e.ctx, path)
		if kept := err == nil; kept != wantKept {
			t.Errorf("%s kept=%v (%v); want %v", path, kept, err, wantKept)
		}
	}
	_ = e.kv.Delete(e.ctx, youngOrphan)
	if kind, code := e.lastAudit(); kind != "upstream.orphan_deleted" || code != CodeOrphan {
		t.Errorf("audit %s %s", kind, code)
	}
}

func TestResponseChecksRefuseAnUnboundOrForeignToken(t *testing.T) {
	e := newEnv(t)
	rewrite := func(edit func(tr map[string]any, claims map[string]any)) func([]byte) ([]byte, error) {
		return func(b []byte) ([]byte, error) {
			var tr map[string]any
			_ = json.Unmarshal(b, &tr)
			parts := strings.Split(tr["access_token"].(string), ".")
			raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
			var c map[string]any
			_ = json.Unmarshal(raw, &c)
			edit(tr, c)
			p, _ := json.Marshal(c)
			tr["access_token"] = parts[0] + "." + base64.RawURLEncoding.EncodeToString(p) + "." + parts[2]
			return json.Marshal(tr)
		}
	}
	for name, edit := range map[string]func(tr, c map[string]any){
		"token_type": func(tr, _ map[string]any) { tr["token_type"] = "Bearer" },
		"cnf.jkt":    func(_, c map[string]any) { c["cnf"] = map[string]any{"jkt": "another-key"} },
		"aud":        func(_, c map[string]any) { delete(c, "aud") },
		"exp":        func(_, c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() },
	} {
		t.Run(name, func(t *testing.T) {
			before := e.state()
			e.hook.set(func(h *hook) { h.onResponse = rewrite(edit) })
			_, err := e.acquire()
			e.wantCode(err, CodeTokenInvalid)
			after := e.state()
			if after.rows != before.rows || after.values != before.values || after.unconsumed != before.unconsumed+1 {
				t.Errorf("state %+v -> %+v", before, after)
			}
			var check string
			if err := e.poolA.QueryRow(e.ctx, `SELECT detail->>'check' FROM audit_event ORDER BY event_id DESC LIMIT 1`).Scan(&check); err != nil || check != name {
				t.Errorf("audit check %q %v; want %q", check, err, name)
			}
		})
	}
}

// TestCanary: no token, proof, client secret or outcome reaches a log record, an error or an audit row.
func TestCanaryNoCredentialInLogsErrorsOrAudit(t *testing.T) {
	e := newEnv(t)
	e.mustAcquire()
	e.hook.set(func(h *hook) { h.onToken = func(f url.Values) { f.Set("challenge", randHex(24)) } })
	_, _ = e.acquire()
	e.hook.set(func(h *hook) {
		h.onToken = nil
		h.onResponse = func([]byte) ([]byte, error) { return nil, io.ErrUnexpectedEOF }
	})
	_, _ = e.acquire()
	e.hook.set(func(h *hook) { h.onResponse = nil })
	e.secrets.afterCreate = func(string) { e.clock.Advance(5 * time.Minute) }
	_, _ = e.acquire()

	rows, err := e.poolA.Query(e.ctx, `SELECT row_to_json(a)::text FROM audit_event a`)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(audit) < 4 {
		t.Fatalf("%d audit rows, %v", len(audit), err)
	}
	haystack := e.logs.String() + strings.Join(e.errs, "\n") + strings.Join(audit, "\n")
	needles := append([]string{e.secret}, e.hook.sent...)
	if len(needles) < 6 {
		t.Fatalf("only %d canaries collected", len(needles))
	}
	// Key material and the OpenBao token are canaries too: the store's public key as transit
	// returns it (PEM body) and as a JWK (its coordinates), and the token every call carries.
	key, err := LoadKey(e.ctx, e.poolA, e.kv, e.a.KeyName)
	if err != nil {
		t.Fatal(err)
	}
	needles = append(needles, rawPublicKeyPEM(t, e.a.KeyName, 1), key.JWK().X, key.JWK().Y, e.token)
	for _, n := range needles {
		if n == "" {
			continue
		}
		// Every credential is long and random; any 24-character piece of it would be a leak. A
		// needle too short for that would pass unsearched, so it is refused instead.
		if len(n) < 24 {
			t.Fatalf("a canary of %d characters cannot be searched safely", len(n))
		}
		for i := 0; i+24 <= len(n); i++ {
			if strings.Contains(haystack, n[i:i+24]) {
				t.Fatalf("a credential piece leaked into logs, errors or audit")
			}
		}
	}
}

// TestOrphanSweepKeepsAValueWhoseActivationCommitsMeanwhile: the sweep finds an old value without a
// row, and the activation of that token_id commits after that first look and before the deletion
// (here: it holds the token's lock while the sweep reaches it and commits 300 ms later). The value
// must be kept.
func TestOrphanSweepKeepsAValueWhoseActivationCommitsMeanwhile(t *testing.T) {
	e := newEnv(t)
	key, err := LoadKey(e.ctx, e.poolA, e.kv, e.a.KeyName)
	if err != nil {
		t.Fatal(err)
	}
	id := newUUID()
	path := e.a.kvPrefix() + "/" + id
	if err := e.kv.Create(e.ctx, path, []byte("v")); err != nil {
		t.Fatal(err)
	}
	created, err := e.kv.CreatedTime(e.ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := created.Add(OrphanAge + time.Minute)
	e.a.Now = func() time.Time { return now }
	committed := make(chan error, 1)
	e.a.sweepPause = func(tokenID string) {
		tx, err := e.poolA.Begin(e.ctx)
		if err != nil {
			t.Fatal(err)
		}
		outcome := newUUID()
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, []any{tokenID}},
			{`INSERT INTO verified_outcome (outcome_id, issuer, client_id, challenge, audience, status, claims, verified_at, expires_at, consumed_at)
				VALUES ($1, $2, 'c', 'challenge-challenge', $3, 'verified', '{}', now(), now() + interval '1 minute', now())`, []any{outcome, vpIssuer, audience}},
			{`INSERT INTO upstream_token (token_id, peer_zone, audience, tenant, outcome_id, token_ref, key_ref, state, issued_at, expires_at, renew_after)
				VALUES ($1, 'zone-b', $2, '', $3, $4, $5, 'active', now(), now() + interval '5 minutes', now() + interval '4 minutes')`,
				[]any{tokenID, audience, outcome, path, key.Ref()}},
		} {
			if _, err := tx.Exec(e.ctx, q.sql, q.args...); err != nil {
				t.Fatal(err)
			}
		}
		time.AfterFunc(300*time.Millisecond, func() { committed <- tx.Commit(context.Background()) })
	}
	n, err := e.a.SweepOrphans(e.ctx)
	if cerr := <-committed; cerr != nil {
		t.Fatalf("activation commit: %v", cerr)
	}
	if err != nil || n != 0 {
		t.Fatalf("sweep deleted %d, %v; want 0", n, err)
	}
	if _, err := e.kv.Read(e.ctx, path); err != nil {
		t.Fatalf("the committed token's value was deleted: %v", err)
	}
}

// TestAnUnknownCommitDoesNotOutliveTheCallersDeadline: COMMIT never reaches the server (the
// transaction stays open until the server's idle timeout), and the caller has a deadline far shorter
// than that wait, or is already gone. The acquisition returns by the deadline with
// ACQ-COMMIT-UNKNOWN and leaves the value for the orphan sweep instead of reconciling past it.
func TestAnUnknownCommitDoesNotOutliveTheCallersDeadline(t *testing.T) {
	for name, gone := range map[string]bool{"deadline during reconciliation": false, "caller gone at COMMIT": true} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			ctx, cancel := context.WithTimeout(e.ctx, 3*time.Second)
			defer cancel()
			e.a.commit = func(_ context.Context, tx pgx.Tx) error {
				// Handed back after the deadline; the open transaction holds the token's lock until then.
				time.AfterFunc(6*time.Second, func() { _ = tx.Rollback(context.Background()) })
				if gone {
					cancel()
				}
				return errors.New("connection reset by peer")
			}
			begin := time.Now()
			_, err := e.a.Acquire(ctx, e.route)
			if took := time.Since(begin); took > 3*time.Second+cleanupTimeout {
				t.Errorf("returned after %v; the deadline was 3 s", took)
			}
			e.wantCode(err, CodeCommitUnknown)
			if _, err := e.kv.Read(e.ctx, e.secrets.created[0]); err != nil {
				t.Errorf("the value of an unknown commit was not kept for the sweep: %v", err)
			}
		})
	}
}

// rawPublicKeyPEM reads the PEM transit returns for version v of a key, as an operator would with
// `bao read`, and returns its body without armour or line breaks: a canary for key material.
func rawPublicKeyPEM(t *testing.T, name string, v int) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, strings.TrimSuffix(os.Getenv("TRANSIT_TEST_ADDR"), "/")+"/v1/transit/keys/"+name, nil)
	req.Header.Set("X-Vault-Token", os.Getenv("TRANSIT_TEST_TOKEN"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal("reading the key failed")
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Data struct {
			Keys map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	var body strings.Builder
	for _, line := range strings.Split(out.Data.Keys[strconv.Itoa(v)].PublicKey, "\n") {
		if line != "" && !strings.HasPrefix(line, "-----") {
			body.WriteString(line)
		}
	}
	if body.Len() < 48 {
		t.Fatalf("no PEM body for version %d of %s", v, name)
	}
	return body.String()
}

// rotateInDatabase is what token-store keys rotate records: the version in use retired, the new
// one active, in one transaction.
func (e *env) rotateInDatabase(oldRef string, kv transit.KeyVersion) {
	e.t.Helper()
	pub, err := e.kv.PublicKey(e.ctx, kv)
	if err != nil {
		e.t.Fatal(err)
	}
	jkt, err := keys.Thumbprint(pub)
	if err != nil {
		e.t.Fatal(err)
	}
	tx, err := e.poolA.Begin(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), `UPDATE signing_key SET state = 'retired', retired_at = now() WHERE key_ref = $1`, oldRef); err != nil {
		e.t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(), `INSERT INTO signing_key (key_ref, jkt, alg, state) VALUES ($1, $2, 'ES256', 'active')`, kv.Ref(), jkt); err != nil {
		e.t.Fatal(err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		e.t.Fatal(err)
	}
}

// The active signing_key row decides which version mints. A rotation in transit alone changes
// nothing; once keys rotate records it, the store signs with the new version and tokens bind to it.
func TestLoadKeyFollowsTheActiveReferenceNotTransitLatest(t *testing.T) {
	e := newEnv(t)
	k1, err := LoadKey(e.ctx, e.poolA, e.kv, e.a.KeyName)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := e.kv.Rotate(e.ctx, e.a.KeyName)
	if err != nil || v2.Version != 2 {
		t.Fatalf("rotate: %+v %v", v2, err)
	}
	again, err := LoadKey(e.ctx, e.poolA, e.kv, e.a.KeyName)
	if err != nil || again.Ref() != k1.Ref() || again.JKT() != k1.JKT() {
		t.Fatalf("after a transit rotation: %v %v; want the registered version %s", again, err, k1.Ref())
	}
	if n := count(t, e.poolA, `SELECT count(*) FROM signing_key WHERE state = 'active'`); n != 1 {
		t.Fatalf("%d active rows after a transit rotation; want 1", n)
	}
	e.rotateInDatabase(k1.Ref(), v2)
	k2, err := LoadKey(e.ctx, e.poolA, e.kv, e.a.KeyName)
	if err != nil || k2.Ref() != v2.Ref() || k2.JKT() == k1.JKT() {
		t.Fatalf("after keys rotate: %v %v; want %s", k2, err, v2.Ref())
	}
	tok := e.mustAcquire()
	var ref string
	if err := e.poolA.QueryRow(e.ctx, `SELECT key_ref FROM upstream_token WHERE token_id = $1`, tok.ID).Scan(&ref); err != nil || ref != v2.Ref() {
		t.Fatalf("the new token is bound to %q, %v; want %s", ref, err, v2.Ref())
	}
}

// A retired registered version, a malformed reference, or a key a read-only signer cannot find:
// each is refused and nothing is created or repaired.
func TestLoadKeyRefusesARetiredKey(t *testing.T) {
	e := newEnv(t)
	if _, err := LoadKey(e.ctx, e.poolA, e.kv, e.a.KeyName); err != nil {
		t.Fatal(err)
	}
	if _, err := e.poolA.Exec(e.ctx, `UPDATE signing_key SET state = 'retired', retired_at = now()`); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(e.ctx, e.poolA, e.kv, e.a.KeyName); !errors.Is(err, ErrKeyRetired) {
		t.Fatalf("retired version: %v; want ErrKeyRetired", err)
	}
	if _, err := e.acquire(); err == nil {
		t.Fatal("an acquisition minted with a retired key")
	} else {
		e.wantCode(err, CodeStore)
	}
	// Transit rotated meanwhile: still nothing is registered on the way to a grant; a key whose
	// rows are all retired moves on only through keys rotate.
	if _, err := e.kv.Rotate(e.ctx, e.a.KeyName); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(e.ctx, e.poolA, e.kv, e.a.KeyName); !errors.Is(err, ErrKeyRetired) {
		t.Fatalf("retired rows with a newer transit version: %v; want ErrKeyRetired", err)
	}
	if n := count(t, e.poolA, `SELECT count(*) FROM signing_key WHERE state = 'active'`); n != 0 {
		t.Fatalf("LoadKey registered %d active rows past retired ones", n)
	}
	readOnly := keys.ReadOnly{Lister: e.kv}
	absent := "acq-ro-" + randHex(6)
	if _, err := LoadKey(e.ctx, e.poolA, readOnly, absent); !errors.Is(err, transit.ErrNotFound) {
		t.Fatalf("read-only signer, missing key: %v; want ErrNotFound", err)
	}
	if _, err := e.kv.LatestKey(e.ctx, absent); !errors.Is(err, transit.ErrNotFound) {
		t.Fatalf("the read-only signer created the key: %v", err)
	}
	malformed := "acq-mal-" + randHex(6)
	if _, err := e.poolA.Exec(e.ctx, `INSERT INTO signing_key (key_ref, jkt, alg, state) VALUES ($1, 'j', 'ES256', 'active')`,
		"transit:"+malformed+":1"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(e.ctx, e.poolA, e.kv, malformed); !errors.Is(err, ErrMalformedRef) {
		t.Fatalf("malformed reference: %v; want ErrMalformedRef", err)
	}
	// The latest version's thumbprint registered under another reference: rows that contradict
	// transit are a conflict, never repaired on the way to a grant.
	conflict := "acq-conf-" + randHex(6)
	kv, jkt, err := keys.Keys{Signer: e.kv, Name: conflict}.Ensure(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.poolA.Exec(e.ctx, `INSERT INTO signing_key (key_ref, jkt, alg, state, retired_at) VALUES ($1, $2, 'ES256', 'retired', now())`,
		"transit:elsewhere-"+randHex(4)+":v1", jkt); err != nil {
		t.Fatal(err)
	}
	_, err = LoadKey(e.ctx, e.poolA, e.kv, conflict)
	if !errors.Is(err, ErrKeyConflict) {
		t.Fatalf("conflicting rows for %s: %v; want ErrKeyConflict", kv.Ref(), err)
	}
	if word, permanent := Reason(err); !permanent || word != ReasonMismatch {
		t.Fatalf("Reason(conflict) = %s %v", word, permanent)
	}
}

// Reason names every cause in the fixed vocabulary and tells a misconfiguration from an outage.
func TestReasonWords(t *testing.T) {
	for _, tc := range []struct {
		err       error
		word      string
		permanent bool
	}{
		{keys.ErrMismatch, ReasonMismatch, true},
		{ErrKeyConflict, ReasonMismatch, true},
		{ErrMalformedRef, ReasonMalformed, true},
		{ErrKeyRetired, ReasonRetired, true},
		{transit.ErrUnsupportedKey, ReasonUnsupported, true},
		{&transit.StatusError{Op: "x", Status: 404}, ReasonMissing, true},
		{&transit.StatusError{Op: "x", Status: 403}, ReasonRefused, true},
		{&transit.StatusError{Op: "x", Status: 429}, ReasonUnreachable, false},
		{&transit.StatusError{Op: "x", Status: 503}, ReasonUnreachable, false},
		{transit.ErrTokenSource, ReasonToken, false},
		{&pgconn.PgError{Code: "42P01"}, ReasonDatabase, false},
		{errors.New("dial tcp: connection refused"), ReasonUnreachable, false},
		{context.DeadlineExceeded, ReasonUnreachable, false},
	} {
		if word, permanent := Reason(tc.err); word != tc.word || permanent != tc.permanent {
			t.Errorf("Reason(%v) = %s %v; want %s %v", tc.err, word, permanent, tc.word, tc.permanent)
		}
	}
}

// The key is retired after the grant was sent and before the activation: the activation finds no
// active row for the key it signed with, inserts nothing, deletes the value and audits
// ACQ-KEY-RETIRED. The next acquisition signs with the new version.
func TestActivationRefusesAKeyRetiredDuringTheGrant(t *testing.T) {
	e := newEnv(t)
	k1, err := LoadKey(e.ctx, e.poolA, e.kv, e.a.KeyName)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := e.kv.Rotate(e.ctx, e.a.KeyName)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	e.hook.set(func(h *hook) {
		h.onResponse = func(b []byte) ([]byte, error) {
			once.Do(func() { e.rotateInDatabase(k1.Ref(), v2) })
			return b, nil
		}
	})
	before := e.state()
	_, err = e.acquire()
	e.wantCode(err, CodeKeyRetired)
	after := e.state()
	if after.rows != before.rows || after.values != before.values {
		t.Fatalf("state %+v -> %+v; want no row and no value", before, after)
	}
	if kind, code := e.lastAudit(); kind != "upstream.failed" || code != CodeKeyRetired {
		t.Fatalf("audit %s %s", kind, code)
	}
	e.hook.set(func(h *hook) { h.onResponse = nil })
	tok := e.mustAcquire()
	var ref string
	if err := e.poolA.QueryRow(e.ctx, `SELECT key_ref FROM upstream_token WHERE token_id = $1`, tok.ID).Scan(&ref); err != nil || ref != v2.Ref() {
		t.Fatalf("the next token is bound to %q, %v; want %s", ref, err, v2.Ref())
	}
}

// Rotate: the next version is active and the previous one retired with the tokens it minted;
// transit no longer signs with the previous version; a version rotated outside the store is
// adopted rather than rotated past; a key with nothing registered is registered, not rotated.
func TestRotateRetiresThePreviousVersionAndItsTokens(t *testing.T) {
	e := newEnv(t)
	tok := e.mustAcquire()
	k1, err := LoadKey(e.ctx, e.poolA, e.kv, e.a.KeyName)
	if err != nil {
		t.Fatal(err)
	}
	rot, err := Rotate(e.ctx, e.poolA, e.kv, e.a.KeyName)
	if err != nil {
		t.Fatal(err)
	}
	v2 := transit.KeyVersion{Name: e.a.KeyName, Version: 2}
	if rot.Active != v2.Ref() || rot.Adopted || rot.MinSigningVersion != 2 || len(rot.Retired) != 1 || rot.Retired[0] != k1.Ref() || rot.UpstreamTokensRetired != 1 {
		t.Fatalf("rotation %+v", rot)
	}
	var state string
	var retiredAt *time.Time
	if err := e.poolA.QueryRow(e.ctx, `SELECT state, retired_at FROM signing_key WHERE key_ref = $1`, k1.Ref()).Scan(&state, &retiredAt); err != nil || state != "retired" || retiredAt == nil {
		t.Fatalf("previous version: %s %v %v", state, retiredAt, err)
	}
	if n := count(t, e.poolA, `SELECT count(*) FROM signing_key WHERE state = 'active'`); n != 1 {
		t.Fatalf("%d active versions; want 1", n)
	}
	if err := e.poolA.QueryRow(e.ctx, `SELECT state FROM upstream_token WHERE token_id = $1`, tok.ID).Scan(&state); err != nil || state != "retired" {
		t.Fatalf("the token minted under the retired version: %s %v", state, err)
	}
	if kind, _ := e.lastAudit(); kind != "key.rotated" {
		t.Fatalf("audit %s", kind)
	}
	var se *transit.StatusError
	if _, err := e.kv.Sign(e.ctx, k1.ref, []byte("eyJhbGciOiJFUzI1NiJ9.e30")); !errors.As(err, &se) || se.Status < 400 {
		t.Fatalf("transit still signs with the retired version: %v", err)
	}
	next := e.mustAcquire()
	var ref string
	if err := e.poolA.QueryRow(e.ctx, `SELECT key_ref FROM upstream_token WHERE token_id = $1`, next.ID).Scan(&ref); err != nil || ref != v2.Ref() {
		t.Fatalf("the next token is bound to %q, %v; want %s", ref, err, v2.Ref())
	}

	// A floor left below the active version (a rotation that committed before its floor was
	// raised, or a key registered before this build): the next rotation raises it past the old
	// versions as part of its own floor raise, nothing else.
	req, _ := http.NewRequest(http.MethodPost, strings.TrimSuffix(os.Getenv("TRANSIT_TEST_ADDR"), "/")+"/v1/transit/keys/"+e.a.KeyName+"/config",
		strings.NewReader(`{"min_encryption_version":1}`))
	req.Header.Set("X-Vault-Token", os.Getenv("TRANSIT_TEST_TOKEN"))
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode >= 300 {
		t.Fatalf("lowering the floor by hand: %v", err)
	} else {
		_ = resp.Body.Close()
	}

	// Rotated outside the store: the next run adopts transit's latest version, and its floor
	// raise covers the floor left behind above.
	if _, err := e.kv.Rotate(e.ctx, e.a.KeyName); err != nil {
		t.Fatal(err)
	}
	rot, err = Rotate(e.ctx, e.poolA, e.kv, e.a.KeyName)
	v3 := transit.KeyVersion{Name: e.a.KeyName, Version: 3}
	if err != nil || !rot.Adopted || rot.Active != v3.Ref() || rot.MinSigningVersion != 3 || len(rot.Retired) != 1 || rot.Retired[0] != v2.Ref() {
		t.Fatalf("adoption: %+v %v", rot, err)
	}
	if latest, err := e.kv.LatestKey(e.ctx, e.a.KeyName); err != nil || latest != v3 {
		t.Fatalf("adoption created a version: %+v %v", latest, err)
	}

	// Nothing registered: Rotate registers the latest version and retires nothing. A key transit
	// does not have is refused, never created: that is keys ensure's.
	fresh := "acq-fresh-" + randHex(6)
	if _, err := e.kv.EnsureKey(e.ctx, fresh); err != nil {
		t.Fatal(err)
	}
	rot, err = Rotate(e.ctx, e.poolA, e.kv, fresh)
	if err != nil || !rot.Adopted || rot.Active != (transit.KeyVersion{Name: fresh, Version: 1}).Ref() || len(rot.Retired) != 0 {
		t.Fatalf("fresh key: %+v %v", rot, err)
	}
	absent := "acq-absent-" + randHex(6)
	if _, err := Rotate(e.ctx, e.poolA, e.kv, absent); !errors.Is(err, transit.ErrNotFound) {
		t.Fatalf("rotate of a key transit does not have: %v; want ErrNotFound", err)
	}
	if _, err := e.kv.LatestKey(e.ctx, absent); !errors.Is(err, transit.ErrNotFound) {
		t.Fatalf("rotate created the key: %v", err)
	}
	rows, err := KeyRows(e.ctx, e.poolA, e.a.KeyName)
	if err != nil || len(rows) != 3 || rows[0].KeyRef != v3.Ref() || rows[0].State != "active" || rows[2].RetiredAt == nil {
		t.Fatalf("key rows: %+v %v", rows, err)
	}
}

// Every registered version retired (an operator retiring a compromised version by hand): Rotate
// moves past them to a fresh version, as ErrKeyRetired says it does.
func TestRotateMovesPastRetiredVersions(t *testing.T) {
	e := newEnv(t)
	if _, err := LoadKey(e.ctx, e.poolA, e.kv, e.a.KeyName); err != nil {
		t.Fatal(err)
	}
	if _, err := e.poolA.Exec(e.ctx, `UPDATE signing_key SET state = 'retired', retired_at = now()`); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(e.ctx, e.poolA, e.kv, e.a.KeyName); !errors.Is(err, ErrKeyRetired) {
		t.Fatalf("before the rotation: %v; want ErrKeyRetired", err)
	}
	rot, err := Rotate(e.ctx, e.poolA, e.kv, e.a.KeyName)
	v2 := transit.KeyVersion{Name: e.a.KeyName, Version: 2}
	if err != nil || rot.Adopted || rot.Active != v2.Ref() || len(rot.Retired) != 0 || rot.MinSigningVersion != 2 {
		t.Fatalf("rotation past retired versions: %+v %v", rot, err)
	}
	k, err := LoadKey(e.ctx, e.poolA, e.kv, e.a.KeyName)
	if err != nil || k.Ref() != v2.Ref() {
		t.Fatalf("after the rotation: %v %v", k, err)
	}
	e.mustAcquire()
}

// A floor raised above the registered version (a rotation that ended between the floor and the
// commit, or a floor set by hand): the registered version resolves but cannot sign, and the next
// Rotate adopts the version transit is at instead of rotating past it.
func TestRotateRepairsAFloorAboveTheRegisteredVersion(t *testing.T) {
	e := newEnv(t)
	k1, err := LoadKey(e.ctx, e.poolA, e.kv, e.a.KeyName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.kv.Rotate(e.ctx, e.a.KeyName); err != nil {
		t.Fatal(err)
	}
	if err := e.kv.SetMinSigningVersion(e.ctx, e.a.KeyName, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(e.ctx, e.poolA, e.kv, e.a.KeyName); !errors.Is(err, ErrKeyRetired) {
		t.Fatalf("a version below the floor loaded: %v; want ErrKeyRetired", err)
	}
	if _, err := e.acquire(); err == nil {
		t.Fatal("an acquisition signed with a version below the floor")
	} else {
		e.wantCode(err, CodeStore)
	}
	rot, err := Rotate(e.ctx, e.poolA, e.kv, e.a.KeyName)
	v2 := transit.KeyVersion{Name: e.a.KeyName, Version: 2}
	if err != nil || !rot.Adopted || rot.Active != v2.Ref() || len(rot.Retired) != 1 || rot.Retired[0] != k1.Ref() {
		t.Fatalf("repair: %+v %v", rot, err)
	}
	if latest, err := e.kv.LatestKey(e.ctx, e.a.KeyName); err != nil || latest != v2 {
		t.Fatalf("the repair rotated past the version transit was at: %+v %v", latest, err)
	}
	e.mustAcquire()
}

// A live token bound to a key that is no longer active (retired by hand, or by a rotation an older
// build's activation overtook) would hold the route's one live slot until it expired; an
// acquisition retires it with the expired rows and the route is served again.
func TestAcquisitionReplacesATokenOfARetiredKey(t *testing.T) {
	e := newEnv(t)
	old := e.mustAcquire()
	k1, err := LoadKey(e.ctx, e.poolA, e.kv, e.a.KeyName)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := e.kv.Rotate(e.ctx, e.a.KeyName)
	if err != nil {
		t.Fatal(err)
	}
	e.rotateInDatabase(k1.Ref(), v2) // retires the key row only; the token stays live under it
	var state string
	if err := e.poolA.QueryRow(e.ctx, `SELECT state FROM upstream_token WHERE token_id = $1`, old.ID).Scan(&state); err != nil || state != "active" {
		t.Fatalf("fixture: the old token is %s %v", state, err)
	}
	fresh := e.mustAcquire()
	if err := e.poolA.QueryRow(e.ctx, `SELECT state FROM upstream_token WHERE token_id = $1`, old.ID).Scan(&state); err != nil || state != "retired" {
		t.Fatalf("the token of the retired key: %s %v; want retired", state, err)
	}
	var ref string
	if err := e.poolA.QueryRow(e.ctx, `SELECT key_ref FROM upstream_token WHERE token_id = $1`, fresh.ID).Scan(&ref); err != nil || ref != v2.Ref() {
		t.Fatalf("the fresh token is bound to %q, %v; want %s", ref, err, v2.Ref())
	}
}
