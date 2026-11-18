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
	kv, err := transit.New(transit.Config{Addr: addr, Token: func(context.Context) (string, error) { return token, nil }})
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
	e := &env{dsnA: dsnA, t: t, ctx: ctx, poolA: poolA, poolB: poolB, kv: kv, hook: &hook{}, clock: &clock{},
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
	for _, n := range needles {
		if n == "" {
			continue
		}
		// Every credential is long and random; any 24-character piece of it would be a leak.
		for i := 0; i+24 <= len(n); i += 24 {
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
