package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/meshcaller"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/testsupport"
)

const (
	connectorID = "spiffe://zone-a.example/ns/ztd-mgmt/sa/connector"
	strangerID  = "spiffe://zone-a.example/ns/ztd-data/sa/participant"
	testJKT     = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
)

// headerCaller authenticates whoever the test names in a header: the store under test trusts what
// its Authenticator says, which is the point of injecting one.
type headerCaller struct{}

func (headerCaller) Authenticate(r *http.Request) (meshcaller.Caller, error) {
	id := r.Header.Get("X-Test-Caller")
	if id == "" {
		return meshcaller.Caller{}, meshcaller.ErrCallerDenied
	}
	return meshcaller.Caller{SPIFFEID: id}, nil
}

func replayServer(t *testing.T, buf *testsupport.Buffer) (*Server, string) {
	t.Helper()
	dbURL := testDatabaseURL(t)
	migrate(t, dbURL)
	cfg := localConfig(dbURL, fakeOpenBao(t).URL)
	cfg.ReplayCallers = []string{connectorID}
	cfg.Callers = headerCaller{}
	s, err := New(context.Background(), cfg, testLogger(buf))
	if err != nil {
		t.Fatal(err)
	}
	startServer(t, s)
	return s, "http://" + s.Addr().String() + "/internal/replay-check"
}

func postReplay(t *testing.T, url, who string, body any) (int, map[string]any) {
	t.Helper()
	raw, ok := body.(string)
	if !ok {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		raw = string(b)
	}
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if who != "" {
		req.Header.Set("X-Test-Caller", who)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return resp.StatusCode, out
}

func proofUse(jti string, iat time.Time) map[string]any {
	return map[string]any{"jkt": testJKT, "htm": "POST", "htu": "https://b.example/token", "jti": jti, "iat": iat.Unix()}
}

func TestReplayCheck_FreshThenReplay(t *testing.T) {
	var buf testsupport.Buffer
	_, url := replayServer(t, &buf)
	now := time.Now()

	status, body := postReplay(t, url, connectorID, proofUse("j1", now))
	if status != http.StatusOK || body["fresh"] != true {
		t.Fatalf("first: %d %v", status, body)
	}
	status, body = postReplay(t, url, connectorID, proofUse("j1", now))
	if status != http.StatusConflict || body["reason_code"] != "TOK-REPLAY" {
		t.Fatalf("second: %d %v", status, body)
	}
}

func TestReplayCheck_CallerMustBeListed(t *testing.T) {
	var buf testsupport.Buffer
	_, url := replayServer(t, &buf)
	for name, who := range map[string]string{"unauthenticated": "", "not listed": strangerID} {
		status, body := postReplay(t, url, who, proofUse("j-"+name, time.Now()))
		if status != http.StatusForbidden || body["reason_code"] != "TOK-CALLER-DENIED" {
			t.Errorf("%s: %d %v", name, status, body)
		}
	}
	// A refused caller's proof was not recorded: the listed caller still finds it fresh.
	if status, _ := postReplay(t, url, connectorID, proofUse("j-not listed", time.Now())); status != http.StatusOK {
		t.Errorf("a refused caller's proof was recorded: %d", status)
	}
}

func TestReplayCheck_RefusesWhatTheContractRefuses(t *testing.T) {
	var buf testsupport.Buffer
	_, url := replayServer(t, &buf)
	now := time.Now()
	with := func(k string, v any) map[string]any {
		m := proofUse("j-"+k+fmt.Sprint(v), now)
		m[k] = v
		return m
	}
	without := func(k string) map[string]any {
		m := proofUse("j-no-"+k, now)
		delete(m, k)
		return m
	}
	cases := map[string]any{
		"not JSON":                     `{"jkt":`,
		"unknown member":               with("extra", 1),
		"two objects":                  `{"jkt":"` + testJKT + `"} {}`,
		"bad jkt":                      with("jkt", "short"),
		"no htm":                       without("htm"),
		"no htu":                       without("htu"),
		"no iat":                       without("iat"),
		"jti too long":                 with("jti", strings.Repeat("x", 257)),
		"iat too old":                  with("iat", now.Add(-61*time.Second).Unix()),
		"iat too far ahead":            with("iat", now.Add(31*time.Second).Unix()),
		"not_after in the past":        with("not_after", now.Add(-time.Second).Unix()),
		"not_after beyond iat plus 90": with("not_after", now.Add(91*time.Second).Unix()),
		"trailing bracket":             `{"jkt":"` + testJKT + `","htm":"POST","htu":"https://b.example/token","jti":"j-tb","iat":` + fmt.Sprint(now.Unix()) + `}]`,
		"trailing brace":               `{"jkt":"` + testJKT + `","htm":"POST","htu":"https://b.example/token","jti":"j-tc","iat":` + fmt.Sprint(now.Unix()) + `}}`,
		// A valid object, then whitespace past the 4 KiB limit, then more: a reader that stops at the
		// limit would see only the object.
		"input past the size limit": `{"jkt":"` + testJKT + `","htm":"POST","htu":"https://b.example/token","jti":"j-big","iat":` + fmt.Sprint(now.Unix()) + `}` + strings.Repeat(" ", 5000) + `{"jti":"x"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			status, out := postReplay(t, url, connectorID, body)
			if status != http.StatusUnprocessableEntity || out["reason_code"] != "TOK-PROOF-INVALID" {
				t.Fatalf("%d %v", status, out)
			}
		})
	}
}

// With not_after the caller's window is used and the default iat window is not applied.
func TestReplayCheck_NotAfterReplacesTheDefaultWindow(t *testing.T) {
	var buf testsupport.Buffer
	_, url := replayServer(t, &buf)
	old := time.Now().Add(-80 * time.Second) // outside the default window, inside the caller's
	body := proofUse("j-own-window", old)
	body["not_after"] = old.Add(90 * time.Second).Unix()
	if status, out := postReplay(t, url, connectorID, body); status != http.StatusOK {
		t.Fatalf("%d %v", status, out)
	}
}

// The database gone: the store fails closed with its own code and says nothing about why.
func TestReplayCheck_FailsClosedWithoutTheDatabase(t *testing.T) {
	var buf testsupport.Buffer
	s, url := replayServer(t, &buf)
	s.pool.Close()
	status, body := postReplay(t, url, connectorID, proofUse("j-down", time.Now()))
	if status != http.StatusServiceUnavailable || body["reason_code"] != "TOK-STORE-UNAVAILABLE" || len(body) > 2 {
		t.Fatalf("%d %v", status, body)
	}
}

// A refusal carries the reason and the correlation id, never what the caller sent.
func TestReplayCheck_RefusalEchoesNothing(t *testing.T) {
	var buf testsupport.Buffer
	_, url := replayServer(t, &buf)
	canary := "CANARY-" + strings.Repeat("z", 40)
	body := proofUse(canary, time.Now().Add(-time.Hour))
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(must(json.Marshal(body))))
	req.Header.Set("X-Test-Caller", connectorID)
	req.Header.Set("X-Request-Id", "corr-1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(data), canary) || strings.Contains(buf.String(), canary) {
		t.Fatalf("the caller's input came back: %s", data)
	}
	if !strings.Contains(string(data), `"correlation_id":"corr-1"`) || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("answer %s, cache-control %q", data, resp.Header.Get("Cache-Control"))
	}
}

// The store warns at start that the replay record may have been lost: on a new database the
// sentinel is not there yet.
func TestReplayEpoch_WarnsOnAFreshDatabase(t *testing.T) {
	var buf testsupport.Buffer
	replayServer(t, &buf)
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(buf.String(), "replay record may have been lost") {
		if time.Now().After(deadline) {
			t.Fatalf("no warning:\n%s", buf.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(buf.String(), `"window":"2m0s"`) {
		t.Errorf("the warning does not name the window:\n%s", buf.String())
	}
}

// A query stalled behind a lock ends at the operation timeout with the store's own refusal, and a
// stop while it waits still returns within the shutdown timeout.
func TestReplayCheck_StalledDatabaseFailsClosedAndShutsDown(t *testing.T) {
	var buf testsupport.Buffer
	dbURL := testDatabaseURL(t)
	migrate(t, dbURL)
	cfg := localConfig(dbURL, fakeOpenBao(t).URL)
	cfg.ReplayCallers, cfg.Callers = []string{connectorID}, headerCaller{}
	cfg.ShutdownTimeout = time.Second
	s, err := New(context.Background(), cfg, testLogger(&buf))
	if err != nil {
		t.Fatal(err)
	}
	stop := startServer(t, s)
	url := "http://" + s.Addr().String() + "/internal/replay-check"

	ctx := context.Background()
	lock, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close(ctx) }()
	tx, err := lock.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `LOCK TABLE proof_jti IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	status, body := postReplay(t, url, connectorID, proofUse("j-stalled", time.Now()))
	if status != http.StatusServiceUnavailable || body["reason_code"] != "TOK-STORE-UNAVAILABLE" {
		t.Fatalf("%d %v", status, body)
	}
	if d := time.Since(start); d > replayOpTimeout+time.Second {
		t.Fatalf("answered after %v", d)
	}

	// Another request stalls again; stopping now must not hang on it.
	stalled := must(json.Marshal(proofUse("j-stalled-2", time.Now())))
	go func() {
		req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(stalled))
		req.Header.Set("X-Test-Caller", connectorID)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	time.Sleep(200 * time.Millisecond)
	start = time.Now()
	_ = stop()
	if d := time.Since(start); d > cfg.DrainDelay+cfg.ShutdownTimeout+replayOpTimeout+time.Second {
		t.Fatalf("Serve took %v to return", d)
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

// Two spellings of one target (RFC 3986 6.2.2-6.2.3) are one proof: the record is keyed on the
// normalised htu.
func TestReplayCheck_EquivalentHTUSpellingsAreOneProof(t *testing.T) {
	var buf testsupport.Buffer
	_, url := replayServer(t, &buf)
	now := time.Now()
	first := proofUse("j-spelling", now)
	first["htu"] = "https://EXAMPLE.test:443/%7Eapi"
	if status, out := postReplay(t, url, connectorID, first); status != http.StatusOK {
		t.Fatalf("first: %d %v", status, out)
	}
	second := proofUse("j-spelling", now)
	second["htu"] = "https://example.test/~api"
	if status, out := postReplay(t, url, connectorID, second); status != http.StatusConflict || out["reason_code"] != "TOK-REPLAY" {
		t.Fatalf("second: %d %v", status, out)
	}
	bad := proofUse("j-bad-htu", now)
	bad["htu"] = "ftp://example.test/x"
	if status, out := postReplay(t, url, connectorID, bad); status != http.StatusUnprocessableEntity || out["reason_code"] != "TOK-PROOF-INVALID" {
		t.Fatalf("non-normalisable htu: %d %v", status, out)
	}
}

type ecKey struct{ k *ecdsa.PrivateKey }

func (k ecKey) JWK() jose.JWK { return jose.PublicJWK(&k.k.PublicKey) }

func (k ecKey) Sign(_ context.Context, in []byte) ([]byte, error) {
	d := sha256.Sum256(in)
	r, s, err := ecdsa.Sign(rand.Reader, k.k, d[:])
	if err != nil {
		return nil, err
	}
	return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...), nil
}

// A use recorded by the resource-side verifier (dpopproof over the shared record) and the same
// proof presented to the replay check under another spelling of its htu are one proof.
func TestReplayCheck_SharesTheRecordWithTheVerifier(t *testing.T) {
	var buf testsupport.Buffer
	s, url := replayServer(t, &buf)
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := ecKey{pk}
	now := time.Now()
	proof, err := dpopproof.Build(context.Background(), key, dpopproof.Claims{JTI: "j-cross", HTM: "GET", HTU: "https://example.test/~api", IAT: now})
	if err != nil {
		t.Fatal(err)
	}
	v, err := dpopproof.Verify(context.Background(), proof, dpopproof.Expect{Method: "GET", URI: "https://example.test/~api"},
		dpopproof.Policy{Lifespan: 60 * time.Second, Skew: 5 * time.Second}, now, s.replay)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"jkt": v.JKT, "htm": "GET", "htu": "https://EXAMPLE.test:443/%7Eapi", "jti": "j-cross", "iat": now.Unix()}
	if status, out := postReplay(t, url, connectorID, body); status != http.StatusConflict || out["reason_code"] != "TOK-REPLAY" {
		t.Fatalf("the verifier's use was not seen: %d %v", status, out)
	}
}
