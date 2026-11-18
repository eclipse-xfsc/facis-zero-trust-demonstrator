package participant_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectortest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03/if03fixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/pgtest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/participant"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/protectedresource"
)

// revocableOutcomes is the fixture verifier with a switch: once revoked, every outcome it answers
// with has the status revoked, as a verifier answers for a credential that was revoked.
type revocableOutcomes struct {
	fixture if03fixture.Fixture
	revoked atomic.Bool
}

func (r *revocableOutcomes) Outcome(ctx context.Context, ch connectorclient.Challenge) (string, error) {
	f := r.fixture
	if r.revoked.Load() {
		f.Status, f.ReasonCode = "revoked", "CRED-REVOKED" // as the contract fixture valid-revoked.json
	}
	return f.Outcome(ctx, ch)
}

// exchange is one grant the Participant made, as it crossed the wire: the outcome it presented
// and what the connector answered. No credential is kept beyond the test.
type exchange struct {
	outcomeStatus string
	verifiedAt    time.Time
	status        int
	reason        string
	accessToken   string
}

// grantRecorder is the Participant's HTTP transport to the connector: it records every grant.
type grantRecorder struct {
	mu        sync.Mutex
	exchanges []exchange
}

func (g *grantRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	var outcome string
	if req.URL.Path == "/oauth2/token" && req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		form, _ := url.ParseQuery(string(body))
		outcome = form.Get("outcome")
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil || outcome == "" {
		return resp, err
	}
	raw, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	var claims struct {
		Status     string    `json:"status"`
		VerifiedAt time.Time `json:"verified_at"`
	}
	if parts := strings.Split(outcome, "."); len(parts) == 3 {
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		_ = json.Unmarshal(payload, &claims)
	}
	var answer struct {
		AccessToken string `json:"access_token"`
		Reason      string `json:"reason"`
	}
	_ = json.Unmarshal(raw, &answer)
	g.mu.Lock()
	g.exchanges = append(g.exchanges, exchange{outcomeStatus: claims.Status, verifiedAt: claims.VerifiedAt,
		status: resp.StatusCode, reason: answer.Reason, accessToken: answer.AccessToken})
	g.mu.Unlock()
	return resp, nil
}

func (g *grantRecorder) all() []exchange {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]exchange(nil), g.exchanges...)
}

// TestSessionRevalidation runs a Participant's session against the real connector with a short
// re-validation interval (the access-token lifespan) and the real Protected Resource verifier.
// While the credential verifies, the session goes on across several intervals, each interval a new
// token granted on a fresh verification, and no token outlives its verification by more than the
// interval. Once the verifier answers revoked, the next renewal is refused and access ends without
// any action, within one interval of the last verification. A token used directly after its expiry,
// with a fresh proof, is refused as expired.
//
// The verifier is the fixture signer: the test proves the enforcement of the interval, not a real
// source of credential status. The Participant calls the Resource directly; the guard's per-request
// policy decision is not on this path.
func TestSessionRevalidation(t *testing.T) {
	addr, token := os.Getenv("TRANSIT_TEST_ADDR"), os.Getenv("TRANSIT_TEST_TOKEN")
	if addr == "" || token == "" {
		t.Skip("TRANSIT_TEST_ADDR and TRANSIT_TEST_TOKEN not set")
	}
	const interval = 12 * time.Second
	dsn := pgtest.MigratedURL(t, "revalidation")

	verifierKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := connectortest.Start(t, dsn, addr, token, connectortest.Options{
		Issuer: cIssuer, VPIssuer: vpIssuer, VPKid: vpKid, VPKey: &verifierKey.PublicKey,
		Audiences: []string{resourceAud},
		ScopeMap:  []connectortest.Scope{{Role: "report-reader", Scopes: []string{protectedresource.ScopeReportRead}}},

		AccessTokenLifespan: interval,
	})
	clientID, clientSecret := c.Register(t, "participant session", protectedresource.ScopeReportRead, resourceAud)

	// The Resource in token mode behind a recorder, as in TestTokenPathEndToEnd.
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	publicBase := "http://" + front.Addr().String()
	for k, v := range map[string]string{
		"PROTECTED_RESOURCE_MODE": "token", "PROTECTED_RESOURCE_TOKEN_ISSUER": cIssuer,
		"PROTECTED_RESOURCE_JWKS_URL": c.Base + "/.well-known/jwks.json", "PROTECTED_RESOURCE_AUDIENCE": resourceAud,
		"PROTECTED_RESOURCE_PUBLIC_BASE_URL": publicBase, "PROTECTED_RESOURCE_ADAPTER_MODE": "sample",
	} {
		t.Setenv(k, v)
	}
	rcfg, err := protectedresource.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	resourceLogs := &syncBuffer{}
	resource := httptest.NewServer(protectedresource.NewServer(rcfg, slog.New(slog.NewJSONHandler(resourceLogs, nil))).Handler())
	t.Cleanup(resource.Close)
	backend, _ := url.Parse(resource.URL)
	proxy := httputil.NewSingleHostReverseProxy(backend)
	rec := &recorder{}
	frontSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.pairs = append(rec.pairs, [2]string{r.Header.Get("Authorization"), r.Header.Get("DPoP")})
		rec.mu.Unlock()
		proxy.ServeHTTP(w, r)
	})}
	go func() { _ = frontSrv.Serve(front) }()
	t.Cleanup(func() { _ = frontSrv.Close() })

	// The Participant, with the switchable verifier as its outcome source.
	outcomes := &revocableOutcomes{fixture: if03fixture.Fixture{Issuer: vpIssuer, Kid: vpKid, Key: verifierKey,
		Claims: if03.Claims{Role: "report-reader"}}}
	grants := &grantRecorder{}
	connectorHTTP := &http.Client{Transport: grants, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	boot, err := participant.NewConnectorBootstrap(c.Base, credentials(t, clientID, clientSecret), resourceAud, outcomes, connectorHTTP)
	if err != nil {
		t.Fatal(err)
	}
	pcfg := participant.Config{Address: "127.0.0.1:0", RequestTimeout: 10 * time.Second, AdapterMode: participant.ModeToken,
		ResourceURL: publicBase, LogLevel: "debug", Bootstrapper: boot}
	plogs := &syncBuffer{}
	app := participant.NewServer(pcfg, slog.New(slog.NewJSONHandler(plogs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	app.Start(ctx)
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(srv.Close)
	var bodies []string
	waitReady(t, participantUnderTest{url: srv.URL, logs: plogs}, &bodies)

	demo := `{"resource":"sample-report","action":"read","requestId":"revalidation","correlationId":"revalidation-run"}`
	// call makes one request and reports when it was sent, its status and whether protected data came
	// back.
	call := func() (time.Time, int, bool) {
		sent := time.Now()
		status, got, _ := getJSON(t, http.MethodPost, srv.URL+"/demo", demo)
		data, _ := got["safeData"].(map[string]any)
		return sent, status, len(data) > 0
	}

	// Three intervals of requests: every one is served with data, by at least three tokens in turn.
	start := time.Now()
	for time.Since(start) < 3*interval {
		if _, status, data := call(); status != http.StatusOK || !data {
			t.Fatalf("a request was refused while the credential verified: %d\nparticipant logs:\n%s\nresource logs:\n%s", status, plogs.String(), resourceLogs.String())
		}
		time.Sleep(500 * time.Millisecond)
	}
	// Every token the Resource saw, with the verification of the outcome it was granted on.
	verifiedFor := map[string]time.Time{}
	for _, e := range grants.all() {
		if e.status == http.StatusOK && e.accessToken != "" {
			verifiedFor[e.accessToken] = e.verifiedAt
		}
	}
	used := map[string]bool{}
	for _, pair := range rec.seen() {
		access := strings.TrimPrefix(pair[0], "DPoP ")
		if used[access] {
			continue
		}
		used[access] = true
		verified, ok := verifiedFor[access]
		if !ok {
			t.Fatal("the Resource saw a token the Participant was not granted")
		}
		var claims struct{ Iat, Exp int64 }
		if err := json.Unmarshal(jwtPayload(t, access), &claims); err != nil {
			t.Fatal(err)
		}
		iat, exp := time.Unix(claims.Iat, 0), time.Unix(claims.Exp, 0)
		if exp.Sub(iat) > interval || exp.After(verified.Add(interval)) {
			t.Errorf("a token lives from %s to %s; the interval is %s from its verification at %s", iat, exp, interval, verified)
		}
	}
	if len(used) < 3 {
		t.Fatalf("%d tokens served three intervals; the session was not re-validated", len(used))
	}

	// The credential is revoked. Requests go on; access ends by itself, at the latest one interval
	// after the last verification a token was granted on.
	outcomes.revoked.Store(true)
	var lastVerified time.Time
	for _, e := range grants.all() {
		if e.status == http.StatusOK && e.verifiedAt.After(lastVerified) {
			lastVerified = e.verifiedAt
		}
	}
	accessEnds := lastVerified.Add(interval)
	refused := 0
	for refused < 3 {
		if time.Now().After(accessEnds.Add(40 * time.Second)) {
			t.Fatalf("only %d requests were sent after access ended at %s", refused, accessEnds)
		}
		sent, status, data := call()
		if !sent.Before(accessEnds) {
			if status == http.StatusOK || data {
				t.Fatalf("a request sent at %s, after access ended at %s, was served", sent, accessEnds)
			}
			refused++
		}
		time.Sleep(500 * time.Millisecond)
	}
	// The renewal after the revocation was the Participant's own, and the connector refused it.
	automatic := false
	for _, e := range grants.all() {
		if e.outcomeStatus == "revoked" {
			if e.status != http.StatusBadRequest || e.reason != "CRED-OUTCOME-NOT-VERIFIED" || e.accessToken != "" {
				t.Fatalf("a revoked outcome was answered %d %q", e.status, e.reason)
			}
			automatic = true
		}
	}
	if !automatic {
		t.Fatal("the session never presented a revoked outcome after the revocation")
	}

	// What the connector answers to a revoked outcome, for the same client.
	key := newKey(t)
	client := connectorclient.Client{BaseURL: c.Base, ClientID: clientID, ClientSecret: clientSecret}
	ch, err := client.Challenge(t.Context(), resourceAud)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := outcomes.Outcome(t.Context(), ch)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Grant(t.Context(), key, revoked, ch.Value, resourceAud)
	var refusal *connectorclient.Error
	if !errors.As(err, &refusal) || refusal.Reason != "CRED-OUTCOME-NOT-VERIFIED" {
		reason := ""
		if refusal != nil {
			reason = refusal.Reason
		}
		t.Fatalf("a revoked outcome was answered with %v (%q), want the refusal CRED-OUTCOME-NOT-VERIFIED", err, reason)
	}

	// A token of the test's own key, used directly at the Resource with a fresh proof each time:
	// served before its expiry, refused as expired after it.
	outcomes.revoked.Store(false)
	ch, err = client.Challenge(t.Context(), resourceAud)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := outcomes.Outcome(t.Context(), ch)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := client.Grant(t.Context(), key, verified, ch.Value, resourceAud)
	if err != nil {
		t.Fatal(err)
	}
	var claims struct{ Exp int64 }
	if err := json.Unmarshal(jwtPayload(t, issued.AccessToken), &claims); err != nil {
		t.Fatal(err)
	}
	direct := func() (int, bool) {
		proof, err := dpopproof.Build(t.Context(), key, dpopproof.Claims{HTM: http.MethodPost, HTU: publicBase + "/demo", ATH: connectorclient.ATH(issued.AccessToken)})
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodPost, publicBase+"/demo", strings.NewReader(demo))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "DPoP "+issued.AccessToken)
		req.Header.Set("DPoP", proof)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var body struct {
			SafeData map[string]any `json:"safeData"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, len(body.SafeData) > 0
	}
	if status, data := direct(); status != http.StatusOK || !data {
		t.Fatalf("the token was refused before its expiry: %d", status)
	}
	time.Sleep(time.Until(time.Unix(claims.Exp, 0)) + 100*time.Millisecond)
	before := strings.Count(resourceLogs.String(), `"reasonCode":"token_expired"`)
	if status, data := direct(); status != http.StatusUnauthorized || data {
		t.Fatalf("the token was answered with %d after its expiry", status)
	}
	if strings.Count(resourceLogs.String(), `"reasonCode":"token_expired"`) != before+1 {
		t.Fatalf("the refusal after the expiry was not for the expiry:\n%s", resourceLogs.String())
	}
}

// jwtPayload is the decoded payload of a compact JWS.
func jwtPayload(t *testing.T, compact string) []byte {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", compact)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
