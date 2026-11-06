package participant_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectortest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03/if03fixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/pgtest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/participant"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/protectedresource"
)

// The token path end to end: the real connector binary with the verified-presentation grant, the
// Participant and the Protected Resource in token mode, built by their LoadConfig and NewServer from
// the environment as the binaries build them. It skips without TOKEN_STORE_TEST_DATABASE_URL,
// TRANSIT_TEST_ADDR and TRANSIT_TEST_TOKEN.

func TestMain(m *testing.M) {
	code := m.Run()
	connectortest.Cleanup()
	os.Exit(code)
}

const (
	cIssuer       = "https://connector.zone-b.test"
	vpIssuer      = "https://verifier.zone-b.test"
	vpKid         = "verifier-1"
	resourceAud   = "https://resource.zone-b.test"
	otherAudience = "https://other.zone-b.test"
)

// syncBuffer collects log records written from server goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// recorder sits in front of the Resource, as an ingress would: it is the Resource's public base URL,
// and it keeps every Authorization and DPoP value that crossed, for the replay and canary checks.
type recorder struct {
	mu    sync.Mutex
	pairs [][2]string
}

func (r *recorder) seen() [][2]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.pairs)
}

type processKey struct{ k *ecdsa.PrivateKey }

func newKey(t *testing.T) processKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return processKey{k}
}

func (p processKey) JWK() jose.JWK { return jose.PublicJWK(&p.k.PublicKey) }
func (p processKey) Sign(_ context.Context, in []byte) ([]byte, error) {
	return if03fixture.SignES256(p.k, in)
}

func writeFile(t *testing.T, name string, content []byte) string {
	t.Helper()
	p := t.TempDir() + "/" + name
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func credentials(t *testing.T, id, secret string) string {
	raw, _ := json.Marshal(map[string]string{"client_id": id, "client_secret": secret})
	return writeFile(t, "credentials.json", raw)
}

type participantUnderTest struct {
	url  string
	logs *syncBuffer
}

// startParticipant builds the Participant from the environment, as cmd/participant does.
func startParticipant(t *testing.T, connector, credentialsFile, outcomeKeyFile, role, resourceURL string) participantUnderTest {
	t.Helper()
	for k, v := range map[string]string{
		"PARTICIPANT_ADAPTER_MODE": "token", "PARTICIPANT_RESOURCE_URL": resourceURL, "PARTICIPANT_REQUEST_TIMEOUT": "10s",
		"PARTICIPANT_CONNECTOR_URL": connector, "PARTICIPANT_CREDENTIALS_FILE": credentialsFile, "PARTICIPANT_AUDIENCE": resourceAud,
		"PARTICIPANT_OUTCOME_ISSUER": vpIssuer, "PARTICIPANT_OUTCOME_KID": vpKid, "PARTICIPANT_OUTCOME_KEY_FILE": outcomeKeyFile,
		"PARTICIPANT_OUTCOME_ROLE": role, "PARTICIPANT_OUTCOME_ENTITLEMENT": "",
	} {
		t.Setenv(k, v)
	}
	cfg, err := participant.LoadConfig()
	if err != nil {
		t.Fatalf("participant config: %v", err)
	}
	if cfg.ServingMode() != participant.ModeToken {
		t.Fatalf("participant mode %q", cfg.ServingMode())
	}
	logs := &syncBuffer{}
	app := participant.NewServer(cfg, slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	app.Start(ctx)
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(srv.Close)
	return participantUnderTest{url: srv.URL, logs: logs}
}

func getJSON(t *testing.T, method, target string, body string) (int, map[string]any, string) {
	t.Helper()
	req, _ := http.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m, string(raw)
}

// waitReady polls /state until ready and checks the path to it.
func waitReady(t *testing.T, p participantUnderTest, bodies *[]string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, state, raw := getJSON(t, http.MethodGet, p.url+"/state", "")
		*bodies = append(*bodies, raw)
		if state["state"] == "ready" {
			var path []string
			for _, h := range state["history"].([]any) {
				e := h.(map[string]any)
				path = append(path, e["state"].(string)+"/"+e["reason"].(string))
			}
			want := []string{"presenting/step_started", "acquiring_token/step_started", "ready/step_completed"}
			if !slices.Equal(path, want) || state["mode"] != "token" {
				t.Fatalf("state path %v; want %v", path, want)
			}
			return
		}
		if s, _ := state["state"].(string); strings.HasPrefix(s, "failed_") || time.Now().After(deadline) {
			t.Fatalf("participant not ready: %s\nlogs:\n%s", raw, p.logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestTokenPathEndToEnd(t *testing.T) {
	addr, token := os.Getenv("TRANSIT_TEST_ADDR"), os.Getenv("TRANSIT_TEST_TOKEN")
	if addr == "" || token == "" {
		t.Skip("TRANSIT_TEST_ADDR and TRANSIT_TEST_TOKEN not set")
	}
	dsn := pgtest.MigratedURL(t, "p10")

	// The fixture verifier's key: the Connector trusts its public half, the Participants sign with it.
	verifier, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(verifier)
	verifierKeyFile := writeFile(t, "verifier.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))

	c := connectortest.Start(t, dsn, addr, token, connectortest.Options{
		Issuer: cIssuer, VPIssuer: vpIssuer, VPKid: vpKid, VPKey: &verifier.PublicKey,
		Audiences: []string{resourceAud, otherAudience},
		ScopeMap: []connectortest.Scope{
			{Role: "report-reader", Scopes: []string{protectedresource.ScopeReportRead}},
			{Role: "report-viewer", Scopes: []string{protectedresource.ScopeReportSummary}},
		},
	})
	readerID, readerSecret := c.Register(t, "participant reader", protectedresource.ScopeReportRead, resourceAud, otherAudience)
	viewerID, viewerSecret := c.Register(t, "participant viewer", protectedresource.ScopeReportSummary, resourceAud)

	// The Resource, built from the environment as cmd/protected-resource builds it, behind the
	// recorder, whose URL is the Resource's public base URL.
	rec := &recorder{}
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
	if err != nil || rcfg.ServingMode() != protectedresource.ModeToken {
		t.Fatalf("resource config: %v %q", err, rcfg.ServingMode())
	}
	resourceLogs := &syncBuffer{}
	resource := httptest.NewServer(protectedresource.NewServer(rcfg, slog.New(slog.NewJSONHandler(resourceLogs, nil))).Handler())
	t.Cleanup(resource.Close)
	backend, _ := url.Parse(resource.URL)
	proxy := httputil.NewSingleHostReverseProxy(backend)
	frontSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.pairs = append(rec.pairs, [2]string{r.Header.Get("Authorization"), r.Header.Get("DPoP")})
		rec.mu.Unlock()
		proxy.ServeHTTP(w, r)
	})}
	go func() { _ = frontSrv.Serve(front) }()
	t.Cleanup(func() { _ = frontSrv.Close() })

	reader := startParticipant(t, c.Base, credentials(t, readerID, readerSecret), verifierKeyFile, "report-reader", publicBase)
	viewer := startParticipant(t, c.Base, credentials(t, viewerID, viewerSecret), verifierKeyFile, "report-viewer", publicBase)
	var bodies []string
	waitReady(t, reader, &bodies)
	waitReady(t, viewer, &bodies)

	// The answer depends on the scope; each Participant calls twice, each call with a fresh proof.
	demo := `{"resource":"sample-report","action":"read","requestId":"p10-check","correlationId":"p10-run"}`
	for _, c := range []struct {
		p      participantUnderTest
		reason string
		key    string
	}{
		{reader, "RESOURCE_REPORT_RETURNED", "report"},
		{viewer, "RESOURCE_SUMMARY_RETURNED", "summary"},
	} {
		for range 2 {
			status, got, raw := getJSON(t, http.MethodPost, c.p.url+"/demo", demo)
			bodies = append(bodies, raw)
			safe, _ := got["safeData"].(map[string]any)
			if status != http.StatusOK || got["reasonCode"] != c.reason || safe[c.key] == nil {
				t.Fatalf("demo: %d %s\nparticipant logs:\n%s\nresource logs:\n%s", status, raw, c.p.logs.String(), resourceLogs.String())
			}
		}
	}

	// The Resource logged who called: client_id, sub (the client id) and the key thumbprint.
	pairs := rec.seen()
	if len(pairs) != 4 {
		t.Fatalf("%d requests reached the Resource; want 4", len(pairs))
	}
	for i, id := range []string{readerID, readerID, viewerID, viewerID} {
		jkt := claim(t, strings.TrimPrefix(pairs[i][0], "DPoP "), "cnf")
		if !strings.Contains(resourceLogs.String(), `"client_id":"`+id+`","sub":"`+id+`","jkt":"`+jkt.(map[string]any)["jkt"].(string)+`"`) {
			t.Fatalf("resource log lacks the identity of call %d:\n%s", i, resourceLogs.String())
		}
	}
	if pairs[0][1] == pairs[1][1] || pairs[0][0] != pairs[1][0] {
		t.Fatal("a proof was reused across calls, or the token changed without renewal")
	}

	// Direct refusals at the Resource: no proof, a replayed proof, a token for another audience.
	direct := func(authorization, proof string) int {
		req, _ := http.NewRequest(http.MethodPost, publicBase+"/demo", strings.NewReader(demo))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", authorization)
		if proof != "" {
			req.Header.Set("DPoP", proof)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		bodies = append(bodies, string(raw))
		return resp.StatusCode
	}
	if s := direct(pairs[0][0], ""); s != http.StatusUnauthorized {
		t.Errorf("no proof: %d; want 401", s)
	}
	if s := direct(pairs[0][0], pairs[0][1]); s != http.StatusUnauthorized {
		t.Errorf("replayed proof: %d; want 401", s)
	}

	// A valid token of the reader's client for the other audience, with a valid fresh proof.
	key := newKey(t)
	cc := &connectorclient.Client{BaseURL: c.Base, ClientID: readerID, ClientSecret: readerSecret}
	ch, err := cc.Challenge(t.Context(), otherAudience)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := if03fixture.Fixture{Issuer: vpIssuer, Kid: vpKid, Key: verifier, Claims: if03.Claims{Role: "report-reader"}}.Outcome(t.Context(), ch)
	if err != nil {
		t.Fatal(err)
	}
	other, err := cc.Grant(t.Context(), key, outcome, ch.Value, otherAudience)
	if err != nil {
		t.Fatal(err)
	}
	jkt, _ := key.JWK().Thumbprint()
	if _, err := cc.Check(other, jkt, otherAudience); err != nil {
		t.Fatal(err)
	}
	proof, err := dpopproof.Build(t.Context(), key, dpopproof.Claims{HTM: http.MethodPost, HTU: publicBase + "/demo", ATH: connectorclient.ATH(other.AccessToken)})
	if err != nil {
		t.Fatal(err)
	}
	if s := direct("DPoP "+other.AccessToken, proof); s != http.StatusUnauthorized {
		t.Errorf("token for another audience: %d; want 401", s)
	}
	if n := strings.Count(resourceLogs.String(), `"msg":"protected resource request refused"`); n != 3 {
		t.Errorf("%d refusals logged; want 3:\n%s", n, resourceLogs.String())
	}

	// Canary: no token, proof or secret in any log or body.
	canaries := []string{readerSecret, viewerSecret, other.AccessToken, proof, outcome}
	for _, p := range pairs {
		canaries = append(canaries, strings.TrimPrefix(p[0], "DPoP "), p[1])
	}
	for _, s := range []string{reader.logs.String(), viewer.logs.String(), resourceLogs.String(), strings.Join(bodies, "\n")} {
		for _, secret := range canaries {
			for _, form := range []string{secret, base64.StdEncoding.EncodeToString([]byte(secret)), sha(secret)} {
				if form != "" && strings.Contains(s, form) {
					t.Fatalf("a credential leaked into a log or body")
				}
			}
		}
	}
}

func sha(s string) string {
	d := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(d[:])
}

func claim(t *testing.T, token, name string) any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m[name]
}
