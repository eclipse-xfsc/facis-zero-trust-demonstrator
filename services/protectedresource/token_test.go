package protectedresource

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/tokenverify"
)

const (
	canaryToken = "canary-access-token-must-not-leak"
	canaryProof = "canary-dpop-proof-must-not-leak"
)

// fakeVerifier stands in for the token path: it either injects a chosen Identity or refuses with 401.
type fakeVerifier struct {
	identity tokenverify.Identity
	refuse   bool
}

func (f fakeVerifier) Verify(*http.Request) (tokenverify.Identity, error) {
	if f.refuse {
		return tokenverify.Identity{}, tokenverify.ErrSignature
	}
	return f.identity, nil
}

func (f fakeVerifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := f.Verify(r)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(tokenverify.WithIdentity(r.Context(), identity)))
	})
}

func callerIdentity(scopes ...string) tokenverify.Identity {
	return tokenverify.Identity{
		ClientID: "client-participant", Subject: "client-participant", JKT: "jkt-thumbprint-1",
		Scopes: scopes, TokenID: "jti-1", Expires: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC),
	}
}

func newTokenServer(logs io.Writer, verifier tokenverify.RequestVerifier) *Server {
	config := testConfig()
	config.Verifier = verifier
	return NewServer(config, slog.New(slog.NewJSONHandler(logs, nil)))
}

func serveWithCredentials(handler http.Handler, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/demo", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "DPoP "+canaryToken)
	request.Header.Set("DPoP", canaryProof)
	request.Header.Set("X-Request-ID", "req-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestTokenModeScopeTable(t *testing.T) {
	t.Parallel()

	const body = `{"resource":"sample-report","action":"read","requestId":"req-token","correlationId":"corr-token"}`
	tests := []struct {
		name       string
		verifier   fakeVerifier
		body       string
		status     int
		reasonCode string
		dataKey    string
	}{
		{name: "report:read returns the full report", verifier: fakeVerifier{identity: callerIdentity(ScopeReportRead)}, body: body, status: 200, reasonCode: ReasonReportReturned, dataKey: "report"},
		{name: "report:summary returns the summary", verifier: fakeVerifier{identity: callerIdentity(ScopeReportSummary)}, body: body, status: 200, reasonCode: ReasonSummaryReturned, dataKey: "summary"},
		{name: "both scopes return the full report", verifier: fakeVerifier{identity: callerIdentity(ScopeReportSummary, ScopeReportRead)}, body: body, status: 200, reasonCode: ReasonReportReturned, dataKey: "report"},
		{name: "unrelated scope is refused with 403", verifier: fakeVerifier{identity: callerIdentity("other:write")}, body: body, status: 403, reasonCode: ReasonScopeInsufficient},
		{name: "no scope is refused with 403", verifier: fakeVerifier{identity: callerIdentity()}, body: body, status: 403, reasonCode: ReasonScopeInsufficient},
		{name: "sample scenario is rejected in token mode", verifier: fakeVerifier{identity: callerIdentity(ScopeReportRead)}, body: `{"resource":"sample-report","action":"read","scenario":"success"}`, status: 400, reasonCode: ReasonScenarioNotAllowed},
		{name: "whitespace-only scenario counts as absent", verifier: fakeVerifier{identity: callerIdentity(ScopeReportRead)}, body: `{"resource":"sample-report","action":"read","scenario":"  "}`, status: 200, reasonCode: ReasonReportReturned, dataKey: "report"},
		{name: "empty scenario counts as absent", verifier: fakeVerifier{identity: callerIdentity(ScopeReportRead)}, body: `{"resource":"sample-report","action":"read","scenario":""}`, status: 200, reasonCode: ReasonReportReturned, dataKey: "report"},
		{name: "padded scenario is still rejected", verifier: fakeVerifier{identity: callerIdentity(ScopeReportRead)}, body: `{"resource":"sample-report","action":"read","scenario":" denied "}`, status: 400, reasonCode: ReasonScenarioNotAllowed},
		{name: "uncatalogued resource is 404 even with scope", verifier: fakeVerifier{identity: callerIdentity(ScopeReportRead)}, body: `{"resource":"other","action":"read"}`, status: 404, reasonCode: ReasonResourceNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			response := serveWithCredentials(newTokenServer(io.Discard, test.verifier).Handler(), test.body)
			result := decodeDemo(t, response)
			if response.Code != test.status || result.ReasonCode != test.reasonCode || result.Mode != ModeToken {
				t.Fatalf("response = %d/%s/%s, want %d/%s/token", response.Code, result.ReasonCode, result.Mode, test.status, test.reasonCode)
			}
			if test.dataKey == "" {
				if len(result.SafeData) != 0 {
					t.Fatalf("refusal exposed data: %+v", result.SafeData)
				}
				return
			}
			if _, ok := result.SafeData[test.dataKey].(map[string]any); !ok || len(result.SafeData) != 3 {
				t.Fatalf("safeData = %+v, want resource, action and %s", result.SafeData, test.dataKey)
			}
		})
	}
}

func TestTokenModeVerifierRefusalNeverReachesHandler(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	response := serveWithCredentials(newTokenServer(&logs, fakeVerifier{refuse: true}).Handler(), `{"resource":"sample-report","action":"read"}`)
	if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("refused request = %d, want 401 with WWW-Authenticate", response.Code)
	}
	text := logs.String()
	if !strings.Contains(text, "protected resource request refused") || !strings.Contains(text, `"status":401`) || !strings.Contains(text, "req-token") {
		t.Fatalf("refusal not logged with status and request id: %s", text)
	}
	if strings.Contains(text, "FACIS-SAMPLE-REPORT") || strings.Contains(response.Body.String(), "FACIS-SAMPLE-REPORT") {
		t.Fatal("refused request reached report data")
	}
}

func TestTokenModeLogsIdentityAndNeverCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		verifier fakeVerifier
		identity bool
	}{
		{name: "granted request", verifier: fakeVerifier{identity: callerIdentity(ScopeReportRead)}, identity: true},
		{name: "scope refusal", verifier: fakeVerifier{identity: callerIdentity()}, identity: true},
		{name: "verifier refusal", verifier: fakeVerifier{refuse: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			response := serveWithCredentials(newTokenServer(&logs, test.verifier).Handler(), `{"resource":"sample-report","action":"read"}`)
			text, body := logs.String(), response.Body.String()
			for _, canary := range []string{canaryToken, canaryProof, "jti-1"} {
				if strings.Contains(text, canary) || strings.Contains(body, canary) {
					t.Fatalf("%q leaked; logs %s body %s", canary, text, body)
				}
			}
			for _, field := range []string{`"client_id":"client-participant"`, `"sub":"client-participant"`, `"jkt":"jkt-thumbprint-1"`} {
				if strings.Contains(text, field) != test.identity {
					t.Fatalf("log line identity %s present=%v, want %v: %s", field, !test.identity, test.identity, text)
				}
			}
		})
	}
}

func TestSampleModeIsUnauthenticatedAndKeepsScenarios(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	server := newTokenServer(&logs, nil)
	response := serve(t, server.Handler(), http.MethodPost, "/demo", `{"resource":"sample-report","action":"read","scenario":"denied"}`)
	assertDemo(t, response.Code, decodeDemo(t, response), http.StatusForbidden, OutcomeDenied, ReasonDenied)
	if strings.Contains(logs.String(), "client_id") {
		t.Fatalf("sample mode logged an identity: %s", logs.String())
	}
}

func TestHealthReportsModeAndSeedVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		verifier tokenverify.RequestVerifier
		mode     string
	}{
		{name: "sample mode without verifier", mode: ModeSample},
		{name: "token mode with verifier", verifier: fakeVerifier{}, mode: ModeToken},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			response := serve(t, newTokenServer(io.Discard, test.verifier).Handler(), http.MethodGet, "/health", "")
			var health healthResponse
			decodeResponse(t, response, &health)
			if health.Mode != test.mode || health.SeedVersion != "v1" || health.SeedVersion != demoSeed.Version {
				t.Fatalf("health = %+v, want mode %s seedVersion v1", health, test.mode)
			}
		})
	}
}

func TestSeedValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
	}{
		{name: "missing version", raw: strings.Replace(string(seedV1), `"version": "v1"`, `"version": ""`, 1)},
		{name: "unknown field", raw: strings.Replace(string(seedV1), `"version": "v1"`, `"version": "v1", "extra": 1`, 1)},
		{name: "trailing object", raw: string(seedV1) + "{}"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := loadSeed([]byte(test.raw)); err == nil {
				t.Fatal("invalid seed accepted")
			}
		})
	}
}

func TestResetEndpoint(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(io.Discard)
	response := serve(t, handler, http.MethodPost, "/reset", "")
	var reset resetResponse
	decodeResponse(t, response, &reset)
	if response.Code != http.StatusOK || reset.Status != "reset" || reset.SeedVersion != "v1" {
		t.Fatalf("POST /reset = %d %+v", response.Code, reset)
	}
	response = serve(t, handler, http.MethodGet, "/reset", "")
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("GET /reset = %d", response.Code)
	}
}

func TestFixedHooksGiveByteIdenticalRuns(t *testing.T) {
	t.Parallel()

	run := func(verifier tokenverify.RequestVerifier) string {
		server := newTokenServer(io.Discard, verifier)
		server.now = func() time.Time { return time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC) }
		counter := 0
		server.newID = func() string { counter++; return fmt.Sprintf("fixed-%d", counter) }
		var out strings.Builder
		for _, step := range []struct{ method, path, body string }{
			{http.MethodGet, "/health", ""},
			{http.MethodPost, "/demo", `{"resource":"sample-report","action":"read"}`},
			{http.MethodPost, "/demo", `{"resource":"other","action":"read"}`},
			{http.MethodPost, "/reset", ""},
			{http.MethodPost, "/demo", `{"resource":"sample-report","action":"read"}`},
		} {
			request := httptest.NewRequest(step.method, step.path, strings.NewReader(step.body))
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			fmt.Fprintf(&out, "%d %s\n", response.Code, response.Body.String())
		}
		return out.String()
	}
	for name, verifier := range map[string]tokenverify.RequestVerifier{
		"sample": nil,
		"token":  fakeVerifier{identity: callerIdentity(ScopeReportSummary)},
	} {
		first, second := run(verifier), run(verifier)
		if first != second {
			t.Fatalf("%s runs differ:\n%s\n%s", name, first, second)
		}
		if !strings.Contains(first, "fixed-1") {
			t.Fatalf("%s run did not use the id hook: %s", name, first)
		}
	}
}

func TestRefusalLogCarriesSafeReasonOnly(t *testing.T) {
	v, err := tokenverify.New(tokenverify.Config{Issuer: "https://issuer.example", JWKSURL: "https://issuer.example/jwks", Audience: "resource", PublicBaseURL: "https://resource.example", Replay: replay.NewMemory()})
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	response := serveWithCredentials(newTokenServer(&logs, v).Handler(), `{"resource":"sample-report","action":"read"}`)
	if response.Code != http.StatusUnauthorized {
		t.Fatal("malformed token was not refused")
	}
	text := logs.String()
	if !strings.Contains(text, `"reasonCode":"token_malformed"`) {
		t.Fatal("safe refusal reason missing")
	}
	for _, forbidden := range []string{canaryToken, canaryProof, "Authorization", "DPoP"} {
		if strings.Contains(text, forbidden) {
			t.Fatal("credential material present in log")
		}
	}
}
