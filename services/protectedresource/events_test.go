package protectedresource

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/appevents"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/appfeedtest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/tokenverify"
)

func TestAccessEventsReachFeed(t *testing.T) {
	for _, tc := range []struct {
		role          string
		scopes        []string
		state, reason string
	}{
		{"reader", []string{ScopeReportRead}, "success", "APP-RESOURCE-REPORT-RETURNED"},
		{"viewer", []string{ScopeReportSummary}, "success", "APP-RESOURCE-SUMMARY-RETURNED"},
		{"reader_and_viewer", []string{ScopeReportRead, ScopeReportSummary}, "success", "APP-RESOURCE-REPORT-RETURNED"},
		{"unauthorized", []string{"other:write"}, "denied", "APP-RESOURCE-SCOPE-INSUFFICIENT"},
		{"unauthorized", nil, "denied", "APP-RESOURCE-SCOPE-INSUFFICIENT"},
	} {
		t.Run(tc.role+strings.Join(tc.scopes, ","), func(t *testing.T) {
			var lines bytes.Buffer
			cfg := testConfig()
			cfg.Verifier = fakeVerifier{identity: callerIdentity(tc.scopes...)}
			var err error
			cfg.Events, err = appevents.New(&lines, "protected-resource-b")
			if err != nil {
				t.Fatal(err)
			}
			response := serveWithCredentials(NewServer(cfg, slog.New(slog.NewJSONHandler(io.Discard, nil))).Handler(), `{"resource":"sample-report","action":"read","correlationId":"access-feed"}`)
			body := decodeDemo(t, response)
			if string(body.Outcome) != tc.state || tc.state == "denied" && (response.Code != 403 || len(body.SafeData) != 0) {
				t.Fatal("incorrect role response")
			}
			events := appfeedtest.RoundTrip(t, "../../docs/contracts", lines.String())
			if len(events) != 1 || events[0].CorrelationID != "access-feed" || events[0].Payload.State != tc.state || events[0].Payload.ReasonCode != tc.reason || events[0].Payload.Detail != "access role="+tc.role {
				t.Fatalf("access event mismatch: %+v", events)
			}
			for _, secret := range []string{canaryToken, canaryProof, "jti-1"} {
				if strings.Contains(lines.String(), secret) {
					t.Fatal("credential leaked")
				}
			}
		})
	}
}

func TestVerifierAndMalformedAccessEventsReachFeed(t *testing.T) {
	v, err := tokenverify.New(tokenverify.Config{Issuer: "https://issuer.example", JWKSURL: "https://issuer.example/jwks", Audience: "resource", PublicBaseURL: "https://resource.example", Replay: replay.NewMemory()})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, body, reason string
		verifier           tokenverify.RequestVerifier
		status             int
	}{
		{"missing token", `{}`, "APP-TOKEN-ABSENT", v, 401},
		{"malformed body", `{`, "APP-SAMPLE-INVALID-REQUEST", nil, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var lines bytes.Buffer
			cfg := testConfig()
			cfg.Verifier = tc.verifier
			cfg.Events, err = appevents.New(&lines, "protected-resource-b")
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/demo", strings.NewReader(tc.body))
			req.Header.Set("X-Request-ID", "refusal-feed")
			NewServer(cfg, slog.New(slog.NewJSONHandler(io.Discard, nil))).Handler().ServeHTTP(response, req)
			events := appfeedtest.RoundTrip(t, "../../docs/contracts", lines.String())
			if response.Code != tc.status || len(events) != 1 || events[0].CorrelationID != "refusal-feed" || events[0].Payload.ReasonCode != tc.reason {
				t.Fatalf("refusal event mismatch: %d %+v", response.Code, events)
			}
		})
	}
}
