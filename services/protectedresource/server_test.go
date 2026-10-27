package protectedresource

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHealthAndUnsupportedMethods(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(io.Discard)
	response := serve(t, handler, http.MethodGet, "/health", "")
	if response.Code != http.StatusOK {
		t.Fatalf("GET /health status = %d, want 200", response.Code)
	}
	var health healthResponse
	decodeResponse(t, response, &health)
	if health.Status != "ok" || health.Mode != "sample" || health.LiveMode != "unavailable" || health.Timestamp.IsZero() {
		t.Fatalf("GET /health response = %+v", health)
	}

	for _, test := range []struct {
		method string
		path   string
		allow  string
	}{
		{method: http.MethodPost, path: "/health", allow: http.MethodGet},
		{method: http.MethodGet, path: "/demo", allow: http.MethodPost},
	} {
		response = serve(t, handler, test.method, test.path, "")
		if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != test.allow {
			t.Fatalf("%s %s = %d Allow %q", test.method, test.path, response.Code, response.Header().Get("Allow"))
		}
	}
}

func TestDemoScenariosAndResponseContract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		scenario   string
		status     int
		outcome    Outcome
		reasonCode string
	}{
		{scenario: "success", status: http.StatusOK, outcome: OutcomeSuccess, reasonCode: ReasonSuccess},
		{scenario: "denied", status: http.StatusForbidden, outcome: OutcomeDenied, reasonCode: ReasonDenied},
		{scenario: "unavailable", status: http.StatusServiceUnavailable, outcome: OutcomeUnavailable, reasonCode: ReasonUnavailable},
		{scenario: "error", status: http.StatusInternalServerError, outcome: OutcomeError, reasonCode: ReasonError},
		{scenario: "slow", status: http.StatusOK, outcome: OutcomeSuccess, reasonCode: ReasonSlowSuccess},
	}
	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			t.Parallel()
			handler := newTestHandler(io.Discard)
			body := `{"resource":"sample-report","action":"read","scenario":"` + test.scenario + `","requestId":"req-1","correlationId":"corr-1"}`
			response := serve(t, handler, http.MethodPost, "/demo", body)
			result := decodeDemo(t, response)
			assertDemo(t, response.Code, result, test.status, test.outcome, test.reasonCode)
			if result.RequestID != "req-1" || result.CorrelationID != "corr-1" {
				t.Fatalf("IDs = %q/%q", result.RequestID, result.CorrelationID)
			}
		})
	}
}

func TestDemoIdentifierResolution(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		body            string
		wantRequest     string
		wantCorrelation string
	}{
		{name: "body request defaults correlation", body: `{"resource":"sample-report","action":"read","requestId":"body-request"}`, wantRequest: "body-request", wantCorrelation: "body-request"},
		{name: "explicit correlation", body: `{"resource":"sample-report","action":"read","requestId":"body-request","correlationId":"explicit-correlation"}`, wantRequest: "body-request", wantCorrelation: "explicit-correlation"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			response := serve(t, newTestHandler(io.Discard), http.MethodPost, "/demo", test.body)
			result := decodeDemo(t, response)
			if result.RequestID != test.wantRequest || result.CorrelationID != test.wantCorrelation {
				t.Fatalf("IDs = %q/%q, want %q/%q", result.RequestID, result.CorrelationID, test.wantRequest, test.wantCorrelation)
			}
		})
	}
}

func TestDemoValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       string
		status     int
		reasonCode string
	}{
		{name: "missing resource", body: `{"action":"read"}`, status: http.StatusBadRequest, reasonCode: ReasonInvalidRequest},
		{name: "missing action", body: `{"resource":"sample-report"}`, status: http.StatusBadRequest, reasonCode: ReasonInvalidRequest},
		{name: "malformed JSON", body: `{"resource":`, status: http.StatusBadRequest, reasonCode: ReasonInvalidRequest},
		{name: "unknown field", body: `{"resource":"sample-report","action":"read","token":"secret"}`, status: http.StatusBadRequest, reasonCode: ReasonInvalidRequest},
		{name: "multiple objects", body: `{"resource":"sample-report","action":"read"}{}`, status: http.StatusBadRequest, reasonCode: ReasonInvalidRequest},
		{name: "unknown scenario", body: `{"resource":"sample-report","action":"read","scenario":"live"}`, status: http.StatusBadRequest, reasonCode: ReasonUnknownScenario},
		{name: "uncatalogued resource", body: `{"resource":"other","action":"read"}`, status: http.StatusNotFound, reasonCode: ReasonResourceNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			response := serve(t, newTestHandler(io.Discard), http.MethodPost, "/demo", test.body)
			result := decodeDemo(t, response)
			if response.Code != test.status || result.ReasonCode != test.reasonCode {
				t.Fatalf("response = %d/%s, want %d/%s", response.Code, result.ReasonCode, test.status, test.reasonCode)
			}
		})
	}

	t.Run("oversized body", func(t *testing.T) {
		t.Parallel()
		body := `{"resource":"` + strings.Repeat("x", maxDemoRequestBytes) + `","action":"read"}`
		response := serve(t, newTestHandler(io.Discard), http.MethodPost, "/demo", body)
		result := decodeDemo(t, response)
		if response.Code != http.StatusRequestEntityTooLarge || result.ReasonCode != ReasonRequestTooLarge {
			t.Fatalf("oversized response = %d/%s", response.Code, result.ReasonCode)
		}
	})
}

func TestSlowScenarioCancellation(t *testing.T) {
	t.Parallel()

	config := testConfig()
	config.SlowDelay = time.Hour
	handler := NewServer(config, slog.New(slog.NewJSONHandler(io.Discard, nil))).Handler()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodPost, "/demo", strings.NewReader(`{"resource":"sample-report","action":"read","scenario":"slow"}`)).WithContext(ctx)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	result := decodeDemo(t, response)
	assertDemo(t, response.Code, result, http.StatusServiceUnavailable, OutcomeUnavailable, ReasonCancelled)
}

type successAfterContextDoneAdapter struct{}

func (successAfterContextDoneAdapter) Request(ctx context.Context, _ ResourceRequest) (ResourceResult, error) {
	<-ctx.Done()
	return ResourceResult{
		Outcome: OutcomeSuccess, ReasonCode: ReasonSuccess,
		Explanation: "This late success must be ignored.",
		SafeData:    map[string]any{"report": "must not be exposed"},
	}, nil
}

func TestDeadlineTakesPrecedenceOverLateAdapterSuccess(t *testing.T) {
	t.Parallel()

	config := testConfig()
	config.RequestTimeout = 10 * time.Millisecond
	handler := NewServerWithAdapter(
		config,
		slog.New(slog.NewJSONHandler(io.Discard, nil)),
		successAfterContextDoneAdapter{},
	).Handler()

	response := serve(t, handler, http.MethodPost, "/demo", `{"resource":"sample-report","action":"read"}`)
	result := decodeDemo(t, response)

	assertDemo(t, response.Code, result, http.StatusGatewayTimeout, OutcomeUnavailable, ReasonRequestTimeout)
	if len(result.SafeData) != 0 {
		t.Fatalf("safeData = %#v, want empty object", result.SafeData)
	}
}

func TestLogsContainSafeMetadataOnly(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	secret := "raw-secret-marker"
	response := serve(t, newTestHandler(&logs), http.MethodPost, "/demo", `{"resource":"`+secret+`","action":"read","requestId":"safe-request","correlationId":"safe-correlation"}`)
	_ = decodeDemo(t, response)
	text := logs.String()
	if strings.Contains(text, secret) {
		t.Fatal("log contains raw request data")
	}
	for _, required := range []string{"safe-request", "safe-correlation", ReasonResourceNotFound} {
		if !strings.Contains(text, required) {
			t.Fatalf("log missing %q: %s", required, text)
		}
	}
}

func testConfig() Config {
	return Config{Address: ":0", RequestTimeout: time.Second, SlowDelay: time.Millisecond, Mode: "sample", LogLevel: "info"}
}

func newTestHandler(writer io.Writer) http.Handler {
	return NewServer(testConfig(), slog.New(slog.NewJSONHandler(writer, nil))).Handler()
}

func serve(t *testing.T, handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func decodeDemo(t *testing.T, response *httptest.ResponseRecorder) demoResponse {
	t.Helper()
	var result demoResponse
	decodeResponse(t, response, &result)
	return result
}

func decodeResponse(t *testing.T, response *httptest.ResponseRecorder, target any) {
	t.Helper()
	if err := json.NewDecoder(response.Body).Decode(target); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func assertDemo(t *testing.T, gotStatus int, result demoResponse, wantStatus int, outcome Outcome, reasonCode string) {
	t.Helper()
	if gotStatus != wantStatus || result.Outcome != outcome || result.ReasonCode != reasonCode {
		t.Fatalf("response = %d/%s/%s, want %d/%s/%s", gotStatus, result.Outcome, result.ReasonCode, wantStatus, outcome, reasonCode)
	}
	if result.RequestID == "" || result.CorrelationID == "" || result.Source != "sample" || result.Mode != "sample" || result.Explanation == "" || result.Timestamp.IsZero() || result.SafeData == nil {
		t.Fatalf("response contract incomplete: %+v", result)
	}
}
