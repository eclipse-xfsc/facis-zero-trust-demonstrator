package participant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/protectedresource"
)

func TestHTTPSampleAdapterOutboundMappings(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		outcome     Outcome
		reason      string
		wantOutcome Outcome
	}{
		{name: "success", status: 200, outcome: OutcomeSuccess, reason: "SAMPLE_RESOURCE_RETURNED", wantOutcome: OutcomeSuccess},
		{name: "denied", status: 403, outcome: OutcomeDenied, reason: "SAMPLE_ACCESS_DENIED", wantOutcome: OutcomeDenied},
		{name: "unavailable", status: 503, outcome: OutcomeUnavailable, reason: "SAMPLE_RESOURCE_UNAVAILABLE", wantOutcome: OutcomeUnavailable},
		{name: "upstream error", status: 500, outcome: OutcomeError, reason: "SAMPLE_RESOURCE_ERROR", wantOutcome: OutcomeError},
		{name: "missing resource", status: 404, outcome: OutcomeError, reason: "SAMPLE_RESOURCE_NOT_FOUND", wantOutcome: OutcomeError},
		{name: "bad request", status: 400, outcome: OutcomeError, reason: "SAMPLE_INVALID_REQUEST", wantOutcome: OutcomeError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/demo" {
					t.Errorf("outbound request = %s %s", r.Method, r.URL.Path)
					http.Error(w, "unexpected request", http.StatusBadRequest)
					return
				}
				var input DemoRequest
				if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
					t.Errorf("decode outbound request: %v", err)
					http.Error(w, "invalid request", http.StatusBadRequest)
					return
				}
				if input.Resource != "sample-report" || input.Action != "read" || input.Scenario != test.name || input.RequestID != "req-http" || input.CorrelationID != "corr-http" {
					t.Errorf("outbound payload = %+v", input)
					http.Error(w, "unexpected payload", http.StatusBadRequest)
					return
				}
				writeUpstreamResponse(w, test.status, input.RequestID, input.CorrelationID, test.outcome, test.reason)
			}))
			defer upstream.Close()

			result, err := NewHTTPSampleAdapter(upstream.URL, nil).Request(context.Background(), AdapterRequest{
				RequestID: "req-http", CorrelationID: "corr-http", Resource: "sample-report", Action: "read", Scenario: test.name,
			})
			if err != nil {
				t.Fatalf("Request() error = %v", err)
			}
			if result.Outcome != test.wantOutcome || result.ReasonCode != test.reason || calls.Load() != 1 {
				t.Fatalf("Request() = %+v, calls = %d", result, calls.Load())
			}
		})
	}

}

func TestHTTPSampleAdapterRejectsInvalidResponses(t *testing.T) {
	valid := func(requestID, correlationID string) string {
		return fmt.Sprintf(`{"requestId":%q,"correlationId":%q,"source":"sample","mode":"sample","outcome":"success","reasonCode":"SAMPLE_RESOURCE_RETURNED","explanation":"safe sample response","timestamp":"2026-10-02T10:00:00Z","safeData":`+validSafeDataJSON+`}`, requestID, correlationID)
	}
	tests := []struct {
		name   string
		status int
		body   func() string
	}{
		{name: "empty", status: 200, body: func() string { return "" }},
		{name: "malformed", status: 200, body: func() string { return `{"outcome":` }},
		{name: "multiple objects", status: 200, body: func() string { return valid("req", "corr") + `{}` }},
		{name: "oversized", status: 200, body: func() string { return strings.Repeat("x", maxUpstreamResponseBytes+1) }},
		{name: "mismatched request ID", status: 200, body: func() string { return valid("other", "corr") }},
		{name: "mismatched correlation ID", status: 200, body: func() string { return valid("req", "other") }},
		{name: "invalid source", status: 200, body: func() string { return strings.Replace(valid("req", "corr"), `"source":"sample"`, `"source":"live"`, 1) }},
		{name: "invalid mode", status: 200, body: func() string { return strings.Replace(valid("req", "corr"), `"mode":"sample"`, `"mode":"live"`, 1) }},
		{name: "unknown outcome", status: 200, body: func() string {
			return strings.Replace(valid("req", "corr"), `"outcome":"success"`, `"outcome":"maybe"`, 1)
		}},
		{name: "unknown reason", status: 200, body: func() string {
			return strings.Replace(valid("req", "corr"), "SAMPLE_RESOURCE_RETURNED", "SAMPLE_UNKNOWN", 1)
		}},
		{name: "inconsistent status", status: 403, body: func() string { return valid("req", "corr") }},
		{name: "unknown field", status: 200, body: func() string {
			return strings.Replace(valid("req", "corr"), `"safeData":`, `"unexpected":true,"safeData":`, 1)
		}},
		{name: "undocumented safeData shape", status: 200, body: func() string {
			return strings.Replace(valid("req", "corr"), validSafeDataJSON, `{"report":"sample"}`, 1)
		}},
		{name: "extra safeData field", status: 200, body: func() string {
			return strings.Replace(valid("req", "corr"), `"action":"read",`, `"action":"read","raw":"upstream body",`, 1)
		}},
		{name: "extra report field", status: 200, body: func() string {
			return strings.Replace(valid("req", "corr"), `"content":"Local sample data."`, `"content":"Local sample data.","secret":"x"`, 1)
		}},
		{name: "non-success with safeData", status: 403, body: func() string {
			body := strings.Replace(valid("req", "corr"), `"outcome":"success"`, `"outcome":"denied"`, 1)
			return strings.Replace(body, "SAMPLE_RESOURCE_RETURNED", "SAMPLE_ACCESS_DENIED", 1)
		}},
		{name: "control characters in explanation", status: 200, body: func() string {
			return strings.Replace(valid("req", "corr"), `"explanation":"safe sample response"`, `"explanation":"line\nbreak"`, 1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body())
			}))
			defer upstream.Close()
			result, err := NewHTTPSampleAdapter(upstream.URL, nil).Request(context.Background(), AdapterRequest{RequestID: "req", CorrelationID: "corr"})
			if result != nil || !errors.Is(err, ErrInvalidUpstreamResponse) {
				t.Fatalf("Request() = (%+v, %v), want invalid upstream response", result, err)
			}
		})
	}

}

func TestHTTPSampleAdapterRejectsRedirectWithoutRetry(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/demo", http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()

	result, err := NewHTTPSampleAdapter(redirect.URL, nil).Request(context.Background(), AdapterRequest{RequestID: "req", CorrelationID: "corr"})
	if result != nil || !errors.Is(err, ErrInvalidUpstreamResponse) || targetCalls.Load() != 0 {
		t.Fatalf("Request() = (%+v, %v), redirected calls = %d", result, err, targetCalls.Load())
	}
}

func TestHTTPSampleAdapterHonorsTimeoutAndConnectionFailure(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		stop := make(chan struct{})
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
			select {
			case <-r.Context().Done():
			case <-stop:
			}
		}))
		t.Cleanup(func() {
			close(stop)
			upstream.Close()
		})
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		result, err := NewHTTPSampleAdapter(upstream.URL, nil).Request(ctx, AdapterRequest{RequestID: "req", CorrelationID: "corr"})
		if result != nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Request() = (%+v, %v), want deadline exceeded", result, err)
		}
	})

	t.Run("connection failure", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := upstream.URL
		upstream.Close()
		result, err := NewHTTPSampleAdapter(url, nil).Request(context.Background(), AdapterRequest{RequestID: "req", CorrelationID: "corr"})
		if result != nil || err == nil || errors.Is(err, ErrInvalidUpstreamResponse) {
			t.Fatalf("Request() = (%+v, %v), want connection error", result, err)
		}
	})
}

func TestParticipantToProtectedResourceHandlerIntegration(t *testing.T) {
	resourceConfig := protectedresource.Config{
		Address: ":0", RequestTimeout: 300 * time.Millisecond, SlowDelay: 150 * time.Millisecond,
		Mode: "sample", AdapterMode: "sample", LogLevel: "info",
	}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	resourceServer := httptest.NewServer(protectedresource.NewServer(resourceConfig, logger).Handler())
	defer resourceServer.Close()

	tests := []struct {
		name       string
		scenario   string
		timeout    time.Duration
		status     int
		outcome    Outcome
		reasonCode string
	}{
		{name: "success", scenario: "success", timeout: time.Second, status: 200, outcome: OutcomeSuccess, reasonCode: "SAMPLE_RESOURCE_RETURNED"},
		{name: "denied", scenario: "denied", timeout: time.Second, status: 403, outcome: OutcomeDenied, reasonCode: "SAMPLE_ACCESS_DENIED"},
		{name: "unavailable", scenario: "unavailable", timeout: time.Second, status: 503, outcome: OutcomeUnavailable, reasonCode: "SAMPLE_RESOURCE_UNAVAILABLE"},
		{name: "error", scenario: "error", timeout: time.Second, status: 502, outcome: OutcomeError, reasonCode: "SAMPLE_RESOURCE_ERROR"},
		{name: "slow timeout", scenario: "slow", timeout: 25 * time.Millisecond, status: 504, outcome: OutcomeUnavailable, reasonCode: ReasonRequestTimeout},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := Config{Address: ":0", RequestTimeout: test.timeout, AdapterMode: "http-sample", ResourceURL: resourceServer.URL, LogLevel: "info"}
			participantServer := httptest.NewServer(NewServer(config, logger).Handler())
			defer participantServer.Close()
			body := fmt.Sprintf(`{"requestId":"req-integration","correlationId":"corr-integration","resource":"sample-report","action":"read","scenario":%q}`, test.scenario)
			result, status := postDemo(t, participantServer, body)
			assertDemoResult(t, result, status, test.status, test.outcome, test.reasonCode)
			if result.RequestID != "req-integration" || result.CorrelationID != "corr-integration" {
				t.Fatalf("identifiers changed: %+v", result)
			}
			if test.scenario == "slow" && len(result.SafeData) != 0 {
				t.Fatalf("late timeout exposed safe data: %+v", result.SafeData)
			}
		})
	}

	t.Run("sample-alternative success preserves identifiers", func(t *testing.T) {
		alternativeConfig := resourceConfig
		alternativeConfig.AdapterMode = "sample-alternative"
		alternativeResourceServer := httptest.NewServer(protectedresource.NewServer(alternativeConfig, logger).Handler())
		defer alternativeResourceServer.Close()

		config := Config{
			Address: ":0", RequestTimeout: time.Second, AdapterMode: "http-sample",
			ResourceURL: alternativeResourceServer.URL, LogLevel: "info",
		}
		participantServer := httptest.NewServer(NewServer(config, logger).Handler())
		defer participantServer.Close()

		body := `{"requestId":"req-alternative","correlationId":"corr-alternative","resource":"sample-report","action":"read","scenario":"success"}`
		result, status := postDemo(t, participantServer, body)
		assertDemoResult(t, result, status, http.StatusOK, OutcomeSuccess, "SAMPLE_ALTERNATIVE_RESOURCE_RETURNED")
		if result.RequestID != "req-alternative" || result.CorrelationID != "corr-alternative" {
			t.Fatalf("identifiers changed: %+v", result)
		}
	})
}

const validSafeDataJSON = `{"resource":"sample-report","action":"read","report":{"id":"FACIS-SAMPLE-REPORT-001","title":"Sample report","content":"Local sample data."}}`

func writeUpstreamResponse(w http.ResponseWriter, status int, requestID, correlationID string, outcome Outcome, reason string) {
	safeData := map[string]any{}
	if outcome == OutcomeSuccess {
		safeData = map[string]any{
			"resource": "sample-report",
			"action":   "read",
			"report": map[string]any{
				"id": "FACIS-SAMPLE-REPORT-001", "title": "Sample report", "content": "Local sample data.",
			},
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(protectedResourceResponse{
		RequestID: requestID, CorrelationID: correlationID, Source: "sample", Mode: "sample",
		Outcome: outcome, ReasonCode: reason, Explanation: "safe sample response",
		Timestamp: time.Now().UTC(), SafeData: safeData,
	})
}

func TestParticipantHealthReportsSampleModeForHTTPSampleAdapter(t *testing.T) {
	config := Config{
		Address: ":0", RequestTimeout: time.Second, AdapterMode: "http-sample",
		ResourceURL: "http://127.0.0.1:1", LogLevel: "info",
	}
	server := httptest.NewServer(NewServer(config, slog.New(slog.NewJSONHandler(io.Discard, nil))).Handler())
	defer server.Close()

	response, err := server.Client().Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	var health struct {
		Status   string `json:"status"`
		Mode     string `json:"mode"`
		LiveMode string `json:"liveMode"`
	}
	if err := json.NewDecoder(response.Body).Decode(&health); err != nil {
		t.Fatalf("decode /health: %v", err)
	}
	if response.StatusCode != http.StatusOK || health.Status != "ok" || health.Mode != "sample" || health.LiveMode != "unavailable" {
		t.Fatalf("GET /health = %d %+v, want 200 ok mode=sample liveMode=unavailable", response.StatusCode, health)
	}
}
