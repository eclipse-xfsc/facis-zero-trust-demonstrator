package participant

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type adapterFunc func(context.Context, AdapterRequest) (*AdapterResult, error)

func (f adapterFunc) Request(ctx context.Context, request AdapterRequest) (*AdapterResult, error) {
	return f(ctx, request)
}

type HTTPAdapter struct {
	URL    string
	Client *http.Client
}

func (a HTTPAdapter) Request(ctx context.Context, _ AdapterRequest) (*AdapterResult, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if err != nil {
		return nil, err
	}
	response, err := a.Client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	return &AdapterResult{Outcome: OutcomeSuccess, ReasonCode: ReasonSampleGranted, Explanation: "received", SafeData: emptySafeData()}, nil
}

func TestHealthEndpoint(t *testing.T) {
	t.Parallel()

	server := newHTTPTestServer(t, NewSampleAdapter(), time.Second)
	response, err := server.Client().Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET /health status = %d, want 200", response.StatusCode)
	}

	request, _ := http.NewRequest(http.MethodPost, server.URL+"/health", nil)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatalf("POST /health: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /health status = %d, want 405", response.StatusCode)
	}
}

func TestSampleAdapterThroughDemoEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       string
		adapter    RequestAdapter
		status     int
		outcome    Outcome
		reasonCode string
	}{
		{name: "success", body: `{"requestId":"req-1","correlationId":"corr-1","resource":"report","action":"read","scenario":"success"}`, adapter: NewSampleAdapter(), status: http.StatusOK, outcome: OutcomeSuccess, reasonCode: ReasonSampleGranted},
		{name: "denial", body: `{"resource":"report","action":"read","scenario":"denied"}`, adapter: NewSampleAdapter(), status: http.StatusForbidden, outcome: OutcomeDenied, reasonCode: ReasonSampleDenied},
		{name: "sample adapter error", body: `{"resource":"report","action":"read","scenario":"error"}`, adapter: NewSampleAdapter(), status: http.StatusBadGateway, outcome: OutcomeError, reasonCode: ReasonAdapterError},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newHTTPTestServer(t, test.adapter, time.Second)
			result, status := postDemo(t, server, test.body)
			assertDemoResult(t, result, status, test.status, test.outcome, test.reasonCode)
		})
	}
}

func TestStubAdapterGenericErrorMapping(t *testing.T) {
	t.Parallel()

	server := newHTTPTestServer(t, adapterFunc(func(context.Context, AdapterRequest) (*AdapterResult, error) {
		return nil, errors.New("in-process stub adapter error")
	}), time.Second)
	result, status := postDemo(t, server, `{"resource":"report","action":"read"}`)
	assertDemoResult(t, result, status, http.StatusBadGateway, OutcomeError, ReasonAdapterError)
}

func TestDemoTimeoutIsUnavailable(t *testing.T) {
	t.Parallel()

	blocking := adapterFunc(func(ctx context.Context, _ AdapterRequest) (*AdapterResult, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	server := newHTTPTestServer(t, blocking, 20*time.Millisecond)
	result, status := postDemo(t, server, `{"resource":"report","action":"read"}`)
	assertDemoResult(t, result, status, http.StatusGatewayTimeout, OutcomeUnavailable, ReasonRequestTimeout)
}

func TestDemoExpiredDeadlineOverridesSuccessfulAdapterResult(t *testing.T) {
	t.Parallel()

	successAfterDeadline := adapterFunc(func(ctx context.Context, _ AdapterRequest) (*AdapterResult, error) {
		<-ctx.Done()
		return &AdapterResult{
			Outcome: OutcomeSuccess, ReasonCode: ReasonSampleGranted,
			Explanation: "late success", SafeData: emptySafeData(),
		}, nil
	})
	server := newHTTPTestServer(t, successAfterDeadline, 20*time.Millisecond)
	result, status := postDemo(t, server, `{"resource":"report","action":"read"}`)
	assertDemoResult(t, result, status, http.StatusGatewayTimeout, OutcomeUnavailable, ReasonRequestTimeout)
}

func TestDemoRequestIdentifiers(t *testing.T) {
	t.Parallel()

	t.Run("body-only request ID becomes correlation ID default", func(t *testing.T) {
		server := newHTTPTestServer(t, NewSampleAdapter(), time.Second)
		result, status := postDemo(t, server, `{"requestId":"body-request","resource":"report","action":"read"}`)
		assertDemoResult(t, result, status, http.StatusOK, OutcomeSuccess, ReasonSampleGranted)
		if result.RequestID != "body-request" || result.CorrelationID != "body-request" {
			t.Fatalf("identifiers = request %q, correlation %q; want body-request for both", result.RequestID, result.CorrelationID)
		}
	})

	t.Run("explicit correlation ID is preserved", func(t *testing.T) {
		server := newHTTPTestServer(t, NewSampleAdapter(), time.Second)
		result, status := postDemo(t, server, `{"requestId":"body-request","correlationId":"explicit-correlation","resource":"report","action":"read"}`)
		assertDemoResult(t, result, status, http.StatusOK, OutcomeSuccess, ReasonSampleGranted)
		if result.RequestID != "body-request" || result.CorrelationID != "explicit-correlation" {
			t.Fatalf("identifiers = request %q, correlation %q; want body-request and explicit-correlation", result.RequestID, result.CorrelationID)
		}
	})

	t.Run("header-only correlation ID is preserved with body request ID", func(t *testing.T) {
		server := newHTTPTestServer(t, NewSampleAdapter(), time.Second)
		request, err := http.NewRequest(http.MethodPost, server.URL+"/demo", strings.NewReader(`{"requestId":"body-request","resource":"report","action":"read"}`))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Correlation-ID", "header-correlation")
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatalf("POST /demo: %v", err)
		}
		defer func() { _ = response.Body.Close() }()
		var result DemoResponse
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			t.Fatalf("decode /demo response: %v", err)
		}
		assertDemoResult(t, result, response.StatusCode, http.StatusOK, OutcomeSuccess, ReasonSampleGranted)
		if result.RequestID != "body-request" || result.CorrelationID != "header-correlation" {
			t.Fatalf("identifiers = request %q, correlation %q; want body-request and header-correlation", result.RequestID, result.CorrelationID)
		}
	})
}

func TestDemoHTTPValidation(t *testing.T) {
	t.Parallel()

	t.Run("unsupported method", func(t *testing.T) {
		server := newHTTPTestServer(t, NewSampleAdapter(), time.Second)
		request, err := http.NewRequest(http.MethodPut, server.URL+"/demo", nil)
		if err != nil {
			t.Fatalf("create PUT /demo: %v", err)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatalf("PUT /demo: %v", err)
		}
		defer func() { _ = response.Body.Close() }()
		var result DemoResponse
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			t.Fatalf("decode PUT /demo response: %v", err)
		}
		assertDemoResult(t, result, response.StatusCode, http.StatusMethodNotAllowed, OutcomeError, ReasonMethodNotAllowed)
	})

	tests := []struct {
		name string
		body string
	}{
		{name: "empty resource", body: `{"resource":"","action":"read"}`},
		{name: "empty action", body: `{"resource":"report","action":"  "}`},
		{name: "malformed JSON", body: `{"resource":"report"`},
		{name: "extra JSON object", body: `{"resource":"report","action":"read"} {"resource":"other","action":"read"}`},
		{name: "unknown field", body: `{"resource":"report","action":"read","role":"admin"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newHTTPTestServer(t, NewSampleAdapter(), time.Second)
			result, status := postDemo(t, server, test.body)
			assertDemoResult(t, result, status, http.StatusBadRequest, OutcomeError, ReasonInvalidRequest)
		})
	}

	// Oversized bodies are exercised in-process through the real handler with a
	// ResponseRecorder: over a socket, net/http may close the connection once
	// MaxBytesReader trips, so the client could see a write/reset error instead
	// of the 400 response. The recorder removes that transport race.
	t.Run("oversized request body", func(t *testing.T) {
		config := Config{Address: ":0", RequestTimeout: time.Second, AdapterMode: "sample", LogLevel: "info"}
		logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
		handler := NewServerWithAdapter(config, logger, NewSampleAdapter()).Handler()
		body := `{"resource":"` + strings.Repeat("x", maxDemoRequestBytes) + `","action":"read"}`
		request := httptest.NewRequest(http.MethodPost, "/demo", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		var result DemoResponse
		if err := json.NewDecoder(recorder.Body).Decode(&result); err != nil {
			t.Fatalf("decode oversized /demo response: %v", err)
		}
		assertDemoResult(t, result, recorder.Code, http.StatusBadRequest, OutcomeError, ReasonInvalidRequest)
	})
}

func TestDemoConnectionFailureIsUnavailable(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	upstreamURL := upstream.URL
	upstream.Close()

	server := newHTTPTestServer(t, HTTPAdapter{URL: upstreamURL, Client: &http.Client{Timeout: time.Second}}, time.Second)
	result, status := postDemo(t, server, `{"resource":"report","action":"read"}`)
	assertDemoResult(t, result, status, http.StatusServiceUnavailable, OutcomeUnavailable, ReasonConnectionFailure)
}

func TestDemoResponseAndLogsExcludeRequestPayload(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	config := Config{Address: ":0", RequestTimeout: time.Second, AdapterMode: "sample", LogLevel: "info"}
	server := httptest.NewServer(NewServerWithAdapter(config, logger, NewSampleAdapter()).Handler())
	t.Cleanup(server.Close)

	secretMarker := "do-not-log-this-token"
	result, status := postDemo(t, server, `{"requestId":"safe-request","correlationId":"safe-correlation","resource":"`+secretMarker+`","action":"read"}`)
	assertDemoResult(t, result, status, http.StatusOK, OutcomeSuccess, ReasonSampleGranted)
	if strings.Contains(logs.String(), secretMarker) {
		t.Fatal("structured log contained request payload")
	}
	if !strings.Contains(logs.String(), `"requestId":"safe-request"`) || !strings.Contains(logs.String(), `"correlationId":"safe-correlation"`) {
		t.Fatal("structured log omitted request or correlation ID")
	}
}

func newHTTPTestServer(t *testing.T, adapter RequestAdapter, timeout time.Duration) *httptest.Server {
	t.Helper()
	config := Config{Address: ":0", RequestTimeout: timeout, AdapterMode: "sample", LogLevel: "info"}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	server := httptest.NewServer(NewServerWithAdapter(config, logger, adapter).Handler())
	t.Cleanup(server.Close)
	return server
}

func postDemo(t *testing.T, server *httptest.Server, body string) (DemoResponse, int) {
	t.Helper()
	response, err := server.Client().Post(server.URL+"/demo", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /demo: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	var result DemoResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatalf("decode /demo response: %v", err)
	}
	return result, response.StatusCode
}

func assertDemoResult(t *testing.T, result DemoResponse, gotStatus, wantStatus int, outcome Outcome, reasonCode string) {
	t.Helper()
	if gotStatus != wantStatus || result.Outcome != outcome || result.ReasonCode != reasonCode {
		t.Fatalf("result = status %d, outcome %q, reason %q; want %d, %q, %q", gotStatus, result.Outcome, result.ReasonCode, wantStatus, outcome, reasonCode)
	}
	if result.RequestID == "" || result.CorrelationID == "" || result.Source != "sample" || result.Mode != "sample" || result.Explanation == "" || result.Timestamp.IsZero() || result.SafeData == nil {
		t.Fatalf("response contract incomplete: %+v", result)
	}
}
