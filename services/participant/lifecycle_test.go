package participant

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/tokenverify"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/protectedresource"
)

const canaryToken = "canary-access-token-must-not-leak"

type runFunc func(context.Context, func(State, string)) (TokenSession, error)

// fakeBootstrapper plays one runFunc per attempt; the last one repeats.
type fakeBootstrapper struct {
	mu    sync.Mutex
	calls int
	runs  []runFunc
}

func (f *fakeBootstrapper) Run(ctx context.Context, report func(State, string)) (TokenSession, error) {
	f.mu.Lock()
	index := f.calls
	f.calls++
	f.mu.Unlock()
	if index >= len(f.runs) {
		index = len(f.runs) - 1
	}
	return f.runs[index](ctx, report)
}

func (f *fakeBootstrapper) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// countingSession hands out a distinct credential pair per call so caching would be visible.
type countingSession struct {
	calls atomic.Int32
	err   error
}

func (c *countingSession) Authorize(_ context.Context, method, _ string) (string, string, error) {
	n := c.calls.Add(1)
	if c.err != nil {
		return "", "", c.err
	}
	return fmt.Sprintf("DPoP %s-%d", canaryToken, n), fmt.Sprintf("proof-%s-%d", method, n), nil
}

func succeed(session TokenSession, reportReady bool) runFunc {
	return func(_ context.Context, report func(State, string)) (TokenSession, error) {
		report(StateRegistering, TransitionStepStarted)
		report(StatePresenting, TransitionStepStarted)
		report(StateAcquiringToken, TransitionStepStarted)
		if reportReady {
			report(StateReady, TransitionStepCompleted)
		}
		return session, nil
	}
}

func failWith(progress, failed State, reason string) runFunc {
	return func(_ context.Context, report func(State, string)) (TokenSession, error) {
		report(progress, TransitionStepStarted)
		if failed != "" {
			report(failed, reason)
		}
		return nil, errors.New("upstream said: " + canaryToken)
	}
}

func tokenConfig(resourceURL string, boot Bootstrapper) Config {
	return Config{
		Address: ":0", RequestTimeout: time.Second, AdapterMode: "sample", ResourceURL: resourceURL, LogLevel: "info",
		Bootstrapper: boot, BootstrapAttempts: 3, BootstrapBackoff: time.Millisecond,
	}
}

func newTokenParticipant(t *testing.T, config Config, logs io.Writer) *Server {
	t.Helper()
	server := NewServer(config, slog.New(slog.NewJSONHandler(logs, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	server.Start(ctx)
	return server
}

// waitBootstrap waits for the current bootstrap run, including its retries, to end.
func waitBootstrap(t *testing.T, server *Server) {
	t.Helper()
	server.lifecycle.mu.Lock()
	done := server.lifecycle.done
	server.lifecycle.mu.Unlock()
	if done == nil {
		t.Fatal("bootstrap not started")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("bootstrap did not finish")
	}
}

func getState(t *testing.T, handler http.Handler) (StateSnapshot, string) {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/state", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET /state = %d", response.Code)
	}
	var snapshot StateSnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("decode /state: %v", err)
	}
	return snapshot, response.Body.String()
}

func historyOf(snapshot StateSnapshot) string {
	parts := make([]string, 0, len(snapshot.History))
	for _, transition := range snapshot.History {
		if transition.At.IsZero() {
			return "missing timestamp"
		}
		parts = append(parts, string(transition.State)+"/"+transition.Reason)
	}
	return strings.Join(parts, " ")
}

func TestLifecycleStateTransitions(t *testing.T) {
	t.Parallel()

	session := &countingSession{}
	tests := []struct {
		name      string
		runs      []runFunc
		state     State
		attempts  int
		lastError string
		history   string
	}{
		{
			name: "bootstrap reaches ready", runs: []runFunc{succeed(session, true)},
			state: StateReady, attempts: 1,
			history: "registering/step_started presenting/step_started acquiring_token/step_started ready/step_completed",
		},
		{
			name: "ready is recorded when the bootstrapper does not report it", runs: []runFunc{succeed(session, false)},
			state: StateReady, attempts: 1,
			history: "registering/step_started presenting/step_started acquiring_token/step_started ready/step_completed",
		},
		{
			name: "registration rejection is final", runs: []runFunc{failWith(StateRegistering, StateFailedRegister, TransitionRegistrationRejected)},
			state: StateFailedRegister, attempts: 1, lastError: TransitionRegistrationRejected,
			history: "registering/step_started failed_registration/registration_rejected",
		},
		{
			name: "error without a failed state maps from the step in progress", runs: []runFunc{failWith(StatePresenting, "", "")},
			state: StateFailedPresent, attempts: 1, lastError: TransitionBootstrapError,
			history: "presenting/step_started failed_presentation/bootstrap_error",
		},
		{
			name: "free-form upstream reason is recorded as unspecified", runs: []runFunc{failWith(StateAcquiringToken, StateFailedToken, "HTTP 400 "+canaryToken)},
			state: StateFailedToken, attempts: 1, lastError: TransitionUnspecified,
			history: "acquiring_token/step_started failed_token/unspecified",
		},
		{
			name: "connector unreachable is retried then failed after the bound", runs: []runFunc{failWith(StateRegistering, StateFailedConnector, TransitionConnectorUnreachable)},
			state: StateFailedConnector, attempts: 3, lastError: TransitionConnectorUnreachable,
			history: "registering/step_started failed_connector_unreachable/connector_unreachable failed_connector_unreachable/retry_scheduled " +
				"registering/step_started failed_connector_unreachable/connector_unreachable failed_connector_unreachable/retry_scheduled " +
				"registering/step_started failed_connector_unreachable/connector_unreachable failed_connector_unreachable/retries_exhausted",
		},
		{
			name:  "connector unreachable recovers on retry",
			runs:  []runFunc{failWith(StateRegistering, StateFailedConnector, TransitionConnectorUnreachable), succeed(session, true)},
			state: StateReady, attempts: 2, lastError: TransitionConnectorUnreachable,
			history: "registering/step_started failed_connector_unreachable/connector_unreachable failed_connector_unreachable/retry_scheduled " +
				"registering/step_started presenting/step_started acquiring_token/step_started ready/step_completed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			boot := &fakeBootstrapper{runs: test.runs}
			server := newTokenParticipant(t, tokenConfig("http://127.0.0.1:1", boot), io.Discard)
			waitBootstrap(t, server)
			snapshot, raw := getState(t, server.Handler())
			if snapshot.Mode != ModeToken || snapshot.State != test.state || snapshot.Attempt != test.attempts || boot.callCount() != test.attempts || snapshot.LastErrorCode != test.lastError {
				t.Fatalf("state = %+v (calls %d), want %s after %d attempts, lastError %q", snapshot, boot.callCount(), test.state, test.attempts, test.lastError)
			}
			if got := historyOf(snapshot); got != test.history {
				t.Fatalf("history =\n%s\nwant\n%s", got, test.history)
			}
			if strings.Contains(raw, canaryToken) {
				t.Fatalf("/state leaked upstream text: %s", raw)
			}
		})
	}
}

func TestSampleModeStateAndReset(t *testing.T) {
	t.Parallel()

	server := NewServer(Config{Address: ":0", RequestTimeout: time.Second, AdapterMode: "sample", LogLevel: "info"}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	server.Start(context.Background())
	snapshot, _ := getState(t, server.Handler())
	if snapshot.Mode != ModeSample || snapshot.State != StateIdle || len(snapshot.History) != 0 {
		t.Fatalf("sample state = %+v", snapshot)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/reset", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("POST /reset = %d", response.Code)
	}
	snapshot, _ = getState(t, server.Handler())
	if snapshot.State != StateIdle || historyOf(snapshot) != "idle/reset" {
		t.Fatalf("after reset = %+v", snapshot)
	}
	demoServer := httptest.NewServer(server.Handler())
	defer demoServer.Close()
	result, status := postDemo(t, demoServer, `{"resource":"report","action":"read"}`)
	assertDemoResult(t, result, status, http.StatusOK, OutcomeSuccess, ReasonSampleGranted)

	for _, request := range []struct{ method, path string }{{http.MethodPost, "/state"}, {http.MethodGet, "/reset"}} {
		response = httptest.NewRecorder()
		server.Handler().ServeHTTP(response, httptest.NewRequest(request.method, request.path, nil))
		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s = %d, want 405", request.method, request.path, response.Code)
		}
	}
}

func TestResetWaitsForInFlightBootstrapAndRestarts(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	entered := make(chan struct{})
	session := &countingSession{}
	boot := &fakeBootstrapper{runs: []runFunc{
		func(_ context.Context, report func(State, string)) (TokenSession, error) {
			report(StateAcquiringToken, TransitionStepStarted)
			close(entered)
			<-release // an acquisition in flight; reset must not cut it short
			return session, nil
		},
		succeed(session, true),
	}}
	server := newTokenParticipant(t, tokenConfig("http://127.0.0.1:1", boot), io.Discard)
	<-entered

	resetDone := make(chan *httptest.ResponseRecorder)
	go func() {
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/reset", nil))
		resetDone <- response
	}()
	select {
	case <-resetDone:
		t.Fatal("reset returned while a bootstrap was in flight")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	response := <-resetDone
	if response.Code != http.StatusOK {
		t.Fatalf("POST /reset = %d %s", response.Code, response.Body.String())
	}
	var resetBody StateSnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &resetBody); err != nil || resetBody.State != StateIdle || historyOf(resetBody) != "idle/reset" {
		t.Fatalf("reset response = %s, want the post-reset idle state only", response.Body.String())
	}
	waitBootstrap(t, server)
	snapshot, _ := getState(t, server.Handler())
	want := "idle/reset registering/step_started presenting/step_started acquiring_token/step_started ready/step_completed"
	if boot.callCount() != 2 || snapshot.State != StateReady || historyOf(snapshot) != want {
		t.Fatalf("after reset: calls %d, state %+v; want history %s", boot.callCount(), snapshot, want)
	}
}

func TestResetTimesOutWhileBootstrapStillRuns(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	entered := make(chan struct{})
	t.Cleanup(func() { close(release) })
	boot := &fakeBootstrapper{runs: []runFunc{func(context.Context, func(State, string)) (TokenSession, error) {
		close(entered)
		<-release
		return nil, errors.New("stopped")
	}}}
	config := tokenConfig("http://127.0.0.1:1", boot)
	config.RequestTimeout = 20 * time.Millisecond
	server := newTokenParticipant(t, config, io.Discard)
	<-entered
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/reset", nil))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "reset_wait_timeout") {
		t.Fatalf("POST /reset = %d %s, want 503 reset_wait_timeout", response.Code, response.Body.String())
	}
}

// fakeVerifier injects a chosen Identity, or refuses with 401, in front of the real Resource handler.
type fakeVerifier struct {
	scopes []string
	refuse bool
	seen   chan http.Header
}

func (f fakeVerifier) Verify(*http.Request) (tokenverify.Identity, error) {
	if f.refuse {
		return tokenverify.Identity{}, tokenverify.ErrSignature
	}
	return tokenverify.Identity{ClientID: "client-participant", Subject: "client-participant", JKT: "jkt-1", Scopes: f.scopes}, nil
}

func (f fakeVerifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.seen != nil {
			f.seen <- r.Header.Clone()
		}
		identity, err := f.Verify(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(tokenverify.WithIdentity(r.Context(), identity)))
	})
}

func newTokenResource(t *testing.T, verifier tokenverify.RequestVerifier) *httptest.Server {
	t.Helper()
	config := protectedresource.Config{
		Address: ":0", RequestTimeout: time.Second, SlowDelay: time.Millisecond, Mode: "sample", AdapterMode: "sample",
		LogLevel: "info", Verifier: verifier,
	}
	server := httptest.NewServer(protectedresource.NewServer(config, slog.New(slog.NewJSONHandler(io.Discard, nil))).Handler())
	t.Cleanup(server.Close)
	return server
}

func readyParticipant(t *testing.T, resourceURL string, session TokenSession, logs io.Writer) *httptest.Server {
	t.Helper()
	server := newTokenParticipant(t, tokenConfig(resourceURL, &fakeBootstrapper{runs: []runFunc{succeed(session, true)}}), logs)
	waitBootstrap(t, server)
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)
	return httpServer
}

func TestTokenAdapterAuthorizesFreshlyPerRequest(t *testing.T) {
	t.Parallel()

	seen := make(chan http.Header, 3)
	resource := newTokenResource(t, fakeVerifier{scopes: []string{protectedresource.ScopeReportRead}, seen: seen})
	session := &countingSession{}
	participant := readyParticipant(t, resource.URL, session, io.Discard)

	authorizations := map[string]bool{}
	for i := 1; i <= 3; i++ {
		result, status := postDemo(t, participant, `{"resource":"sample-report","action":"read"}`)
		if status != http.StatusOK || result.ReasonCode != protectedresource.ReasonReportReturned || result.Mode != ModeToken {
			t.Fatalf("call %d = %d %+v", i, status, result)
		}
		header := <-seen
		authorizations[header.Get("Authorization")] = true
		if header.Get("DPoP") != fmt.Sprintf("proof-POST-%d", i) {
			t.Fatalf("call %d DPoP = %q, want a fresh proof", i, header.Get("DPoP"))
		}
	}
	if session.calls.Load() != 3 || len(authorizations) != 3 {
		t.Fatalf("Authorize calls = %d, distinct Authorization headers = %d; want 3 and 3", session.calls.Load(), len(authorizations))
	}
}

func TestTokenAdapterResourceStatusMapping(t *testing.T) {
	t.Parallel()

	statusResource := func(status int) string {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"error":"`+canaryToken+`"}`)
		}))
		t.Cleanup(server.Close)
		return server.URL
	}
	tests := []struct {
		name        string
		resourceURL string
		session     *countingSession
		status      int
		outcome     Outcome
		reasonCode  string
		dataKey     string
	}{
		{name: "401 is token rejected", resourceURL: statusResource(401), session: &countingSession{}, status: 403, outcome: OutcomeDenied, reasonCode: ReasonTokenRejected},
		{name: "403 is token forbidden", resourceURL: statusResource(403), session: &countingSession{}, status: 403, outcome: OutcomeDenied, reasonCode: ReasonTokenForbidden},
		{name: "503 is resource unavailable", resourceURL: statusResource(503), session: &countingSession{}, status: 503, outcome: OutcomeUnavailable, reasonCode: ReasonTokenResourceUnavailable},
		{name: "verifier refusal through the real resource is token rejected", resourceURL: newTokenResource(t, fakeVerifier{refuse: true}).URL, session: &countingSession{}, status: 403, outcome: OutcomeDenied, reasonCode: ReasonTokenRejected},
		{name: "insufficient scope through the real resource is token forbidden", resourceURL: newTokenResource(t, fakeVerifier{scopes: []string{"other"}}).URL, session: &countingSession{}, status: 403, outcome: OutcomeDenied, reasonCode: ReasonTokenForbidden},
		{name: "summary scope returns the summary", resourceURL: newTokenResource(t, fakeVerifier{scopes: []string{protectedresource.ScopeReportSummary}}).URL, session: &countingSession{}, status: 200, outcome: OutcomeSuccess, reasonCode: protectedresource.ReasonSummaryReturned, dataKey: "summary"},
		{name: "read scope returns the report", resourceURL: newTokenResource(t, fakeVerifier{scopes: []string{protectedresource.ScopeReportRead}}).URL, session: &countingSession{}, status: 200, outcome: OutcomeSuccess, reasonCode: protectedresource.ReasonReportReturned, dataKey: "report"},
		{name: "authorize failure never reaches the resource", resourceURL: statusResource(200), session: &countingSession{err: errors.New("signer said " + canaryToken)}, status: 502, outcome: OutcomeError, reasonCode: ReasonTokenAuthorizeFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			participant := readyParticipant(t, test.resourceURL, test.session, &logs)
			result, status := postDemo(t, participant, `{"resource":"sample-report","action":"read","requestId":"req-map"}`)
			assertDemoResultMode(t, result, status, test.status, test.outcome, test.reasonCode, ModeToken)
			if test.dataKey != "" {
				if _, ok := result.SafeData[test.dataKey].(map[string]any); !ok {
					t.Fatalf("safeData = %+v, want %s", result.SafeData, test.dataKey)
				}
			} else if len(result.SafeData) != 0 {
				t.Fatalf("refusal exposed data: %+v", result.SafeData)
			}
			raw, _ := json.Marshal(result)
			if strings.Contains(logs.String(), canaryToken) || strings.Contains(string(raw), canaryToken) {
				t.Fatalf("credential or upstream text leaked; logs %s body %s", logs.String(), raw)
			}
		})
	}
}

func TestTokenModeBeforeReadyIsUnavailable(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	boot := &fakeBootstrapper{runs: []runFunc{func(context.Context, func(State, string)) (TokenSession, error) {
		<-release
		return nil, errors.New("stopped")
	}}}
	server := newTokenParticipant(t, tokenConfig("http://127.0.0.1:1", boot), io.Discard)
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)
	result, status := postDemo(t, httpServer, `{"resource":"sample-report","action":"read"}`)
	assertDemoResultMode(t, result, status, http.StatusServiceUnavailable, OutcomeUnavailable, ReasonTokenSessionNotReady, ModeToken)
}

func TestFixedHooksGiveByteIdenticalRuns(t *testing.T) {
	t.Parallel()

	resource := newTokenResource(t, fakeVerifier{scopes: []string{protectedresource.ScopeReportSummary}})
	run := func() string {
		server := NewServer(tokenConfig(resource.URL, &fakeBootstrapper{runs: []runFunc{succeed(&countingSession{}, true)}}),
			slog.New(slog.NewJSONHandler(io.Discard, nil)))
		server.now = func() time.Time { return time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC) }
		counter := 0
		server.newID = func() string { counter++; return fmt.Sprintf("fixed-%d", counter) }
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		server.Start(ctx)
		waitBootstrap(t, server)

		var out strings.Builder
		do := func(method, path, body string) {
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, httptest.NewRequest(method, path, strings.NewReader(body)))
			fmt.Fprintf(&out, "%d %s\n", response.Code, response.Body.String())
		}
		do(http.MethodGet, "/health", "")
		do(http.MethodGet, "/state", "")
		do(http.MethodPost, "/demo", `{"resource":"sample-report","action":"read"}`)
		do(http.MethodPost, "/demo", `{"resource":"other","action":"read"}`)
		do(http.MethodPost, "/reset", "")
		waitBootstrap(t, server)
		do(http.MethodGet, "/state", "")
		do(http.MethodPost, "/demo", `{"resource":"sample-report","action":"read"}`)
		return out.String()
	}
	first, second := run(), run()
	if first != second {
		t.Fatalf("runs differ:\n%s\n%s", first, second)
	}
	if !strings.Contains(first, "fixed-1") || !strings.Contains(first, "2026-10-21T09:00:00Z") {
		t.Fatalf("run did not use the hooks: %s", first)
	}
}

func assertDemoResultMode(t *testing.T, result DemoResponse, gotStatus, wantStatus int, outcome Outcome, reasonCode, mode string) {
	t.Helper()
	if gotStatus != wantStatus || result.Outcome != outcome || result.ReasonCode != reasonCode || result.Mode != mode {
		t.Fatalf("result = %d %q %q %q; want %d %q %q %q", gotStatus, result.Outcome, result.ReasonCode, result.Mode, wantStatus, outcome, reasonCode, mode)
	}
	if result.RequestID == "" || result.Explanation == "" || result.Timestamp.IsZero() || result.SafeData == nil {
		t.Fatalf("response contract incomplete: %+v", result)
	}
}

func TestTokenModeIgnoresInjectedSampleAdapter(t *testing.T) {
	t.Parallel()

	resource := newTokenResource(t, fakeVerifier{scopes: []string{protectedresource.ScopeReportRead}})
	session := &countingSession{}
	config := tokenConfig(resource.URL, &fakeBootstrapper{runs: []runFunc{succeed(session, true)}})
	server := NewServerWithAdapter(config, slog.New(slog.NewJSONHandler(io.Discard, nil)), NewSampleAdapter())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	server.Start(ctx)
	waitBootstrap(t, server)
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)

	for i, body := range []string{
		`{"resource":"sample-report","action":"read","scenario":"success"}`,
		`{"resource":"sample-report","action":"read"}`,
	} {
		result, status := postDemo(t, httpServer, body)
		if result.ReasonCode == ReasonSampleGranted || result.Mode != ModeToken {
			t.Fatalf("token-mode Participant answered from the sample adapter: %d %+v", status, result)
		}
		assertDemoResultMode(t, result, status, http.StatusOK, OutcomeSuccess, protectedresource.ReasonReportReturned, ModeToken)
		if got := session.calls.Load(); got != int32(i+1) {
			t.Fatalf("Authorize calls = %d after %d requests", got, i+1)
		}
	}
}

// echoResource answers with a contract-shaped token-mode body whose text fields come from echo, which
// sees the request's own credential headers.
func echoResource(t *testing.T, status int, outcome Outcome, reason string, echo func(*http.Request) (explanation, content string)) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input DemoRequest
		_ = json.NewDecoder(r.Body).Decode(&input)
		explanation, content := echo(r)
		safeData := map[string]any{}
		if outcome == OutcomeSuccess {
			safeData = map[string]any{"resource": "sample-report", "action": "read",
				"report": map[string]any{"id": "FACIS-SAMPLE-REPORT-001", "title": "Sample report", "content": content}}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"requestId": input.RequestID, "correlationId": input.CorrelationID, "source": "sample", "mode": "token",
			"outcome": outcome, "reasonCode": reason, "explanation": explanation,
			"timestamp": "2026-10-21T09:00:00Z", "safeData": safeData,
		})
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func TestTokenAdapterDiscardsEchoedCredentialsAndUpstreamText(t *testing.T) {
	t.Parallel()

	const upstreamText = "upstream-detail-must-not-be-forwarded"
	bareToken := func(r *http.Request) string {
		_, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		return token
	}
	tests := []struct {
		name       string
		url        string
		status     int
		outcome    Outcome
		reasonCode string
	}{
		{name: "400 echoing the Authorization value", url: echoResource(t, 400, OutcomeError, "SAMPLE_INVALID_REQUEST", func(r *http.Request) (string, string) {
			return "bad request for " + r.Header.Get("Authorization"), ""
		}), status: 502, outcome: OutcomeError, reasonCode: ReasonTokenCredentialEchoed},
		{name: "500 echoing the DPoP proof", url: echoResource(t, 500, OutcomeError, "SAMPLE_ADAPTER_FAILURE", func(r *http.Request) (string, string) {
			return "failed with proof " + r.Header.Get("DPoP"), ""
		}), status: 502, outcome: OutcomeError, reasonCode: ReasonTokenCredentialEchoed},
		{name: "200 echoing the bare token in report data", url: echoResource(t, 200, OutcomeSuccess, "RESOURCE_REPORT_RETURNED", func(r *http.Request) (string, string) {
			return "ok", "token was " + bareToken(r)
		}), status: 502, outcome: OutcomeError, reasonCode: ReasonTokenCredentialEchoed},
		{name: "200 hiding the token behind a JSON escape", url: echoResource(t, 200, OutcomeSuccess, "RESOURCE_REPORT_RETURNED", func(r *http.Request) (string, string) {
			return "ok", "<" + bareToken(r) + ">" // encoding/json writes < as \u003c, so only decoded strings show the token
		}), status: 502, outcome: OutcomeError, reasonCode: ReasonTokenCredentialEchoed},
		{name: "400 upstream explanation is replaced locally", url: echoResource(t, 400, OutcomeError, "SAMPLE_INVALID_REQUEST", func(*http.Request) (string, string) {
			return upstreamText, ""
		}), status: 502, outcome: OutcomeError, reasonCode: "SAMPLE_INVALID_REQUEST"},
		{name: "200 upstream explanation is replaced locally", url: echoResource(t, 200, OutcomeSuccess, "RESOURCE_REPORT_RETURNED", func(*http.Request) (string, string) {
			return upstreamText, "Local sample data."
		}), status: 200, outcome: OutcomeSuccess, reasonCode: "RESOURCE_REPORT_RETURNED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			participant := readyParticipant(t, test.url, &countingSession{}, &logs)
			result, status := postDemo(t, participant, `{"resource":"sample-report","action":"read","requestId":"req-echo"}`)
			assertDemoResultMode(t, result, status, test.status, test.outcome, test.reasonCode, ModeToken)
			raw, _ := json.Marshal(result)
			for _, leak := range []string{canaryToken, "proof-POST", upstreamText} {
				if strings.Contains(string(raw), leak) || strings.Contains(logs.String(), leak) {
					t.Fatalf("%q forwarded; body %s logs %s", leak, raw, logs.String())
				}
			}
		})
	}
}

func TestCancelledResetReturnsWithoutMutating(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	entered := make(chan struct{})
	session := &countingSession{}
	boot := &fakeBootstrapper{runs: []runFunc{
		func(_ context.Context, report func(State, string)) (TokenSession, error) {
			report(StateRegistering, TransitionStepStarted)
			close(entered)
			<-release
			return session, nil
		},
		succeed(session, true),
	}}
	server := newTokenParticipant(t, tokenConfig("http://127.0.0.1:1", boot), io.Discard)
	<-entered
	before := server.lifecycle.snapshot(ModeToken)

	// Already cancelled, uncontended: no state is cleared and the running bootstrap keeps its retries.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := server.lifecycle.reset(cancelled, ModeToken); err == nil {
		t.Fatal("cancelled reset succeeded")
	}
	server.lifecycle.mu.Lock()
	stopIntact := server.lifecycle.stop != nil
	server.lifecycle.mu.Unlock()
	if !stopIntact {
		t.Fatal("cancelled reset stopped the bootstrap")
	}

	// A first reset waits on the in-flight run and holds the slot; a second one queues behind it.
	firstDone := make(chan error, 1)
	go func() {
		_, err := server.lifecycle.reset(context.Background(), ModeToken)
		firstDone <- err
	}()
	for {
		server.lifecycle.mu.Lock()
		closed := server.lifecycle.stop == nil
		server.lifecycle.mu.Unlock()
		if closed {
			break
		}
		time.Sleep(time.Millisecond)
	}
	queued, cancelQueued := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelQueued()
	start := time.Now()
	if _, err := server.lifecycle.reset(queued, ModeToken); err == nil {
		t.Fatal("queued reset succeeded while another held the slot")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("queued reset took %s after cancellation", elapsed)
	}
	if after := server.lifecycle.snapshot(ModeToken); historyOf(after) != historyOf(before) {
		t.Fatalf("cancelled resets changed history: %s -> %s", historyOf(before), historyOf(after))
	}

	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first reset: %v", err)
	}
	waitBootstrap(t, server)
	if got := historyOf(server.lifecycle.snapshot(ModeToken)); !strings.HasPrefix(got, "idle/reset ") {
		t.Fatalf("history after the admitted reset = %s", got)
	}
}

func TestResetAtRetryBoundaryNeverStartsExtraRun(t *testing.T) {
	t.Parallel()

	// The reset's stop signal arrives while a connector-unreachable Run is in flight. When that Run
	// returns, a retry is due after 1ns, so the elapsed timer and the closed stop are both ready; the
	// lifecycle must still not start a second Run. Repeated because a select between ready channels is
	// random.
	for i := 0; i < 50; i++ {
		var l *lifecycle
		boot := &fakeBootstrapper{runs: []runFunc{func(_ context.Context, report func(State, string)) (TokenSession, error) {
			l.mu.Lock()
			if l.stop != nil {
				close(l.stop) // exactly what reset does, under the same lock
				l.stop = nil
			}
			l.mu.Unlock()
			report(StateFailedConnector, TransitionConnectorUnreachable)
			return nil, errors.New("unreachable")
		}}}
		l = newLifecycle(boot, 1000, time.Nanosecond, time.Now, slog.New(slog.NewJSONHandler(io.Discard, nil)))
		l.start(context.Background())
		l.mu.Lock()
		done := l.done
		l.mu.Unlock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("lifecycle kept retrying after stop")
		}
		if calls := boot.callCount(); calls != 1 {
			t.Fatalf("iteration %d: %d Runs, want 1", i, calls)
		}
	}
}

// rawResource answers 200 with the exact body body builds, which sees the request's credential headers.
func rawResource(t *testing.T, body func(*http.Request) string) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body(r))
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func unicodeEscaped(value string) string {
	var out strings.Builder
	for _, r := range value {
		fmt.Fprintf(&out, `\u%04x`, r)
	}
	return out.String()
}

func tokenBody(safeData string) string {
	return `{"requestId":"req-strict","correlationId":"req-strict","source":"sample","mode":"token","outcome":"success",` +
		`"reasonCode":"RESOURCE_REPORT_RETURNED","explanation":"ok","timestamp":"2026-10-21T09:00:00Z","safeData":` + safeData + `}`
}

func reportData(id, title, content string) string {
	return `{"resource":"sample-report","action":"read","report":{"id":"` + id + `","title":"` + title + `","content":"` + content + `"}}`
}

func TestTokenAdapterRefusesAmbiguousOrFreeFormSuccessBodies(t *testing.T) {
	t.Parallel()

	bareToken := func(r *http.Request) string {
		_, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		return token
	}
	tests := []struct {
		name       string
		body       func(*http.Request) string
		reasonCode string
	}{
		{
			// Decoding into any keeps the last safeData ({}), the struct decode keeps the first; the
			// escaped canary is invisible to a raw byte match.
			name: "duplicate top-level safeData hiding an escaped canary",
			body: func(r *http.Request) string {
				body := tokenBody(reportData("FACIS-SAMPLE-REPORT-001", "Sample report", unicodeEscaped(bareToken(r))))
				return strings.TrimSuffix(body, "}") + `,"safeData":{}}`
			},
			reasonCode: ReasonTokenDuplicateMember,
		},
		{
			name: "duplicate member nested in the report",
			body: func(*http.Request) string {
				return tokenBody(`{"resource":"sample-report","action":"read","report":{"id":"A","title":"T","content":"C","id":"B"}}`)
			},
			reasonCode: ReasonTokenDuplicateMember,
		},
		{
			name: "duplicate member inside an array element",
			body: func(*http.Request) string {
				return strings.TrimSuffix(tokenBody(reportData("FACIS-SAMPLE-REPORT-001", "Sample report", "Local sample data.")), "}") +
					`,"extra":[{"k":1,"k":2}]}`
			},
			reasonCode: ReasonTokenDuplicateMember,
		},
		{
			name: "unknown key in report data",
			body: func(*http.Request) string {
				return tokenBody(`{"resource":"sample-report","action":"read","report":{"id":"FACIS-SAMPLE-REPORT-001","title":"T","content":"C","note":"x"}}`)
			},
			reasonCode: ReasonTokenResourceInvalid,
		},
		{
			name: "unknown key beside report data",
			body: func(*http.Request) string {
				return tokenBody(`{"resource":"sample-report","action":"read","report":{"id":"FACIS-SAMPLE-REPORT-001","title":"T","content":"C"},"note":"x"}`)
			},
			reasonCode: ReasonTokenResourceInvalid,
		},
		{
			name: "base64 of the token in a known field",
			body: func(r *http.Request) string {
				return tokenBody(reportData("FACIS-SAMPLE-REPORT-001", "Sample report", "data "+base64.StdEncoding.EncodeToString([]byte(bareToken(r)))))
			},
			reasonCode: ReasonTokenCredentialEchoed,
		},
		{
			name: "base64url of the DPoP proof in a known field",
			body: func(r *http.Request) string {
				return tokenBody(reportData("FACIS-SAMPLE-REPORT-001", "Sample report", base64.RawURLEncoding.EncodeToString([]byte(r.Header.Get("DPoP")))))
			},
			reasonCode: ReasonTokenCredentialEchoed,
		},
		{
			name: "long unbroken word in a known field",
			body: func(*http.Request) string {
				return tokenBody(reportData("FACIS-SAMPLE-REPORT-001", "Sample report", "data "+strings.Repeat("QUJD", 9)))
			},
			reasonCode: ReasonTokenResourceInvalid,
		},
		{
			name: "id outside the seed alphabet",
			body: func(*http.Request) string {
				return tokenBody(reportData("facis.sample/001", "Sample report", "Local sample data."))
			},
			reasonCode: ReasonTokenResourceInvalid,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			participant := readyParticipant(t, rawResource(t, test.body), &countingSession{}, &logs)
			result, status := postDemo(t, participant, `{"resource":"sample-report","action":"read","requestId":"req-strict"}`)
			assertDemoResultMode(t, result, status, http.StatusBadGateway, OutcomeError, test.reasonCode, ModeToken)
			raw, _ := json.Marshal(result)
			for _, leak := range []string{canaryToken, "proof-POST"} {
				if strings.Contains(string(raw), leak) || strings.Contains(logs.String(), leak) {
					t.Fatalf("%q forwarded; body %s logs %s", leak, raw, logs.String())
				}
			}
			if len(result.SafeData) != 0 {
				t.Fatalf("refused answer forwarded data: %+v", result.SafeData)
			}
		})
	}

	t.Run("documented seed shape is still accepted", func(t *testing.T) {
		t.Parallel()
		participant := readyParticipant(t, rawResource(t, func(*http.Request) string {
			return tokenBody(reportData("FACIS-SAMPLE-REPORT-001", "FACIS deterministic sample report", "Local sample data for F04 / WP09 / ZT-75 testing only."))
		}), &countingSession{}, io.Discard)
		result, status := postDemo(t, participant, `{"resource":"sample-report","action":"read","requestId":"req-strict"}`)
		assertDemoResultMode(t, result, status, http.StatusOK, OutcomeSuccess, "RESOURCE_REPORT_RETURNED", ModeToken)
	})
}

func TestHasDuplicateMembers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		raw       string
		duplicate bool
		invalid   bool
	}{
		{name: "flat unique", raw: `{"a":1,"b":{"a":2}}`},
		{name: "same name in sibling objects", raw: `[{"a":1},{"a":2}]`},
		{name: "string value equal to a later key", raw: `{"a":"b","b":1}`},
		{name: "top-level duplicate", raw: `{"a":1,"a":2}`, duplicate: true},
		{name: "escaped duplicate", raw: `{"a":1,"a":2}`, duplicate: true},
		{name: "deep duplicate after nested values", raw: `{"x":{"y":[1,{"z":[]}],"y":0}}`, duplicate: true},
		{name: "malformed", raw: `{"a":`, invalid: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			duplicate, err := hasDuplicateMembers([]byte(test.raw))
			if duplicate != test.duplicate || (err != nil) != test.invalid {
				t.Fatalf("hasDuplicateMembers(%s) = %v, %v", test.raw, duplicate, err)
			}
		})
	}
}
