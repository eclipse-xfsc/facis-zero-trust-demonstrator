package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/testsupport"
)

func word(w string) func(context.Context) string {
	return func(context.Context) string { return w }
}

func TestReadinessEvaluate(t *testing.T) {
	cases := []struct {
		name       string
		postgres   string
		openbao    string
		signingKey string
		ready      bool
	}{
		{"all ok", checkOK, checkOK, checkOK, true},
		{"database unreachable", checkUnreachable, checkOK, checkOK, false},
		{"schema behind", checkSchemaBehind, checkOK, checkOK, false},
		{"schema drift", checkSchemaDrift, checkOK, checkOK, false},
		{"key-value store unreachable", checkOK, checkUnreachable, checkOK, false},
		{"key-value store sealed", checkOK, checkSealed, checkOK, false},
		{"key-value store uninitialised", checkOK, checkUninitialized, checkOK, false},
		{"signing key missing", checkOK, checkOK, checkMissing, false},
		{"signing key mismatch", checkOK, checkOK, checkMismatch, false},
		{"signing key unconfigured", checkOK, checkOK, checkUnconfigured, false},
		{"both down", checkUnreachable, checkUnreachable, checkUnreachable, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &readiness{timeout: time.Second, postgres: word(tc.postgres), openbao: word(tc.openbao), signingKey: word(tc.signingKey)}
			rep := r.evaluate(context.Background())
			if rep.Ready != tc.ready || rep.Checks.Postgres != tc.postgres || rep.Checks.OpenBao != tc.openbao ||
				rep.Checks.SigningKey != tc.signingKey {
				t.Errorf("report %+v", rep)
			}
		})
	}
}

// Each check waits for the other to have started before it answers: run one after the other,
// the first would wait for a second that never starts and time out as unreachable.
func TestReadinessRunsTheChecksTogether(t *testing.T) {
	postgresStarted := make(chan struct{})
	openbaoStarted := make(chan struct{})
	meet := func(mine, other chan struct{}) func(context.Context) string {
		return func(ctx context.Context) string {
			close(mine)
			select {
			case <-other:
				return checkOK
			case <-ctx.Done():
				return checkUnreachable
			}
		}
	}
	r := &readiness{
		timeout:    2 * time.Second,
		postgres:   meet(postgresStarted, openbaoStarted),
		openbao:    meet(openbaoStarted, postgresStarted),
		signingKey: word(checkOK),
	}
	if rep := r.evaluate(context.Background()); !rep.Ready {
		t.Errorf("the checks did not run at once: %+v", rep)
	}
}

func TestReadinessNeverOutlivesItsBudget(t *testing.T) {
	// A check that ignores its context and sleeps past the budget.
	stuck := func(context.Context) string {
		time.Sleep(time.Second)
		return checkOK
	}
	r := &readiness{timeout: 200 * time.Millisecond, postgres: stuck, openbao: word(checkOK), signingKey: word(checkOK)}
	start := time.Now()
	rep := r.evaluate(context.Background())
	if elapsed := time.Since(start); elapsed > 800*time.Millisecond {
		t.Errorf("the evaluation took %v with a 200ms budget", elapsed)
	}
	if rep.Ready || rep.Checks.Postgres != checkUnreachable || rep.Checks.OpenBao != checkOK {
		t.Errorf("report %+v", rep)
	}
}

func TestReadyzHandler(t *testing.T) {
	var buf testsupport.Buffer
	s := &Server{log: testLogger(&buf)}
	s.ready = &readiness{timeout: time.Second, postgres: word(checkOK), openbao: word(checkSealed), signingKey: word(checkOK)}
	h := s.correlate(http.HandlerFunc(s.handleReadyz))

	get := func() (*http.Response, report) {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		resp := rec.Result()
		var rep report
		if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
			t.Fatalf("body is not a report: %v", err)
		}
		return resp, rep
	}

	resp, rep := get()
	if resp.StatusCode != http.StatusServiceUnavailable || rep.Ready || rep.Checks.OpenBao != checkSealed {
		t.Errorf("sealed key-value store: %d %+v", resp.StatusCode, rep)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content type %q", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("cache control %q", cc)
	}
	get() // the same outcome again: no second transition record
	s.ready.openbao = word(checkOK)
	resp, rep = get()
	if resp.StatusCode != http.StatusOK || !rep.Ready {
		t.Errorf("all ok: %d %+v", resp.StatusCode, rep)
	}

	var transitions []string
	for _, r := range records(t, &buf) {
		if msg, _ := r["msg"].(string); msg == "ready" || msg == "not ready" {
			transitions = append(transitions, msg)
			if r["correlation_id"] == nil {
				t.Errorf("transition record %q has no correlation_id", msg)
			}
		}
	}
	if strings.Join(transitions, ",") != "not ready,ready" {
		t.Errorf("transitions %v, want one 'not ready' then one 'ready'", transitions)
	}
}

// A caller that is gone before the evaluation ends gets the cut-off words, but they are not the
// dependencies' state and record no transition; draining answers 503 and records none either.
func TestReadyzRecordsNoPhantomTransition(t *testing.T) {
	var buf testsupport.Buffer
	s := &Server{log: testLogger(&buf)}
	s.ready = &readiness{timeout: time.Second, postgres: word(checkOK), openbao: word(checkOK), signingKey: word(checkOK)}
	h := s.correlate(http.HandlerFunc(s.handleReadyz))
	transitions := func() int {
		n := 0
		for _, r := range records(t, &buf) {
			if msg, _ := r["msg"].(string); msg == "ready" || msg == "not ready" {
				n++
			}
		}
		return n
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK || transitions() != 1 {
		t.Fatalf("first evaluation: %d, %d transitions", rec.Code, transitions())
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil).WithContext(cancelled))
	if transitions() != 1 {
		t.Errorf("a cancelled request recorded a transition")
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK || transitions() != 1 {
		t.Errorf("after the cancelled request: %d, %d transitions, want 200 and still 1", rec.Code, transitions())
	}

	s.ready.drain()
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	var rep report
	if err := json.NewDecoder(rec.Body).Decode(&rep); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusServiceUnavailable || rep.Ready || !rep.Draining || rep.Checks != nil {
		t.Errorf("draining: %d %+v (the dependencies must not be asked)", rec.Code, rep)
	}
	if transitions() != 1 {
		t.Errorf("draining recorded a transition")
	}
}

// Callers that arrive while an evaluation runs share it: the checks run once for all of them, and
// a caller that goes away does not cancel what the others wait for.
func TestReadinessCoalescesConcurrentCallers(t *testing.T) {
	var calls atomic.Int32
	var sawCancelled atomic.Bool
	slow := func(ctx context.Context) string {
		calls.Add(1)
		if ctx.Err() != nil {
			sawCancelled.Store(true)
		}
		time.Sleep(150 * time.Millisecond)
		return checkOK
	}
	r := &readiness{timeout: 2 * time.Second, postgres: slow, openbao: slow, signingKey: word(checkOK)}

	gone, cancel := context.WithCancel(context.Background())
	cancel()
	if rep := r.evaluate(gone); rep.Ready || rep.Checks == nil || rep.Checks.Postgres != checkUnreachable {
		t.Errorf("a caller that is gone learnt something: %+v", rep)
	}

	const callers = 8
	results := make(chan report, callers)
	for range callers {
		go func() { results <- r.evaluate(context.Background()) }()
	}
	for range callers {
		if rep := <-results; !rep.Ready {
			t.Errorf("a sharing caller got %+v", rep)
		}
	}
	// The gone caller's evaluation and the burst's: at most one run each, two checks per run.
	if n := calls.Load(); n > 4 {
		t.Errorf("the checks ran %d times for 9 callers; they should have been shared", n)
	}
	if sawCancelled.Load() {
		t.Error("a check ran under the gone caller's cancelled context")
	}
}

func TestHealthzIsAlwaysAlive(t *testing.T) {
	var buf testsupport.Buffer
	s := &Server{log: testLogger(&buf)}
	rec := httptest.NewRecorder()
	s.correlate(http.HandlerFunc(s.handleHealthz)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("healthz %d", rec.Code)
	}
}
