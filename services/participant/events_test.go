package participant

import (
	"bytes"
	"context"
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
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/protectedresource"
)

func TestRequestEventsReachFeed(t *testing.T) {
	var lines bytes.Buffer
	cfg := Config{RequestTimeout: defaultRequestTimeout, AdapterMode: "sample"}
	var err error
	cfg.Events, err = appevents.New(&lines, "participant-a")
	if err != nil {
		t.Fatal(err)
	}
	app := NewServer(cfg, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	for _, scenario := range []string{"success", "denied", "unavailable", "error"} {
		request := httptest.NewRequest(http.MethodPost, "/demo", strings.NewReader(`{"resource":"sample-report","action":"read","scenario":"`+scenario+`","correlationId":"`+scenario+`"}`))
		response := httptest.NewRecorder()
		app.Handler().ServeHTTP(response, request)
	}
	app.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/demo", strings.NewReader(`{`)))
	app.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/state", nil))
	events := appfeedtest.RoundTrip(t, "../../docs/contracts", lines.String())
	// A /state read publishes nothing: polling must not push real events out of the feed's buffer.
	if len(events) != 5 {
		t.Fatalf("got %d events, want 5", len(events))
	}
	for i, state := range []string{"success", "denied", "unavailable", "error", "error"} {
		if events[i].Payload.State != state {
			t.Fatalf("event %d: %+v", i, events[i])
		}
	}
	if events[1].Payload.ReasonCode != "APP-SAMPLE-ACCESS-DENIED" || events[1].CorrelationID != "denied" {
		t.Fatal("denial lost reason/correlation")
	}
}

func TestRegistrationTransitionsReachFeed(t *testing.T) {
	var lines bytes.Buffer
	cfg := Config{}
	var err error
	cfg.Events, err = appevents.New(&lines, "participant-a")
	if err != nil {
		t.Fatal(err)
	}
	app := NewServer(cfg, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	// Drive the same lifecycle reporter the Connector bootstrap calls; no credentials enter events.
	for _, state := range []State{StateRegistering, StateRegistered, StateReady, StateFailedRegister} {
		app.lifecycle.report(state, TransitionStepCompleted)
	}
	app.lifecycle.report(StateFailedRegister, "canary-client-secret")
	_, err = app.lifecycle.reset(context.Background(), ModeToken)
	if err != nil {
		t.Fatal(err)
	}
	events := appfeedtest.RoundTrip(t, "../../docs/contracts", lines.String())
	if len(events) != 6 {
		t.Fatalf("got %d transitions", len(events))
	}
	for i, detail := range []string{"registration", "registration", "status", "registration", "registration", "status"} {
		if events[i].Payload.Detail != detail {
			t.Fatalf("transition %d not published", i)
		}
	}
	if events[4].Payload.ReasonCode != "APP-UNSPECIFIED" || strings.Contains(lines.String(), "canary-client-secret") {
		t.Fatal("unknown reason leaked")
	}
}

// handlerTransport exercises the HTTP handler without a listening socket.
type handlerTransport struct{ handler http.Handler }

func (h handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response := httptest.NewRecorder()
	h.handler.ServeHTTP(response, r)
	return response.Result(), nil
}

func TestTokenRefusalKeepsCorrelationInFeed(t *testing.T) {
	verifier, err := tokenverify.New(tokenverify.Config{Issuer: "https://issuer.example", JWKSURL: "https://issuer.example/jwks", Audience: "resource", PublicBaseURL: "https://resource.example", Replay: replay.NewMemory()})
	if err != nil {
		t.Fatal(err)
	}
	var lines bytes.Buffer
	sink, err := appevents.New(&lines, "protected-resource-b")
	if err != nil {
		t.Fatal(err)
	}
	resource := protectedresource.NewServer(protectedresource.Config{Verifier: verifier, Events: sink}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	adapter := NewTokenAdapter("https://resource.example", &http.Client{Transport: handlerTransport{resource.Handler()}}, func() TokenSession { return &countingSession{} })
	result, err := adapter.Request(t.Context(), AdapterRequest{RequestID: "request-1", CorrelationID: "correlation-1", Resource: "sample-report", Action: "read"})
	if err != nil || result.Outcome != OutcomeDenied || result.ReasonCode != ReasonTokenRejected {
		t.Fatal("malformed token did not fail closed")
	}
	events := appfeedtest.RoundTrip(t, "../../docs/contracts", lines.String())
	if len(events) != 1 || events[0].CorrelationID != "correlation-1" || events[0].Payload.State != "denied" || events[0].Payload.ReasonCode != "APP-TOKEN-MALFORMED" {
		t.Fatalf("verifier refusal lost correlation/reason: %+v", events)
	}
}
