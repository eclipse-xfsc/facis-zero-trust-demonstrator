package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestEchoJoinsTheCallersTrace(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	handler := newHandler(provider, propagation.TraceContext{})

	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	const parentID = "00f067aa0ba902b7"
	req := httptest.NewRequest(http.MethodGet, "/hello", nil)
	req.Header.Set("traceparent", "00-"+traceID+"-"+parentID+"-01")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("want one span, got %d", len(spans))
	}
	span := spans[0]
	if got := span.SpanContext().TraceID().String(); got != traceID {
		t.Errorf("span trace id %s, want the caller's %s", got, traceID)
	}
	if got := span.Parent().SpanID().String(); got != parentID {
		t.Errorf("span parent %s, want the caller's span %s", got, parentID)
	}
	if !span.Parent().IsRemote() {
		t.Error("the parent should be the remote caller's span")
	}
	if span.SpanKind() != trace.SpanKindServer {
		t.Errorf("span kind %v, want server", span.SpanKind())
	}
	var body echoResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.TraceID != traceID || body.SpanID != span.SpanContext().SpanID().String() || body.Path != "/hello" {
		t.Errorf("response %+v does not name the span", body)
	}
	if got := rec.Header().Get("traceparent"); got != "00-"+traceID+"-"+body.SpanID+"-01" {
		t.Errorf("response traceparent %q does not carry the echo's span", got)
	}
}

func TestEchoStartsATraceWithoutTraceparent(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	rec := httptest.NewRecorder()
	newHandler(provider, propagation.TraceContext{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	spans := recorder.Ended()
	if len(spans) != 1 || spans[0].Parent().IsValid() {
		t.Fatalf("want one root span, got %d spans", len(spans))
	}
}
