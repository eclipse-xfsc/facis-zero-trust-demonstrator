package main

import (
	"encoding/json"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// echoResponse is what the echo answers: the trace and span it emitted, and the request's path.
type echoResponse struct {
	TraceID string `json:"trace_id"`
	SpanID  string `json:"span_id"`
	Path    string `json:"path"`
}

// newHandler answers every request with one server span, the child of the span named by the
// request's traceparent header (a new trace when there is none).
func newHandler(provider trace.TracerProvider, propagator propagation.TextMapPropagator) http.Handler {
	tracer := provider.Tracer("github.com/eclipse-xfsc/facis-zero-trust-demonstrator/tools/trace-echo")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := tracer.Start(ctx, "echo "+r.Method,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("http.request.method", r.Method),
				attribute.String("url.path", r.URL.Path),
			))
		defer span.End()
		propagator.Inject(ctx, propagation.HeaderCarrier(w.Header()))
		sc := span.SpanContext()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(echoResponse{
			TraceID: sc.TraceID().String(),
			SpanID:  sc.SpanID().String(),
			Path:    r.URL.Path,
		})
	})
}
