// Command trace-echo is a proof-only HTTP echo service instrumented with the OpenTelemetry Go SDK.
// It extracts the W3C traceparent of each request, emits one server span as the child of the
// caller's span (in the mesh, the span of its own proxy), and answers with the trace id it joined.
// scripts/verify-observability/verify.sh runs it behind a mesh proxy to prove that one trace holds
// the proxy's span and the service's span (the check correlated-trace). It is never part of a zone.
//
// Configuration is the SDK's standard environment: OTEL_EXPORTER_OTLP_ENDPOINT (or
// OTEL_EXPORTER_OTLP_TRACES_ENDPOINT) for the OTLP/HTTP exporter, OTEL_SERVICE_NAME for the service.
// LISTEN_ADDR sets the listen address (default :8080). SERVE_FILE=<url path>=<file> turns it into the
// proof's static server of a fixture (the revocation status list): that path answers the file, every
// other path 404, and no span is emitted.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return err
	}
	res, err := resource.Merge(resource.Default(), resource.Environment())
	if err != nil {
		return err
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(time.Second)),
	)
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := provider.Shutdown(shutdownCtx); err != nil {
			log.Printf("trace-echo: shutdown: %v", err)
		}
	}()

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	handler := newHandler(provider, propagation.TraceContext{})
	if spec := os.Getenv("SERVE_FILE"); spec != "" {
		if handler, err = newFileHandler(spec); err != nil {
			return err
		}
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	otel.SetTracerProvider(provider)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	log.Printf("trace-echo: listening on %s", addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
