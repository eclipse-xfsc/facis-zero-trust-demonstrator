package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
)

// The headers a request carries its identifiers in. x-request-id is minted by the guard for a
// request from outside the mesh and carried unchanged by every component after it; it is the
// correlation id of the events and logs of that request. traceparent and tracestate are the W3C
// trace context the mesh's spans are keyed by, passed through untouched.
const (
	headerRequestID   = "X-Request-Id"
	headerTraceparent = "Traceparent"
	headerTracestate  = "Tracestate"
)

// requestFields are the identifiers of one request, carried in its context so every log record
// written while handling it names them and every call made on its behalf forwards them.
type requestFields struct {
	correlationID string
	traceID       string
	spanID        string
	traceparent   string
	tracestate    string
}

type fieldsKey struct{}

func withFields(ctx context.Context, f requestFields) context.Context {
	return context.WithValue(ctx, fieldsKey{}, f)
}

func fieldsFrom(ctx context.Context) (requestFields, bool) {
	f, ok := ctx.Value(fieldsKey{}).(requestFields)
	return f, ok
}

// outbound returns the headers a call made on behalf of this request forwards unchanged. The
// trace state travels only with the trace context it belongs to.
func (f requestFields) outbound() http.Header {
	h := http.Header{}
	if f.correlationID != "" {
		h.Set(headerRequestID, f.correlationID)
	}
	if f.traceparent != "" {
		h.Set(headerTraceparent, f.traceparent)
		if f.tracestate != "" {
			h.Set(headerTracestate, f.tracestate)
		}
	}
	return h
}

// attrs are the identifiers as log attributes: always the correlation id, the trace context when
// the caller passed one.
func (f requestFields) attrs() []slog.Attr {
	out := []slog.Attr{slog.String("correlation_id", f.correlationID)}
	if f.traceID != "" {
		out = append(out, slog.String("trace_id", f.traceID), slog.String("span_id", f.spanID))
	}
	return out
}

// correlationID keeps the caller's x-request-id when it is 1 to 128 bytes of visible ASCII, the
// bounds the contract puts on a correlation id, and mints one otherwise: a request that arrives
// without one, as the kubelet's probes do, still has an id its records join on.
func correlationID(header string) string {
	if n := len(header); n >= 1 && n <= 128 && visibleASCII(header) {
		return header
	}
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func visibleASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// parseTraceparent reads a W3C traceparent, version-traceid-parentid-flags in lowercase hex, and
// returns the trace id and the parent's span id. A version of ff, an all-zero trace or parent id
// and any other shape are ignored; a version above 00 is read on its first four fields, as the
// specification asks of a reader that wants to stay compatible.
func parseTraceparent(header string) (traceID, spanID string, ok bool) {
	parts := strings.Split(header, "-")
	if len(parts) < 4 || len(parts[0]) != 2 || len(parts[1]) != 32 || len(parts[2]) != 16 || len(parts[3]) != 2 {
		return "", "", false
	}
	for _, p := range parts[:4] {
		if !lowerHex(p) {
			return "", "", false
		}
	}
	if parts[0] == "ff" || (parts[0] == "00" && len(parts) != 4) {
		return "", "", false
	}
	if allZero(parts[1]) || allZero(parts[2]) {
		return "", "", false
	}
	return parts[1], parts[2], true
}

func lowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func allZero(s string) bool { return strings.Trim(s, "0") == "" }

// correlate wraps a handler so every request carries its identifiers in its context, answers with
// its x-request-id, and ends with one record naming the method, the path, the status and the
// duration, so a request that logs nothing else still leaves a correlated line.
func (s *Server) correlate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		f := requestFields{correlationID: correlationID(r.Header.Get(headerRequestID))}
		if tp := r.Header.Get(headerTraceparent); tp != "" {
			if traceID, spanID, ok := parseTraceparent(tp); ok {
				f.traceID, f.spanID, f.traceparent = traceID, spanID, tp
				f.tracestate = r.Header.Get(headerTracestate)
			}
		}
		ctx := withFields(r.Context(), f)
		w.Header().Set(headerRequestID, f.correlationID)
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r.WithContext(ctx))
		s.log.InfoContext(ctx, "request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"duration_ms", float64(time.Since(start).Microseconds())/1000)
	})
}

// statusWriter remembers the status a handler wrote.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the underlying writer, so a handler that flushes or
// hijacks keeps that ability through this wrapper.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// NewHandler wraps a slog handler so every record written with a request's context carries the
// request's correlation_id and, when the caller passed a trace context, its trace_id and span_id
// (the parent span's, the one the mesh opened for the call), always at the top level of the
// record, whatever groups the logger has opened. Records written outside a request pass through
// unchanged.
func NewHandler(next slog.Handler) slog.Handler { return stampHandler{next: next} }

// stampHandler stamps the request's identifiers. While no group is open the stamp is added to the
// record itself. Once a group is open, attributes added to the record would land inside it, so the
// handler remembers the handler as it was before the first group (root) and what was applied since
// (ops), and stamps by rebuilding that chain with the identifiers in front of the first group.
// That rebuild happens per record while a group is open, so a logger on a hot path should carry
// its context with With rather than WithGroup, or open its group once per request, not per line.
type stampHandler struct {
	next slog.Handler
	root slog.Handler
	ops  []handlerOp
}

// handlerOp is one WithGroup (group set) or WithAttrs (attrs set) applied after the first group.
type handlerOp struct {
	group string
	attrs []slog.Attr
}

func (h stampHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h stampHandler) Handle(ctx context.Context, r slog.Record) error {
	f, ok := fieldsFrom(ctx)
	if !ok {
		return h.next.Handle(ctx, r)
	}
	if h.root == nil {
		r = r.Clone()
		r.AddAttrs(f.attrs()...)
		return h.next.Handle(ctx, r)
	}
	stamped := h.root.WithAttrs(f.attrs())
	for _, op := range h.ops {
		if op.group != "" {
			stamped = stamped.WithGroup(op.group)
		} else {
			stamped = stamped.WithAttrs(op.attrs)
		}
	}
	return stamped.Handle(ctx, r)
}

func (h stampHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	out := stampHandler{next: h.next.WithAttrs(attrs), root: h.root}
	if h.root != nil {
		out.ops = append(slices.Clone(h.ops), handlerOp{attrs: attrs})
	}
	return out
}

func (h stampHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	out := stampHandler{next: h.next.WithGroup(name), root: h.root}
	if h.root == nil {
		out.root = h.next
	}
	out.ops = append(slices.Clone(h.ops), handlerOp{group: name})
	return out
}
