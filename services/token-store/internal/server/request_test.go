package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"testing/slogtest"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/testsupport"
)

var hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)

const validTraceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

// serveOnce handles one request through the correlation middleware and returns the response,
// the fields the handler saw in its context and the headers it would forward.
func serveOnce(t *testing.T, buf *testsupport.Buffer, headers map[string]string) (*http.Response, requestFields, http.Header) {
	t.Helper()
	s := &Server{log: testLogger(buf)}
	var seen requestFields
	var outbound http.Header
	h := s.correlate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = fieldsFrom(r.Context())
		outbound = seen.outbound()
		s.log.InfoContext(r.Context(), "inside the handler")
		w.WriteHeader(http.StatusTeapot)
	}))
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result(), seen, outbound
}

func TestRequestID(t *testing.T) {
	cases := []struct {
		name   string
		header string
		kept   bool
	}{
		{name: "absent is minted", header: "", kept: false},
		{name: "a plain id is kept", header: "abc-123.v2", kept: true},
		{name: "128 bytes is kept", header: strings.Repeat("a", 128), kept: true},
		{name: "129 bytes is replaced", header: strings.Repeat("a", 129), kept: false},
		{name: "a space is replaced", header: "has space", kept: false},
		{name: "a control byte is replaced", header: "tab\there", kept: false},
		{name: "a non-ASCII byte is replaced", header: "caf\xc3\xa9", kept: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf testsupport.Buffer
			headers := map[string]string{}
			if tc.header != "" {
				headers["X-Request-Id"] = tc.header
			}
			resp, seen, outbound := serveOnce(t, &buf, headers)
			echoed := resp.Header.Get("X-Request-Id")
			if tc.kept {
				if seen.correlationID != tc.header || echoed != tc.header {
					t.Errorf("kept id: context %q, echoed %q, want %q", seen.correlationID, echoed, tc.header)
				}
			} else {
				if !hex32.MatchString(seen.correlationID) || seen.correlationID == tc.header {
					t.Errorf("minted id %q is not 32 hex characters", seen.correlationID)
				}
				if echoed != seen.correlationID {
					t.Errorf("echoed %q, context %q", echoed, seen.correlationID)
				}
			}
			if outbound.Get("X-Request-Id") != seen.correlationID {
				t.Errorf("outbound x-request-id %q, want %q", outbound.Get("X-Request-Id"), seen.correlationID)
			}
			for _, r := range records(t, &buf) {
				if r["correlation_id"] != seen.correlationID {
					t.Errorf("record %q carries correlation_id %v, want %q", r["msg"], r["correlation_id"], seen.correlationID)
				}
			}
		})
	}
}

func TestTraceContext(t *testing.T) {
	cases := []struct {
		name        string
		traceparent string
		tracestate  string
		wantTrace   string
		wantSpan    string
	}{
		{name: "valid", traceparent: validTraceparent, tracestate: "vendor=a", wantTrace: "0af7651916cd43dd8448eb211c80319c", wantSpan: "b7ad6b7169203331"},
		{name: "a later version is read on its first fields", traceparent: "01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01-future", wantTrace: "0af7651916cd43dd8448eb211c80319c", wantSpan: "b7ad6b7169203331"},
		{name: "version ff is ignored", traceparent: "ff-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01", tracestate: "vendor=a"},
		{name: "version 00 with a fifth field is ignored", traceparent: "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01-extra"},
		{name: "uppercase is ignored", traceparent: "00-0AF7651916CD43DD8448EB211C80319C-B7AD6B7169203331-01"},
		{name: "a short trace id is ignored", traceparent: "00-0af7651916cd43dd8448eb211c80319-b7ad6b7169203331-01"},
		{name: "a zero trace id is ignored", traceparent: "00-00000000000000000000000000000000-b7ad6b7169203331-01"},
		{name: "a zero parent id is ignored", traceparent: "00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01"},
		{name: "garbage is ignored", traceparent: "not-a-trace"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf testsupport.Buffer
			headers := map[string]string{"Traceparent": tc.traceparent}
			if tc.tracestate != "" {
				headers["Tracestate"] = tc.tracestate
			}
			_, seen, outbound := serveOnce(t, &buf, headers)
			if seen.traceID != tc.wantTrace || seen.spanID != tc.wantSpan {
				t.Fatalf("trace %q span %q, want %q %q", seen.traceID, seen.spanID, tc.wantTrace, tc.wantSpan)
			}
			records := records(t, &buf)
			if tc.wantTrace == "" {
				if outbound.Get("Traceparent") != "" || outbound.Get("Tracestate") != "" {
					t.Errorf("an ignored trace context was forwarded: %v", outbound)
				}
				for _, r := range records {
					if _, has := r["trace_id"]; has {
						t.Errorf("record %q carries a trace_id for an ignored traceparent", r["msg"])
					}
				}
				return
			}
			if outbound.Get("Traceparent") != tc.traceparent || outbound.Get("Tracestate") != tc.tracestate {
				t.Errorf("forwarded %v, want the headers unchanged", outbound)
			}
			for _, r := range records {
				if r["trace_id"] != tc.wantTrace || r["span_id"] != tc.wantSpan {
					t.Errorf("record %q carries trace %v span %v", r["msg"], r["trace_id"], r["span_id"])
				}
			}
		})
	}
}

func TestRequestCompletionRecord(t *testing.T) {
	var buf testsupport.Buffer
	_, seen, _ := serveOnce(t, &buf, map[string]string{"X-Request-Id": "req-7", "Traceparent": validTraceparent})
	records := requestRecords(t, &buf)
	if len(records) != 1 {
		t.Fatalf("%d completion records, want 1", len(records))
	}
	r := records[0]
	if r["method"] != "GET" || r["path"] != "/readyz" || r["status"] != float64(http.StatusTeapot) {
		t.Errorf("completion record %v", r)
	}
	if _, ok := r["duration_ms"].(float64); !ok {
		t.Errorf("duration_ms missing or not a number: %v", r["duration_ms"])
	}
	if r["correlation_id"] != "req-7" || r["trace_id"] != seen.traceID || r["span_id"] != seen.spanID {
		t.Errorf("completion record lacks the ids: %v", r)
	}
}

func TestHandlerStampsTheContextFields(t *testing.T) {
	var buf testsupport.Buffer
	log := testLogger(&buf).With("service", "token-store")
	ctx := withFields(context.Background(), requestFields{correlationID: "c1", traceID: "t1", spanID: "s1"})
	log.InfoContext(ctx, "with fields")
	log.InfoContext(withFields(context.Background(), requestFields{correlationID: "c2"}), "without a trace")
	log.Info("outside a request")
	// Groups opened later keep the stamp at the top level, where every reader of the records
	// looks for it; the grouped attributes stay grouped.
	log.WithGroup("db").With("table", "proof_jti").WithGroup("row").InfoContext(ctx, "grouped", "jti", "x")
	log.WithGroup("db").Info("grouped outside a request", "jti", "y")

	records := records(t, &buf)
	if len(records) != 5 {
		t.Fatalf("%d records, want 5", len(records))
	}
	if r := records[0]; r["correlation_id"] != "c1" || r["trace_id"] != "t1" || r["span_id"] != "s1" || r["service"] != "token-store" {
		t.Errorf("first record: %v", r)
	}
	if r := records[1]; r["correlation_id"] != "c2" || r["trace_id"] != nil {
		t.Errorf("second record: %v", r)
	}
	if r := records[2]; r["correlation_id"] != nil {
		t.Errorf("a record outside a request was stamped: %v", r)
	}
	r := records[3]
	if r["correlation_id"] != "c1" || r["trace_id"] != "t1" || r["span_id"] != "s1" || r["service"] != "token-store" {
		t.Errorf("grouped record: the stamp is not at the top level: %v", r)
	}
	db, _ := r["db"].(map[string]any)
	if db == nil || db["table"] != "proof_jti" {
		t.Fatalf("grouped record lost its group: %v", r)
	}
	if _, inGroup := db["correlation_id"]; inGroup {
		t.Errorf("the stamp landed inside the group: %v", r)
	}
	if row, _ := db["row"].(map[string]any); row == nil || row["jti"] != "x" {
		t.Errorf("the nested group is wrong: %v", r)
	}
	if r := records[4]; r["correlation_id"] != nil || r["db"].(map[string]any)["jti"] != "y" {
		t.Errorf("grouped record outside a request: %v", r)
	}
}

func TestHandlerConformsToSlog(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(slog.NewJSONHandler(&buf, nil))
	results := func() []map[string]any {
		var out []map[string]any
		for _, line := range bytes.Split(buf.Bytes(), []byte{'\n'}) {
			if len(line) == 0 {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal(line, &m); err != nil {
				t.Fatal(err)
			}
			out = append(out, m)
		}
		return out
	}
	if err := slogtest.TestHandler(h, results); err != nil {
		t.Fatal(err)
	}
}
