package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/testsupport"
)

// records decodes every JSON line written to buf so far.
func records(t *testing.T, buf *testsupport.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range bytes.Split(buf.Bytes(), []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("a record is not JSON: %v\n%s", err, line)
		}
		out = append(out, m)
	}
	return out
}

// testLogger is a logger wrapped by NewHandler, writing JSON to buf at Debug level.
func testLogger(buf *testsupport.Buffer) *slog.Logger {
	return slog.New(NewHandler(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
}

// requestRecords returns the completion records, one per request handled.
func requestRecords(t *testing.T, buf *testsupport.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range records(t, buf) {
		if r["msg"] == "request" {
			out = append(out, r)
		}
	}
	return out
}
