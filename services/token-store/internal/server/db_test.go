package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/schema"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/testsupport"
)

// testDatabaseURL is a database of this test's own; see testsupport.DatabaseURL.
func testDatabaseURL(t *testing.T) string {
	t.Helper()
	return testsupport.DatabaseURL(t, "srv")
}

// exec runs one statement on the test database.
func exec(t *testing.T, dbURL, sql string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, sql); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// migrate brings the test database to the latest version.
func migrate(t *testing.T, dbURL string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	r, err := schema.NewRunner(conn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Up(ctx, 0); err != nil {
		t.Fatal(err)
	}
}

// fakeOpenBao answers as an initialised, unsealed server.
func fakeOpenBao(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCheckPostgres(t *testing.T) {
	dbURL := testDatabaseURL(t)
	var buf testsupport.Buffer
	s, err := New(context.Background(), localConfig(dbURL, fakeOpenBao(t).URL), testLogger(&buf))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.pool.Close)
	ctx := context.Background()

	if w := s.checkPostgres(ctx); w != checkSchemaBehind {
		t.Errorf("empty database: %q, want %q", w, checkSchemaBehind)
	}
	migrate(t, dbURL)
	if w := s.checkPostgres(ctx); w != checkOK {
		t.Errorf("migrated database: %q, want %q", w, checkOK)
	}
	exec(t, dbURL, "UPDATE schema_migrations SET checksum = '0' WHERE version = 1")
	if w := s.checkPostgres(ctx); w != checkSchemaDrift {
		t.Errorf("edited checksum: %q, want %q", w, checkSchemaDrift)
	}
	s.pool.Close()
	if w := s.checkPostgres(ctx); w != checkUnreachable {
		t.Errorf("closed pool: %q, want %q", w, checkUnreachable)
	}

	var unreachable testsupport.Buffer
	u, err := New(context.Background(), localConfig(unreachableDatabase, fakeOpenBao(t).URL), testLogger(&unreachable))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(u.pool.Close)
	if w := u.checkPostgres(ctx); w != checkUnreachable {
		t.Errorf("unreachable database: %q, want %q", w, checkUnreachable)
	}
	if logs := unreachable.String(); strings.Contains(logs, "hunter2") {
		t.Errorf("the password reached the records:\n%s", logs)
	}
}

// With a migrated database and a key-value store that answers, the store is ready on both
// listeners, echoes the caller's id, stamps it on the records, and drains cleanly.
func TestServerServesAndDrains(t *testing.T) {
	dbURL := testDatabaseURL(t)
	migrate(t, dbURL)
	var buf testsupport.Buffer
	s, err := New(context.Background(), localConfig(dbURL, fakeOpenBao(t).URL), testLogger(&buf))
	if err != nil {
		t.Fatal(err)
	}
	stop := startServer(t, s)

	for i, base := range []string{"http://" + s.OpsAddr().String(), "http://" + s.Addr().String()} {
		id := []string{"ops-1", "api-1"}[i]
		resp, body := get(t, base+"/readyz", map[string]string{"X-Request-Id": id, "Traceparent": validTraceparent})
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"ready":true`) {
			t.Errorf("%s/readyz: %d %s", base, resp.StatusCode, body)
		}
		if resp.Header.Get("X-Request-Id") != id {
			t.Errorf("%s: x-request-id echoed as %q", base, resp.Header.Get("X-Request-Id"))
		}
		if resp, _ := get(t, base+"/healthz", nil); resp.StatusCode != http.StatusOK {
			t.Errorf("%s/healthz: %d", base, resp.StatusCode)
		}
	}
	if err := stop(); err != nil {
		t.Errorf("Serve returned %v after a clean stop", err)
	}

	var found int
	for _, r := range requestRecords(t, &buf) {
		if r["path"] == "/readyz" && (r["correlation_id"] == "ops-1" || r["correlation_id"] == "api-1") {
			found++
			if r["trace_id"] != "0af7651916cd43dd8448eb211c80319c" || r["span_id"] != "b7ad6b7169203331" {
				t.Errorf("record lacks the trace context: %v", r)
			}
		}
	}
	if found != 2 {
		t.Errorf("%d correlated readiness records, want 2:\n%s", found, buf.String())
	}
	if !strings.Contains(buf.String(), `"msg":"ready"`) {
		t.Errorf("no transition to ready was recorded:\n%s", buf.String())
	}
}
