// Package pgtest gives a test a PostgreSQL database of its own, optionally with the zone's
// authorization schema applied, on the server that TOKEN_STORE_TEST_DATABASE_URL names. Shared by the
// token store's and the Connector's database tests, which use one schema.
package pgtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// DatabaseEnv names the PostgreSQL the database tests run against.
const DatabaseEnv = "TOKEN_STORE_TEST_DATABASE_URL"

// DatabaseURL creates a database of its own, ts_<prefix>_<random>, on the PostgreSQL that
// DatabaseEnv names, drops it when the test ends, and returns its connection URL. Without the
// variable the test skips, so the ordinary test job stays self-contained and the database job,
// which fails on a skip, proves the variable was set.
func DatabaseURL(t *testing.T, prefix string) string {
	t.Helper()
	admin := os.Getenv(DatabaseEnv)
	if admin == "" {
		t.Skipf("%s not set; this test needs a PostgreSQL", DatabaseEnv)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatalf("connecting to %s: %v", DatabaseEnv, err)
	}
	var suffix [6]byte
	_, _ = rand.Read(suffix[:])
	name := "ts_" + prefix + "_" + hex.EncodeToString(suffix[:])
	ident := pgx.Identifier{name}.Sanitize()
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+ident); err != nil {
		t.Fatalf("creating the test database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = conn.Exec(ctx, "DROP DATABASE "+ident+" WITH (FORCE)")
		_ = conn.Close(ctx)
	})
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}

// MigratedURL is DatabaseURL with every up migration of the token store's schema applied in order.
// It runs the files directly: the migration runner and its checks are the schema package's and are
// tested there.
func MigratedURL(t *testing.T, prefix string) string {
	t.Helper()
	dsn := DatabaseURL(t, prefix)
	_, self, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(self), "..", "..", "services", "token-store", "internal", "schema", "migrations")
	files, err := filepath.Glob(filepath.Join(dir, "*.up.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no migrations under %s: %v", dir, err)
	}
	sort.Strings(files)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	for _, f := range files {
		sql, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("applying %s: %v", strings.TrimPrefix(f, dir+"/"), err)
		}
	}
	return dsn
}
