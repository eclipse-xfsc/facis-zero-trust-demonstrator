// Package testsupport holds what the token store's tests share and would otherwise copy: a
// database of their own on the PostgreSQL that TOKEN_STORE_TEST_DATABASE_URL names, and a buffer
// that is safe for records written from other goroutines.
package testsupport

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"sync"
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

// Buffer collects what handlers and servers write from their own goroutines.
type Buffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *Buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// String is everything written so far.
func (b *Buffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Bytes is a copy of everything written so far.
func (b *Buffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buf.Bytes())
}
