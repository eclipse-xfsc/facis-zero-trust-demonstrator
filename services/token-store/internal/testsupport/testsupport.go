// Package testsupport holds what the token store's tests share and would otherwise copy: a
// database of their own on the PostgreSQL that TOKEN_STORE_TEST_DATABASE_URL names, and a buffer
// that is safe for records written from other goroutines.
package testsupport

import (
	"bytes"
	"sync"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/pgtest"
)

// DatabaseEnv names the PostgreSQL the database tests run against.
const DatabaseEnv = pgtest.DatabaseEnv

// DatabaseURL creates a database of its own on the PostgreSQL that DatabaseEnv names; see
// pgtest.DatabaseURL.
func DatabaseURL(t *testing.T, prefix string) string {
	t.Helper()
	return pgtest.DatabaseURL(t, prefix)
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
