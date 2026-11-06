package schema

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/testsupport"
)

// The database tests run against the PostgreSQL that TOKEN_STORE_TEST_DATABASE_URL names and skip
// without it. Each test gets a database of its own (testsupport.DatabaseURL), dropped afterwards,
// so tests neither share state nor need a clean server.

type testDatabase struct {
	t   *testing.T
	cfg *pgx.ConnConfig
}

func newTestDatabase(t *testing.T) *testDatabase {
	t.Helper()
	cfg, err := pgx.ParseConfig(testsupport.DatabaseURL(t, "test"))
	if err != nil {
		t.Fatal(err)
	}
	return &testDatabase{t: t, cfg: cfg}
}

// conn opens a connection to the test database, closed when the test ends.
func (d *testDatabase) conn() *pgx.Conn {
	d.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := pgx.ConnectConfig(ctx, d.cfg)
	if err != nil {
		d.t.Fatalf("connecting to the test database: %v", err)
	}
	d.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.Close(ctx)
	})
	return c
}

// migrated returns a connection to a test database at the latest schema version.
func (d *testDatabase) migrated() *pgx.Conn {
	d.t.Helper()
	c := d.conn()
	r, err := NewRunner(c)
	if err != nil {
		d.t.Fatal(err)
	}
	if _, err := r.Up(context.Background(), 0); err != nil {
		d.t.Fatalf("migrating the test database: %v", err)
	}
	return c
}

// publicTables lists the tables of the public schema, sorted.
func publicTables(t *testing.T, c *pgx.Conn) []string { return tablesIn(t, c, "public") }

// tablesIn lists the tables of one schema, sorted.
func tablesIn(t *testing.T, c *pgx.Conn, schema string) []string {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT table_name FROM information_schema.tables WHERE table_schema = $1 ORDER BY table_name`, schema)
	if err != nil {
		t.Fatal(err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return names
}
