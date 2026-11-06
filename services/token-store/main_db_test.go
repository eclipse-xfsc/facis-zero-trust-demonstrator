package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// testDatabaseURL creates a database of its own on the PostgreSQL that TOKEN_STORE_TEST_DATABASE_URL
// names, dropped when the test ends, and returns its URL. Skips without the variable.
func testDatabaseURL(t *testing.T) string {
	t.Helper()
	admin := os.Getenv("TOKEN_STORE_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("TOKEN_STORE_TEST_DATABASE_URL not set; this test needs a PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatalf("connecting to TOKEN_STORE_TEST_DATABASE_URL: %v", err)
	}
	var suffix [6]byte
	_, _ = rand.Read(suffix[:])
	name := "ts_cli_" + hex.EncodeToString(suffix[:])
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

// The migrate command end to end, exit codes included: status on an empty database is 3, up is 0
// and leaves it current, down to 0 empties it again, and a database that cannot be reached is a
// failure that does not echo the URL.
func TestMigrateRunsAgainstADatabase(t *testing.T) {
	dbURL := testDatabaseURL(t)
	var out, logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	migrate := func(args ...string) int {
		out.Reset()
		logs.Reset()
		return run(append([]string{"migrate"}, args...), &out, &logs)
	}
	status := func() (int, int) {
		t.Helper()
		var s struct{ Current, Latest int }
		if err := json.Unmarshal(out.Bytes(), &s); err != nil {
			t.Fatalf("status output is not JSON: %v\n%s", err, out.String())
		}
		return s.Current, s.Latest
	}

	if code := migrate("status", "--database-url", dbURL); code != exitNotCurrent {
		t.Fatalf("status on an empty database: exit %d, want %d\n%s", code, exitNotCurrent, logs.String())
	}
	if current, latest := status(); current != 0 || latest < 1 {
		t.Errorf("empty database reported as current %d, latest %d", current, latest)
	}
	if code := migrate("up", "--database-url", dbURL); code != exitOK {
		t.Fatalf("up: exit %d\n%s", code, logs.String())
	}
	if code := migrate("status", "--database-url", dbURL); code != exitOK {
		t.Fatalf("status after up: exit %d\n%s", code, logs.String())
	}
	if current, latest := status(); current != latest {
		t.Errorf("after up: current %d, latest %d", current, latest)
	}
	if code := migrate("down", "--to", "0", "--database-url", dbURL); code != exitOK {
		t.Fatalf("down to 0: exit %d\n%s", code, logs.String())
	}
	if code := migrate("status", "--database-url", dbURL); code != exitNotCurrent {
		t.Errorf("status after down to 0: exit %d, want %d", code, exitNotCurrent)
	}
	if current, _ := status(); current != 0 {
		t.Errorf("after down to 0: current %d", current)
	}

	const unreachable = "postgres://u:hunter2@127.0.0.1:1/x?sslmode=disable&connect_timeout=2"
	if code := migrate("status", "--database-url", unreachable); code != exitFailed {
		t.Errorf("unreachable database: exit %d, want %d", code, exitFailed)
	}
	if strings.Contains(logs.String(), "hunter2") {
		t.Errorf("the password reached the log:\n%s", logs.String())
	}
}
