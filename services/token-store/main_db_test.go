package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/testsupport"
)

// testDatabaseURL is a database of this test's own; see testsupport.DatabaseURL.
func testDatabaseURL(t *testing.T) string {
	t.Helper()
	return testsupport.DatabaseURL(t, "cli")
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
