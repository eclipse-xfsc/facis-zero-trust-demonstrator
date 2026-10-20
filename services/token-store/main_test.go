package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func noEnv(string) string { return "" }

func withURL(string) string { return "postgres://u:p@db/x" }

func TestRunWithoutACommandPrintsUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(nil, &out, &errOut); code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut.String(), "token-store migrate up") {
		t.Errorf("usage not printed: %q", errOut.String())
	}
	if code := run([]string{"serve"}, &out, &errOut); code != exitUsage {
		t.Errorf("unknown command: exit %d, want %d", code, exitUsage)
	}
}

func TestParseMigrate(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		env     func(string) string
		wantErr string
		want    migrateOptions
	}{
		{name: "up defaults to latest", args: []string{"up"}, env: withURL,
			want: migrateOptions{action: "up", databaseURL: "postgres://u:p@db/x", to: -1, timeout: time.Minute}},
		{name: "up to a version", args: []string{"up", "--to", "3", "--timeout", "30s"}, env: withURL,
			want: migrateOptions{action: "up", databaseURL: "postgres://u:p@db/x", to: 3, timeout: 30 * time.Second}},
		{name: "flag beats environment", args: []string{"status", "--database-url", "postgres://flag"}, env: withURL,
			want: migrateOptions{action: "status", databaseURL: "postgres://flag", to: -1, timeout: time.Minute}},
		{name: "down needs a target", args: []string{"down"}, env: withURL, wantErr: "needs --to"},
		{name: "down to zero is explicit", args: []string{"down", "--to", "0"}, env: withURL,
			want: migrateOptions{action: "down", databaseURL: "postgres://u:p@db/x", to: 0, timeout: time.Minute}},
		{name: "up to zero is refused", args: []string{"up", "--to", "0"}, env: withURL, wantErr: "would apply nothing"},
		{name: "no database", args: []string{"up"}, env: noEnv, wantErr: "no database"},
		{name: "no action", args: nil, env: withURL, wantErr: "needs one of"},
		{name: "unknown action", args: []string{"sideways"}, env: withURL, wantErr: "unknown migrate action"},
		{name: "stray argument", args: []string{"up", "extra"}, env: withURL, wantErr: "unexpected argument"},
		{name: "negative target", args: []string{"up", "--to", "-5"}, env: withURL, wantErr: "0 or more"},
		{name: "zero timeout", args: []string{"status", "--timeout", "0"}, env: withURL, wantErr: "longer than 0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var errOut bytes.Buffer
			got, err := parseMigrate(tc.args, tc.env, &errOut)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("options %+v, want %+v", got, tc.want)
			}
		})
	}
}
