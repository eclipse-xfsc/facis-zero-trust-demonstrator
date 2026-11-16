package main

import (
	"bytes"
	"strings"
	"testing"
)

// keys without an action or with an unknown one is a usage error; a bad flag prints the usage
// text without the connection URL from the environment.
func TestKeysUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"keys"}, &out, &errOut); code != exitUsage || !strings.Contains(errOut.String(), "ensure, rotate, status") {
		t.Errorf("keys without an action: exit %d, %q", code, errOut.String())
	}
	errOut.Reset()
	if code := run([]string{"keys", "sideways"}, &out, &errOut); code != exitUsage {
		t.Errorf("unknown action: exit %d", code)
	}
	t.Setenv("TOKEN_STORE_DATABASE_URL", "postgres://u:hunter2@db/x")
	errOut.Reset()
	if code := run([]string{"keys", "rotate", "--bogus"}, &out, &errOut); code != exitUsage {
		t.Errorf("bad flag: exit %d", code)
	}
	if strings.Contains(errOut.String(), "hunter2") {
		t.Errorf("the connection URL reached the usage text:\n%s", errOut.String())
	}
	errOut.Reset()
	if code := run([]string{"keys", "status", "--help"}, &out, &errOut); code != exitOK {
		t.Errorf("--help: exit %d", code)
	}
	if !strings.Contains(usage, "keys rotate") || !strings.Contains(usage, "keys ensure") || !strings.Contains(usage, "keys status") {
		t.Error("the usage text does not list the keys commands")
	}
}
