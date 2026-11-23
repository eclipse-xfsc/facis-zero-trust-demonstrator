// Package contractpath locates the repository's contract files for tests, which run from their
// package directory.
package contractpath

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Root is the module root.
func Root(t testing.TB) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err != nil {
		t.Fatalf("locate the module root: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// Contracts is docs/contracts.
func Contracts(t testing.TB) string { return filepath.Join(Root(t), "docs", "contracts") }

// Fixtures is docs/contracts/fixtures.
func Fixtures(t testing.TB) string { return filepath.Join(Contracts(t), "fixtures") }

// Templates is the folder of the Envoy bootstrap templates.
func Templates(t testing.TB) string {
	return filepath.Join(Root(t), "scripts", "verify-policy-hook", "envoy")
}
