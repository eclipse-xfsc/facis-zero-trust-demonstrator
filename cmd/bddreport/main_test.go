package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// With --require-complete a gap fails the run, but only after the sheets are written, so a publish
// step that always runs still carries them.
func TestRequireCompleteFailsAfterWritingTheSheets(t *testing.T) {
	dir := t.TempDir()
	rows := filepath.Join(dir, "rows.txt")
	report := filepath.Join(dir, "report.json")
	out := filepath.Join(dir, "out")
	must(t, os.WriteFile(rows, []byte("ZT-01\nZT-02\n"), 0o644))
	must(t, os.WriteFile(report, []byte(`[{"uri":"f","name":"F","tags":[],"elements":[
	  {"type":"scenario","name":"a","tags":[{"name":"@ZT-01"}],"steps":[{"result":{"status":"passed"}}]}]}]`), 0o644))

	if err := run(rows, out, []string{report}, false); err != nil {
		t.Fatalf("without the flag a gap is reported, not fatal: %v", err)
	}
	must(t, os.RemoveAll(out))

	err := run(rows, out, []string{report}, true)
	if err == nil || !strings.Contains(err.Error(), "uncovered: ZT-02") {
		t.Fatalf("run = %v, want the gap named", err)
	}
	sheet, readErr := os.ReadFile(filepath.Join(out, "traceability.md"))
	if readErr != nil || !strings.Contains(string(sheet), "| ZT-02 | no |") {
		t.Fatalf("the sheet was not written before failing: %v", readErr)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
