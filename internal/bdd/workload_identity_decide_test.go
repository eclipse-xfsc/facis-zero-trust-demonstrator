package bdd

import (
	"strings"
	"testing"
)

// TestDecideIdentityRow holds the decision of the workload identity rows to the record: a row passes only
// when each of its sections is present with checks and no failure, and each check it names passed.
func TestDecideIdentityRow(t *testing.T) {
	record := func(row string, mutate func(string) string) string {
		spec := identityRows[row]
		var b strings.Builder
		b.WriteString("# header\n\n- PASS: not in a section\n")
		for _, s := range spec.sections {
			b.WriteString("\n## " + s + ". section\n\n- PASS: filler\n")
		}
		// The named checks go in the row's last section; the decider does not tie a check to a section.
		for _, c := range spec.checks {
			b.WriteString("- PASS: " + c + " (detail)\n  detail line\n")
		}
		b.WriteString("\n## The cluster's CNI as found\n\n- **FAIL**: outside the row\n")
		return mutate(b.String())
	}
	same := func(s string) string { return s }
	for row := range identityRows {
		if _, err := decideIdentityRow(strings.NewReader(record(row, same)), row); err != nil {
			t.Errorf("%s: a complete record is not held: %v", row, err)
		}
	}
	cases := []struct {
		name, row, wantErr string
		mutate             func(string) string
	}{
		{"a failed check in a row's section", "ZT-60", "failed: §9 boom", func(s string) string {
			return strings.Replace(s, "\n## 9. section\n\n", "\n## 9. section\n\n- **FAIL**: boom\n", 1)
		}},
		{"a named check failed instead of passed", "ZT-60", "no PASS line: the SPIRE agent refuses its proxy over SDS", func(s string) string {
			return strings.Replace(s, "- PASS: the SPIRE agent refuses", "- **FAIL**: the SPIRE agent refuses", 1)
		}},
		{"a missing section", "ZT-57", "section 4 holds no check", func(s string) string {
			return strings.Replace(s, "## 4. section", "## 40. section", 1)
		}},
		{"a failed install", "ZT-59", "failed: §2", func(s string) string {
			return strings.Replace(s, "\n## 2. section\n\n", "\n## 2. section\n\n- **FAIL**: install\n", 1)
		}},
		{"an empty record", "ZT-24", "section 0 holds no check", func(string) string { return "" }},
	}
	for _, c := range cases {
		_, err := decideIdentityRow(strings.NewReader(record(c.row, c.mutate)), c.row)
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: got %v, want an error containing %q", c.name, err, c.wantErr)
		}
	}
}
