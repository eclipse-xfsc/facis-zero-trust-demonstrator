package bdd

import (
	"strings"
	"testing"
)

// TestDecideObservability holds the decision of ZT-27 to the record: the row passes only when every
// check its clauses name is in the record as passed.
func TestDecideObservability(t *testing.T) {
	record := func(result map[string]string) string {
		var b strings.Builder
		b.WriteString(`{"run":"obs-test","checks":[{"check":"missing-target-alerts","result":"failed","detail":"outside the row"}`)
		for _, clause := range observabilityClauses {
			for _, name := range clause.checks {
				r, ok := result[name]
				if !ok {
					r = "passed"
				}
				if r != "" {
					b.WriteString(`,{"check":"` + name + `","result":"` + r + `","detail":"d"}`)
				}
			}
		}
		b.WriteString("]}")
		return b.String()
	}
	if _, err := decideObservability(strings.NewReader(record(nil))); err != nil {
		t.Errorf("a complete record is not held: %v", err)
	}
	for name, c := range map[string]struct {
		record, wantErr string
	}{
		"the gap check failed":     {record(map[string]string{"silent-component-is-a-gap": "failed"}), "silent-component-is-a-gap failed"},
		"the gap check is missing": {record(map[string]string{"silent-component-is-a-gap": ""}), "silent-component-is-a-gap is not in the record"},
		"retention is pending":     {record(map[string]string{"metrics-survive-restart": "pending"}), "metrics-survive-restart pending"},
		"an empty record":          {`{"checks":[]}`, "correlated-trace is not in the record"},
		"no record":                {``, "record.json"},
	} {
		if _, err := decideObservability(strings.NewReader(c.record)); err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: got %v, want an error containing %q", name, err, c.wantErr)
		}
	}
}
