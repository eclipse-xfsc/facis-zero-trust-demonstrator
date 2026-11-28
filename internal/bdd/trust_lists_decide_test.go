package bdd

import (
	"strings"
	"testing"
)

// The record of a real run of scripts/verify-train-allow-list/verify.sh decides the row; the same
// record with the unlisted peer served, or a refusal without its event, does not.
func TestDecideAllowList(t *testing.T) {
	cases, err := readAllowListRecord("testdata/train-allow-list/record.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := decideAllowList(cases); err != nil {
		t.Fatalf("a passing record: %v", err)
	}
	for name, want := range map[string]string{"unlisted peer": "unlisted peer: 200", "trust list unavailable": "trust list unavailable: 200"} {
		c := cases[name]
		c.Status, c.Reason, c.Upstream = 200, "", 1
		broken := map[string]allowListCase{name: c}
		for k, v := range cases {
			if k != name {
				broken[k] = v
			}
		}
		if err := decideAllowList(broken); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s served: %v", name, err)
		}
	}
	c := cases["unlisted peer"]
	c.Event = nil
	cases["unlisted peer"] = c
	if err := decideAllowList(cases); err == nil || !strings.Contains(err.Error(), "no denied decision event") {
		t.Errorf("a refusal without its event: %v", err)
	}
}
