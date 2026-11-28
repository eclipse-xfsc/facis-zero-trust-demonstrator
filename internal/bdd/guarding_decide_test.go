package bdd

import (
	"encoding/json"
	"strings"
	"testing"
)

// guardingRecord is a cases.jsonl in which every case held, as the proof writes it.
func guardingRecord() map[string]*guardingCase {
	cases := map[string]*guardingCase{}
	for _, protocol := range []string{"rest", "grpc"} {
		for name, want := range map[string][2]string{"authorized": {"allowed", ""}, "unauthorized": {"denied", "POL-RULE-DENY"}, "presentation-required": {"denied", "POL-PRESENTATION-REQUIRED"}} {
			c := &guardingCase{Case: protocol + "-" + name, Protocol: protocol, CorrelationID: "id-" + protocol + name, ReasonCode: want[1],
				ResourceReached: want[0] == "allowed", Verdict: "yes", GuardEvent: &guardingEvent{}, PolicyEvent: &guardingEvent{}}
			for _, e := range []*guardingEvent{c.GuardEvent, c.PolicyEvent} {
				e.CorrelationID, e.Payload.State, e.Payload.ReasonCode, e.Payload.RuleID, e.Payload.BundleRevision = c.CorrelationID, want[0], want[1], "m3-rule", "rev-1"
			}
			if name == "presentation-required" {
				c.OID4VPLink = "openid4vp://authorize?request_uri=https%3A%2F%2Fverifier.test%2Frequest"
			}
			cases[c.Case] = c
		}
	}
	return cases
}

func decideGuardingRecord(cases map[string]*guardingCase) ([]string, error) {
	var b strings.Builder
	for _, c := range cases {
		line, _ := json.Marshal(c)
		b.Write(append(line, '\n'))
	}
	return decideGuarding(strings.NewReader(b.String()), "rev-1")
}

func TestDecideGuarding(t *testing.T) {
	if lines, err := decideGuardingRecord(guardingRecord()); err != nil || len(lines) != 6 {
		t.Fatalf("a record in which every case held: %v %v", lines, err)
	}
	for name, change := range map[string]func(map[string]*guardingCase){
		"no gRPC case":                          func(c map[string]*guardingCase) { delete(c, "grpc-authorized") },
		"the proof did not hold a case":         func(c map[string]*guardingCase) { c["rest-authorized"].Verdict = "no" },
		"authorized never reached the resource": func(c map[string]*guardingCase) { c["grpc-authorized"].ResourceReached = false },
		"denied request reached the resource":   func(c map[string]*guardingCase) { c["rest-unauthorized"].ResourceReached = true },
		"denial without the guard's event":      func(c map[string]*guardingCase) { c["grpc-unauthorized"].GuardEvent = nil },
		"denial without the policy's event":     func(c map[string]*guardingCase) { c["rest-unauthorized"].PolicyEvent = nil },
		"policy event under another id":         func(c map[string]*guardingCase) { c["rest-unauthorized"].PolicyEvent.CorrelationID = "other" },
		"decision without a rule":               func(c map[string]*guardingCase) { c["rest-authorized"].PolicyEvent.Payload.RuleID = "" },
		"decided under another revision": func(c map[string]*guardingCase) {
			c["grpc-authorized"].PolicyEvent.Payload.BundleRevision = "chart-rules"
		},
		"denied with another code":      func(c map[string]*guardingCase) { c["grpc-unauthorized"].ReasonCode = "TOK-MISSING" },
		"presentation without a link":   func(c map[string]*guardingCase) { c["grpc-presentation-required"].OID4VPLink = "" },
		"a link that is no OID4VP link": func(c map[string]*guardingCase) { c["rest-presentation-required"].OID4VPLink = "javascript:alert(1)" },
	} {
		cases := guardingRecord()
		change(cases)
		if _, err := decideGuardingRecord(cases); err == nil {
			t.Errorf("%s: the row was decided as held", name)
		}
	}
	if _, err := decideGuarding(strings.NewReader(""), "rev-1"); err == nil {
		t.Error("an empty record decided the row")
	}
}
