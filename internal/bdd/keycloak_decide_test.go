package bdd

import (
	"encoding/json"
	"testing"
)

func TestViewerDecisionRequiresRecordedRefusals(t *testing.T) {
	cases := []viewerDecision{}
	for _, v := range []struct {
		name, reason, state string
		status, dispatch    int
	}{
		{"operator start", "UI-AUTHORISED", "allowed", 200, 1},
		{"observer start", "UI-NOT-AUTHORISED", "denied", 403, 0},
		{"observer configuration", "CFG-NOT-AUTHORISED", "denied", 403, 0},
		{"logged out operator", "LOGGED_OUT", "denied", 401, 0},
		{"expired observer", "EXPIRED", "denied", 401, 0},
	} {
		c := viewerDecision{Case: v.name, Status: v.status, Dispatched: v.dispatch}
		c.Event.Kind = "ui.authorization"
		c.Event.CorrelationID = v.name
		c.Event.Reason = v.reason
		c.Event.State = v.state
		cases = append(cases, c)
	}
	check := func(rows []viewerDecision, discovery bool) error {
		raw, err := json.Marshal(map[string]any{"discovery": discovery, "cases": rows})
		if err != nil {
			t.Fatal(err)
		}
		return decideViewer(raw)
	}
	if err := check(cases, true); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct {
		name string
		edit func([]viewerDecision) []viewerDecision
	}{
		{"missing case", func(c []viewerDecision) []viewerDecision { return c[:len(c)-1] }},
		{"status without event", func(c []viewerDecision) []viewerDecision { c[1].Event.Kind = ""; return c }},
		{"wrong reason", func(c []viewerDecision) []viewerDecision { c[1].Event.Reason = "other"; return c }},
		{"denied but dispatched", func(c []viewerDecision) []viewerDecision { c[1].Dispatched = 1; return c }},
		{"duplicate correlation", func(c []viewerDecision) []viewerDecision {
			c[1].Event.CorrelationID = c[0].Event.CorrelationID
			return c
		}},
		{"no correlation", func(c []viewerDecision) []viewerDecision { c[1].Event.CorrelationID = ""; return c }},
		{"duplicate case", func(c []viewerDecision) []viewerDecision { return append(c, c[0]) }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			if check(mutation.edit(append([]viewerDecision(nil), cases...)), true) == nil {
				t.Fatal("incomplete proof accepted")
			}
		})
	}
	if check(cases, false) == nil {
		t.Fatal("unreachable Keycloak accepted")
	}
}
