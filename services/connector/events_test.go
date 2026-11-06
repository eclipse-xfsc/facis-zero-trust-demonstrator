package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// if01Schema compiles the contract the events must satisfy.
func if01Schema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile("../../docs/contracts/if01-event.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.UseLoader(jsonschema.SchemeURLLoader{})
	const url = "https://github.com/eclipse-xfsc/facis-zero-trust-demonstrator/docs/contracts/if01-event.v1.schema.json"
	if err := c.AddResource(url, doc); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile(url)
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

// Every event the sink writes is one JSON line that satisfies the IF-01 contract: the connector's
// source, a run id of the right shape, sequence numbers from zero, the request's correlation id,
// and a payload within the schema's bounds.
func TestEventsMatchTheContract(t *testing.T) {
	schema := if01Schema(t)
	var out bytes.Buffer
	sink := newEventSink(&out, "b")
	sink.now = func() time.Time { return time.Date(2026, 10, 24, 10, 0, 0, 123456789, time.UTC) }
	ctx := context.WithValue(context.Background(), correlationKey{}, "corr-1")
	sink.tokenEvent(ctx, eventPayload{State: "registered", Detail: "client_id=" + strings.Repeat("c", 64)})
	sink.tokenEvent(ctx, eventPayload{State: "refused", ReasonCode: "TOK-REGISTRATION-REJECTED", RuleID: ruleDPoPBound, Detail: ruleText[ruleDPoPBound]})
	sink.tokenEvent(context.Background(), eventPayload{State: "refused", ReasonCode: "TOK-MISSING", Detail: strings.Repeat("d", 2000)})

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("%d lines:\n%s", len(lines), out.String())
	}
	for i, line := range lines {
		doc, err := jsonschema.UnmarshalJSON(strings.NewReader(line))
		if err != nil {
			t.Fatalf("line %d is not JSON: %v", i, err)
		}
		if err := schema.Validate(doc); err != nil {
			t.Errorf("line %d violates the contract: %v\n%s", i, err, line)
		}
		var ev if01Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatal(err)
		}
		if ev.Seq != uint64(i) || ev.Source != "connector-b" || ev.Kind != "token_event" || !regexp.MustCompile(`^connector-b-[0-9a-f]{8}$`).MatchString(ev.RunID) || ev.TS != "2026-10-24T10:00:00.123456789Z" {
			t.Errorf("line %d: %+v", i, ev)
		}
		if i < 2 && ev.CorrelationID != "corr-1" || i == 2 && ev.CorrelationID != "" {
			t.Errorf("line %d correlation: %q", i, ev.CorrelationID)
		}
	}
	if len(lines[2]) > 1024 || !strings.Contains(lines[2], strings.Repeat("d", maxEventDetail)+`"`) {
		t.Errorf("the detail was not bounded to %d: %d bytes", maxEventDetail, len(lines[2]))
	}

	// Every start is its own run: two sinks never share a run id.
	if a, b := newEventSink(&out, "a"), newEventSink(&out, "a"); a.runID == b.runID || a.source != "connector-a" {
		t.Errorf("run ids %q and %q, source %q", a.runID, b.runID, a.source)
	}
}
