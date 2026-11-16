package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"
	"time"
)

// maxEventDetail is the schema's bound on a payload's detail.
const maxEventDetail = 512

// eventSink writes IF-01 security-state events (docs/contracts/if01-event.v1.schema.json) as JSON
// lines on stdout, beside the records: one write per line, numbered in sequence from each start.
// The source is connector-<zone>; the run id is minted at every start, connector-<zone>-<8 hex>, so
// each process is its own run and (run_id, seq) stays unique across restarts and replicas.
type eventSink struct {
	mu     sync.Mutex
	w      io.Writer
	source string
	runID  string
	seq    uint64
	now    func() time.Time
}

type eventPayload struct {
	State      string `json:"state"`
	ReasonCode string `json:"reason_code,omitempty"`
	RuleID     string `json:"rule_id,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

type if01Event struct {
	RunID         string       `json:"run_id"`
	Seq           uint64       `json:"seq"`
	TS            string       `json:"ts"`
	Source        string       `json:"source"`
	Kind          string       `json:"kind"`
	CorrelationID string       `json:"correlation_id,omitempty"`
	Payload       eventPayload `json:"payload"`
}

func newEventSink(w io.Writer, zone string) *eventSink {
	return &eventSink{w: w, source: "connector-" + zone, runID: "connector-" + zone + "-" + randomHex(4), now: time.Now}
}

// tokenEvent emits one token_event for the request ctx belongs to.
func (s *eventSink) tokenEvent(ctx context.Context, p eventPayload) {
	if len(p.Detail) > maxEventDetail {
		p.Detail = p.Detail[:maxEventDetail]
	}
	id, _ := ctx.Value(correlationKey{}).(string)
	s.mu.Lock()
	defer s.mu.Unlock()
	ev := if01Event{RunID: s.runID, Seq: s.seq, TS: s.now().UTC().Format(time.RFC3339Nano),
		Source: s.source, Kind: "token_event", CorrelationID: id, Payload: p}
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	s.seq++
	_, _ = s.w.Write(append(line, '\n'))
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
