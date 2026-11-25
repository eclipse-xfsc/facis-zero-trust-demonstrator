// Package feedbridge is the IF-01 feed bridge: it takes the components' IF-01 log lines, v1 and v2
// alike, and serves each run's snapshot and its events as server-sent events, in two versions
// selected by path (docs/contracts/if01-feed.v1.openapi.yaml, if01-feed.v2.openapi.yaml).
//
//   - /snapshot and /events (v1) stay valid against the v1 schemas: a v2 event is served in its v1
//     form (the decision members and "version" removed), a source v1 does not name is left out.
//   - /v2/snapshot and /v2/events serve every event as its producer wrote it and every v2 source.
//
// Sequencing is the producers': each process names its own run and numbers its events from 0
// (hook.LogSink), so (run_id, seq) is unique and the bridge never renumbers. A line repeating a
// seq already taken is a duplicate of at-least-once delivery and is dropped; a seq that skips
// ahead records a gap event (VIS-STALE) under the first missing number. Each run keeps its last
// 1000 events, and all runs together stay within a byte budget: the least recently updated runs
// are dropped first and answered 410 afterwards.
package feedbridge

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	// Buffer is the number of events a run keeps.
	Buffer = 1000
	// MaxLine is the longest line taken; a longer one is drained and counted, never buffered.
	MaxLine = 64 * 1024
	// DefaultBudget is the bytes of event lines all runs together keep.
	DefaultBudget = 32 << 20
	// evictedNames is how many dropped run names are remembered, to answer them 410 instead of 404.
	evictedNames = 4096
)

type meta struct {
	Version int    `json:"version"`
	RunID   string `json:"run_id"`
	Seq     uint64 `json:"seq"`
	TS      string `json:"ts"`
	Source  string `json:"source"`
	Payload struct {
		State      string `json:"state"`
		ReasonCode string `json:"reason_code"`
	} `json:"payload"`
}

type stored struct {
	seq    uint64
	source string
	raw    json.RawMessage // as the producer wrote it
	v1     json.RawMessage // its v1 form; nil when v1 cannot name its source
}

type panel struct {
	State      string `json:"state"`
	ReasonCode string `json:"reason_code,omitempty"`
	TS         string `json:"ts"`
}

type run struct {
	events  []stored
	next    uint64 // the next seq expected
	panels  map[string]panel
	bytes   int
	touched uint64 // the bridge's ingest counter when the run last took an event
}

// Bridge holds the runs. Safe for concurrent use.
type Bridge struct {
	// Budget bounds the bytes of all runs' event lines; zero means DefaultBudget.
	Budget int

	mu      sync.Mutex
	runs    map[string]*run
	evicted map[string]bool
	order   []string // evicted names, oldest first
	bytes   int
	clock   uint64
	v1, v2  *jsonschema.Schema
	changed chan struct{}
}

// New compiles the v1 and v2 event schemas from the contracts directory.
func New(contracts string) (*Bridge, error) {
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	v1, err := c.Compile(filepath.Join(contracts, "if01-event.v1.schema.json"))
	if err != nil {
		return nil, err
	}
	v2, err := c.Compile(filepath.Join(contracts, "if01-event.v2.schema.json"))
	if err != nil {
		return nil, err
	}
	return &Bridge{runs: map[string]*run{}, evicted: map[string]bool{}, v1: v1, v2: v2, changed: make(chan struct{})}, nil
}

// ErrNotEvent is a line that is not a valid IF-01 event of either version.
var ErrNotEvent = errors.New("not an IF-01 event")

// v1Source is the v1 event schema's source constraint.
var v1Source = regexp.MustCompile(`^((guard|gateway|connector|token-store)-(a|b)|verification|admission|feed-bridge)$`)

// Ingest takes one log line. A line that is not an IF-01 event is refused with ErrNotEvent.
func (b *Bridge) Ingest(line []byte) error {
	line = bytes.TrimSpace(line)
	if len(line) > MaxLine {
		return ErrNotEvent
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(line))
	if err != nil {
		return ErrNotEvent
	}
	var m meta
	if json.Unmarshal(line, &m) != nil {
		return ErrNotEvent
	}
	schema := b.v1
	if m.Version == 2 {
		schema = b.v2
	}
	if schema.Validate(doc) != nil {
		return ErrNotEvent
	}
	e := stored{seq: m.Seq, source: m.Source, raw: json.RawMessage(append([]byte(nil), line...))}
	e.v1 = downgrade(e.raw, m)
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.runs[m.RunID]
	if r == nil {
		r = &run{panels: map[string]panel{}}
		b.runs[m.RunID] = r
		if b.evicted[m.RunID] { // a run seen again after its eviction starts afresh
			delete(b.evicted, m.RunID)
		}
	} else if m.Seq < r.next {
		return nil // a duplicate
	}
	if len(r.events) > 0 && m.Seq > r.next {
		g := gap(m.RunID, r.next, fmt.Sprintf("events %d to %d never arrived", r.next, m.Seq-1))
		b.add(r, stored{seq: r.next, source: "feed-bridge", raw: g, v1: g})
	}
	b.add(r, e)
	r.next = m.Seq + 1
	r.panels[m.Source] = panel{State: m.Payload.State, ReasonCode: m.Payload.ReasonCode, TS: m.TS}
	b.clock++
	r.touched = b.clock
	b.enforceBudget(m.RunID)
	close(b.changed)
	b.changed = make(chan struct{})
	return nil
}

func (b *Bridge) add(r *run, e stored) {
	size := len(e.raw) + len(e.v1)
	r.events = append(r.events, e)
	r.bytes += size
	b.bytes += size
	if len(r.events) > Buffer {
		drop := r.events[0]
		size := len(drop.raw) + len(drop.v1)
		r.bytes -= size
		b.bytes -= size
		r.events = append([]stored(nil), r.events[1:]...)
	}
}

// enforceBudget drops the least recently updated runs, never keep, until the bytes fit.
func (b *Bridge) enforceBudget(keep string) {
	budget := b.Budget
	if budget <= 0 {
		budget = DefaultBudget
	}
	for b.bytes > budget {
		victim, oldest := "", uint64(0)
		for name, r := range b.runs {
			if name != keep && (victim == "" || r.touched < oldest) {
				victim, oldest = name, r.touched
			}
		}
		if victim == "" {
			return // one run alone is bounded by Buffer and MaxLine
		}
		b.bytes -= b.runs[victim].bytes
		delete(b.runs, victim)
		b.evicted[victim] = true
		b.order = append(b.order, victim)
		if len(b.order) > evictedNames {
			delete(b.evicted, b.order[0])
			b.order = b.order[1:]
		}
	}
}

// downgrade is the v1 form of an event: the event itself for v1, a v2 event without "version" and
// its decision members, or nil when v1 cannot name its source.
func downgrade(raw json.RawMessage, m meta) json.RawMessage {
	if !v1Source.MatchString(m.Source) {
		return nil
	}
	if m.Version != 2 {
		return raw
	}
	var e map[string]any
	if json.Unmarshal(raw, &e) != nil {
		return nil
	}
	delete(e, "version")
	if p, ok := e["payload"].(map[string]any); ok {
		for _, k := range []string{"caller_spiffe_id", "token_subject", "resource", "bundle_revision"} {
			delete(p, k)
		}
		if p["rule_id"] == "not_evaluated" {
			delete(p, "rule_id")
		}
	}
	out, err := json.Marshal(e)
	if err != nil {
		return nil
	}
	return out
}

func gap(runID string, seq uint64, detail string) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{"run_id": runID, "seq": seq, "ts": time.Now().UTC().Format(time.RFC3339Nano), "source": "feed-bridge",
		"kind": "gap", "payload": map[string]string{"state": "gap", "reason_code": "VIS-STALE", "detail": detail}})
	return raw
}

// lookup is a run's state: 200 when held, 410 when evicted, 404 when never seen.
func (b *Bridge) lookup(runID string) (*run, int) {
	if r := b.runs[runID]; r != nil {
		return r, http.StatusOK
	}
	if b.evicted[runID] {
		return nil, http.StatusGone
	}
	return nil, http.StatusNotFound
}

// Snapshot is a run's state as of its last seq in the given feed version, and the HTTP status.
func (b *Bridge) Snapshot(runID string, version int) (map[string]any, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, status := b.lookup(runID)
	if r == nil {
		return nil, status
	}
	panels := map[string]panel{}
	for k, v := range r.panels {
		if version == 2 || v1Source.MatchString(k) {
			panels[k] = v
		}
	}
	snap := map[string]any{"run_id": runID, "as_of_seq": r.next - 1, "panels": panels}
	if version == 2 {
		snap["version"] = 2
	}
	return snap, http.StatusOK
}

// since returns the run's events from seq on in the given version, a gap event first when some are
// no longer kept, the next seq to ask for, a channel closed on the next ingest, and the status.
func (b *Bridge) since(runID string, from uint64, version int) ([]stored, uint64, <-chan struct{}, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, status := b.lookup(runID)
	if r == nil {
		return nil, 0, nil, status
	}
	var out []stored
	if len(r.events) > 0 && from < r.events[0].seq {
		g := gap(runID, from, fmt.Sprintf("events %d to %d are no longer buffered", from, r.events[0].seq-1))
		out = append(out, stored{seq: from, raw: g, v1: g})
	}
	for _, e := range r.events {
		if e.seq >= from && (version == 2 || e.v1 != nil) {
			out = append(out, e)
		}
	}
	if r.next > from {
		from = r.next
	}
	return out, from, b.changed, http.StatusOK
}

// Consume ingests r line by line until EOF. A line longer than MaxLine is drained and counted as
// oversized, a line that is not an IF-01 event as refused; a read error ends it and is returned.
func (b *Bridge) Consume(r io.Reader) (accepted, refused, oversized int, err error) {
	in := bufio.NewReaderSize(r, MaxLine+1)
	for {
		line, isPrefix, err := in.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return accepted, refused, oversized, nil
			}
			return accepted, refused, oversized, err
		}
		if isPrefix {
			oversized++
			for isPrefix && err == nil {
				_, isPrefix, err = in.ReadLine()
			}
			if err != nil && !errors.Is(err, io.EOF) {
				return accepted, refused, oversized, err
			}
			continue
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if b.Ingest(line) != nil {
			refused++
		} else {
			accepted++
		}
	}
}

// ServeHTTP serves the feed in both versions and /ingest.
func (b *Bridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.URL.Path == "/ingest" && r.Method == http.MethodPost {
		accepted, refused, oversized, err := b.Consume(http.MaxBytesReader(w, r.Body, 8<<20))
		if err != nil {
			http.Error(w, "unreadable body", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"accepted": accepted, "refused": refused, "oversized": oversized})
		return
	}
	runID := r.URL.Query().Get("run_id")
	if r.Method != http.MethodGet || runID == "" {
		http.NotFound(w, r)
		return
	}
	version, path := 1, r.URL.Path
	if p, ok := strings.CutPrefix(path, "/v2/"); ok {
		p = "/" + p
		version, path = 2, p
	}
	switch path {
	case "/snapshot":
		snap, status := b.Snapshot(runID, version)
		if snap == nil {
			http.Error(w, http.StatusText(status), status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(snap)
	case "/events":
		from, err := strconv.ParseUint(r.URL.Query().Get("from_seq"), 10, 64)
		if err != nil {
			http.Error(w, "from_seq required", http.StatusBadRequest)
			return
		}
		b.stream(w, r, runID, from, version)
	default:
		http.NotFound(w, r)
	}
}

func (b *Bridge) stream(w http.ResponseWriter, r *http.Request, runID string, from uint64, version int) {
	events, next, changed, status := b.since(runID, from, version)
	if status != http.StatusOK {
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	flusher, _ := w.(http.Flusher)
	for {
		for _, e := range events {
			line := e.raw
			if version == 1 {
				line = e.v1
			}
			if _, err := fmt.Fprintf(w, "id: %d\ndata: %s\n\n", e.seq, line); err != nil {
				return
			}
		}
		if flusher != nil {
			flusher.Flush()
		}
		select {
		case <-r.Context().Done():
			return
		case <-changed:
		}
		events, next, changed, status = b.since(runID, next, version)
		if status != http.StatusOK {
			return // the run was evicted while streaming
		}
	}
}
