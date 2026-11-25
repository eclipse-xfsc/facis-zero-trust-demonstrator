// Package appevents writes application steps using the IF-01 v2 log export contract.
// Like the guard, producers write whole JSON lines for the node collector and feed bridge.
package appevents

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
)

// Sink owns a process run and serializes events, including concurrent requests and lifecycle changes.
type Sink struct {
	mu            sync.Mutex
	w             io.Writer
	source, runID string
	seq           uint64
}

// New accepts only application sources. Run IDs are unique across replicas and restarts.
func New(w io.Writer, source string) (*Sink, error) {
	switch source {
	case "participant-a", "participant-b", "protected-resource-a", "protected-resource-b":
	default:
		return nil, fmt.Errorf("invalid application IF-01 source")
	}
	var id [12]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	return &Sink{w: w, source: source, runID: source + "-" + hex.EncodeToString(id[:])}, nil
}

var reasonPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_\-]{0,120}$`)

// Emit writes a step, never a policy decision. detail must be producer-owned text, not request data.
// Application reason names use underscores; the APP family converts them to IF-01's hyphen syntax.
func (s *Sink) Emit(correlationID, state, reason, detail string) {
	if s == nil {
		return
	}
	code := "APP-UNSPECIFIED"
	if reasonPattern.MatchString(reason) {
		code = "APP-" + strings.ReplaceAll(reason, "_", "-")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if correlationID == "" {
		correlationID = s.runID
	}
	e := hook.Event{Version: 2, RunID: s.runID, Seq: s.seq, TS: time.Now().UTC().Format(time.RFC3339Nano),
		Source: s.source, Kind: "step", CorrelationID: correlationID,
		Payload: hook.EventPayload{State: state, ReasonCode: code, Detail: detail}}
	s.seq++
	if b, err := json.Marshal(e); err == nil {
		_, _ = s.w.Write(append(b, '\n'))
	}
}
