package hook

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Decider answers one policy input: the policy engine, or the fixtures here.
type Decider interface {
	Decide(ctx context.Context, in Input) (Decision, error)
}

// Authenticator turns the caller's credential headers into the authenticated token of the policy
// input. The guard verifies the token before policy is asked; here only the result is needed.
type Authenticator interface {
	Authenticate(authorization, dpop string) Token
}

// SubstituteRequest is what the guard asks the token store for when an allow carries the
// substitution obligation (token-store API, /internal/substitute).
type SubstituteRequest struct {
	PeerZone      string  `json:"peer_zone"`
	Audience      string  `json:"audience"`
	Tenant        *string `json:"tenant"`
	Method        string  `json:"method"`
	TargetURI     string  `json:"target_uri"`
	CorrelationID string  `json:"correlation_id"`
}

// Substitution is the token store's answer: the upstream credential and a proof minted for
// exactly the upstream method and URI.
type Substitution struct {
	Authorization string
	DPoP          string
}

// Substituter is the token store as the guard sees it.
type Substituter interface {
	Substitute(ctx context.Context, req SubstituteRequest) (Substitution, error)
}

// RefusalError is a substitution the token store refused, with the reason code it answered.
type RefusalError struct {
	ReasonCode string
}

func (e *RefusalError) Error() string { return "substitution refused: " + e.ReasonCode }

// StaticSubstituter answers every substitution with the same values; it stands in for the token
// store in the verification.
type StaticSubstituter Substitution

// Substitute implements Substituter.
func (s StaticSubstituter) Substitute(context.Context, SubstituteRequest) (Substitution, error) {
	return Substitution(s), nil
}

// Request is one request as a filter hands it to the guard.
type Request struct {
	Method string
	Scheme string
	Host   string
	Path   string
	// Headers are the request headers; keys are canonical.
	Headers http.Header
	// PeerID is the caller's SPIFFE ID when the transport authenticated one, else empty.
	PeerID string
}

// Config is what the guard knows about its zone.
type Config struct {
	// PublishedBaseURL is the scheme and host the guard is reached at; the upstream proof is
	// minted for it plus the route path, never for what the caller's headers say.
	PublishedBaseURL string
	// PeerZone and Audience name the upstream the token store substitutes for.
	PeerZone string
	Audience string
	// SourceID is the caller identity used when the transport authenticated none.
	SourceID string
	// DecisionTimeout bounds one policy decision; zero means unbounded.
	DecisionTimeout time.Duration
}

// Guard evaluates requests.
type Guard struct {
	cfg    Config
	decide Decider
	auth   Authenticator
	subst  Substituter
	events EventSink
	newID  func() string
}

// New returns a guard. events may be nil.
func New(cfg Config, d Decider, a Authenticator, s Substituter, events EventSink) *Guard {
	return &Guard{cfg: cfg, decide: d, auth: a, subst: s, events: events, newID: newRequestID}
}

// SetIDGenerator replaces the request-id source (tests).
func (g *Guard) SetIDGenerator(f func() string) { g.newID = f }

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// forwardedHeaders are removed from a request that arrives from outside the mesh: only the mesh
// ingress may set them, and the proof's htu is rebuilt from configuration.
var forwardedHeaders = []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded"}

// Evaluate decides one request. It never returns an error: a failure anywhere is a refusal with
// its reason code, so the request is denied rather than forwarded.
func (g *Guard) Evaluate(ctx context.Context, req Request) Outcome {
	id := g.newID()
	method := strings.ToUpper(req.Method)
	path, _, _ := strings.Cut(req.Path, "?")
	if path == "" {
		path = "/"
	}
	source := req.PeerID
	if source == "" {
		source = g.cfg.SourceID
	}
	in := Input{
		CorrelationID: id,
		Source:        Source{SPIFFEID: source},
		Request:       RequestInfo{Method: method, Path: path, Host: req.Host},
		Token:         g.auth.Authenticate(req.Headers.Get("Authorization"), req.Headers.Get("DPoP")),
	}

	if g.cfg.DecisionTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, g.cfg.DecisionTimeout)
		defer cancel()
	}
	dec, err := g.decide.Decide(ctx, in)
	if err == nil {
		err = dec.Validate()
	}
	if err != nil {
		return g.refuse(id, Refusal{Error: "policy_unavailable", ReasonCode: ReasonPDPUnavailable}, err.Error())
	}
	if !dec.Allow {
		return g.refuse(id, Refusal{Error: dec.DenyBody.Error, ReasonCode: dec.ReasonCode, RuleID: dec.RuleID, OID4VPLink: dec.DenyBody.OID4VPLink}, "")
	}

	set := []Header{{HeaderRequestID, id}}
	remove := append([]string(nil), forwardedHeaders...)
	for name := range req.Headers {
		if IsFacisHeader(name) {
			remove = append(remove, name)
		}
	}
	if dec.Substitutes() {
		sub, err := g.subst.Substitute(ctx, SubstituteRequest{
			PeerZone: g.cfg.PeerZone, Audience: g.cfg.Audience, Method: method,
			TargetURI: g.cfg.PublishedBaseURL + path, CorrelationID: id,
		})
		if err != nil {
			var refusal *RefusalError
			if errors.As(err, &refusal) {
				return g.refuse(id, Refusal{Error: "substitution_refused", ReasonCode: refusal.ReasonCode}, err.Error())
			}
			return g.refuse(id, Refusal{Error: "token_store_unavailable", ReasonCode: ReasonTokenStoreUnavailable}, err.Error())
		}
		set = append(set, Header{"Authorization", sub.Authorization}, Header{"DPoP", sub.DPoP})
	} else {
		remove = append(remove, "Authorization", "DPoP")
	}
	g.emit(id, EventPayload{State: "allowed", RuleID: dec.RuleID})
	return Outcome{Allowed: true, CorrelationID: id, RuleID: dec.RuleID, SetHeaders: sortHeaders(set), RemoveHeaders: sortNames(remove)}
}

// refuse builds the refusal the caller receives and records the denial.
func (g *Guard) refuse(id string, r Refusal, detail string) Outcome {
	body, err := json.Marshal(r)
	if err != nil { // a Refusal holds strings only
		panic(err)
	}
	if len(detail) > 512 {
		detail = detail[:512]
	}
	g.emit(id, EventPayload{State: "denied", ReasonCode: r.ReasonCode, RuleID: r.RuleID, Detail: detail})
	return Outcome{
		Allowed: false, CorrelationID: id, Status: StatusFor(r.ReasonCode), ReasonCode: r.ReasonCode, RuleID: r.RuleID,
		SetHeaders: sortHeaders([]Header{{"Content-Type", ContentTypeJSON}, {HeaderReasonCode, r.ReasonCode}, {HeaderRequestID, id}}),
		Body:       body,
	}
}

func (g *Guard) emit(id string, p EventPayload) {
	if g.events != nil {
		g.events.Emit(id, p)
	}
}

func sortHeaders(h []Header) []Header {
	for i := range h {
		h[i].Name = strings.ToLower(h[i].Name)
	}
	sort.Slice(h, func(i, j int) bool { return h[i].Name < h[j].Name })
	return h
}

func sortNames(names []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n = strings.ToLower(n); !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// Event is one security-state event (docs/contracts/if01-event.v1.schema.json), written as a
// JSON log line. The guard emits a decision event per request; it carries no token.
type Event struct {
	RunID         string       `json:"run_id"`
	Seq           uint64       `json:"seq"`
	TS            string       `json:"ts"`
	Source        string       `json:"source"`
	Kind          string       `json:"kind"`
	CorrelationID string       `json:"correlation_id,omitempty"`
	Payload       EventPayload `json:"payload"`
}

// EventPayload is the state a decision event reports.
type EventPayload struct {
	State      string `json:"state"`
	ReasonCode string `json:"reason_code,omitempty"`
	RuleID     string `json:"rule_id,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

// EventSink receives the guard's decision events.
type EventSink interface {
	Emit(correlationID string, p EventPayload)
}

// LogSink writes decision events as JSON lines, one per call, numbered per source.
type LogSink struct {
	mu     sync.Mutex
	w      io.Writer
	source string
	runID  string
	seq    uint64
}

// NewLogSink returns a sink writing to w for the given source (for example guard-a) and run.
func NewLogSink(w io.Writer, source, runID string) *LogSink {
	return &LogSink{w: w, source: source, runID: runID}
}

// Emit implements EventSink.
func (s *LogSink) Emit(correlationID string, p EventPayload) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := Event{RunID: s.runID, Seq: s.seq, TS: time.Now().UTC().Format(time.RFC3339Nano), Source: s.source,
		Kind: "decision", CorrelationID: correlationID, Payload: p}
	s.seq++
	if b, err := json.Marshal(e); err == nil {
		_, _ = s.w.Write(append(b, '\n'))
	}
}

// ReadEvent returns the first decision event in r with the given correlation id, or nil.
func ReadEvent(r io.Reader, correlationID string) (*Event, error) {
	dec := json.NewDecoder(r)
	for {
		var e Event
		if err := dec.Decode(&e); err != nil {
			if errors.Is(err, io.EOF) {
				return nil, nil
			}
			return nil, fmt.Errorf("events: %w", err)
		}
		if e.CorrelationID == correlationID {
			return &e, nil
		}
	}
}
