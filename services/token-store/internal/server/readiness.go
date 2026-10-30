package server

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/openbao"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/schema"
)

// The words a readiness check answers with. They are the whole vocabulary of /readyz: fixed, so
// nothing a dependency says, no address and no credential, can reach the body.
const (
	checkOK            = "ok"
	checkUnreachable   = "unreachable"
	checkSchemaBehind  = "schema_behind"
	checkSchemaDrift   = "schema_drift"
	checkUninitialized = "uninitialized"
	checkSealed        = "sealed"
)

// readiness evaluates the store's dependencies within one budget. The checks are fields so the
// evaluation is tested with fakes and no database.
type readiness struct {
	timeout  time.Duration
	postgres func(context.Context) string
	openbao  func(context.Context) string
	// state is what the last evaluation found: 0 nothing yet, 1 ready, 2 not ready. Only a change
	// is logged, so a long outage is one line, not one per probe.
	state atomic.Int32
	// draining is set once the service was asked to stop: not ready from then on, whatever the
	// dependencies say, so routing moves away from the pod while its listeners are still open.
	draining atomic.Bool
	// inflight is the evaluation running now, shared by every caller that arrives meanwhile.
	mu       sync.Mutex
	inflight *evaluation
}

type evaluation struct {
	done chan struct{}
	rep  report
}

// checks are the words of one evaluation.
type checks struct {
	Postgres string `json:"postgres"`
	OpenBao  string `json:"openbao"`
}

// report is the body of /readyz. A draining service answers without checks: it asked nothing.
type report struct {
	Ready    bool    `json:"ready"`
	Draining bool    `json:"draining,omitempty"`
	Checks   *checks `json:"checks,omitempty"`
}

// drain makes every /readyz from now on a 503, without asking the dependencies.
func (r *readiness) drain() { r.draining.Store(true) }

// evaluate returns the dependencies' state. One evaluation runs at a time and callers that arrive
// while it runs share its result, so a burst of /readyz on the published port costs one
// connection and one key-value store call rather than one each, and the kubelet's own probe never
// queues behind a caller's. The evaluation runs under its own budget, detached from the first
// caller's cancellation but carrying its request identifiers. A caller that goes away before it
// ends learns nothing: both words are unreachable, and the handler records no transition for it.
func (r *readiness) evaluate(ctx context.Context) report {
	r.mu.Lock()
	ev := r.inflight
	if ev == nil {
		ev = &evaluation{done: make(chan struct{})}
		r.inflight = ev
		go func() {
			ev.rep = r.run(context.WithoutCancel(ctx))
			r.mu.Lock()
			r.inflight = nil
			r.mu.Unlock()
			close(ev.done)
		}()
	}
	r.mu.Unlock()
	select {
	case <-ev.done:
		return ev.rep
	case <-ctx.Done():
		return report{Checks: &checks{Postgres: checkUnreachable, OpenBao: checkUnreachable}}
	}
}

// run asks both dependencies at once under the budget. A check that has not answered when the
// budget ends counts as unreachable; the run never outlives the budget, whatever a check does.
func (r *readiness) run(ctx context.Context) report {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	postgres := make(chan string, 1)
	openbao := make(chan string, 1)
	go func() { postgres <- r.postgres(ctx) }()
	go func() { openbao <- r.openbao(ctx) }()
	c := &checks{}
	c.Postgres = await(ctx, postgres)
	c.OpenBao = await(ctx, openbao)
	return report{Ready: c.Postgres == checkOK && c.OpenBao == checkOK, Checks: c}
}

func await(ctx context.Context, answer <-chan string) string {
	select {
	case w := <-answer:
		return w
	case <-ctx.Done():
		// The budget is over. A check that answered in the meantime still counts, its word is
		// waiting in the channel; only a check still running is unreachable.
		select {
		case w := <-answer:
			return w
		default:
			return checkUnreachable
		}
	}
}

// changed records the outcome and reports whether it differs from the last one.
func (r *readiness) changed(rep report) bool {
	state := int32(2)
	if rep.Ready {
		state = 1
	}
	return r.state.Swap(state) != state
}

// checkPostgres acquires a pooled connection and reads the schema's status over it: reaching the
// database and reading it are one check, and the status is read-only and takes no lock. A
// database that is there but cannot be read is unreachable for a store that fails closed.
func (s *Server) checkPostgres(ctx context.Context) string {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		s.log.WarnContext(ctx, "database unreachable", "err", err)
		return checkUnreachable
	}
	defer conn.Release()
	runner, err := schema.NewRunnerWith(conn.Conn(), s.migrations)
	if err != nil {
		s.log.WarnContext(ctx, "schema runner", "err", err)
		return checkUnreachable
	}
	status, err := runner.Status(ctx)
	if err != nil {
		s.log.WarnContext(ctx, "schema status unreadable", "err", err)
		return checkUnreachable
	}
	switch {
	case len(status.Drift) > 0:
		return checkSchemaDrift
	case status.Current < status.Latest:
		return checkSchemaBehind
	}
	return checkOK
}

// checkOpenBao asks the key-value store whether it is initialised and unsealed; a standby is
// fine. The request forwards the identifiers of the request being served, when there is one.
func (s *Server) checkOpenBao(ctx context.Context) string {
	var propagate http.Header
	if f, ok := fieldsFrom(ctx); ok {
		propagate = f.outbound()
	}
	state, err := openbao.Health(ctx, s.client, s.openBaoURL, propagate)
	if err != nil {
		s.log.WarnContext(ctx, "key-value store unreachable", "err", err)
		return checkUnreachable
	}
	switch {
	case !state.Initialized:
		return checkUninitialized
	case state.Sealed:
		return checkSealed
	}
	return checkOK
}

// handleHealthz says the process is alive. It consults nothing, so no dependency outage ever
// restarts the pod.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// handleReadyz answers 200 only when every dependency is reachable and in the state the store
// needs and the service is not stopping, 503 otherwise, with the checks' words as the body.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	var rep report
	if s.ready.draining.Load() {
		// Stopping: not ready whatever the dependencies say, so they are not asked, and nothing
		// of theirs is recorded.
		rep.Draining = true
	} else {
		rep = s.ready.evaluate(r.Context())
		switch {
		case r.Context().Err() != nil:
			// The caller went away, or the write deadline passed, before the evaluation ended:
			// the words are not the dependencies' and record no transition.
		case s.ready.changed(rep):
			if rep.Ready {
				s.log.InfoContext(r.Context(), "ready")
			} else {
				s.log.WarnContext(r.Context(), "not ready", "postgres", rep.Checks.Postgres, "openbao", rep.Checks.OpenBao)
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if !rep.Ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(rep)
}
