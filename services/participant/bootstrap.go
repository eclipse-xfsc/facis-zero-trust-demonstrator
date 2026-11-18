package participant

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// StateIdle is the lifecycle before a bootstrap starts, after /reset, and permanently in sample mode.
const StateIdle State = "idle"

// Transition reasons. A Bootstrapper's reason is recorded only if it is one of these; anything else is
// recorded as TransitionUnspecified, so upstream text never reaches /state.
const (
	TransitionStepStarted          = "step_started"
	TransitionStepCompleted        = "step_completed"
	TransitionConnectorUnreachable = "connector_unreachable"
	TransitionRegistrationRejected = "registration_rejected"
	TransitionPresentationRejected = "presentation_rejected"
	TransitionTokenRejected        = "token_rejected"
	TransitionNonceRetryExhausted  = "nonce_retry_exhausted"
	TransitionUpstreamError        = "upstream_error"
	TransitionTimeout              = "timeout"
	TransitionBootstrapError       = "bootstrap_error"
	TransitionRetryScheduled       = "retry_scheduled"
	TransitionRetriesExhausted     = "retries_exhausted"
	TransitionReset                = "reset"
	TransitionUnspecified          = "unspecified"
)

var transitionReasons = map[string]bool{
	TransitionStepStarted: true, TransitionStepCompleted: true, TransitionConnectorUnreachable: true,
	TransitionRegistrationRejected: true, TransitionPresentationRejected: true, TransitionTokenRejected: true,
	TransitionNonceRetryExhausted: true, TransitionUpstreamError: true, TransitionTimeout: true,
	TransitionBootstrapError: true, TransitionRetryScheduled: true, TransitionRetriesExhausted: true,
	TransitionReset: true, TransitionUnspecified: true,
}

var knownStates = map[State]bool{
	StateIdle: true, StateRegistering: true, StatePresenting: true, StateAcquiringToken: true, StateReady: true,
	StateFailedRegister: true, StateFailedPresent: true, StateFailedToken: true, StateFailedConnector: true,
}

// failedFor is the failure state of a bootstrap that stopped while in a progress state.
var failedFor = map[State]State{
	StateIdle: StateFailedConnector, StateRegistering: StateFailedRegister,
	StatePresenting: StateFailedPresent, StateAcquiringToken: StateFailedToken, StateReady: StateFailedToken,
}

const (
	defaultBootstrapAttempts = 3
	defaultBootstrapBackoff  = 500 * time.Millisecond
)

// Transition is one recorded state change.
type Transition struct {
	State  State     `json:"state"`
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

// StateSnapshot is the body of GET /state.
type StateSnapshot struct {
	Mode          string       `json:"mode"`
	State         State        `json:"state"`
	Attempt       int          `json:"attempt"`
	LastErrorCode string       `json:"lastErrorCode"`
	History       []Transition `json:"history"`
}

// lifecycle runs the Bootstrapper and records its states. Only connector-unreachable failures are
// retried, up to attempts with doubling backoff; any other failure is final until /reset.
type lifecycle struct {
	boot     Bootstrapper
	attempts int
	backoff  time.Duration
	now      func() time.Time
	logger   *slog.Logger

	resetSlot chan struct{} // 1-slot semaphore serialising resets; acquiring it honours the request context

	mu        sync.Mutex
	base      context.Context
	state     State
	progress  State // last state reported in the current attempt
	attempt   int
	lastError string
	history   []Transition
	session   TokenSession
	done      chan struct{} // closed when the current run ends; nil before Start
	stop      chan struct{} // closed by reset to skip remaining retries; never interrupts a running Run
}

func newLifecycle(boot Bootstrapper, attempts int, backoff time.Duration, now func() time.Time, logger *slog.Logger) *lifecycle {
	if attempts <= 0 {
		attempts = defaultBootstrapAttempts
	}
	if backoff <= 0 {
		backoff = defaultBootstrapBackoff
	}
	return &lifecycle{
		boot: boot, attempts: attempts, backoff: backoff, now: now, logger: logger,
		resetSlot: make(chan struct{}, 1), state: StateIdle, history: []Transition{},
	}
}

// start begins the first bootstrap. ctx bounds every later run too (the process lifetime).
func (l *lifecycle) start(ctx context.Context) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done != nil {
		return
	}
	l.base = ctx
	l.launchLocked()
}

func (l *lifecycle) launchLocked() {
	done, stop := make(chan struct{}), make(chan struct{})
	l.done, l.stop = done, stop
	go l.run(l.base, done, stop)
}

func (l *lifecycle) run(ctx context.Context, done, stop chan struct{}) {
	defer close(done)
	for attempt := 1; ; attempt++ {
		// reset closes stop under l.mu, so deciding here under l.mu means a Run either started before the
		// reset (and reset waits for it) or never starts.
		l.mu.Lock()
		if stopped(stop) || ctx.Err() != nil {
			l.mu.Unlock()
			return
		}
		l.attempt, l.progress = attempt, StateIdle
		l.mu.Unlock()

		session, err := l.boot.Run(ctx, l.report)
		l.mu.Lock()
		if err == nil && session != nil {
			l.session = session
			if l.state != StateReady {
				l.recordLocked(StateReady, TransitionStepCompleted)
			}
			l.mu.Unlock()
			return
		}
		failed := l.progress
		if !isFailed(failed) {
			failed = failedFor[l.progress]
			l.recordLocked(failed, TransitionBootstrapError)
		}
		if failed != StateFailedConnector || attempt >= l.attempts {
			if failed == StateFailedConnector {
				l.recordLocked(failed, TransitionRetriesExhausted)
			}
			l.mu.Unlock()
			return
		}
		l.recordLocked(failed, TransitionRetryScheduled)
		l.mu.Unlock()

		timer := time.NewTimer(l.backoff << (attempt - 1))
		select {
		case <-timer.C:
		case <-stop:
			timer.Stop()
			return
		case <-ctx.Done():
			timer.Stop()
			return
		}
	}
}

// report is the callback handed to the Bootstrapper.
func stopped(stop chan struct{}) bool {
	select {
	case <-stop:
		return true
	default:
		return false
	}
}

func (l *lifecycle) report(state State, reason string) {
	if !knownStates[state] || state == StateIdle {
		return
	}
	if !transitionReasons[reason] {
		reason = TransitionUnspecified
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recordLocked(state, reason)
}

func (l *lifecycle) recordLocked(state State, reason string) {
	l.state, l.progress = state, state
	if isFailed(state) && reason != TransitionRetryScheduled && reason != TransitionRetriesExhausted {
		l.lastError = reason
	}
	l.history = append(l.history, Transition{State: state, Reason: reason, At: l.now()})
	l.logger.Info("participant lifecycle transition", slog.String("state", string(state)), slog.String("reason", reason))
}

// reset waits for an in-flight Run to return (it is never cancelled, so no acquisition is cut short),
// skips any pending retry, clears the lifecycle and starts a fresh bootstrap. It returns the state as it
// was right after the reset, before the new run can change it. It touches no token, replay or key state:
// the lifecycle holds none beyond the TokenSession reference it drops. A reset whose ctx ends while it
// is queued or waiting returns ctx.Err() without clearing anything. A session that renews its own
// token (retirable) is retired first, and a renewal in flight is waited for in the same way.
func (l *lifecycle) reset(ctx context.Context, mode string) (StateSnapshot, error) {
	select {
	case l.resetSlot <- struct{}{}:
	case <-ctx.Done():
		return StateSnapshot{}, ctx.Err()
	}
	defer func() { <-l.resetSlot }()
	if err := ctx.Err(); err != nil {
		return StateSnapshot{}, err
	}

	l.mu.Lock()
	done, stop := l.done, l.stop
	if stop != nil {
		close(stop)
		l.stop = nil
	}
	l.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
		}
	}
	if err := ctx.Err(); err != nil {
		return StateSnapshot{}, err
	}
	// A ready session may be renewing its token outside the run: let it finish, and start no other.
	l.mu.Lock()
	session := l.session
	l.mu.Unlock()
	if r, ok := session.(retirable); ok {
		if err := r.retire(ctx); err != nil {
			return StateSnapshot{}, err
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.session, l.lastError, l.attempt = nil, "", 0
	l.history = []Transition{}
	l.recordLocked(StateIdle, TransitionReset)
	snapshot := l.snapshotLocked(mode)
	if done != nil {
		l.launchLocked()
	}
	return snapshot, nil
}

// retirable is a TokenSession that acquires tokens itself after the bootstrap (ConnectorBootstrap's
// renewals). reset retires it before dropping it: no renewal starts after that, and a running one is
// waited for.
type retirable interface {
	retire(ctx context.Context) error
}

func (l *lifecycle) currentSession() TokenSession {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.session
}

func (l *lifecycle) snapshot(mode string) StateSnapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.snapshotLocked(mode)
}

func (l *lifecycle) snapshotLocked(mode string) StateSnapshot {
	return StateSnapshot{
		Mode: mode, State: l.state, Attempt: l.attempt, LastErrorCode: l.lastError,
		History: append([]Transition{}, l.history...),
	}
}

func isFailed(state State) bool {
	return strings.HasPrefix(string(state), "failed_")
}
