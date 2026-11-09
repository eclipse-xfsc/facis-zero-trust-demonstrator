package server

import (
	"context"
	"errors"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire"
)

// Startup resolution of the signing keys: the contract's "every active key reference resolves",
// asserted before the store is ready rather than discovered at the first call. Each attempt has
// its own budget; attempts repeat with a growing pause while a dependency is away.
const (
	startupAttempt    = 5 * time.Second
	startupBackoffMin = time.Second
	startupBackoffMax = 30 * time.Second
)

// The records startup writes. Named once, so the tests and the lifecycle proof look for the same
// words the service writes.
const (
	msgKeysResolved      = "signing keys resolved"
	msgKeysUnavailable   = "startup signing key unavailable"
	msgKeysMisconfigured = "signing key misconfigured; stopping"
	msgKeyNewer          = "transit key is newer than the registered version; run token-store keys rotate"
	msgKeyForeign        = "an active row of another key cannot be read with this token; retire it or grant read on that key"
)

// misconfigured is a startup failure the service cannot wait out: its reason word (acquire.Reason),
// the row it concerns when one does, and the error behind it. Error names the reason only.
type misconfigured struct {
	reason string
	ref    string
	err    error
}

func (e *misconfigured) Error() string { return "signing key misconfigured: " + e.reason }
func (e *misconfigured) Unwrap() error { return e.err }

// reasonOf is the reason word of a startup failure, unreachable for anything else.
func reasonOf(err error) string {
	var m *misconfigured
	if errors.As(err, &m) {
		return m.reason
	}
	return acquire.ReasonUnreachable
}

// refError carries the signing_key row an error is about.
type refError struct {
	ref string
	err error
}

func (e *refError) Error() string { return e.err.Error() }
func (e *refError) Unwrap() error { return e.err }

// startKeys resolves the store's keys until they resolve, ctx ends, or a misconfiguration is
// found, which it returns. An outage is retried with a backoff from startupBackoffMin to
// startupBackoffMax and is logged once per change of reason, not per attempt; success is logged
// once with what resolved.
func (s *Server) startKeys(ctx context.Context) error {
	name := s.cfg.Acquisition.SigningKey
	backoff := startupBackoffMin
	lastReason := ""
	for attempt := 1; ; attempt++ {
		actx, cancel := context.WithTimeout(ctx, startupAttempt)
		ref, active, err := s.assertKeys(actx)
		cancel()
		if err == nil {
			s.log.InfoContext(ctx, msgKeysResolved, "key", name, "key_ref", ref, "active_references", active,
				"attempts", attempt)
			return nil
		}
		if ctx.Err() != nil {
			return nil // asked to stop while waiting: not a finding
		}
		reason, permanent := acquire.Reason(err)
		if permanent {
			var re *refError
			if errors.As(err, &re) {
				ref = re.ref
			}
			return &misconfigured{reason: reason, ref: ref, err: err}
		}
		if reason != lastReason {
			s.log.WarnContext(ctx, msgKeysUnavailable, "key", name, "reason", reason)
			lastReason = reason
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, startupBackoffMax)
	}
}

// assertKeys is one attempt: the configured key's active signing_key row is registered or verified
// and is not below transit's signing floor (a key with no row and no transit key yet is created
// here, the one place in the service that may; a key with rows is never recreated), every active
// row of every key resolves to a version of the key it names with its thumbprint, and transit's
// latest version is noted when it is newer than the registered one. It returns the registered
// reference and the number of active rows; on a failure that concerns one row, the error carries
// that row (refError).
func (s *Server) assertKeys(ctx context.Context) (string, int, error) {
	name := s.cfg.Acquisition.SigningKey
	key, err := acquire.LoadKey(ctx, s.pool, s.cfg.OpenBao, name)
	if err != nil {
		// A fault of the configured key's own row carries that row into the record.
		if _, permanent := acquire.Reason(err); permanent {
			var ref string
			if s.pool.QueryRow(ctx, `SELECT key_ref FROM signing_key WHERE state = 'active' AND split_part(key_ref, ':', 2) = $1`, name).Scan(&ref) == nil {
				return "", 0, &refError{ref: ref, err: err}
			}
		}
		return "", 0, err
	}
	registered, _ := transit.ParseRef(key.Ref())
	latest, _, err := s.cfg.OpenBao.KeyStatus(ctx, name)
	if err != nil {
		return key.Ref(), 0, err
	}
	refs, err := s.activeRefs(ctx)
	if err != nil {
		return key.Ref(), 0, err
	}
	// Another key's row, unreadable with a token scoped to this store's key: the row's owner
	// retires it, or an operator does; it is not this key's misconfiguration.
	if _, ref, err := s.foreignRefs(ctx, refs, name, func(ref string) { s.log.WarnContext(ctx, msgKeyForeign, "key_ref", ref) }); err != nil {
		return key.Ref(), 0, &refError{ref: ref, err: err}
	}
	if latest.Version > registered.Version {
		s.log.WarnContext(ctx, msgKeyNewer, "key", name, "key_ref", key.Ref(), "latest_version", latest.Version)
	}
	return key.Ref(), len(refs), nil
}
