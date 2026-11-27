// Package renew renews upstream tokens before they expire, once per token however many store
// replicas run (design D11): a worker claims a due token with FOR UPDATE SKIP LOCKED and records the
// claim (claimed_by, claimed_at), the fence; the replacement commits only while that fence still
// holds; a claim whose worker died is released by a staleness sweep. It also schedules the orphan
// sweep of acquisition (D10).
package renew

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire"
)

// Defaults of a Worker's zero fields. A renewal lasts at most Attempts acquisitions of
// attemptTimeout each (a settling activation may add settleWait), with the backoff between them, far
// below StaleAfter: a live worker's claim is never taken as stale.
const (
	DefaultEvery       = 15 * time.Second
	DefaultBatch       = 4
	DefaultAttempts    = 3
	DefaultBackoff     = 2 * time.Second // doubled after each failed attempt
	DefaultStaleAfter  = 5 * time.Minute
	DefaultOrphanEvery = 5 * time.Minute

	attemptTimeout = 30 * time.Second
	opTimeout      = 5 * time.Second
	orphanTimeout  = 2 * time.Minute
)

// Reason codes the worker writes on its audit rows. Each acquisition attempt is audited by
// acquisition itself, with the row it replaces in its detail.
const (
	CodeNoRoute      = "REN-NO-ROUTE"      // the row's route is not configured: nothing to renew with
	CodeNotAutomated = "REN-NOT-AUTOMATED" // the route has no outcome source: nothing presents for it unattended
	CodeClaimStale   = "REN-CLAIM-STALE"   // a claim older than StaleAfter was released
	CodeExpired      = "REN-EXPIRED"       // a stale claim on an expired token: failed
	CodeClaimLost    = acquire.CodeClaimLost
)

// Worker renews the due tokens of the store's database. Run it in every replica; Instance tells the
// replicas apart.
type Worker struct {
	DB       *pgxpool.Pool
	Acquirer *acquire.Acquirer
	Routes   acquire.Loaded
	Instance string // claimed_by

	Every, Backoff, StaleAfter, OrphanEvery time.Duration
	Attempts, Batch                         int
	Now                                     func() time.Time
	Log                                     *slog.Logger
}

// Claim is a claimed token and its fence.
type Claim struct {
	PeerZone, Audience, Tenant string
	Fence                      acquire.Fence
}

// Run renews every Every and sweeps orphans every OrphanEvery until ctx ends.
func (w *Worker) Run(ctx context.Context) {
	cycle := time.NewTicker(or(w.Every, DefaultEvery))
	defer cycle.Stop()
	orphans := time.NewTicker(or(w.OrphanEvery, DefaultOrphanEvery))
	defer orphans.Stop()
	w.Cycle(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-cycle.C:
			w.Cycle(ctx)
		case <-orphans.C:
			sctx, cancel := context.WithTimeout(ctx, orphanTimeout)
			if n, err := w.Acquirer.SweepOrphans(sctx); err != nil && ctx.Err() == nil {
				w.log().WarnContext(ctx, "orphan sweep failed", "deleted", n)
			}
			cancel()
		}
	}
}

// Cycle releases stale claims, then claims and renews due tokens one at a time, up to Batch, so a
// claim is never older than the renewal it is for.
func (w *Worker) Cycle(ctx context.Context) {
	if err := w.releaseStale(ctx); err != nil && ctx.Err() == nil {
		w.log().WarnContext(ctx, "stale renewal claims not released")
	}
	for range or(w.Batch, DefaultBatch) {
		claims, err := w.claim(ctx, 1)
		if err != nil {
			if ctx.Err() == nil {
				w.log().WarnContext(ctx, "renewal claim failed")
			}
			return
		}
		if len(claims) == 0 {
			return
		}
		for _, c := range claims {
			w.renew(ctx, c)
		}
	}
}

// claim takes up to n due tokens: active, unclaimed and past renew_after. Rows another worker is
// claiming at this moment are skipped, not waited for; the outer conditions repeat the inner ones so
// a row that changed meanwhile is never claimed twice. The due rows are a materialized CTE so the
// locking subquery runs once: as an IN semi-join it can be rescanned per row and claim more than n.
func (w *Worker) claim(ctx context.Context, n int) ([]Claim, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	rows, err := w.DB.Query(ctx, `WITH due AS MATERIALIZED (SELECT token_id FROM upstream_token
			WHERE state = 'active' AND claimed_at IS NULL AND renew_after <= $2
			ORDER BY renew_after FOR UPDATE SKIP LOCKED LIMIT $3)
		UPDATE upstream_token t SET state = 'renewing', claimed_by = $1, claimed_at = $2, updated_at = $2
		FROM due WHERE t.token_id = due.token_id AND t.state = 'active' AND t.claimed_at IS NULL
		RETURNING t.token_id::text, t.peer_zone, t.audience, t.tenant, t.claimed_by, t.claimed_at`, w.Instance, w.now(), n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Claim
	for rows.Next() {
		var c Claim
		if err := rows.Scan(&c.Fence.TokenID, &c.PeerZone, &c.Audience, &c.Tenant, &c.Fence.ClaimedBy, &c.Fence.ClaimedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// renew replaces c's token with bounded attempts and backoff, each a fresh challenge and outcome.
// A lost claim ends it; the last failure marks the row failed, if the claim still holds.
//
// Every renewal presents a credential again, and only the route's outcome source can do that
// without a person: a route that has none is not eligible for renewal and its row fails at once,
// with no attempt. An attempt whose outcome says the credential is revoked is the last one: the
// answer is signed and for this request, and asking again would only present the same credential.
// Every other failure is retried, an outcome source that cannot be reached or does not answer
// among them.
func (w *Worker) renew(ctx context.Context, c Claim) {
	route, ok := w.Routes.For(c.PeerZone, c.Audience, c.Tenant)
	if !ok {
		w.fail(ctx, c, "", CodeNoRoute, "")
		return
	}
	if route.Outcomes == nil {
		w.fail(ctx, c, route.Name, CodeNotAutomated, "")
		return
	}
	code, cause := "", ""
	backoff := or(w.Backoff, DefaultBackoff)
	for i := range or(w.Attempts, DefaultAttempts) {
		if i > 0 {
			select {
			case <-time.After(backoff):
				backoff *= 2
			case <-ctx.Done():
				return // the claim stays for the staleness sweep
			}
		}
		if held, err := w.held(ctx, c); err != nil || !held {
			if err == nil {
				w.lost(ctx, c)
			}
			return
		}
		actx, cancel := context.WithTimeout(ctx, attemptTimeout)
		tok, err := w.Acquirer.Replace(actx, route, c.Fence)
		cancel()
		if err == nil {
			w.log().InfoContext(ctx, "upstream token renewed", "route", route.Name, "token_id", tok.ID, "replaces", c.Fence.TokenID)
			return
		}
		code, cause = acquire.CodeStore, ""
		var e *acquire.Error
		if errors.As(err, &e) {
			code, cause = e.Code, e.Cause
		}
		if code == acquire.CodeClaimLost {
			w.lost(ctx, c)
			return
		}
		if ctx.Err() != nil {
			return
		}
		if terminal(cause) {
			break
		}
	}
	w.fail(ctx, c, route.Name, code, cause)
}

// terminal reports whether an attempt that failed for cause settles the renewal: another attempt
// could not end differently. A revoked credential does (a suspended one reads as revoked); a status
// list that could not be read, or a credential the verifier could not accept, may be the
// verifier's side passing, and keeps its attempts.
func terminal(cause string) bool { return cause == if03.CodeRevoked }

// held reports whether c's fence still holds.
func (w *Worker) held(ctx context.Context, c Claim) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	var held bool
	err := w.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM upstream_token
		WHERE token_id = $1 AND state = 'renewing' AND claimed_by = $2 AND claimed_at = $3)`,
		c.Fence.TokenID, c.Fence.ClaimedBy, c.Fence.ClaimedAt).Scan(&held)
	return held, err
}

// fail marks c's row failed, terminal, only while c's fence holds, and audits it in the same
// statement. cause is the last attempt's (acquire.Error's Cause) and is recorded when there is one;
// route is the configured route's name, empty when the row has none, and goes into the record so
// that a failure no acquisition attempt has logged still says which route it is.
func (w *Worker) fail(ctx context.Context, c Claim, route, code, cause string) {
	ctx2, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	tag, err := w.DB.Exec(ctx2, `WITH f AS (UPDATE upstream_token SET state = 'failed', updated_at = $4
			WHERE token_id = $1 AND state = 'renewing' AND claimed_by = $2 AND claimed_at = $3 RETURNING token_id)
		INSERT INTO audit_event (kind, token_id, reason_code, detail)
		SELECT 'renewal.failed', token_id, $5, jsonb_strip_nulls(jsonb_build_object(
			'peer_zone', $6::text, 'audience', $7::text, 'instance', $2::text, 'cause', NULLIF($8::text, ''))) FROM f`,
		c.Fence.TokenID, c.Fence.ClaimedBy, c.Fence.ClaimedAt, w.now(), code, c.PeerZone, c.Audience, cause)
	switch {
	case err != nil:
		w.log().WarnContext(ctx, "renewal failure not recorded; the claim stays for the staleness sweep", "token_id", c.Fence.TokenID)
	case tag.RowsAffected() == 0:
		w.lost(ctx, c)
	default:
		record := []any{"token_id", c.Fence.TokenID, "peer_zone", c.PeerZone, "audience", c.Audience, "reason_code", code}
		if route != "" {
			record = append(record, "route", route)
		}
		w.log().WarnContext(ctx, "upstream token renewal failed; token failed", acquire.WithCause(record, cause)...)
	}
}

// lost records that c's claim no longer held: another worker released or took it.
func (w *Worker) lost(ctx context.Context, c Claim) {
	w.log().InfoContext(ctx, "renewal claim lost; result discarded", "token_id", c.Fence.TokenID, "reason_code", CodeClaimLost)
	ctx2, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	_, _ = w.DB.Exec(ctx2, `INSERT INTO audit_event (kind, token_id, reason_code, detail) VALUES ('renewal.claim_lost', $1, $2,
		jsonb_build_object('instance', $3::text))`, c.Fence.TokenID, CodeClaimLost, c.Fence.ClaimedBy)
}

// releaseStale releases the claims older than StaleAfter, whose workers are taken to be dead: back
// to active when the token is still valid (it is due, so the next claim renews it), failed when it
// has expired. Each release is audited in the same statement.
func (w *Worker) releaseStale(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	now := w.now()
	_, err := w.DB.Exec(ctx, `WITH s AS (UPDATE upstream_token SET
			state = CASE WHEN expires_at > $1 THEN 'active' ELSE 'failed' END,
			claimed_by = CASE WHEN expires_at > $1 THEN NULL ELSE claimed_by END,
			claimed_at = CASE WHEN expires_at > $1 THEN NULL ELSE claimed_at END,
			updated_at = $1
		WHERE state = 'renewing' AND claimed_at <= $2
		RETURNING token_id, state)
		INSERT INTO audit_event (kind, token_id, reason_code)
		SELECT CASE state WHEN 'active' THEN 'renewal.released' ELSE 'renewal.failed' END, token_id,
			CASE state WHEN 'active' THEN $3 ELSE $4 END FROM s`,
		now, now.Add(-or(w.StaleAfter, DefaultStaleAfter)), CodeClaimStale, CodeExpired)
	return err
}

func (w *Worker) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func (w *Worker) log() *slog.Logger {
	if w.Log != nil {
		return w.Log
	}
	return slog.New(slog.DiscardHandler)
}

func or[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}
