// Package substitute hands the guard the upstream credential of an authorized route: the route's
// live upstream token and a fresh DPoP proof for exactly the upstream request, signed by the store
// key the token is bound to. The caller's own proof is never forwarded (token-store.v1, substitute).
package substitute

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/caller"
)

// OpTimeout bounds every single database, key-value store and transit operation of a substitution.
// An on-demand acquisition is bounded by the caller's deadline instead.
const OpTimeout = 2 * time.Second

// MaxAcquiring is how many on-demand acquisitions, over all routes, run at once in one process.
// Each holds at most two pooled connections (its route lock and one acquisition statement or
// transaction), so the pool keeps capacity for the replay check, readiness, lookups and renewal
// whatever the number of cold routes; the pool is sized for it (internal/server).
const MaxAcquiring = 2

// ExpiryMargin is how long a handed-out token must still be valid when the answer leaves: the
// value read and the proof signed after the lookup take time, and the guard still has to send it.
const ExpiryMargin = time.Second

var (
	ErrNoUpstream  = errors.New("TOK-NO-UPSTREAM")
	ErrUnavailable = errors.New("TOK-STORE-UNAVAILABLE")
)

// Request is an authorized substitution: the route, the upstream request and the upstream's nonce.
type Request struct {
	PeerZone, Audience, Tenant string
	Method, TargetURI          string // TargetURI as caller.Target accepts it
	Nonce                      string // the upstream's DPoP-Nonce, or empty
}

// Result is what the guard sets on the upstream request.
type Result struct {
	Authorization string // "DPoP " + the token
	DPoP          string
	ExpiresAt     time.Time
	TokenID       string
}

// Service substitutes. Safe for concurrent use.
type Service struct {
	DB      *pgxpool.Pool
	Signer  transit.Signer
	Secrets transit.Secrets
	// Routes are the acquisition routes; Acquirer acquires a route's token when it has no live one.
	// A nil Acquirer never acquires.
	Routes   acquire.Loaded
	Acquirer *acquire.Acquirer
	Log      *slog.Logger
	Now      func() time.Time

	mu        sync.Mutex
	gates     map[string]chan struct{} // one per route: in-process single flight of on-demand acquisition
	acquiring chan struct{}            // MaxAcquiring slots over all routes
	keys      map[string]*acquire.Key  // by key_ref; a version's public key never changes
}

// tokenPattern is the contract's authorization value without its scheme: a value from the key-value
// store that is anything else never reaches a header.
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)

// Substitute returns the route's live token and a proof for req. ErrNoUpstream when the route has no
// live, unexpired token and none could be acquired, or when the token found expires within
// ExpiryMargin of the answer; ErrUnavailable when a dependency failed. The
// request must already be authorized: nothing here decides who may ask.
func (s *Service) Substitute(ctx context.Context, req Request) (Result, error) {
	origin, path, err := caller.Target(req.TargetURI)
	if err != nil {
		return Result{}, caller.ErrRouteDenied
	}
	tok, err := s.lookup(ctx, s.DB, req)
	if errors.Is(err, pgx.ErrNoRows) {
		tok, err = s.acquireOnDemand(ctx, req)
	} else if err != nil {
		err = s.unavailable(ctx, "upstream token lookup failed")
	}
	if err != nil {
		return Result{}, err
	}

	opCtx, cancel := context.WithTimeout(ctx, OpTimeout)
	defer cancel()
	value, err := s.Secrets.Read(opCtx, tok.ref)
	if err != nil {
		return Result{}, s.unavailable(ctx, "upstream token value unreadable")
	}
	if !tokenPattern.Match(value) {
		return Result{}, s.unavailable(ctx, "upstream token value malformed")
	}
	key, err := s.key(ctx, tok.keyRef, tok.jkt)
	if err != nil {
		return Result{}, s.unavailable(ctx, "store key unavailable")
	}
	ath := sha256.Sum256(value)
	signCtx, cancelSign := context.WithTimeout(ctx, OpTimeout)
	defer cancelSign()
	proof, err := dpopproof.Build(signCtx, key, dpopproof.Claims{HTM: req.Method, HTU: origin + path,
		ATH: base64.RawURLEncoding.EncodeToString(ath[:]), Nonce: req.Nonce})
	if err != nil {
		return Result{}, s.unavailable(ctx, "proof not signed")
	}
	// Expiry was judged at the lookup; reading the value and signing took time since. A token that
	// has expired, or is about to, is discarded rather than handed out, and not reacquired here:
	// the caller retries, and the next lookup finds no live row and acquires.
	if !s.now().Add(ExpiryMargin).Before(tok.expiresAt) {
		s.log().WarnContext(ctx, "no upstream token: it expired during substitution", "peer_zone", req.PeerZone,
			"audience", req.Audience, "token_id", tok.id)
		return Result{}, ErrNoUpstream
	}
	s.log().InfoContext(ctx, "upstream token substituted", "peer_zone", req.PeerZone, "audience", req.Audience,
		"token_id", tok.id)
	return Result{Authorization: "DPoP " + string(value), DPoP: proof, ExpiresAt: tok.expiresAt, TokenID: tok.id}, nil
}

type live struct {
	id, ref, keyRef, jkt string
	expiresAt            time.Time
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// lookup reads the route's one live row (active, or claimed for renewal and still the route's token
// until its replacement commits; migration 4 allows no second), unexpired and bound to an active
// store key. A failed or retired row is never read. pgx.ErrNoRows when there is none.
func (s *Service) lookup(ctx context.Context, q querier, req Request) (live, error) {
	ctx, cancel := context.WithTimeout(ctx, OpTimeout)
	defer cancel()
	var t live
	err := q.QueryRow(ctx, `SELECT u.token_id::text, u.token_ref, u.key_ref, k.jkt, u.expires_at
		FROM upstream_token u JOIN signing_key k ON k.key_ref = u.key_ref AND k.state = 'active'
		WHERE u.peer_zone = $1 AND u.audience = $2 AND u.tenant = $3 AND u.state IN ('active', 'renewing') AND u.expires_at > $4
		ORDER BY u.expires_at DESC LIMIT 1`, req.PeerZone, req.Audience, req.Tenant, s.now()).
		Scan(&t.id, &t.ref, &t.keyRef, &t.jkt, &t.expiresAt)
	return t, err
}

// acquireOnDemand acquires the route's token when it has no live one, once for all concurrent
// callers: in this process they queue on the route's gate, across replicas on a transaction-scoped
// advisory lock on the route, and whoever gets the lock first looks again before acquiring. The wait
// and the acquisition are bounded by ctx, the caller's deadline. Before it takes a connection a
// route also takes one of MaxAcquiring process-wide slots, so cold routes cannot hold every pooled
// connection with their locks while their acquisitions wait for one.
func (s *Service) acquireOnDemand(ctx context.Context, req Request) (live, error) {
	route, ok := s.Routes.For(req.PeerZone, req.Audience, req.Tenant)
	if !ok || s.Acquirer == nil {
		return live{}, ErrNoUpstream
	}
	release, err := s.gate(ctx, route.Name)
	if err != nil {
		return live{}, s.unavailable(ctx, "on-demand acquisition: deadline reached waiting for the route")
	}
	defer release()
	s.mu.Lock()
	if s.acquiring == nil {
		s.acquiring = make(chan struct{}, MaxAcquiring)
	}
	slots := s.acquiring
	s.mu.Unlock()
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	case <-ctx.Done():
		return live{}, s.unavailable(ctx, "on-demand acquisition: deadline reached waiting for a slot")
	}

	tx, err := s.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return live{}, s.unavailable(ctx, "on-demand acquisition: no transaction")
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), OpTimeout)
		defer cancel()
		_ = tx.Rollback(rctx)
	}()
	wait := 10 * time.Second
	if d, ok := ctx.Deadline(); ok {
		wait = time.Until(d)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true), set_config('idle_in_transaction_session_timeout', $2, true),
		pg_advisory_xact_lock(hashtextextended($3, 0))`,
		ms(wait), ms(wait+5*time.Second), routeLock(req)); err != nil {
		return live{}, s.unavailable(ctx, "on-demand acquisition: route lock not taken")
	}
	// Each statement in READ COMMITTED reads what committed before it: a token another caller
	// acquired while this one waited is found here.
	tok, err := s.lookup(ctx, tx, req)
	if !errors.Is(err, pgx.ErrNoRows) {
		if err != nil {
			err = s.unavailable(ctx, "upstream token lookup failed")
		}
		return tok, err
	}
	if _, err := s.Acquirer.Acquire(ctx, route); err != nil {
		return live{}, s.acquisitionFailed(ctx, route.Name, err)
	}
	tok, err = s.lookup(ctx, tx, req)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return live{}, ErrNoUpstream
	case err != nil:
		return live{}, s.unavailable(ctx, "upstream token lookup failed")
	}
	_ = tx.Commit(ctx)
	return tok, nil
}

// acquisitionFailed maps a failed acquisition to the contract: TOK-NO-UPSTREAM when the peer side
// definitively gave no token (it refused the grant or the outcome, issued none it would answer for,
// could not be reached, or the outcome source had none), TOK-STORE-UNAVAILABLE when the store's own
// dependencies failed (database, transit, KV, activation, a key retired during the grant) or the
// caller's deadline ended it, and for anything not known to be the peer's answer.
func (s *Service) acquisitionFailed(ctx context.Context, route string, err error) error {
	code := ""
	var e *acquire.Error
	if errors.As(err, &e) {
		code = e.Code
	}
	peer := strings.HasPrefix(code, "CRED-")
	switch code {
	case acquire.CodeChallenge, acquire.CodeOutcomeSource, acquire.CodePeerRefused, acquire.CodePeerLost, acquire.CodeTokenInvalid:
		peer = true
	}
	if peer && ctx.Err() == nil {
		s.log().WarnContext(ctx, "no upstream token: on-demand acquisition refused or failed at the peer", "route", route, "reason_code", code)
		return ErrNoUpstream
	}
	if code == "" {
		code = acquire.CodeStore
	}
	s.log().WarnContext(ctx, "on-demand acquisition failed in the store", "route", route, "reason_code", code)
	return ErrUnavailable
}

// routeLock is the route's advisory lock key text, length-prefixed so no two routes share it.
func routeLock(r Request) string {
	return fmt.Sprintf("upstream-route:%d:%s:%d:%s:%s", len(r.PeerZone), r.PeerZone, len(r.Audience), r.Audience, r.Tenant)
}

func (s *Service) gate(ctx context.Context, name string) (func(), error) {
	s.mu.Lock()
	if s.gates == nil {
		s.gates = map[string]chan struct{}{}
	}
	g, ok := s.gates[name]
	if !ok {
		g = make(chan struct{}, 1)
		s.gates[name] = g
	}
	s.mu.Unlock()
	select {
	case g <- struct{}{}:
		return func() { <-g }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// key is the store key version ref, checked against its recorded thumbprint jkt.
func (s *Service) key(ctx context.Context, ref, jkt string) (*acquire.Key, error) {
	s.mu.Lock()
	k := s.keys[ref]
	s.mu.Unlock()
	if k != nil && k.JKT() == jkt {
		return k, nil
	}
	ctx, cancel := context.WithTimeout(ctx, OpTimeout)
	defer cancel()
	k, err := acquire.KeyAt(ctx, s.Signer, ref, jkt)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.keys == nil {
		s.keys = map[string]*acquire.Key{}
	}
	s.keys[ref] = k
	s.mu.Unlock()
	return k, nil
}

// unavailable logs why a dependency failed, never what it said, and fails closed.
func (s *Service) unavailable(ctx context.Context, what string) error {
	s.log().WarnContext(ctx, what)
	return ErrUnavailable
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.New(slog.DiscardHandler)
}

func ms(d time.Duration) string {
	return strconv.FormatInt(max(d, time.Millisecond).Milliseconds(), 10)
}
