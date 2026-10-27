// Package pgstore keeps the connector's clients, issued tokens and DPoP nonces in the zone's
// authorization database (tables oauth2_client, oauth2_token, oauth2_dpop_nonce; schema owned by the
// token store's migrations). Tokens are keyed by signature, so the database never holds a usable
// credential, and client secrets are bcrypt hashes. Replay detection is not here: it is the shared
// proof_jti table (internal/replay), which the stores use through the provider's replay interface.
// Creates are insert-only: a second client, token or nonce under an existing key is
// an error, never an overwrite.
//
// The verified-presentation grant's challenges (oauth2_challenge) and consumed outcomes
// (verified_outcome) are here too. Stores.Transactions runs a transaction: a client, token,
// challenge or outcome call made with the context it returns uses that transaction. Nonces and
// replay records never do; they stay outside any grant transaction.
package pgstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

// New returns the PostgreSQL stores. Validity is evaluated against now, which defaults to time.Now
// when nil, and passed to the database as a parameter, so tests move one clock for every store.
// Replay detection is the zone's shared proof_jti record, the one the token store and the guard use.
func New(pool *pgxpool.Pool, now func() time.Time) oauth2provider.Stores {
	if now == nil {
		now = time.Now
	}

	return oauth2provider.Stores{
		Clients:            &clients{pool: pool},
		AccessTokens:       &tokens{pool: pool, kind: "access"},
		RegistrationTokens: &tokens{pool: pool, kind: "registration"},
		DPoPNonces:         &nonces{pool: pool, now: now},
		DPoPReplay:         replayStore{replay.NewPostgres(pool)},
		Challenges:         &challenges{pool: pool},
		Outcomes:           &outcomes{pool: pool},
		Transactions:       transactor{pool: pool},
	}
}

// querier is what a store needs of a pool or a transaction.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type txKey struct{}

// db is the transaction ctx carries, or the pool when it carries none.
func db(ctx context.Context, pool *pgxpool.Pool) querier {
	if tx, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return tx
	}

	return pool
}

type transactor struct{ pool *pgxpool.Pool }

func (t transactor) BeginTx(ctx context.Context) (context.Context, error) {
	if _, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return nil, errors.New("begin: a transaction is already open")
	}

	tx, err := t.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}

	return context.WithValue(ctx, txKey{}, tx), nil
}

func (t transactor) Commit(ctx context.Context) error {
	tx, ok := ctx.Value(txKey{}).(pgx.Tx)
	if !ok {
		return errors.New("commit: no transaction")
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	return nil
}

// Rollback is detached from ctx's cancellation, so a request that was cancelled still rolls back
// cleanly. Rolling back a finished transaction is not an error.
func (t transactor) Rollback(ctx context.Context) error {
	tx, ok := ctx.Value(txKey{}).(pgx.Tx)
	if !ok {
		return errors.New("rollback: no transaction")
	}

	if err := tx.Rollback(context.WithoutCancel(ctx)); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("rollback: %w", err)
	}

	return nil
}

// challenges compare expiry against the instant the caller passes, the provider's one clock.
type challenges struct{ pool *pgxpool.Pool }

func (s *challenges) CreateChallenge(ctx context.Context, c oauth2provider.Challenge) error {
	if _, err := db(ctx, s.pool).Exec(ctx, `INSERT INTO oauth2_challenge (challenge, client_id, audience, expires_at)
		VALUES ($1, $2, $3, $4)`, c.Value, c.ClientID, c.Audience, c.ExpiresAt); err != nil {
		return fmt.Errorf("create challenge: %w", err)
	}

	return nil
}

func (s *challenges) GetChallenge(ctx context.Context, value string) (oauth2provider.Challenge, error) {
	return s.read(ctx, value, "")
}

// LockChallenge takes the row lock, which a concurrent consumer of the same challenge holds until
// its transaction ends.
func (s *challenges) LockChallenge(ctx context.Context, value string) (oauth2provider.Challenge, error) {
	return s.read(ctx, value, " FOR UPDATE")
}

func (s *challenges) read(ctx context.Context, value, lock string) (oauth2provider.Challenge, error) {
	c := oauth2provider.Challenge{Value: value}

	var consumed *time.Time
	err := db(ctx, s.pool).QueryRow(ctx, `SELECT client_id, audience, expires_at, consumed_at
		FROM oauth2_challenge WHERE challenge = $1`+lock, value).Scan(&c.ClientID, &c.Audience, &c.ExpiresAt, &consumed)
	if errors.Is(err, pgx.ErrNoRows) {
		return oauth2provider.Challenge{}, oauth2provider.ErrNotFound
	}
	if err != nil {
		return oauth2provider.Challenge{}, fmt.Errorf("get challenge: %w", err)
	}
	if consumed != nil {
		c.ConsumedAt = *consumed
	}

	return c, nil
}

// ConsumeChallenge is one conditional update: a concurrent consumer of the same row waits for the
// row lock and then finds it consumed.
func (s *challenges) ConsumeChallenge(ctx context.Context, value, clientID, audience string, now time.Time) error {
	tag, err := db(ctx, s.pool).Exec(ctx, `UPDATE oauth2_challenge SET consumed_at = $4
		WHERE challenge = $1 AND client_id = $2 AND audience = $3 AND consumed_at IS NULL AND expires_at > $4`,
		value, clientID, audience, now)
	if err != nil {
		return fmt.Errorf("consume challenge: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return oauth2provider.ErrConsumed
	}

	return nil
}

type outcomes struct{ pool *pgxpool.Pool }

// ConsumeOutcome inserts the outcome already consumed. The primary key makes a second insert of
// one outcome id a no-op, which a concurrent inserter observes once the first commits.
func (s *outcomes) ConsumeOutcome(ctx context.Context, o oauth2provider.VerifiedOutcome, at time.Time) error {
	var refs any
	if o.CredentialRefs != nil {
		refs = o.CredentialRefs
	}

	tag, err := db(ctx, s.pool).Exec(ctx, `INSERT INTO verified_outcome (outcome_id, issuer, client_id, challenge, audience,
		status, claims, credential_refs, verified_at, expires_at, received_at, consumed_at)
		VALUES ($1, $2, $3, $4, $5, 'verified', $6, $7, $8, $9, $10, $10)
		ON CONFLICT (outcome_id) DO NOTHING`,
		o.ID, o.Issuer, o.ClientID, o.Challenge, o.Audience, string(o.Claims), refs, o.VerifiedAt, o.ExpiresAt, at)
	if err != nil {
		return fmt.Errorf("consume outcome: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return oauth2provider.ErrConsumed
	}

	return nil
}

// replayStore presents the shared replay record as the provider's replay store. The two say the
// same thing the other way round: TryUse reports fresh, MarkUsed reports already used. The URI is
// normalised once more by dpopproof.NormalizeURI, the form the token store and the guard record:
// the provider's own normalisation can differ from it (an empty port "host:" is kept), and the
// record must hold one spelling per target. A URI it refuses is an error, so the proof fails closed.
type replayStore struct{ store replay.Store }

func (s replayStore) MarkUsed(ctx context.Context, use oauth2provider.DPoPProofUse) (bool, error) {
	uri, err := dpopproof.NormalizeURI(use.URI)
	if err != nil {
		return false, err
	}
	fresh, err := s.store.TryUse(ctx, replay.Use{
		JKT: use.Thumbprint, Method: use.Method, URI: uri, JTI: use.ID, NotAfter: use.NotAfter,
	})
	if err != nil {
		return false, err
	}
	return !fresh, nil
}

type clients struct{ pool *pgxpool.Pool }

func (s *clients) GetClient(ctx context.Context, id string) (oauth2provider.Client, error) {
	var c oauth2provider.Client
	err := db(ctx, s.pool).QueryRow(ctx, `SELECT client_id, secret_hash, grant_types, scopes, audience, dpop_bound, metadata
		FROM oauth2_client WHERE client_id = $1`, id).
		Scan(&c.ID, &c.SecretHash, &c.GrantTypes, &c.Scopes, &c.Audience, &c.DPoPBound, &c.Metadata)
	if errors.Is(err, pgx.ErrNoRows) {
		return oauth2provider.Client{}, oauth2provider.ErrNotFound
	}
	if err != nil {
		return oauth2provider.Client{}, fmt.Errorf("get client: %w", err)
	}

	return c, nil
}

func (s *clients) CreateClient(ctx context.Context, c oauth2provider.Client) error {
	_, err := db(ctx, s.pool).Exec(ctx, `INSERT INTO oauth2_client
		(client_id, secret_hash, grant_types, scopes, audience, dpop_bound, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		c.ID, c.SecretHash, nonNil(c.GrantTypes), nonNil(c.Scopes), nonNil(c.Audience), c.DPoPBound, nullJSON(c.Metadata))
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	return nil
}

func (s *clients) UpdateClient(ctx context.Context, c oauth2provider.Client) error {
	tag, err := db(ctx, s.pool).Exec(ctx, `UPDATE oauth2_client SET secret_hash = $2, grant_types = $3, scopes = $4,
		audience = $5, dpop_bound = $6, metadata = $7, updated_at = now() WHERE client_id = $1`,
		c.ID, c.SecretHash, nonNil(c.GrantTypes), nonNil(c.Scopes), nonNil(c.Audience), c.DPoPBound, nullJSON(c.Metadata))
	if err != nil {
		return fmt.Errorf("update client: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return oauth2provider.ErrNotFound
	}

	return nil
}

func (s *clients) DeleteClient(ctx context.Context, id string) error {
	tag, err := db(ctx, s.pool).Exec(ctx, `DELETE FROM oauth2_client WHERE client_id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete client: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return oauth2provider.ErrNotFound
	}

	return nil
}

type tokens struct {
	pool *pgxpool.Pool
	kind string
}

func (s *tokens) CreateToken(ctx context.Context, signature string, r oauth2provider.TokenRecord) error {
	if r.ExpiresAt.IsZero() {
		return errors.New("create token: no expiry")
	}

	_, err := db(ctx, s.pool).Exec(ctx, `INSERT INTO oauth2_token (kind, signature, request_id, client_id, requested_at,
		requested_scopes, granted_scopes, requested_audience, granted_audience, session, expires_at, outcome_id, grant_type)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		s.kind, signature, r.RequestID, r.ClientID, r.RequestedAt,
		nonNil(r.RequestedScopes), nonNil(r.GrantedScopes), nonNil(r.RequestedAudience), nonNil(r.GrantedAudience),
		r.Session, r.ExpiresAt, nullString(r.OutcomeID), r.GrantType)
	if err != nil {
		return fmt.Errorf("create %s token: %w", s.kind, err)
	}

	return nil
}

func (s *tokens) GetToken(ctx context.Context, signature string) (oauth2provider.TokenRecord, error) {
	var r oauth2provider.TokenRecord
	err := db(ctx, s.pool).QueryRow(ctx, `SELECT request_id, client_id, requested_at, requested_scopes, granted_scopes,
		requested_audience, granted_audience, session, expires_at, coalesce(outcome_id::text, ''), grant_type
		FROM oauth2_token WHERE kind = $1 AND signature = $2`, s.kind, signature).
		Scan(&r.RequestID, &r.ClientID, &r.RequestedAt, &r.RequestedScopes, &r.GrantedScopes,
			&r.RequestedAudience, &r.GrantedAudience, &r.Session, &r.ExpiresAt, &r.OutcomeID, &r.GrantType)
	if errors.Is(err, pgx.ErrNoRows) {
		return oauth2provider.TokenRecord{}, oauth2provider.ErrNotFound
	}
	if err != nil {
		return oauth2provider.TokenRecord{}, fmt.Errorf("get %s token: %w", s.kind, err)
	}

	return r, nil
}

// DeleteToken is idempotent, as the in-memory store's is.
func (s *tokens) DeleteToken(ctx context.Context, signature string) error {
	if _, err := db(ctx, s.pool).Exec(ctx, `DELETE FROM oauth2_token WHERE kind = $1 AND signature = $2`, s.kind, signature); err != nil {
		return fmt.Errorf("delete %s token: %w", s.kind, err)
	}

	return nil
}

type nonces struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

func (s *nonces) CreateNonce(ctx context.Context, nonce string, exp time.Time) error {
	if _, err := s.pool.Exec(ctx, `INSERT INTO oauth2_dpop_nonce (nonce, expires_at) VALUES ($1, $2)`, nonce, exp); err != nil {
		return fmt.Errorf("create nonce: %w", err)
	}

	return nil
}

func (s *nonces) IsNonceValid(ctx context.Context, nonce string) (bool, error) {
	var valid bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM oauth2_dpop_nonce WHERE nonce = $1 AND expires_at > $2)`,
		nonce, s.now()).Scan(&valid)
	if err != nil {
		return false, fmt.Errorf("check nonce: %w", err)
	}

	return valid, nil
}

// Sweep removes expired tokens, nonces and unconsumed challenges and reports how many rows went. A
// consumed challenge stays, as does every consumed outcome. The binary runs it on a
// ticker; nothing reads an expired row, so sweeping is housekeeping, not a security control.
func Sweep(ctx context.Context, pool *pgxpool.Pool, now time.Time) (int64, error) {
	var total int64
	for _, q := range []string{
		`DELETE FROM oauth2_token WHERE expires_at <= $1`,
		`DELETE FROM oauth2_dpop_nonce WHERE expires_at <= $1`,
		`DELETE FROM oauth2_challenge WHERE expires_at <= $1 AND consumed_at IS NULL`,
	} {
		tag, err := pool.Exec(ctx, q, now)
		if err != nil {
			return total, fmt.Errorf("sweep: %w", err)
		}
		total += tag.RowsAffected()
	}

	return total, nil
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func nullString(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func nullJSON(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	return string(raw)
}
