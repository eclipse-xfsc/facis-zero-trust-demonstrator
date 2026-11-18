// Package memstore provides in-memory implementations of the oauth2provider
// stores. Nothing is persisted: it is meant for tests and local development.
//
// Transactions are serialised and undo-logged: one transaction runs at a time, and a rollback
// undoes the token creations, challenge creations and consumptions, and outcome consumptions made
// with its context. Nothing else is transactional: client changes and token deletions take effect
// at once and are not undone. A transaction's writes are visible to readers outside it before it
// commits. That is all the verified-presentation grant needs.
package memstore

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

// New returns a set of in-memory stores. Expiry is evaluated against now,
// which defaults to time.Now when nil.
func New(now func() time.Time) oauth2provider.Stores {
	if now == nil {
		now = time.Now
	}

	return oauth2provider.Stores{
		Clients:            &clientStore{clients: map[string]oauth2provider.Client{}},
		AccessTokens:       &tokenStore{tokens: map[string]oauth2provider.TokenRecord{}, outcomes: map[string]bool{}},
		RegistrationTokens: &tokenStore{tokens: map[string]oauth2provider.TokenRecord{}, outcomes: map[string]bool{}},
		DPoPNonces:         &expiringSet{now: now, entries: map[string]time.Time{}},
		DPoPReplay:         &replayStore{set: expiringSet{now: now, entries: map[string]time.Time{}}},
		Challenges:         &challengeStore{challenges: map[string]oauth2provider.Challenge{}},
		Outcomes:           &outcomeStore{outcomes: map[string]oauth2provider.VerifiedOutcome{}},
		Transactions:       &transactor{},
	}
}

type txKey struct{}

type memTx struct {
	undo []func()
	done bool
}

// ponytail: one global transaction lock; a per-record lock if this store ever serves real load.
type transactor struct{ mu sync.Mutex }

func (t *transactor) BeginTx(ctx context.Context) (context.Context, error) {
	if _, ok := ctx.Value(txKey{}).(*memTx); ok {
		return nil, errors.New("begin: a transaction is already open")
	}

	t.mu.Lock()

	return context.WithValue(ctx, txKey{}, &memTx{}), nil
}

func (t *transactor) Commit(ctx context.Context) error {
	tx, ok := ctx.Value(txKey{}).(*memTx)
	if !ok || tx.done {
		return errors.New("commit: no open transaction")
	}

	tx.done, tx.undo = true, nil
	t.mu.Unlock()

	return nil
}

func (t *transactor) Rollback(ctx context.Context) error {
	tx, ok := ctx.Value(txKey{}).(*memTx)
	if !ok {
		return errors.New("rollback: no transaction")
	}

	if tx.done {
		return nil
	}

	for i := len(tx.undo) - 1; i >= 0; i-- {
		tx.undo[i]()
	}

	tx.done, tx.undo = true, nil
	t.mu.Unlock()

	return nil
}

// onRollback registers undo with the transaction ctx carries, if any. The caller holds the lock
// undo needs; undo runs later and takes it itself.
func onRollback(ctx context.Context, undo func()) {
	if tx, ok := ctx.Value(txKey{}).(*memTx); ok && !tx.done {
		tx.undo = append(tx.undo, undo)
	}
}

type challengeStore struct {
	mu         sync.Mutex
	challenges map[string]oauth2provider.Challenge
}

func (s *challengeStore) CreateChallenge(ctx context.Context, c oauth2provider.Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.challenges[c.Value]; ok {
		return errors.New("create challenge: exists")
	}

	s.challenges[c.Value] = c
	onRollback(ctx, func() { s.mu.Lock(); delete(s.challenges, c.Value); s.mu.Unlock() })

	return nil
}

func (s *challengeStore) GetChallenge(_ context.Context, value string) (oauth2provider.Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.challenges[value]
	if !ok {
		return oauth2provider.Challenge{}, oauth2provider.ErrNotFound
	}

	return c, nil
}

// LockChallenge is GetChallenge: a transaction already excludes every other one.
func (s *challengeStore) LockChallenge(ctx context.Context, value string) (oauth2provider.Challenge, error) {
	return s.GetChallenge(ctx, value)
}

func (s *challengeStore) ConsumeChallenge(ctx context.Context, value, clientID, audience string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.challenges[value]
	if !ok || c.ClientID != clientID || c.Audience != audience || !c.ConsumedAt.IsZero() || !now.Before(c.ExpiresAt) {
		return oauth2provider.ErrConsumed
	}

	before := c
	c.ConsumedAt = now
	s.challenges[value] = c
	onRollback(ctx, func() { s.mu.Lock(); s.challenges[value] = before; s.mu.Unlock() })

	return nil
}

type outcomeStore struct {
	mu       sync.Mutex
	outcomes map[string]oauth2provider.VerifiedOutcome
}

func (s *outcomeStore) ConsumeOutcome(ctx context.Context, o oauth2provider.VerifiedOutcome, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.outcomes[o.ID]; ok {
		return oauth2provider.ErrConsumed
	}

	s.outcomes[o.ID] = o
	onRollback(ctx, func() { s.mu.Lock(); delete(s.outcomes, o.ID); s.mu.Unlock() })

	return nil
}

type clientStore struct {
	mu      sync.RWMutex
	clients map[string]oauth2provider.Client
}

func (s *clientStore) GetClient(_ context.Context, id string) (oauth2provider.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, ok := s.clients[id]
	if !ok {
		return oauth2provider.Client{}, oauth2provider.ErrNotFound
	}

	return client, nil
}

func (s *clientStore) CreateClient(_ context.Context, client oauth2provider.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.clients[client.ID] = client

	return nil
}

func (s *clientStore) UpdateClient(_ context.Context, client oauth2provider.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.clients[client.ID]; !ok {
		return oauth2provider.ErrNotFound
	}

	s.clients[client.ID] = client

	return nil
}

func (s *clientStore) DeleteClient(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.clients[id]; !ok {
		return oauth2provider.ErrNotFound
	}

	delete(s.clients, id)

	return nil
}

type tokenStore struct {
	mu       sync.RWMutex
	tokens   map[string]oauth2provider.TokenRecord
	outcomes map[string]bool
}

// CreateToken keeps the database's rules: an outcome id is unique, a verified-presentation token
// has one and no other token does.
func (s *tokenStore) CreateToken(ctx context.Context, signature string, record oauth2provider.TokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if (record.GrantType == oauth2provider.VerifiedPresentationGrantType) != (record.OutcomeID != "") {
		return errors.New("create token: a verified-presentation token has an outcome id and no other token does")
	}

	if record.OutcomeID != "" {
		if s.outcomes[record.OutcomeID] {
			return errors.New("create token: outcome already has a token")
		}

		s.outcomes[record.OutcomeID] = true
	}

	s.tokens[signature] = record
	onRollback(ctx, func() {
		s.mu.Lock()
		delete(s.tokens, signature)
		delete(s.outcomes, record.OutcomeID)
		s.mu.Unlock()
	})

	return nil
}

func (s *tokenStore) GetToken(_ context.Context, signature string) (oauth2provider.TokenRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, ok := s.tokens[signature]
	if !ok {
		return oauth2provider.TokenRecord{}, oauth2provider.ErrNotFound
	}

	return record, nil
}

func (s *tokenStore) DeleteToken(_ context.Context, signature string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.tokens, signature)

	return nil
}

// expiringSet backs the nonce store and the replay store.
type expiringSet struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]time.Time
}

func (s *expiringSet) CreateNonce(_ context.Context, nonce string, exp time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.prune()
	s.entries[nonce] = exp

	return nil
}

func (s *expiringSet) IsNonceValid(_ context.Context, nonce string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	exp, ok := s.entries[nonce]

	return ok && s.now().Before(exp), nil
}

// markUsed checks and inserts under a single lock, which is what makes the
// replay check atomic.
func (s *expiringSet) markUsed(key string, exp time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if previous, ok := s.entries[key]; ok && s.now().Before(previous) {
		return true
	}

	s.prune()
	s.entries[key] = exp

	return false
}

// replayStore keys a proof by every field that identifies it, the nonce
// included, so a client can answer a nonce challenge by re-signing with the
// same jti.
type replayStore struct {
	set expiringSet
}

func (s *replayStore) MarkUsed(_ context.Context, use oauth2provider.DPoPProofUse) (bool, error) {
	key, err := json.Marshal([]string{use.Thumbprint, use.Method, use.URI, use.ID, use.Nonce})
	if err != nil {
		return false, err
	}

	return s.set.markUsed(string(key), use.NotAfter), nil
}

func (s *expiringSet) prune() {
	now := s.now()

	for key, exp := range s.entries {
		if !now.Before(exp) {
			delete(s.entries, key)
		}
	}
}
