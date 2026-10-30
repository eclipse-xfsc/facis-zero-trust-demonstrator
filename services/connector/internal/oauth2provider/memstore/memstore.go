// Package memstore provides in-memory implementations of the oauth2provider
// stores. Nothing is persisted: it is meant for tests and local development.
package memstore

import (
	"context"
	"encoding/json"
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
		AccessTokens:       &tokenStore{tokens: map[string]oauth2provider.TokenRecord{}},
		RegistrationTokens: &tokenStore{tokens: map[string]oauth2provider.TokenRecord{}},
		DPoPNonces:         &expiringSet{now: now, entries: map[string]time.Time{}},
		DPoPReplay:         &replayStore{set: expiringSet{now: now, entries: map[string]time.Time{}}},
	}
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
	mu     sync.RWMutex
	tokens map[string]oauth2provider.TokenRecord
}

func (s *tokenStore) CreateToken(_ context.Context, signature string, record oauth2provider.TokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens[signature] = record

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
