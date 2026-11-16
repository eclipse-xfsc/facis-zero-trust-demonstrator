package tokenverify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

var errUnknownKid = errors.New("tokenverify: unknown kid")

// keySet is the cached JWKS. One fetch runs at a time and the others wait for it; fetches start at
// most once per MinRefresh. Only a successful fetch moves fetched, so a failing JWKS endpoint lets the
// cache age until MaxStale and then every lookup fails.
type keySet struct {
	cfg *Config

	mu        sync.Mutex
	keys      map[string]*ecdsa.PublicKey
	fetched   time.Time     // last successful fetch
	attempted time.Time     // start of the last fetch
	flight    chan struct{} // non-nil while a fetch runs; closed when it ends
}

// key returns the key for kid. Time is read from cfg.Now under the lock, again after any fetch or
// wait, and MaxStale is checked last, immediately before a key is handed out.
func (s *keySet) key(kid string) (*ecdsa.PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.fetched.IsZero() || s.cfg.Now().Sub(s.fetched) >= s.cfg.CacheTTL {
		s.refreshLocked()
	}
	k, ok := s.keys[kid]
	if !ok && s.usableLocked() {
		s.refreshLocked()
		k, ok = s.keys[kid]
	}
	if !s.usableLocked() {
		return nil, ErrKeySetUnavailable
	}
	if !ok {
		return nil, errUnknownKid
	}
	return k, nil
}

func (s *keySet) usableLocked() bool {
	return !s.fetched.IsZero() && s.cfg.Now().Sub(s.fetched) <= s.cfg.MaxStale
}

// refreshLocked fetches the key set, or waits for the fetch already running. Called and returns with
// s.mu held. A successful fetch dates the keys from when it started, never later.
func (s *keySet) refreshLocked() {
	if ch := s.flight; ch != nil {
		s.mu.Unlock()
		<-ch
		s.mu.Lock()
		return
	}
	start := s.cfg.Now()
	if !s.attempted.IsZero() && start.Sub(s.attempted) < s.cfg.MinRefresh {
		return
	}
	s.attempted = start
	ch := make(chan struct{})
	s.flight = ch
	s.mu.Unlock()

	keys, err := s.fetch()

	s.mu.Lock()
	if err == nil {
		s.keys, s.fetched = keys, start
	}
	s.flight = nil
	close(ch)
}

// fetch reads the key set from JWKSURL. It is not tied to any one request's context, since other
// requests may be waiting on it.
func (s *keySet) fetch() (map[string]*ecdsa.PublicKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tokenverify: key set status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeySetBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxKeySetBytes {
		return nil, errors.New("tokenverify: key set too large")
	}
	return parseKeySet(body)
}

// parseKeySet keeps the EC P-256 signing keys that carry a kid; other keys are ignored, and a kid that
// appears twice is dropped. A set with no usable key is an error, so it never replaces a good one.
func parseKeySet(body []byte) (map[string]*ecdsa.PublicKey, error) {
	top, err := jose.ParseObject(body)
	if err != nil {
		return nil, err
	}
	var entries []json.RawMessage
	if raw := bytes.TrimSpace(top["keys"]); len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &entries) != nil {
		return nil, errors.New("tokenverify: key set has no keys array")
	}
	keys := map[string]*ecdsa.PublicKey{}
	dup := map[string]bool{}
	for _, raw := range entries {
		kid, pub, ok := parseKey(raw)
		if !ok {
			continue
		}
		if _, seen := keys[kid]; seen || dup[kid] {
			dup[kid] = true
			delete(keys, kid)
			continue
		}
		keys[kid] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("tokenverify: key set has no usable key")
	}
	return keys, nil
}

func parseKey(raw json.RawMessage) (string, *ecdsa.PublicKey, bool) {
	m, err := jose.ParseObject(raw)
	if err != nil {
		return "", nil, false
	}
	if _, private := m["d"]; private {
		return "", nil, false
	}
	str := func(name string) string { v, _, _ := jose.String(m, name); return v }
	if use, present, _ := jose.String(m, "use"); present && use != "sig" {
		return "", nil, false
	}
	if alg, present, _ := jose.String(m, "alg"); present && alg != jose.AlgES256 {
		return "", nil, false
	}
	if ops, present := m["key_ops"]; present && !opsAllowVerify(ops) {
		return "", nil, false
	}
	j := jose.JWK{Kty: str("kty"), Crv: str("crv"), X: str("x"), Y: str("y"), Kid: str("kid")}
	if j.Kid == "" {
		return "", nil, false
	}
	pub, err := j.PublicKey()
	if err != nil {
		return "", nil, false
	}
	return j.Kid, pub, true
}

// opsAllowVerify reports whether key_ops (RFC 7517 4.3) is a JSON array of unique strings that
// includes "verify".
func opsAllowVerify(raw json.RawMessage) bool {
	var elems []json.RawMessage
	if raw = bytes.TrimSpace(raw); len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &elems) != nil {
		return false
	}
	seen := map[string]bool{}
	for _, e := range elems {
		var op string
		if e = bytes.TrimSpace(e); len(e) == 0 || e[0] != '"' || json.Unmarshal(e, &op) != nil || seen[op] {
			return false
		}
		seen[op] = true
	}
	return seen["verify"]
}
