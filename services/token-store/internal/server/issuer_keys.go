package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

const issuerSeparationTTL = 5 * time.Minute
const checkSharedIssuerKey = "shared_issuer_key"

type issuerSeparationCache struct {
	mu          sync.Mutex
	fingerprint string
	expires     time.Time
}

// checkIssuerSeparation caches only passing results. A changed key set invalidates
// the result immediately. All distinct issuer endpoints are fetched concurrently.
func (s *Server) checkIssuerSeparation(ctx context.Context, storeKeys map[string]bool) string {
	endpoints := map[string]bool{}
	for _, route := range s.cfg.Acquisition.Routes {
		endpoints[strings.TrimRight(route.ConnectorURL, "/")+"/.well-known/jwks.json"] = true
	}
	fingerprint := strings.Join(slices.Sorted(maps.Keys(storeKeys)), "\n") + "\x00" + strings.Join(slices.Sorted(maps.Keys(endpoints)), "\n")
	cache := &s.issuerCache
	cache.mu.Lock()
	defer cache.mu.Unlock()
	now := s.now()
	if cache.fingerprint == fingerprint && now.Before(cache.expires) {
		return checkOK
	}
	cache.expires = time.Time{}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	results := make(chan string, len(endpoints))
	for endpoint := range endpoints {
		go func() { results <- issuerKeyState(ctx, client, endpoint, storeKeys, s.log) }()
	}
	state := checkOK
	for range endpoints {
		result := <-results
		if result == checkSharedIssuerKey {
			s.log.WarnContext(ctx, "store and Connector share an issuer key", "reason", checkSharedIssuerKey)
			return checkSharedIssuerKey
		}
		if result != checkOK {
			state = result
		}
	}
	if state == checkOK {
		cache.fingerprint = fingerprint
		cache.expires = s.now().Add(issuerSeparationTTL)
	}
	return state
}

func issuerKeyState(ctx context.Context, client *http.Client, endpoint string, storeKeys map[string]bool, log *slog.Logger) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return checkUnreachable
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return checkUnreachable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return checkUnreachable
	}
	const limit = 64 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || len(body) > limit {
		return checkUnreachable
	}
	object, err := jose.ParseObject(body)
	if err != nil {
		return checkUnreachable
	}
	var entries []json.RawMessage
	if json.Unmarshal(object["keys"], &entries) != nil || len(entries) == 0 {
		return checkUnreachable
	}
	for _, raw := range entries {
		members, err := jose.ParseObject(raw)
		if err != nil {
			return checkUnreachable
		}
		if _, private := members["d"]; private {
			return checkUnreachable
		}
		var key jose.JWK
		if json.Unmarshal(raw, &key) != nil {
			return checkUnreachable
		}
		if key.Kty != "EC" || key.Crv != "P-256" {
			log.InfoContext(ctx, "skipped Connector JWKS key with unsupported type or curve")
			continue
		}
		thumbprint, err := key.Thumbprint()
		if err != nil {
			return checkUnreachable
		}
		if storeKeys[thumbprint] {
			return checkSharedIssuerKey
		}
	}
	return checkOK
}
