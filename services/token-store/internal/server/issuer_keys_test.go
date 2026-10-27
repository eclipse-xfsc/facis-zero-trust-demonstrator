package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire"
)

func TestIssuerSeparationCacheAndKeyChanges(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.PublicJWK(&key.PublicKey)
	thumbprint, err := jwk.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	var unavailable atomic.Bool
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		if unavailable.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "n": "ignored", "e": "AQAB"}, map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "ignored"}, jwk}})
	}))
	defer issuer.Close()
	now := time.Now()
	s := &Server{cfg: Config{Acquisition: &acquire.Loaded{}}, log: slog.New(slog.NewTextHandler(io.Discard, nil)), now: func() time.Time { return now }}
	// Loaded routes are the same public acquisition configuration used by readiness.
	s.cfg.Acquisition.Routes = map[string]acquire.Route{"test": {ConnectorURL: issuer.URL}}
	if state := s.checkIssuerSeparation(context.Background(), map[string]bool{"distinct": true}); state != checkOK {
		t.Fatal(state)
	}
	if state := s.checkIssuerSeparation(context.Background(), map[string]bool{"distinct": true}); state != checkOK || requests.Load() != 1 {
		t.Fatal("fresh cache not used")
	}
	// A newly active older version invalidates the cache even with the same latest key.
	if state := s.checkIssuerSeparation(context.Background(), map[string]bool{"distinct": true, thumbprint: true}); state != checkSharedIssuerKey || requests.Load() != 2 {
		t.Fatal("overlapping older active key was missed")
	}
	if state := s.checkIssuerSeparation(context.Background(), map[string]bool{"distinct": true}); state != checkOK {
		t.Fatal(state)
	}
	unavailable.Store(true)
	now = now.Add(issuerSeparationTTL - time.Second)
	if state := s.checkIssuerSeparation(context.Background(), map[string]bool{"distinct": true}); state != checkOK {
		t.Fatal("fresh result lost")
	}
	now = now.Add(2 * time.Second)
	if state := s.checkIssuerSeparation(context.Background(), map[string]bool{"distinct": true}); state != checkUnreachable {
		t.Fatal("expired result reused")
	}
}
