package guard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
)

type dependencyKey struct{ key *ecdsa.PrivateKey }

func (k dependencyKey) JWK() jose.JWK { return jose.PublicJWK(&k.key.PublicKey) }
func (k dependencyKey) Sign(_ context.Context, in []byte) ([]byte, error) {
	sum := sha256.Sum256(in)
	r, s, err := ecdsa.Sign(rand.Reader, k.key, sum[:])
	if err != nil {
		return nil, err
	}
	return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...), nil
}

func TestRuntimeDependencyHangsDeny(t *testing.T) {
	for _, dependency := range []string{"jwks", "replay"} {
		t.Run(dependency, func(t *testing.T) {
			private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			key := dependencyKey{private}
			jwk := key.JWK()
			jwk.Kid = "test"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/jwks" && dependency != "jwks" {
					_ = json.NewEncoder(w).Encode(map[string]any{"keys": []jose.JWK{jwk}})
					return
				}
				select {
				case <-r.Context().Done():
				case <-time.After(250 * time.Millisecond):
				}
			}))
			defer server.Close()
			cfg := testConfig(server.URL)
			runtime, err := New(cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			jkt, err := jwk.Thumbprint()
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			payload, _ := json.Marshal(map[string]any{"iss": cfg.Issuer, "sub": "participant", "client_id": "participant", "aud": cfg.InboundAudience, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": "dependency-token", "scope": "report:read", "cnf": map[string]string{"jkt": jkt}})
			token, err := jose.Sign(t.Context(), jose.Header{Typ: "at+jwt", Kid: "test"}, payload, key.Sign)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := dpopproof.Build(t.Context(), key, dpopproof.Claims{HTM: "POST", HTU: cfg.PublishedBaseURL + "/demo", ATH: connectorclient.ATH(token)})
			if err != nil {
				t.Fatal(err)
			}
			req := hook.Request{Method: "POST", Path: "/demo", Host: "RESOURCE.EXAMPLE", Headers: http.Header{}}
			req.Headers.Set("Authorization", "DPoP "+token)
			req.Headers.Set("DPoP", proof)
			req.Headers.Set("X-Forwarded-Client-Cert", "URI="+cfg.AllowedCallers[0])
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			out := runtime.Evaluate(ctx, req)
			want := "replay_unavailable"
			if dependency == "jwks" {
				want = "key_set_unavailable"
			}
			if out.Allowed || out.Status != 503 || out.ReasonCode != want {
				t.Fatalf("hanging %s: status=%d reason=%s", dependency, out.Status, out.ReasonCode)
			}
			if time.Since(start) > time.Second {
				t.Fatal("request deadline not respected")
			}
		})
	}
}
