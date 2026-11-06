package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectortest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03/if03fixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/meshcaller"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/pgtest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/tokenverify"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/guard"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/policyevaluator"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire/acquiretest"
)

type guardTestKey struct{ key *ecdsa.PrivateKey }

func (k guardTestKey) JWK() jose.JWK { return jose.PublicJWK(&k.key.PublicKey) }
func (k guardTestKey) Sign(_ context.Context, in []byte) ([]byte, error) {
	sum := sha256.Sum256(in)
	r, s, err := ecdsa.Sign(rand.Reader, k.key, sum[:])
	if err != nil {
		return nil, err
	}
	return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...), nil
}

// This adapter models only the trusted sidecar header boundary locally. It is not mesh evidence.
// Connector, policy evaluator, token store, Postgres, OpenBao and token/proof verification are real.
func guardTestProxy(t *testing.T, target, identity string) *httptest.Server {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(u)
		r.Out.Header.Del("X-Forwarded-Client-Cert")
		r.Out.Header.Set("X-Forwarded-Client-Cert", "URI="+identity)
	}}
	proxy.ErrorLog = slog.NewLogLogger(slog.NewTextHandler(io.Discard, nil), slog.LevelError)
	front := httptest.NewServer(proxy)
	t.Cleanup(front.Close)
	return front
}

func TestGuardWithRealConnectorStorePolicyPostgresAndOpenBao(t *testing.T) {
	addr, token := os.Getenv("TRANSIT_TEST_ADDR"), os.Getenv("TRANSIT_TEST_TOKEN")
	if addr == "" || token == "" || os.Getenv(pgtest.DatabaseEnv) == "" {
		t.Skip("real Postgres/OpenBao inputs unavailable")
	}
	const issuer = "https://connector.guard.test"
	const aud = "https://resource.facis.invalid"
	const inbound = "https://guard.facis.invalid"
	const published = "https://resource.guard.test"
	const participantID = "spiffe://zone-b.test/ns/example/sa/ztd-participant"
	const guardPrincipal = "spiffe://zone-b.test/ns/example/sa/ztd-guard"
	const vpIssuer = "https://fixture.guard.test"
	const vpKid = "fixture-1"
	fixtureKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := connectortest.Start(t, pgtest.MigratedURL(t, "guard_issuer"), addr, token, connectortest.Options{
		Issuer: issuer, VPIssuer: vpIssuer, VPKid: vpKid, VPKey: &fixtureKey.PublicKey, Audiences: []string{inbound, aud},
		ScopeMap: []connectortest.Scope{{Role: "reader", Scopes: []string{"report:read"}}, {Role: "viewer", Scopes: []string{"report:summary"}}, {Role: "unrelated", Scopes: []string{"other:read"}}},
	})
	bao, err := transit.New(transit.Config{Addr: addr, Token: func(context.Context) (string, error) { return token, nil }})
	if err != nil {
		t.Fatal(err)
	}
	prefix := "ztd/m3-test/" + acquiretest.RandHex(8)
	loaded := acquire.Loaded{SigningKey: "guard-store-" + acquiretest.RandHex(6), KVPrefix: prefix,
		Trusted: if03.Issuers{vpIssuer: {vpKid: &fixtureKey.PublicKey}}, Routes: map[string]acquire.Route{}}
	scopes := map[string]string{"report:read": "read", "report:summary": "summary"}
	for scope, tenant := range scopes {
		clientID, secret := c.Register(t, "store "+tenant, scope, aud)
		file := filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(file, []byte(secret), 0o600); err != nil {
			t.Fatal(err)
		}
		role := "reader"
		if tenant == "summary" {
			role = "viewer"
		}
		loaded.Routes[tenant] = acquire.Route{Name: tenant, PeerZone: "zone-b", Audience: aud, Tenant: tenant, ConnectorURL: c.Base, ClientID: clientID, ClientSecretFile: file,
			Outcomes: if03fixture.Fixture{Issuer: vpIssuer, Kid: vpKid, Key: fixtureKey, Claims: if03.Claims{Role: role}}}
		loaded.Substitution = append(loaded.Substitution, meshcaller.Route{Callers: []string{guardPrincipal}, PeerZone: "zone-b", Audience: aud, Tenant: tenant, Methods: []string{"POST"}, TargetPrefix: published + "/demo"})
	}
	dsn := testDatabaseURL(t)
	migrate(t, dsn)
	cfg := localConfig(dsn, addr)
	cfg.Acquisition = &loaded
	cfg.OpenBao = bao
	cfg.ReplayCallers = []string{guardPrincipal}
	store, err := New(t.Context(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	startServer(t, store)
	storeFront := guardTestProxy(t, "http://"+store.Addr().String(), guardPrincipal)
	policy, err := policyevaluator.New(policyevaluator.Config{Revision: "integration-1", Audience: inbound, Host: "resource.guard.test", GuardCallers: []string{guardPrincipal}, ParticipantCallers: []string{participantID}, ScopeTenants: scopes})
	if err != nil {
		t.Fatal(err)
	}
	policyServer := httptest.NewServer(policy)
	t.Cleanup(policyServer.Close)
	policyFront := guardTestProxy(t, policyServer.URL, guardPrincipal)
	runtime, err := guard.New(guard.Config{Issuer: issuer, JWKSURL: c.Base + "/.well-known/jwks.json", InboundAudience: inbound, UpstreamAudience: aud, PublishedBaseURL: published, PeerZone: "zone-b", PolicyURL: policyFront.URL, StoreURL: storeFront.URL, AllowedCallers: []string{participantID}, ScopeTenants: scopes}, nil)
	if err != nil {
		t.Fatal(err)
	}
	resource, err := tokenverify.New(tokenverify.Config{Issuer: issuer, JWKSURL: c.Base + "/.well-known/jwks.json", Audience: aud, PublicBaseURL: published, Replay: replay.NewMemory()})
	if err != nil {
		t.Fatal(err)
	}
	var last hook.Request
	for _, entry := range []struct{ role, scope string }{{"reader", "report:read"}, {"viewer", "report:summary"}, {"unrelated", "other:read"}} {
		t.Run(entry.role, func(t *testing.T) {
			id, secret := c.Register(t, "participant "+entry.role, entry.scope, inbound)
			cc := &connectorclient.Client{BaseURL: c.Base, ClientID: id, ClientSecret: secret}
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			signer := guardTestKey{key}
			challenge, err := cc.Challenge(t.Context(), inbound)
			if err != nil {
				t.Fatal(err)
			}
			outcome, err := if03fixture.Fixture{Issuer: vpIssuer, Kid: vpKid, Key: fixtureKey, Claims: if03.Claims{Role: entry.role}}.Outcome(t.Context(), challenge)
			if err != nil {
				t.Fatal(err)
			}
			granted, err := cc.Grant(t.Context(), signer, outcome, challenge.Value, inbound)
			if err != nil {
				t.Fatal(err)
			}
			makeRequest := func() hook.Request {
				proof, err := dpopproof.Build(t.Context(), signer, dpopproof.Claims{HTM: "POST", HTU: published + "/demo", ATH: connectorclient.ATH(granted.AccessToken)})
				if err != nil {
					t.Fatal(err)
				}
				header := http.Header{}
				header.Set("Authorization", "DPoP "+granted.AccessToken)
				header.Set("DPoP", proof)
				header.Set("X-Forwarded-Client-Cert", "URI="+participantID)
				return hook.Request{Method: "POST", Path: "/demo", Host: "resource.guard.test", Headers: header}
			}
			if _, err := cc.Challenge(t.Context(), aud); err == nil {
				t.Fatal("Participant obtained a Resource-audience challenge")
			}
			// The very same valid proof/token must fail at the Resource before any
			// mesh control is involved, then succeed through the guard after substitution.
			req := makeRequest()
			direct, _ := http.NewRequest(http.MethodPost, published+"/demo", nil)
			direct.Header = req.Headers.Clone()
			if _, err := resource.Verify(direct); !errors.Is(err, tokenverify.ErrAudience) {
				t.Fatal("Resource did not reject Participant token for audience mismatch")
			}
			answer := runtime.Evaluate(t.Context(), req)
			if entry.role == "unrelated" {
				if answer.Allowed || answer.Status != 403 {
					t.Fatal("scope-denied request allowed")
				}
				return
			}
			if !answer.Allowed {
				t.Fatalf("guard refused: status=%d reason=%s", answer.Status, answer.ReasonCode)
			}
			forwarded, _ := http.NewRequest(http.MethodPost, published+"/demo", nil)
			for _, h := range answer.SetHeaders {
				forwarded.Header.Set(h.Name, h.Value)
			}
			verified, err := resource.Verify(forwarded)
			if err != nil {
				t.Fatal("resource refused substituted token/proof")
			}
			if !slices.Contains(verified.Scopes, entry.scope) || (entry.role == "viewer" && slices.Contains(verified.Scopes, "report:read")) {
				t.Fatal("substitution changed privilege")
			}
			// An upstream token is not accepted on the inbound guard boundary either.
			upstreamAtGuard := hook.Request{Method: "POST", Path: "/demo", Host: "resource.guard.test", Headers: forwarded.Header.Clone()}
			upstreamAtGuard.Headers.Set("X-Forwarded-Client-Cert", "URI="+participantID)
			if runtime.Evaluate(t.Context(), upstreamAtGuard).ReasonCode != "audience_mismatch" {
				t.Fatal("guard accepted a Resource-audience token")
			}
			if forwarded.Header.Get("Authorization") == req.Headers.Get("Authorization") {
				t.Fatal("token was not substituted")
			}
			replayed := runtime.Evaluate(t.Context(), req)
			if replayed.Allowed || replayed.ReasonCode != "proof_replayed" {
				t.Fatal("replayed input escaped substitution gate")
			}
			missing := makeRequest()
			missing.Headers.Del("DPoP")
			if runtime.Evaluate(t.Context(), missing).ReasonCode != "proof_absent" {
				t.Fatal("missing proof not refused")
			}
			fresh := makeRequest()
			if !runtime.Evaluate(t.Context(), fresh).Allowed {
				t.Fatal("fresh proof failed after replay")
			}
			spoof := makeRequest()
			spoof.Headers.Set("X-Forwarded-Client-Cert", "URI=spiffe://wrong.test/ns/x/sa/y")
			if runtime.Evaluate(t.Context(), spoof).ReasonCode != "mesh_caller_denied" {
				t.Fatal("wrong identity accepted")
			}
			last = makeRequest()
		})
	}
	policyFront.Close()
	refused := runtime.Evaluate(t.Context(), last)
	if refused.Allowed || refused.Status != 503 {
		t.Fatal("policy outage did not fail closed")
	}
	storeFront.Close()
	refused = runtime.Evaluate(t.Context(), last)
	if refused.Allowed || refused.ReasonCode != "replay_unavailable" {
		t.Fatal("store outage did not fail closed")
	}
	// Cleanup only test-owned KV entries; no bearer material is emitted on failure.
	entries, err := bao.List(t.Context(), prefix)
	if err != nil {
		t.Fatal("test KV list failed")
	}
	for _, entry := range entries {
		if strings.Contains(entry, "/") {
			t.Fatal("unexpected nested test key")
		}
		if err := bao.Delete(t.Context(), prefix+"/"+entry); err != nil {
			t.Fatal("test KV cleanup failed")
		}
	}
}
