package guard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
)

// dependencyStub answers the three probes; each answer can be changed while it runs.
type dependencyStub struct {
	decision atomic.Value // string: the body of /decision
	keys     atomic.Value // string: the body of /jwks
	ready    atomic.Int32 // the status of /readyz
}

func newDependencyStub(t *testing.T) (*dependencyStub, *httptest.Server) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.PublicJWK(&private.PublicKey)
	jwk.Kid = "probe"
	keys, _ := json.Marshal(map[string]any{"keys": []jose.JWK{jwk}})
	deny, _ := json.Marshal(hook.Decision{Allow: false, ReasonCode: hook.ReasonRuleDeny, RuleID: "m3-default-deny", BundleRevision: "probe", DenyBody: &hook.DenyBody{Error: "access_denied"}})
	s := &dependencyStub{}
	s.decision.Store(string(deny))
	s.keys.Store(string(keys))
	s.ready.Store(http.StatusOK)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/decision":
			var in hook.Input
			if json.NewDecoder(r.Body).Decode(&in) != nil || in.Token.Present || in.Source.SPIFFEID != probeSource {
				t.Error("the policy probe did not send a token-less input from the probe source")
			}
			_, _ = w.Write([]byte(s.decision.Load().(string)))
		case "/jwks":
			_, _ = w.Write([]byte(s.keys.Load().(string)))
		case "/readyz":
			w.WriteHeader(int(s.ready.Load()))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return s, server
}

func TestProberReportsEachDependency(t *testing.T) {
	stub, server := newDependencyStub(t)
	p := NewProber(testConfig(server.URL))
	now := time.Now()
	p.now = func() time.Time { return now }
	check := func() map[string]bool {
		for _, dependency := range Dependencies {
			p.Check(t.Context(), dependency)
		}
		return p.Up()
	}

	if down := p.Down(); len(down) != 3 {
		t.Fatalf("before any check %v are down, want all three", down)
	}
	if up := check(); !up[DependencyPolicyEngine] || !up[DependencyKeySet] || !up[DependencyTokenStore] {
		t.Fatalf("all answer correctly, but up = %v", up)
	}

	allow, _ := json.Marshal(hook.Decision{Allow: true, RuleID: "x", BundleRevision: "probe", Obligations: []string{hook.ObligationSubstituteUpstreamToken}})
	for name, tc := range map[string]struct {
		change     func()
		dependency string
	}{
		"the policy allows the probe":   {func() { stub.decision.Store(string(allow)) }, DependencyPolicyEngine},
		"the policy answers garbage":    {func() { stub.decision.Store(`{"allow":false}`) }, DependencyPolicyEngine},
		"the key set has no usable key": {func() { stub.keys.Store(`{"keys":[{"kty":"RSA","kid":"r","n":"AQAB","e":"AQAB"}]}`) }, DependencyKeySet},
		"the key set is not JSON":       {func() { stub.keys.Store(`<html>`) }, DependencyKeySet},
		"the token store is not ready":  {func() { stub.ready.Store(http.StatusServiceUnavailable) }, DependencyTokenStore},
	} {
		t.Run(name, func(t *testing.T) {
			decision, keys, ready := stub.decision.Load(), stub.keys.Load(), stub.ready.Load()
			tc.change()
			up := check()
			for _, dependency := range Dependencies {
				if up[dependency] == (dependency == tc.dependency) {
					t.Errorf("%s up = %v", dependency, up[dependency])
				}
			}
			stub.decision.Store(decision)
			stub.keys.Store(keys)
			stub.ready.Store(ready)
		})
	}

	// A dependency that cannot be reached is down.
	server.Close()
	if up := check(); up[DependencyPolicyEngine] || up[DependencyKeySet] || up[DependencyTokenStore] {
		t.Errorf("with the dependencies gone, up = %v", up)
	}
}

// A success counts for probeMaxAge: a prober that stops checking reports its dependencies down.
func TestProberResultsGoStale(t *testing.T) {
	_, server := newDependencyStub(t)
	p := NewProber(testConfig(server.URL))
	now := time.Now()
	p.now = func() time.Time { return now }
	for _, dependency := range Dependencies {
		p.Check(t.Context(), dependency)
	}
	now = now.Add(probeMaxAge)
	if down := p.Down(); len(down) != 0 {
		t.Fatalf("at probeMaxAge %v are down", down)
	}
	now = now.Add(time.Millisecond)
	if down := p.Down(); len(down) != 3 {
		t.Fatalf("after probeMaxAge only %v are down", down)
	}
}

// Run checks at once, and stops with its context.
func TestProberRunsAtOnceAndStops(t *testing.T) {
	_, server := newDependencyStub(t)
	p := NewProber(testConfig(server.URL))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	deadline := time.Now().Add(probeTimeout + time.Second)
	for len(p.Down()) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("not up after the first checks: %v", p.Down())
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(probeTimeout + time.Second):
		t.Fatal("Run did not stop with its context")
	}
}

// Every refusal is counted once by its code, an unknown code as "other"; the metrics always carry
// the three dependencies.
func TestMetricsCarryEveryDependencyAndBoundedRefusals(t *testing.T) {
	_, server := newDependencyStub(t)
	p := NewProber(testConfig(server.URL))
	r, err := New(testConfig("http://127.0.0.1:1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Evaluate(t.Context(), hook.Request{Method: "GET", Path: "/demo", Host: "resource.example", Headers: http.Header{}})
	r.Refused.add("a code from nowhere")
	var b strings.Builder
	WriteMetrics(&b, p, &r.Refused)
	for _, want := range []string{
		`ztd_guard_dependency_up{dependency="policy_engine"} 0`, `ztd_guard_dependency_up{dependency="key_set"} 0`,
		`ztd_guard_dependency_up{dependency="token_store"} 0`, `ztd_guard_refusals_total{reason_code="route_denied"} 1`,
		`ztd_guard_refusals_total{reason_code="other"} 1`,
	} {
		if !strings.Contains(b.String(), want+"\n") {
			t.Errorf("metrics lack %q:\n%s", want, b.String())
		}
	}
}
