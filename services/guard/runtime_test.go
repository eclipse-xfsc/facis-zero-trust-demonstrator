package guard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/tokenverify"
)

func testConfig(endpoint string) Config {
	return Config{Issuer: "https://issuer.example", JWKSURL: endpoint + "/jwks", InboundAudience: "guard", UpstreamAudience: "resource", PublishedBaseURL: "https://resource.example", PeerZone: "test", PolicyURL: endpoint, StoreURL: endpoint, AllowedCallers: []string{"spiffe://test/ns/demo/sa/participant"}, ScopeTenants: map[string]string{"report:read": "read", "report:summary": "summary"}}
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	for _, change := range []func(*Config){func(c *Config) { c.PublishedBaseURL = "https://resource.example/path" }, func(c *Config) { c.StoreURL = "http://user:password@store" }, func(c *Config) { c.PolicyURL = "ftp://policy" }, func(c *Config) { c.Issuer = "" }, func(c *Config) { c.InboundAudience = "" }, func(c *Config) { c.UpstreamAudience = "" }, func(c *Config) { c.UpstreamAudience = c.InboundAudience }, func(c *Config) { c.InboundAudience = " " }, func(c *Config) { c.UpstreamAudience = "bad audience" }, func(c *Config) { c.InboundAudience = "guard\u00a0audience" }, func(c *Config) { c.UpstreamAudience = "resource\u2003audience" }, func(c *Config) { c.JWKSURL = "bad" }, func(c *Config) { c.AllowedCallers = []string{"invalid"} }, func(c *Config) { c.ScopeTenants["report:summary"] = "read" }} {
		c := testConfig("http://127.0.0.1:1")
		change(&c)
		if _, err := New(c, nil); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
}

func TestHostAndRouteRefusedBeforeDependencies(t *testing.T) {
	r, err := New(testConfig("http://127.0.0.1:1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ method, path, host, reason string }{{"POST", "/demo", "foreign.example", "host_denied"}, {"POST", "/other", "resource.example", "route_denied"}, {"GET", "/demo", "resource.example", "route_denied"}} {
		got := r.Evaluate(t.Context(), hook.Request{Method: tc.method, Path: tc.path, Host: tc.host, Headers: http.Header{}})
		if got.Allowed || got.Status != 403 || got.ReasonCode != tc.reason {
			t.Fatalf("unexpected refusal: %s/%d", got.ReasonCode, got.Status)
		}
	}
}

type verifiedUnitIdentity struct{}

func (verifiedUnitIdentity) Verify(*http.Request) (tokenverify.Identity, error) {
	return tokenverify.Identity{Subject: "participant", ClientID: "participant", JKT: "test-thumbprint", Scopes: []string{"report:read"}}, nil
}

func TestRuntimeRemovesCallerHeadersBeforeForwarding(t *testing.T) {
	dependency := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/decision" {
			var input hook.Input
			if json.NewDecoder(r.Body).Decode(&input) != nil || input.Token.Aud != "guard" {
				t.Error("policy did not receive the verified inbound audience")
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"allow": true, "bundle_revision": "test", "obligations": []string{hook.ObligationSubstituteUpstreamToken}})
			return
		}
		var request hook.SubstituteRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.Audience != "resource" || request.TargetURI != "https://resource.example/demo" {
			t.Error("store did not receive the upstream audience and published target")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"authorization": "DPoP upstream-unit-token", "dpop": "upstream-unit-proof", "expires_at": time.Now().Add(time.Minute).UTC().Format(time.RFC3339)})
	}))
	defer dependency.Close()
	r, err := New(testConfig(dependency.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	r.verifier = verifiedUnitIdentity{}
	result := r.Evaluate(t.Context(), hook.Request{Method: "POST", Path: "/demo", Host: "resource.example", Headers: http.Header{"X-Forwarded-Client-Cert": []string{"URI=spiffe://test/ns/demo/sa/participant"}, "Authorization": []string{"DPoP caller-unit-token"}, "Dpop": []string{"caller-unit-proof"}, "X-Forwarded-Host": []string{"foreign.example"}, "X-Facis-Evil": []string{"untrusted"}}})
	if !result.Allowed {
		t.Fatalf("allowed unit request refused: %s", result.ReasonCode)
	}
	for _, name := range []string{"x-forwarded-client-cert", "x-forwarded-host", "x-facis-evil"} {
		if !slices.Contains(result.RemoveHeaders, name) {
			t.Fatalf("header not removed: %s", name)
		}
	}
	for _, h := range result.SetHeaders {
		if h.Value == "DPoP caller-unit-token" || h.Value == "caller-unit-proof" {
			t.Fatal("caller credential forwarded")
		}
	}
}

func TestDependencyTimeoutsDeny(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(250 * time.Millisecond):
		}
	}))
	defer server.Close()
	c := NewClients(server.URL, server.URL)
	c.HTTP.Timeout = 30 * time.Millisecond
	start := time.Now()
	if _, err := c.Decide(t.Context(), hook.Input{}); err == nil {
		t.Fatal("hanging policy allowed")
	}
	if _, err := c.Substitute(t.Context(), hook.SubstituteRequest{}); err == nil {
		t.Fatal("hanging store allowed")
	}
	if time.Since(start) > time.Second {
		t.Fatal("dependency timeout not bounded")
	}
}

func TestSubstitutionFailureResponses(t *testing.T) {
	for _, tc := range []struct {
		status       int
		body, reason string
	}{{403, `{"reason_code":"TOK-CALLER-DENIED"}`, hook.ReasonTokenCallerDenied}, {500, `{"reason_code":"TOK-STORE-UNAVAILABLE"}`, hook.ReasonTokenStoreUnavailable}, {500, `{"reason_code":"arbitrary-private-value"}`, ""}, {200, `{bad-json`, ""}, {200, `{}`, ""}} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		c := NewClients(server.URL, server.URL)
		_, err := c.Substitute(context.Background(), hook.SubstituteRequest{})
		server.Close()
		if err == nil {
			t.Fatal("bad substitution accepted")
		}
		if strings.Contains(err.Error(), "arbitrary-private-value") {
			t.Fatal("private store reason leaked")
		}
		var refusal *hook.RefusalError
		if tc.reason != "" && (!errors.As(err, &refusal) || refusal.ReasonCode != tc.reason) {
			t.Fatal("safe store refusal lost")
		}
	}
}

func TestHostCaseAndPortBoundaries(t *testing.T) {
	for _, authority := range []string{"resource.example", "resource.example:8080"} {
		cfg := testConfig("http://127.0.0.1:1")
		cfg.PublishedBaseURL = "https://" + authority
		r, err := New(cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, host := range []string{authority, strings.ToUpper(authority), "resource.example:443", "resource.example:9090", "foreign.example"} {
			got := r.Evaluate(t.Context(), hook.Request{Method: "POST", Path: "/demo", Host: host, Headers: http.Header{}})
			want := "host_denied"
			if strings.EqualFold(host, authority) {
				want = "mesh_caller_denied"
			}
			if got.ReasonCode != want {
				t.Fatalf("host variant reason %s, want %s", got.ReasonCode, want)
			}
		}
	}
}
