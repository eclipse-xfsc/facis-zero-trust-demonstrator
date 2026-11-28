package guard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/tokenverify"
)

func testConfig(endpoint string) Config {
	return Config{Issuer: "https://issuer.example", JWKSURL: endpoint + "/jwks", InboundAudience: "guard", UpstreamAudience: "resource", PublishedBaseURL: "https://resource.example", PeerZone: "test", PolicyURL: endpoint, StoreURL: endpoint, AllowedCallers: []string{"spiffe://test/ns/demo/sa/participant"}, ScopeTenants: map[string]string{"report:read": "read", "report:summary": "summary"}, EventSource: "guard-b"}
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	for _, change := range []func(*Config){func(c *Config) { c.PublishedBaseURL = "https://resource.example/path" }, func(c *Config) { c.StoreURL = "http://user:password@store" }, func(c *Config) { c.PolicyURL = "ftp://policy" }, func(c *Config) { c.Issuer = "" }, func(c *Config) { c.InboundAudience = "" }, func(c *Config) { c.UpstreamAudience = "" }, func(c *Config) { c.UpstreamAudience = c.InboundAudience }, func(c *Config) { c.InboundAudience = " " }, func(c *Config) { c.UpstreamAudience = "bad audience" }, func(c *Config) { c.InboundAudience = "guard\u00a0audience" }, func(c *Config) { c.UpstreamAudience = "resource\u2003audience" }, func(c *Config) { c.JWKSURL = "bad" }, func(c *Config) { c.AllowedCallers = []string{"invalid"} }, func(c *Config) { c.ScopeTenants["report:summary"] = "read" }, func(c *Config) { c.TargetTenant = "Tenant A" }} {
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
	for _, tc := range []struct{ method, path, host, reason string }{{"POST", "/demo", "foreign.example", "POL-RULE-DENY"}, {"POST", "/other", "resource.example", "POL-RULE-DENY"}, {"GET", "/demo", "resource.example", "POL-RULE-DENY"}} {
		got := r.Evaluate(t.Context(), hook.Request{Method: tc.method, Path: tc.path, Host: tc.host, Headers: http.Header{}})
		if got.Allowed || got.Status != 403 || got.ReasonCode != tc.reason || got.RuleID != guardRule {
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
			want := "POL-RULE-DENY"
			if strings.EqualFold(host, authority) {
				want = "MESH-PAIR-DENIED"
			}
			if got.ReasonCode != want {
				t.Fatalf("host variant reason %s, want %s", got.ReasonCode, want)
			}
		}
	}
}

// TestRefusalsUseTheRegistry keeps every guard refusal on a registered code with the registry's
// status (a family without an HTTP status of its own, MESH, answers 403).
func TestRefusalsUseTheRegistry(t *testing.T) {
	raw, err := os.ReadFile("../../docs/contracts/reason-codes.json")
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		Families map[string]struct {
			HTTP  *int `json:"http"`
			Codes map[string]struct {
				HTTP *int `json:"http"`
			} `json:"codes"`
		} `json:"families"`
	}
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatal(err)
	}
	for runtimeCode, entry := range registry {
		family, ok := reg.Families[strings.SplitN(entry.code, "-", 2)[0]]
		code, registered := family.Codes[entry.code]
		if !ok || !registered {
			t.Fatalf("%s maps to unregistered %s", runtimeCode, entry.code)
		}
		want := http.StatusForbidden
		if code.HTTP != nil {
			want = *code.HTTP
		} else if family.HTTP != nil {
			want = *family.HTTP
		}
		if entry.status != want {
			t.Fatalf("%s: %s answers %d, registry %d", runtimeCode, entry.code, entry.status, want)
		}
	}
	for _, code := range []string{"token_absent", "proof_absent", "token_malformed", "signature_invalid", "token_expired", "issuer_mismatch", "audience_mismatch", "scope_insufficient", "key_binding_mismatch", "proof_invalid", "proof_replayed", "key_set_unavailable", "request_invalid", "replay_unavailable", "unclassified"} {
		if _, ok := registry[code]; !ok {
			t.Fatalf("verifier code %s unmapped", code)
		}
	}
}

type tenantEvents struct{ ps []hook.EventPayload }

func (s *tenantEvents) Emit(_ string, p hook.EventPayload) { s.ps = append(s.ps, p) }

// TestTargetTenantComesFromConfiguration: the policy input and every decision event name the
// configured tenant, whatever the request says.
func TestTargetTenantComesFromConfiguration(t *testing.T) {
	var got []string
	policy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input hook.Input
		_ = json.NewDecoder(r.Body).Decode(&input)
		got = append(got, input.TargetTenant)
		_ = json.NewEncoder(w).Encode(map[string]any{"allow": false, "reason_code": hook.ReasonRuleDeny, "rule_id": "m3-tenant-membership", "bundle_revision": "test", "deny_body": map[string]string{"error": "access_denied"}})
	}))
	defer policy.Close()
	c := testConfig(policy.URL)
	c.TargetTenant = "tenant-a"
	events := &tenantEvents{}
	r, err := New(c, events)
	if err != nil {
		t.Fatal(err)
	}
	r.verifier = verifiedUnitIdentity{}
	headers := http.Header{"X-Forwarded-Client-Cert": []string{"URI=spiffe://test/ns/demo/sa/participant"}, "X-Facis-Tenant": []string{"tenant-b"}, "Tenant": []string{"tenant-b"}}
	denied := r.Evaluate(t.Context(), hook.Request{Method: "POST", Path: "/demo", Host: "resource.example", Headers: headers})
	refused := r.Evaluate(t.Context(), hook.Request{Method: "POST", Path: "/demo", Host: "resource.example", Headers: http.Header{}})
	if denied.Allowed || denied.RuleID != "m3-tenant-membership" || refused.ReasonCode != "MESH-PAIR-DENIED" || !slices.Equal(got, []string{"tenant-a"}) {
		t.Fatalf("policy saw %v; outcomes %+v %+v", got, denied, refused)
	}
	if len(events.ps) != 2 || events.ps[0].Tenant != "tenant-a" || events.ps[1].Tenant != "tenant-a" {
		t.Fatalf("events do not carry the configured tenant: %+v", events.ps)
	}
}

// A gRPC call is a route only when its method is configured and its content type is gRPC's; the
// REST route is unaffected by the gRPC configuration.
func TestGRPCRouteNeedsAConfiguredMethodAndAGRPCContentType(t *testing.T) {
	const method = "/grpc.health.v1.Health/Check"
	cfg := testConfig("http://127.0.0.1:1")
	cfg.GRPCMethods = []string{method}
	r, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, method, path, contentType, service string
		routed                                   bool
	}{
		{"configured method", "POST", method, "application/grpc", "grpc.health.v1.Health", true},
		{"with a message encoding", "POST", method, "application/grpc+proto", "grpc.health.v1.Health", true},
		{"REST route", "POST", "/demo", "application/json", "", true},
		{"method not configured", "POST", "/grpc.health.v1.Health/Watch", "application/grpc", "", false},
		{"not a gRPC content type", "POST", method, "application/json", "", false},
		{"a look-alike content type", "POST", method, "application/grpcx", "", false},
		{"no content type", "POST", method, "", "", false},
		{"GET", "GET", method, "application/grpc", "", false},
		{"path with a query", "POST", method + "?x=1", "application/grpc", "", false},
	} {
		in := hook.Request{Method: tc.method, Path: tc.path, Headers: http.Header{}}
		if tc.contentType != "" {
			in.Headers.Set("Content-Type", tc.contentType)
		}
		service, routed := r.route(in)
		if routed != tc.routed || service != tc.service {
			t.Errorf("%s: routed=%v service=%q, want %v %q", tc.name, routed, service, tc.routed, tc.service)
		}
	}
	plain, err := New(testConfig("http://127.0.0.1:1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	in := hook.Request{Method: "POST", Path: method, Headers: http.Header{"Content-Type": []string{"application/grpc"}}}
	if _, routed := plain.route(in); routed {
		t.Error("a gRPC method is a route of a guard that names none")
	}
	for _, bad := range []string{"grpc.health.v1.Health/Check", "/Check", "/grpc.health.v1.Health/", "/a/b/c", "/pkg.Service/Method?x", "/demo"} {
		cfg := testConfig("http://127.0.0.1:1")
		cfg.GRPCMethods = []string{bad}
		if _, err := New(cfg, nil); err == nil {
			t.Errorf("gRPC method %q accepted", bad)
		}
	}
}
