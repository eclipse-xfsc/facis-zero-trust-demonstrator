package policyevaluator

import (
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
	"net/http"
	"testing"
)

func TestPolicyDefaultsToDenyAndDoesNotElevateSummary(t *testing.T) {
	const participant = "spiffe://zone-b.test/ns/m3/sa/participant"
	p, err := New(Config{Revision: "test-1", Audience: "resource", Host: "resource.test", GuardCallers: []string{"spiffe://zone-b.test/ns/m3/sa/guard"}, ParticipantCallers: []string{participant}, ScopeTenants: map[string]string{"report:read": "read", "report:summary": "summary"}})
	if err != nil {
		t.Fatal(err)
	}
	tenant := "summary"
	valid := hook.Input{Source: hook.Source{SPIFFEID: participant}, Request: hook.RequestInfo{Method: http.MethodPost, Path: "/demo", Host: "resource.test"}, Token: hook.Token{Present: true, ProofValid: true, Sub: "sub", ClientID: "client", JKT: "bound-key", Aud: "resource", Scope: "report:summary"}, Tenant: &tenant}
	if !p.Decide(valid).Allow {
		t.Fatal("valid summary refused")
	}
	for name, change := range map[string]func(*hook.Input){
		"wrong source":      func(i *hook.Input) { i.Source.SPIFFEID = "spiffe://wrong.test/ns/x/sa/y" },
		"wrong audience":    func(i *hook.Input) { i.Token.Aud = "other" },
		"missing proof":     func(i *hook.Input) { i.Token.ProofValid = false },
		"wrong path":        func(i *hook.Input) { i.Request.Path = "/admin" },
		"wrong method":      func(i *hook.Input) { i.Request.Method = "GET" },
		"wrong host":        func(i *hook.Input) { i.Request.Host = "caller.invalid" },
		"no scope":          func(i *hook.Input) { i.Token.Scope = "" },
		"full report route": func(i *hook.Input) { v := "read"; i.Tenant = &v },
		"absent route":      func(i *hook.Input) { i.Tenant = nil },
	} {
		t.Run(name, func(t *testing.T) {
			in := valid
			change(&in)
			decision := p.Decide(in)
			if decision.Allow || decision.Validate() != nil {
				t.Fatal("unsafe input did not produce valid denial")
			}
		})
	}
}

// A gRPC call to a configured method gets the decision the REST route gets, rule and all; a method
// the configuration does not name, or one whose service the guard did not name, is denied.
func TestPolicyDecidesAConfiguredGRPCMethodLikeTheRESTRoute(t *testing.T) {
	const participant = "spiffe://zone-b.test/ns/m3/sa/participant"
	const method = "/grpc.health.v1.Health/Check"
	p, err := New(Config{Revision: "test-1", Audience: "resource", Host: "resource.test", GuardCallers: []string{"spiffe://zone-b.test/ns/m3/sa/guard"}, ParticipantCallers: []string{participant}, ScopeTenants: map[string]string{"report:read": "read", "report:summary": "summary"}, GRPCMethods: []string{method}})
	if err != nil {
		t.Fatal(err)
	}
	tenant := "read"
	rest := hook.Input{Source: hook.Source{SPIFFEID: participant}, Request: hook.RequestInfo{Method: http.MethodPost, Path: "/demo", Host: "resource.test"}, Token: hook.Token{Present: true, ProofValid: true, Sub: "sub", ClientID: "client", JKT: "bound-key", Aud: "resource", Scope: "report:read"}, Tenant: &tenant}
	grpc := rest
	grpc.Request = hook.RequestInfo{Method: http.MethodPost, Path: method, Host: "resource.test", GRPCService: "grpc.health.v1.Health"}
	want, got := p.Decide(rest), p.Decide(grpc)
	if !want.Allow || !got.Allow || got.RuleID != want.RuleID || got.BundleRevision != want.BundleRevision || len(got.Obligations) != len(want.Obligations) {
		t.Fatalf("the gRPC decision %+v is not the REST decision %+v", got, want)
	}
	for name, change := range map[string]func(*hook.Input){
		"method not configured":       func(i *hook.Input) { i.Request.Path = "/grpc.health.v1.Health/Watch" },
		"service of another method":   func(i *hook.Input) { i.Request.GRPCService = "other.Service" },
		"gRPC path without service":   func(i *hook.Input) { i.Request.GRPCService = "" },
		"REST path named as gRPC":     func(i *hook.Input) { i.Request.Path = "/demo" },
		"no token":                    func(i *hook.Input) { i.Token = hook.Token{} },
		"wrong method":                func(i *hook.Input) { i.Request.Method = "GET" },
		"scope of the other tenant":   func(i *hook.Input) { i.Token.Scope = "report:summary" },
		"participant of another zone": func(i *hook.Input) { i.Source.SPIFFEID = "spiffe://wrong.test/ns/x/sa/y" },
	} {
		t.Run(name, func(t *testing.T) {
			in := grpc
			change(&in)
			decision := p.Decide(in)
			if decision.Allow || decision.Validate() != nil {
				t.Fatal("unsafe gRPC input did not produce a valid denial")
			}
		})
	}
	// Without the configuration the same call is no route at all.
	plain, err := New(Config{Revision: "test-1", Audience: "resource", Host: "resource.test", GuardCallers: []string{"spiffe://zone-b.test/ns/m3/sa/guard"}, ParticipantCallers: []string{participant}, ScopeTenants: map[string]string{"report:read": "read", "report:summary": "summary"}})
	if err != nil {
		t.Fatal(err)
	}
	if plain.Decide(grpc).Allow {
		t.Fatal("a gRPC method was allowed by a policy that names none")
	}
}
