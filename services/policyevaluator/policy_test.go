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
