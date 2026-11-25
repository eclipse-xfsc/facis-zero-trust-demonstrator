package policyevaluator

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/contractpath"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
)

const (
	participant = "spiffe://zone-b.test/ns/m3/sa/participant"
	guardID     = "spiffe://zone-b.test/ns/m3/sa/guard"
	link        = "openid4vp://authorize?request_uri=https%3A%2F%2Fverifier.test%2Frequest"
)

func testConfig() Config {
	return Config{Revision: "test-1", Audience: "resource", Host: "resource.test", GuardCallers: []string{guardID}, ParticipantCallers: []string{participant},
		ScopeTenants: map[string]string{"report:read": "read", "report:summary": "summary"}, EventSource: "policy-b",
		BlockedClients: []string{"blocked-client"}, Presentation: &Presentation{Scopes: []string{"report:full"}, OID4VPLink: link}}
}

func validInput() hook.Input {
	tenant := "summary"
	return hook.Input{CorrelationID: "corr-1", Source: hook.Source{SPIFFEID: participant}, Request: hook.RequestInfo{Method: http.MethodPost, Path: "/demo", Host: "resource.test"}, Token: hook.Token{Present: true, ProofValid: true, Sub: "sub", ClientID: "client", JKT: "bound-key", Aud: "resource", Scope: "report:summary"}, Tenant: &tenant}
}

func TestPolicyDefaultsToDenyAndDoesNotElevateSummary(t *testing.T) {
	p, err := New(testConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Decide(validInput()); !d.Allow || d.RuleID != "m3-report-summary" || d.BundleRevision != "test-1" {
		t.Fatalf("valid summary refused: %+v", d)
	}
	for name, tc := range map[string]struct {
		change func(*hook.Input)
		rule   string
	}{
		"wrong source":          {func(i *hook.Input) { i.Source.SPIFFEID = "spiffe://wrong.test/ns/x/sa/y" }, RuleDefaultDeny},
		"wrong audience":        {func(i *hook.Input) { i.Token.Aud = "other" }, RuleDefaultDeny},
		"missing proof":         {func(i *hook.Input) { i.Token.ProofValid = false }, RuleDefaultDeny},
		"wrong path":            {func(i *hook.Input) { i.Request.Path = "/admin" }, RuleDefaultDeny},
		"wrong method":          {func(i *hook.Input) { i.Request.Method = "GET" }, RuleDefaultDeny},
		"wrong host":            {func(i *hook.Input) { i.Request.Host = "caller.invalid" }, RuleDefaultDeny},
		"no token":              {func(i *hook.Input) { i.Token = hook.Token{} }, RuleDefaultDeny},
		"no scope":              {func(i *hook.Input) { i.Token.Scope = "" }, RuleScopeRequired},
		"unknown scope":         {func(i *hook.Input) { i.Token.Scope = "report:admin" }, RuleScopeRequired},
		"blocked client":        {func(i *hook.Input) { i.Token.ClientID = "blocked-client" }, RuleClientBlocked},
		"full report route":     {func(i *hook.Input) { v := "read"; i.Tenant = &v }, RuleTenantRoute},
		"absent route":          {func(i *hook.Input) { i.Tenant = nil }, RuleTenantRoute},
		"presentation required": {func(i *hook.Input) { i.Token.Scope = "report:full report:summary" }, RulePresentationRequired},
	} {
		t.Run(name, func(t *testing.T) {
			in := validInput()
			tc.change(&in)
			d := p.Decide(in)
			if d.Allow || d.Validate() != nil || d.RuleID != tc.rule || d.BundleRevision != "test-1" {
				t.Fatalf("got %+v, want denial by %s", d, tc.rule)
			}
			want := hook.ReasonRuleDeny
			if tc.rule == RulePresentationRequired {
				want = hook.ReasonPresentationRequired
				if d.DenyBody.OID4VPLink != link {
					t.Fatal("presentation denial without the OID4VP link")
				}
			}
			if d.ReasonCode != want {
				t.Fatalf("reason %s, want %s", d.ReasonCode, want)
			}
		})
	}
}

func TestConfigurationRefused(t *testing.T) {
	for _, change := range []func(*Config){
		func(c *Config) { c.EventSource = "guard-b" },
		func(c *Config) { c.Presentation.OID4VPLink = "javascript:alert(1)" },
		func(c *Config) { c.Presentation.Scopes = nil },
		func(c *Config) { c.Presentation.Scopes = []string{"report:read"} },
	} {
		c := testConfig()
		p := *c.Presentation
		c.Presentation = &p
		change(&c)
		if _, err := New(c, nil); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
}

type sink struct {
	ids []string
	ps  []hook.EventPayload
}

func (s *sink) Emit(id string, p hook.EventPayload) { s.ids, s.ps = append(s.ids, id), append(s.ps, p) }

// TestEveryDecisionIsRecorded: each answered decision is one event under the guard's correlation
// id, with the rule id and bundle revision that decided it.
func TestEveryDecisionIsRecorded(t *testing.T) {
	events := &sink{}
	p, err := New(testConfig(), events)
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"report:summary", "report:full"} {
		in := validInput()
		in.Token.Scope = scope
		body, _ := json.Marshal(in)
		req := httptest.NewRequest(http.MethodPost, "/decision", bytes.NewReader(body))
		req.Header.Set("X-Forwarded-Client-Cert", "URI="+guardID)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
	}
	if len(events.ps) != 2 || events.ids[0] != "corr-1" {
		t.Fatalf("events: %+v %+v", events.ids, events.ps)
	}
	allowed, denied := events.ps[0], events.ps[1]
	if allowed.State != "allowed" || allowed.RuleID != "m3-report-summary" || allowed.BundleRevision != "test-1" || allowed.CallerSPIFFEID != participant || allowed.TokenSubject != "sub" || allowed.Resource != "POST resource.test/demo" {
		t.Fatalf("allowed event: %+v", allowed)
	}
	if denied.State != "denied" || denied.ReasonCode != hook.ReasonPresentationRequired || denied.RuleID != RulePresentationRequired {
		t.Fatalf("denied event: %+v", denied)
	}
	if strings.Contains(denied.Detail, link) {
		t.Fatal("link copied into the event")
	}
}

// TestTenantMembership: with tenants configured, a request is allowed only for a member of the
// target tenant the guard's route names, in both directions; the event carries that tenant. Scope
// separation still holds inside a tenant.
func TestTenantMembership(t *testing.T) {
	const memberA, memberB = "spiffe://zone-a.test/ns/tenant-a/sa/ztd-participant", "spiffe://zone-a.test/ns/tenant-b/sa/ztd-participant"
	for _, own := range []struct{ tenant, member, other string }{{"tenant-a", memberA, memberB}, {"tenant-b", memberB, memberA}} {
		c := testConfig()
		c.ParticipantCallers = []string{memberA, memberB}
		c.TenantMembers = map[string][]string{own.tenant: {own.member}}
		c.ScopeTenants = map[string]string{"report:read": own.tenant + "-read", "report:summary": own.tenant + "-summary"}
		events := &sink{}
		p, err := New(c, events)
		if err != nil {
			t.Fatal(err)
		}
		in := validInput()
		route := own.tenant + "-summary"
		in.Tenant, in.TargetTenant, in.Source.SPIFFEID = &route, own.tenant, own.member
		if d := p.Decide(in); !d.Allow || d.RuleID != "m3-report-summary" {
			t.Fatalf("%s member refused: %+v", own.tenant, d)
		}
		for name, change := range map[string]func(*hook.Input){
			"other tenant's caller":        func(i *hook.Input) { i.Source.SPIFFEID = own.other },
			"no target tenant":             func(i *hook.Input) { i.TargetTenant = "" },
			"route of a tenant not served": func(i *hook.Input) { i.TargetTenant = "tenant-c" },
		} {
			bad := in
			change(&bad)
			if d := p.Decide(bad); d.Allow || d.RuleID != RuleTenantMembership || d.ReasonCode != hook.ReasonRuleDeny {
				t.Fatalf("%s %s: got %+v", own.tenant, name, d)
			}
		}
		// Scope separation inside the tenant: a summary token never selects the full-report route.
		full := own.tenant + "-read"
		in.Tenant = &full
		if d := p.Decide(in); d.Allow || d.RuleID != RuleTenantRoute {
			t.Fatalf("%s summary token on the full route: %+v", own.tenant, d)
		}
		cross := in
		cross.Source.SPIFFEID, cross.Tenant = own.other, &route
		p.record(cross, p.Decide(cross))
		if e := events.ps[len(events.ps)-1]; e.Tenant != own.tenant || e.RuleID != RuleTenantMembership || e.State != "denied" || e.CallerSPIFFEID != own.other {
			t.Fatalf("%s cross-tenant event: %+v", own.tenant, e)
		}
	}
	// A target tenant reaching a policy that serves no tenant is denied, not ignored.
	p, _ := New(testConfig(), nil)
	in := validInput()
	in.TargetTenant = "tenant-a"
	if d := p.Decide(in); d.Allow || d.RuleID != RuleTenantMembership {
		t.Fatalf("untenanted policy accepted a target tenant: %+v", d)
	}
	for _, members := range []map[string][]string{{"Tenant A": {participant}}, {"tenant-a": nil}, {"tenant-a": {"spiffe://zone-a.test/ns/x/sa/not-a-caller"}}} {
		c := testConfig()
		c.TenantMembers = members
		if _, err := New(c, nil); err == nil {
			t.Fatalf("tenant_members %v accepted", members)
		}
	}
}

// checkV2Event validates one written event line against the IF-01 v2 schema and returns it.
func checkV2Event(t *testing.T, line []byte) hook.Event {
	t.Helper()
	c := jsonschema.NewCompiler()
	sch, err := c.Compile(filepath.Join(contractpath.Contracts(t), "if01-event.v2.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	line = bytes.TrimSpace(line)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(line))
	if err != nil {
		t.Fatalf("event %q: %v", line, err)
	}
	if err := sch.Validate(doc); err != nil {
		t.Fatalf("event does not validate against IF-01 v2: %v\n%s", err, line)
	}
	var e hook.Event
	_ = json.Unmarshal(line, &e)
	return e
}

// TestBuiltInRulesWriteValidV2Events: the Go rule source's events through the real v2 sink.
func TestBuiltInRulesWriteValidV2Events(t *testing.T) {
	var events bytes.Buffer
	p, err := New(testConfig(), hook.NewLogSinkV2(&events, "policy-b", "go-test"))
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"report:summary", "other:read"} {
		events.Reset()
		in := validInput()
		in.Token.Scope = scope
		body, _ := json.Marshal(in)
		req := httptest.NewRequest(http.MethodPost, "/decision", bytes.NewReader(body))
		req.Header.Set("X-Forwarded-Client-Cert", "URI="+guardID)
		p.ServeHTTP(httptest.NewRecorder(), req)
		e := checkV2Event(t, events.Bytes())
		if e.Payload.BundleRevision != "test-1" || e.Payload.RuleID == "" || e.CorrelationID != "corr-1" {
			t.Fatalf("event %+v", e)
		}
	}
}

// A gRPC call to a configured method gets the decision the REST route gets, rule and all; a method
// the configuration does not name, or one whose service the guard did not name, is denied.
func TestPolicyDecidesAConfiguredGRPCMethodLikeTheRESTRoute(t *testing.T) {
	const participant = "spiffe://zone-b.test/ns/m3/sa/participant"
	const method = "/grpc.health.v1.Health/Check"
	p, err := New(Config{Revision: "test-1", Audience: "resource", Host: "resource.test", GuardCallers: []string{"spiffe://zone-b.test/ns/m3/sa/guard"}, ParticipantCallers: []string{participant}, ScopeTenants: map[string]string{"report:read": "read", "report:summary": "summary"}, EventSource: "policy-b", GRPCMethods: []string{method}}, nil)
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
	// The decision event names the gRPC method as the resource.
	events := &sink{}
	recordDecision(events, "resource.test", grpc, got)
	if events.ps[0].Resource != "POST resource.test"+method || events.ps[0].State != "allowed" {
		t.Fatalf("gRPC decision event: %+v", events.ps[0])
	}
	// Without the configuration the same call is no route at all.
	plain, err := New(Config{Revision: "test-1", Audience: "resource", Host: "resource.test", GuardCallers: []string{"spiffe://zone-b.test/ns/m3/sa/guard"}, ParticipantCallers: []string{participant}, ScopeTenants: map[string]string{"report:read": "read", "report:summary": "summary"}, EventSource: "policy-b"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plain.Decide(grpc).Allow {
		t.Fatal("a gRPC method was allowed by a policy that names none")
	}
}
