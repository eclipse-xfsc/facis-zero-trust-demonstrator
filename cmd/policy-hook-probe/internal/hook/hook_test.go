package hook_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/policy-hook-probe/internal/contractpath"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/policy-hook-probe/internal/hook"
)

const (
	testID      = "corr-0001"
	testBaseURL = "https://guard-a.example"
)

type fakeDecider struct {
	decision hook.Decision
	err      error
	block    bool
	got      hook.Input
}

func (d *fakeDecider) Decide(ctx context.Context, in hook.Input) (hook.Decision, error) {
	d.got = in
	if d.block {
		<-ctx.Done()
		return hook.Decision{}, ctx.Err()
	}
	return d.decision, d.err
}

type fakeAuth struct{ token hook.Token }

func (a fakeAuth) Authenticate(_, _ string) hook.Token { return a.token }

type fakeSubstituter struct {
	err error
	got hook.SubstituteRequest
}

func (s *fakeSubstituter) Substitute(_ context.Context, req hook.SubstituteRequest) (hook.Substitution, error) {
	s.got = req
	if s.err != nil {
		return hook.Substitution{}, s.err
	}
	return hook.Substitution{Authorization: "DPoP upstream-token", DPoP: "upstream-proof"}, nil
}

type recordingSink struct {
	ids      []string
	payloads []hook.EventPayload
}

func (r *recordingSink) Emit(id string, p hook.EventPayload) {
	r.ids = append(r.ids, id)
	r.payloads = append(r.payloads, p)
}

var (
	presentToken = hook.Token{Present: true, ClientID: "fx-client", JKT: "jkt", Scope: "read", Aud: testBaseURL, ProofValid: true}
	allowSubst   = hook.Decision{Allow: true, BundleRevision: "v1", Obligations: []string{hook.ObligationSubstituteUpstreamToken}}
	ruleDeny     = hook.Decision{ReasonCode: hook.ReasonRuleDeny, RuleID: "data.guard.deny", BundleRevision: "v1", DenyBody: &hook.DenyBody{Error: "insufficient_entitlement"}}
	presentation = hook.Decision{ReasonCode: hook.ReasonPresentationRequired, BundleRevision: "v1", DenyBody: &hook.DenyBody{Error: "presentation_required", OID4VPLink: "https://zone-a.example/present?c=1"}}
)

type fixture struct {
	guard   *hook.Guard
	decider *fakeDecider
	subst   *fakeSubstituter
	sink    *recordingSink
}

func newFixture(decision hook.Decision, token hook.Token) *fixture {
	f := &fixture{decider: &fakeDecider{decision: decision}, subst: &fakeSubstituter{}, sink: &recordingSink{}}
	f.guard = hook.New(hook.Config{PublishedBaseURL: testBaseURL, PeerZone: "zone-b", Audience: "https://guard-b.example",
		SourceID: "spiffe://zone-a.example/ns/data/sa/backend", DecisionTimeout: 50 * time.Millisecond},
		f.decider, fakeAuth{token}, f.subst, f.sink)
	f.guard.SetIDGenerator(func() string { return testID })
	return f
}

func callerRequest() hook.Request {
	return hook.Request{Method: "get", Scheme: "https", Host: "guard-a.example", Path: "/api/data?q=1",
		Headers: http.Header{
			"Authorization": {"DPoP caller-token"}, "DPoP": {"caller-proof"}, "X-Facis-Evil": {"1"},
			"X-Forwarded-For": {"203.0.113.9"}, "X-Forwarded-Host": {"evil.example"},
			"Traceparent": {"00-abc-def-01"}, "X-Request-Id": {"chosen-by-the-caller"},
		}}
}

func header(h []hook.Header, name string) (string, bool) {
	for _, x := range h {
		if x.Name == name {
			return x.Value, true
		}
	}
	return "", false
}

func assertUnavailable(t *testing.T, out hook.Outcome, reason string) {
	t.Helper()
	if out.Allowed || out.Status != http.StatusServiceUnavailable || out.ReasonCode != reason {
		t.Fatalf("expected a 503 %s refusal, got %+v", reason, out)
	}
	var body hook.Refusal
	if err := json.Unmarshal(out.Body, &body); err != nil || body.ReasonCode != reason {
		t.Errorf("body %s (%v)", out.Body, err)
	}
}

func TestAllowSetsSubstitutedUpstreamHeaders(t *testing.T) {
	f := newFixture(allowSubst, presentToken)
	out := f.guard.Evaluate(context.Background(), callerRequest())
	if !out.Allowed || out.Status != 0 || out.Body != nil {
		t.Fatalf("expected a forwarded request, got %+v", out)
	}
	for name, want := range map[string]string{"authorization": "DPoP upstream-token", "dpop": "upstream-proof", hook.HeaderRequestID: testID} {
		if got, ok := header(out.SetHeaders, name); !ok || got != want {
			t.Errorf("set header %s = %q, want %q", name, got, want)
		}
	}
	if f.subst.got.TargetURI != testBaseURL+"/api/data" || f.subst.got.Method != "GET" || f.subst.got.CorrelationID != testID ||
		f.subst.got.PeerZone != "zone-b" || f.subst.got.Audience != "https://guard-b.example" {
		t.Errorf("substitution asked with %+v", f.subst.got)
	}
	for _, name := range []string{"x-facis-evil", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "forwarded"} {
		if !slices.Contains(out.RemoveHeaders, name) {
			t.Errorf("%s is not removed: %v", name, out.RemoveHeaders)
		}
	}
	if slices.Contains(out.RemoveHeaders, "authorization") || slices.Contains(out.RemoveHeaders, "traceparent") {
		t.Errorf("a substituted credential is overwritten and traceparent propagated: %v", out.RemoveHeaders)
	}
}

func TestAllowWithoutObligationRemovesTheCallerCredential(t *testing.T) {
	f := newFixture(hook.Decision{Allow: true, BundleRevision: "v1"}, presentToken)
	out := f.guard.Evaluate(context.Background(), callerRequest())
	if !out.Allowed || !slices.Contains(out.RemoveHeaders, "authorization") || !slices.Contains(out.RemoveHeaders, "dpop") {
		t.Errorf("got %+v", out)
	}
	if _, ok := header(out.SetHeaders, "authorization"); ok || f.subst.got != (hook.SubstituteRequest{}) {
		t.Errorf("no credential is set and the token store is not asked without the obligation")
	}
}

func TestRequestIDIsReplacedAndIsTheCorrelationID(t *testing.T) {
	f := newFixture(allowSubst, presentToken)
	out := f.guard.Evaluate(context.Background(), callerRequest())
	id, _ := header(out.SetHeaders, hook.HeaderRequestID)
	if id != testID || out.CorrelationID != testID || f.decider.got.CorrelationID != testID {
		t.Errorf("request id %q, outcome %q, policy input %q", id, out.CorrelationID, f.decider.got.CorrelationID)
	}
	if len(f.sink.ids) != 1 || f.sink.ids[0] != testID || f.sink.payloads[0].State != "allowed" {
		t.Errorf("decision event: %v %+v", f.sink.ids, f.sink.payloads)
	}
}

func TestPolicyInputIsBuiltFromTheRequest(t *testing.T) {
	f := newFixture(allowSubst, presentToken)
	req := callerRequest()
	f.guard.Evaluate(context.Background(), req)
	in := f.decider.got
	if in.Request != (hook.RequestInfo{Method: "GET", Path: "/api/data", Host: "guard-a.example"}) ||
		in.Source.SPIFFEID != "spiffe://zone-a.example/ns/data/sa/backend" || in.Token != presentToken || in.Tenant != nil {
		t.Errorf("input: %+v", in)
	}
	b, _ := json.Marshal(in)
	if !strings.Contains(string(b), `"tenant":null`) || !strings.Contains(string(b), `"proof_valid":true`) {
		t.Errorf("serialised input: %s", b)
	}
	req.PeerID = "spiffe://zone-a.example/ns/data/sa/other"
	f.guard.Evaluate(context.Background(), req)
	if f.decider.got.Source.SPIFFEID != req.PeerID {
		t.Errorf("an authenticated peer is the source: %+v", f.decider.got.Source)
	}
}

func TestRuleDenyIs403WithReasonBody(t *testing.T) {
	f := newFixture(ruleDeny, presentToken)
	out := f.guard.Evaluate(context.Background(), callerRequest())
	if out.Allowed || out.Status != http.StatusForbidden || out.ReasonCode != hook.ReasonRuleDeny || len(out.RemoveHeaders) != 0 {
		t.Fatalf("got %+v", out)
	}
	var body hook.Refusal
	_ = json.Unmarshal(out.Body, &body)
	if want := (hook.Refusal{Error: "insufficient_entitlement", ReasonCode: hook.ReasonRuleDeny, RuleID: "data.guard.deny"}); body != want {
		t.Errorf("body %+v, want %+v", body, want)
	}
	for name, v := range map[string]string{"content-type": hook.ContentTypeJSON, hook.HeaderReasonCode: hook.ReasonRuleDeny, hook.HeaderRequestID: testID} {
		if got, ok := header(out.SetHeaders, name); !ok || got != v {
			t.Errorf("response header %s = %q, want %q", name, got, v)
		}
	}
	if p := f.sink.payloads[0]; p.State != "denied" || p.ReasonCode != hook.ReasonRuleDeny || p.RuleID != "data.guard.deny" {
		t.Errorf("event payload %+v", p)
	}
}

func TestPresentationRequiredIs401WithLink(t *testing.T) {
	f := newFixture(presentation, hook.Token{Present: false})
	out := f.guard.Evaluate(context.Background(), callerRequest())
	var body hook.Refusal
	_ = json.Unmarshal(out.Body, &body)
	if out.Status != http.StatusUnauthorized || body.OID4VPLink != presentation.DenyBody.OID4VPLink || body.RuleID != "" {
		t.Errorf("status %d body %+v", out.Status, body)
	}
}

func TestFailuresAreRefusedClosed(t *testing.T) {
	f := newFixture(allowSubst, presentToken)
	f.decider.err = errors.New("engine unreachable")
	assertUnavailable(t, f.guard.Evaluate(context.Background(), callerRequest()), hook.ReasonPDPUnavailable)
	if !strings.Contains(f.sink.payloads[0].Detail, "engine unreachable") {
		t.Errorf("event detail %q", f.sink.payloads[0].Detail)
	}

	f = newFixture(hook.Decision{Allow: true, ReasonCode: hook.ReasonRuleDeny, BundleRevision: "v1"}, presentToken)
	assertUnavailable(t, f.guard.Evaluate(context.Background(), callerRequest()), hook.ReasonPDPUnavailable)

	f = newFixture(allowSubst, presentToken)
	f.decider.block = true
	start := time.Now()
	assertUnavailable(t, f.guard.Evaluate(context.Background(), callerRequest()), hook.ReasonPDPUnavailable)
	if time.Since(start) > time.Second {
		t.Error("the decision timeout did not bound the call")
	}

	f = newFixture(allowSubst, presentToken)
	f.subst.err = &hook.RefusalError{ReasonCode: hook.ReasonTokenNoUpstream}
	if out := f.guard.Evaluate(context.Background(), callerRequest()); out.Allowed || out.Status != http.StatusConflict || out.ReasonCode != hook.ReasonTokenNoUpstream {
		t.Errorf("refused substitution: %+v", out)
	}
	f.subst.err = errors.New("connection refused")
	assertUnavailable(t, f.guard.Evaluate(context.Background(), callerRequest()), hook.ReasonTokenStoreUnavailable)
}

func TestDecisionValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		d    hook.Decision
		ok   bool
	}{
		{"allow", hook.Decision{Allow: true, BundleRevision: "v1"}, true},
		{"allow with obligation", allowSubst, true},
		{"allow with unknown obligation", hook.Decision{Allow: true, BundleRevision: "v1", Obligations: []string{"other"}}, false},
		{"rule deny", ruleDeny, true},
		{"presentation required", presentation, true},
		{"no bundle revision", hook.Decision{Allow: true}, false},
		{"deny without body", hook.Decision{ReasonCode: hook.ReasonRuleDeny, RuleID: "r", BundleRevision: "v1"}, false},
	} {
		if err := tc.d.Validate(); (err == nil) != tc.ok {
			t.Errorf("%s: Validate() = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

// --- against the contract -------------------------------------------------------------------

func compile(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	sch, err := c.Compile(filepath.Join(contractpath.Contracts(t), name))
	if err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}
	return sch
}

func validate(t *testing.T, sch *jsonschema.Schema, doc []byte) error {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	return sch.Validate(v)
}

// TestDecisionEventsValidateAgainstTheContract checks the JSON lines the sink writes against
// the security-state event schema, and that the schema would refuse a denial without a reason.
func TestDecisionEventsValidateAgainstTheContract(t *testing.T) {
	sch := compile(t, "if01-event.v1.schema.json")
	var buf bytes.Buffer
	sink := hook.NewLogSink(&buf, "guard-a", "verification")
	sink.Emit("corr-1", hook.EventPayload{State: "allowed"})
	sink.Emit("corr-2", hook.EventPayload{State: "denied", ReasonCode: hook.ReasonRuleDeny, RuleID: "data.guard.deny"})
	sink.Emit("corr-3", hook.EventPayload{State: "denied", ReasonCode: hook.ReasonPDPUnavailable, Detail: "engine unreachable"})
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("%d lines", len(lines))
	}
	for i, line := range lines {
		if err := validate(t, sch, []byte(line)); err != nil {
			t.Errorf("line %d does not validate: %v\n%s", i, err, line)
		}
	}
	e, err := hook.ReadEvent(strings.NewReader(buf.String()), "corr-2")
	if err != nil || e == nil || e.Seq != 1 || e.Kind != "decision" || e.Payload.RuleID != "data.guard.deny" {
		t.Errorf("ReadEvent: %+v (%v)", e, err)
	}
	bad, _ := json.Marshal(hook.Event{RunID: "verification", Seq: 9, TS: time.Now().UTC().Format(time.RFC3339Nano), Source: "guard-a",
		Kind: "decision", Payload: hook.EventPayload{State: "denied"}})
	if err := validate(t, sch, bad); err == nil {
		t.Error("a denial without a reason code validated")
	}
}

// TestDecisionFixturesValidate checks Decision.Validate against every decision fixture, and
// that what the hook re-serialises still validates against the schema.
func TestDecisionFixturesValidate(t *testing.T) {
	sch := compile(t, "if05-policy-decision.v1.schema.json")
	dir := filepath.Join(contractpath.Fixtures(t), "if05-policy-decision.v1")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var seen int
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var d hook.Decision
		if err := json.Unmarshal(b, &d); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		seen++
		if strings.HasPrefix(e.Name(), "valid-") {
			if err := d.Validate(); err != nil {
				t.Errorf("%s: %v", e.Name(), err)
			}
			again, _ := json.Marshal(d)
			if err := validate(t, sch, again); err != nil {
				t.Errorf("%s re-serialised does not validate: %v\n%s", e.Name(), err, again)
			}
		} else if err := d.Validate(); err == nil {
			t.Errorf("%s was accepted", e.Name())
		}
	}
	if seen < 9 {
		t.Errorf("only %d fixtures read", seen)
	}
}

// registry is the part of docs/contracts/reason-codes.json the statuses come from.
type registry struct {
	Families map[string]struct {
		HTTP  *int `json:"http"`
		Codes map[string]struct {
			HTTP *int `json:"http"`
		} `json:"codes"`
	} `json:"families"`
}

// TestStatusesMatchTheRegistry keeps the hook's status table equal to the reason-code registry:
// a code's override, else its family's default.
func TestStatusesMatchTheRegistry(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(contractpath.Contracts(t), "reason-codes.json"))
	if err != nil {
		t.Fatal(err)
	}
	var reg registry
	if err := json.Unmarshal(b, &reg); err != nil {
		t.Fatal(err)
	}
	codes := hook.KnownCodes()
	for _, code := range codes {
		family, _, _ := strings.Cut(code, "-")
		fam, ok := reg.Families[family]
		entry, registered := fam.Codes[code]
		if !ok || !registered {
			t.Errorf("%s is not registered", code)
			continue
		}
		want := fam.HTTP
		if entry.HTTP != nil {
			want = entry.HTTP
		}
		if want == nil || hook.StatusFor(code) != *want {
			t.Errorf("%s: status %d, registry says %v", code, hook.StatusFor(code), want)
		}
	}
	for code := range reg.Families["POL"].Codes {
		if !slices.Contains(codes, code) {
			t.Errorf("policy code %s is registered but unknown to the hook", code)
		}
	}
	if hook.StatusFor("POL-SOMETHING-NEW") != *reg.Families["POL"].HTTP || hook.StatusFor("TOK-SOMETHING-NEW") != *reg.Families["TOK"].HTTP {
		t.Error("an unknown code does not fall back to its family's default")
	}
}

func TestTokenSerialisation(t *testing.T) {
	absent, _ := json.Marshal(hook.Token{Present: false, Scope: "ignored"})
	present, _ := json.Marshal(hook.Token{Present: true, ClientID: "c", JKT: "j", Scope: "s", Aud: "a"})
	if string(absent) != `{"present":false}` || !strings.Contains(string(present), `"proof_valid":false`) || strings.Contains(string(present), `"sub"`) {
		t.Errorf("absent %s present %s", absent, present)
	}
	var back hook.Token
	if err := json.Unmarshal(present, &back); err != nil || back.ClientID != "c" || !back.Present {
		t.Errorf("round trip: %+v (%v)", back, err)
	}
}

// --- the fixtures -----------------------------------------------------------------------------

func asJSON(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

func fileJSON(t *testing.T, path string) any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

func TestFixtureCasesReproduceTheContractFixtures(t *testing.T) {
	dir := contractpath.Fixtures(t)
	fx, err := hook.LoadFixtures(dir)
	if err != nil {
		t.Fatal(err)
	}
	cases := fx.Cases()
	if len(cases) != 3 {
		t.Fatalf("%d cases", len(cases))
	}
	for i, tc := range []struct{ input, decision string }{
		{"valid-example.json", "valid-allow-substitute.json"}, {"", "valid-deny.json"}, {"valid-no-token.json", "valid-presentation-required.json"},
	} {
		c := cases[i]
		if tc.input != "" {
			if got, want := asJSON(t, c.Input), fileJSON(t, filepath.Join(dir, "if05-policy-input.v1", tc.input)); !reflect.DeepEqual(got, want) {
				t.Errorf("%s: input %v\nwant %v", c.Name, got, want)
			}
		}
		if got, want := asJSON(t, c.Decision), fileJSON(t, filepath.Join(dir, "if05-policy-decision.v1", tc.decision)); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: decision %v\nwant %v", c.Name, got, want)
		}
		dec, err := fx.Decide(context.Background(), hook.Input{Token: fx.Authenticate(c.Authorization, "proof")})
		if err != nil || !reflect.DeepEqual(dec, c.Decision) {
			t.Errorf("%s: Decide gave %+v (%v)", c.Name, dec, err)
		}
	}
	for _, auth := range []string{"Bearer " + hook.FixtureTokenRead, "DPoP unknown", ""} {
		if fx.Authenticate(auth, "").Present {
			t.Errorf("%q authenticated", auth)
		}
	}
	if _, err := hook.LoadFixtures(t.TempDir()); err == nil {
		t.Error("an empty directory was accepted")
	}
}
