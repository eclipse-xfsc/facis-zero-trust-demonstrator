package envoyhook_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"reflect"
	"sort"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/policy-hook-probe/internal/contractpath"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/policy-hook-probe/internal/envoyhook"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/policy-hook-probe/internal/hook"
)

type failingDecider struct{}

func (failingDecider) Decide(context.Context, hook.Input) (hook.Decision, error) {
	return hook.Decision{}, errors.New("engine down")
}

func newGuard(t *testing.T, decider hook.Decider) (*hook.Guard, *hook.Fixtures) {
	t.Helper()
	fx, err := hook.LoadFixtures(contractpath.Fixtures(t))
	if err != nil {
		t.Fatal(err)
	}
	if decider == nil {
		decider = fx
	}
	return hook.New(hook.Config{PublishedBaseURL: "https://guard-a.example", PeerZone: "zone-b", Audience: "https://guard-b.example",
		SourceID: "spiffe://zone-a.example/ns/data/sa/backend"}, decider, fx,
		hook.StaticSubstituter{Authorization: "DPoP upstream-token", DPoP: "upstream-proof"}, nil), fx
}

var callerHeaders = map[string]string{"dpop": "caller-proof", "x-facis-evil": "1", "x-forwarded-for": "203.0.113.9", "traceparent": "00-a-b-01"}

func checkRequest(authorization string) *authv3.CheckRequest {
	headers := map[string]string{":method": "GET", ":path": "/api/data", ":authority": "guard-a.example"}
	for k, v := range callerHeaders {
		headers[k] = v
	}
	if authorization != "" {
		headers["authorization"] = authorization
	}
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
		Source: &authv3.AttributeContext_Peer{Principal: "spiffe://zone-a.example/ns/data/sa/caller"},
		Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{
			Method: "GET", Path: "/api/data", Host: "guard-a.example", Scheme: "https", Headers: headers}},
	}}
}

func headersMessage(authorization string) *extprocv3.ProcessingRequest {
	hm := &corev3.HeaderMap{}
	for k, v := range map[string]string{":method": "GET", ":path": "/api/data", ":authority": "guard-a.example", ":scheme": "https"} {
		hm.Headers = append(hm.Headers, &corev3.HeaderValue{Key: k, RawValue: []byte(v)})
	}
	for k, v := range callerHeaders {
		hm.Headers = append(hm.Headers, &corev3.HeaderValue{Key: k, RawValue: []byte(v)})
	}
	if authorization != "" {
		hm.Headers = append(hm.Headers, &corev3.HeaderValue{Key: "authorization", RawValue: []byte(authorization)})
	}
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestHeaders{
		RequestHeaders: &extprocv3.HttpHeaders{Headers: hm, EndOfStream: true}}}
}

func TestAuthzRequestReadsTheAttributes(t *testing.T) {
	req := envoyhook.AuthzRequest(checkRequest("DPoP x"))
	if req.Method != "GET" || req.Path != "/api/data" || req.Host != "guard-a.example" || req.Scheme != "https" ||
		req.PeerID != "spiffe://zone-a.example/ns/data/sa/caller" || req.Headers.Get("Authorization") != "DPoP x" {
		t.Errorf("request %+v", req)
	}
	if _, ok := req.Headers[":path"]; ok {
		t.Error("pseudo headers are not request headers")
	}
}

func TestCheckAllowAndDeny(t *testing.T) {
	g, _ := newGuard(t, nil)
	s := envoyhook.NewAuthzServer(g)
	resp, err := s.Check(context.Background(), checkRequest("DPoP "+hook.FixtureTokenRead))
	if err != nil || codes.Code(resp.GetStatus().GetCode()) != codes.OK || resp.GetOkResponse() == nil {
		t.Fatalf("allow: %v (%v)", resp, err)
	}
	set := map[string]string{}
	for _, h := range resp.GetOkResponse().GetHeaders() {
		set[h.GetHeader().GetKey()] = value(h)
	}
	if set["authorization"] != "DPoP upstream-token" || set["dpop"] != "upstream-proof" || set[hook.HeaderRequestID] == "" {
		t.Errorf("set headers %v", set)
	}
	if removed := resp.GetOkResponse().GetHeadersToRemove(); !contains(removed, "x-facis-evil") || !contains(removed, "x-forwarded-for") {
		t.Errorf("removed %v", removed)
	}

	resp, err = s.Check(context.Background(), checkRequest(""))
	if err != nil || codes.Code(resp.GetStatus().GetCode()) != codes.Unauthenticated {
		t.Fatalf("deny: %v (%v)", resp, err)
	}
	denied := resp.GetDeniedResponse()
	headers := map[string]string{}
	for _, h := range denied.GetHeaders() {
		headers[h.GetHeader().GetKey()] = value(h)
	}
	var body hook.Refusal
	if int(denied.GetStatus().GetCode()) != http.StatusUnauthorized || headers["content-type"] != hook.ContentTypeJSON ||
		headers[hook.HeaderReasonCode] != hook.ReasonPresentationRequired ||
		json.Unmarshal([]byte(denied.GetBody()), &body) != nil || body.OID4VPLink == "" {
		t.Errorf("denied response %v", denied)
	}

	g, _ = newGuard(t, failingDecider{})
	resp, _ = envoyhook.NewAuthzServer(g).Check(context.Background(), checkRequest("DPoP "+hook.FixtureTokenRead))
	if codes.Code(resp.GetStatus().GetCode()) != codes.Unavailable || int(resp.GetDeniedResponse().GetStatus().GetCode()) != http.StatusServiceUnavailable {
		t.Errorf("unavailable: %v", resp)
	}
}

// dial serves both services in-process and returns an ext_proc client stream.
func dial(t *testing.T, g *hook.Guard) extprocv3.ExternalProcessor_ProcessClient {
	t.Helper()
	ln := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	envoyhook.Register(srv, g)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return ln.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	stream, err := extprocv3.NewExternalProcessorClient(conn).Process(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return stream
}

func TestProcessRequestHeaders(t *testing.T) {
	g, _ := newGuard(t, nil)
	stream := dial(t, g)
	if err := stream.Send(headersMessage("DPoP " + hook.FixtureTokenRead)); err != nil {
		t.Fatal(err)
	}
	resp, err := stream.Recv()
	if err != nil || resp.GetRequestHeaders().GetResponse().GetStatus() != extprocv3.CommonResponse_CONTINUE {
		t.Fatalf("allow: %v (%v)", resp, err)
	}
	m := resp.GetRequestHeaders().GetResponse().GetHeaderMutation()
	set := map[string]string{}
	for _, h := range m.GetSetHeaders() {
		set[h.GetHeader().GetKey()] = value(h)
	}
	if set["authorization"] != "DPoP upstream-token" || !contains(m.GetRemoveHeaders(), "x-facis-evil") {
		t.Errorf("mutation set %v remove %v", set, m.GetRemoveHeaders())
	}
	// A later phase is passed through unchanged.
	_ = stream.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseHeaders{
		ResponseHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{}}}})
	if resp, err = stream.Recv(); err != nil || resp.GetResponseHeaders() == nil || resp.GetResponseHeaders().GetResponse().GetHeaderMutation() != nil {
		t.Errorf("response headers phase: %v (%v)", resp, err)
	}

	stream = dial(t, g)
	_ = stream.Send(headersMessage("DPoP " + hook.FixtureTokenNone))
	resp, err = stream.Recv()
	im := resp.GetImmediateResponse()
	var body hook.Refusal
	if err != nil || im == nil || int(im.GetStatus().GetCode()) != http.StatusForbidden || im.GetDetails() != hook.ReasonRuleDeny ||
		json.Unmarshal(im.GetBody(), &body) != nil || body.RuleID == "" {
		t.Errorf("deny: %v (%v)", resp, err)
	}
}

// translation is what both filters tell Envoy to do, in one shape.
type translation struct {
	Allowed bool
	Status  int
	Set     map[string]string
	Remove  []string
	Body    string
}

func fromAuthz(r *authv3.CheckResponse) translation {
	tr := translation{Set: map[string]string{}}
	if ok := r.GetOkResponse(); ok != nil {
		tr.Allowed, tr.Remove = true, append([]string(nil), ok.GetHeadersToRemove()...)
		for _, h := range ok.GetHeaders() {
			tr.Set[h.GetHeader().GetKey()] = value(h)
		}
		return tr
	}
	d := r.GetDeniedResponse()
	tr.Status, tr.Body = int(d.GetStatus().GetCode()), d.GetBody()
	for _, h := range d.GetHeaders() {
		tr.Set[h.GetHeader().GetKey()] = value(h)
	}
	return tr
}

func fromProc(r *extprocv3.ProcessingResponse) translation {
	tr := translation{Set: map[string]string{}}
	if hr := r.GetRequestHeaders(); hr != nil {
		m := hr.GetResponse().GetHeaderMutation()
		tr.Allowed, tr.Remove = true, append([]string(nil), m.GetRemoveHeaders()...)
		for _, h := range m.GetSetHeaders() {
			tr.Set[h.GetHeader().GetKey()] = value(h)
		}
		return tr
	}
	im := r.GetImmediateResponse()
	tr.Status, tr.Body = int(im.GetStatus().GetCode()), string(im.GetBody())
	for _, h := range im.GetHeaders().GetSetHeaders() {
		tr.Set[h.GetHeader().GetKey()] = value(h)
	}
	return tr
}

// TestBothFiltersTranslateOutcomesIdentically runs the fixture cases through the guard once and
// checks that the ext_authz and ext_proc translations say the same thing.
func TestBothFiltersTranslateOutcomesIdentically(t *testing.T) {
	g, fx := newGuard(t, nil)
	g.SetIDGenerator(func() string { return "corr-parity" })
	for _, c := range fx.Cases() {
		req := hook.Request{Method: "GET", Scheme: "https", Host: "guard-a.example", Path: "/api/data",
			Headers: http.Header{"DPoP": {"caller-proof"}, "X-Facis-Evil": {"1"}, "X-Forwarded-For": {"203.0.113.9"}}}
		if c.Authorization != "" {
			req.Headers.Set("Authorization", c.Authorization)
		}
		out := g.Evaluate(context.Background(), req)
		a, b := fromAuthz(envoyhook.AuthzResponse(out)), fromProc(envoyhook.ProcResponse(out))
		sort.Strings(a.Remove)
		sort.Strings(b.Remove)
		if !reflect.DeepEqual(a, b) || a.Allowed != c.Decision.Allow {
			t.Errorf("%s: ext_authz %+v\next_proc %+v", c.Name, a, b)
		}
	}
}

// value is a header's value under either member.
func value(h *corev3.HeaderValueOption) string {
	if v := h.GetHeader().GetValue(); v != "" {
		return v
	}
	return string(h.GetHeader().GetRawValue())
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
