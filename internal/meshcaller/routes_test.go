package meshcaller

import (
	"errors"
	"testing"
)

const (
	guardID = "spiffe://zone-a.example/ns/ztd-mgmt/sa/guard"
	otherID = "spiffe://zone-a.example/ns/ztd-data/sa/participant"
)

func testRoutes(t *testing.T) Routes {
	t.Helper()
	rs, err := NewRoutes([]Route{{
		Callers: []string{guardID}, PeerZone: "zone-b", Audience: "https://api.zone-b.example", Tenant: "",
		Methods: []string{"GET", "POST"}, TargetPrefix: "https://api.zone-b.example/v1",
	}, {
		Callers: []string{otherID}, PeerZone: "zone-b", Audience: "https://api.zone-b.example", Tenant: "t1",
		Methods: []string{"GET"}, TargetPrefix: "https://api.zone-b.example/",
	}})
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestRoutesAuthorize(t *testing.T) {
	rs := testRoutes(t)
	ok := Request{PeerZone: "zone-b", Audience: "https://api.zone-b.example", Method: "GET", TargetURI: "https://api.zone-b.example/v1/items?x=1"}
	if r, err := rs.Authorize(Caller{SPIFFEID: guardID}, ok); err != nil || r.TargetPrefix != "https://api.zone-b.example/v1" {
		t.Fatalf("allowed request: %+v %v", r, err)
	}
	exact := ok
	exact.TargetURI = "https://api.zone-b.example/v1"
	if _, err := rs.Authorize(Caller{SPIFFEID: guardID}, exact); err != nil {
		t.Errorf("the prefix itself: %v", err)
	}
	if _, err := rs.Authorize(Caller{SPIFFEID: "spiffe://zone-a.example/ns/x/sa/y"}, ok); !errors.Is(err, ErrCallerDenied) {
		t.Errorf("unlisted caller: %v", err)
	}
	if _, err := rs.Authorize(Caller{}, ok); !errors.Is(err, ErrCallerDenied) {
		t.Errorf("anonymous caller: %v", err)
	}
	for name, edit := range map[string]func(*Request){
		"peer zone":              func(r *Request) { r.PeerZone = "zone-c" },
		"audience":               func(r *Request) { r.Audience = "https://other.zone-b.example" },
		"tenant":                 func(r *Request) { r.Tenant = "t1" },
		"method":                 func(r *Request) { r.Method = "DELETE" },
		"another caller's route": func(r *Request) { r.Tenant = "t1"; r.TargetURI = "https://api.zone-b.example/x" },
		"sibling segment":        func(r *Request) { r.TargetURI = "https://api.zone-b.example/v10/items" },
		"other origin":           func(r *Request) { r.TargetURI = "https://evil.example/v1/items" },
		"other port":             func(r *Request) { r.TargetURI = "https://api.zone-b.example:8443/v1/items" },
		"http":                   func(r *Request) { r.TargetURI = "http://api.zone-b.example/v1/items" },
		"dot segment":            func(r *Request) { r.TargetURI = "https://api.zone-b.example/v1/../admin" },
		"encoded dot segment":    func(r *Request) { r.TargetURI = "https://api.zone-b.example/v1/%2E%2e/admin" },
		"matrix dot segment":     func(r *Request) { r.TargetURI = "https://api.zone-b.example/v1/..;x/admin" },
		"encoded slash":          func(r *Request) { r.TargetURI = "https://api.zone-b.example/v1%2F..%2Fadmin" },
		"backslash":              func(r *Request) { r.TargetURI = `https://api.zone-b.example/v1\..\admin` },
		"userinfo":               func(r *Request) { r.TargetURI = "https://u@api.zone-b.example/v1/items" },
		"fragment":               func(r *Request) { r.TargetURI = "https://api.zone-b.example/v1/items#x" },
		"uppercase host":         func(r *Request) { r.TargetURI = "https://API.zone-b.example/v1/items" },
		"uppercase scheme":       func(r *Request) { r.TargetURI = "HTTPS://api.zone-b.example/v1/items" },
		"default port":           func(r *Request) { r.TargetURI = "https://api.zone-b.example:443/v1/items" },
		"relative":               func(r *Request) { r.TargetURI = "/v1/items" },
		"not canonical":          func(r *Request) { r.TargetURI = "https://api.zone-b.example/v1/a b" },
	} {
		req := ok
		edit(&req)
		if _, err := rs.Authorize(Caller{SPIFFEID: guardID}, req); !errors.Is(err, ErrRouteDenied) {
			t.Errorf("%s: %v; want TOK-ROUTE-DENIED", name, err)
		}
	}
}

func TestNewRoutesRefusesAnIncompleteRoute(t *testing.T) {
	good := Route{Callers: []string{guardID}, PeerZone: "z", Audience: "a", Methods: []string{"GET"}, TargetPrefix: "https://h/p"}
	for name, edit := range map[string]func(*Route){
		"no callers":    func(r *Route) { r.Callers = nil },
		"not spiffe":    func(r *Route) { r.Callers = []string{"guard"} },
		"no methods":    func(r *Route) { r.Methods = nil },
		"bad method":    func(r *Route) { r.Methods = []string{"get"} },
		"no peer":       func(r *Route) { r.PeerZone = "" },
		"no audience":   func(r *Route) { r.Audience = "" },
		"prefix query":  func(r *Route) { r.TargetPrefix = "https://h/p?x" },
		"prefix dots":   func(r *Route) { r.TargetPrefix = "https://h/p/../q" },
		"prefix scheme": func(r *Route) { r.TargetPrefix = "ftp://h/p" },
	} {
		r := good
		edit(&r)
		if _, err := NewRoutes([]Route{r}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewRoutes([]Route{good}); err != nil {
		t.Errorf("good route: %v", err)
	}
}
