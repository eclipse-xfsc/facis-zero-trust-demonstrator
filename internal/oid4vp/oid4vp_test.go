package oid4vp

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestParseDirectPost(t *testing.T) {
	for _, tc := range []struct {
		name string
		form url.Values
		want string
		err  bool
	}{
		{"bare string", url.Values{"vp_token": {"a.b.c~d~e.f.g"}}, "a.b.c~d~e.f.g", false},
		{"json string", url.Values{"vp_token": {`"a.b.c~d~e.f.g"`}}, "a.b.c~d~e.f.g", false},
		{"one-element array", url.Values{"vp_token": {`["a.b.c~d~e.f.g"]`}}, "a.b.c~d~e.f.g", false},
		{"dcql object with string", url.Values{"vp_token": {`{"participant":"a.b.c~d~e.f.g"}`}}, "a.b.c~d~e.f.g", false},
		{"dcql object with array", url.Values{"vp_token": {`{"participant":["a.b.c~d~e.f.g"]}`}}, "a.b.c~d~e.f.g", false},
		{"with other members", url.Values{"vp_token": {"a.b.c~d~e.f.g"}, "presentation_submission": {"{}"}, "state": {"s"}}, "a.b.c~d~e.f.g", false},
		{"missing", url.Values{}, "", true},
		{"twice", url.Values{"vp_token": {"a", "b"}}, "", true},
		{"empty", url.Values{"vp_token": {"  "}}, "", true},
		{"two in array", url.Values{"vp_token": {`["a","b"]`}}, "", true},
		{"empty array", url.Values{"vp_token": {`[]`}}, "", true},
		{"two queries", url.Values{"vp_token": {`{"a":"x","b":"y"}`}}, "", true},
		{"duplicate query member", url.Values{"vp_token": {`{"a":"x","a":"y"}`}}, "", true},
		{"nested object", url.Values{"vp_token": {`{"a":{"b":"c"}}`}}, "", true},
		{"too large", url.Values{"vp_token": {strings.Repeat("a", MaxVPToken+1)}}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseDirectPost(tc.form)
			if tc.err {
				if !errors.Is(err, ErrResponse) {
					t.Errorf("got %q, %v; want ErrResponse", got, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Errorf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestRequestForm(t *testing.T) {
	r := Request{ClientID: "https://zone-b.example/resource", Nonce: "n-0123456789abcdef", ResponseURI: "https://verification.zone-b.example/v1/responses/1",
		DCQL: DCQLQuery("participant", "https://facis.example/credentials/participant")}
	f := r.Form()
	if f.Get("response_mode") != ResponseModeDirectPost || f.Get("response_type") != "vp_token" || f.Get("client_id") != r.ClientID || f.Get("nonce") != r.Nonce {
		t.Errorf("form: %v", f)
	}
	if _, present := f["state"]; present {
		t.Error("state rendered although empty")
	}
	if !strings.Contains(f.Get("dcql_query"), `"format":"dc+sd-jwt"`) || !strings.Contains(f.Get("dcql_query"), `"vct_values":["https://facis.example/credentials/participant"]`) {
		t.Errorf("dcql: %s", f.Get("dcql_query"))
	}
}
