package caller

import (
	"errors"
	"net/http"
	"testing"
)

const (
	guard   = "spiffe://zone-a.example/ns/ztd-data/sa/guard"
	store   = "spiffe://zone-a.example/ns/ztd-mgmt/sa/ztd-token-store"
	mallory = "spiffe://zone-a.example/ns/ztd-data/sa/participant"
)

// What Envoy writes under SANITIZE_SET for a verified client certificate.
func envoyXFCC(uri string) string {
	return `By=` + store + `;Hash=468ed33be74eee6556d90c0149c1309e9ba61d6425303443c0748a02dd8de688;Subject="";URI=` + uri
}

func request(fields ...string) *http.Request {
	r, _ := http.NewRequest(http.MethodPost, "http://store/internal/replay-check", nil)
	for _, f := range fields {
		r.Header.Add("X-Forwarded-Client-Cert", f)
	}
	return r
}

func TestXFCC_AllowedCallerIsAuthenticated(t *testing.T) {
	a, err := NewXFCC([]string{guard})
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.Authenticate(request(envoyXFCC(guard)))
	if err != nil || got.SPIFFEID != guard {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestXFCC_RefusesWhatItCannotTrust(t *testing.T) {
	a, _ := NewXFCC([]string{guard})
	cases := map[string]*http.Request{
		"no header":         request(),
		"caller not listed": request(envoyXFCC(mallory)),
		// APPEND_FORWARD: the client's own claim of the guard's identity, then the sidecar's element.
		"forged element before the real one, one field":  request(envoyXFCC(guard) + "," + envoyXFCC(mallory)),
		"forged element before the real one, two fields": request(envoyXFCC(guard), envoyXFCC(mallory)),
		"allowed caller twice":                           request(envoyXFCC(guard) + "," + envoyXFCC(guard)),
		"two URI SANs":                                   request(envoyXFCC(guard) + ";URI=" + mallory),
		"no URI":                                         request(`By=` + store + `;Hash=abc`),
		"not a SPIFFE ID":                                request(`URI=https://guard.example/`),
		"unterminated quote":                             request(`Subject="CN=x;URI=` + guard),
		"bare equals in a value":                         request(`URI=spiffe://zone-a.example/ns/a=b`),
		"control character":                              request("URI=" + guard + "\x01"),
		"text after quoted value":                        request(`Subject="x"y;URI=` + guard),
		"empty key":                                      request(`=x;URI=` + guard),
		"empty element":                                  request(envoyXFCC(guard) + ","),
		"quoted key":                                     request(`"URI"=` + guard),
		"control inside a quoted value":                  request("Subject=\"a\x01b\";URI=" + guard),
		"escaped control inside a quoted value":          request("Subject=\"a\\\x01b\";URI=" + guard),
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := a.Authenticate(r); !errors.Is(err, ErrCallerDenied) {
				t.Fatalf("authenticated %+v", got)
			}
		})
	}
}

// Quoted values carry the separators without splitting the element.
func TestParseXFCC_QuotedValues(t *testing.T) {
	elements, err := ParseXFCC(`Hash=ab;Subject="CN=guard,O=zone\"a\";x";URI=` + guard)
	if err != nil {
		t.Fatal(err)
	}
	if len(elements) != 1 {
		t.Fatalf("%d elements", len(elements))
	}
	if got := elements[0]["subject"]; len(got) != 1 || got[0] != `CN=guard,O=zone"a";x` {
		t.Errorf("subject = %q", got)
	}
	if got := elements[0]["uri"]; len(got) != 1 || got[0] != guard {
		t.Errorf("uri = %q", got)
	}
}

func TestNewXFCC_AllowListHoldsSPIFFEIDsOnly(t *testing.T) {
	for _, bad := range []string{"", "guard", "https://guard", "spiffe://", "spiffe://domain-only", "spiffe://d/p;q"} {
		if _, err := NewXFCC([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	empty, err := NewXFCC(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := empty.Authenticate(request(envoyXFCC(guard))); !errors.Is(err, ErrCallerDenied) {
		t.Error("an empty allow-list admitted a caller")
	}
}
