package trainresolve

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const (
	keyB     = "spiffe://zone-b.facis-ztd.local/gateway"
	pointerB = "zone-b.facis-ztd.local"
	tlURI    = "https://tspa.facis-ztd.local/tspa-service/tspa/v1/facis-ztd.local/trust-list"
	vcURI    = "https://tspa.facis-ztd.local/tspa-service/tspa/v1/facis-ztd.local/vc/trust-list"
)

var lookupB = Lookup{Key: keyB, Pointers: []string{pointerB}}

// entry builds a trust-list provider entry as the publisher writes it: the key in the service's
// ServiceTypeIdentifier, the measurement pairs in TSPInformation.
func entry(uuid, key string, pairs ...[2]string) map[string]any {
	certs := []map[string]string{}
	for _, p := range pairs {
		certs = append(certs, map[string]string{"Type": p[0], "Value": p[1]})
	}
	return map[string]any{
		"UUID":         uuid,
		"TSPName":      "gateway (b)",
		"TSPTradeName": "b-gateway",
		"TSPInformation": map[string]any{
			"TSPCertificationList": map[string]any{"TSPCertification": certs},
			"TSPEntityIdentifierList": map[string]any{"TSPEntityIdendifier": []map[string]string{
				{"Type": "zone", "Value": "b"}, {"Type": "component", "Value": "gateway"},
			}},
		},
		"TSPServices": map[string]any{"TSPService": []map[string]any{{
			"ServiceName":            "attested-tls-endpoint",
			"ServiceTypeIdentifier":  key,
			"ServiceDigitalIdentity": map[string]any{"DigitalId": map[string]string{"DID": key}},
		}}},
	}
}

func teem(v string) [2]string { return [2]string{"TEEM-sha256", v} }

type endpointJSON map[string]any

// endpoint builds one resolved trust-list endpoint; entry nil means a verified list without an
// entry for the issuer.
func endpoint(e map[string]any, verified bool) endpointJSON {
	ep := endpointJSON{"vcUri": vcURI, "tlUri": tlURI, "vcVerified": verified}
	if e != nil {
		ep["trustList"] = e
	}
	return ep
}

// answer builds the resolver's document for one pointer resolved to one DID with the given endpoints.
func answer(didVerified bool, endpoints ...endpointJSON) map[string]any {
	return map[string]any{
		"trustSchemePointers": []map[string]any{{"pointer": pointerB, "dids": []string{"did:web:facis-ztd.local"}}},
		"resolvedResults": []map[string]any{{
			"did":         "did:web:facis-ztd.local",
			"resolvedDoc": map[string]any{"document": map[string]any{}, "endpoints": endpoints, "didVerified": didVerified},
		}},
	}
}

// serve runs a resolver stand-in that answers every request with handler and returns the Source.
func serve(t *testing.T, handler http.HandlerFunc, cfg ...func(*TCRConfig)) *TCR {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := TCRConfig{BaseURL: srv.URL, Client: srv.Client()}
	for _, f := range cfg {
		f(&c)
	}
	tcr, err := NewTCR(c)
	if err != nil {
		t.Fatal(err)
	}
	return tcr
}

func serveJSON(t *testing.T, status int, doc any) *TCR {
	return serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(doc)
	})
}

func TestNewTCRValidatesTheOrigin(t *testing.T) {
	for _, bad := range []string{"", "tcr.example", "ftp://tcr.example", "https://", "https://tcr.example/tcr/v1", "https://tcr.example/?x=1", "https://tcr.example/#f", "https://user:pw@tcr.example"} {
		if _, err := NewTCR(TCRConfig{BaseURL: bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, good := range []string{"https://tcr.example", "https://tcr.example/", "http://127.0.0.1:8087"} {
		tcr, err := NewTCR(TCRConfig{BaseURL: good})
		if err != nil {
			t.Fatalf("%q: %v", good, err)
		}
		if !strings.HasSuffix(tcr.endpoint, "/tcr/v1/resolve") || strings.Contains(tcr.endpoint, "//tcr/") {
			t.Fatalf("%q: endpoint %q", good, tcr.endpoint)
		}
		if tcr.maxBody != defaultMaxBody || tcr.client == nil {
			t.Fatalf("defaults not applied: %+v", tcr)
		}
	}
}

func TestNewHTTPClientIsHardened(t *testing.T) {
	c := NewHTTPClient(nil)
	tr := c.Transport.(*http.Transport)
	if tr.Proxy != nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS13 || tr.MaxIdleConnsPerHost != 2 {
		t.Fatalf("transport: proxy %v, min TLS %x, idle %d", tr.Proxy != nil, tr.TLSClientConfig.MinVersion, tr.MaxIdleConnsPerHost)
	}
	if err := c.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatal("redirects must not be followed")
	}
}

func TestResolveSendsTheResolveRequest(t *testing.T) {
	var mu sync.Mutex
	var gotMethod, gotPath, gotType, gotAccept, gotBody string
	tcr := serve(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotMethod, gotPath, gotType, gotAccept, gotBody = r.Method, r.URL.Path, r.Header.Get("Content-Type"), r.Header.Get("Accept"), strings.TrimSpace(string(b))
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(answer(false, endpoint(entry("u1", keyB, teem(teemA)), true)))
	})
	exp, err := tcr.Resolve(ctxBg, Lookup{Key: keyB, Pointers: []string{pointerB, "zone-a.facis-ztd.local"}})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotMethod != http.MethodPost || gotPath != "/tcr/v1/resolve" || gotType != "application/json" || gotAccept != "application/json" {
		t.Fatalf("request: %s %s %s %s", gotMethod, gotPath, gotType, gotAccept)
	}
	if want := `{"issuer":"` + keyB + `","trustSchemePointers":["` + pointerB + `","zone-a.facis-ztd.local"]}`; gotBody != want {
		t.Fatalf("body = %s, want %s", gotBody, want)
	}
	if exp.EntryUUID != "u1" || strings.Join(exp.Values, ",") != teemA || exp.TrustList != tlURI || exp.Key != keyB || exp.ResolvedAt.IsZero() {
		t.Fatalf("expected = %+v", exp)
	}
}

func TestResolveInterpretsTheAnswer(t *testing.T) {
	cases := []struct {
		name       string
		doc        any
		wantKind   error
		wantValues []string
		wantUUID   string
		wantReason string
	}{
		{"one value", answer(false, endpoint(entry("u1", keyB, teem(teemA)), true)), nil, []string{teemA}, "u1", ""},
		{"set semantics: two values, other pairs ignored", answer(false, endpoint(entry("u1", keyB, teem(teemB), [2]string{"image-digest", "sha256:" + teemC}, teem(teemA), [2]string{"TEEM-sha384", "00"}), true)), nil, []string{teemB, teemA}, "u1", ""},
		{"duplicate values collapse", answer(false, endpoint(entry("u1", keyB, teem(teemA), teem(teemA)), true)), nil, []string{teemA}, "u1", ""},
		{"zero TEEM pairs: a resolution without values", answer(false, endpoint(entry("u1", keyB, [2]string{"image-digest", "sha256:ab"}), true)), nil, nil, "u1", ""},
		{"verified list without an entry: absence", answer(false, endpoint(nil, true)), nil, nil, "", ""},
		{"explicit null entry: absence", map[string]any{
			"trustSchemePointers": []map[string]any{{"pointer": pointerB, "dids": []string{"did:web:x"}}},
			"resolvedResults": []map[string]any{{"did": "did:web:x", "resolvedDoc": map[string]any{
				"endpoints": []map[string]any{{"vcUri": vcURI, "tlUri": tlURI, "trustList": nil, "vcVerified": true}}}}},
		}, nil, nil, "", ""},
		{"credential not verified", answer(false, endpoint(entry("u1", keyB, teem(teemA)), false)), ErrUnreachable, nil, "", "did not verify the trust-list credential"},
		{"pointer error, nothing resolved: zone unknown", map[string]any{
			"trustSchemePointers": []map[string]any{{"pointer": pointerB, "error": map[string]string{"code": "dns_error", "message": "no PTR"}}},
			"resolvedResults":     []any{},
		}, ErrZoneUnknown, nil, "", "no trust list is anchored"},
		{"pointer without dids, nothing resolved: zone unknown", map[string]any{
			"trustSchemePointers": []map[string]any{{"pointer": pointerB, "dids": []string{}}},
		}, ErrZoneUnknown, nil, "", ""},
		{"empty document: zone unknown", map[string]any{}, ErrZoneUnknown, nil, "", ""},
		{"dids but no results: unreachable", map[string]any{
			"trustSchemePointers": []map[string]any{{"pointer": pointerB, "dids": []string{"did:web:x"}}},
		}, ErrUnreachable, nil, "", "no result"},
		{"result with an error", map[string]any{
			"trustSchemePointers": []map[string]any{{"pointer": pointerB, "dids": []string{"did:web:x"}}},
			"resolvedResults":     []map[string]any{{"did": "did:web:x", "error": map[string]string{"code": "did_error"}}},
		}, ErrUnreachable, nil, "", "reported an error for DID"},
		{"result without endpoints", map[string]any{
			"trustSchemePointers": []map[string]any{{"pointer": pointerB, "dids": []string{"did:web:x"}}},
			"resolvedResults":     []map[string]any{{"did": "did:web:x", "resolvedDoc": map[string]any{"endpoints": []any{}}}},
		}, ErrUnreachable, nil, "", "no trust-list endpoint"},
		{"result without a document", map[string]any{
			"trustSchemePointers": []map[string]any{{"pointer": pointerB, "dids": []string{"did:web:x"}}},
			"resolvedResults":     []map[string]any{{"did": "did:web:x"}},
		}, ErrUnreachable, nil, "", "no trust-list endpoint"},
		{"entry naming another key", answer(false, endpoint(entry("u1", "did:web:connector-b.facis-ztd.local", teem(teemA)), true)), ErrUnreachable, nil, "", "does not name the key"},
		{"value with a prefix", answer(false, endpoint(entry("u1", keyB, teem("sha256:"+teemA[7:])), true)), ErrUnreachable, nil, "", "grammar"},
		{"value in uppercase", answer(false, endpoint(entry("u1", keyB, teem(strings.ToUpper(teemA))), true)), ErrUnreachable, nil, "", "grammar"},
		{"value of 63 characters", answer(false, endpoint(entry("u1", keyB, teem(teemA[:63])), true)), ErrUnreachable, nil, "", "grammar"},
		{"two endpoints, same entry", answer(false, endpoint(entry("u1", keyB, teem(teemA)), true), endpoint(entry("u1", keyB, teem(teemA)), true)), nil, []string{teemA}, "u1", ""},
		{"two endpoints, one without the entry", answer(false, endpoint(entry("u1", keyB, teem(teemA)), true), endpoint(nil, true)), nil, []string{teemA}, "u1", ""},
		{"two endpoints, different entries", answer(false, endpoint(entry("u1", keyB, teem(teemA)), true), endpoint(entry("u2", keyB, teem(teemA)), true)), ErrUnreachable, nil, "", "two different entries"},
		{"two endpoints, same entry other values", answer(false, endpoint(entry("u1", keyB, teem(teemA)), true), endpoint(entry("u1", keyB, teem(teemB)), true)), ErrUnreachable, nil, "", "two different entries"},
		{"entry that is not a document", map[string]any{
			"trustSchemePointers": []map[string]any{{"pointer": pointerB, "dids": []string{"did:web:x"}}},
			"resolvedResults": []map[string]any{{"did": "did:web:x", "resolvedDoc": map[string]any{
				"endpoints": []map[string]any{{"vcUri": vcURI, "tlUri": tlURI, "trustList": "not an object", "vcVerified": true}}}}},
		}, ErrUnreachable, nil, "", "not the provider document"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exp, err := serveJSON(t, http.StatusOK, tc.doc).Resolve(ctxBg, lookupB)
			if tc.wantKind != nil {
				if !errors.Is(err, tc.wantKind) {
					t.Fatalf("err = %v, want %v", err, tc.wantKind)
				}
				if tc.wantReason != "" && !strings.Contains(err.Error(), tc.wantReason) {
					t.Fatalf("reason %q not in %v", tc.wantReason, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if strings.Join(exp.Values, ",") != strings.Join(tc.wantValues, ",") || exp.EntryUUID != tc.wantUUID {
				t.Fatalf("values %v uuid %q, want %v %q", exp.Values, exp.EntryUUID, tc.wantValues, tc.wantUUID)
			}
		})
	}
}

func TestResolveRequiresTheDIDConfigurationWhenAsked(t *testing.T) {
	doc := answer(false, endpoint(entry("u1", keyB, teem(teemA)), true))
	if _, err := serveJSON(t, http.StatusOK, doc).Resolve(ctxBg, lookupB); err != nil {
		t.Fatalf("off by default: %v", err)
	}
	strict := func(c *TCRConfig) { c.RequireDIDVerified = true }
	tcr := serve(t, func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(doc) }, strict)
	if _, err := tcr.Resolve(ctxBg, lookupB); !errors.Is(err, ErrUnreachable) || !strings.Contains(err.Error(), "DID configuration") {
		t.Fatalf("err = %v", err)
	}
	verified := answer(true, endpoint(entry("u1", keyB, teem(teemA)), true))
	tcr = serve(t, func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(verified) }, strict)
	if _, err := tcr.Resolve(ctxBg, lookupB); err != nil {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveRefusesAnythingButA200Document(t *testing.T) {
	for _, status := range []int{400, 404, 500, 502, 510} {
		_, err := serveJSON(t, status, map[string]any{"message": "nope"}).Resolve(ctxBg, lookupB)
		if !errors.Is(err, ErrUnreachable) || !strings.Contains(err.Error(), "answered "+itoa(status)) {
			t.Errorf("%d: err = %v", status, err)
		}
	}
	t.Run("a redirect is not followed", func(t *testing.T) {
		tcr := serve(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/tcr/v1/resolve" {
				http.Redirect(w, r, "/elsewhere", http.StatusFound)
				return
			}
			_ = json.NewEncoder(w).Encode(answer(false, endpoint(entry("u1", keyB, teem(teemA)), true)))
		}, func(c *TCRConfig) { c.Client = NewHTTPClient(nil) }) // the hardened client, not httptest's
		if _, err := tcr.Resolve(ctxBg, lookupB); !errors.Is(err, ErrUnreachable) || !strings.Contains(err.Error(), "answered 302") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("invalid JSON", func(t *testing.T) {
		tcr := serve(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "{not json") })
		if _, err := tcr.Resolve(ctxBg, lookupB); !errors.Is(err, ErrUnreachable) || !strings.Contains(err.Error(), "not the resolve document") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("body over the bound", func(t *testing.T) {
		tcr := serve(t, func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"padding": strings.Repeat("x", 2048)})
		}, func(c *TCRConfig) { c.MaxBody = 512 })
		if _, err := tcr.Resolve(ctxBg, lookupB); !errors.Is(err, ErrUnreachable) || !strings.Contains(err.Error(), "exceeds 512 bytes") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("resolver unreachable", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		url := srv.URL
		srv.Close()
		tcr, err := NewTCR(TCRConfig{BaseURL: url})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tcr.Resolve(ctxBg, lookupB); !errors.Is(err, ErrUnreachable) || !strings.Contains(err.Error(), "asking the resolver") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("the context bounds the request", func(t *testing.T) {
		release := make(chan struct{})
		defer close(release)
		tcr := serve(t, func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
			}
		})
		ctx, cancel := context.WithCancel(ctxBg)
		cancel()
		if _, err := tcr.Resolve(ctx, lookupB); !errors.Is(err, ErrUnreachable) || !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	})
}

// TestVerifierOverTheTCR is the package end to end against the stand-in: the channel's peer,
// the resolver's answer, the verdict.
func TestVerifierOverTheTCR(t *testing.T) {
	var mu sync.Mutex
	doc := answer(false, endpoint(entry("u1", keyB, teem(teemA)), true))
	calls := 0
	tcr := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		d := doc
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(d)
	})
	v := New(tcr, nil)
	peer := Peer{Identity: keyB, Digests: []Digest{{teemA, "SHA-256"}}}
	if err := v.Verify(ctxBg, peer); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(ctxBg, Peer{Identity: keyB, Digests: []Digest{{teemB, "SHA-256"}}}); !errors.Is(err, ErrMismatch) {
		t.Fatalf("err = %v", err)
	}
	if err := v.Verify(ctxBg, Peer{Identity: "spiffe://zone-b.facis-ztd.local/other", Digests: peer.Digests}); !errors.Is(err, ErrUnreachable) {
		// The stand-in answers the same entry for any issuer; the package notices the entry does not name the key.
		t.Fatalf("err = %v", err)
	}
	mu.Lock()
	n := calls
	mu.Unlock()
	if n != 2 {
		t.Fatalf("resolver asked %d times, want 2 (one per distinct key)", n)
	}
}
