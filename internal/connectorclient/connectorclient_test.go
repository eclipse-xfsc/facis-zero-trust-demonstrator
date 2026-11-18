package connectorclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
)

type key struct{ k *ecdsa.PrivateKey }

func newKey(t *testing.T) key {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key{k}
}

func (k key) JWK() jose.JWK { return jose.PublicJWK(&k.k.PublicKey) }
func (k key) Sign(_ context.Context, in []byte) ([]byte, error) {
	digest := sha256.Sum256(in)
	r, s, err := ecdsa.Sign(rand.Reader, k.k, digest[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, nil
}

type anyReplay struct{}

func (anyReplay) TryUse(context.Context, replay.Use) (bool, error) { return true, nil }

// fake is a Connector whose token endpoint answers from a script, one entry per request.
type fake struct {
	t       *testing.T
	mu      sync.Mutex
	srv     *httptest.Server
	answers []func(w http.ResponseWriter, r *http.Request)
	proofs  []dpopproof.Verified
}

func newFake(t *testing.T, answers ...func(w http.ResponseWriter, r *http.Request)) *fake {
	f := &fake{t: t, answers: answers}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, secret, ok := r.BasicAuth(); !ok || id != "client%3A1" || secret != "s%26cret" {
			t.Errorf("basic auth %q %q", id, secret)
		}
		if p := r.Header.Get("DPoP"); p != "" {
			v, err := dpopproof.Verify(r.Context(), p, dpopproof.Expect{Method: http.MethodPost, URI: f.srv.URL + r.URL.Path},
				dpopproof.Policy{Lifespan: time.Minute, Skew: 30 * time.Second}, time.Now(), anyReplay{})
			if err != nil {
				t.Errorf("proof: %v", err)
			}
			f.mu.Lock()
			f.proofs = append(f.proofs, v)
			f.mu.Unlock()
		}
		f.mu.Lock()
		if len(f.answers) == 0 {
			f.mu.Unlock()
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(http.StatusTeapot)
			return
		}
		next := f.answers[0]
		f.answers = f.answers[1:]
		f.mu.Unlock()
		next(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) client() *Client {
	return &Client{BaseURL: f.srv.URL + "/", ClientID: "client:1", ClientSecret: "s&cret"}
}

func reply(status int, header map[string]string, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		for k, v := range header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

func wantErr(t *testing.T, err error, kind Kind) *Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Kind != kind {
		t.Fatalf("error %v; want kind %d", err, kind)
	}
	return e
}

func TestChallenge(t *testing.T) {
	good := strings.Repeat("c", 43)
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/challenge" || r.FormValue("audience") != "https://api.test" {
			t.Errorf("challenge request %s %v", r.URL.Path, r.Form)
		}
		reply(200, nil, `{"challenge":"`+good+`","expires_in":120}`)(w, r)
	})
	ch, err := f.client().Challenge(t.Context(), "https://api.test")
	if err != nil || ch.Value != good || ch.ClientID != "client:1" || ch.Audience != "https://api.test" || time.Until(ch.ExpiresAt) < 110*time.Second {
		t.Fatalf("challenge %+v %v", ch, err)
	}

	for name, c := range map[string]struct {
		answer      func(http.ResponseWriter, *http.Request)
		unreachable bool
		status      int
	}{
		"5xx":       {reply(503, nil, ""), true, 503},
		"refused":   {reply(401, nil, `{"error":"invalid_client"}`), false, 401},
		"malformed": {reply(200, nil, `{"challenge":"short","expires_in":120}`), false, 0},
		"redirect":  {reply(302, map[string]string{"Location": "http://example.invalid/"}, ""), false, 302},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, c.answer)
			_, err := f.client().Challenge(t.Context(), "https://api.test")
			e := wantErr(t, err, KindChallenge)
			if e.Unreachable != c.unreachable || e.Status != c.status {
				t.Fatalf("error %+v", e)
			}
		})
	}
	t.Run("unreachable", func(t *testing.T) {
		f := newFake(t)
		c := f.client()
		f.srv.Close()
		_, err := c.Challenge(t.Context(), "https://api.test")
		if e := wantErr(t, err, KindChallenge); !e.Unreachable {
			t.Fatalf("error %+v", e)
		}
	})
}

func TestGrantRetriesOneNonce(t *testing.T) {
	k := newKey(t)
	f := newFake(t,
		reply(400, map[string]string{"DPoP-Nonce": "n-1"}, `{"error":"use_dpop_nonce","reason":"dpop_use_nonce"}`),
		func(w http.ResponseWriter, r *http.Request) {
			if r.FormValue("grant_type") != VPGrantType || r.FormValue("outcome") != "o" || r.FormValue("challenge") != "c" || r.FormValue("audience") != "a" {
				t.Errorf("grant form %v", r.Form)
			}
			reply(200, nil, `{"access_token":"tok","token_type":"DPoP"}`)(w, r)
		})
	got, err := f.client().Grant(t.Context(), k, "o", "c", "a")
	if err != nil || got.AccessToken != "tok" {
		t.Fatalf("grant %+v %v", got, err)
	}
	if len(f.proofs) != 2 || f.proofs[0].Claims.Nonce != "" || f.proofs[1].Claims.Nonce != "n-1" ||
		f.proofs[0].Claims.JTI == f.proofs[1].Claims.JTI || f.proofs[1].Claims.HTU != f.srv.URL+"/oauth2/token" {
		t.Fatalf("proofs %+v", f.proofs)
	}
	thumb, _ := k.JWK().Thumbprint()
	if f.proofs[1].JKT != thumb {
		t.Fatal("proof not signed with the caller's key")
	}
}

func TestGrantRefusals(t *testing.T) {
	nonce := reply(400, map[string]string{"DPoP-Nonce": "n"}, `{"reason":"dpop_use_nonce"}`)
	for name, c := range map[string]struct {
		answers []func(http.ResponseWriter, *http.Request)
		kind    Kind
		reason  string
	}{
		"nonce twice":   {[]func(http.ResponseWriter, *http.Request){nonce, nonce}, KindRefused, ReasonUseNonce},
		"cred code":     {[]func(http.ResponseWriter, *http.Request){reply(400, nil, `{"reason":"CRED-OUTCOME-CONSUMED"}`)}, KindRefused, "CRED-OUTCOME-CONSUMED"},
		"other reason":  {[]func(http.ResponseWriter, *http.Request){reply(400, nil, `{"reason":"attacker text"}`)}, KindRefused, ""},
		"5xx":           {[]func(http.ResponseWriter, *http.Request){reply(500, nil, "")}, KindLost, ""},
		"unreadable ok": {[]func(http.ResponseWriter, *http.Request){reply(200, nil, "{")}, KindLost, ""},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, c.answers...)
			_, err := f.client().Grant(t.Context(), newKey(t), "o", "c", "a")
			if e := wantErr(t, err, c.kind); e.Reason != c.reason || strings.Contains(e.Error(), "attacker") {
				t.Fatalf("error %+v", e)
			}
		})
	}
}

func token(t *testing.T, claims map[string]any) string {
	raw, _ := json.Marshal(claims)
	return "e30." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
}

func TestCheck(t *testing.T) {
	now := time.Now()
	c := &Client{Now: func() time.Time { return now }}
	good := func() map[string]any {
		return map[string]any{"aud": "a", "exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "cnf": map[string]any{"jkt": "J"}}
	}
	got, err := c.Check(TokenResponse{AccessToken: token(t, good()), TokenType: "dpop"}, "J", "a")
	if err != nil || got.ExpiresAt.Unix() != now.Add(5*time.Minute).Unix() || got.IssuedAt.Unix() != now.Unix() {
		t.Fatalf("check %+v %v", got, err)
	}
	listAud := good()
	listAud["aud"] = []string{"x", "a"}
	if _, err := c.Check(TokenResponse{AccessToken: token(t, listAud), TokenType: "DPoP"}, "J", "a"); err != nil {
		t.Fatalf("aud list: %v", err)
	}
	for check, edit := range map[string]func(m map[string]any) string{
		"token_type": func(map[string]any) string { return "Bearer" },
		"cnf.jkt":    func(m map[string]any) string { m["cnf"] = map[string]any{"jkt": "other"}; return "DPoP" },
		"aud":        func(m map[string]any) string { m["aud"] = "other"; return "DPoP" },
		"exp":        func(m map[string]any) string { m["exp"] = now.Unix(); return "DPoP" },
	} {
		m := good()
		typ := edit(m)
		_, err := c.Check(TokenResponse{AccessToken: token(t, m), TokenType: typ}, "J", "a")
		if e := wantErr(t, err, KindTokenInvalid); e.Check != check {
			t.Errorf("%s: check %q", check, e.Check)
		}
	}
	if e := wantErr(t, func() error {
		_, err := c.Check(TokenResponse{AccessToken: "x.y", TokenType: "DPoP"}, "J", "a")
		return err
	}(), KindTokenInvalid); e.Check != "format" {
		t.Errorf("format: %q", e.Check)
	}
}

func TestBaseURL(t *testing.T) {
	if got, err := BaseURL("https://c.test/base/"); err != nil || got != "https://c.test/base" {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range []string{"", "c.test", "ftp://c.test", "https://u:p@c.test", "https://c.test?q", "https://c.test#f"} {
		if _, err := BaseURL(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestATH(t *testing.T) {
	// RFC 9449 section 7.1 example.
	if got := ATH("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"); got != "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo" {
		t.Fatal(got)
	}
}
