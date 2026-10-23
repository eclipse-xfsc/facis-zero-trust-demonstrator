package transit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	canaryToken  = "canary-token-7f3a91"
	canarySecret = "canary-secret-c0ffee"
)

func staticToken(tok string) TokenSource {
	return func(context.Context) (string, error) { return tok, nil }
}

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(Config{Addr: srv.URL, Token: staticToken(canaryToken)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestParseRef(t *testing.T) {
	k, err := ParseRef("transit:zone-a.sign_1:v12")
	if err != nil || k != (KeyVersion{Name: "zone-a.sign_1", Version: 12}) {
		t.Fatalf("got %+v, %v", k, err)
	}
	if k.Ref() != "transit:zone-a.sign_1:v12" {
		t.Fatalf("round trip %q", k.Ref())
	}
	for _, bad := range []string{
		"", "transit:", "transit:k", "transit:k:v", "transit:k:v0", "transit:k:v-1", "transit:k:v+1",
		"transit:k:v01", "transit:k:1", "transit::v1", "Transit:k:v1", "kv:k:v1", "transit:a:b:v1",
		"transit:k:v1 ", " transit:k:v1", "transit:k/x:v1", "transit:..:v1", "transit:k:v1x",
		"transit:k:v99999999999999999999",
	} {
		if _, err := ParseRef(bad); err == nil {
			t.Errorf("ParseRef(%q) accepted", bad)
		}
	}
}

func TestNewValidates(t *testing.T) {
	tok := staticToken("x")
	for _, cfg := range []Config{
		{Addr: "", Token: tok},
		{Addr: "ftp://h", Token: tok},
		{Addr: "http://h/v1", Token: tok},
		{Addr: "http://u:p@h", Token: tok},
		{Addr: "http://h?x=1", Token: tok},
		{Addr: "http://h"},
		{Addr: "http://h", Token: tok, KVMount: "../sys"},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) accepted", cfg.Addr)
		}
	}
	c, err := New(Config{Addr: "http://h:8200/", Token: tok})
	if err != nil || c.cfg.TransitMount != "transit" || c.cfg.KVMount != "secret" || c.cfg.Addr != "http://h:8200" {
		t.Fatalf("defaults: %+v %v", c, err)
	}
}

func TestSignRequestAndVersionCheck(t *testing.T) {
	sig64 := strings.Repeat("A", 86) // 64 zero bytes, base64url without padding
	answer := "vault:v3:" + sig64
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/transit/sign/k" || r.Header.Get("X-Vault-Token") != canaryToken {
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		want := map[string]any{"input": "aGVsbG8=", "hash_algorithm": "sha2-256", "prehashed": false,
			"key_version": float64(3), "marshaling_algorithm": "jws"}
		if fmt.Sprint(body) != fmt.Sprint(want) {
			t.Errorf("body %v", body)
		}
		_, _ = fmt.Fprintf(w, `{"data":{"signature":%q,"key_version":3}}`, answer)
	})
	ctx := context.Background()
	got, err := c.Sign(ctx, KeyVersion{Name: "k", Version: 3}, []byte("hello"))
	if err != nil || len(got) != 64 {
		t.Fatalf("sign: %d bytes, %v", len(got), err)
	}

	answer = "vault:v4:" + sig64 // OpenBao signing with another version than the pinned one
	if _, err := c.Sign(ctx, KeyVersion{Name: "k", Version: 3}, []byte("hello")); !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("forged version: %v", err)
	}
	for _, bad := range []string{
		"vault:v3:" + sig64[:85],      // 63 bytes
		"vault:v3:" + sig64 + "AAA",   // 66 bytes
		"vault:v3:MEUCIQ==",           // DER-ish, short
		"vault:v3:" + sig64 + "=",     // padded
		"v3:" + sig64, "vault:v3", "", // malformed
	} {
		answer = bad
		if _, err := c.Sign(ctx, KeyVersion{Name: "k", Version: 3}, []byte("hello")); err == nil || errors.Is(err, ErrVersionMismatch) {
			t.Errorf("signature %q: %v", bad, err)
		}
	}
	if _, err := c.Sign(ctx, KeyVersion{Name: "k"}, nil); err == nil {
		t.Error("unpinned version accepted")
	}
}

func pemOf(t *testing.T, curve elliptic.Curve) string {
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func keyAnswer(typ string, exportable bool, pubs map[string]string) string {
	keys := map[string]any{}
	for v, p := range pubs {
		keys[v] = map[string]string{"public_key": p, "name": "P-256"}
	}
	b, _ := json.Marshal(map[string]any{"data": map[string]any{"type": typ, "exportable": exportable,
		"allow_plaintext_backup": false, "latest_version": len(pubs), "keys": keys}})
	return string(b)
}

func TestPublicKey(t *testing.T) {
	answer := ""
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, answer) })
	ctx := context.Background()
	answer = keyAnswer("ecdsa-p256", false, map[string]string{"1": pemOf(t, elliptic.P256())})
	if pub, err := c.PublicKey(ctx, KeyVersion{Name: "k", Version: 1}); err != nil || pub.Curve != elliptic.P256() {
		t.Fatalf("p256: %v", err)
	}
	if _, err := c.PublicKey(ctx, KeyVersion{Name: "k", Version: 2}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing version: %v", err)
	}
	answer = keyAnswer("ecdsa-p256", false, map[string]string{"1": pemOf(t, elliptic.P384())})
	if _, err := c.PublicKey(ctx, KeyVersion{Name: "k", Version: 1}); err == nil {
		t.Fatal("P-384 accepted")
	}
	answer = keyAnswer("ecdsa-p256", false, map[string]string{"1": "not pem"})
	if _, err := c.PublicKey(ctx, KeyVersion{Name: "k", Version: 1}); err == nil {
		t.Fatal("garbage accepted")
	}
	answer = `{"data":{"type":"aes256-gcm96","keys":{"1":1700000000}}}`
	if _, err := c.PublicKey(ctx, KeyVersion{Name: "k", Version: 1}); err == nil {
		t.Fatal("symmetric key accepted")
	}
}

func TestEnsureKeyRejectsForeignKey(t *testing.T) {
	for name, answer := range map[string]string{
		"exportable": keyAnswer("ecdsa-p256", true, map[string]string{"1": "x"}),
		"other type": keyAnswer("ecdsa-p384", false, map[string]string{"1": "x"}),
		"backup":     `{"data":{"type":"ecdsa-p256","allow_plaintext_backup":true,"latest_version":1}}`,
	} {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, answer) })
		if _, err := c.EnsureKey(context.Background(), "k"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEnsureKeyCreatesWhenMissing(t *testing.T) {
	created := false
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && !created:
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPost:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["type"] != "ecdsa-p256" || body["exportable"] != false || body["allow_plaintext_backup"] != false {
				t.Errorf("create body %v", body)
			}
			created = true
			w.WriteHeader(http.StatusNoContent)
		default:
			_, _ = io.WriteString(w, keyAnswer("ecdsa-p256", false, map[string]string{"1": "x"}))
		}
	})
	kv, err := c.EnsureKey(context.Background(), "k")
	if err != nil || kv != (KeyVersion{Name: "k", Version: 1}) || !created {
		t.Fatalf("%+v %v", kv, err)
	}
}

func TestKVStatusMapping(t *testing.T) {
	status, body := 0, ""
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
	ctx := context.Background()
	status, body = 400, `{"errors":["check-and-set parameter did not match the current version"]}`
	if err := c.Create(ctx, "a/b", []byte(canarySecret)); !errors.Is(err, ErrExists) {
		t.Fatalf("cas: %v", err)
	}
	status, body = 400, `{"errors":["no data provided"]}`
	if err := c.Create(ctx, "a/b", []byte(canarySecret)); err == nil || errors.Is(err, ErrExists) {
		t.Fatalf("other 400: %v", err)
	}
	status, body = 404, `{"errors":[]}`
	if _, err := c.Read(ctx, "a/b"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read 404: %v", err)
	}
	if keys, err := c.List(ctx, "a/"); err != nil || len(keys) != 0 {
		t.Fatalf("list 404: %v %v", keys, err)
	}
	status, body = 403, `{"errors":["permission denied"]}`
	if _, err := c.Read(ctx, "a/b"); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("read 403: %v", err)
	}
	status, body = 200, strings.Repeat(" ", maxBody+1)
	if _, err := c.Read(ctx, "a/b"); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized: %v", err)
	}
	for _, p := range []string{"", "/a", "a/", "a//b", "a/../b", "."} {
		if err := c.Create(ctx, p, nil); err == nil {
			t.Errorf("path %q accepted", p)
		}
	}
}

func TestKVRequests(t *testing.T) {
	var seen []string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.EscapedPath())
		switch r.Method {
		case http.MethodPost:
			var body struct {
				Data    map[string][]byte `json:"data"`
				Options map[string]int    `json:"options"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if string(body.Data["value"]) != canarySecret || body.Options["cas"] != 0 || len(body.Options) != 1 {
				t.Errorf("create body %+v", body)
			}
		case http.MethodGet:
			_, _ = fmt.Fprintf(w, `{"data":{"data":{"value":"%s"}}}`, "Y2FuYXJ5") // "canary"
		case "LIST":
			_, _ = io.WriteString(w, `{"data":{"keys":["b","c/"]}}`)
		}
	})
	ctx := context.Background()
	if err := c.Create(ctx, "z/a b?", []byte(canarySecret)); err != nil {
		t.Fatal(err)
	}
	if v, err := c.Read(ctx, "z/x"); err != nil || string(v) != "canary" {
		t.Fatalf("read %q %v", v, err)
	}
	if err := c.Delete(ctx, "z/x"); err != nil {
		t.Fatal(err)
	}
	if keys, err := c.List(ctx, "z"); err != nil || fmt.Sprint(keys) != "[b c/]" {
		t.Fatalf("list %v %v", keys, err)
	}
	want := "[POST /v1/secret/data/z/a%20b%3F GET /v1/secret/data/z/x DELETE /v1/secret/metadata/z/x LIST /v1/secret/metadata/z]"
	if fmt.Sprint(seen) != want {
		t.Fatalf("requests\n got %v\nwant %s", seen, want)
	}
}

// TestNoSecretsInErrors drives every operation into every failure an OpenBao (or something in
// between) can answer with, each echoing the token and the secret value back, and asserts that
// neither reaches an error string.
func TestNoSecretsInErrors(t *testing.T) {
	echo := fmt.Sprintf(`{"errors":["token %s value %s"]}`, canaryToken, canarySecret)
	for _, answer := range []struct {
		status int
		body   string
	}{
		{400, echo}, {403, echo}, {404, echo}, {500, echo}, {502, canaryToken + canarySecret},
		{200, `{"data":` + canaryToken}, {200, `{"data":{"signature":"vault:v1:` + canarySecret + `"}}`},
		{200, `{"data":{"data":{"value":"` + canarySecret + `"}}}`},
		{200, `{"data":{"type":"ecdsa-p256","keys":{"1":{"public_key":"` + canarySecret + `"}}}}`},
		{307, echo},
	} {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "http://"+canaryToken+".invalid/"+canarySecret)
			w.WriteHeader(answer.status)
			_, _ = io.WriteString(w, answer.body)
		})
		ctx := context.Background()
		k := KeyVersion{Name: "k", Version: 1}
		var errs []error
		_, err := c.Sign(ctx, k, []byte(canarySecret))
		errs = append(errs, err)
		_, err = c.PublicKey(ctx, k)
		errs = append(errs, err)
		_, err = c.EnsureKey(ctx, "k")
		errs = append(errs, err)
		errs = append(errs, c.Create(ctx, "a", []byte(canarySecret)))
		_, err = c.Read(ctx, "a")
		errs = append(errs, err)
		errs = append(errs, c.Delete(ctx, "a"))
		_, err = c.List(ctx, "a")
		errs = append(errs, err)
		for _, err := range errs {
			if err != nil && (strings.Contains(err.Error(), canaryToken) || strings.Contains(err.Error(), canarySecret)) {
				t.Errorf("status %d: error leaks: %v", answer.status, err)
			}
		}
	}
	// Transport failure: the address is unreachable.
	c, _ := New(Config{Addr: "http://127.0.0.1:1", Token: staticToken(canaryToken)})
	if err := c.Create(context.Background(), canarySecret, []byte(canarySecret)); err == nil || strings.Contains(err.Error(), canarySecret) || strings.Contains(err.Error(), canaryToken) {
		t.Errorf("transport error: %v", err)
	}
}

func TestTokenPerCall(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != fmt.Sprint("t", calls) {
			t.Errorf("token %q at call %d", r.Header.Get("X-Vault-Token"), calls)
		}
		_, _ = io.WriteString(w, `{"data":{"keys":[]}}`)
	}))
	defer srv.Close()
	c, _ := New(Config{Addr: srv.URL, Token: func(context.Context) (string, error) {
		calls++
		return fmt.Sprint("t", calls), nil
	}})
	for range 3 {
		if _, err := c.List(context.Background(), "a"); err != nil {
			t.Fatal(err)
		}
	}
	failing, _ := New(Config{Addr: srv.URL, Token: func(context.Context) (string, error) { return "", errors.New("no auth") }})
	if _, err := failing.List(context.Background(), "a"); err == nil {
		t.Fatal("token failure ignored")
	}
}
