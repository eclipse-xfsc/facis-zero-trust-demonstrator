package accessrunner

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

func TestCallersAcceptOnlyTheRunnersAccessTokens(t *testing.T) {
	key, other := newTestKey(t), newTestKey(t)
	jwk := jose.PublicJWK(&key.k.PublicKey)
	jwk.Kid = "realm-ec"
	keys, _ := json.Marshal(map[string]any{"keys": []any{jwk, map[string]string{"kty": "RSA", "kid": "realm-rsa", "n": "AQAB", "e": "AQAB"}}})
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(keys) }))
	defer jwks.Close()
	now := time.Unix(1_800_000_000, 0)
	c := &Callers{Issuer: "https://kc.example/realms/facis-ztd", JWKSURL: jwks.URL, Audience: "ztd-access-runner", Client: "ztd-access",
		HTTP: jwks.Client(), Now: func() time.Time { return now }}
	claims := map[string]any{"iss": c.Issuer, "sub": "caller-sub", "azp": "ztd-access", "typ": "Bearer", "exp": now.Unix() + 60,
		"aud": []string{"ztd-access-runner", "account"}}
	token := func(change func(map[string]any), kid string, k testKey) string {
		m := map[string]any{}
		for name, v := range claims {
			m[name] = v
		}
		if change != nil {
			change(m)
		}
		payload, _ := json.Marshal(m)
		compact, err := jose.Sign(t.Context(), jose.Header{Typ: "JWT", Kid: kid}, payload, k.sign)
		if err != nil {
			t.Fatal(err)
		}
		return "Bearer " + compact
	}
	if sub, err := c.Authenticate(t.Context(), token(nil, "realm-ec", key)); err != nil || sub != "caller-sub" {
		t.Fatalf("a valid token: %q %v", sub, err)
	}
	for name, auth := range map[string]string{
		"no token":                 "",
		"not a bearer":             "Basic " + token(nil, "realm-ec", key)[7:],
		"expired":                  token(func(m map[string]any) { m["exp"] = now.Unix() }, "realm-ec", key),
		"for another audience":     token(func(m map[string]any) { m["aud"] = "ztd-ui" }, "realm-ec", key),
		"issued to another client": token(func(m map[string]any) { m["azp"] = "ztd-ui" }, "realm-ec", key),
		"an ID token":              token(func(m map[string]any) { m["typ"] = "ID" }, "realm-ec", key),
		"of another issuer":        token(func(m map[string]any) { m["iss"] = "https://kc.example/realms/master" }, "realm-ec", key),
		"without a subject":        token(func(m map[string]any) { delete(m, "sub") }, "realm-ec", key),
		"signed by another key":    token(nil, "realm-ec", other),
		"naming the realm RSA key": token(nil, "realm-rsa", key),
		"naming no key of the set": token(nil, "unknown", key),
	} {
		if _, err := c.Authenticate(t.Context(), auth); !errors.Is(err, ErrCaller) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
