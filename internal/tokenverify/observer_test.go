package tokenverify

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRefusalObserverDistinguishesFiveNegativesWithoutChangingResponse(t *testing.T) {
	for _, code := range []string{"token_expired", "audience_mismatch", "key_binding_mismatch", "proof_absent", "proof_replayed"} {
		t.Run(code, func(t *testing.T) {
			f := newFixture(t)
			token := f.token(func(c map[string]any) {
				switch code {
				case "token_expired":
					c["exp"] = f.clock.Now().Add(-time.Minute).Unix()
				case "audience_mismatch":
					c["aud"] = "https://other.invalid"
				}
			})
			key := f.client
			if code == "key_binding_mismatch" {
				key = newECKey(t)
			}
			proof := f.proof(key, http.MethodGet, baseURL+path, token)
			if code == "proof_absent" {
				proof = ""
			}
			r := request(http.MethodGet, token, proof)
			if code == "proof_replayed" {
				if _, err := f.v.Verify(r); err != nil {
					t.Fatal(err)
				}
			}
			var observed []string
			r = r.WithContext(WithRefusalObserver(r.Context(), func(reason string) { observed = append(observed, reason) }))
			response := httptest.NewRecorder()
			f.v.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("refused request reached application")
			})).ServeHTTP(response, r)
			if len(observed) != 1 || observed[0] != code {
				t.Fatalf("observed %v, expected %s", observed, code)
			}
			if response.Code != http.StatusUnauthorized || strings.TrimSpace(response.Body.String()) != "Unauthorized" {
				t.Fatalf("public response changed: %d", response.Code)
			}
		})
	}
	if got := ReasonCode(errors.New("private-canary")); got != "unclassified" {
		t.Fatal("unknown error text escaped into reason code")
	}
}
