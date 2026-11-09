package if03

import (
	"fmt"
	"strings"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

func jwkWith(t *testing.T, kid string) string {
	t.Helper()
	j := jose.PublicJWK(&newKey(t).PublicKey)
	return fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q,"kid":%q}`, j.X, j.Y, kid)
}

func TestParseIssuers(t *testing.T) {
	good := `{"https://a.example":{"keys":[` + jwkWith(t, "a-1") + `,` + jwkWith(t, "a-2") + `]},"https://b.example":{"keys":[` + jwkWith(t, "b-1") + `]}}`
	issuers, err := ParseIssuers([]byte(good))
	if err != nil {
		t.Fatalf("good document: %v", err)
	}
	if len(issuers) != 2 || len(issuers["https://a.example"]) != 2 || issuers["https://b.example"]["b-1"] == nil {
		t.Fatalf("parsed %v", issuers)
	}
	owner, key, ok := issuers.Key("a-2")
	if !ok || owner != "https://a.example" || key == nil {
		t.Errorf("Key(a-2) = %q, %v, %v", owner, key != nil, ok)
	}
	if _, _, ok := issuers.Key("none"); ok {
		t.Error("unknown kid resolved")
	}
	long := strings.Repeat("k", MaxKid+1)
	issuers["https://b.example"][long] = issuers["https://b.example"]["b-1"]
	if _, _, ok := issuers.Key(long); ok {
		t.Error("overlong kid resolved")
	}
	if _, _, ok := issuers.Key(""); ok {
		t.Error("empty kid resolved")
	}
	// A kid held by two issuers is never resolved, whatever the document said.
	issuers["https://b.example"]["a-1"] = issuers["https://a.example"]["a-1"]
	if _, _, ok := issuers.Key("a-1"); ok {
		t.Error("ambiguous kid resolved")
	}

	for _, tc := range []struct{ name, doc, want string }{
		{"empty object", `{}`, "one or more issuers"},
		{"not an object", `[]`, "one or more issuers"},
		{"duplicate issuer", `{"https://a.example":{"keys":[` + jwkWith(t, "k") + `]},"https://a.example":{"keys":[` + jwkWith(t, "j") + `]}}`, "one or more issuers"},
		{"relative issuer", `{"a.example":{"keys":[` + jwkWith(t, "k") + `]}}`, "absolute URI"},
		{"extra member", `{"https://a.example":{"keys":[` + jwkWith(t, "k") + `],"x":1}}`, `exactly the member "keys"`},
		{"empty keys", `{"https://a.example":{"keys":[]}}`, "non-empty array"},
		{"private member", `{"https://a.example":{"keys":[` + strings.Replace(jwkWith(t, "k"), `"kid"`, `"d":"AA","kid"`, 1) + `]}}`, "public EC P-256 JWK"},
		{"no kid", `{"https://a.example":{"keys":[` + strings.Replace(jwkWith(t, "k"), `,"kid":"k"`, "", 1) + `]}}`, "no kid"},
		{"kid too long", `{"https://a.example":{"keys":[` + jwkWith(t, strings.Repeat("k", MaxKid+1)) + `]}}`, "longer than 128"},
		{"kid twice", `{"https://a.example":{"keys":[` + jwkWith(t, "k") + `]},"https://b.example":{"keys":[` + jwkWith(t, "k") + `]}}`, "more than once"},
		{"too large", `{"https://a.example":{"keys":[` + jwkWith(t, "k") + `]}}` + strings.Repeat(" ", MaxIssuersFile), "larger than 1 MiB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseIssuers([]byte(tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want %q", err, tc.want)
			}
		})
	}
}
