package if03

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

const (
	issuer = "https://verifier.zone-b.example"
	kid    = "verifier-1"
)

var now = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func signer(k *ecdsa.PrivateKey) jose.SignFunc {
	return func(_ context.Context, input []byte) ([]byte, error) {
		d := sha256.Sum256(input)
		r, s, err := ecdsa.Sign(rand.Reader, k, d[:])
		if err != nil {
			return nil, err
		}
		return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...), nil
	}
}

func payload() map[string]any {
	return map[string]any{
		"iss": issuer, "outcome_id": "00000000-0000-4000-8000-000000000001", "client_id": "participant",
		"challenge": "challenge-0123456789ab", "audience": "https://zone-b.example/resource",
		"claims":      map[string]any{"role": "participant", "entitlement": "read"},
		"verified_at": now.Add(-10 * time.Second).Format(time.RFC3339), "expires_at": now.Add(100 * time.Second).Format(time.RFC3339),
		"status": "verified",
	}
}

func sign(t *testing.T, k *ecdsa.PrivateKey, h jose.Header, body any) string {
	t.Helper()
	raw, ok := body.([]byte)
	if !ok {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			t.Fatal(err)
		}
	}
	tok, err := jose.Sign(context.Background(), h, raw, signer(k))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

var header = jose.Header{Alg: jose.AlgES256, Typ: Typ, Kid: kid}

func want() Expect {
	return Expect{ClientID: "participant", Challenge: "challenge-0123456789ab", Audience: "https://zone-b.example/resource"}
}

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestVerify_AcceptsAVerifiedOutcome(t *testing.T) {
	k := newKey(t)
	o, err := Verify(sign(t, k, header, payload()), Issuers{issuer: {kid: &k.PublicKey}}, want(), now)
	if err != nil {
		t.Fatal(err)
	}
	if o.OutcomeID != "00000000-0000-4000-8000-000000000001" || o.Claims.Role != "participant" || len(o.Raw) == 0 {
		t.Errorf("got %+v", o)
	}
}

func TestVerify_RefusesWithTheIF03Code(t *testing.T) {
	k, other := newKey(t), newKey(t)
	trusted := Issuers{issuer: {kid: &k.PublicKey}, "https://other.example": {"other-1": &other.PublicKey}}
	with := func(key string, v any) map[string]any { p := payload(); p[key] = v; return p }

	cases := []struct {
		name  string
		token string
		want  Expect
		code  string
	}{
		{"unknown kid", sign(t, k, jose.Header{Alg: jose.AlgES256, Typ: Typ, Kid: "nope"}, payload()), want(), CodeSignature},
		{"wrong key", sign(t, other, header, payload()), want(), CodeSignature},
		{"key of another issuer", sign(t, other, jose.Header{Alg: jose.AlgES256, Typ: Typ, Kid: "other-1"}, payload()), want(), CodeSignature},
		{"wrong typ", sign(t, k, jose.Header{Alg: jose.AlgES256, Typ: "JWT", Kid: kid}, payload()), want(), CodeSignature},
		{"embedded key", sign(t, k, jose.Header{Alg: jose.AlgES256, Typ: Typ, Kid: kid, JWK: ptr(jose.PublicJWK(&k.PublicKey))}, payload()), want(), CodeSignature},
		{"unknown member", sign(t, k, header, with("extra", 1)), want(), CodeSignature},
		{"duplicate member", sign(t, k, header, []byte(`{"iss":"`+issuer+`","iss":"`+issuer+`"}`)), want(), CodeSignature},
		{"reason on verified", sign(t, k, header, with("reason_code", "CRED-X")), want(), CodeSignature},
		{"empty reason on verified", sign(t, k, header, with("reason_code", "")), want(), CodeSignature},
		{"failed without reason", sign(t, k, header, with("status", "failed")), want(), CodeSignature},
		{"revoked with reason", sign(t, k, header, func() map[string]any { p := with("status", "revoked"); p["reason_code"] = "CRED-REVOKED"; return p }()), want(), CodeNotVerified},
		{"other client", sign(t, k, header, payload()), Expect{"someone", want().Challenge, want().Audience}, CodeMismatch},
		{"other challenge", sign(t, k, header, payload()), Expect{want().ClientID, "challenge-other-0000", want().Audience}, CodeMismatch},
		{"other audience", sign(t, k, header, payload()), Expect{want().ClientID, want().Challenge, "https://zone-b.example/other"}, CodeMismatch},
		{"expired", sign(t, k, header, with("expires_at", now.Format(time.RFC3339))), want(), CodeExpired},
		{"valid for too long", sign(t, k, header, with("expires_at", now.Add(111*time.Second).Format(time.RFC3339))), want(), CodeExpired},
		{"verified in the future", sign(t, k, header, func() map[string]any {
			p := with("verified_at", now.Add(31*time.Second).Format(time.RFC3339))
			p["expires_at"] = now.Add(100 * time.Second).Format(time.RFC3339)
			return p
		}()), want(), CodeExpired},
		{"expires before verified", sign(t, k, header, with("expires_at", now.Add(-20*time.Second).Format(time.RFC3339))), want(), CodeExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Verify(tc.token, trusted, tc.want, now)
			if code(err) != tc.code {
				t.Fatalf("code %q (%v), want %q", code(err), err, tc.code)
			}
		})
	}
}

// A kid two issuers both claim is ambiguous and refused, whichever one signed.
func TestVerify_AKidHeldByTwoIssuersIsRefused(t *testing.T) {
	k := newKey(t)
	trusted := Issuers{issuer: {kid: &k.PublicKey}, "https://other.example": {kid: &k.PublicKey}}
	if _, err := Verify(sign(t, k, header, payload()), trusted, want(), now); code(err) != CodeSignature {
		t.Fatalf("code %q", code(err))
	}
}

// The contract's own fixtures: the valid payloads pass the schema check, the invalid ones do not.
func TestParsePayload_FollowsTheContractFixtures(t *testing.T) {
	dir := filepath.Join("..", "..", "docs", "contracts", "fixtures", "if03-verification-outcome.v1")
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures in %s", dir)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(f)
		_, ok := parsePayload(raw)
		if wantOK := strings.HasPrefix(name, "valid-"); ok != wantOK {
			t.Errorf("%s: accepted=%v, want %v", name, ok, wantOK)
		}
	}
}

// Errors say what failed, never what the outcome carried.
func TestVerify_ErrorsCarryNoOutcomeContent(t *testing.T) {
	k := newKey(t)
	canary := "CANARY-client-7f3a91"
	p := payload()
	p["client_id"] = canary
	_, err := Verify(sign(t, k, header, p), Issuers{issuer: {kid: &k.PublicKey}}, want(), now)
	if err == nil || strings.Contains(err.Error(), canary) {
		t.Fatalf("error %v", err)
	}
}

func ptr[T any](v T) *T { return &v }

// Schema conformance beyond the fixtures: exact member names, null, character lengths, formats.
func TestParsePayload_SchemaEdges(t *testing.T) {
	base := func() map[string]any { return payload() }
	raw := func(m map[string]any) []byte { b, _ := json.Marshal(m); return b }
	rename := func(from, to string) []byte { m := base(); m[to] = m[from]; delete(m, from); return raw(m) }
	set := func(k string, v any) []byte { m := base(); m[k] = v; return raw(m) }
	claims := func(c map[string]any) []byte { m := base(); m["claims"] = c; return raw(m) }
	refused := map[string][]byte{
		"ISS instead of iss":          rename("iss", "ISS"),
		"iss and ISS":                 set("ISS", "https://evil.example"),
		"Role instead of role":        claims(map[string]any{"Role": "participant"}),
		"role and Role":               claims(map[string]any{"role": "participant", "Role": "admin"}),
		"null reason on verified":     set("reason_code", nil),
		"null entitlement":            claims(map[string]any{"role": "participant", "entitlement": nil}),
		"null credential_refs":        set("credential_refs", nil),
		"null item in refs":           set("credential_refs", []any{nil}),
		"refs as a string":            set("credential_refs", "urn:x"),
		"null iss":                    set("iss", nil),
		"challenge of 15 characters":  set("challenge", strings.Repeat("é", 15)),
		"client_id of 257 characters": set("client_id", strings.Repeat("é", 257)),
		"comma fraction":              set("verified_at", "2026-10-21T11:59:50,5Z"),
		"one-digit hour":              set("verified_at", "2026-10-21T1:59:50Z"),
		"offset +24:00":               set("verified_at", "2026-10-21T11:59:50+24:00"),
		"day 31 of April":             set("verified_at", "2026-04-31T11:59:50Z"),
		"space in a URN":              set("iss", "urn:bad value"),
		"bad percent escape":          set("audience", "https://zone-b.example/%zz"),
		"relative audience":           set("audience", "/resource"),
	}
	for name, body := range refused {
		t.Run("refused/"+name, func(t *testing.T) {
			if _, ok := parsePayload(body); ok {
				t.Fatalf("accepted %s", body)
			}
		})
	}
	accepted := map[string][]byte{
		"challenge of 16 characters":  set("challenge", strings.Repeat("é", 16)),
		"client_id of 256 characters": set("client_id", strings.Repeat("é", 256)),
		"lowercase t and z":           set("verified_at", "2026-10-21t11:59:50z"),
		"leap second":                 set("verified_at", "2016-12-31T23:59:60Z"),
		"escaped T":                   []byte(strings.Replace(string(raw(base())), `T11:59:50Z`, `T11:59:50Z`, 1)),
		"file URI issuer":             set("iss", "file:///tmp/a"),
		"empty credential_refs":       set("credential_refs", []any{}),
	}
	for name, body := range accepted {
		t.Run("accepted/"+name, func(t *testing.T) {
			if _, ok := parsePayload(body); !ok {
				t.Fatalf("refused %s", body)
			}
		})
	}
}

func TestParseDateTime_LeapSecondAndOffsets(t *testing.T) {
	got, ok := parseDateTime("2016-12-31T23:59:60Z")
	if !ok || !got.Equal(time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("leap second: %v %v", got, ok)
	}
	got, ok = parseDateTime("2026-10-21T13:00:00.25+01:00")
	if !ok || !got.Equal(time.Date(2026, 10, 21, 12, 0, 0, 250_000_000, time.UTC)) {
		t.Errorf("offset: %v %v", got, ok)
	}
}

func TestVerify_KidLongerThan128CharactersIsRefused(t *testing.T) {
	k := newKey(t)
	for n, wantCode := range map[int]string{128: "", 129: CodeSignature} {
		long := strings.Repeat("é", n)
		h := jose.Header{Alg: jose.AlgES256, Typ: Typ, Kid: long}
		_, err := Verify(sign(t, k, h, payload()), Issuers{issuer: {long: &k.PublicKey}}, want(), now)
		if code(err) != wantCode {
			t.Errorf("kid of %d characters: code %q, want %q", n, code(err), wantCode)
		}
	}
}

// The interval's edges are inclusive where IF-03 says "at most", exclusive where it says "before".
func TestVerify_IntervalEdges(t *testing.T) {
	k := newKey(t)
	trusted := Issuers{issuer: {kid: &k.PublicKey}}
	at := func(verified, expires time.Duration) string {
		p := payload()
		p["verified_at"], p["expires_at"] = now.Add(verified).Format(time.RFC3339), now.Add(expires).Format(time.RFC3339)
		return sign(t, k, header, p)
	}
	for name, tc := range map[string]struct {
		token string
		code  string
	}{
		"valid for exactly 120 s":     {at(-10*time.Second, 110*time.Second), ""},
		"verified exactly 30 s ahead": {at(30*time.Second, 60*time.Second), ""},
		"verified_at equals expires":  {at(10*time.Second, 10*time.Second), CodeExpired},
		"expires exactly now":         {at(-10*time.Second, 0), CodeExpired},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(tc.token, trusted, want(), now); code(err) != tc.code {
				t.Fatalf("code %q, want %q", code(err), tc.code)
			}
		})
	}
}

// When several rules fail, the first in IF-03's order names the refusal.
func TestVerify_RulePrecedence(t *testing.T) {
	k := newKey(t)
	trusted := Issuers{issuer: {kid: &k.PublicKey}}
	revokedExpired := payload()
	revokedExpired["status"], revokedExpired["reason_code"] = "revoked", "CRED-REVOKED"
	revokedExpired["expires_at"] = now.Add(-time.Second).Format(time.RFC3339)
	if _, err := Verify(sign(t, k, header, revokedExpired), trusted, Expect{ClientID: "other"}, now); code(err) != CodeNotVerified {
		t.Errorf("not verified, mismatched and expired: %q", code(err))
	}
	mismatchedExpired := payload()
	mismatchedExpired["expires_at"] = now.Add(-time.Second).Format(time.RFC3339)
	if _, err := Verify(sign(t, k, header, mismatchedExpired), trusted, Expect{ClientID: "other"}, now); code(err) != CodeMismatch {
		t.Errorf("mismatched and expired: %q", code(err))
	}
}

func TestIsURI_ComponentGrammar(t *testing.T) {
	for _, s := range []string{
		"https://example.org/[x]", "https://example.org/?q=[x]", "https://[garbage]/", "https://example.org:abc/",
		"https://[fe80::1%25eth0]/", "https://exa mple.org/", "https://example.org/#a#b", "https://[v1.]/",
	} {
		if isURI(s) {
			t.Errorf("accepted %q", s)
		}
	}
	for _, s := range []string{
		"https://example.org/%5Bx%5D", "https://[2001:db8::1]:8443/resource", "https://[v1.fe:x]/", "file:///tmp/a",
		"urn:uuid:00000000-0000-4000-8000-000000000001", "https://user:pw@example.org/a?b=c#d", "https://example.org:/a",
	} {
		if !isURI(s) {
			t.Errorf("refused %q", s)
		}
	}
}

func TestParseDateTime_LeapSecondOnlyWhereOneCanBe(t *testing.T) {
	for _, s := range []string{"2026-10-21T11:59:60Z", "2016-12-31T12:34:60Z", "2016-11-30T23:59:60Z", "2017-01-01T00:59:60Z",
		"1990-06-30T23:59:60Z", "1990-07-01T00:59:60+01:00"} {
		if _, ok := parseDateTime(s); ok {
			t.Errorf("accepted %q", s)
		}
	}
	for s, want := range map[string]time.Time{
		"2016-12-31T23:59:60Z":      time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
		"2017-01-01T00:59:60+01:00": time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
		"2015-06-30T23:59:60Z":      time.Date(2015, 7, 1, 0, 0, 0, 0, time.UTC),
	} {
		if got, ok := parseDateTime(s); !ok || !got.Equal(want) {
			t.Errorf("%q: %v %v", s, got, ok)
		}
	}
}
