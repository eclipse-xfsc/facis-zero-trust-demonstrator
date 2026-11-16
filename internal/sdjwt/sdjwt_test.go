package sdjwt_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt/sdjwtfixture"
)

const (
	issuer   = "https://issuer.zone-a.example"
	kid      = "issuer-1"
	vct      = "https://facis.example/credentials/participant"
	nonce    = "challenge-0123456789abcdef"
	audience = "https://zone-b.example/resource"
	listURI  = "https://status.zone-a.example/lists/1.jwt"
)

var now = time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)

var (
	issuerKey = sdjwtfixture.TestIssuerKey()
	holderKey = sdjwtfixture.TestHolderKey()
	otherKey  = sdjwtfixture.TestOtherIssuerKey()
)

func trust() if03.Issuers {
	return if03.Issuers{issuer: {kid: &issuerKey.PublicKey}}
}

func accepted() map[string]bool { return map[string]bool{vct: true} }

func expect() sdjwt.Expect { return sdjwt.Expect{Nonce: nonce, Audience: audience, Now: now} }

func options() sdjwtfixture.IssueOptions {
	return sdjwtfixture.IssueOptions{
		IssuerKey: issuerKey, Kid: kid, Issuer: issuer, VCT: vct, JTI: "urn:uuid:00000000-0000-4000-8000-0000000000aa",
		Claims:      []sdjwtfixture.Claim{{Name: "role", Value: "participant"}, {Name: "entitlement", Value: "read"}, {Name: "organisation", Value: "Zone A GmbH"}, {Name: "address", Value: map[string]any{"country": "DE"}}},
		Disclosable: []string{"role", "entitlement", "organisation"},
		Holder:      &holderKey.PublicKey, Status: &sdjwt.StatusRef{URI: listURI, Index: 42},
		IssuedAt: now.Add(-time.Hour), NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour),
	}
}

func issue(t *testing.T, o sdjwtfixture.IssueOptions) sdjwtfixture.Issued {
	t.Helper()
	issued, err := sdjwtfixture.Issue(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	return issued
}

func present(t *testing.T, issued sdjwtfixture.Issued, key *ecdsa.PrivateKey, n, aud string, iat time.Time, names ...string) string {
	t.Helper()
	selected, err := sdjwtfixture.Select(issued, names...)
	if err != nil {
		t.Fatal(err)
	}
	p, err := sdjwtfixture.Present(context.Background(), selected, key, n, aud, iat)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func verify(t *testing.T, compact string) (sdjwt.Verified, error) {
	t.Helper()
	p, err := sdjwt.Parse(compact)
	if err != nil {
		return sdjwt.Verified{}, err
	}
	return sdjwt.Verify(p, trust(), accepted(), expect())
}

func TestVerify_RoundTrip(t *testing.T) {
	issued := issue(t, options())
	v, err := verify(t, present(t, issued, holderKey, nonce, audience, now.Add(-5*time.Second), "role", "entitlement"))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.Issuer != issuer || v.Kid != kid || v.VCT != vct || v.JTI != "urn:uuid:00000000-0000-4000-8000-0000000000aa" {
		t.Errorf("envelope: %+v", v)
	}
	if v.Status == nil || v.Status.URI != listURI || v.Status.Index != 42 {
		t.Errorf("status: %+v", v.Status)
	}
	if !v.NotBefore.Equal(now.Add(-time.Hour)) || !v.ExpiresAt.Equal(now.Add(24*time.Hour)) {
		t.Errorf("validity: %v %v", v.NotBefore, v.ExpiresAt)
	}
	role, _, _ := jose.String(v.Claims, "role")
	ent, _, _ := jose.String(v.Claims, "entitlement")
	if role != "participant" || ent != "read" {
		t.Errorf("claims: %s", v.Claims)
	}
	if _, present := v.Claims["organisation"]; present {
		t.Error("an undisclosed claim surfaced")
	}
	if string(v.Claims["address"]) != `{"country":"DE"}` {
		t.Errorf("clear claim: %s", v.Claims["address"])
	}
	for _, reserved := range []string{"iss", "vct", "cnf", "_sd", "_sd_alg", "status", "exp", "nbf", "iat", "jti"} {
		if _, present := v.Claims[reserved]; present {
			t.Errorf("%s is in the claim set", reserved)
		}
	}
	if thumb, _ := v.Holder.Thumbprint(); thumb == "" {
		t.Error("holder key missing")
	}
}

func TestVerify_NoDisclosureAndNoStatus(t *testing.T) {
	o := options()
	o.Status = nil
	o.Disclosable = nil
	v, err := verify(t, present(t, issue(t, o), holderKey, nonce, audience, now))
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != nil || len(v.Claims) != 4 {
		t.Errorf("got %+v", v)
	}
}

func TestParse_Refusals(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{"no tilde", "a.b.c"},
		{"too long", strings.Repeat("a", sdjwt.MaxLength+1)},
		{"issuer not a JWT", "ab~"},
		{"disclosure not base64url", "a.b.c~not+base64~"},
		{"empty disclosure", "a.b.c~~"},
		{"key binding not a JWT", "a.b.c~abc~kb"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := sdjwt.Parse(tc.in); !errors.Is(err, sdjwt.ErrMalformed) {
				t.Errorf("got %v", err)
			}
		})
	}
	if _, err := sdjwt.Parse("a.b.c~abc~"); err != nil {
		t.Errorf("presentation without key binding parses: %v", err)
	}
}

func TestVerify_TrustAndSignature(t *testing.T) {
	t.Run("untrusted issuer", func(t *testing.T) {
		o := options()
		o.IssuerKey, o.Issuer = otherKey, "https://other.example"
		_, err := verify(t, present(t, issue(t, o), holderKey, nonce, audience, now, "role"))
		if !errors.Is(err, sdjwt.ErrUntrusted) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("unknown kid", func(t *testing.T) {
		o := options()
		o.Kid = "issuer-2"
		_, err := verify(t, present(t, issue(t, o), holderKey, nonce, audience, now, "role"))
		if !errors.Is(err, sdjwt.ErrUntrusted) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("wrong key under a trusted kid", func(t *testing.T) {
		o := options()
		o.IssuerKey = otherKey
		_, err := verify(t, present(t, issue(t, o), holderKey, nonce, audience, now, "role"))
		if !errors.Is(err, sdjwt.ErrIssuerSignature) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("payload altered after signing", func(t *testing.T) {
		issued := issue(t, options())
		jwt, rest, _ := strings.Cut(issued.SDJWT, "~")
		parts := strings.Split(jwt, ".")
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		altered := strings.Replace(string(payload), `"vct"`, `"vct_"`, 1)
		altered = strings.Replace(altered, `"iss":`, `"vct":"`+vct+`","iss":`, 1)
		parts[1] = base64.RawURLEncoding.EncodeToString([]byte(altered))
		tampered := sdjwtfixture.Issued{SDJWT: strings.Join(parts, ".") + "~" + rest, Disclosures: issued.Disclosures}
		_, err := verify(t, present(t, tampered, holderKey, nonce, audience, now, "role"))
		if !errors.Is(err, sdjwt.ErrIssuerSignature) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("wrong typ", func(t *testing.T) {
		raw, _ := json.Marshal(map[string]any{"iss": issuer, "vct": vct, "cnf": map[string]any{"jwk": jose.PublicJWK(&holderKey.PublicKey)}})
		jwt, err := jose.Sign(context.Background(), jose.Header{Typ: "vc+sd-jwt", Kid: kid}, raw, signWith(issuerKey))
		if err != nil {
			t.Fatal(err)
		}
		p, err := sdjwtfixture.Present(context.Background(), jwt+"~", holderKey, nonce, audience, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verify(t, p); !errors.Is(err, sdjwt.ErrMalformed) {
			t.Errorf("got %v", err)
		}
	})
}

func TestVerify_Envelope(t *testing.T) {
	t.Run("vct not accepted", func(t *testing.T) {
		o := options()
		o.VCT = "https://facis.example/credentials/other"
		_, err := verify(t, present(t, issue(t, o), holderKey, nonce, audience, now, "role"))
		if !errors.Is(err, sdjwt.ErrVCT) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		o := options()
		o.ExpiresAt = now.Add(-31 * time.Second)
		_, err := verify(t, present(t, issue(t, o), holderKey, nonce, audience, now, "role"))
		if !errors.Is(err, sdjwt.ErrExpired) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("expired within skew is accepted", func(t *testing.T) {
		for _, exp := range []time.Time{now.Add(-20 * time.Second), now.Add(-29 * time.Second), now} {
			o := options()
			o.ExpiresAt = exp
			if _, err := verify(t, present(t, issue(t, o), holderKey, nonce, audience, now, "role")); err != nil {
				t.Errorf("exp %v: %v", exp, err)
			}
		}
		o := options()
		o.ExpiresAt = now.Add(-30 * time.Second)
		if _, err := verify(t, present(t, issue(t, o), holderKey, nonce, audience, now, "role")); !errors.Is(err, sdjwt.ErrExpired) {
			t.Errorf("exp at the skew boundary: %v", err)
		}
	})
	t.Run("not yet valid", func(t *testing.T) {
		o := options()
		o.NotBefore = now.Add(31 * time.Second)
		_, err := verify(t, present(t, issue(t, o), holderKey, nonce, audience, now, "role"))
		if !errors.Is(err, sdjwt.ErrExpired) {
			t.Errorf("got %v", err)
		}
		o.NotBefore = now.Add(30 * time.Second)
		if _, err := verify(t, present(t, issue(t, o), holderKey, nonce, audience, now, "role")); err != nil {
			t.Errorf("nbf within skew: %v", err)
		}
	})
	t.Run("status index not a non-negative int32", func(t *testing.T) {
		for name, idx := range map[string]any{"fraction": 1.5, "null": nil, "string": "42", "negative": -1, "exponent": json.RawMessage("1e2"), "above int32": int64(1) << 31} {
			raw, _ := json.Marshal(map[string]any{"iss": issuer, "vct": vct, "cnf": map[string]any{"jwk": jose.PublicJWK(&holderKey.PublicKey)},
				"status": map[string]any{"status_list": map[string]any{"uri": listURI, "idx": idx}}})
			if _, err := verifyRaw(t, raw); !errors.Is(err, sdjwt.ErrMalformed) {
				t.Errorf("idx %s: %v", name, err)
			}
		}
	})
	t.Run("dates null or not integers", func(t *testing.T) {
		for _, member := range []string{"nbf", "exp", "iat"} {
			for name, value := range map[string]any{"null": nil, "string": "1", "float": 1.5} {
				raw, _ := json.Marshal(map[string]any{"iss": issuer, "vct": vct, "cnf": map[string]any{"jwk": jose.PublicJWK(&holderKey.PublicKey)}, member: value})
				if _, err := verifyRaw(t, raw); !errors.Is(err, sdjwt.ErrMalformed) {
					t.Errorf("%s %s: %v", member, name, err)
				}
			}
		}
	})
	t.Run("cnf missing", func(t *testing.T) {
		raw, _ := json.Marshal(map[string]any{"iss": issuer, "vct": vct})
		if _, err := verifyRaw(t, raw); !errors.Is(err, sdjwt.ErrMalformed) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("unsupported hash algorithm", func(t *testing.T) {
		raw, _ := json.Marshal(map[string]any{"iss": issuer, "vct": vct, "cnf": map[string]any{"jwk": jose.PublicJWK(&holderKey.PublicKey)}, "_sd_alg": "sha-512"})
		if _, err := verifyRaw(t, raw); !errors.Is(err, sdjwt.ErrMalformed) {
			t.Errorf("got %v", err)
		}
	})
}

func TestVerify_Disclosures(t *testing.T) {
	issued := issue(t, options())
	t.Run("tampered value", func(t *testing.T) {
		altered, _ := sdjwtfixture.EncodeDisclosure("salt", "role", "admin")
		jwt, _, _ := strings.Cut(issued.SDJWT, "~")
		p, _ := sdjwtfixture.Present(context.Background(), jwt+"~"+altered+"~", holderKey, nonce, audience, now)
		if _, err := verify(t, p); !errors.Is(err, sdjwt.ErrDisclosure) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("presented twice", func(t *testing.T) {
		jwt, _, _ := strings.Cut(issued.SDJWT, "~")
		d := issued.Disclosures["role"]
		p, _ := sdjwtfixture.Present(context.Background(), jwt+"~"+d+"~"+d+"~", holderKey, nonce, audience, now)
		if _, err := verify(t, p); !errors.Is(err, sdjwt.ErrDisclosure) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("registered claim disclosed", func(t *testing.T) {
		o := options()
		o.Claims = append(o.Claims, sdjwtfixture.Claim{Name: "jti", Value: "x"})
		o.JTI = ""
		o.Disclosable = []string{"jti"}
		_, err := verify(t, present(t, issue(t, o), holderKey, nonce, audience, now, "jti"))
		if !errors.Is(err, sdjwt.ErrDisclosure) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("name already present", func(t *testing.T) {
		d, _ := sdjwtfixture.EncodeDisclosure("s1", "role", "admin")
		raw, _ := json.Marshal(map[string]any{"iss": issuer, "vct": vct, "cnf": map[string]any{"jwk": jose.PublicJWK(&holderKey.PublicKey)},
			"role": "participant", "_sd": []string{sdjwtfixture.Digest(d)}})
		if _, err := verifyRaw(t, raw, d); !errors.Is(err, sdjwt.ErrDisclosure) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("decoy digest is fine", func(t *testing.T) {
		raw, _ := json.Marshal(map[string]any{"iss": issuer, "vct": vct, "cnf": map[string]any{"jwk": jose.PublicJWK(&holderKey.PublicKey)},
			"_sd": []string{sdjwtfixture.Digest("decoy")}, "role": "participant"})
		if _, err := verifyRaw(t, raw); err != nil {
			t.Errorf("got %v", err)
		}
	})
	t.Run("nested _sd", func(t *testing.T) {
		inner, _ := sdjwtfixture.EncodeDisclosure("s1", "country", "DE")
		raw, _ := json.Marshal(map[string]any{"iss": issuer, "vct": vct, "cnf": map[string]any{"jwk": jose.PublicJWK(&holderKey.PublicKey)},
			"role": "participant", "address": map[string]any{"_sd": []string{sdjwtfixture.Digest(inner)}}})
		v, err := verifyRaw(t, raw, inner)
		if err != nil {
			t.Fatalf("got %v", err)
		}
		if string(v.Claims["address"]) != `{"country":"DE"}` {
			t.Errorf("nested: %s", v.Claims["address"])
		}
	})
	t.Run("array element disclosure refused", func(t *testing.T) {
		// The {"...": digest} placeholder is refused where it stands, whether or not a matching
		// disclosure is presented: this profile has no array element disclosures.
		raw, _ := json.Marshal(map[string]any{"iss": issuer, "vct": vct, "cnf": map[string]any{"jwk": jose.PublicJWK(&holderKey.PublicKey)},
			"role": "participant", "tags": []any{map[string]any{"...": sdjwtfixture.Digest("whatever")}}})
		if _, err := verifyRaw(t, raw); !errors.Is(err, sdjwt.ErrDisclosure) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("envelope members are not descended into", func(t *testing.T) {
		// A digest placed inside cnf or status never resolves a disclosure: the envelope is read by
		// Verify, so a disclosure referenced only from there is unreferenced.
		d, _ := sdjwtfixture.EncodeDisclosure("s1", "role", "admin")
		raw, _ := json.Marshal(map[string]any{"iss": issuer, "vct": vct, "cnf": map[string]any{"jwk": jose.PublicJWK(&holderKey.PublicKey)},
			"status": map[string]any{"status_list": map[string]any{"uri": listURI, "idx": 1}, "_sd": []string{sdjwtfixture.Digest(d)}}})
		if _, err := verifyRaw(t, raw, d); !errors.Is(err, sdjwt.ErrMalformed) && !errors.Is(err, sdjwt.ErrDisclosure) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("nesting bound", func(t *testing.T) {
		// The payload is bounded by jose.ParseObject; a disclosure's value is read with the plain
		// decoder, so the disclosure resolver bounds it itself, arrays included: 15 nested
		// containers inside a disclosure value are the most (its leaf then sits at depth 16).
		nest := func(levels int, array bool) any {
			var v any = "leaf"
			for i := 0; i < levels; i++ {
				if array {
					v = []any{v}
				} else {
					v = map[string]any{"a": v}
				}
			}
			return v
		}
		for _, tc := range []struct {
			levels int
			array  bool
			ok     bool
		}{{15, false, true}, {15, true, true}, {16, false, false}, {16, true, false}, {40, true, false}} {
			d, _ := sdjwtfixture.EncodeDisclosure("s1", "deep", nest(tc.levels, tc.array))
			raw, _ := json.Marshal(map[string]any{"iss": issuer, "vct": vct, "cnf": map[string]any{"jwk": jose.PublicJWK(&holderKey.PublicKey)},
				"_sd": []string{sdjwtfixture.Digest(d)}})
			_, err := verifyRaw(t, raw, d)
			if tc.ok && err != nil {
				t.Errorf("%d levels (array %v): %v", tc.levels, tc.array, err)
			}
			if !tc.ok && !errors.Is(err, sdjwt.ErrDisclosure) {
				t.Errorf("%d levels (array %v): %v", tc.levels, tc.array, err)
			}
		}
		raw, _ := json.Marshal(map[string]any{"iss": issuer, "vct": vct, "cnf": map[string]any{"jwk": jose.PublicJWK(&holderKey.PublicKey)}, "deep": nest(40, true)})
		if _, err := verifyRaw(t, raw); !errors.Is(err, sdjwt.ErrMalformed) {
			t.Errorf("payload nested 40 deep: %v", err)
		}
	})
	t.Run("disclosure count bound", func(t *testing.T) {
		o := options()
		o.Claims, o.Disclosable = nil, nil
		for i := 0; i < 65; i++ {
			name := fmt.Sprintf("c%02d", i)
			o.Claims = append(o.Claims, sdjwtfixture.Claim{Name: name, Value: i})
			o.Disclosable = append(o.Disclosable, name)
		}
		issued := issue(t, o)
		if _, err := verify(t, present(t, issued, holderKey, nonce, audience, now, o.Disclosable[:64]...)); err != nil {
			t.Errorf("64 disclosures: %v", err)
		}
		if _, err := verify(t, present(t, issued, holderKey, nonce, audience, now, o.Disclosable...)); !errors.Is(err, sdjwt.ErrMalformed) {
			t.Errorf("65 disclosures: %v", err)
		}
	})
	t.Run("_sd not an array", func(t *testing.T) {
		raw, _ := json.Marshal(map[string]any{"iss": issuer, "vct": vct, "cnf": map[string]any{"jwk": jose.PublicJWK(&holderKey.PublicKey)}, "_sd": "x"})
		if _, err := verifyRaw(t, raw); !errors.Is(err, sdjwt.ErrDisclosure) {
			t.Errorf("got %v", err)
		}
	})
}

func TestVerify_KeyBinding(t *testing.T) {
	issued := issue(t, options())
	selected, _ := sdjwtfixture.Select(issued, "role")
	for _, tc := range []struct {
		name string
		make func() string
		want error
	}{
		{"missing", func() string { return selected }, sdjwt.ErrKeyBinding},
		{"wrong holder key", func() string { return present(t, issued, otherKey, nonce, audience, now, "role") }, sdjwt.ErrKeyBinding},
		{"wrong nonce", func() string { return present(t, issued, holderKey, "other-nonce-0123456789", audience, now, "role") }, sdjwt.ErrKeyBinding},
		{"wrong audience", func() string { return present(t, issued, holderKey, nonce, "https://zone-c.example", now, "role") }, sdjwt.ErrKeyBinding},
		{"too old", func() string {
			return present(t, issued, holderKey, nonce, audience, now.Add(-301*time.Second), "role")
		}, sdjwt.ErrKeyBinding},
		{"as old as allowed", func() string {
			return present(t, issued, holderKey, nonce, audience, now.Add(-300*time.Second), "role")
		}, nil},
		{"from the future", func() string { return present(t, issued, holderKey, nonce, audience, now.Add(31*time.Second), "role") }, sdjwt.ErrKeyBinding},
		{"within the skew", func() string { return present(t, issued, holderKey, nonce, audience, now.Add(30*time.Second), "role") }, nil},
		{"iat null", func() string {
			raw := []byte(`{"iat":null,"aud":"` + audience + `","nonce":"` + nonce + `","sd_hash":"` + sdjwt.SDHash(mustParse(t, selected)) + `"}`)
			kb, _ := jose.Sign(context.Background(), jose.Header{Typ: sdjwt.TypKeyBinding}, raw, signWith(holderKey))
			return selected + kb
		}, sdjwt.ErrKeyBinding},
		{"sd_hash over another selection", func() string {
			p := present(t, issued, holderKey, nonce, audience, now, "role", "entitlement")
			// Drop the entitlement disclosure after the key binding was computed.
			parts := strings.Split(p, "~")
			return strings.Join(append(parts[:2], parts[3]), "~")
		}, sdjwt.ErrKeyBinding},
		{"extra member", func() string {
			raw, _ := json.Marshal(map[string]any{"iat": now.Unix(), "aud": audience, "nonce": nonce, "sd_hash": sdjwt.SDHash(mustParse(t, selected)), "extra": 1})
			kb, _ := jose.Sign(context.Background(), jose.Header{Typ: sdjwt.TypKeyBinding}, raw, signWith(holderKey))
			return selected + kb
		}, sdjwt.ErrKeyBinding},
		{"aud as array", func() string {
			raw, _ := json.Marshal(map[string]any{"iat": now.Unix(), "aud": []string{audience}, "nonce": nonce, "sd_hash": sdjwt.SDHash(mustParse(t, selected))})
			kb, _ := jose.Sign(context.Background(), jose.Header{Typ: sdjwt.TypKeyBinding}, raw, signWith(holderKey))
			return selected + kb
		}, sdjwt.ErrKeyBinding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verify(t, tc.make())
			if (tc.want == nil && err != nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Errorf("got %v, want %v", err, tc.want)
			}
		})
	}
	t.Run("errors carry nothing from the presentation", func(t *testing.T) {
		_, err := verify(t, present(t, issued, holderKey, "SECRET-NONCE-0123456789", audience, now, "role"))
		if err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), audience) {
			t.Errorf("error text: %v", err)
		}
	})
}

func TestVerify_SkewAndAgeOptions(t *testing.T) {
	issued := issue(t, options())
	p, _ := sdjwt.Parse(present(t, issued, holderKey, nonce, audience, now.Add(-100*time.Second), "role"))
	want := expect()
	want.KeyBindingMaxAge = 60 * time.Second
	if _, err := sdjwt.Verify(p, trust(), accepted(), want); !errors.Is(err, sdjwt.ErrKeyBinding) {
		t.Errorf("max age not applied: %v", err)
	}
}

// TestVerify_ExpectRequired: an empty nonce or audience would bind the presentation to nothing,
// and a zero instant or negative tolerance is a caller's mistake; all are refused before anything
// about the presentation is judged.
func TestVerify_ExpectRequired(t *testing.T) {
	issued := issue(t, options())
	unbound, err := sdjwtfixture.Present(context.Background(), mustSelect(t, issued, "role"), holderKey, "", "", now)
	if err != nil {
		t.Fatal(err)
	}
	p := mustParse(t, unbound)
	for name, want := range map[string]sdjwt.Expect{
		"empty":         {},
		"no nonce":      {Audience: audience, Now: now},
		"no audience":   {Nonce: nonce, Now: now},
		"zero instant":  {Nonce: nonce, Audience: audience},
		"negative skew": {Nonce: nonce, Audience: audience, Now: now, Skew: -time.Second},
		"negative age":  {Nonce: nonce, Audience: audience, Now: now, KeyBindingMaxAge: -time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := sdjwt.Verify(p, trust(), accepted(), want); !errors.Is(err, sdjwt.ErrExpect) {
				t.Errorf("got %v", err)
			}
		})
	}
}

func mustSelect(t *testing.T, issued sdjwtfixture.Issued, names ...string) string {
	t.Helper()
	s, err := sdjwtfixture.Select(issued, names...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// verifyRaw signs an arbitrary issuer payload with the trusted key and presents it with the given
// disclosures, so envelope refusals are tested with valid signatures.
func verifyRaw(t *testing.T, payload []byte, disclosures ...string) (sdjwt.Verified, error) {
	t.Helper()
	jwt, err := jose.Sign(context.Background(), jose.Header{Typ: sdjwt.TypIssuer, Kid: kid}, payload, signWith(issuerKey))
	if err != nil {
		t.Fatal(err)
	}
	s := jwt + "~"
	for _, d := range disclosures {
		s += d + "~"
	}
	p, err := sdjwtfixture.Present(context.Background(), s, holderKey, nonce, audience, now)
	if err != nil {
		t.Fatal(err)
	}
	return verify(t, p)
}

func mustParse(t *testing.T, s string) sdjwt.Presentation {
	t.Helper()
	p, err := sdjwt.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func signWith(k *ecdsa.PrivateKey) jose.SignFunc {
	return func(_ context.Context, in []byte) ([]byte, error) { return sdjwtfixture.SignES256(k, in) }
}
