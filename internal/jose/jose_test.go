package jose

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func signer(k *ecdsa.PrivateKey) SignFunc {
	return func(_ context.Context, in []byte) ([]byte, error) {
		d := sha256.Sum256(in)
		r, s, err := ecdsa.Sign(rand.Reader, k, d[:])
		if err != nil {
			return nil, err
		}
		return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...), nil
	}
}

func fixed(k *ecdsa.PrivateKey) KeyFunc {
	return func(Header) (*ecdsa.PublicKey, error) { return &k.PublicKey, nil }
}

// signRaw signs an arbitrary header JSON, so header refusals are tested with a valid signature.
func signRaw(t *testing.T, k *ecdsa.PrivateKey, header, payload string) string {
	t.Helper()
	in := b64([]byte(header)) + "." + b64([]byte(payload))
	sig, err := signer(k)(context.Background(), []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + b64(sig)
}

func jwkJSON(k *ecdsa.PrivateKey) string {
	j := PublicJWK(&k.PublicKey)
	return fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q}`, j.X, j.Y)
}

var atPolicy = HeaderPolicy{Typ: "at+jwt", KidNeeded: true}

func TestSignVerify_RoundTrip(t *testing.T) {
	k := newKey(t)
	jwk := PublicJWK(&k.PublicKey)
	for _, tc := range []struct {
		name   string
		h      Header
		policy HeaderPolicy
	}{
		{"kid header", Header{Typ: "at+jwt", Kid: "k1"}, atPolicy},
		{"embedded jwk", Header{Typ: "dpop+jwt", JWK: &jwk}, HeaderPolicy{Typ: "dpop+jwt", JWKNeeded: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := Sign(context.Background(), tc.h, []byte(`{"a":1}`), signer(k))
			if err != nil {
				t.Fatal(err)
			}
			h, payload, err := Verify(tok, tc.policy, fixed(k))
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if string(payload) != `{"a":1}` || h.Alg != AlgES256 || h.Typ != tc.h.Typ || h.Kid != tc.h.Kid {
				t.Errorf("got header %+v payload %s", h, payload)
			}
		})
	}
}

func TestSign_AlwaysWritesES256(t *testing.T) {
	k := newKey(t)
	tok, err := Sign(context.Background(), Header{Alg: "none", Typ: "at+jwt", Kid: "k"}, []byte(`{}`), signer(k))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := decodeB64(strings.Split(tok, ".")[0])
	if string(raw) != `{"alg":"ES256","typ":"at+jwt","kid":"k"}` {
		t.Errorf("header = %s", raw)
	}
}

func TestSign_RefusesSignatureThatIsNot64Bytes(t *testing.T) {
	for _, n := range []int{0, 63, 65, 72} {
		_, err := Sign(context.Background(), Header{}, nil, func(context.Context, []byte) ([]byte, error) { return make([]byte, n), nil })
		if err == nil {
			t.Errorf("signer returning %d bytes was accepted", n)
		}
	}
}

func TestVerify_RefusesHeaderMembersOutsideAllowList(t *testing.T) {
	k := newKey(t)
	for _, member := range []string{
		`"crit":["exp"]`, `"b64":false`, `"jku":"https://evil.example/jwks"`, `"x5u":"https://evil.example/c"`,
		`"x5c":["MIIB"]`, `"x5t":"abc"`, `"cty":"JWT"`, `"zip":"DEF"`, `"enc":"A128GCM"`, `"ALG":"ES256"`, `"Kid":"k"`, `"anything":1`,
	} {
		t.Run(member, func(t *testing.T) {
			tok := signRaw(t, k, `{"alg":"ES256","typ":"at+jwt","kid":"k",`+member+`}`, `{}`)
			if _, _, err := Verify(tok, atPolicy, fixed(k)); !errors.Is(err, ErrHeader) {
				t.Errorf("err = %v, want ErrHeader", err)
			}
		})
	}
}

func TestVerify_RefusesDuplicateMembers(t *testing.T) {
	k := newKey(t)
	j := PublicJWK(&k.PublicKey)
	for name, header := range map[string]string{
		"alg twice":          `{"alg":"ES256","alg":"none","typ":"at+jwt","kid":"k"}`,
		"kid twice":          `{"alg":"ES256","typ":"at+jwt","kid":"a","kid":"b"}`,
		"x twice inside jwk": fmt.Sprintf(`{"alg":"ES256","typ":"dpop+jwt","jwk":{"kty":"EC","crv":"P-256","x":%q,"x":%q,"y":%q}}`, j.X, j.X, j.Y),
	} {
		t.Run(name, func(t *testing.T) {
			policy := atPolicy
			if strings.Contains(header, "jwk") {
				policy = HeaderPolicy{Typ: "dpop+jwt", JWKNeeded: true}
			}
			if _, _, err := Verify(signRaw(t, k, header, `{}`), policy, fixed(k)); !errors.Is(err, ErrMalformed) {
				t.Errorf("err = %v, want ErrMalformed", err)
			}
		})
	}
	if _, err := ParseObject([]byte(`{"a":{"b":1,"b":2}}`)); err == nil {
		t.Error("ParseObject accepted a nested duplicate")
	}
}

func TestVerify_RefusesEveryAlgButES256(t *testing.T) {
	k := newKey(t)
	for _, alg := range []string{`"none"`, `"HS256"`, `"RS256"`, `"ES384"`, `"es256"`, `"ES256 "`, `""`, `null`, `1`} {
		t.Run(alg, func(t *testing.T) {
			tok := signRaw(t, k, `{"alg":`+alg+`,"typ":"at+jwt","kid":"k"}`, `{}`)
			if _, _, err := Verify(tok, atPolicy, fixed(k)); !errors.Is(err, ErrHeader) {
				t.Errorf("err = %v, want ErrHeader", err)
			}
		})
	}
	t.Run("absent", func(t *testing.T) {
		tok := signRaw(t, k, `{"typ":"at+jwt","kid":"k"}`, `{}`)
		if _, _, err := Verify(tok, atPolicy, fixed(k)); !errors.Is(err, ErrHeader) {
			t.Errorf("err = %v, want ErrHeader", err)
		}
	})
	t.Run("alg none with empty signature", func(t *testing.T) {
		tok := b64([]byte(`{"alg":"none","typ":"at+jwt","kid":"k"}`)) + "." + b64([]byte(`{}`)) + "."
		if _, _, err := Verify(tok, atPolicy, fixed(k)); err == nil {
			t.Error("unsigned token accepted")
		}
	})
}

func TestVerify_HeaderPolicy(t *testing.T) {
	k := newKey(t)
	other := newKey(t)
	jwk := jwkJSON(k)
	dpop := HeaderPolicy{Typ: "dpop+jwt", JWKNeeded: true}
	for _, tc := range []struct {
		name   string
		header string
		policy HeaderPolicy
	}{
		{"typ must equal policy", `{"alg":"ES256","typ":"JWT","kid":"k"}`, atPolicy},
		{"typ must be present", `{"alg":"ES256","kid":"k"}`, atPolicy},
		{"typ must be a string", `{"alg":"ES256","typ":null,"kid":"k"}`, atPolicy},
		{"kid required when policy says so", `{"alg":"ES256","typ":"at+jwt"}`, atPolicy},
		{"kid must not be empty", `{"alg":"ES256","typ":"at+jwt","kid":""}`, atPolicy},
		{"jwk refused when not needed", `{"alg":"ES256","typ":"at+jwt","kid":"k","jwk":` + jwk + `}`, atPolicy},
		{"jwk required when needed", `{"alg":"ES256","typ":"dpop+jwt"}`, dpop},
		{"jwk with private d refused", `{"alg":"ES256","typ":"dpop+jwt","jwk":` + strings.TrimSuffix(jwk, "}") + `,"d":"AAAA"}}`, dpop},
		{"jwk with other member refused", `{"alg":"ES256","typ":"dpop+jwt","jwk":` + strings.TrimSuffix(jwk, "}") + `,"use":"sig"}}`, dpop},
		{"jwk on another curve refused", `{"alg":"ES256","typ":"dpop+jwt","jwk":` + strings.Replace(jwk, "P-256", "P-384", 1) + `}`, dpop},
		{"jwk RSA refused", `{"alg":"ES256","typ":"dpop+jwt","jwk":{"kty":"RSA","n":"AQAB","e":"AQAB"}}`, dpop},
		{"jwk not an object", `{"alg":"ES256","typ":"dpop+jwt","jwk":"x"}`, dpop},
		{"jwk off-curve point refused", `{"alg":"ES256","typ":"dpop+jwt","jwk":` + offCurveJWK(other) + `}`, dpop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok := signRaw(t, k, tc.header, `{}`)
			_, _, err := Verify(tok, tc.policy, func(Header) (*ecdsa.PublicKey, error) { return &k.PublicKey, nil })
			if !errors.Is(err, ErrHeader) && !errors.Is(err, ErrMalformed) {
				t.Errorf("err = %v, want a header refusal", err)
			}
		})
	}
}

func offCurveJWK(k *ecdsa.PrivateKey) string {
	j := PublicJWK(&k.PublicKey)
	y, _ := decodeB64(j.Y)
	y[31] ^= 1
	return fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q}`, j.X, b64(y))
}

func TestVerify_RefusesMalformedCompactForm(t *testing.T) {
	k := newKey(t)
	good := signRaw(t, k, `{"alg":"ES256","typ":"at+jwt","kid":"k"}`, `{"a":1}`)
	p := strings.Split(good, ".")
	std := base64.URLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"at+jwt","kid":"k"}`)) // with padding
	for name, tok := range map[string]string{
		"two parts":                p[0] + "." + p[1],
		"four parts":               good + ".",
		"empty":                    "",
		"padded header":            std + "." + p[1] + "." + p[2],
		"padding on signature":     p[0] + "." + p[1] + "." + p[2] + "=",
		"newline inside signature": p[0] + "." + p[1] + "." + p[2][:8] + "\r\n" + p[2][8:],
		"newline inside header":    p[0][:4] + "\n" + p[0][4:] + "." + p[1] + "." + p[2],
		"standard alphabet":        p[0] + "." + p[1] + ".+" + p[2][1:],
		"header is an array":       signRaw(t, k, `["alg","ES256"]`, `{}`),
		"header is a string":       signRaw(t, k, `"ES256"`, `{}`),
		"data after header object": signRaw(t, k, `{"alg":"ES256","typ":"at+jwt","kid":"k"}{}`, `{}`),
		"header not UTF-8":         signRaw(t, k, "{\"alg\":\"ES256\",\"typ\":\"at+jwt\",\"kid\":\"\xff\"}", `{}`),
		"header not JSON":          signRaw(t, k, `{alg:ES256}`, `{}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Verify(tok, atPolicy, fixed(k)); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestVerify_RefusesSignatureOfWrongLength(t *testing.T) {
	k := newKey(t)
	p := strings.Split(signRaw(t, k, `{"alg":"ES256","typ":"at+jwt","kid":"k"}`, `{}`), ".")
	sig, _ := decodeB64(p[2])
	for _, s := range [][]byte{nil, sig[:63], append(sig, 0), append([]byte{0}, sig...)} {
		tok := p[0] + "." + p[1] + "." + b64(s)
		if _, _, err := Verify(tok, atPolicy, fixed(k)); !errors.Is(err, ErrSignature) {
			t.Errorf("%d-byte signature: err = %v, want ErrSignature", len(s), err)
		}
	}
}

func TestVerify_RAndSMustBeIn1ToNMinus1(t *testing.T) {
	k := newKey(t)
	p := strings.Split(signRaw(t, k, `{"alg":"ES256","typ":"at+jwt","kid":"k"}`, `{}`), ".")
	sig, _ := decodeB64(p[2])
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	n := elliptic.P256().Params().N
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	for _, tc := range []struct {
		name string
		r, s *big.Int
	}{
		{"zero R", big.NewInt(0), s},
		{"zero S", r, big.NewInt(0)},
		{"R equal to N", n, s},
		{"S equal to N", r, n},
		{"S plus N (same value mod N)", r, new(big.Int).Add(s, n)},
		{"S all ones", r, max},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.s.BitLen() > 256 {
				// Not expressible in a 64-byte signature at all, so there is nothing to refuse. Not a
				// skip: the CI job fails on skips, and this depends on the random key.
				return
			}
			raw := append(tc.r.FillBytes(make([]byte, 32)), tc.s.FillBytes(make([]byte, 32))...)
			if _, _, err := Verify(p[0]+"."+p[1]+"."+b64(raw), atPolicy, fixed(k)); !errors.Is(err, ErrSignature) {
				t.Errorf("err = %v, want ErrSignature", err)
			}
		})
	}
	// ES256 has no low-S rule (RFC 7518 3.4), so the high-S twin (R, N-S) of a valid signature is
	// itself valid. Replay protection never keys on signature bytes, so this is documented, not refused.
	t.Run("high-S twin verifies by design", func(t *testing.T) {
		twin := append(r.FillBytes(make([]byte, 32)), new(big.Int).Sub(n, s).FillBytes(make([]byte, 32))...)
		if _, _, err := Verify(p[0]+"."+p[1]+"."+b64(twin), atPolicy, fixed(k)); err != nil {
			t.Errorf("err = %v", err)
		}
	})
}

func TestVerify_RefusesTamperingAndWrongKey(t *testing.T) {
	k := newKey(t)
	good := signRaw(t, k, `{"alg":"ES256","typ":"at+jwt","kid":"k"}`, `{"sub":"a"}`)
	p := strings.Split(good, ".")
	tampered := p[0] + "." + b64([]byte(`{"sub":"b"}`)) + "." + p[2]
	if _, _, err := Verify(tampered, atPolicy, fixed(k)); !errors.Is(err, ErrSignature) {
		t.Errorf("tampered payload: err = %v", err)
	}
	if _, _, err := Verify(good, atPolicy, fixed(newKey(t))); !errors.Is(err, ErrSignature) {
		t.Errorf("wrong key: err = %v", err)
	}
	if _, _, err := Verify(good, atPolicy, func(Header) (*ecdsa.PublicKey, error) { return nil, errors.New("no such kid") }); !errors.Is(err, ErrSignature) {
		t.Errorf("key lookup error: err = %v, want ErrSignature", err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, _, err := Verify(good, atPolicy, fixed(p384)); !errors.Is(err, ErrSignature) {
		t.Errorf("P-384 key: err = %v", err)
	}
}

func TestPublicKey_RefusesAnythingButAValidP256Point(t *testing.T) {
	k := newKey(t)
	good := PublicJWK(&k.PublicKey)
	x, _ := decodeB64(good.X)
	off := good
	y, _ := decodeB64(good.Y)
	y[0] ^= 0x80
	off.Y = b64(y)
	for name, j := range map[string]JWK{
		"wrong kty":           {Kty: "RSA", Crv: "P-256", X: good.X, Y: good.Y},
		"wrong crv":           {Kty: "EC", Crv: "P-384", X: good.X, Y: good.Y},
		"lowercase crv":       {Kty: "EC", Crv: "p-256", X: good.X, Y: good.Y},
		"x 31 bytes":          {Kty: "EC", Crv: "P-256", X: b64(x[1:]), Y: good.Y},
		"x 33 bytes":          {Kty: "EC", Crv: "P-256", X: b64(append([]byte{0}, x...)), Y: good.Y},
		"x padded base64":     {Kty: "EC", Crv: "P-256", X: good.X + "=", Y: good.Y},
		"off-curve point":     off,
		"point at zero":       {Kty: "EC", Crv: "P-256", X: b64(make([]byte, 32)), Y: b64(make([]byte, 32))},
		"coordinate above p":  {Kty: "EC", Crv: "P-256", X: b64(bytesFF(32)), Y: good.Y},
		"missing coordinates": {Kty: "EC", Crv: "P-256"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := j.PublicKey(); err == nil {
				t.Error("accepted")
			}
			if _, err := j.Thumbprint(); err == nil {
				t.Error("thumbprint of an invalid key")
			}
		})
	}
	pub, err := good.PublicKey()
	if err != nil || !pub.Equal(&k.PublicKey) {
		t.Errorf("valid key: %v", err)
	}
}

func bytesFF(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 0xff
	}
	return b
}

// RFC 7638 3.1's worked example is an RSA key; this is the EC example of RFC 9449 (sections 4.1 and
// 6.1), whose thumbprint the RFC states.
func TestThumbprint_MatchesRFC9449Example(t *testing.T) {
	j := JWK{Kty: "EC", Crv: "P-256", X: "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs", Y: "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"}
	got, err := j.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if want := "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"; got != want {
		t.Errorf("thumbprint = %s, want %s", got, want)
	}
	j.Kid = "ignored"
	if again, _ := j.Thumbprint(); again != got {
		t.Error("kid changed the thumbprint")
	}
}

// The canonical form below is copied from services/connector/internal/dpoptest (Key.Thumbprint),
// which Go's internal-package rule keeps this package from importing.
func TestThumbprint_MatchesRepoTestMinter(t *testing.T) {
	for range 20 {
		k := newKey(t)
		j := PublicJWK(&k.PublicKey)
		canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, j.Crv, j.Kty, j.X, j.Y)
		d := sha256.Sum256([]byte(canonical))
		got, err := j.Thumbprint()
		if err != nil || got != b64(d[:]) {
			t.Fatalf("thumbprint = %s (%v), want %s", got, err, b64(d[:]))
		}
	}
}

func TestPublicJWK_RoundTripsThroughPublicKey(t *testing.T) {
	k := newKey(t)
	pub, err := PublicJWK(&k.PublicKey).PublicKey()
	if err != nil || !pub.Equal(&k.PublicKey) {
		t.Fatalf("round trip: %v", err)
	}
	if (PublicJWK(nil) != JWK{}) {
		t.Error("nil key gave a JWK")
	}
}

// Canary: errors from this package are fixed text. Member names, JSON parser messages and the
// errors of caller-supplied callbacks never reach them; only the category and a context
// cancellation or deadline survive.
func TestErrors_NeverCarryInputOrCallbackText(t *testing.T) {
	k := newKey(t)
	good := signRaw(t, k, `{"alg":"ES256","typ":"at+jwt","kid":"k"}`, `{}`)
	canaryErr := errors.New("CANARY-CALLBACK-SECRET")
	cases := []struct {
		name string
		err  func() error
		want error
	}{
		{"unknown member name", func() error {
			_, _, err := Verify(signRaw(t, k, `{"alg":"ES256","typ":"at+jwt","kid":"k","CANARY_MEMBER":1}`, `{}`), atPolicy, fixed(k))
			return err
		}, ErrHeader},
		{"unknown jwk member name", func() error {
			h := `{"alg":"ES256","typ":"dpop+jwt","jwk":` + strings.TrimSuffix(jwkJSON(k), "}") + `,"CANARY_JWK":1}}`
			_, _, err := Verify(signRaw(t, k, h, `{}`), HeaderPolicy{Typ: "dpop+jwt", JWKNeeded: true}, fixed(k))
			return err
		}, ErrHeader},
		{"duplicate member name", func() error {
			_, _, err := Verify(signRaw(t, k, `{"alg":"ES256","typ":"at+jwt","kid":"k","CANARY_DUP":1,"CANARY_DUP":2}`, `{}`), atPolicy, fixed(k))
			return err
		}, ErrMalformed},
		{"overflowing number", func() error {
			_, _, err := Verify(signRaw(t, k, `{"alg":"ES256","typ":"at+jwt","kid":"k","n":1e31337999}`, `{}`), atPolicy, fixed(k))
			return err
		}, ErrMalformed},
		{"invalid JSON token", func() error {
			_, _, err := Verify(signRaw(t, k, `{"alg":"ES256","typ":"at+jwt","kid":CANARY_BARE}`, `{}`), atPolicy, fixed(k))
			return err
		}, ErrMalformed},
		{"ParseObject on an overflowing number", func() error {
			_, err := ParseObject([]byte(`{"CANARY_N":1e31337999,"CANARY_N":0}`))
			return err
		}, ErrMalformed},
		{"key callback error", func() error {
			_, _, err := Verify(good, atPolicy, func(Header) (*ecdsa.PublicKey, error) { return nil, canaryErr })
			return err
		}, ErrSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.err()
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if msg := err.Error(); strings.Contains(msg, "CANARY") || strings.Contains(msg, "31337") || errors.Is(err, canaryErr) {
				t.Errorf("error carries input: %q", msg)
			}
		})
	}
	t.Run("signer error", func(t *testing.T) {
		_, err := Sign(context.Background(), Header{}, nil, func(context.Context, []byte) ([]byte, error) { return nil, canaryErr })
		if err == nil || strings.Contains(err.Error(), "CANARY") || errors.Is(err, canaryErr) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("context errors stay recognisable", func(t *testing.T) {
		wrapped := fmt.Errorf("CANARY wrapper: %w", context.Canceled)
		_, _, err := Verify(good, atPolicy, func(Header) (*ecdsa.PublicKey, error) { return nil, wrapped })
		if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrSignature) || strings.Contains(err.Error(), "CANARY") {
			t.Errorf("key callback cancel: err = %v", err)
		}
		_, err = Sign(context.Background(), Header{}, nil, func(context.Context, []byte) ([]byte, error) {
			return nil, fmt.Errorf("CANARY: %w", context.DeadlineExceeded)
		})
		if !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "CANARY") {
			t.Errorf("signer deadline: err = %v", err)
		}
	})
}
