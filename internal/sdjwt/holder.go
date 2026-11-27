package sdjwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

// The holder's side of a presentation: what a holder can know about its credential without the
// issuer's key, and the key binding it adds.

// Inspect reads a credential as a holder keeps it, "<issuer JWT>~<disclosure>~...~", and applies
// every check of Verify that needs no key: the issuer JWT's header and encoding, the registered
// claims, the validity at now, and the disclosures. The issuer signature is not checked, so the
// result says the credential is well formed, not that it is genuine. A holder uses it to refuse
// material a verifier would refuse anyway. The validity is judged with the default clock tolerance
// of 30 s; a verifier configured with a wider one accepts a credential this refuses near its nbf or
// exp.
func Inspect(credential string, now time.Time) (Verified, error) {
	if now.IsZero() {
		return Verified{}, ErrExpect
	}
	p, err := Parse(credential)
	if err != nil {
		return Verified{}, err
	}
	if p.KeyBinding != "" {
		return Verified{}, fmt.Errorf("%w: a held credential ends with a tilde and carries no key binding", ErrMalformed)
	}
	rawPayload, err := unverifiedPayload(p.IssuerJWT)
	if err != nil {
		return Verified{}, err
	}
	payload, err := jose.ParseObject(rawPayload)
	if err != nil {
		return Verified{}, fmt.Errorf("%w: payload", ErrMalformed)
	}
	iss, _, ok := jose.String(payload, "iss")
	if !ok || iss == "" {
		return Verified{}, fmt.Errorf("%w: iss", ErrMalformed)
	}
	// The header and the three segments' encoding, by the verifier's own rules. The key function
	// is reached only when they hold; it stops there, since a holder has no issuer key. The
	// signature's length is checked here, because the verifier checks it only after the key.
	if sig, err := jose.DecodeB64(p.IssuerJWT[strings.LastIndex(p.IssuerJWT, ".")+1:]); err != nil || len(sig) != 64 {
		return Verified{}, fmt.Errorf("%w: issuer JWT signature", ErrMalformed)
	}
	var kid string
	headerRead := false
	_, _, _ = jose.Verify(p.IssuerJWT, jose.HeaderPolicy{Typ: TypIssuer, KidNeeded: true}, func(h jose.Header) (*ecdsa.PublicKey, error) {
		kid, headerRead = h.Kid, true
		return nil, errors.New("no issuer key")
	})
	if !headerRead {
		return Verified{}, fmt.Errorf("%w: issuer JWT header", ErrMalformed)
	}
	v, err := envelope(payload, p.Disclosures, func(string) bool { return true }, now, defaultSkew)
	if err != nil {
		return Verified{}, err
	}
	v.Issuer, v.Kid = iss, kid
	return v, nil
}

// Bind appends a key-binding JWT for nonce and audience, dated iat and signed by sign with the
// credential's holder key, to credential, which must end with a tilde and carry exactly the
// disclosures to reveal. The result is the presentation a verifier checks with Verify.
func Bind(ctx context.Context, credential string, sign jose.SignFunc, nonce, audience string, iat time.Time) (string, error) {
	if sign == nil || nonce == "" || audience == "" || iat.IsZero() || len(credential) == 0 || credential[len(credential)-1] != '~' {
		return "", ErrExpect
	}
	digest := sha256.Sum256([]byte(credential))
	raw, err := json.Marshal(map[string]any{"iat": iat.Unix(), "aud": audience, "nonce": nonce, "sd_hash": jose.B64(digest[:])})
	if err != nil {
		return "", err
	}
	kb, err := jose.Sign(ctx, jose.Header{Typ: TypKeyBinding}, raw, sign)
	if err != nil {
		return "", err
	}
	if len(credential)+len(kb) > MaxLength {
		return "", fmt.Errorf("%w: longer than %d bytes", ErrMalformed, MaxLength)
	}
	return credential + kb, nil
}
