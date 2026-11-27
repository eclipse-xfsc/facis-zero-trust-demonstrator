// Package sdjwt verifies SD-JWT VC presentations (IETF SD-JWT and SD-JWT VC): an issuer-signed JWT
// of type dc+sd-jwt, the disclosures the holder chose to reveal, and a key-binding JWT that ties the
// presentation to a nonce and an audience. ES256 only, trust by a configured issuer set, standard
// library only. The package reports why a presentation is refused through typed errors; mapping
// those to outcomes is the verifier's policy.
package sdjwt

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

// The typ header values of the two JWTs.
const (
	TypIssuer     = "dc+sd-jwt"
	TypKeyBinding = "kb+jwt"
)

// Bounds. A presentation is small: one credential, a handful of disclosures, one key binding.
const (
	MaxLength      = 64 << 10
	maxDisclosures = 64
	maxDepth       = 16
	defaultSkew    = 30 * time.Second
	defaultKBAge   = 300 * time.Second
)

var (
	// ErrExpect is the caller's: Expect names no nonce, no audience or no instant, or a negative
	// tolerance. Nothing about the presentation was judged.
	ErrExpect          = errors.New("sdjwt: expectation incomplete")
	ErrMalformed       = errors.New("sdjwt: malformed presentation")
	ErrUntrusted       = errors.New("sdjwt: issuer or key not trusted")
	ErrIssuerSignature = errors.New("sdjwt: issuer signature does not verify")
	ErrDisclosure      = errors.New("sdjwt: disclosure not accepted")
	ErrKeyBinding      = errors.New("sdjwt: key binding not accepted")
	ErrExpired         = errors.New("sdjwt: credential outside its validity")
	ErrVCT             = errors.New("sdjwt: credential type not accepted")
)

// Presentation is the three parts of "<issuer JWT>~<disclosure>~...~<key-binding JWT>".
type Presentation struct {
	IssuerJWT   string
	Disclosures []string
	KeyBinding  string // empty when the presentation carries no key binding
}

// StatusRef is the credential's Token Status List reference (status.status_list).
type StatusRef struct {
	URI   string
	Index int
}

// Expect is what the key binding must prove, and when. Nonce, Audience and Now are required: a
// zero value would bind the presentation to nothing, so Verify refuses it with ErrExpect.
type Expect struct {
	Nonce    string
	Audience string
	Now      time.Time
	// Skew is the clock tolerance on nbf, exp and iat; zero means 30 s.
	Skew time.Duration
	// KeyBindingMaxAge bounds how old the key-binding JWT may be; zero means 300 s.
	KeyBindingMaxAge time.Duration
}

// Verified is a presentation whose issuer signature, disclosures and key binding all held.
type Verified struct {
	Issuer    string
	Kid       string
	VCT       string
	JTI       string // empty when the credential has none
	Claims    map[string]json.RawMessage
	Status    *StatusRef // nil when the credential carries no status reference
	NotBefore time.Time  // zero when absent
	ExpiresAt time.Time  // zero when absent
	Holder    jose.JWK
}

// Parse splits a presentation into its parts. The issuer JWT and the key binding are only split
// here; their signatures and content are checked by Verify.
func Parse(compact string) (Presentation, error) {
	if len(compact) > MaxLength {
		return Presentation{}, fmt.Errorf("%w: longer than %d bytes", ErrMalformed, MaxLength)
	}
	parts := strings.Split(compact, "~")
	if len(parts) < 2 {
		return Presentation{}, fmt.Errorf("%w: no tilde", ErrMalformed)
	}
	p := Presentation{IssuerJWT: parts[0], KeyBinding: parts[len(parts)-1]}
	if strings.Count(p.IssuerJWT, ".") != 2 || p.IssuerJWT == "" {
		return Presentation{}, fmt.Errorf("%w: issuer JWT", ErrMalformed)
	}
	for _, d := range parts[1 : len(parts)-1] {
		if d == "" || !jose.IsB64URL(d) {
			return Presentation{}, fmt.Errorf("%w: disclosure encoding", ErrMalformed)
		}
		p.Disclosures = append(p.Disclosures, d)
	}
	if len(p.Disclosures) > maxDisclosures {
		return Presentation{}, fmt.Errorf("%w: more than %d disclosures", ErrMalformed, maxDisclosures)
	}
	if p.KeyBinding != "" && strings.Count(p.KeyBinding, ".") != 2 {
		return Presentation{}, fmt.Errorf("%w: key binding", ErrMalformed)
	}
	return p, nil
}

// Verify checks p against trusted issuers, the accepted credential types and want, in this order:
// the issuer is trusted and its kid known (ErrUntrusted); the issuer signature verifies
// (ErrIssuerSignature); the payload is a well-formed SD-JWT VC of an accepted type within its
// validity (ErrMalformed, ErrVCT, ErrExpired); every disclosure is referenced exactly once and
// names no reserved or registered claim (ErrDisclosure); the key binding is signed by the
// credential's holder key over this exact presentation for want's nonce and audience, and is fresh
// (ErrKeyBinding). Errors are fixed text; nothing from the presentation is repeated in them.
func Verify(p Presentation, trusted if03.Issuers, acceptedVCT map[string]bool, want Expect) (Verified, error) {
	if want.Nonce == "" || want.Audience == "" || want.Now.IsZero() || want.Skew < 0 || want.KeyBindingMaxAge < 0 {
		return Verified{}, ErrExpect
	}
	skew, maxAge := want.Skew, want.KeyBindingMaxAge
	if skew == 0 {
		skew = defaultSkew
	}
	if maxAge == 0 {
		maxAge = defaultKBAge
	}
	now := want.Now

	// 1. Trust: read iss from the unverified payload, resolve the key by kid, only then verify.
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
	if _, trustedIssuer := trusted[iss]; !trustedIssuer {
		return Verified{}, fmt.Errorf("%w: issuer", ErrUntrusted)
	}
	var kid string
	kidUnknown := false
	_, _, err = jose.Verify(p.IssuerJWT, jose.HeaderPolicy{Typ: TypIssuer, KidNeeded: true}, func(h jose.Header) (*ecdsa.PublicKey, error) {
		kid = h.Kid
		owner, k, ok := trusted.Key(h.Kid)
		if !ok || owner != iss {
			kidUnknown = true
			return nil, errors.New("kid not held by the issuer")
		}
		return k, nil
	})
	switch {
	case kidUnknown:
		return Verified{}, fmt.Errorf("%w: kid", ErrUntrusted)
	case errors.Is(err, jose.ErrHeader) || errors.Is(err, jose.ErrMalformed):
		return Verified{}, fmt.Errorf("%w: issuer JWT header", ErrMalformed)
	case err != nil:
		return Verified{}, ErrIssuerSignature
	}

	// 2. The registered claims of an SD-JWT VC.
	v := Verified{Issuer: iss, Kid: kid}
	if v.VCT, _, ok = jose.String(payload, "vct"); !ok || v.VCT == "" {
		return Verified{}, fmt.Errorf("%w: vct", ErrMalformed)
	}
	if !acceptedVCT[v.VCT] {
		return Verified{}, ErrVCT
	}
	if alg, present, ok := jose.String(payload, "_sd_alg"); present && (!ok || alg != "sha-256") {
		return Verified{}, fmt.Errorf("%w: _sd_alg", ErrMalformed)
	}
	if v.Holder, err = holderKey(payload["cnf"]); err != nil {
		return Verified{}, err
	}
	if _, present := payload["jti"]; present {
		if v.JTI, _, ok = jose.String(payload, "jti"); !ok || v.JTI == "" {
			return Verified{}, fmt.Errorf("%w: jti", ErrMalformed)
		}
	}
	for _, c := range []struct {
		name string
		dst  *time.Time
	}{{"nbf", &v.NotBefore}, {"exp", &v.ExpiresAt}} {
		if _, present := payload[c.name]; !present {
			continue
		}
		t, ok := numericDate(payload[c.name])
		if !ok {
			return Verified{}, fmt.Errorf("%w: %s", ErrMalformed, c.name)
		}
		*c.dst = t
	}
	if _, present := payload["iat"]; present {
		if _, ok := numericDate(payload["iat"]); !ok {
			return Verified{}, fmt.Errorf("%w: iat", ErrMalformed)
		}
	}
	if !v.NotBefore.IsZero() && v.NotBefore.After(now.Add(skew)) {
		return Verified{}, fmt.Errorf("%w: not yet valid", ErrExpired)
	}
	if !v.ExpiresAt.IsZero() && !v.ExpiresAt.After(now.Add(-skew)) {
		return Verified{}, fmt.Errorf("%w: expired", ErrExpired)
	}
	if raw, present := payload["status"]; present {
		if v.Status, err = statusRef(raw); err != nil {
			return Verified{}, err
		}
	}

	// 3. Disclosures: resolve every _sd digest, refuse anything unreferenced or reserved.
	if v.Claims, err = disclose(payload, p.Disclosures); err != nil {
		return Verified{}, err
	}

	// 4. Key binding over this exact presentation, by the holder key, for this nonce and audience.
	if p.KeyBinding == "" {
		return Verified{}, fmt.Errorf("%w: missing", ErrKeyBinding)
	}
	holder, err := v.Holder.PublicKey()
	if err != nil {
		return Verified{}, fmt.Errorf("%w: cnf", ErrMalformed)
	}
	_, kbPayload, err := jose.Verify(p.KeyBinding, jose.HeaderPolicy{Typ: TypKeyBinding}, func(jose.Header) (*ecdsa.PublicKey, error) {
		return holder, nil
	})
	if err != nil {
		return Verified{}, fmt.Errorf("%w: signature", ErrKeyBinding)
	}
	kb, err := jose.ParseObject(kbPayload)
	if err != nil {
		return Verified{}, fmt.Errorf("%w: payload", ErrKeyBinding)
	}
	for name := range kb {
		if !keyBindingMembers[name] {
			return Verified{}, fmt.Errorf("%w: member not allowed", ErrKeyBinding)
		}
	}
	nonce, _, nonceOK := jose.String(kb, "nonce")
	aud, _, audOK := jose.String(kb, "aud")
	hash, _, hashOK := jose.String(kb, "sd_hash")
	iat, iatOK := numericDate(kb["iat"])
	if !nonceOK || !audOK || !hashOK || !iatOK {
		return Verified{}, fmt.Errorf("%w: members", ErrKeyBinding)
	}
	if nonce != want.Nonce || aud != want.Audience {
		return Verified{}, fmt.Errorf("%w: nonce or audience", ErrKeyBinding)
	}
	if iat.After(now.Add(skew)) || iat.Before(now.Add(-maxAge)) {
		return Verified{}, fmt.Errorf("%w: iat", ErrKeyBinding)
	}
	if hash != SDHash(p) {
		return Verified{}, fmt.Errorf("%w: sd_hash", ErrKeyBinding)
	}
	return v, nil
}

// SDHash is the key binding's sd_hash: the SHA-256 of the presentation up to and including the
// tilde before the key binding, base64url without padding.
func SDHash(p Presentation) string {
	s := p.IssuerJWT + "~"
	for _, d := range p.Disclosures {
		s += d + "~"
	}
	digest := sha256.Sum256([]byte(s))
	return jose.B64(digest[:])
}

// Registered claims of an SD-JWT VC: part of the credential's envelope, never selectively
// disclosable, and not part of the claim set a verifier maps to roles.
var registeredClaims = map[string]bool{"iss": true, "vct": true, "cnf": true, "nbf": true, "exp": true, "iat": true, "jti": true, "status": true, "_sd_alg": true}

var keyBindingMembers = map[string]bool{"iat": true, "aud": true, "nonce": true, "sd_hash": true}

func unverifiedPayload(token string) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: issuer JWT", ErrMalformed)
	}
	payload, err := jose.DecodeB64(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: issuer JWT payload encoding", ErrMalformed)
	}
	return payload, nil
}

// holderKey reads cnf as exactly {"jwk": <public P-256 JWK>}.
func holderKey(raw json.RawMessage) (jose.JWK, error) {
	if raw == nil {
		return jose.JWK{}, fmt.Errorf("%w: cnf", ErrMalformed)
	}
	cnf, err := jose.ParseObject(raw)
	if err != nil || len(cnf) != 1 || cnf["jwk"] == nil {
		return jose.JWK{}, fmt.Errorf("%w: cnf", ErrMalformed)
	}
	jwk, err := jose.ParseJWK(cnf["jwk"])
	if err != nil {
		return jose.JWK{}, fmt.Errorf("%w: cnf.jwk", ErrMalformed)
	}
	return jwk, nil
}

// statusRef reads status as exactly {"status_list": {"uri": <string>, "idx": <non-negative int>}}.
func statusRef(raw json.RawMessage) (*StatusRef, error) {
	status, err := jose.ParseObject(raw)
	if err != nil || len(status) != 1 || status["status_list"] == nil {
		return nil, fmt.Errorf("%w: status", ErrMalformed)
	}
	list, err := jose.ParseObject(status["status_list"])
	if err != nil || len(list) != 2 {
		return nil, fmt.Errorf("%w: status_list", ErrMalformed)
	}
	uri, _, ok := jose.String(list, "uri")
	if !ok || uri == "" || utf8.RuneCountInString(uri) > 2048 {
		return nil, fmt.Errorf("%w: status_list.uri", ErrMalformed)
	}
	idx, ok := jose.Integer(list["idx"])
	if !ok || idx > math.MaxInt32 {
		return nil, fmt.Errorf("%w: status_list.idx", ErrMalformed)
	}
	return &StatusRef{URI: uri, Index: int(idx)}, nil
}

// numericDate reads a JWT NumericDate: a non-negative integer number of seconds. null, a fraction
// or an exponent is not one.
func numericDate(raw json.RawMessage) (time.Time, bool) {
	n, ok := jose.Integer(raw)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(n, 0).UTC(), true
}
