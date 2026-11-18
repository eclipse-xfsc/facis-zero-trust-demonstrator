// Package jose is the compact JWS (RFC 7515) and JWK (RFC 7517, RFC 7638) subset the token path uses:
// ES256 only, a fixed header allow-list, and signing through a caller-supplied function so that a
// private key never has to be held by this package. Standard library only.
package jose

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"unicode/utf8"
)

// AlgES256 is the only signature algorithm accepted or produced.
const AlgES256 = "ES256"

// JWK is a public P-256 key. Private members are never represented.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid,omitempty"`
}

// Header is the protected header. Members other than these are refused on verification.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`
	JWK *JWK   `json:"jwk,omitempty"`
}

// HeaderPolicy says which header members a verification accepts.
type HeaderPolicy struct {
	Typ       string // required value of typ
	KidNeeded bool   // kid must be present
	JWKNeeded bool   // jwk must be present (DPoP proofs); otherwise jwk is refused
}

// SignFunc signs the JWS signing input and returns the 64-byte R||S signature.
type SignFunc func(ctx context.Context, signingInput []byte) ([]byte, error)

// KeyFunc resolves the verification key for a parsed header.
type KeyFunc func(Header) (*ecdsa.PublicKey, error)

var (
	ErrMalformed = errors.New("jose: malformed token")
	ErrHeader    = errors.New("jose: header not allowed")
	ErrSignature = errors.New("jose: signature does not verify")
)

// Sign builds a compact JWS of payload with header h. The header alg is always ES256.
func Sign(ctx context.Context, h Header, payload []byte, sign SignFunc) (string, error) {
	h.Alg = AlgES256
	header, err := json.Marshal(h)
	if err != nil {
		return "", errors.New("jose: encode header")
	}
	signingInput := b64(header) + "." + b64(payload)
	sig, err := sign(ctx, []byte(signingInput))
	if err != nil {
		return "", withContextCause(errors.New("jose: signer failed"), err)
	}
	if len(sig) != sigSize {
		return "", errors.New("jose: signer did not return a 64-byte signature")
	}
	return signingInput + "." + b64(sig), nil
}

// Verify checks the compact JWS against policy and the key from key, and returns its header and payload.
func Verify(token string, policy HeaderPolicy, key KeyFunc) (Header, []byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Header{}, nil, fmt.Errorf("%w: want three parts", ErrMalformed)
	}
	rawHeader, err := decodeB64(parts[0])
	if err != nil {
		return Header{}, nil, fmt.Errorf("%w: header encoding", ErrMalformed)
	}
	payload, err := decodeB64(parts[1])
	if err != nil {
		return Header{}, nil, fmt.Errorf("%w: payload encoding", ErrMalformed)
	}
	sig, err := decodeB64(parts[2])
	if err != nil {
		return Header{}, nil, fmt.Errorf("%w: signature encoding", ErrMalformed)
	}

	h, err := parseHeader(rawHeader, policy)
	if err != nil {
		return Header{}, nil, err
	}

	pub, err := key(h)
	if err != nil {
		return Header{}, nil, withContextCause(fmt.Errorf("%w: no key", ErrSignature), err)
	}
	if pub == nil || pub.Curve != elliptic.P256() {
		return Header{}, nil, fmt.Errorf("%w: key is not P-256", ErrSignature)
	}

	if len(sig) != sigSize {
		return Header{}, nil, fmt.Errorf("%w: signature length", ErrSignature)
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	n := elliptic.P256().Params().N
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return Header{}, nil, fmt.Errorf("%w: R or S out of range", ErrSignature)
	}
	// ponytail: ES256 (RFC 7518 3.4) has no low-S rule, so the (R, N-S) twin also verifies; proof
	// replay is keyed on jti, never on the signature bytes.
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return Header{}, nil, ErrSignature
	}
	return h, payload, nil
}

// PublicJWK returns the public JWK of k. A key that is not a valid P-256 point yields the zero JWK.
func PublicJWK(k *ecdsa.PublicKey) JWK {
	if k == nil || k.Curve != elliptic.P256() {
		return JWK{}
	}
	point, err := k.Bytes()
	if err != nil || len(point) != 1+2*coordSize {
		return JWK{}
	}
	return JWK{Kty: "EC", Crv: "P-256", X: b64(point[1 : 1+coordSize]), Y: b64(point[1+coordSize:])}
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint of j, base64url without padding.
func (j JWK) Thumbprint() (string, error) {
	if _, err := j.PublicKey(); err != nil {
		return "", err
	}
	// RFC 7638 3.2: the required EC members in lexicographic order, no whitespace. X and Y were just
	// validated as strict base64url, which needs no JSON escaping.
	canonical := `{"crv":"P-256","kty":"EC","x":"` + j.X + `","y":"` + j.Y + `"}`
	digest := sha256.Sum256([]byte(canonical))
	return b64(digest[:]), nil
}

// PublicKey returns j as an ECDSA P-256 public key, refusing any other curve or an off-curve point.
func (j JWK) PublicKey() (*ecdsa.PublicKey, error) {
	if j.Kty != "EC" || j.Crv != "P-256" {
		return nil, fmt.Errorf("%w: jwk is not an EC P-256 key", ErrHeader)
	}
	x, errX := decodeB64(j.X)
	y, errY := decodeB64(j.Y)
	if errX != nil || errY != nil || len(x) != coordSize || len(y) != coordSize {
		return nil, fmt.Errorf("%w: jwk coordinates must be 32-byte base64url", ErrHeader)
	}
	point := append(append([]byte{4}, x...), y...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, fmt.Errorf("%w: jwk point is not on P-256", ErrHeader)
	}
	return pub, nil
}

// ParseObject decodes data as one strict JSON object: valid UTF-8, no duplicate member names at any
// depth, nothing after the object. It returns the top-level members undecoded. Every JSON object the
// token path reads from a peer (headers, claims, keys) goes through it.
func ParseObject(data []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: not UTF-8", ErrMalformed)
	}
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fmt.Errorf("%w: not a JSON object", ErrMalformed)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := checkValue(dec, 0); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: data after the JSON object", ErrMalformed)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return nil, fmt.Errorf("%w: not a JSON object", ErrMalformed)
	}
	return members, nil
}

// String returns members[name] when it is a JSON string; present reports whether the member exists.
// A member that exists but is not a string yields ok=false.
func String(members map[string]json.RawMessage, name string) (value string, present, ok bool) {
	raw, present := members[name]
	if !present {
		return "", false, false
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '"' {
		return "", true, false
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", true, false
	}
	return value, true, true
}

const (
	sigSize   = 64
	coordSize = 32
	maxDepth  = 16
)

var (
	headerMembers = map[string]bool{"alg": true, "typ": true, "kid": true, "jwk": true}
	jwkMembers    = map[string]bool{"kty": true, "crv": true, "x": true, "y": true, "kid": true}
)

func parseHeader(raw []byte, policy HeaderPolicy) (Header, error) {
	members, err := ParseObject(raw)
	if err != nil {
		return Header{}, err
	}
	for name := range members {
		if !headerMembers[name] {
			return Header{}, fmt.Errorf("%w: member not allowed", ErrHeader)
		}
	}

	var h Header
	var present, ok bool
	if h.Alg, _, ok = String(members, "alg"); !ok || h.Alg != AlgES256 {
		return Header{}, fmt.Errorf("%w: alg must be %s", ErrHeader, AlgES256)
	}
	if h.Typ, present, ok = String(members, "typ"); present != (policy.Typ != "") || (present && !ok) || h.Typ != policy.Typ {
		return Header{}, fmt.Errorf("%w: typ must be %q", ErrHeader, policy.Typ)
	}
	if h.Kid, present, ok = String(members, "kid"); (present && (!ok || h.Kid == "")) || (policy.KidNeeded && !present) {
		return Header{}, fmt.Errorf("%w: kid", ErrHeader)
	}

	rawJWK, present := members["jwk"]
	if present != policy.JWKNeeded {
		return Header{}, fmt.Errorf("%w: jwk presence", ErrHeader)
	}
	if present {
		jwk, err := ParseJWK(rawJWK)
		if err != nil {
			return Header{}, err
		}
		h.JWK = &jwk
	}
	return h, nil
}

// ParseJWK accepts a public P-256 key with members kty, crv, x, y and optionally kid; any other
// member, private ones (d) included, is refused.
func ParseJWK(raw []byte) (JWK, error) {
	members, err := ParseObject(raw)
	if err != nil {
		return JWK{}, fmt.Errorf("%w: jwk: %w", ErrHeader, err)
	}
	for name := range members {
		if !jwkMembers[name] {
			return JWK{}, fmt.Errorf("%w: jwk member not allowed", ErrHeader)
		}
	}
	var j JWK
	fields := []struct {
		name     string
		dst      *string
		optional bool
	}{{"kty", &j.Kty, false}, {"crv", &j.Crv, false}, {"x", &j.X, false}, {"y", &j.Y, false}, {"kid", &j.Kid, true}}
	for _, f := range fields {
		v, present, ok := String(members, f.name)
		if (present && !ok) || (!present && !f.optional) {
			return JWK{}, fmt.Errorf("%w: jwk member missing or not a string", ErrHeader)
		}
		*f.dst = v
	}
	if _, err := j.PublicKey(); err != nil {
		return JWK{}, err
	}
	return j, nil
}

// checkValue consumes one JSON value from dec, refusing duplicate object member names.
func checkValue(dec *json.Decoder, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("%w: JSON nested too deeply", ErrMalformed)
	}
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%w: invalid JSON", ErrMalformed)
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			tok, err := dec.Token()
			if err != nil {
				return fmt.Errorf("%w: invalid JSON", ErrMalformed)
			}
			name, _ := tok.(string)
			if seen[name] {
				return fmt.Errorf("%w: duplicate member", ErrMalformed)
			}
			seen[name] = true
			if err := checkValue(dec, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := checkValue(dec, depth+1); err != nil {
				return err
			}
		}
	}
	if _, err := dec.Token(); err != nil { // the closing delimiter
		return fmt.Errorf("%w: invalid JSON", ErrMalformed)
	}
	return nil
}

// decodeB64 is strict base64url without padding. The alphabet check matters: encoding/base64 skips
// CR and LF, which would let two different strings decode to the same bytes.
func decodeB64(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isB64URL(c) {
			return nil, ErrMalformed
		}
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

// withContextCause returns err, plus the context cancellation or deadline inside cause if there is one.
// Nothing else of cause is kept: callback errors may carry input or secrets, and errors from this
// package are fixed text.
func withContextCause(err, cause error) error {
	for _, c := range []error{context.Canceled, context.DeadlineExceeded} {
		if errors.Is(cause, c) {
			return fmt.Errorf("%w: %w", err, c)
		}
	}
	return err
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func isB64URL(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}
