package if03

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"net/url"
	"unicode/utf8"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

// MaxIssuersFile bounds a trusted-issuers document.
const MaxIssuersFile = 1 << 20

// ParseIssuers reads {"<issuer URI>": {"keys": [<public P-256 JWK with kid>, ...]}}: a strict JSON
// object (no duplicate member at any depth), no other member, at least one issuer and one key each,
// every kid unique across all issuers. It is the trust-set format the connector and the verification
// service share; the token store reads a list of PEM public-key files of its own (docs/token-store.md),
// to be aligned when its configuration is next revised. Errors are fixed text and never repeat the
// document.
func ParseIssuers(b []byte) (Issuers, error) {
	if len(b) > MaxIssuersFile {
		return nil, errors.New("the document is larger than 1 MiB")
	}
	top, err := jose.ParseObject(b)
	if err != nil || len(top) == 0 {
		return nil, errors.New("not a JSON object of one or more issuers")
	}
	issuers := Issuers{}
	kids := map[string]bool{}
	for iss, raw := range top {
		if u, err := url.Parse(iss); err != nil || u.Scheme == "" {
			return nil, errors.New("an issuer is not an absolute URI")
		}
		entry, err := jose.ParseObject(raw)
		if err != nil || len(entry) != 1 || entry["keys"] == nil {
			return nil, errors.New(`an issuer is not an object with exactly the member "keys"`)
		}
		var jwks []json.RawMessage
		if err := json.Unmarshal(entry["keys"], &jwks); err != nil || len(jwks) == 0 {
			return nil, errors.New(`an issuer's "keys" is not a non-empty array`)
		}
		keys := map[string]*ecdsa.PublicKey{}
		for _, rawKey := range jwks {
			jwk, err := jose.ParseJWK(rawKey)
			if err != nil {
				return nil, errors.New("a key is not a public EC P-256 JWK (kty, crv, x, y, kid and nothing else)")
			}
			if jwk.Kid == "" || utf8.RuneCountInString(jwk.Kid) > MaxKid {
				return nil, errors.New("a key has no kid, or one longer than 128 characters")
			}
			if kids[jwk.Kid] {
				return nil, errors.New("a kid appears more than once")
			}
			kids[jwk.Kid] = true
			keys[jwk.Kid], _ = jwk.PublicKey() // ParseJWK already checked the point
		}
		issuers[iss] = keys
	}
	return issuers, nil
}

// Key returns the key kid belongs to and the issuer that owns it. A kid held by more than one
// issuer, by none, or longer than MaxKid yields ok=false: the caller must not use a key whose owner
// is ambiguous. Every kid lookup on the token path goes through here.
func (i Issuers) Key(kid string) (owner string, key *ecdsa.PublicKey, ok bool) {
	if kid == "" || utf8.RuneCountInString(kid) > MaxKid {
		return "", nil, false
	}
	for iss, keys := range i {
		if k, present := keys[kid]; present && k != nil {
			if owner != "" {
				return "", nil, false
			}
			owner, key = iss, k
		}
	}
	return owner, key, owner != ""
}
