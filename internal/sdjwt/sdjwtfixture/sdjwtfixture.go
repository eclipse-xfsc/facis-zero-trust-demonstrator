// Package sdjwtfixture issues and presents SD-JWT VCs with process keys, for tests, fixtures and
// the fixture holder. It is never an issuer of record: it attests whatever it is asked to.
package sdjwtfixture

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt"
)

// Claim is one credential claim, in the order the issuer writes it.
type Claim struct {
	Name  string
	Value any
}

// IssueOptions describes the credential to issue.
type IssueOptions struct {
	IssuerKey *ecdsa.PrivateKey
	Kid       string
	Issuer    string
	VCT       string
	JTI       string // optional
	// Claims are the credential's claims; those named in Disclosable become selectively
	// disclosable (an _sd digest plus a disclosure), the rest are written in the clear.
	Claims      []Claim
	Disclosable []string
	Holder      *ecdsa.PublicKey
	Status      *sdjwt.StatusRef // optional
	IssuedAt    time.Time
	NotBefore   time.Time // optional
	ExpiresAt   time.Time // optional
	// Rand is the salt source; nil means crypto/rand.
	Rand io.Reader
}

// Issued is a credential as the issuer hands it to the holder: "<issuer JWT>~<disclosure>~...~".
type Issued struct {
	SDJWT       string
	Disclosures map[string]string // claim name → encoded disclosure
}

// Issue signs an SD-JWT VC. The returned string ends with a tilde and carries every disclosure;
// Present chooses which of them to reveal.
func Issue(ctx context.Context, o IssueOptions) (Issued, error) {
	if o.IssuerKey == nil || o.Holder == nil || o.Kid == "" || o.Issuer == "" || o.VCT == "" {
		return Issued{}, errors.New("sdjwtfixture: issue options incomplete")
	}
	random := o.Rand
	if random == nil {
		random = rand.Reader
	}
	disclosable := map[string]bool{}
	for _, name := range o.Disclosable {
		disclosable[name] = true
	}
	payload := map[string]any{"iss": o.Issuer, "vct": o.VCT, "cnf": map[string]any{"jwk": jose.PublicJWK(o.Holder)}, "_sd_alg": "sha-256"}
	if o.JTI != "" {
		payload["jti"] = o.JTI
	}
	if !o.IssuedAt.IsZero() {
		payload["iat"] = o.IssuedAt.Unix()
	}
	if !o.NotBefore.IsZero() {
		payload["nbf"] = o.NotBefore.Unix()
	}
	if !o.ExpiresAt.IsZero() {
		payload["exp"] = o.ExpiresAt.Unix()
	}
	if o.Status != nil {
		payload["status"] = map[string]any{"status_list": map[string]any{"uri": o.Status.URI, "idx": o.Status.Index}}
	}
	var digests []string
	disclosures := map[string]string{}
	var order []string
	for _, c := range o.Claims {
		if !disclosable[c.Name] {
			payload[c.Name] = c.Value
			continue
		}
		salt := make([]byte, 16)
		if _, err := io.ReadFull(random, salt); err != nil {
			return Issued{}, err
		}
		encoded, err := EncodeDisclosure(jose.B64(salt), c.Name, c.Value)
		if err != nil {
			return Issued{}, err
		}
		disclosures[c.Name] = encoded
		order = append(order, c.Name)
		digests = append(digests, Digest(encoded))
	}
	if len(digests) > 0 {
		payload["_sd"] = digests
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return Issued{}, err
	}
	jwt, err := jose.Sign(ctx, jose.Header{Typ: sdjwt.TypIssuer, Kid: o.Kid}, raw, signer(o.IssuerKey))
	if err != nil {
		return Issued{}, err
	}
	s := jwt + "~"
	for _, name := range order {
		s += disclosures[name] + "~"
	}
	return Issued{SDJWT: s, Disclosures: disclosures}, nil
}

// Present appends a key-binding JWT for nonce and audience to sdjwtWithDisclosures, which must end
// with a tilde and carry exactly the disclosures to reveal (see Select).
func Present(ctx context.Context, sdjwtWithDisclosures string, holderKey *ecdsa.PrivateKey, nonce, audience string, iat time.Time) (string, error) {
	if holderKey == nil || len(sdjwtWithDisclosures) == 0 || sdjwtWithDisclosures[len(sdjwtWithDisclosures)-1] != '~' {
		return "", errors.New("sdjwtfixture: presentation input must end with a tilde")
	}
	digest := sha256.Sum256([]byte(sdjwtWithDisclosures))
	raw, err := json.Marshal(map[string]any{"iat": iat.Unix(), "aud": audience, "nonce": nonce, "sd_hash": jose.B64(digest[:])})
	if err != nil {
		return "", err
	}
	kb, err := jose.Sign(ctx, jose.Header{Typ: sdjwt.TypKeyBinding}, raw, signer(holderKey))
	if err != nil {
		return "", err
	}
	return sdjwtWithDisclosures + kb, nil
}

// Select rebuilds "<issuer JWT>~<disclosure>~...~" from an issued credential with only the named
// claims disclosed, in the order given.
func Select(issued Issued, names ...string) (string, error) {
	jwt, _, _ := cut(issued.SDJWT, '~')
	s := jwt + "~"
	for _, name := range names {
		d, ok := issued.Disclosures[name]
		if !ok {
			return "", errors.New("sdjwtfixture: no disclosure for " + name)
		}
		s += d + "~"
	}
	return s, nil
}

// EncodeDisclosure is base64url(JSON [salt, name, value]).
func EncodeDisclosure(salt, name string, value any) (string, error) {
	raw, err := json.Marshal([]any{salt, name, value})
	if err != nil {
		return "", err
	}
	return jose.B64(raw), nil
}

// Digest is the _sd digest of an encoded disclosure.
func Digest(encoded string) string {
	d := sha256.Sum256([]byte(encoded))
	return jose.B64(d[:])
}

// SignES256 signs with a process key, R||S of 32 bytes each.
func SignES256(key *ecdsa.PrivateKey, in []byte) ([]byte, error) {
	digest := sha256.Sum256(in)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, nil
}

func signer(k *ecdsa.PrivateKey) jose.SignFunc {
	return func(_ context.Context, in []byte) ([]byte, error) { return SignES256(k, in) }
}

// Deterministic test keys, built from fixed scalars so that fixtures regenerate with the same
// public keys and no private key file is ever committed. They sign nothing of value.
var (
	issuerScalar = "6f2c3b9a1d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8"
	holderScalar = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809"
	otherScalar  = "9e8d7c6b5a49382716f5e4d3c2b1a0998e8d7c6b5a49382716f5e4d3c2b1a099"
)

// TestIssuerKey is the trusted fixture issuer's key.
func TestIssuerKey() *ecdsa.PrivateKey { return keyFromScalar(issuerScalar) }

// TestHolderKey is the fixture holder's key (the credential's cnf).
func TestHolderKey() *ecdsa.PrivateKey { return keyFromScalar(holderScalar) }

// TestOtherIssuerKey is a key no trust set lists: the untrusted issuer, or the wrong holder.
func TestOtherIssuerKey() *ecdsa.PrivateKey { return keyFromScalar(otherScalar) }

func keyFromScalar(h string) *ecdsa.PrivateKey {
	raw, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		panic(err)
	}
	return k
}

func cut(s string, sep byte) (before, after string, found bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}
