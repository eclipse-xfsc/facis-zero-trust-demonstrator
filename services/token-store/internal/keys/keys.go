// Package keys is the token store's signing-key lifecycle on top of transit: the zone's key is
// created non-exportable in OpenBao, and the store only ever holds its public half, named by an
// RFC 7638 thumbprint.
package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
)

// ErrMismatch is returned by Check when the referenced key is not the one the thumbprint names.
var ErrMismatch = errors.New("keys: key reference does not match the thumbprint")

// Keys manages the zone's signing key, Name, through Signer.
type Keys struct {
	Signer transit.Signer
	Name   string
}

// Ensure creates the zone's key if missing and returns its latest version with that version's
// public key thumbprint.
func (k Keys) Ensure(ctx context.Context) (transit.KeyVersion, string, error) {
	kv, err := k.Signer.EnsureKey(ctx, k.Name)
	if err != nil {
		return transit.KeyVersion{}, "", err
	}
	jkt, err := k.thumbprint(ctx, kv)
	if err != nil {
		return transit.KeyVersion{}, "", err
	}
	return kv, jkt, nil
}

// Check is the readiness check of a stored key reference: ref must name a version of the zone's
// key, and that version's public key must have the thumbprint wantJKT.
func (k Keys) Check(ctx context.Context, ref string, wantJKT string) error {
	kv, err := transit.ParseRef(ref)
	if err != nil {
		return err
	}
	if kv.Name != k.Name {
		return fmt.Errorf("keys: reference names another key: %w", ErrMismatch)
	}
	jkt, err := k.thumbprint(ctx, kv)
	if err != nil {
		return err
	}
	if jkt != wantJKT {
		return ErrMismatch
	}
	return nil
}

func (k Keys) thumbprint(ctx context.Context, kv transit.KeyVersion) (string, error) {
	pub, err := k.Signer.PublicKey(ctx, kv)
	if err != nil {
		return "", err
	}
	return Thumbprint(pub)
}

// Thumbprint is the RFC 7638 SHA-256 thumbprint of a P-256 public key, base64url without padding.
//
// A local copy until internal/jose is implemented; swap for jose.PublicJWK(pub).Thumbprint() then.
func Thumbprint(pub *ecdsa.PublicKey) (string, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return "", errors.New("keys: not a P-256 public key")
	}
	b, err := pub.Bytes() // 0x04 || X || Y, each 32 bytes for P-256
	if err != nil || len(b) != 65 {
		return "", errors.New("keys: not a P-256 public key")
	}
	enc := base64.RawURLEncoding.EncodeToString
	// Members in lexicographic order, no whitespace, as RFC 7638 section 3 requires.
	canon := `{"crv":"P-256","kty":"EC","x":"` + enc(b[1:33]) + `","y":"` + enc(b[33:]) + `"}`
	sum := sha256.Sum256([]byte(canon))
	return enc(sum[:]), nil
}
