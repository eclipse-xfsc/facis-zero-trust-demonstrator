// Package keys is the token store's signing-key lifecycle on top of transit: the zone's key is
// created non-exportable in OpenBao, and the store only ever holds its public half, named by an
// RFC 7638 thumbprint.
package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
)

// ErrMismatch is returned by Check when the referenced key is not the one the thumbprint names.
var ErrMismatch = errors.New("keys: key reference does not match the thumbprint")

// Lister reads a key's latest version and signing floor without creating it.
type Lister interface {
	transit.Signer
	LatestKey(ctx context.Context, name string) (transit.KeyVersion, error)
	KeyStatus(ctx context.Context, name string) (latest transit.KeyVersion, floor int, err error)
}

// ReadOnly is a Signer that never creates a key: EnsureKey reads the latest version instead. The
// service and the acquire command sign through it, so a deleted or missing key is reported, never
// replaced; only token-store keys ensure|rotate hold a client that may create or rotate.
type ReadOnly struct{ Lister }

// EnsureKey reads the latest version; a missing key is transit.ErrNotFound.
func (r ReadOnly) EnsureKey(ctx context.Context, name string) (transit.KeyVersion, error) {
	return r.LatestKey(ctx, name)
}

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

// Thumbprint is the RFC 7638 SHA-256 thumbprint of a P-256 public key, base64url without padding:
// the one encoding, internal/jose's, that rows, proofs and tokens are bound with.
func Thumbprint(pub *ecdsa.PublicKey) (string, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return "", errors.New("keys: not a P-256 public key")
	}
	return jose.PublicJWK(pub).Thumbprint()
}
