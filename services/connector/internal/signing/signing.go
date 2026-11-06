// Package signing provides the access-token signers the Connector's OAuth2 provider uses
// (oauth2provider.TokenSigner): Transit over OpenBao transit, and Local over an in-process key for
// tests.
package signing

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

// Transit signs with one pinned version of an OpenBao transit key. The private key never enters the
// process. Build it with NewTransit.
type Transit struct {
	Signer transit.Signer
	Key    transit.KeyVersion

	public *ecdsa.PublicKey
	kid    string
}

var (
	_ oauth2provider.TokenSigner = (*Transit)(nil)
	_ oauth2provider.TokenSigner = (*Local)(nil)
)

// NewTransit reads the public half of key once and derives the key id from it.
func NewTransit(ctx context.Context, signer transit.Signer, key transit.KeyVersion) (*Transit, error) {
	if signer == nil {
		return nil, errors.New("signing: no transit signer")
	}

	public, err := signer.PublicKey(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("signing: reading %s: %w", key.Ref(), err)
	}

	kid, err := keyID(public)
	if err != nil {
		return nil, err
	}

	return &Transit{Signer: signer, Key: key, public: public, kid: kid}, nil
}

// KeyID is the RFC 7638 thumbprint of the public key.
func (t *Transit) KeyID() string { return t.kid }

func (t *Transit) Public() *ecdsa.PublicKey { return t.public }

// Sign has transit sign the JWS signing input with the pinned key version.
func (t *Transit) Sign(ctx context.Context, signingInput []byte) ([]byte, error) {
	return t.Signer.Sign(ctx, t.Key, signingInput)
}

// Local signs with a P-256 key held in process memory. It is for tests only: a deployment signs
// through Transit, so that no private key is ever in the Connector's memory.
type Local struct {
	key *ecdsa.PrivateKey
	kid string
}

// NewLocal returns a Local signer over key. Test use only.
func NewLocal(key *ecdsa.PrivateKey) (*Local, error) {
	if key == nil {
		return nil, errors.New("signing: no key")
	}

	kid, err := keyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	return &Local{key: key, kid: kid}, nil
}

// KeyID is the RFC 7638 thumbprint of the public key.
func (l *Local) KeyID() string { return l.kid }

func (l *Local) Public() *ecdsa.PublicKey { return &l.key.PublicKey }

// Sign returns the ES256 signature of signingInput as R||S.
func (l *Local) Sign(ctx context.Context, signingInput []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	digest := sha256.Sum256(signingInput)

	r, s, err := ecdsa.Sign(rand.Reader, l.key, digest[:])
	if err != nil {
		return nil, err
	}

	return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...), nil
}

func keyID(public *ecdsa.PublicKey) (string, error) {
	kid, err := jose.PublicJWK(public).Thumbprint()
	if err != nil {
		return "", fmt.Errorf("signing: key is not ECDSA P-256: %w", err)
	}

	return kid, nil
}
