package dpopproof

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

// ProcessKey is a proof key generated and held in this process, for a client that is one process:
// the Participant, the registration command, a test's registrar. It is never persisted, so a
// restart is a new key and the tokens bound to the old one die with it.
type ProcessKey struct{ k *ecdsa.PrivateKey }

// NewProcessKey generates a fresh P-256 key.
func NewProcessKey() (ProcessKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ProcessKey{}, errors.New("dpop: generate key")
	}
	return ProcessKey{k: k}, nil
}

// JWK is the public key as a JWK.
func (p ProcessKey) JWK() jose.JWK { return jose.PublicJWK(&p.k.PublicKey) }

// Thumbprint is the key's RFC 7638 thumbprint, the jkt a token is bound to.
func (p ProcessKey) Thumbprint() (string, error) { return p.JWK().Thumbprint() }

// Sign signs the signing input with ES256: the raw r||s signature over its SHA-256.
func (p ProcessKey) Sign(_ context.Context, signingInput []byte) ([]byte, error) {
	digest := sha256.Sum256(signingInput)
	r, s, err := ecdsa.Sign(rand.Reader, p.k, digest[:])
	if err != nil {
		return nil, errors.New("dpop: sign")
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, nil
}
