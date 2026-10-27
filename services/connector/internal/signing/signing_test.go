package signing

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
)

func TestLocal_SignsES256WithThumbprintKeyID(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	l, err := NewLocal(key)
	if err != nil {
		t.Fatal(err)
	}

	want, _ := jose.PublicJWK(&key.PublicKey).Thumbprint()
	if l.KeyID() != want {
		t.Errorf("KeyID = %q, want the RFC 7638 thumbprint %q", l.KeyID(), want)
	}

	input := []byte("header.payload")

	sig, err := l.Sign(t.Context(), input)
	if err != nil || len(sig) != 64 {
		t.Fatalf("Sign: %d bytes, %v", len(sig), err)
	}

	digest := sha256.Sum256(input)
	if !ecdsa.Verify(l.Public(), digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Error("signature does not verify")
	}
}

type ctxKey struct{}

// fakeTransit signs locally and records what it was asked.
type fakeTransit struct {
	key     *ecdsa.PrivateKey
	gotKey  transit.KeyVersion
	gotCtx  context.Context //nolint:containedctx // recorded for the assertion
	signing *Local
}

func (f *fakeTransit) Sign(ctx context.Context, key transit.KeyVersion, input []byte) ([]byte, error) {
	f.gotKey, f.gotCtx = key, ctx

	return f.signing.Sign(ctx, input)
}

func (f *fakeTransit) PublicKey(context.Context, transit.KeyVersion) (*ecdsa.PublicKey, error) {
	return &f.key.PublicKey, nil
}

func (f *fakeTransit) EnsureKey(context.Context, string) (transit.KeyVersion, error) {
	return transit.KeyVersion{}, nil
}

func TestTransit_DelegatesWithContextAndPinnedVersion(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	local, _ := NewLocal(key)
	fake := &fakeTransit{key: key, signing: local}
	version := transit.KeyVersion{Name: "connector", Version: 3}

	tr, err := NewTransit(t.Context(), fake, version)
	if err != nil {
		t.Fatal(err)
	}

	if tr.KeyID() != local.KeyID() || !tr.Public().Equal(&key.PublicKey) {
		t.Errorf("KeyID %q, want %q", tr.KeyID(), local.KeyID())
	}

	ctx := context.WithValue(t.Context(), ctxKey{}, "request")
	if _, err := tr.Sign(ctx, []byte("x.y")); err != nil {
		t.Fatal(err)
	}

	if fake.gotKey != version || fake.gotCtx.Value(ctxKey{}) != "request" {
		t.Errorf("transit asked with key %+v and ctx value %v", fake.gotKey, fake.gotCtx.Value(ctxKey{}))
	}
}
