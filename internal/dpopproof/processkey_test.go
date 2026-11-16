package dpopproof

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"math/big"
	"testing"
)

// A process key signs ES256 signatures its own public JWK verifies, and two keys differ.
func TestProcessKeySignsWhatItsJWKVerifies(t *testing.T) {
	key, err := NewProcessKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.JWK().PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("header.payload")
	sig, err := key.Sign(context.Background(), input)
	if err != nil || len(sig) != 64 {
		t.Fatalf("signature: %d bytes, %v", len(sig), err)
	}
	digest := sha256.Sum256(input)
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Error("the signature does not verify against the key's JWK")
	}
	if ecdsa.Verify(pub, sha256.New().Sum([]byte("other")), r, s) {
		t.Error("the signature verifies another input")
	}
	other, _ := NewProcessKey()
	a, errA := key.Thumbprint()
	b, errB := other.Thumbprint()
	if errA != nil || errB != nil || a == "" || a == b {
		t.Errorf("thumbprints %q %q, %v %v", a, b, errA, errB)
	}
}
