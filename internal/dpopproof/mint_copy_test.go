package dpopproof

// mintLikeDpoptest is services/connector/internal/dpoptest.Mint (and Key.Thumbprint), copied because
// Go's internal-package rule keeps internal/dpopproof from importing it. It signs with the standard
// library only, so a proof it mints exercises Verify from the outside. Keep it in step with the original.

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

type minterProof struct {
	Method, URL string
	IssuedAt    time.Time
	ID, Nonce   string
	AccessToken string
	ATH         string
}

func minterJWK(k *ecdsa.PrivateKey) map[string]string {
	point, err := k.PublicKey.Bytes()
	if err != nil || len(point) != 65 {
		panic("unexpected public key encoding")
	}
	return map[string]string{"kty": "EC", "crv": "P-256", "x": mb64(point[1:33]), "y": mb64(point[33:65])}
}

func minterThumbprint(k *ecdsa.PrivateKey) string {
	jwk := minterJWK(k)
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, jwk["crv"], jwk["kty"], jwk["x"], jwk["y"])
	digest := sha256.Sum256([]byte(canonical))
	return mb64(digest[:])
}

func mintLikeDpoptest(t testing.TB, key *ecdsa.PrivateKey, proof minterProof) string {
	t.Helper()
	if proof.IssuedAt.IsZero() {
		proof.IssuedAt = time.Now()
	}
	if proof.ID == "" {
		raw := make([]byte, 16)
		_, _ = rand.Read(raw)
		proof.ID = mb64(raw)
	}
	claims := map[string]any{"jti": proof.ID, "htm": proof.Method, "htu": proof.URL, "iat": proof.IssuedAt.Unix()}
	if proof.Nonce != "" {
		claims["nonce"] = proof.Nonce
	}
	switch {
	case proof.ATH != "":
		claims["ath"] = proof.ATH
	case proof.AccessToken != "":
		d := sha256.Sum256([]byte(proof.AccessToken))
		claims["ath"] = mb64(d[:])
	}
	header := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": minterJWK(key)}
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	signingInput := mb64(h) + "." + mb64(c)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	return signingInput + "." + mb64(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

func mb64(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }
