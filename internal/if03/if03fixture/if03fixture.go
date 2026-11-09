// Package if03fixture is a fixture IF-03 outcome signer, for tests and the demo. It is not a verifier:
// it attests whatever it is asked to, so it is never a deployment's outcome source.
package if03fixture

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

// Fixture is an OutcomeSource that signs a verified IF-03 outcome for every challenge with a
// configured key, with a new outcome_id per call.
type Fixture struct {
	Issuer   string
	Kid      string
	Key      *ecdsa.PrivateKey
	Claims   if03.Claims
	Validity time.Duration // 60 s to 120 s; zero means 90 s
	Now      func() time.Time
}

var _ connectorclient.OutcomeSource = Fixture{}

func (f Fixture) Outcome(ctx context.Context, ch connectorclient.Challenge) (string, error) {
	validity := f.Validity
	if validity == 0 {
		validity = 90 * time.Second
	}
	if validity < 60*time.Second || validity > 120*time.Second || f.Key == nil {
		return "", errors.New("if03fixture: fixture misconfigured")
	}
	now := time.Now
	if f.Now != nil {
		now = f.Now
	}
	at := now().UTC().Truncate(time.Second)
	payload, err := json.Marshal(map[string]any{
		"iss": f.Issuer, "outcome_id": NewUUID(), "client_id": ch.ClientID, "challenge": ch.Value,
		"audience": ch.Audience, "claims": f.Claims, "status": "verified",
		"verified_at": at.Format(time.RFC3339), "expires_at": at.Add(validity).Format(time.RFC3339),
	})
	if err != nil {
		return "", err
	}
	return jose.Sign(ctx, jose.Header{Typ: if03.Typ, Kid: f.Kid}, payload, func(_ context.Context, in []byte) ([]byte, error) {
		return SignES256(f.Key, in)
	})
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

// NewUUID is a random (version 4) UUID.
func NewUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// ReadPrivateKey reads a P-256 private key from a PEM file, "EC PRIVATE KEY" or "PRIVATE KEY". Its
// errors never repeat the file's content.
func ReadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(raw)
	if b == nil || (b.Type != "EC PRIVATE KEY" && b.Type != "PRIVATE KEY") {
		return nil, errors.New("not a PEM block of the expected type")
	}
	if k, err := x509.ParseECPrivateKey(b.Bytes); err == nil && k.Curve == elliptic.P256() {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	ec, ok := k.(*ecdsa.PrivateKey)
	if err != nil || !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("not a P-256 private key")
	}
	return ec, nil
}
