// Package statuslistfixture signs Token Status List tokens with a process key, for tests and
// fixtures.
package statuslistfixture

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/statuslist"
)

// Options describes the list to sign.
type Options struct {
	Key     *ecdsa.PrivateKey
	Kid     string
	Issuer  string
	Subject string // the URI the list is served at
	Bits    int    // 1, 2, 4 or 8
	Size    int    // number of entries
	// Set gives entries a value other than 0: index → value.
	Set       map[int]statuslist.Status
	IssuedAt  time.Time
	ExpiresAt time.Time     // optional
	TTL       time.Duration // optional
}

// Sign returns the compact status-list JWT.
func Sign(ctx context.Context, o Options) (string, error) {
	if o.Key == nil || o.Kid == "" || o.Issuer == "" || o.Subject == "" || o.Size <= 0 {
		return "", errors.New("statuslistfixture: options incomplete")
	}
	if o.Bits != 1 && o.Bits != 2 && o.Bits != 4 && o.Bits != 8 {
		return "", errors.New("statuslistfixture: bits must be 1, 2, 4 or 8")
	}
	perByte := 8 / o.Bits
	entries := make([]byte, (o.Size+perByte-1)/perByte)
	for idx, v := range o.Set {
		if idx < 0 || idx >= o.Size {
			return "", errors.New("statuslistfixture: index out of range")
		}
		if int(v) >= 1<<o.Bits {
			return "", errors.New("statuslistfixture: value does not fit the entry width")
		}
		entries[idx/perByte] |= byte(v) << (uint(idx%perByte) * uint(o.Bits))
	}
	var buf bytes.Buffer
	zw, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := zw.Write(entries); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	payload := map[string]any{
		"iss": o.Issuer, "sub": o.Subject, "iat": o.IssuedAt.Unix(),
		"status_list": map[string]any{"bits": o.Bits, "lst": jose.B64(buf.Bytes())},
	}
	if !o.ExpiresAt.IsZero() {
		payload["exp"] = o.ExpiresAt.Unix()
	}
	if o.TTL > 0 {
		payload["ttl"] = int64(o.TTL / time.Second)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return jose.Sign(ctx, jose.Header{Typ: statuslist.Typ, Kid: o.Kid}, raw, func(_ context.Context, in []byte) ([]byte, error) {
		digest := sha256.Sum256(in)
		r, s, err := ecdsa.Sign(rand.Reader, o.Key, digest[:])
		if err != nil {
			return nil, err
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig, nil
	})
}
