package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
)

// vectorPEM is a public key OpenBao 2.7.0 returned for an ecdsa-p256 transit key; vectorJKT is its
// thumbprint computed independently with openssl (DER tail as x||y, the canonical JSON, sha256).
const (
	vectorPEM = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsk8dmxP0Dpa9ye1xIHR+20cMMD5l\nKg8S4uDPfypxoHL/MWwiU53SsS18OOwaDzhZXworho4EBAEkT1ww3CqUkw==\n-----END PUBLIC KEY-----\n"
	vectorJKT = "WSQRbt4UZF9jzEq8IzayrICR45q9Y0Fz-0jKLSKSTRU"
)

func vectorKey(t *testing.T) *ecdsa.PublicKey {
	block, _ := pem.Decode([]byte(vectorPEM))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return pub.(*ecdsa.PublicKey)
}

func TestThumbprintVector(t *testing.T) {
	if got, err := Thumbprint(vectorKey(t)); err != nil || got != vectorJKT {
		t.Fatalf("got %q, %v", got, err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := Thumbprint(&p384.PublicKey); err == nil {
		t.Fatal("P-384 accepted")
	}
	if _, err := Thumbprint(nil); err == nil {
		t.Fatal("nil accepted")
	}
}

// fakeSigner serves public keys by version; only PublicKey and EnsureKey are used by keys.
type fakeSigner struct {
	transit.Signer
	pubs map[transit.KeyVersion]*ecdsa.PublicKey
}

func (f fakeSigner) PublicKey(_ context.Context, k transit.KeyVersion) (*ecdsa.PublicKey, error) {
	if p, ok := f.pubs[k]; ok {
		return p, nil
	}
	return nil, transit.ErrNotFound
}

func (f fakeSigner) EnsureKey(_ context.Context, name string) (transit.KeyVersion, error) {
	return transit.KeyVersion{Name: name, Version: 1}, nil
}

func TestCheckUnit(t *testing.T) {
	v1 := transit.KeyVersion{Name: "zone", Version: 1}
	k := Keys{Signer: fakeSigner{pubs: map[transit.KeyVersion]*ecdsa.PublicKey{v1: vectorKey(t)}}, Name: "zone"}
	ctx := context.Background()

	kv, jkt, err := k.Ensure(ctx)
	if err != nil || kv != v1 || jkt != vectorJKT {
		t.Fatalf("ensure: %+v %q %v", kv, jkt, err)
	}
	if err := k.Check(ctx, v1.Ref(), vectorJKT); err != nil {
		t.Fatalf("match: %v", err)
	}
	if err := k.Check(ctx, v1.Ref(), "other"); !errors.Is(err, ErrMismatch) {
		t.Fatalf("wrong thumbprint: %v", err)
	}
	if err := k.Check(ctx, "transit:other:v1", vectorJKT); !errors.Is(err, ErrMismatch) {
		t.Fatalf("other key: %v", err)
	}
	if err := k.Check(ctx, "transit:zone:v2", vectorJKT); !errors.Is(err, transit.ErrNotFound) {
		t.Fatalf("missing version: %v", err)
	}
	if err := k.Check(ctx, "zone:1", vectorJKT); err == nil {
		t.Fatal("malformed ref accepted")
	}
}

// TestCheckOpenBao runs against a real OpenBao dev server when TRANSIT_TEST_ADDR and
// TRANSIT_TEST_TOKEN are set, and skips otherwise.
func TestCheckOpenBao(t *testing.T) {
	addr, token := os.Getenv("TRANSIT_TEST_ADDR"), os.Getenv("TRANSIT_TEST_TOKEN")
	if addr == "" || token == "" {
		t.Skip("TRANSIT_TEST_ADDR and TRANSIT_TEST_TOKEN not set")
	}
	raw := func(method, path, body string) int {
		req, _ := http.NewRequest(method, strings.TrimSuffix(addr, "/")+path, strings.NewReader(body))
		req.Header.Set("X-Vault-Token", token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: request failed", method, path)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if s := raw(http.MethodPost, "/v1/sys/mounts/transit", `{"type":"transit"}`); s != 204 && s != 400 {
		t.Fatalf("enabling transit: status %d", s)
	}
	c, err := transit.New(transit.Config{Addr: addr, Token: func(context.Context) (string, error) { return token, nil }})
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	k := Keys{Signer: c, Name: "p3-keys-" + hex.EncodeToString(b)}
	ctx := context.Background()

	v1, jkt1, err := k.Ensure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Check(ctx, v1.Ref(), jkt1); err != nil {
		t.Fatalf("match: %v", err)
	}
	if s := raw(http.MethodPost, "/v1/transit/keys/"+k.Name+"/rotate", ""); s != 200 && s != 204 {
		t.Fatalf("rotate: status %d", s)
	}
	v2, jkt2, err := k.Ensure(ctx)
	if err != nil || v2.Version != 2 || jkt2 == jkt1 {
		t.Fatalf("after rotate: %+v %v", v2, err)
	}
	// The stored v1 reference still checks against its own thumbprint, and not against v2's.
	if err := k.Check(ctx, v1.Ref(), jkt1); err != nil {
		t.Fatalf("v1 after rotate: %v", err)
	}
	if err := k.Check(ctx, v1.Ref(), jkt2); !errors.Is(err, ErrMismatch) {
		t.Fatalf("v1 against v2's thumbprint: %v", err)
	}
	if err := k.Check(ctx, "transit:"+k.Name+":v9", jkt1); !errors.Is(err, transit.ErrNotFound) {
		t.Fatalf("missing version: %v", err)
	}
}
