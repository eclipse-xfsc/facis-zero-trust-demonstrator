package transit

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// These tests run against a real OpenBao dev server when TRANSIT_TEST_ADDR and TRANSIT_TEST_TOKEN
// are set (for example `bao server -dev`), and skip otherwise. They enable the transit mount if it
// is missing and use fresh key names and paths, so they can rerun against the same server.

func realClient(t *testing.T) (*Client, func(method, path, body string) int) {
	t.Helper()
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
	// 400 is "path is already in use".
	if s := raw(http.MethodPost, "/v1/sys/mounts/transit", `{"type":"transit"}`); s != 204 && s != 400 {
		t.Fatalf("enabling transit: status %d", s)
	}
	c, err := New(Config{Addr: addr, Token: staticToken(token)})
	if err != nil {
		t.Fatal(err)
	}
	return c, raw
}

func unique(prefix string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func verify(pub *ecdsa.PublicKey, input, sig []byte) bool {
	h := sha256.Sum256(input)
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, h[:], r, s)
}

func TestOpenBaoSigning(t *testing.T) {
	c, raw := realClient(t)
	ctx := context.Background()
	name := unique("p3-")

	v1, err := c.EnsureKey(ctx, name)
	if err != nil || v1 != (KeyVersion{Name: name, Version: 1}) {
		t.Fatalf("ensure: %+v %v", v1, err)
	}
	again, err := c.EnsureKey(ctx, name)
	if err != nil || again != v1 {
		t.Fatalf("ensure is not idempotent: %+v %v", again, err)
	}
	info, err := c.readKey(ctx, "test", name)
	if err != nil || info.Exportable || info.AllowPlaintextBackup || info.Type != "ecdsa-p256" {
		t.Fatalf("key settings: %+v %v", info, err)
	}
	// Non-exportable on the server's own word: export is refused.
	if s := raw(http.MethodGet, "/v1/transit/export/signing-key/"+name, ""); s < 400 {
		t.Fatalf("export answered %d", s)
	}

	input := []byte("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0")
	pub1, err := c.PublicKey(ctx, v1)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := c.Sign(ctx, v1, input)
	if err != nil || len(sig) != 64 || !verify(pub1, input, sig) {
		t.Fatalf("sign v1: %d bytes, %v", len(sig), err)
	}

	if s := raw(http.MethodPost, "/v1/transit/keys/"+name+"/rotate", ""); s != 200 && s != 204 {
		t.Fatalf("rotate: status %d", s)
	}
	if latest, err := c.EnsureKey(ctx, name); err != nil || latest.Version != 2 {
		t.Fatalf("after rotate: %+v %v", latest, err)
	}
	// The pinned old version still signs, and only the old public key verifies it.
	sig, err = c.Sign(ctx, v1, input)
	if err != nil || !verify(pub1, input, sig) {
		t.Fatalf("sign pinned v1 after rotate: %v", err)
	}
	pub2, err := c.PublicKey(ctx, KeyVersion{Name: name, Version: 2})
	if err != nil || pub2.Equal(pub1) || verify(pub2, input, sig) {
		t.Fatalf("v2 must be a different key: %v", err)
	}
	sig2, err := c.Sign(ctx, KeyVersion{Name: name, Version: 2}, input)
	if err != nil || !verify(pub2, input, sig2) {
		t.Fatalf("sign v2: %v", err)
	}
	if _, err := c.PublicKey(ctx, KeyVersion{Name: name, Version: 3}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing version: %v", err)
	}
	if _, err := c.Sign(ctx, KeyVersion{Name: name, Version: 3}, input); err == nil {
		t.Fatal("signing with a version that does not exist succeeded")
	}
}

func TestOpenBaoSecrets(t *testing.T) {
	c, _ := realClient(t)
	ctx := context.Background()
	dir := unique("p3-")
	a, b := dir+"/a", dir+"/sub/b"

	if err := c.Create(ctx, a, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(ctx, a, []byte("two")); !errors.Is(err, ErrExists) {
		t.Fatalf("second create: %v", err)
	}
	if v, err := c.Read(ctx, a); err != nil || string(v) != "one" {
		t.Fatalf("read: %q %v", v, err)
	}
	if err := c.Create(ctx, b, []byte{0, 1, 2}); err != nil {
		t.Fatal(err)
	}
	keys, err := c.List(ctx, dir)
	slices.Sort(keys)
	if err != nil || !slices.Equal(keys, []string{"a", "sub/"}) {
		t.Fatalf("list: %v %v", keys, err)
	}
	if ct, err := c.CreatedTime(ctx, a); err != nil || time.Since(ct) > time.Minute || time.Since(ct) < -time.Minute {
		t.Fatalf("created time: %v %v", ct, err)
	}
	if _, err := c.CreatedTime(ctx, dir+"/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("created time of missing: %v", err)
	}
	if _, err := c.Read(ctx, dir+"/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read missing: %v", err)
	}
	if err := c.Delete(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(ctx, a); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read after delete: %v", err)
	}
	// All versions are gone, so the path can be created afresh.
	if err := c.Create(ctx, a, []byte("three")); err != nil {
		t.Fatalf("create after delete: %v", err)
	}
	if keys, err := c.List(ctx, unique("p3-none-")); err != nil || len(keys) != 0 {
		t.Fatalf("list empty: %v %v", keys, err)
	}
	_ = c.Delete(ctx, a)
	_ = c.Delete(ctx, b)
}
