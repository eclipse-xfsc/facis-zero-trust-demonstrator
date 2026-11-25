package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
)

func pemOf(t *testing.T, pub any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestDIDWeb(t *testing.T) {
	for location, want := range map[string][2]string{
		"trust.example.org":                 {"did:web:trust.example.org", "https://trust.example.org/.well-known/did.json"},
		"trust.example.org:8443":            {"did:web:trust.example.org%3A8443", "https://trust.example.org:8443/.well-known/did.json"},
		"tspa.example.org/ztd/release-keys": {"did:web:tspa.example.org:ztd:release-keys", "https://tspa.example.org/ztd/release-keys/did.json"},
		// The image-signing trust anchor the project lead fixed: a path next to TSPA, not its root DID.
		"tspa.facis.cloud/ztd/release-keys": {"did:web:tspa.facis.cloud:ztd:release-keys", "https://tspa.facis.cloud/ztd/release-keys/did.json"},
	} {
		did, url, err := didWeb(location)
		if err != nil || did != want[0] || url != want[1] {
			t.Errorf("%s: got %s %s %v, want %s %s", location, did, url, err, want[0], want[1])
		}
	}
	for _, bad := range []string{"", "https://trust.example.org", "Trust.Example.org", "trust.example.org/a b", "trust.example.org//x"} {
		if _, _, err := didWeb(bad); err == nil {
			t.Errorf("%q: accepted, want refused", bad)
		}
	}
}

// RFC 7638, section 3.1: the thumbprint of the example RSA key.
func TestThumbprintRFC7638(t *testing.T) {
	n := "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	raw, err := b64.DecodeString(n)
	if err != nil {
		t.Fatal(err)
	}
	k, err := toJWK(&rsa.PublicKey{N: new(big.Int).SetBytes(raw), E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	if got := thumbprint(k); got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("thumbprint %s", got)
	}
}

func TestDocumentDeterministicAndComplete(t *testing.T) {
	interim, err := os.ReadFile("../../docs/contracts/keys/interim-cosign.pub")
	if err != nil {
		t.Fatal(err)
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ed, _, _ := ed25519.GenerateKey(rand.Reader)
	keys := [][]byte{interim, pemOf(t, &ec.PublicKey), pemOf(t, ed)}
	a, url, err := document("trust.example.org", keys)
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := document("trust.example.org", [][]byte{keys[2], keys[0], keys[1]})
	if !bytes.Equal(a, b) {
		t.Fatal("the same keys in another order give other bytes")
	}
	if url != "https://trust.example.org/.well-known/did.json" {
		t.Fatalf("url %s", url)
	}
	var doc didDocument
	if err := json.Unmarshal(a, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.ID != "did:web:trust.example.org" || len(doc.VerificationMethod) != 3 || len(doc.AssertionMethod) != 3 {
		t.Fatalf("document %s", a)
	}
	for i, m := range doc.VerificationMethod {
		if m.Type != "JsonWebKey2020" || m.Controller != doc.ID || doc.AssertionMethod[i] != m.ID ||
			m.ID != doc.ID+"#"+thumbprint(m.PublicKeyJwk) {
			t.Errorf("method %+v", m)
		}
	}
	// The interim key is the cosign P-256 key: its coordinates are 32 bytes each.
	var p256 jwk
	for _, m := range doc.VerificationMethod {
		if m.PublicKeyJwk.Crv == "P-256" {
			p256 = m.PublicKeyJwk
		}
	}
	if x, _ := b64.DecodeString(p256.X); len(x) != 32 {
		t.Errorf("the interim key is not in the document as a P-256 JWK: %+v", p256)
	}
}

func TestDocumentRefusals(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := pemOf(t, &ec.PublicKey)
	der, _ := x509.MarshalPKCS8PrivateKey(ec)
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	for name, keys := range map[string][][]byte{
		"no key":        nil,
		"a private key": {private},
		"a key twice":   {pub, pub},
		"not PEM":       {[]byte("ssh-ed25519 AAAA")},
	} {
		if _, _, err := document("trust.example.org", keys); err == nil {
			t.Errorf("%s: accepted, want refused", name)
		} else if strings.Contains(err.Error(), "BEGIN") {
			t.Errorf("%s: the error repeats key material", name)
		}
	}
}
