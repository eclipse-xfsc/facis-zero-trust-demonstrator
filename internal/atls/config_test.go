package atls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// TestPrepareSetsParsedLeaf: CMC dereferences Certificates[i].Leaf when a TLS dial fails
// (finding N9), so the wrapper must hand CMC a certificate whose leaf is parsed.
func TestPrepareSetsParsedLeaf(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	cfg := Config{
		TLS:                  &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, RootCAs: pool},
		CmcdAddr:             "127.0.0.1:9955",
		ExpectedPeerIdentity: "spiffe://zone-b/gateway",
	}
	for _, r := range []role{roleClient, roleServer} {
		p, err := cfg.prepare(r)
		if err != nil {
			t.Fatal(err)
		}
		if p.base.Certificates[0].Leaf == nil {
			t.Fatal("certificate handed to CMC has no parsed leaf")
		}
		if p.base.MinVersion != tls.VersionTLS13 || !p.base.SessionTicketsDisabled {
			t.Fatal("TLS policy not applied")
		}
		if r == roleServer && p.base.ClientAuth != tls.RequireAndVerifyClientCert {
			t.Fatal("listener does not require client certificates")
		}
		if p.handshakeTimeout != DefaultHandshakeTimeout || p.lifetime != DefaultChannelLifetime ||
			p.maxConcurrent != DefaultMaxConcurrentHandshakes {
			t.Fatal("defaults not applied")
		}
	}
	if cfg.TLS.Certificates[0].Leaf != nil {
		t.Fatal("the caller's certificate was modified")
	}
}
