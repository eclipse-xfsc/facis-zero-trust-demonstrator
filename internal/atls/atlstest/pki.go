// Package atlstest provides test fixtures for package atls: a throwaway zone PKI, per-zone
// attester material (sw-driver evidence with signed metadata), the in-process CMC backend and an
// in-process stand-in for a zone's cmcd.
//
// It is for tests only. Every constructor panics outside a test binary, and a depguard rule
// refuses imports of this package from non-test files.
//
// Two tests of this package do nothing unless asked through the environment, and exist for the
// proofs that run the channel against real cmcd processes (scripts/atls-probe): TestWriteFixtures
// writes two zones' material to the directory ATLS_FIXTURE_DIR names, and TestCmcdReports checks
// the cmcd processes listed in ATLS_FIXTURE_CMCD_CHECK.
package atlstest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mustTest() {
	if !testing.Testing() {
		panic("atlstest: test-only package used outside a test binary")
	}
}

// PKI is a throwaway zone certificate authority.
type PKI struct {
	CA   *x509.Certificate
	Pool *x509.CertPool
	key  *ecdsa.PrivateKey
	// CAFile is the CA certificate in PEM, as CMC's root-CA configuration expects.
	CAFile string
	// swStorage is the sw driver storage shared by all zones of this PKI (see NewZone).
	swStorage string
}

// NewPKI creates a CA valid for one hour.
func NewPKI(t testing.TB) *PKI {
	mustTest()
	t.Helper()
	return newPKI(t, "atlstest zone CA")
}

// newPKI creates a CA named commonName, valid for one hour.
func newPKI(t testing.TB, commonName string) *PKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("atlstest: CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("atlstest: CA cert: %v", err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("atlstest: parse CA: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	file := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(file, certPEM(der), 0o600); err != nil {
		t.Fatalf("atlstest: write CA: %v", err)
	}
	return &PKI{CA: ca, Pool: pool, key: key, CAFile: file, swStorage: filepath.Join(t.TempDir(), "sw")}
}

// CertOption adjusts an issued certificate.
type CertOption func(*certOptions)

type certOptions struct {
	key       crypto.Signer
	notBefore time.Time
	notAfter  time.Time
}

// PEM encodings of a certificate and of a private key (PKCS #8), as files on disk hold them.
func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func keyPEM(key crypto.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// WithKey issues the certificate for key instead of a fresh P-256 key.
func WithKey(key crypto.Signer) CertOption { return func(o *certOptions) { o.key = key } }

// WithValidity sets the certificate's validity window.
func WithValidity(notBefore, notAfter time.Time) CertOption {
	return func(o *certOptions) { o.notBefore, o.notAfter = notBefore, notAfter }
}

// Issue returns a TLS certificate for identity, which becomes a URI SAN when it contains "://"
// and a DNS SAN otherwise. The certificate also carries "localhost" and 127.0.0.1 and is valid
// for client and server authentication.
func (p *PKI) Issue(t testing.TB, identity string, opts ...CertOption) tls.Certificate {
	mustTest()
	t.Helper()
	o := certOptions{notBefore: time.Now().Add(-time.Minute), notAfter: time.Now().Add(time.Hour)}
	for _, opt := range opts {
		opt(&o)
	}
	if o.key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("atlstest: leaf key: %v", err)
		}
		o.key = k
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("atlstest: serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: identity},
		NotBefore:    o.notBefore,
		NotAfter:     o.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	if u, err := url.Parse(identity); err == nil && u.Scheme != "" && u.Host != "" {
		tmpl.URIs = []*url.URL{u}
	} else {
		tmpl.DNSNames = append(tmpl.DNSNames, identity)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.CA, o.key.Public(), p.key)
	if err != nil {
		t.Fatalf("atlstest: leaf cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("atlstest: parse leaf: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: o.key, Leaf: leaf}
}

// signer issues a metadata-signing certificate and key.
func (p *PKI) signer(t testing.TB, name string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("atlstest: signer key: %v", err)
	}
	c := p.Issue(t, name, WithKey(key))
	return c.Leaf, key
}
