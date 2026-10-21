// Package material loads the static TLS material a probe run is given on the command line: one
// certificate, its key and the zone trust anchors.
package material

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// Material is one static certificate with its key, and the trust anchors.
type Material struct {
	Cert    tls.Certificate
	Anchors *x509.CertPool
}

// Load reads the certificate, its key and the trust anchor files. The certificate file must
// hold the leaf first; every anchor file must hold at least one PEM certificate.
func Load(certFile, keyFile string, caFiles []string) (*Material, error) {
	cert, err := LoadCert(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	if len(caFiles) == 0 {
		return nil, errors.New("at least one trust anchor file is required (--ca)")
	}
	pool := x509.NewCertPool()
	for _, f := range caFiles {
		pem, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("trust anchors: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("trust anchors: %s holds no PEM certificate", f)
		}
	}
	return &Material{Cert: cert, Anchors: pool}, nil
}

// LoadCert reads one certificate and its key, and parses the leaf.
func LoadCert(certFile, keyFile string) (tls.Certificate, error) {
	if certFile == "" || keyFile == "" {
		return tls.Certificate{}, errors.New("a certificate and its key are required (--cert, --key)")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("certificate: %w", err)
	}
	if cert.Leaf == nil {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("certificate: %w", err)
		}
		cert.Leaf = leaf
	}
	return cert, nil
}

// Fingerprint is the hex SHA-256 of a certificate, as the attested channel names its peers.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// Identities lists the URI and DNS names a certificate carries.
func Identities(c *x509.Certificate) []string {
	var ids []string
	for _, u := range c.URIs {
		ids = append(ids, u.String())
	}
	return append(ids, c.DNSNames...)
}
