package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// An unreachable cmcd is "no report" (exit 3), not a rejected report (exit 2).
func TestCheckWithoutCmcdExitsThree(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	err = check([]string{"--zone", "../../deployment/attestation/zone-a.json", "--cmcd", addr, "--ca", ca, "--timeout", "2s"})
	if code := exitCode(err); code != 3 {
		t.Fatalf("exit %d for %v", code, err)
	}
	if exitCode(checkFailed{errors.New("rejected")}) != 2 || exitCode(errors.New("usage")) != 1 || exitCode(nil) != 0 {
		t.Fatal("exit codes")
	}
}
