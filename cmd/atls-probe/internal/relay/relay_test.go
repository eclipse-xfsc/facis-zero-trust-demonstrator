package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/atls-probe/internal/record"
)

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newCA(t *testing.T) *ca {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay test CA"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &ca{cert: cert, key: key, pool: pool}
}

func (c *ca) issue(t *testing.T, identity string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(identity)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: identity},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:        []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func exporter(t *testing.T, c *tls.Conn) string {
	t.Helper()
	cs := c.ConnectionState()
	b, err := cs.ExportKeyingMaterial(bindingLabel, nil, bindingLen)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The relay copies bytes between two TLS sessions of its own: the ends talk to each other, and
// each sits in a TLS session with another channel binding than its peer's.
func TestRelayForwardsBetweenTwoSessions(t *testing.T) {
	zone := newCA(t)
	serverCert := zone.issue(t, "spiffe://a/gateway")
	clientCert := zone.issue(t, "spiffe://b/gateway")

	// The real listener: plain TLS, echoes one message in upper case.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: zone.pool,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	serverBinding := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 5)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		cs := c.(*tls.Conn).ConnectionState()
		b, _ := cs.ExportKeyingMaterial(bindingLabel, nil, bindingLen)
		serverBinding <- string(b)
		_, _ = c.Write([]byte("WORLD"))
	}()

	path := filepath.Join(t.TempDir(), "relay.json")
	rec := record.New(path, "relay", "man-in-the-middle", record.Environment{})
	ready := make(chan net.Addr, 1)
	type result struct {
		forwarded bool
		err       error
	}
	done := make(chan result, 1)
	go func() {
		ok, err := Run(context.Background(), Config{
			Listen: "127.0.0.1:0", Upstream: ln.Addr().String(),
			DownstreamCert: zone.issue(t, "spiffe://a/gateway"),
			UpstreamCert:   zone.issue(t, "spiffe://b/gateway"),
			Anchors:        zone.pool,
			AcceptTimeout:  10 * time.Second, HandshakeTimeout: 10 * time.Second,
			Ready: func(a net.Addr) { ready <- a },
		}, rec)
		done <- result{ok, err}
	}()

	c, err := tls.Dial("tcp", (<-ready).String(), &tls.Config{
		Certificates: []tls.Certificate{clientCert}, MinVersion: tls.VersionTLS13,
		RootCAs: zone.pool, ServerName: "relay", InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "WORLD" {
		t.Fatalf("answer through the relay: %q, %v", buf, err)
	}
	clientBinding := exporter(t, c)
	_ = c.Close()

	r := <-done
	if r.err != nil || !r.forwarded {
		t.Fatalf("relay: forwarded %v, err %v", r.forwarded, r.err)
	}
	if clientBinding == <-serverBinding {
		t.Fatal("the two ends share a channel binding: the relay did not terminate TLS")
	}
	if err := rec.Save(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got record.Record
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	rl := got.Relay
	if got.Outcome != record.OutcomeForwarded || !rl.BindingsDiffer ||
		rl.BytesDialerToListener != 5 || rl.BytesListenerToDialer != 5 {
		t.Fatalf("record: outcome %q, relay %+v", got.Outcome, rl)
	}
	if rl.Downstream.PresentedIdentities[0] != "spiffe://a/gateway" || rl.Upstream.PresentedIdentities[0] != "spiffe://b/gateway" ||
		rl.Downstream.PeerIdentities[0] != "spiffe://b/gateway" || rl.Upstream.PeerIdentities[0] != "spiffe://a/gateway" {
		t.Fatalf("identities: %+v / %+v", rl.Downstream, rl.Upstream)
	}
}

// Without a dialing end the relay gives up after its accept timeout and forwards nothing.
func TestRelayWithoutDialer(t *testing.T) {
	zone := newCA(t)
	rec := record.New("", "relay", "man-in-the-middle", record.Environment{})
	ok, err := Run(context.Background(), Config{
		Listen: "127.0.0.1:0", Upstream: "127.0.0.1:1",
		DownstreamCert: zone.issue(t, "spiffe://a/gateway"), UpstreamCert: zone.issue(t, "spiffe://b/gateway"),
		Anchors: zone.pool, AcceptTimeout: 50 * time.Millisecond, HandshakeTimeout: time.Second,
	}, rec)
	if ok || err != nil {
		t.Fatalf("forwarded %v, err %v", ok, err)
	}
}
