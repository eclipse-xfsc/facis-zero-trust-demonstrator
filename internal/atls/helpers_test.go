package atls_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/Fraunhofer-AISEC/cmc/attestedtls"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls/atlstest"
)

func TestMain(m *testing.M) {
	// CMC logs every handshake step at info and every refusal at warn; keep test output readable.
	logrus.SetLevel(logrus.ErrorLevel)
	os.Exit(m.Run())
}

// fixture is two zones of one PKI: a dials, b listens.
type fixture struct {
	pki  *atlstest.PKI
	a, b *atlstest.Zone
}

func newFixture(t *testing.T, aOpts ...atlstest.ZoneOption) *fixture {
	t.Helper()
	pki := atlstest.NewPKI(t)
	return &fixture{
		pki: pki,
		a:   atlstest.NewZone(t, pki, "zone-a", aOpts...),
		b:   atlstest.NewZone(t, pki, "zone-b"),
	}
}

// skipLibAPIUnderRace skips tests that run both ends through CMC's in-process backend under the
// race detector: CMC's libapi re-initialises its process-global drivers on every call, which the
// race detector reports inside CMC (design.md, finding N4). The gRPC path has no such race.
func skipLibAPIUnderRace(t *testing.T) {
	t.Helper()
	if raceEnabled {
		t.Skip("CMC libapi races on its process-global drivers (finding N4); covered over gRPC")
	}
}

type accepted struct {
	conn *atls.Conn
	err  error
}

func listen(t *testing.T, cfg atls.Config) *atls.Listener {
	t.Helper()
	ln, err := atls.Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// acceptOne returns the outcome of the listener's next Accept.
func acceptOne(ln *atls.Listener, timeout time.Duration) <-chan accepted {
	ch := make(chan accepted, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		c, err := ln.Accept(ctx)
		ch <- accepted{c, err}
	}()
	return ch
}

func dial(t *testing.T, addr string, cfg atls.Config) (*atls.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return atls.Dial(ctx, addr, cfg)
}

// pair establishes one channel and returns both ends.
func pair(t *testing.T, server, client atls.Config) (cli, srv *atls.Conn) {
	t.Helper()
	ln := listen(t, server)
	acc := acceptOne(ln, 20*time.Second)
	c, err := dial(t, ln.Addr().String(), client)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	a := <-acc
	if a.err != nil {
		t.Fatalf("accept: %v", a.err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = a.conn.Close() })
	return c, a.conn
}

// Fake peers speak the attested-TLS wire protocol of CMC v0.9.15 by hand: 4-byte big-endian
// length, then a JSON message (attestedtls.Write/Read and its message types).

const atlsVersion = "1.2.0"

func sendMsg(t *testing.T, c net.Conn, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := attestedtls.Write(data, c); err != nil {
		t.Logf("fake peer: send: %v", err)
	}
}

func recvMsg(t *testing.T, c net.Conn) []byte {
	t.Helper()
	data, err := attestedtls.Read(c)
	if err != nil {
		t.Logf("fake peer: receive: %v", err)
	}
	return data
}

// fakeTLSClient opens a TLS 1.3 connection with zone's certificate and completes the TLS
// handshake only.
func fakeTLSClient(t *testing.T, addr string, zone *atlstest.Zone) *tls.Conn {
	t.Helper()
	cfg := zone.TLSConfig()
	cfg.MinVersion = tls.VersionTLS13
	cfg.ServerName = "localhost"
	c, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("fake client: TLS: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// fakeTLSServer accepts TLS 1.3 connections with zone's certificate, completes the TLS
// handshake and passes each connection to script. It returns the address.
func fakeTLSServer(t *testing.T, zone *atlstest.Zone, script func(*tls.Conn)) string {
	t.Helper()
	cfg := zone.TLSConfig()
	cfg.MinVersion = tls.VersionTLS13
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				tc := c.(*tls.Conn)
				if err := tc.Handshake(); err != nil {
					_ = tc.Close()
					return
				}
				script(tc)
			}()
		}
	}()
	return ln.Addr().String()
}

// silentUntilCleanup keeps a connection open and silent until the test ends.
func silentUntilCleanup(t *testing.T) func(*tls.Conn) {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	return func(c *tls.Conn) {
		<-done
		_ = c.Close()
	}
}

// bindNonce mirrors CMC's report nonce: sha256(exporter || prover's TLS leaf certificate).
func bindNonce(exporter, leafDER []byte) []byte {
	h := sha256.New()
	h.Write(exporter)
	h.Write(leafDER)
	return h.Sum(nil)
}

func exporter(t *testing.T, c *tls.Conn) []byte {
	t.Helper()
	cs := c.ConnectionState()
	e, err := cs.ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// expectClosed asserts the peer closed c: a read returns EOF (or a reset) promptly.
func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	_, err := c.Read(buf)
	if err == nil {
		t.Fatal("connection still carries data; expected the peer to close it")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("peer did not close the connection")
	}
	if err != io.EOF {
		t.Logf("read after refusal: %v", err)
	}
}
