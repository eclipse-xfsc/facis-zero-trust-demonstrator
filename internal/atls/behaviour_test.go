package atls_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Fraunhofer-AISEC/cmc/attestedtls"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls/atlstest"
)

var sentinels = []error{
	atls.ErrNotAttested, atls.ErrBindingMismatch, atls.ErrEvidenceExpired, atls.ErrIdentityMismatch,
	atls.ErrPlainTLS, atls.ErrPeerAborted, atls.ErrAttestModeMismatch, atls.ErrAttesterUnavailable,
	atls.ErrHandshakeTimeout, atls.ErrPeerRejected, atls.ErrPeerUnreachable, atls.ErrConfig,
	atls.ErrChannelLost,
}

// assertRefusal checks err matches want and no other sentinel, and states a reason in words.
func assertRefusal(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
	for _, s := range sentinels {
		if s != want && errors.Is(err, s) {
			t.Fatalf("%v matches %v as well as %v", err, s, want)
		}
	}
	var ae *atls.Error
	if !errors.As(err, &ae) || strings.TrimSpace(ae.Reason) == "" {
		t.Fatalf("%v is not an *atls.Error with a reason", err)
	}
}

// assertAnyRefusal checks err matches exactly one sentinel.
func assertAnyRefusal(t *testing.T, err error) {
	t.Helper()
	n := 0
	for _, s := range sentinels {
		if errors.Is(err, s) {
			n++
		}
	}
	if err == nil || n != 1 {
		t.Fatalf("%v matches %d sentinels, want exactly one", err, n)
	}
}

func certFingerprint(c tls.Certificate) string {
	f := sha256.Sum256(c.Certificate[0])
	return hex.EncodeToString(f[:])
}

func exchange(t *testing.T, from, to *atls.Conn, msg string) {
	t.Helper()
	errc := make(chan error, 1)
	go func() { _, err := from.Write([]byte(msg)); errc <- err }()
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(to, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("write: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("got %q, want %q", buf, msg)
	}
}

// 5.1 Both peers are attested: both ends return a connection, verdict success, same binding.
func TestMutualHandshake(t *testing.T) {
	f := newFixture(t)
	cli, srv := pair(t, f.b.Config(t, f.a), f.a.Config(t, f.b))
	checkMutual(t, f, cli, srv)
}

func TestMutualHandshakeInProcess(t *testing.T) {
	skipLibAPIUnderRace(t)
	f := newFixture(t)
	libapiMu.Lock()
	cli, srv := pair(t, f.b.InProcessConfig(f.a), f.a.InProcessConfig(f.b))
	libapiMu.Unlock()
	checkMutual(t, f, cli, srv)
}

func checkMutual(t *testing.T, f *fixture, cli, srv *atls.Conn) {
	t.Helper()
	if cli.Peer().Verdict != atls.VerdictSuccess || srv.Peer().Verdict != atls.VerdictSuccess {
		t.Fatalf("verdicts: client %q, server %q", cli.Peer().Verdict, srv.Peer().Verdict)
	}
	if cli.Peer().PeerID != certFingerprint(f.b.Cert) || srv.Peer().PeerID != certFingerprint(f.a.Cert) {
		t.Fatal("PeerID is not the fingerprint of the peer's certificate")
	}
	if len(cli.Binding()) != 32 || !bytes.Equal(cli.Binding(), srv.Binding()) {
		t.Fatalf("bindings differ or are not 32 bytes: %x / %x", cli.Binding(), srv.Binding())
	}
	if cli.ConnectionState().Version != tls.VersionTLS13 || srv.ConnectionState().Version != tls.VersionTLS13 {
		t.Fatal("not TLS 1.3")
	}
	exchange(t, cli, srv, "ping over the attested channel")
	exchange(t, srv, cli, "pong")
}

// fakeATLSClient runs the client side of the aTLS protocol by hand on c, presenting report.
func fakeATLSClient(t *testing.T, c *tls.Conn, report []byte) {
	t.Helper()
	sendMsg(t, c, attestedtls.AtlsHandshakeRequest{Version: atlsVersion, Attest: attestedtls.Attest_Mutual})
	recvMsg(t, c) // server's request
	sendMsg(t, c, attestedtls.AtlsHandshakeResponse{Version: atlsVersion, Report: report})
	recvMsg(t, c) // server's response
	sendMsg(t, c, attestedtls.AtlsHandshakeComplete{Version: atlsVersion, Success: true})
	recvMsg(t, c) // server's handshake complete
}

// 5.2 A report bound to another TLS session is refused with ErrBindingMismatch.
func TestRelayedReportRefused(t *testing.T) {
	f := newFixture(t)
	ln := listen(t, f.b.Config(t, f.a))

	// Control: the hand-made client is accepted with a report bound to its own session.
	acc := acceptOne(ln, 15*time.Second)
	own := fakeTLSClient(t, ln.Addr().String(), f.a)
	fakeATLSClient(t, own, f.a.Report(t, bindNonce(exporter(t, own), f.a.Cert.Leaf.Raw)))
	if a := <-acc; a.err != nil {
		t.Fatalf("control handshake refused: %v", a.err)
	} else {
		_ = a.conn.Close()
	}

	// Another session of zone a, with some other endpoint.
	other := fakeTLSClient(t, fakeTLSServer(t, f.b, silentUntilCleanup(t)), f.a)
	relayed := f.a.Report(t, bindNonce(exporter(t, other), f.a.Cert.Leaf.Raw))

	acc = acceptOne(ln, 15*time.Second)
	c := fakeATLSClient
	victim := fakeTLSClient(t, ln.Addr().String(), f.a)
	c(t, victim, relayed)
	a := <-acc
	assertRefusal(t, a.err, atls.ErrBindingMismatch)
	expectClosed(t, victim)
}

// 5.3 A TLS 1.3 client that holds a valid zone certificate and leaves before the attestation
// exchange completes — a plain TLS client, or a peer whose attester is down — is refused as
// peer aborted, not as plain TLS.
func TestPlainTLSClientRefused(t *testing.T) {
	f := newFixture(t)
	ln := listen(t, f.b.Config(t, f.a))
	acc := acceptOne(ln, 15*time.Second)
	c := fakeTLSClient(t, ln.Addr().String(), f.a)
	recvMsg(t, c) // the server's attestation request, which a plain client does not understand
	_ = c.Close()
	assertRefusal(t, (<-acc).err, atls.ErrPeerAborted)
}

// 5.3 A TLS 1.2-only client is refused even when the caller's tls.Config allows TLS 1.2, and a
// caller allowing TLS 1.2 still negotiates TLS 1.3.
func TestTLS12Refused(t *testing.T) {
	f := newFixture(t)
	sc := f.b.Config(t, f.a)
	sc.TLS.MinVersion = tls.VersionTLS12
	ln := listen(t, sc)

	acc := acceptOne(ln, 15*time.Second)
	old := f.a.TLSConfig()
	old.MaxVersion = tls.VersionTLS12
	old.ServerName = "localhost"
	if c, err := tls.Dial("tcp", ln.Addr().String(), old); err == nil {
		_ = c.Close()
		t.Fatal("TLS 1.2 client completed a handshake")
	}
	assertRefusal(t, (<-acc).err, atls.ErrPlainTLS)

	cc := f.a.Config(t, f.b)
	cc.TLS.MinVersion = tls.VersionTLS10
	acc = acceptOne(ln, 15*time.Second)
	cli, err := dial(t, ln.Addr().String(), cc)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Close() }()
	srv := <-acc
	if srv.err != nil {
		t.Fatal(srv.err)
	}
	defer func() { _ = srv.conn.Close() }()
	if cli.ConnectionState().Version != tls.VersionTLS13 || srv.conn.ConnectionState().Version != tls.VersionTLS13 {
		t.Fatal("wrapper did not enforce TLS 1.3")
	}
	if sc.TLS.MinVersion != tls.VersionTLS12 {
		t.Fatal("the caller's tls.Config was modified")
	}
}

// 5.4 The peer carries another identity: refused with ErrIdentityMismatch on the checking side.
func TestWrongPeerIdentity(t *testing.T) {
	f := newFixture(t)

	t.Run("client checks server", func(t *testing.T) {
		ln := listen(t, f.b.Config(t, f.a))
		acc := acceptOne(ln, 15*time.Second)
		cc := f.a.Config(t, f.b)
		cc.ExpectedPeerIdentity = "spiffe://zone-c/gateway"
		_, err := dial(t, ln.Addr().String(), cc)
		assertRefusal(t, err, atls.ErrIdentityMismatch)
		assertRefusal(t, (<-acc).err, atls.ErrIdentityMismatch) // the server sees its certificate refused
	})
	t.Run("server checks client", func(t *testing.T) {
		sc := f.b.Config(t, f.a)
		sc.ExpectedPeerIdentity = "spiffe://zone-c/gateway"
		ln := listen(t, sc)
		acc := acceptOne(ln, 15*time.Second)
		_, err := dial(t, ln.Addr().String(), f.a.Config(t, f.b))
		assertAnyRefusal(t, err)
		assertRefusal(t, (<-acc).err, atls.ErrIdentityMismatch)
	})
	t.Run("untrusted CA", func(t *testing.T) {
		stranger := atlstest.NewZone(t, atlstest.NewPKI(t), "zone-b")
		ln := listen(t, stranger.Config(t, f.a))
		acc := acceptOne(ln, 15*time.Second)
		_, err := dial(t, ln.Addr().String(), f.a.Config(t, f.b))
		assertRefusal(t, err, atls.ErrIdentityMismatch)
		<-acc
	})
	t.Run("DNS identity", func(t *testing.T) {
		cert := f.pki.Issue(t, "gateway.zone-b.example")
		sc := f.b.Config(t, f.a)
		sc.TLS.Certificates = []tls.Certificate{cert}
		ln := listen(t, sc)
		acc := acceptOne(ln, 15*time.Second)
		cc := f.a.Config(t, f.b)
		cc.ExpectedPeerIdentity = "gateway.zone-b.example"
		c, err := dial(t, ln.Addr().String(), cc)
		// The certificate matches; attestation is by zone b's attester for a different
		// certificate, which CMC binds by nonce to the certificate actually used, so it passes.
		if err != nil {
			t.Fatalf("DNS SAN identity refused: %v", err)
		}
		_ = c.Close()
		if a := <-acc; a.conn != nil {
			_ = a.conn.Close()
		}
	})
}

// 5.4 / N3 A configuration relying on GetCertificate is refused before any connection is made.
func TestDynamicCertificateRefused(t *testing.T) {
	f := newFixture(t)
	for _, cfg := range []atls.Config{
		{TLS: &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &f.b.Cert, nil },
			RootCAs: f.pki.Pool}, CmcdAddr: "127.0.0.1:1", ExpectedPeerIdentity: f.a.Identity},
		{TLS: &tls.Config{GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &f.a.Cert, nil },
			RootCAs: f.pki.Pool}, CmcdAddr: "127.0.0.1:1", ExpectedPeerIdentity: f.b.Identity},
	} {
		if _, err := atls.Listen("127.0.0.1:0", cfg); !errors.Is(err, atls.ErrConfig) {
			t.Fatalf("Listen: got %v, want ErrConfig", err)
		}
		// Port 1 is not listening: ErrConfig proves no connection was attempted.
		if _, err := atls.Dial(context.Background(), "127.0.0.1:1", cfg); !errors.Is(err, atls.ErrConfig) {
			t.Fatalf("Dial: got %v, want ErrConfig", err)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	f := newFixture(t)
	good := func() atls.Config { return f.a.Config(t, f.b) }

	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	cases := map[string]func(c *atls.Config){
		"nil TLS":          func(c *atls.Config) { c.TLS = nil },
		"no certificate":   func(c *atls.Config) { c.TLS.Certificates = nil },
		"two certificates": func(c *atls.Config) { c.TLS.Certificates = append(c.TLS.Certificates, f.a.Cert) },
		"no cmcd":          func(c *atls.Config) { c.CmcdAddr = "" },
		"no peer identity": func(c *atls.Config) { c.ExpectedPeerIdentity = "" },
		"no trust anchors": func(c *atls.Config) { c.TLS.RootCAs, c.TLS.ClientCAs = nil, nil },
		"insecure skip":    func(c *atls.Config) { c.TLS.InsecureSkipVerify = true },
		"negative timeout": func(c *atls.Config) { c.HandshakeTimeout = -time.Second },
		"RSA-2048": func(c *atls.Config) {
			c.TLS.Certificates = []tls.Certificate{f.pki.Issue(t, "x", atlstest.WithKey(rsa2048))}
		},
		"ECDSA P-521": func(c *atls.Config) {
			c.TLS.Certificates = []tls.Certificate{f.pki.Issue(t, "x", atlstest.WithKey(p521))}
		},
		"Ed25519": func(c *atls.Config) {
			c.TLS.Certificates = []tls.Certificate{f.pki.Issue(t, "x", atlstest.WithKey(edKey))}
		},
		"GetConfigForClient": func(c *atls.Config) {
			c.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, nil }
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := good()
			mutate(&c)
			if _, err := atls.Listen("127.0.0.1:0", c); !errors.Is(err, atls.ErrConfig) {
				t.Fatalf("Listen: got %v", err)
			}
			if _, err := atls.Dial(context.Background(), "127.0.0.1:1", c); !errors.Is(err, atls.ErrConfig) {
				t.Fatalf("Dial: got %v", err)
			}
		})
	}
	t.Run("RSA-4096 accepted", func(t *testing.T) {
		k, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			t.Fatal(err)
		}
		c := good()
		c.TLS.Certificates = []tls.Certificate{f.pki.Issue(t, "x", atlstest.WithKey(k))}
		ln, err := atls.Listen("127.0.0.1:0", c)
		if err != nil {
			t.Fatalf("RSA-4096 refused: %v", err)
		}
		_ = ln.Close()
	})
}

// 5.5 A warn verdict is refused as not attested, and the connection is closed.
func TestWarnVerdictRefused(t *testing.T) {
	f := newFixture(t)
	t.Run("server judges warn", func(t *testing.T) {
		ln := listen(t, atlstest.ForceVerdict(f.b.Config(t, f.a), "warn"))
		acc := acceptOne(ln, 15*time.Second)
		cli, err := dial(t, ln.Addr().String(), f.a.Config(t, f.b))
		if err != nil {
			t.Fatalf("client side: %v", err) // CMC reports success to the client
		}
		defer func() { _ = cli.Close() }()
		assertRefusal(t, (<-acc).err, atls.ErrNotAttested)
		expectClosed(t, cli)
	})
	t.Run("client judges warn", func(t *testing.T) {
		ln := listen(t, f.b.Config(t, f.a))
		acc := acceptOne(ln, 15*time.Second)
		_, err := dial(t, ln.Addr().String(), atlstest.ForceVerdict(f.a.Config(t, f.b), "warn"))
		assertRefusal(t, err, atls.ErrNotAttested)
		srv := <-acc
		if srv.err != nil {
			t.Fatalf("server side: %v", srv.err)
		}
		defer func() { _ = srv.conn.Close() }()
		expectClosed(t, srv.conn)
	})
}

// 5.5 No result means not attested.
func TestMissingResultRefused(t *testing.T) {
	f := newFixture(t)
	ln := listen(t, f.b.Config(t, f.a))
	acc := acceptOne(ln, 15*time.Second)
	_, err := dial(t, ln.Addr().String(), atlstest.DropResult(f.a.Config(t, f.b)))
	assertRefusal(t, err, atls.ErrNotAttested)
	if srv := <-acc; srv.conn != nil {
		defer func() { _ = srv.conn.Close() }()
		expectClosed(t, srv.conn)
	}
}

// 5.5 A handshake that fails before any result exists reports no valid peer.
func TestNoResultBeforeFailure(t *testing.T) {
	f := newFixture(t)
	sc := f.b.Config(t, f.a)
	sc.CmcdAddr = atlstest.UnreachableCmcd(t)
	ln := listen(t, sc)
	acc := acceptOne(ln, 15*time.Second)
	c, err := dial(t, ln.Addr().String(), f.a.Config(t, f.b))
	if c != nil {
		t.Fatal("a connection was returned")
	}
	assertAnyRefusal(t, err)
	assertRefusal(t, (<-acc).err, atls.ErrAttesterUnavailable)
}

// 5.6 Expired evidence is refused with ErrEvidenceExpired.
func TestExpiredEvidenceRefused(t *testing.T) {
	f := newFixture(t, atlstest.WithEvidenceValidity(time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)))
	ln := listen(t, f.b.Config(t, f.a))
	acc := acceptOne(ln, 15*time.Second)
	_, err := dial(t, ln.Addr().String(), f.a.Config(t, f.b))
	assertAnyRefusal(t, err)
	assertRefusal(t, (<-acc).err, atls.ErrEvidenceExpired)
}

// 5.6 ValidUntil is the earlier of the channel lifetime and the evidence validity.
func TestValidUntil(t *testing.T) {
	pki := atlstest.NewPKI(t)
	a := atlstest.NewZone(t, pki, "zone-a")
	t.Run("lifetime first", func(t *testing.T) {
		b := atlstest.NewZone(t, pki, "zone-b") // evidence valid for an hour
		cc := a.Config(t, b)
		cc.ChannelLifetime = 15 * time.Minute
		cli, _ := pair(t, b.Config(t, a), cc)
		p := cli.Peer()
		if !p.ValidUntil.Equal(p.AttestedAt.Add(15 * time.Minute)) {
			t.Fatalf("ValidUntil %v, want AttestedAt+15m %v", p.ValidUntil, p.AttestedAt.Add(15*time.Minute))
		}
	})
	t.Run("evidence first", func(t *testing.T) {
		end := time.Now().Add(5 * time.Minute)
		b := atlstest.NewZone(t, pki, "zone-b", atlstest.WithEvidenceValidity(time.Now().Add(-time.Minute), end))
		cc := a.Config(t, b)
		cc.ChannelLifetime = 15 * time.Minute
		cli, _ := pair(t, b.Config(t, a), cc)
		p := cli.Peer()
		want := end.Truncate(time.Second) // metadata validity is stated in whole seconds
		if !p.ValidUntil.Equal(want) || !p.EvidenceNotAfter.Equal(want) {
			t.Fatalf("ValidUntil %v / EvidenceNotAfter %v, want %v", p.ValidUntil, p.EvidenceNotAfter, want)
		}
	})
	t.Run("default lifetime", func(t *testing.T) {
		b := atlstest.NewZone(t, pki, "zone-b")
		cli, _ := pair(t, b.Config(t, a), a.Config(t, b))
		p := cli.Peer()
		if !p.ValidUntil.Equal(p.AttestedAt.Add(atls.DefaultChannelLifetime)) {
			t.Fatalf("ValidUntil %v with the default lifetime", p.ValidUntil)
		}
	})
}

// 5.7 A PeerVerifier error refuses the channel with ErrPeerRejected wrapping it.
func TestPeerVerifierRejects(t *testing.T) {
	f := newFixture(t)
	errTrust := errors.New("peer not on the trust list")
	t.Run("dialer", func(t *testing.T) {
		ln := listen(t, f.b.Config(t, f.a))
		acc := acceptOne(ln, 15*time.Second)
		var seen atls.PeerAttestation
		cc := f.a.Config(t, f.b)
		cc.PeerVerifier = atls.PeerVerifierFunc(func(_ context.Context, p atls.PeerAttestation) error {
			seen = p
			return errTrust
		})
		_, err := dial(t, ln.Addr().String(), cc)
		assertRefusal(t, err, atls.ErrPeerRejected)
		if !errors.Is(err, errTrust) {
			t.Fatal("the verifier's error is not inspectable")
		}
		if seen.Verdict != atls.VerdictSuccess || seen.PeerID != certFingerprint(f.b.Cert) {
			t.Fatalf("verifier saw %+v", seen)
		}
		srv := <-acc
		if srv.err != nil {
			t.Fatal(srv.err)
		}
		defer func() { _ = srv.conn.Close() }()
		expectClosed(t, srv.conn)
	})
	t.Run("listener", func(t *testing.T) {
		sc := f.b.Config(t, f.a)
		sc.PeerVerifier = atls.PeerVerifierFunc(func(context.Context, atls.PeerAttestation) error { return errTrust })
		ln := listen(t, sc)
		acc := acceptOne(ln, 15*time.Second)
		cli, err := dial(t, ln.Addr().String(), f.a.Config(t, f.b))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = cli.Close() }()
		err = (<-acc).err
		assertRefusal(t, err, atls.ErrPeerRejected)
		if !errors.Is(err, errTrust) {
			t.Fatal("the verifier's error is not inspectable")
		}
		expectClosed(t, cli)
	})
}

// 5.8 An unreachable cmcd is reported as ErrAttesterUnavailable.
func TestAttesterUnavailable(t *testing.T) {
	f := newFixture(t)
	sc := f.b.Config(t, f.a)
	// The server waits for a message the failed client never sends (finding N6); keep it short.
	sc.HandshakeTimeout = 2 * time.Second
	ln := listen(t, sc)
	acc := acceptOne(ln, 15*time.Second)
	cc := f.a.Config(t, f.b)
	cc.CmcdAddr = atlstest.UnreachableCmcd(t)
	_, err := dial(t, ln.Addr().String(), cc)
	assertRefusal(t, err, atls.ErrAttesterUnavailable)
	assertAnyRefusal(t, (<-acc).err)
}

// A peer requesting another attestation mode is refused with ErrAttestModeMismatch.
func TestAttestModeMismatch(t *testing.T) {
	f := newFixture(t)
	ln := listen(t, f.b.Config(t, f.a))
	acc := acceptOne(ln, 15*time.Second)
	c := fakeTLSClient(t, ln.Addr().String(), f.a)
	sendMsg(t, c, attestedtls.AtlsHandshakeRequest{Version: atlsVersion, Attest: attestedtls.Attest_Server})
	recvMsg(t, c)
	sendMsg(t, c, attestedtls.AtlsHandshakeResponse{Version: atlsVersion})
	recvMsg(t, c)
	sendMsg(t, c, attestedtls.AtlsHandshakeComplete{Version: atlsVersion, Success: true})
	recvMsg(t, c)
	assertRefusal(t, (<-acc).err, atls.ErrAttestModeMismatch)
}

// Dialing a closed port is a transport failure, not a refusal by the peer.
func TestPeerUnreachable(t *testing.T) {
	f := newFixture(t)
	_, err := dial(t, atlstest.UnreachableCmcd(t), f.a.Config(t, f.b))
	assertRefusal(t, err, atls.ErrPeerUnreachable)
}

// 5.9 A server that completes TLS and stays silent makes Dial fail with ErrHandshakeTimeout once
// the deadline passes.
func TestSilentServerTimesOut(t *testing.T) {
	f := newFixture(t)
	addr := fakeTLSServer(t, f.b, silentUntilCleanup(t))

	cc := f.a.Config(t, f.b)
	cc.HandshakeTimeout = 1500 * time.Millisecond
	start := time.Now()
	_, err := atls.Dial(context.Background(), addr, cc)
	assertRefusal(t, err, atls.ErrHandshakeTimeout)
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("Dial returned after %v, handshake timeout 1.5 s", d)
	}

	// The caller's context deadline applies when it is sooner.
	cc.HandshakeTimeout = 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start = time.Now()
	_, err = atls.Dial(ctx, addr, cc)
	assertRefusal(t, err, atls.ErrHandshakeTimeout)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Dial returned after %v, context deadline 0.5 s", d)
	}
}

// 5.10 An accepted connection carries traffic more than 10 s after Accept (CMC's handshake
// deadline is cleared).
func TestTrafficAfterTenSeconds(t *testing.T) {
	if testing.Short() {
		t.Skip("waits 11 s")
	}
	t.Parallel()
	f := newFixture(t)
	cli, srv := pair(t, f.b.Config(t, f.a), f.a.Config(t, f.b))
	time.Sleep(11 * time.Second)
	exchange(t, cli, srv, "still here")
	exchange(t, srv, cli, "still here too")
}

// 5.10 A client stalled in its handshake does not delay a second client.
func TestStalledClientDoesNotDelayOthers(t *testing.T) {
	f := newFixture(t)
	ln := listen(t, f.b.Config(t, f.a))
	stalled := fakeTLSClient(t, ln.Addr().String(), f.a) // TLS done, then silence
	defer func() { _ = stalled.Close() }()

	acc := acceptOne(ln, 5*time.Second)
	start := time.Now()
	cli, err := dial(t, ln.Addr().String(), f.a.Config(t, f.b))
	if err != nil {
		t.Fatalf("second client: %v", err)
	}
	defer func() { _ = cli.Close() }()
	srv := <-acc
	if srv.err != nil {
		t.Fatalf("second client not accepted while the first stalls: %v", srv.err)
	}
	defer func() { _ = srv.conn.Close() }()
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("second handshake took %v", d)
	}
}

// 5.11 N parallel clients against one listener: all connect, and neither side runs more
// handshakes at once than its cap. Run with -race.
func TestParallelClientsRespectCap(t *testing.T) {
	f := newFixture(t)
	const clients, serverCap, dialCap = 12, 3, 4
	sc := f.b.Config(t, f.a)
	sc.MaxConcurrentHandshakes = serverCap
	// Slow each server-side verification a little so handshakes overlap.
	sc = atlstest.OnResult(sc, func(string) { time.Sleep(50 * time.Millisecond) })
	ln := listen(t, sc)

	var accepted sync.WaitGroup
	accepted.Add(1)
	acceptErrs := make(chan error, clients)
	go func() {
		defer accepted.Done()
		for range clients {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			c, err := ln.Accept(ctx)
			cancel()
			if err != nil {
				acceptErrs <- err
				continue
			}
			_ = c.Close()
		}
	}()

	atls.ResetDialPeak()
	cc := f.a.Config(t, f.b)
	cc.MaxConcurrentHandshakes = dialCap
	cc.HandshakeTimeout = 30 * time.Second
	var wg sync.WaitGroup
	dialErrs := make(chan error, clients)
	for range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := dial(t, ln.Addr().String(), cc)
			if err != nil {
				dialErrs <- err
				return
			}
			_ = c.Close()
		}()
	}
	wg.Wait()
	accepted.Wait()
	close(dialErrs)
	close(acceptErrs)
	for err := range dialErrs {
		t.Errorf("dial: %v", err)
	}
	for err := range acceptErrs {
		t.Errorf("accept: %v", err)
	}
	if p := atls.ListenerPeak(ln); p > serverCap || p < 2 {
		t.Fatalf("listener ran %d handshakes at once, cap %d (and at least 2 expected to overlap)", p, serverCap)
	}
	if p := atls.DialPeak(); p > dialCap {
		t.Fatalf("dialer ran %d handshakes at once, cap %d", p, dialCap)
	}
}
