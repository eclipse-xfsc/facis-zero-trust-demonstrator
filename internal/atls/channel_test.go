package atls_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls/atlstest"
)

// rawConn returns the TCP connection under an established channel, to end the channel in ways
// its own Close does not: without a closing alert, with a reset, with a forged record.
func rawConn(t *testing.T, c *atls.Conn) *net.TCPConn {
	t.Helper()
	tc, ok := c.Conn.(*tls.Conn)
	if !ok {
		t.Fatalf("the channel wraps a %T, want *tls.Conn", c.Conn)
	}
	tcp, ok := tc.NetConn().(*net.TCPConn)
	if !ok {
		t.Fatalf("the TLS connection runs over a %T, want *net.TCPConn", tc.NetConn())
	}
	return tcp
}

// reset ends the channel from c's side with a TCP reset.
func reset(t *testing.T, c *atls.Conn) {
	t.Helper()
	tcp := rawConn(t, c)
	if err := tcp.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	_ = tcp.Close()
}

// readErr returns the error of one Read on c, which must not carry data.
func readErr(t *testing.T, c *atls.Conn) error {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := c.Read(make([]byte, 16))
	if n != 0 || err == nil {
		t.Fatalf("read returned %d bytes and error %v, want no data and an error", n, err)
	}
	return err
}

// assertChannelLost checks err is an *atls.Error matching ErrChannelLost and no other sentinel,
// that it still matches its cause, and that it names the peer's address.
func assertChannelLost(t *testing.T, err error, peer net.Addr) {
	t.Helper()
	assertRefusal(t, err, atls.ErrChannelLost)
	var ae *atls.Error
	if !errors.As(err, &ae) {
		t.Fatalf("%v is not an *atls.Error", err)
	}
	if ae.Err == nil || !errors.Is(err, ae.Err) {
		t.Fatalf("%v does not match its cause %v", err, ae.Err)
	}
	if ae.Peer == nil || ae.Peer.String() != peer.String() {
		t.Fatalf("lost channel names peer %v, want %v", ae.Peer, peer)
	}
}

// The peer closes the channel, or its process dies (the kernel then closes the connection
// without a closing alert): Read returns io.EOF itself, not a wrapped error.
func TestChannelPeerGoneIsEOF(t *testing.T) {
	f := newFixture(t)
	for name, leave := range map[string]func(*testing.T, *atls.Conn){
		"orderly close":                  func(_ *testing.T, c *atls.Conn) { _ = c.Close() },
		"connection ends without alert":  func(t *testing.T, c *atls.Conn) { _ = rawConn(t, c).Close() },
		"write side shut, no alert sent": func(t *testing.T, c *atls.Conn) { _ = rawConn(t, c).CloseWrite() },
	} {
		t.Run(name, func(t *testing.T) {
			cli, srv := pair(t, f.b.Config(t, f.a), f.a.Config(t, f.b))
			leave(t, cli)
			if err := readErr(t, srv); err != io.EOF {
				t.Fatalf("read after the peer left returned %#v, want io.EOF itself", err)
			}
		})
	}
}

// Standard-library consumers end on the raw io.EOF: io.Copy and io.ReadAll return the whole
// stream and no error.
func TestChannelStandardConsumers(t *testing.T) {
	f := newFixture(t)
	payload := bytes.Repeat([]byte("attested channel "), 64<<10) // about 1 MiB, many TLS records

	t.Run("io.Copy", func(t *testing.T) {
		cli, srv := pair(t, f.b.Config(t, f.a), f.a.Config(t, f.b))
		sent := make(chan error, 1)
		go func() {
			_, err := io.Copy(cli, bytes.NewReader(payload))
			_ = cli.Close()
			sent <- err
		}()
		var got bytes.Buffer
		if _, err := io.Copy(&got, srv); err != nil {
			t.Fatalf("io.Copy from the channel: %v", err)
		}
		if err := <-sent; err != nil {
			t.Fatalf("io.Copy into the channel: %v", err)
		}
		if !bytes.Equal(got.Bytes(), payload) {
			t.Fatalf("received %d bytes, sent %d", got.Len(), len(payload))
		}
	})
	t.Run("io.ReadAll", func(t *testing.T) {
		cli, srv := pair(t, f.b.Config(t, f.a), f.a.Config(t, f.b))
		go func() {
			_, _ = srv.Write(payload)
			_ = srv.Close()
		}()
		got, err := io.ReadAll(cli)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("io.ReadAll: %d of %d bytes, error %v", len(got), len(payload), err)
		}
	})
}

// A read deadline that expires returns the connection's own timeout error, and the channel
// stays usable.
func TestChannelReadDeadlineIsRawTimeout(t *testing.T) {
	f := newFixture(t)
	cli, srv := pair(t, f.b.Config(t, f.a), f.a.Config(t, f.b))

	if err := srv.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err := srv.Read(make([]byte, 16))
	ne, ok := err.(net.Error) // a type assertion, as callers written against net.Conn do
	if !ok || !ne.Timeout() {
		t.Fatalf("read past its deadline returned %#v, want the connection's timeout error", err)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%v does not match os.ErrDeadlineExceeded", err)
	}
	var ae *atls.Error
	if errors.As(err, &ae) || errors.Is(err, atls.ErrChannelLost) {
		t.Fatalf("a timeout was wrapped: %v", err)
	}

	if err := srv.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	exchange(t, cli, srv, "after the deadline")
	exchange(t, srv, cli, "and back")
}

// A write deadline that expires returns the raw timeout too, and — as crypto/tls documents for
// SetWriteDeadline — leaves the session broken: later writes fail the same way, so the channel
// must be discarded.
func TestChannelWriteDeadlineBreaksChannel(t *testing.T) {
	f := newFixture(t)
	cli, _ := pair(t, f.b.Config(t, f.a), f.a.Config(t, f.b))

	if err := cli.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	isRawTimeout := func(err error) bool {
		ne, ok := err.(net.Error)
		return ok && ne.Timeout() && !errors.Is(err, atls.ErrChannelLost)
	}
	if _, err := cli.Write([]byte("late")); !isRawTimeout(err) {
		t.Fatalf("write past its deadline returned %#v, want the connection's timeout error", err)
	}
	if err := cli.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.Write([]byte("again")); !isRawTimeout(err) {
		t.Fatalf("write after an expired write deadline returned %#v, want the same timeout error", err)
	}
}

// A reset connection is a lost channel: an *atls.Error matching ErrChannelLost that still
// matches the transport error underneath.
func TestChannelLostOnReset(t *testing.T) {
	f := newFixture(t)

	t.Run("read", func(t *testing.T) {
		cli, srv := pair(t, f.b.Config(t, f.a), f.a.Config(t, f.b))
		peer := cli.LocalAddr()
		reset(t, cli)
		err := readErr(t, srv)
		assertChannelLost(t, err, peer)
		if !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("%v does not match the connection reset underneath", err)
		}
	})
	t.Run("write", func(t *testing.T) {
		cli, srv := pair(t, f.b.Config(t, f.a), f.a.Config(t, f.b))
		peer := cli.LocalAddr()
		reset(t, cli)
		// The reset reaches this end a moment after the peer sent it.
		var err error
		for deadline := time.Now().Add(10 * time.Second); err == nil && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			_, err = srv.Write([]byte("anyone there?"))
		}
		assertChannelLost(t, err, peer)
		if !errors.Is(err, syscall.EPIPE) && !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("%v matches neither a broken pipe nor a connection reset", err)
		}
	})
}

// A TLS alert is a lost channel on both ends: the end that raises it and the end that receives
// it.
func TestChannelLostOnTLSAlert(t *testing.T) {
	f := newFixture(t)
	cli, srv := pair(t, f.b.Config(t, f.a), f.a.Config(t, f.b))

	// An application-data record that was not produced by this TLS session: the server cannot
	// authenticate it and answers with a bad-record-MAC alert.
	forged := append([]byte{0x17, 0x03, 0x03, 0x00, 0x20}, make([]byte, 0x20)...)
	if _, err := rawConn(t, cli).Write(forged); err != nil {
		t.Fatal(err)
	}

	raised := readErr(t, srv)
	assertChannelLost(t, raised, cli.LocalAddr())
	var op *net.OpError
	if !errors.As(raised, &op) || op.Op != "local error" {
		t.Fatalf("the raising end got %v, want the TLS local error as its cause", raised)
	}

	received := readErr(t, cli)
	assertChannelLost(t, received, srv.LocalAddr())
	if !errors.As(received, &op) || op.Op != "remote error" {
		t.Fatalf("the receiving end got %v, want the TLS alert of the peer as its cause", received)
	}
}

// Using a channel this end closed is a lost channel that matches net.ErrClosed.
func TestChannelLostAfterOwnClose(t *testing.T) {
	f := newFixture(t)
	cli, _ := pair(t, f.b.Config(t, f.a), f.a.Config(t, f.b))
	peer := cli.RemoteAddr()
	_ = cli.Close()
	_, err := cli.Write([]byte("too late"))
	assertChannelLost(t, err, peer)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("%v does not match net.ErrClosed", err)
	}
}

func refusalError(t *testing.T, err error) *atls.Error {
	t.Helper()
	var ae *atls.Error
	if !errors.As(err, &ae) {
		t.Fatalf("%v is not an *atls.Error", err)
	}
	// The address is a field, never part of the text.
	if bare := (&atls.Error{Kind: ae.Kind, Reason: ae.Reason, Err: ae.Err}).Error(); ae.Error() != bare {
		t.Fatalf("error text %q changes with the peer address (without: %q)", ae.Error(), bare)
	}
	return ae
}

// A refusal returned by Accept names the transport address of the connection it refused.
func TestAcceptRefusalCarriesPeerAddress(t *testing.T) {
	f := newFixture(t)

	t.Run("refused in the attestation exchange", func(t *testing.T) {
		ln := listen(t, f.b.Config(t, f.a))
		acc := acceptOne(ln, 15*time.Second)
		c := fakeTLSClient(t, ln.Addr().String(), f.a)
		local := c.LocalAddr().String()
		recvMsg(t, c)
		_ = c.Close()
		err := (<-acc).err
		assertRefusal(t, err, atls.ErrPeerAborted)
		if ae := refusalError(t, err); ae.Peer == nil || ae.Peer.String() != local {
			t.Fatalf("refusal names peer %v, want %s", ae.Peer, local)
		}
	})
	t.Run("refused in the TLS handshake", func(t *testing.T) {
		ln := listen(t, f.b.Config(t, f.a))
		acc := acceptOne(ln, 15*time.Second)
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if _, err := c.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		err = (<-acc).err
		assertRefusal(t, err, atls.ErrPlainTLS)
		if ae := refusalError(t, err); ae.Peer == nil || ae.Peer.String() != c.LocalAddr().String() {
			t.Fatalf("refusal names peer %v, want %s", ae.Peer, c.LocalAddr())
		}
	})
	t.Run("refused by the peer verifier", func(t *testing.T) {
		sc := f.b.Config(t, f.a)
		sc.PeerVerifier = atls.PeerVerifierFunc(func(context.Context, atls.PeerAttestation) error {
			return errors.New("not on the trust list")
		})
		ln := listen(t, sc)
		acc := acceptOne(ln, 15*time.Second)
		cli, err := dial(t, ln.Addr().String(), f.a.Config(t, f.b))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = cli.Close() }()
		err = (<-acc).err
		assertRefusal(t, err, atls.ErrPeerRejected)
		if ae := refusalError(t, err); ae.Peer == nil || ae.Peer.String() != cli.LocalAddr().String() {
			t.Fatalf("refusal names peer %v, want %s", ae.Peer, cli.LocalAddr())
		}
	})
	t.Run("timed out, each refusal names its own peer", func(t *testing.T) {
		sc := f.b.Config(t, f.a)
		sc.HandshakeTimeout = time.Second
		sc.MaxConcurrentHandshakes = 1
		ln := listen(t, sc)
		// Two peers that connect and stay silent: one holds the only handshake slot, the other
		// waits for it. Both are refused once the timeout passes.
		want := map[string]bool{}
		for range 2 {
			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			want[c.LocalAddr().String()] = true
		}
		for range 2 {
			err := (<-acceptOne(ln, 15*time.Second)).err
			assertRefusal(t, err, atls.ErrHandshakeTimeout)
			ae := refusalError(t, err)
			if ae.Peer == nil || !want[ae.Peer.String()] {
				t.Fatalf("refusal names peer %v, want one of %v", ae.Peer, want)
			}
			delete(want, ae.Peer.String())
		}
	})
}

// A refusal returned by Dial names the peer once a connection existed; an error raised before
// any connection — a configuration error, an unreachable peer — names none.
func TestDialRefusalPeerAddress(t *testing.T) {
	f := newFixture(t)

	t.Run("a connection existed", func(t *testing.T) {
		ln := listen(t, f.b.Config(t, f.a))
		acc := acceptOne(ln, 15*time.Second)
		cc := f.a.Config(t, f.b)
		cc.PeerVerifier = atls.PeerVerifierFunc(func(context.Context, atls.PeerAttestation) error {
			return errors.New("not on the trust list")
		})
		_, err := dial(t, ln.Addr().String(), cc)
		assertRefusal(t, err, atls.ErrPeerRejected)
		if ae := refusalError(t, err); ae.Peer == nil || ae.Peer.String() != ln.Addr().String() {
			t.Fatalf("refusal names peer %v, want %s", ae.Peer, ln.Addr())
		}
		if srv := <-acc; srv.conn != nil {
			_ = srv.conn.Close()
		}
	})
	t.Run("no connection: peer unreachable", func(t *testing.T) {
		_, err := dial(t, atlstest.UnreachableCmcd(t), f.a.Config(t, f.b))
		assertRefusal(t, err, atls.ErrPeerUnreachable)
		if ae := refusalError(t, err); ae.Peer != nil {
			t.Fatalf("refusal names peer %v although no connection existed", ae.Peer)
		}
	})
	t.Run("no connection: configuration error", func(t *testing.T) {
		bad := f.a.Config(t, f.b)
		bad.ExpectedPeerIdentity = ""
		_, dialErr := atls.Dial(context.Background(), "127.0.0.1:1", bad)
		_, listenErr := atls.Listen("127.0.0.1:0", bad)
		for _, err := range []error{dialErr, listenErr} {
			assertRefusal(t, err, atls.ErrConfig)
			if ae := refusalError(t, err); ae.Peer != nil {
				t.Fatalf("configuration error names peer %v", ae.Peer)
			}
		}
	})
}

// Peer().Identity is the identity the peer's certificate matched, on both ends, and the
// PeerVerifier sees it.
func TestPeerIdentityReported(t *testing.T) {
	f := newFixture(t)

	t.Run("URI identity", func(t *testing.T) {
		var dialerSaw, listenerSaw string
		sc := f.b.Config(t, f.a)
		sc.PeerVerifier = atls.PeerVerifierFunc(func(_ context.Context, p atls.PeerAttestation) error {
			listenerSaw = p.Identity
			return nil
		})
		cc := f.a.Config(t, f.b)
		cc.PeerVerifier = atls.PeerVerifierFunc(func(_ context.Context, p atls.PeerAttestation) error {
			dialerSaw = p.Identity
			return nil
		})
		if cc.ExpectedPeerIdentity != "spiffe://zone-b/gateway" || sc.ExpectedPeerIdentity != "spiffe://zone-a/gateway" {
			t.Fatalf("fixture identities changed: %q, %q", cc.ExpectedPeerIdentity, sc.ExpectedPeerIdentity)
		}
		cli, srv := pair(t, sc, cc)
		if got := cli.Peer().Identity; got != "spiffe://zone-b/gateway" {
			t.Fatalf("dialer: Peer().Identity = %q, want spiffe://zone-b/gateway", got)
		}
		if got := srv.Peer().Identity; got != "spiffe://zone-a/gateway" {
			t.Fatalf("listener: Peer().Identity = %q, want spiffe://zone-a/gateway", got)
		}
		if dialerSaw != "spiffe://zone-b/gateway" || listenerSaw != "spiffe://zone-a/gateway" {
			t.Fatalf("verifiers saw %q (dialer) and %q (listener)", dialerSaw, listenerSaw)
		}
	})
	t.Run("DNS identity", func(t *testing.T) {
		sc := f.b.Config(t, f.a)
		sc.TLS.Certificates = []tls.Certificate{f.pki.Issue(t, "gateway.zone-b.example")}
		cc := f.a.Config(t, f.b)
		cc.ExpectedPeerIdentity = "gateway.zone-b.example"
		cli, _ := pair(t, sc, cc)
		if got := cli.Peer().Identity; got != "gateway.zone-b.example" {
			t.Fatalf("Peer().Identity = %q, want gateway.zone-b.example", got)
		}
	})
}
