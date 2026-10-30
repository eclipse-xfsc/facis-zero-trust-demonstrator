package atls_test

// Tests for the resource and timing bounds of the listener and Dial: connections waiting for a
// handshake slot, connections nobody accepts before their validity ends, and peer verification
// within the handshake deadline and slot.

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls/atlstest"
)

// listenerHandlers counts the goroutines that handle one incoming connection of a listener.
func listenerHandlers() int {
	buf := make([]byte, 1<<22)
	buf = buf[:runtime.Stack(buf, true)]
	n := 0
	for _, g := range bytes.Split(buf, []byte("\n\n")) {
		if bytes.Contains(g, []byte("atls.(*Listener).handle(")) {
			n++
		}
	}
	return n
}

// openDescriptors counts the open file descriptors of the process.
func openDescriptors(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot count descriptors: %v", err)
	}
	return len(entries)
}

// More clients than the cap connect and stay silent. The listener holds a goroutine and a
// descriptor only for the connections it handshakes; the others wait in the kernel backlog. Each
// silent client is closed when its handshake times out, and an honest client is accepted after.
func TestSilentClientsWaitInBacklog(t *testing.T) {
	f := newFixture(t)
	const silent, capacity = 8, 2
	const timeout = time.Second
	sc := f.b.Config(t, f.a)
	sc.MaxConcurrentHandshakes = capacity
	sc.HandshakeTimeout = timeout
	ln := listen(t, sc)

	fdsBefore := openDescriptors(t)
	start := time.Now()
	clients := make([]net.Conn, 0, silent)
	for range silent {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		clients = append(clients, c)
	}
	// Give the listener time to accept whatever it is going to accept, well within the timeout.
	time.Sleep(timeout / 3)
	if n := listenerHandlers(); n > capacity {
		t.Fatalf("listener runs %d connection goroutines for %d silent clients, cap %d", n, silent, capacity)
	}
	// The process holds one descriptor per client end, plus one per connection the listener
	// accepted; allow one more for anything else the runtime opens meanwhile.
	if extra := openDescriptors(t) - fdsBefore - silent; extra > capacity+1 {
		t.Fatalf("listener holds %d descriptors for %d silent clients, cap %d", extra, silent, capacity)
	}

	// Every silent client is closed once its handshake times out: they are handshaken cap at a
	// time, so the last batch ends after silent/cap timeouts.
	drained := time.Duration(silent/capacity) * timeout
	for i, c := range clients {
		_ = c.SetReadDeadline(start.Add(drained + 3*time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatalf("silent client %d received data", i)
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatalf("silent client %d still open after %v", i, time.Since(start))
		}
	}
	if d := time.Since(start); d < timeout {
		t.Fatalf("silent clients closed after %v, before the handshake timeout %v", d, timeout)
	}

	// The refusals of the silent clients are reported first; then the honest client's channel.
	cc := f.a.Config(t, f.b)
	cc.HandshakeTimeout = 20 * time.Second
	type dialed struct {
		c   *atls.Conn
		err error
	}
	dc := make(chan dialed, 1)
	go func() {
		c, err := dial(t, ln.Addr().String(), cc)
		dc <- dialed{c, err}
	}()
	refusals := 0
	for {
		a := <-acceptOne(ln, 20*time.Second)
		if a.err != nil {
			if !errors.Is(a.err, atls.ErrHandshakeTimeout) {
				t.Fatalf("silent client refused with %v, want a handshake timeout", a.err)
			}
			refusals++
			if refusals > silent {
				t.Fatalf("more refusals than silent clients: %v", a.err)
			}
			continue
		}
		defer func() { _ = a.conn.Close() }()
		break
	}
	d := <-dc
	if d.err != nil {
		t.Fatalf("honest client: %v", d.err)
	}
	_ = d.c.Close()
	if refusals != silent {
		t.Fatalf("%d refusals for %d silent clients", refusals, silent)
	}
}

// expiringFixture is a fixture whose dialing zone's evidence ends on a whole second about two
// seconds from now (signed metadata states its validity in whole seconds); end is that second.
func expiringFixture(t *testing.T) (f *fixture, end time.Time) {
	t.Helper()
	// Start just after a whole second, so the evidence has close to two seconds left.
	next := time.Now().Truncate(time.Second).Add(time.Second)
	time.Sleep(time.Until(next) + 20*time.Millisecond)
	end = next.Add(2 * time.Second)
	return newFixture(t, atlstest.WithEvidenceValidity(time.Now().Add(-time.Minute), end)), end
}

// handshakeUnaccepted completes one handshake against ln without calling Accept and returns the
// dialer's end.
func handshakeUnaccepted(t *testing.T, ln *atls.Listener, f *fixture) *atls.Conn {
	t.Helper()
	cli, err := dial(t, ln.Addr().String(), f.a.Config(t, f.b))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	return cli
}

// sleepPast sleeps until two seconds have passed since from, and at least until after end.
func sleepPast(from, end time.Time) {
	until := from.Add(2 * time.Second)
	if !until.After(end) {
		until = end.Add(200 * time.Millisecond)
	}
	time.Sleep(time.Until(until))
}

// A handshaken connection that nobody accepts before its ValidUntil is closed and refused; Accept
// never returns a connection whose validity has passed.
func TestPendingConnectionExpires(t *testing.T) {
	t.Run("accept called after the evidence expired", func(t *testing.T) {
		f, end := expiringFixture(t)
		ln := listen(t, f.b.Config(t, f.a))
		cli := handshakeUnaccepted(t, ln, f)
		if !time.Now().Before(end) {
			t.Fatal("the handshake ended after the evidence expired")
		}
		sleepPast(time.Now(), end)
		err := (<-acceptOne(ln, 5*time.Second)).err
		assertRefusal(t, err, atls.ErrEvidenceExpired)
		if ae := refusalError(t, err); ae.Peer == nil || ae.Peer.String() != cli.LocalAddr().String() {
			t.Fatalf("refusal names peer %v, want %s", ae.Peer, cli.LocalAddr())
		}
		expectClosed(t, cli)
	})
	t.Run("nobody accepts before the evidence expires", func(t *testing.T) {
		f, end := expiringFixture(t)
		ln := listen(t, f.b.Config(t, f.a))
		cli := handshakeUnaccepted(t, ln, f)
		// The listener closes the connection at its ValidUntil without any Accept call.
		_ = cli.SetReadDeadline(end.Add(2 * time.Second))
		if _, err := cli.Read(make([]byte, 1)); err == nil {
			t.Fatal("the dialer received data")
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatal("the listener did not close the connection at its ValidUntil")
		}
		if time.Now().Before(end) {
			t.Fatalf("the listener closed the connection before its ValidUntil %v", end)
		}
		assertRefusal(t, (<-acceptOne(ln, 5*time.Second)).err, atls.ErrEvidenceExpired)
	})
	t.Run("channel lifetime ends first", func(t *testing.T) {
		f := newFixture(t)
		sc := f.b.Config(t, f.a)
		sc.ChannelLifetime = time.Second
		ln := listen(t, sc)
		handshakeUnaccepted(t, ln, f)
		time.Sleep(2 * time.Second)
		assertRefusal(t, (<-acceptOne(ln, 5*time.Second)).err, atls.ErrHandshakeTimeout)
	})
	t.Run("accept called in time", func(t *testing.T) {
		f, end := expiringFixture(t)
		ln := listen(t, f.b.Config(t, f.a))
		cli := handshakeUnaccepted(t, ln, f)
		a := <-acceptOne(ln, 5*time.Second)
		if a.err != nil {
			t.Fatalf("accept in time: %v", a.err)
		}
		defer func() { _ = a.conn.Close() }()
		if p := a.conn.Peer(); !p.ValidUntil.Equal(end) || !p.EvidenceNotAfter.Equal(end) {
			t.Fatalf("ValidUntil %v / EvidenceNotAfter %v, want %v", p.ValidUntil, p.EvidenceNotAfter, end)
		}
		exchange(t, cli, a.conn, "in time")
	})
}

// Verifiers for the slow-verifier tests: one waits for its context to end, one sleeps past the
// deadline ignoring its context and then accepts the peer.
var (
	blockingVerifier = atls.PeerVerifierFunc(func(ctx context.Context, _ atls.PeerAttestation) error {
		<-ctx.Done()
		return ctx.Err()
	})
	lateVerifier = atls.PeerVerifierFunc(func(context.Context, atls.PeerAttestation) error {
		time.Sleep(3 * time.Second)
		return nil
	})
)

// The PeerVerifier runs within the handshake deadline: a verifier still running when the deadline
// passes refuses the channel as a handshake timeout, whether it honours its context or not.
func TestSlowVerifierTimesOut(t *testing.T) {
	f := newFixture(t)
	const deadline = 1500 * time.Millisecond
	verifiers := map[string]atls.PeerVerifier{"honours its context": blockingVerifier, "ignores its context": lateVerifier}

	for name, v := range verifiers {
		t.Run("dialer, verifier "+name, func(t *testing.T) {
			ln := listen(t, f.b.Config(t, f.a))
			acc := acceptOne(ln, 15*time.Second)
			cc := f.a.Config(t, f.b)
			cc.HandshakeTimeout = deadline
			cc.PeerVerifier = v
			start := time.Now()
			c, err := atls.Dial(context.Background(), ln.Addr().String(), cc)
			if c != nil {
				_ = c.Close()
			}
			assertRefusal(t, err, atls.ErrHandshakeTimeout)
			if d := time.Since(start); d > deadline+time.Second {
				t.Fatalf("Dial returned after %v, handshake timeout %v", d, deadline)
			}
			srv := <-acc
			if srv.err != nil {
				t.Fatalf("accept: %v", srv.err)
			}
			defer func() { _ = srv.conn.Close() }()
			// The dialer closes its end at the deadline, not when the verifier returns.
			_ = srv.conn.SetReadDeadline(start.Add(deadline + time.Second))
			if _, err := srv.conn.Read(make([]byte, 1)); err == nil {
				t.Fatal("the dialer sent data")
			} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("the dialer did not close the connection at the deadline")
			}
		})
		t.Run("listener, verifier "+name, func(t *testing.T) {
			sc := f.b.Config(t, f.a)
			sc.HandshakeTimeout = deadline
			sc.PeerVerifier = v
			ln := listen(t, sc)
			acc := acceptOne(ln, 15*time.Second)
			start := time.Now()
			cli, err := dial(t, ln.Addr().String(), f.a.Config(t, f.b))
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer func() { _ = cli.Close() }()
			// The listener closes the connection at the deadline, not when the verifier returns.
			_ = cli.SetReadDeadline(start.Add(deadline + time.Second))
			if _, err := cli.Read(make([]byte, 1)); err == nil {
				t.Fatal("the listener sent data")
			} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("the listener did not close the connection at the deadline")
			}
			err = (<-acc).err
			assertRefusal(t, err, atls.ErrHandshakeTimeout)
			if ae := refusalError(t, err); ae.Peer == nil || ae.Peer.String() != cli.LocalAddr().String() {
				t.Fatalf("refusal names peer %v, want %s", ae.Peer, cli.LocalAddr())
			}
		})
	}
}

// Peer verification holds the handshake slot: with a slow verifier on both ends, no end runs
// more verifications at once than its cap.
func TestSlowVerifiersRespectCap(t *testing.T) {
	f := newFixture(t)
	const clients, capacity = 6, 2
	var srvRunning, srvPeak, cliRunning, cliPeak atomic.Int64
	slow := func(running, peak *atomic.Int64) atls.PeerVerifier {
		return atls.PeerVerifierFunc(func(context.Context, atls.PeerAttestation) error {
			n := running.Add(1)
			for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
			}
			time.Sleep(300 * time.Millisecond)
			running.Add(-1)
			return nil
		})
	}
	sc := f.b.Config(t, f.a)
	sc.MaxConcurrentHandshakes = capacity
	sc.HandshakeTimeout = 30 * time.Second
	sc.PeerVerifier = slow(&srvRunning, &srvPeak)
	ln := listen(t, sc)
	cc := f.a.Config(t, f.b)
	cc.MaxConcurrentHandshakes = capacity
	cc.HandshakeTimeout = 30 * time.Second
	cc.PeerVerifier = slow(&cliRunning, &cliPeak)

	var wg sync.WaitGroup
	errs := make(chan error, 2*clients)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range clients {
			a := <-acceptOne(ln, 30*time.Second)
			if a.err != nil {
				errs <- a.err
				continue
			}
			_ = a.conn.Close()
		}
	}()
	for range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := dial(t, ln.Addr().String(), cc)
			if err != nil {
				errs <- err
				return
			}
			_ = c.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("handshake: %v", err)
	}
	if p := srvPeak.Load(); p > capacity {
		t.Fatalf("listener ran %d verifications at once, cap %d", p, capacity)
	}
	if p := cliPeak.Load(); p > capacity {
		t.Fatalf("dialer ran %d verifications at once, cap %d", p, capacity)
	}
	if srvPeak.Load() < 2 && cliPeak.Load() < 2 {
		t.Fatal("no verifications overlapped; the test proves nothing")
	}
}
