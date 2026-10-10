package atls

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Fraunhofer-AISEC/cmc/attestedtls"
)

// bindingLabel and bindingLen are the RFC 9266 tls-exporter channel binding.
const (
	bindingLabel = "EXPORTER-Channel-Binding"
	bindingLen   = 32
)

// Conn is an established, mutually attested TLS 1.3 connection.
type Conn struct {
	net.Conn
	tls     *tls.Conn
	binding []byte
	peer    PeerAttestation
}

// Binding returns the RFC 9266 tls-exporter value of this session (label
// "EXPORTER-Channel-Binding", 32 bytes). Both ends of one channel return the same value.
func (c *Conn) Binding() []byte {
	return append([]byte(nil), c.binding...)
}

// Peer returns what the attestation established about the peer.
func (c *Conn) Peer() PeerAttestation {
	p := c.peer
	p.Measurements = append([]Measurement(nil), c.peer.Measurements...)
	return p
}

// ConnectionState returns the TLS state of the connection.
func (c *Conn) ConnectionState() tls.ConnectionState {
	return c.tls.ConnectionState()
}

// Read reads from the channel. io.EOF and timeout errors are returned exactly as the connection
// returns them; any other error is returned as an *Error matching ErrChannelLost that wraps it.
func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	return n, c.transportErr("read failed", err)
}

// Write writes to the channel. Timeout errors are returned exactly as the connection returns
// them; any other error is returned as an *Error matching ErrChannelLost that wraps it. After a
// write deadline has expired the TLS session is broken and the channel must be discarded.
func (c *Conn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	return n, c.transportErr("write failed", err)
}

// transportErr classifies an error of an established channel: io.EOF and timeouts stay as they
// are, so standard-library consumers and the caller's deadlines keep working; everything else
// is a lost channel.
func (c *Conn) transportErr(reason string, err error) error {
	if err == nil || errors.Is(err, io.EOF) {
		return err
	}
	var t interface{ Timeout() bool }
	if errors.As(err, &t) && t.Timeout() {
		return err
	}
	return &Error{Kind: ErrChannelLost, Reason: reason, Err: err, Peer: c.RemoteAddr()}
}

// gate caps concurrent handshakes. Waiters give up when their context ends.
type gate struct {
	mu   sync.Mutex
	n    int
	wake chan struct{}
	// inflight and peak observe the cap in tests.
	inflight atomic.Int64
	peak     atomic.Int64
}

func newGate() *gate { return &gate{wake: make(chan struct{})} }

func (g *gate) acquire(ctx context.Context, limit int) error {
	for {
		g.mu.Lock()
		if g.n < limit {
			g.n++
			g.mu.Unlock()
			cur := g.inflight.Add(1)
			for {
				p := g.peak.Load()
				if cur <= p || g.peak.CompareAndSwap(p, cur) {
					break
				}
			}
			return nil
		}
		wake := g.wake
		g.mu.Unlock()
		select {
		case <-wake:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (g *gate) release() {
	g.inflight.Add(-1)
	g.mu.Lock()
	g.n--
	close(g.wake)
	g.wake = make(chan struct{})
	g.mu.Unlock()
}

// dialGate is shared by all Dial calls of the process: the dialer side of the channel.
var dialGate = newGate()

// cmcConfig builds the per-connection CMC configuration: this zone's attester, mutual
// attestation over mTLS, JSON handshake messages, and a callback bound to this connection only.
func (p *prepared) cmcOptions(rec *recorder) ([]attestedtls.ConnectionOption[attestedtls.CmcConfig], error) {
	ser, err := jsonSerializer()
	if err != nil {
		return nil, err
	}
	opts := []attestedtls.ConnectionOption[attestedtls.CmcConfig]{
		attestedtls.WithAttest(attestedtls.Attest_Mutual),
		attestedtls.WithMtls(true),
		attestedtls.WithSerializer(ser),
		attestedtls.WithResultCb(rec.callback),
	}
	if len(p.policies) > 0 {
		opts = append(opts, attestedtls.WithCmcPolicies(p.policies))
	}
	if p.inProcess != nil {
		opts = append(opts, attestedtls.WithCmcApi("libapi"), attestedtls.WithLibApiCmcConfig(p.inProcess))
	} else {
		opts = append(opts, attestedtls.WithCmcApi("grpc"), attestedtls.WithCmcAddr(p.cmcdAddr))
	}
	return opts, nil
}

// finish applies the verdict rules to a connection CMC completed, resets deadlines, asks the
// PeerVerifier and computes the binding. On every refusal it closes the connection and records
// the peer's address on the error.
func (p *prepared) finish(ctx context.Context, tc *tls.Conn, rec *recorder) (*Conn, error) {
	conn, err := p.accept(ctx, tc, rec)
	if err != nil {
		_ = tc.Close()
		return nil, attribute(err, tc.RemoteAddr())
	}
	return conn, nil
}

// finishWithin runs finish within the handshake deadline: the connection is closed when ctx
// ends, so a PeerVerifier blocked on it is cut short, and an outcome reached after the deadline
// — a success from a verifier that ignores ctx included — is refused as a handshake timeout.
func (p *prepared) finishWithin(ctx context.Context, tc *tls.Conn, rec *recorder) (*Conn, error) {
	if ctx.Err() != nil {
		_ = tc.Close()
		return nil, attribute(timeoutError(ctx), tc.RemoteAddr())
	}
	stop := context.AfterFunc(ctx, func() { _ = tc.Close() })
	conn, err := p.finish(ctx, tc, rec)
	timedOut := !stop()
	if timedOut || ctx.Err() != nil {
		_ = tc.Close()
		return nil, attribute(timeoutError(ctx), tc.RemoteAddr())
	}
	return conn, err
}

// accept is finish without the handling of a refusal.
func (p *prepared) accept(ctx context.Context, tc *tls.Conn, rec *recorder) (*Conn, error) {
	cs := tc.ConnectionState()
	peers := cs.PeerCertificates
	if len(peers) == 0 {
		return nil, refuse(ErrNotAttested, "peer presented no certificate", nil)
	}
	peer, err := judge(rec, peers[0], p.lifetime, time.Now())
	if err != nil {
		return nil, err
	}
	// The TLS verification of this connection matched the certificate against p.expected
	// (verifyPeer); a handshake that got here carries that identity.
	peer.Identity = p.expected
	if p.verifier != nil {
		if err := p.verifier.VerifyPeer(ctx, peer); err != nil {
			return nil, refuse(ErrPeerRejected, "the peer verifier refused the attested peer", err)
		}
	}
	binding, err := cs.ExportKeyingMaterial(bindingLabel, nil, bindingLen)
	if err != nil {
		return nil, refuse(ErrNotAttested, "cannot export the channel binding", textCause(err))
	}
	// CMC leaves its handshake deadline on the connection; clear it for the caller.
	if err := tc.SetDeadline(time.Time{}); err != nil {
		return nil, refuse(ErrNotAttested, "cannot clear the handshake deadline", textCause(err))
	}
	return &Conn{Conn: tc, tls: tc, binding: binding, peer: peer}, nil
}

// Dial opens a mutually attested TLS 1.3 channel to addr. It returns only when the server's
// certificate carries the expected identity, both attestations verified with verdict success,
// the peer's evidence is valid and the PeerVerifier (if any) accepted the peer. The handshake,
// peer verification included, is bounded by ctx and Config.HandshakeTimeout, whichever ends first.
func Dial(ctx context.Context, addr string, cfg Config) (*Conn, error) {
	p, err := cfg.prepare(roleClient)
	if err != nil {
		return nil, err
	}
	ctx, cancel := p.handshakeContext(ctx)
	defer cancel()

	if err := dialGate.acquire(ctx, p.maxConcurrent); err != nil {
		return nil, refuse(ErrHandshakeTimeout, "no handshake slot became free before the deadline", err)
	}
	rec := newRecorder(p.rewrite)
	tlsCfg := p.connTLS(rec)
	opts, err := p.cmcOptions(rec)
	if err != nil {
		dialGate.release()
		return nil, refuse(ErrConfig, "cannot build the attestation configuration", textCause(err))
	}

	type dialed struct {
		conn *Conn
		err  error
	}
	done := make(chan dialed, 1)
	go func() {
		// The slot is held until CMC returns and the connection is finished, so stalled
		// handshakes the caller gave up on and peer verifications still running count against
		// the cap.
		defer dialGate.release()
		c, err := attestedtls.Dial("tcp", addr, tlsCfg, opts...)
		if err != nil {
			refusal := classify(err, rec, false, ctx)
			// CMC v0.9.15 returns no connection with an error, so such a refusal carries no
			// peer address; should it ever return one, close it and name its peer.
			if c != nil {
				refusal.Peer = c.RemoteAddr()
				_ = c.Close()
			}
			done <- dialed{nil, refusal}
			return
		}
		conn, err := p.finishWithin(ctx, c, rec)
		done <- dialed{conn, err}
	}()

	select {
	case d := <-done:
		return d.conn, d.err
	case <-ctx.Done():
		// CMC's attestation phase has no deadline; close whatever it returns later.
		go func() {
			if d := <-done; d.conn != nil {
				_ = d.conn.Close()
			}
		}()
		return nil, timeoutError(ctx)
	}
}
