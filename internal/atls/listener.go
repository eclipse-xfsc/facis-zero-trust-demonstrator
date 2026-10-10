package atls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Fraunhofer-AISEC/cmc/attestedtls"
)

// refusalBuffer bounds how many refusals wait for Accept. Further refusals are dropped (the
// connection is closed either way), so a flood of bad peers cannot pile up goroutines while
// the caller is not accepting.
const refusalBuffer = 64

// Listener accepts mutually attested TLS 1.3 channels. Each incoming connection is handshaken in
// its own goroutine, at most Config.MaxConcurrentHandshakes at a time, so one slow peer does not
// delay the others. The listener takes a handshake slot before it accepts a TCP connection: while
// every slot is busy, further connections wait in the kernel backlog and cost the process nothing.
type Listener struct {
	ln       net.Listener
	p        *prepared
	gate     *gate
	ready    chan *Conn
	refusals chan error
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	once     sync.Once
}

// Listen listens on the TCP address addr for attested channels. An invalid cfg is reported as an
// *Error matching ErrConfig; a failure to open the address is the error of package net, wrapped,
// and not an *Error.
func Listen(addr string, cfg Config) (*Listener, error) {
	p, err := cfg.prepare(roleServer)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("atls: listen on %s: %w", addr, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &Listener{
		ln:       ln,
		p:        p,
		gate:     newGate(),
		ready:    make(chan *Conn),
		refusals: make(chan error, refusalBuffer),
		ctx:      ctx,
		cancel:   cancel,
	}
	l.wg.Add(1)
	go l.serve()
	return l, nil
}

// Accept returns the next attested connection. A refused connection is reported as an *Error
// matching one of the refusal sentinels and carrying the address of the refused peer; the
// listener stays open and Accept can be called again. A connection whose ValidUntil has passed
// before Accept takes it is closed and refused. Two errors are not an *Error: ctx.Err() when ctx
// ends first, and net.ErrClosed after Close.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	select {
	case c := <-l.ready:
		// The delivery may win the race against the connection's expiry timer in handle.
		if !time.Now().Before(c.peer.ValidUntil) {
			_ = c.Close()
			return nil, attribute(expired(c.peer), c.RemoteAddr())
		}
		return c, nil
	case err := <-l.refusals:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Close stops accepting, aborts handshakes in progress and waits for them to end. Connections
// already returned by Accept stay open.
func (l *Listener) Close() error {
	var err error
	l.once.Do(func() {
		l.cancel()
		err = l.ln.Close()
		l.wg.Wait()
	})
	return err
}

func (l *Listener) serve() {
	defer l.wg.Done()
	var backoff time.Duration
	for {
		// Take the slot first, so a connection is only accepted when it can be handshaken at
		// once. The slot belongs to handle from here on.
		if err := l.gate.acquire(l.ctx, l.p.maxConcurrent); err != nil {
			return
		}
		raw, err := l.ln.Accept()
		if err != nil {
			l.gate.release()
			if l.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			// Transient accept failure (for example out of file descriptors): back off.
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			select {
			case <-time.After(backoff):
			case <-l.ctx.Done():
				return
			}
			continue
		}
		backoff = 0
		l.wg.Add(1)
		go l.handle(raw)
	}
}

// handle owns the handshake slot serve took for raw. It keeps the slot until the connection is
// delivered to Accept or closed, so the connections the listener holds never exceed the cap.
func (l *Listener) handle(raw net.Conn) {
	defer l.wg.Done()
	defer l.gate.release()
	ctx, cancel := l.p.handshakeContext(l.ctx)
	defer cancel()
	// Every refusal Accept returns names the transport address of the connection it refused.
	peer := raw.RemoteAddr()

	conn, err := l.handshake(ctx, raw)
	cancel()
	if err != nil {
		l.refused(attribute(err, peer))
		return
	}
	// Deliver the connection to Accept, unless its validity ends first: then close it and report
	// the refusal, so no caller receives a channel whose ValidUntil has passed.
	expiry := time.NewTimer(time.Until(conn.peer.ValidUntil))
	defer expiry.Stop()
	select {
	case l.ready <- conn:
	case <-expiry.C:
		_ = conn.Close()
		l.refused(attribute(expired(conn.peer), peer))
	case <-l.ctx.Done():
		_ = conn.Close()
	}
}

// expired is the refusal of a handshaken connection whose ValidUntil passed before Accept took
// it: evidence expired when the peer's evidence validity set ValidUntil, a handshake timeout when
// the channel lifetime did.
func expired(p PeerAttestation) *Error {
	if !p.EvidenceNotAfter.IsZero() && !p.EvidenceNotAfter.After(p.ValidUntil) {
		return refuse(ErrEvidenceExpired, fmt.Sprintf("peer evidence expired at %s before Accept took the connection",
			p.EvidenceNotAfter.UTC().Format(time.RFC3339)), nil)
	}
	return refuse(ErrHandshakeTimeout, fmt.Sprintf("the channel lifetime ended at %s before Accept took the connection",
		p.ValidUntil.UTC().Format(time.RFC3339)), nil)
}

// handshake runs CMC's server-side attestation on one raw connection through a one-shot CMC
// listener with this connection's own CMC and TLS configuration.
func (l *Listener) handshake(ctx context.Context, raw net.Conn) (*Conn, error) {
	rec := newRecorder(l.p.rewrite)
	tlsCfg := l.p.connTLS(rec)
	opts, err := l.p.cmcOptions(rec)
	if err != nil {
		_ = raw.Close()
		return nil, refuse(ErrConfig, "cannot build the attestation configuration", textCause(err))
	}
	cc, err := attestedtls.NewCmcConfig(opts...)
	if err != nil {
		_ = raw.Close()
		return nil, refuse(ErrConfig, "cannot build the attestation configuration", textCause(err))
	}
	tc := tls.Server(raw, tlsCfg)
	cmcLn := attestedtls.Listener{Listener: &oneShot{conn: tc, addr: l.ln.Addr()}, CmcConfig: cc, Config: tlsCfg}

	// Bound the whole server handshake: closing the connection unblocks CMC's reads and writes.
	stop := context.AfterFunc(ctx, func() { _ = tc.Close() })
	c, err := cmcLn.Accept()
	timedOut := !stop()

	if err != nil {
		_ = tc.Close()
		return nil, classify(err, rec, timedOut, ctx)
	}
	if timedOut || c != net.Conn(tc) {
		_ = tc.Close()
		return nil, timeoutError(ctx)
	}
	// The verdict, the PeerVerifier and the binding count within the deadline and the slot,
	// which handle holds until the connection is delivered.
	return l.p.finishWithin(ctx, tc, rec)
}

func (l *Listener) refused(err error) {
	select {
	case l.refusals <- err:
	default:
		// Nobody is accepting; the refusal is dropped, the connection is already closed.
	}
}

// oneShot is a net.Listener that yields one connection, then reports itself closed. It lets CMC's
// Listener.Accept handshake exactly one connection that the wrapper accepted.
type oneShot struct {
	mu   sync.Mutex
	conn net.Conn
	addr net.Addr
}

func (o *oneShot) Accept() (net.Conn, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.conn == nil {
		return nil, net.ErrClosed
	}
	c := o.conn
	o.conn = nil
	return c, nil
}

func (o *oneShot) Close() error   { return nil }
func (o *oneShot) Addr() net.Addr { return o.addr }
