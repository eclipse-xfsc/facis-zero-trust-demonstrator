package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/atls-probe/internal/material"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/atls-probe/internal/record"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls"
)

// exchangeTimeout bounds the single heartbeat exchange of a run without --hold.
const exchangeTimeout = 10 * time.Second

// sentinels are the sentinels of the wrapper, by name: the refusals, and ErrChannelLost for an
// established channel.
var sentinels = []struct {
	err  error
	name string
}{
	{atls.ErrNotAttested, "ErrNotAttested"},
	{atls.ErrBindingMismatch, "ErrBindingMismatch"},
	{atls.ErrEvidenceExpired, "ErrEvidenceExpired"},
	{atls.ErrIdentityMismatch, "ErrIdentityMismatch"},
	{atls.ErrPlainTLS, "ErrPlainTLS"},
	{atls.ErrPeerAborted, "ErrPeerAborted"},
	{atls.ErrAttestModeMismatch, "ErrAttestModeMismatch"},
	{atls.ErrAttesterUnavailable, "ErrAttesterUnavailable"},
	{atls.ErrHandshakeTimeout, "ErrHandshakeTimeout"},
	{atls.ErrPeerRejected, "ErrPeerRejected"},
	{atls.ErrPeerUnreachable, "ErrPeerUnreachable"},
	{atls.ErrConfig, "ErrConfig"},
	{atls.ErrChannelLost, "ErrChannelLost"},
}

// sentinelName returns the name of the wrapper sentinel err matches, or "".
func sentinelName(err error) string {
	for _, s := range sentinels {
		if errors.Is(err, s.err) {
			return s.name
		}
	}
	return ""
}

// transportKind names the transport error of a read or write failure, also when the wrapper
// reports it as a lost channel: the wrapper's error still matches its cause.
func transportKind(err error) string {
	var alert tls.AlertError
	var netErr net.Error
	switch {
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected-eof"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection-reset"
	case errors.Is(err, syscall.EPIPE):
		return "broken-pipe"
	case errors.Is(err, syscall.ETIMEDOUT):
		return "tcp-timeout"
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "deadline-exceeded"
	case errors.Is(err, net.ErrClosed):
		return "closed"
	case errors.As(err, &alert):
		return "tls-alert"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	default:
		return "other"
	}
}

// channel runs the server or the client mode: one end of the attested channel.
func (p *probe) channel(ctx context.Context, mode string, args []string) int {
	fs := flag.NewFlagSet("atls-probe "+mode, flag.ContinueOnError)
	fs.SetOutput(p.stderr)
	var c common
	c.register(fs)
	cmcd := fs.String("cmcd", "", "`address` (host:port) of this zone's cmcd")
	peerID := fs.String("peer-id", "", "`identity` the peer's certificate must carry, e.g. spiffe://b/gateway")
	hold := fs.Duration("hold", 0, "keep the channel open this long, exchanging heartbeats; 0 exchanges one heartbeat and closes")
	interval := fs.Duration("interval", time.Second, "time between heartbeats while holding")
	handshakeTimeout := fs.Duration("handshake-timeout", 0, "bound of the attested handshake; 0 uses the wrapper's default")
	var addr *string
	sessions := new(int)
	acceptTimeout := new(time.Duration)
	role := "dialer"
	if mode == "server" {
		role = "listener"
		addr = fs.String("listen", "", "`address` to accept the attested channel on")
		sessions = fs.Int("sessions", 1, "handshakes to take before leaving; 0 takes them until stopped")
		acceptTimeout = fs.Duration("accept-timeout", 2*time.Minute, "how long to wait for the first handshake; 0 waits until stopped")
	} else {
		addr = fs.String("connect", "", "`address` of the listening end")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitEstablished
		}
		return exitConfig
	}

	rec := record.New(c.record, mode, role, p.env)
	rec.Update(func(r *record.Record) {
		r.CmcdAddr = *cmcd
		r.ExpectedPeerIdentity = *peerID
		r.HoldMs = hold.Milliseconds()
		r.IntervalMs = interval.Milliseconds()
		if mode == "server" {
			r.ListenAddr = *addr
		} else {
			r.ConnectAddr = *addr
		}
	})

	// Everything is checked before any socket is opened.
	switch {
	case fs.NArg() > 0:
		return p.configError(rec, fmt.Errorf("unexpected argument %q", fs.Arg(0)))
	case c.record == "":
		return p.configError(rec, errors.New("--record is required"))
	case *cmcd == "":
		return p.configError(rec, errors.New("--cmcd is required: the probe attests only through a running cmcd"))
	case *addr == "" && mode == "server":
		return p.configError(rec, errors.New("--listen is required"))
	case *addr == "":
		return p.configError(rec, errors.New("--connect is required"))
	case *peerID == "":
		return p.configError(rec, errors.New("--peer-id is required"))
	case *hold < 0 || *interval <= 0 || *handshakeTimeout < 0 || *sessions < 0 || *acceptTimeout < 0:
		return p.configError(rec, errors.New("--hold, --handshake-timeout, --sessions and --accept-timeout must not be negative; --interval must be positive"))
	}
	m, err := material.Load(c.cert, c.key, c.cas)
	if err != nil {
		return p.configError(rec, err)
	}
	rec.Update(func(r *record.Record) {
		r.CertFingerprint = material.Fingerprint(m.Cert.Leaf)
		r.Identities = material.Identities(m.Cert.Leaf)
	})
	cfg := atls.Config{
		TLS: &tls.Config{
			Certificates: []tls.Certificate{m.Cert},
			RootCAs:      m.Anchors,
			ClientCAs:    m.Anchors,
		},
		CmcdAddr:             *cmcd,
		ExpectedPeerIdentity: *peerID,
		HandshakeTimeout:     *handshakeTimeout,
	}
	h := holder{probe: p, rec: rec, hold: *hold, interval: *interval}

	if mode == "client" {
		return p.dial(ctx, *addr, cfg, &h)
	}
	return p.serve(ctx, *addr, cfg, &h, *sessions, *acceptTimeout)
}

// dial opens one channel and holds it.
func (p *probe) dial(ctx context.Context, addr string, cfg atls.Config, h *holder) int {
	rec := h.rec
	i := rec.NextSession()
	began := time.Now()
	rec.UpdateSession(i, func(s *record.Session) {
		s.HandshakeStartedAt, _ = record.Stamp(began)
		s.PeerAddr = addr
	})
	_ = rec.Save()
	p.logf("dialing %s through cmcd %s, expecting %s", addr, cfg.CmcdAddr, cfg.ExpectedPeerIdentity)

	conn, err := atls.Dial(ctx, addr, cfg)
	took := time.Since(began).Milliseconds()
	if err != nil {
		if errors.Is(err, atls.ErrConfig) {
			return p.configError(rec, err)
		}
		p.refused(rec, i, err)
		rec.UpdateSession(i, func(s *record.Session) { s.HandshakeMs = took })
		return p.finish(rec, exitNoChannel)
	}
	p.established(rec, i, conn)
	rec.UpdateSession(i, func(s *record.Session) { s.HandshakeMs = took })
	_ = rec.Save()
	h.run(ctx, i, conn)
	return p.finish(rec, exitEstablished)
}

// serve takes handshakes until the configured number was taken or the run is stopped, and holds
// every channel that was established.
func (p *probe) serve(ctx context.Context, addr string, cfg atls.Config, h *holder, sessions int, acceptTimeout time.Duration) int {
	rec := h.rec
	ln, err := atls.Listen(addr, cfg)
	if err != nil {
		return p.configError(rec, err)
	}
	defer func() { _ = ln.Close() }()
	rec.Update(func(r *record.Record) { r.ListenAddr = ln.Addr().String() })
	_ = rec.Save()
	p.logf("listening on %s through cmcd %s, expecting %s", ln.Addr(), cfg.CmcdAddr, cfg.ExpectedPeerIdentity)

	var wg sync.WaitGroup
	for taken := 0; sessions == 0 || taken < sessions; taken++ {
		actx, cancel := ctx, context.CancelFunc(func() {})
		if taken == 0 && acceptTimeout > 0 {
			actx, cancel = context.WithTimeout(ctx, acceptTimeout)
		}
		conn, err := ln.Accept(actx)
		cancel()
		if err != nil && sentinelName(err) == "" {
			// Not a refusal: the run was stopped, or nobody came.
			if ctx.Err() == nil {
				p.logf("no handshake within %s", acceptTimeout)
			}
			break
		}
		i := rec.NextSession()
		if err != nil {
			p.refused(rec, i, err)
			rec.UpdateSession(i, func(s *record.Session) {
				s.LocalAddr = ln.Addr().String()
				// A refusal returned by Accept names the address of the refused peer.
				var refusal *atls.Error
				if errors.As(err, &refusal) && refusal.Peer != nil {
					s.PeerAddr = refusal.Peer.String()
				}
			})
			_ = rec.Save()
			continue
		}
		p.established(rec, i, conn)
		_ = rec.Save()
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.run(ctx, i, conn)
			_ = rec.Save()
		}()
	}
	wg.Wait()

	first := rec.Snapshot()
	switch {
	case rec.Sessions() == 0:
		rec.Update(func(r *record.Record) { r.Outcome = record.OutcomeNoPeer })
		return p.finish(rec, exitNoChannel)
	case first.Outcome == record.OutcomeEstablished:
		return p.finish(rec, exitEstablished)
	default:
		return p.finish(rec, exitNoChannel)
	}
}

// established records a returned channel.
func (p *probe) established(rec *record.File, i int, conn *atls.Conn) {
	now := time.Now()
	peer := conn.Peer()
	binding := conn.Binding()
	rec.UpdateSession(i, func(s *record.Session) {
		s.Outcome = record.OutcomeEstablished
		s.LocalAddr = conn.LocalAddr().String()
		s.PeerAddr = conn.RemoteAddr().String()
		s.EstablishedAt, s.EstablishedAtUnixMs = record.Stamp(now)
		s.Binding = hex.EncodeToString(binding)
		s.BindingBytes = len(binding)
		s.PeerFingerprint = peer.PeerID
		s.Verdict = string(peer.Verdict)
		s.AttestedAt, _ = record.Stamp(peer.AttestedAt)
		if !peer.EvidenceNotAfter.IsZero() {
			s.EvidenceNotAfter, _ = record.Stamp(peer.EvidenceNotAfter)
		}
		s.ValidUntil, _ = record.Stamp(peer.ValidUntil)
		for _, m := range peer.Measurements {
			s.Measurements = append(s.Measurements, record.Measurement{
				Evidence: m.Evidence, Name: m.Name, Index: m.Index, Digest: m.Digest, HashAlg: m.HashAlg,
			})
		}
	})
	p.logf("session %d established with %s: binding %s, peer %s, verdict %s, valid until %s",
		i, conn.RemoteAddr(), hex.EncodeToString(binding), peer.PeerID, peer.Verdict,
		peer.ValidUntil.UTC().Format(time.RFC3339))
}

// refused records a handshake that returned no channel.
func (p *probe) refused(rec *record.File, i int, err error) {
	now := time.Now()
	name := sentinelName(err)
	rec.UpdateSession(i, func(s *record.Session) {
		s.Outcome = record.OutcomeRefused
		s.Refusal = &record.Refusal{Sentinel: name, Message: err.Error()}
		s.RefusedAt, s.RefusedAtUnixMs = record.Stamp(now)
		s.EndedAt, s.EndedAtUnixMs = s.RefusedAt, s.RefusedAtUnixMs
		s.Ended = record.EndedRefused
	})
	if name == "" {
		name = "no wrapper sentinel"
	}
	p.logf("session %d refused (%s): %v", i, name, err)
}

// holder keeps established channels open and records how they end.
type holder struct {
	probe    *probe
	rec      *record.File
	hold     time.Duration
	interval time.Duration
}

type ioFailure struct {
	op  string
	err error
	at  time.Time
}

// run exchanges heartbeats on conn until the hold time is over, the peer leaves, a read or
// write fails, or the run is stopped. Without a hold time it exchanges one heartbeat each way.
// It closes conn.
func (h *holder) run(ctx context.Context, i int, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	established := time.Now()
	lastPeer := established

	failures := make(chan ioFailure, 2)
	heard := make(chan time.Time)
	wrote := make(chan struct{}, 1) // the first heartbeat of this end is on its way
	done := make(chan struct{})
	defer close(done)

	// Reader: one line per heartbeat of the peer.
	go func() {
		br := bufio.NewReader(conn)
		for {
			line, err := br.ReadString('\n')
			if n := len(line); n > 0 {
				now := time.Now()
				h.rec.UpdateSession(i, func(s *record.Session) { s.ApplicationBytesReceived += int64(n) })
				if err == nil {
					select {
					case heard <- now:
					case <-done:
						return
					}
				}
			}
			if err != nil {
				failures <- ioFailure{"read", err, time.Now()}
				return
			}
		}
	}()

	// Writer: a heartbeat at once, then one per interval. It runs apart from the loop below
	// because a write can block once the peer stops reading.
	go func() {
		tick := time.NewTicker(h.interval)
		defer tick.Stop()
		for seq := int64(1); ; seq++ {
			msg := fmt.Sprintf("heartbeat %d %d\n", seq, time.Now().UnixMilli())
			n, err := conn.Write([]byte(msg))
			h.rec.UpdateSession(i, func(s *record.Session) {
				s.ApplicationBytesSent += int64(n)
				if err == nil {
					s.Heartbeats.Sent++
				}
			})
			if err != nil {
				failures <- ioFailure{"write", err, time.Now()}
				return
			}
			if seq == 1 {
				wrote <- struct{}{}
			}
			if h.hold == 0 {
				return
			}
			select {
			case <-tick.C:
			case <-done:
				return
			}
		}
	}()

	limit := h.hold
	if limit == 0 {
		limit = exchangeTimeout
	}
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	snapshot := time.NewTicker(h.interval)
	defer snapshot.Stop()

	gap := func(now time.Time) {
		d := now.Sub(lastPeer).Milliseconds()
		h.rec.UpdateSession(i, func(s *record.Session) { s.Heartbeats.MaxGapMs = max(s.Heartbeats.MaxGapMs, d) })
	}
	end := func(how string, f *ioFailure) {
		now := time.Now()
		gap(now)
		h.rec.UpdateSession(i, func(s *record.Session) {
			s.Ended = how
			s.EndedAt, s.EndedAtUnixMs = record.Stamp(now)
			if f == nil {
				return
			}
			e := &record.IOError{
				Op:                       f.op,
				Message:                  f.err.Error(),
				Kind:                     "transport",
				Transport:                transportKind(f.err),
				SinceEstablishedMs:       f.at.Sub(established).Milliseconds(),
				SinceLastPeerHeartbeatMs: f.at.Sub(lastPeer).Milliseconds(),
			}
			if name := sentinelName(f.err); name != "" {
				e.Kind, e.Sentinel = "sentinel", name
				// A lost channel keeps the transport error it wraps; no other sentinel has one.
				if !errors.Is(f.err, atls.ErrChannelLost) {
					e.Transport = ""
				}
			}
			e.DetectedAt, e.DetectedAtUnixMs = record.Stamp(f.at)
			s.Error = e
		})
		if f != nil {
			h.probe.logf("session %d ended (%s): %s failed after %s: %v", i, how, f.op,
				f.at.Sub(established).Round(time.Millisecond), f.err)
		} else {
			h.probe.logf("session %d ended (%s) after %s", i, how, now.Sub(established).Round(time.Millisecond))
		}
	}

	// Without a hold time the session is over once this end's heartbeat was written and the
	// peer's was read; neither end closes before both happened.
	received, sent := int64(0), false
	exchanged := func() bool { return h.hold == 0 && sent && received > 0 }
	for {
		select {
		case at := <-heard:
			gap(at)
			lastPeer = at
			received++
			h.rec.UpdateSession(i, func(s *record.Session) {
				s.Heartbeats.Received = received
				s.Heartbeats.LastReceivedAt, s.Heartbeats.LastReceivedAtUnixMs = record.Stamp(at)
			})
			if exchanged() {
				end(record.EndedExchangeComplete, nil)
				return
			}
		case <-wrote:
			sent = true
			if exchanged() {
				end(record.EndedExchangeComplete, nil)
				return
			}
		case f := <-failures:
			if h.hold == 0 && received > 0 && !sent && errors.Is(f.err, io.EOF) {
				// The peer left after reading this end's heartbeat, so the write is done; its
				// signal may only not have been taken yet.
				select {
				case <-wrote:
					sent = true
				case <-time.After(time.Second):
				}
			}
			switch {
			case exchanged() && errors.Is(f.err, io.EOF):
				// The single exchange is over and the peer closed first.
				end(record.EndedExchangeComplete, nil)
			case f.op == "read" && errors.Is(f.err, io.EOF):
				end(record.EndedPeerClosed, &f)
			default:
				end(record.EndedError, &f)
			}
			return
		case <-snapshot.C:
			gap(time.Now())
			_ = h.rec.Save()
		case <-deadline.C:
			if h.hold == 0 {
				f := ioFailure{"read", fmt.Errorf("no heartbeat from the peer within %s", exchangeTimeout), time.Now()}
				end(record.EndedError, &f)
				return
			}
			end(record.EndedHoldElapsed, nil)
			return
		case <-ctx.Done():
			end(record.EndedSignal, nil)
			return
		}
	}
}
