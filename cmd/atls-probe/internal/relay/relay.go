// Package relay is a man-in-the-middle between a dialing and a listening end of the attested
// channel. It terminates plain TLS 1.3 on both sides with certificates of its own and copies the
// bytes of one session into the other, without reading them.
//
// It speaks TLS through crypto/tls only and takes no part in the attestation: the attestation
// messages pass through it unchanged. Each end therefore receives a report that is bound to a TLS
// session it is not part of — the relay's other session — and must refuse it.
package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/atls-probe/internal/material"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/atls-probe/internal/record"
)

// The RFC 9266 tls-exporter channel binding, as the attested channel derives it.
const (
	bindingLabel = "EXPORTER-Channel-Binding"
	bindingLen   = 32
)

// Config configures a relay run.
type Config struct {
	// Listen is the address the dialing end is pointed at; Upstream the real listener.
	Listen, Upstream string
	// Downstream is the certificate shown to the dialing end, Upstream the one shown to the
	// listener.
	DownstreamCert, UpstreamCert tls.Certificate
	Anchors                      *x509.CertPool
	// AcceptTimeout bounds the wait for the dialing end; HandshakeTimeout each TLS handshake.
	AcceptTimeout, HandshakeTimeout time.Duration
	// Ready, when set, is called with the address the relay listens on.
	Ready func(addr net.Addr)
	// Logf receives progress lines.
	Logf func(format string, args ...any)
}

// Run relays one connection and fills in rec. It returns true when both TLS sessions were up
// and bytes were copied between them.
func Run(ctx context.Context, cfg Config, rec *record.File) (bool, error) {
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	rec.Update(func(r *record.Record) {
		if r.Relay == nil {
			r.Relay = &record.Relay{}
		}
		r.Relay.UpstreamAddr = cfg.Upstream
	})
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return false, fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}
	defer func() { _ = ln.Close() }()
	if cfg.Ready != nil {
		cfg.Ready(ln.Addr())
	}
	logf("relay listening on %s, upstream %s", ln.Addr(), cfg.Upstream)

	// Stop waiting for the dialing end when told to, or after AcceptTimeout.
	actx, cancel := context.WithCancel(ctx)
	if cfg.AcceptTimeout > 0 {
		actx, cancel = context.WithTimeout(ctx, cfg.AcceptTimeout)
	}
	defer cancel()
	stop := context.AfterFunc(actx, func() { _ = ln.Close() })
	raw, err := ln.Accept()
	stop()
	if err != nil {
		rec.Update(func(r *record.Record) { r.Outcome = record.OutcomeNoPeer })
		logf("no dialing end connected: %v", err)
		return false, nil
	}
	defer func() { _ = raw.Close() }()

	anchors := cfg.Anchors
	verify := func(cs tls.ConnectionState, usage x509.ExtKeyUsage) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("peer presented no certificate")
		}
		inter := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
			Roots: anchors, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{usage},
		})
		return err
	}
	curves := []tls.CurveID{tls.CurveP256, tls.CurveP384}

	// Session 1: the dialing end believes it reached the listener.
	down := tls.Server(raw, &tls.Config{
		Certificates:     []tls.Certificate{cfg.DownstreamCert},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: curves,
		ClientAuth:       tls.RequireAnyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error { return verify(cs, x509.ExtKeyUsageClientAuth) },
	})
	hctx, hcancel := context.WithTimeout(ctx, cfg.HandshakeTimeout)
	err = down.HandshakeContext(hctx)
	hcancel()
	rec.Update(func(r *record.Record) {
		r.Relay.Downstream = leg(down, cfg.DownstreamCert, err)
	})
	if err != nil {
		rec.Update(func(r *record.Record) { r.Outcome = record.OutcomeNotRelayed })
		logf("TLS with the dialing end failed: %v", err)
		return false, nil
	}
	logf("TLS session with the dialing end %s is up", down.RemoteAddr())

	// Session 2: the listener believes the dialing end reached it.
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			Certificates:     []tls.Certificate{cfg.UpstreamCert},
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: curves,
			// The listener is identified by its certificate chain, not by the name it was
			// dialled at: the chain is verified below against the zone trust anchors.
			InsecureSkipVerify: true,
			VerifyConnection:   func(cs tls.ConnectionState) error { return verify(cs, x509.ExtKeyUsageServerAuth) },
		},
	}
	hctx, hcancel = context.WithTimeout(ctx, cfg.HandshakeTimeout)
	upConn, err := dialer.DialContext(hctx, "tcp", cfg.Upstream)
	hcancel()
	if err != nil {
		rec.Update(func(r *record.Record) {
			r.Relay.Upstream = record.RelayLeg{PeerAddr: cfg.Upstream, Error: err.Error()}
			r.Outcome = record.OutcomeNotRelayed
		})
		logf("TLS with the listener failed: %v", err)
		return false, nil
	}
	up := upConn.(*tls.Conn)
	defer func() { _ = up.Close() }()
	logf("TLS session with the listener %s is up", up.RemoteAddr())

	started, _ := record.Stamp(time.Now())
	rec.Update(func(r *record.Record) {
		r.Relay.Upstream = leg(up, cfg.UpstreamCert, nil)
		r.Relay.BindingsDiffer = r.Relay.Downstream.Binding != "" && r.Relay.Upstream.Binding != "" &&
			r.Relay.Downstream.Binding != r.Relay.Upstream.Binding
		r.Relay.ForwardingStartedAt = started
		r.LocalAddr = down.LocalAddr().String()
		r.PeerAddr = down.RemoteAddr().String()
	})
	_ = rec.Save()

	// Copy both ways. When one direction ends, both sessions are closed: the relay does not
	// keep a half-open channel alive.
	var toListener, toDialer atomic.Int64
	var once sync.Once
	var because string
	finish := func(reason string) {
		once.Do(func() {
			because = reason
			_ = down.Close()
			_ = up.Close()
		})
	}
	stopCopy := context.AfterFunc(ctx, func() { finish("relay stopped") })
	defer stopCopy()
	var wg sync.WaitGroup
	pipe := func(dst, src *tls.Conn, n *atomic.Int64, from string) {
		defer wg.Done()
		_, err := io.Copy(dst, countingReader{src, n})
		if err != nil {
			finish(fmt.Sprintf("%s: %v", from, err))
			return
		}
		finish(from + " closed its session")
	}
	wg.Add(2)
	go pipe(up, down, &toListener, "the dialing end")
	go pipe(down, up, &toDialer, "the listener")
	wg.Wait()

	ended, _ := record.Stamp(time.Now())
	forwarded := toListener.Load() > 0 && toDialer.Load() > 0
	rec.Update(func(r *record.Record) {
		r.Relay.BytesDialerToListener = toListener.Load()
		r.Relay.BytesListenerToDialer = toDialer.Load()
		r.Relay.ForwardingEndedAt = ended
		r.Relay.ForwardingEndedBecause = because
		r.Outcome = record.OutcomeNotRelayed
		if forwarded {
			r.Outcome = record.OutcomeForwarded
		}
	})
	logf("forwarded %d bytes to the listener and %d bytes to the dialing end; ended because %s",
		toListener.Load(), toDialer.Load(), because)
	return forwarded, nil
}

// leg describes one TLS session of the relay.
func leg(c *tls.Conn, presented tls.Certificate, err error) record.RelayLeg {
	l := record.RelayLeg{
		LocalAddr: c.LocalAddr().String(),
		PeerAddr:  c.RemoteAddr().String(),
	}
	if presented.Leaf != nil {
		l.PresentedFingerprint = material.Fingerprint(presented.Leaf)
		l.PresentedIdentities = material.Identities(presented.Leaf)
	}
	if err != nil {
		l.Error = err.Error()
		return l
	}
	cs := c.ConnectionState()
	l.TLSVersion = tls.VersionName(cs.Version)
	if len(cs.PeerCertificates) > 0 {
		l.PeerFingerprint = material.Fingerprint(cs.PeerCertificates[0])
		l.PeerIdentities = material.Identities(cs.PeerCertificates[0])
	}
	if b, err := cs.ExportKeyingMaterial(bindingLabel, nil, bindingLen); err == nil {
		l.Binding = hex.EncodeToString(b)
	}
	return l
}

type countingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}
