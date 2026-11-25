// Package connectorgateway carries opaque application streams through an attested
// inter-zone channel. HTTP authorities, headers, bodies, gRPC frames and trailers
// stay byte-for-byte intact; only the two in-zone legs use the local mesh transport.
package connectorgateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls"
)

type Config struct {
	Role         string `json:"role"`
	Listen       string `json:"listen"`
	Target       string `json:"target"`
	Certificate  string `json:"certificate"`
	Key          string `json:"key"`
	CA           string `json:"ca"`
	Cmcd         string `json:"cmcd"`
	PeerIdentity string `json:"peerIdentity"`
}

// Attestation loads credentials from mounted files. There is deliberately no
// plain TLS, insecure verification or non-mutual mode switch.
func (c Config) Attestation() (atls.Config, error) {
	cert, err := tls.LoadX509KeyPair(c.Certificate, c.Key)
	if err != nil {
		return atls.Config{}, fmt.Errorf("load gateway certificate: %w", err)
	}
	pem, err := os.ReadFile(c.CA)
	if err != nil {
		return atls.Config{}, fmt.Errorf("load gateway trust: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return atls.Config{}, errors.New("gateway trust contains no certificate")
	}
	return atls.Config{TLS: &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, ClientCAs: roots}, CmcdAddr: c.Cmcd, ExpectedPeerIdentity: c.PeerIdentity}, nil
}

// Event records a channel decision, never application metadata or credentials.
// Record callbacks must be concurrency safe.
type Event struct {
	Role       string `json:"role"`
	Decision   string `json:"decision"`
	Reason     string `json:"reason"`
	Peer       string `json:"peer,omitempty"`
	Binding    string `json:"binding,omitempty"`
	TLSVersion uint16 `json:"tlsVersion,omitempty"`
}
type Record func(Event)

type Gateway struct {
	addr   net.Addr
	cancel context.CancelFunc
	done   chan struct{}
}

func (g *Gateway) Addr() net.Addr { return g.addr }
func (g *Gateway) Close() error   { g.cancel(); <-g.done; return nil }

// Start starts exactly one role. An ingress never exposes a raw application
// listener, and an egress has only atls.Dial as its inter-connector dial path.
func Start(parent context.Context, c Config, att atls.Config, record Record) (*Gateway, error) {
	if c.Role != "ingress" && c.Role != "egress" {
		return nil, errors.New("role must be ingress or egress")
	}
	if _, _, err := net.SplitHostPort(c.Target); err != nil {
		return nil, fmt.Errorf("target: %w", err)
	}
	if att.Mode != atls.ModeMutual {
		return nil, errors.New("gateway requires mutual attestation")
	}
	if record == nil {
		return nil, errors.New("gateway requires a decision recorder")
	}
	// Validate even the egress configuration before accepting local connections.
	probe, err := atls.Listen("127.0.0.1:0", att)
	if err != nil {
		return nil, err
	}
	_ = probe.Close()
	ctx, cancel := context.WithCancel(parent)
	var addr net.Addr
	var accept func() (net.Conn, error)
	var closeListener func() error
	if c.Role == "ingress" {
		ln, e := atls.Listen(c.Listen, att)
		if e != nil {
			cancel()
			return nil, e
		}
		addr, closeListener = ln.Addr(), ln.Close
		accept = func() (net.Conn, error) { return ln.Accept(ctx) }
	} else {
		ln, e := net.Listen("tcp", c.Listen)
		if e != nil {
			cancel()
			return nil, e
		}
		addr, closeListener, accept = ln.Addr(), ln.Close, ln.Accept
	}
	g := &Gateway{addr: addr, cancel: cancel, done: make(chan struct{})}
	stop := context.AfterFunc(ctx, func() { _ = closeListener() })
	go func() {
		defer close(g.done)
		defer stop()
		defer func() { _ = closeListener() }()
		var wg sync.WaitGroup
		defer wg.Wait()
		slots := make(chan struct{}, 128)
		for {
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				return
			}
			conn, e := accept()
			if e != nil {
				<-slots
				if ctx.Err() != nil || errors.Is(e, net.ErrClosed) {
					return
				}
				refusal(record, c.Role, e)
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-slots }()
				forward(ctx, c, att, conn, record)
			}()
		}
	}()
	return g, nil
}

func refusal(record Record, role string, err error) {
	reason := "upstream_unavailable"
	var e *atls.Error
	if errors.As(err, &e) {
		reason = e.Kind.Error()
	}
	record(Event{Role: role, Decision: "refused", Reason: reason})
}

func forward(ctx context.Context, cfg Config, att atls.Config, incoming net.Conn, record Record) {
	defer func() { _ = incoming.Close() }()
	stopIncoming := context.AfterFunc(ctx, func() { _ = incoming.Close() })
	defer stopIncoming()
	var protected *atls.Conn
	var outgoing net.Conn
	var err error
	if cfg.Role == "egress" {
		protected, err = atls.Dial(ctx, cfg.Target, att)
		if err == nil {
			outgoing = protected
		}
	} else {
		protected = incoming.(*atls.Conn) // only atls.Listener.Accept supplies this role
		outgoing, err = (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", cfg.Target)
	}
	if err != nil {
		refusal(record, cfg.Role, err)
		return
	}
	defer func() { _ = outgoing.Close() }()
	stopOutgoing := context.AfterFunc(ctx, func() { _ = outgoing.Close() })
	defer stopOutgoing()
	// Bound pooled HTTP/2 streams as well as fresh connections by the verdict lifetime.
	expiry := time.AfterFunc(time.Until(protected.Peer().ValidUntil), func() {
		record(Event{Role: cfg.Role, Decision: "refused", Reason: "channel_expired"})
		_ = incoming.Close()
		_ = outgoing.Close()
	})
	defer expiry.Stop()
	record(Event{Role: cfg.Role, Decision: "established", Reason: "mutual_attestation", Peer: protected.Peer().Identity, Binding: hex.EncodeToString(protected.Binding()), TLSVersion: protected.ConnectionState().Version})
	done := make(chan struct{})
	go func() { relay(outgoing, incoming); close(done) }()
	relay(incoming, outgoing)
	_ = incoming.Close()
	<-done
}

// Preserve TCP half-closes so a request EOF does not discard the reply.
func relay(dst, src net.Conn) {
	_, err := io.Copy(dst, src)
	raw := dst
	if c, ok := dst.(*atls.Conn); ok {
		raw = c.Conn
	}
	if cw, ok := raw.(interface{ CloseWrite() error }); ok && err == nil {
		_ = cw.CloseWrite()
	} else {
		_ = dst.Close()
	}
}
