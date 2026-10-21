package atls

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// Accept re-checks ValidUntil when it takes a connection, covering the instant in which the
// delivery wins against the expiry timer of the connection's goroutine.
func TestAcceptRefusesConnectionPastValidUntil(t *testing.T) {
	past := time.Now().Add(-time.Second)
	for name, tc := range map[string]struct {
		peer PeerAttestation
		want error
	}{
		"evidence ended":            {PeerAttestation{ValidUntil: past, EvidenceNotAfter: past}, ErrEvidenceExpired},
		"channel lifetime ended":    {PeerAttestation{ValidUntil: past, EvidenceNotAfter: past.Add(time.Hour)}, ErrHandshakeTimeout},
		"no evidence end, lifetime": {PeerAttestation{ValidUntil: past}, ErrHandshakeTimeout},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			l := &Listener{ready: make(chan *Conn), refusals: make(chan error, 1), ctx: ctx}
			ours, theirs := net.Pipe()
			defer func() { _ = theirs.Close() }()
			go func() { l.ready <- &Conn{Conn: ours, peer: tc.peer} }()

			c, err := l.Accept(context.Background())
			if c != nil || !errors.Is(err, tc.want) {
				t.Fatalf("Accept returned %v, %v; want a refusal matching %v", c, err, tc.want)
			}
			var e *Error
			if !errors.As(err, &e) || e.Peer == nil {
				t.Fatalf("refusal %v names no peer", err)
			}
			if _, err := theirs.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("connection not closed: read returned %v", err)
			}
		})
	}
}

func TestAcceptReturnsConnectionInTime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &Listener{ready: make(chan *Conn), refusals: make(chan error, 1), ctx: ctx}
	ours, theirs := net.Pipe()
	defer func() { _ = ours.Close(); _ = theirs.Close() }()
	until := time.Now().Add(time.Minute)
	go func() { l.ready <- &Conn{Conn: ours, peer: PeerAttestation{ValidUntil: until}} }()
	c, err := l.Accept(context.Background())
	if err != nil || !c.Peer().ValidUntil.Equal(until) {
		t.Fatalf("Accept returned %v, %v", c, err)
	}
}
