package atls

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// TestErrorTextIgnoresPeer: the peer address is a field of the error and never part of its text.
func TestErrorTextIgnoresPeer(t *testing.T) {
	cause := errors.New("write: broken pipe")
	with := &Error{Kind: ErrPeerAborted, Reason: "the peer left", Err: cause,
		Peer: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 4433}}
	without := &Error{Kind: ErrPeerAborted, Reason: "the peer left", Err: cause}
	if with.Error() != without.Error() {
		t.Fatalf("text with a peer %q, without %q", with.Error(), without.Error())
	}
	if strings.Contains(with.Error(), "192.0.2.7") {
		t.Fatalf("the peer address is in the text: %q", with.Error())
	}
	if want := "atls: peer left before the attestation exchange completed: the peer left: write: broken pipe"; with.Error() != want {
		t.Fatalf("got %q, want %q", with.Error(), want)
	}
}

func TestAttribute(t *testing.T) {
	first := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 4433}
	second := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 8), Port: 4433}

	e := attribute(refuse(ErrPeerRejected, "refused", nil), first)
	if e.Peer != net.Addr(first) || !errors.Is(e, ErrPeerRejected) {
		t.Fatalf("refusal not attributed: %+v", e)
	}
	// An address that is already recorded stays.
	if attribute(e, second).Peer != net.Addr(first) {
		t.Fatal("a recorded peer address was overwritten")
	}
	// An error that is not a refusal never leaves the wrapper bare.
	type foreign struct{ error }
	bare := attribute(foreign{errors.New("something else")}, first)
	assertKind(t, bare, ErrNotAttested)
	if bare.Peer != net.Addr(first) || errors.As(bare, new(foreign)) {
		t.Fatalf("foreign error not reduced to an attributed refusal: %+v", bare)
	}
}
