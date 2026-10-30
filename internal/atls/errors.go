package atls

import (
	"errors"
	"net"
	"strings"
)

// Sentinels. Every refused channel returns an *Error whose Kind is exactly one of the refusal
// sentinels, so callers match with errors.Is. The Reason of the *Error states the cause in
// words. ErrChannelLost is the one sentinel that is not a refusal: it reports the loss of a
// channel that was established.
var (
	// ErrNotAttested: the peer's attestation did not verify with verdict success. Covers a failed
	// verification, a warn verdict, a missing result, and a peer that reports it could not verify
	// this end.
	ErrNotAttested = errors.New("atls: peer not attested")

	// ErrBindingMismatch: the peer's attestation report is not bound to this TLS session (for
	// example a report relayed from another session).
	ErrBindingMismatch = errors.New("atls: attestation report not bound to this TLS session")

	// ErrEvidenceExpired: the peer's evidence is past its validity.
	ErrEvidenceExpired = errors.New("atls: peer evidence expired")

	// ErrIdentityMismatch: the peer's certificate does not chain to the zone trust anchors, does
	// not carry the expected identity, uses a key algorithm outside the crypto baseline, or the
	// peer refused this end's certificate.
	ErrIdentityMismatch = errors.New("atls: peer certificate identity rejected")

	// ErrPlainTLS: the peer does not speak attested TLS 1.3 — a plain TLS peer, a peer limited
	// to TLS 1.2 or older, or a peer whose first attestation message is malformed.
	ErrPlainTLS = errors.New("atls: peer does not speak attested TLS 1.3")

	// ErrPeerAborted: the peer completed TLS 1.3 with a valid zone certificate and left before
	// the attestation exchange completed. Typically the peer's attester is down; a TLS 1.3
	// client holding a zone certificate that never speaks attestation looks the same.
	ErrPeerAborted = errors.New("atls: peer left before the attestation exchange completed")

	// ErrAttestModeMismatch: the peer requested an attestation mode other than mutual.
	ErrAttestModeMismatch = errors.New("atls: attestation mode mismatch")

	// ErrAttesterUnavailable: this zone's attester (cmcd) could not be reached or failed.
	ErrAttesterUnavailable = errors.New("atls: local attester unavailable")

	// ErrHandshakeTimeout: the handshake did not finish within the caller's deadline or the
	// configured handshake timeout, or no handshake slot became free in time.
	ErrHandshakeTimeout = errors.New("atls: handshake timed out")

	// ErrPeerRejected: the configured PeerVerifier refused the attested peer. The verifier's
	// error is wrapped and remains inspectable with errors.Is and errors.As.
	ErrPeerRejected = errors.New("atls: peer rejected by verifier")

	// ErrPeerUnreachable: no TCP connection to the peer could be opened. This is a transport
	// failure before any TLS or attestation exchange, not a refusal by either side.
	ErrPeerUnreachable = errors.New("atls: peer unreachable")

	// ErrConfig: the Config is invalid; no connection was attempted.
	ErrConfig = errors.New("atls: invalid configuration")

	// ErrChannelLost: a Read or Write on an established channel failed with an error other than
	// io.EOF or a timeout — a connection reset, a broken pipe, a TLS alert, or use of a channel
	// that was closed. The cause is wrapped and stays inspectable with errors.Is and errors.As.
	// A peer that closes the channel or whose process dies surfaces as io.EOF, not as this.
	ErrChannelLost = errors.New("atls: channel lost")
)

// Error is the error type returned for every refusal, every configuration error and every lost
// channel.
type Error struct {
	// Kind is the sentinel the error matches.
	Kind error
	// Reason states the cause in words.
	Reason string
	// Err is the underlying cause, if any. Causes from the attestation library are reduced to
	// their text; a PeerVerifier error, context errors and the transport error of a lost
	// channel are kept as they are.
	Err error
	// Peer is the transport address of the peer's end of the connection the error is about. It
	// is set on every refusal Accept returns and on a lost channel, and on a refusal Dial returns
	// once a connection existed. It is nil when no connection existed: a configuration error
	// from Dial or Listen, an unreachable peer, a handshake that timed out in Dial. It is an
	// address, not an identity, and it is not part of the Error text.
	Peer net.Addr
}

// Error returns the sentinel's text, the reason and the cause. Peer is not part of it.
func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString(e.Kind.Error())
	if e.Reason != "" {
		b.WriteString(": ")
		b.WriteString(e.Reason)
	}
	if e.Err != nil {
		b.WriteString(": ")
		b.WriteString(e.Err.Error())
	}
	return b.String()
}

// Unwrap exposes the sentinel and the cause to errors.Is and errors.As.
func (e *Error) Unwrap() []error {
	if e.Err == nil {
		return []error{e.Kind}
	}
	return []error{e.Kind, e.Err}
}

func refuse(kind error, reason string, cause error) *Error {
	return &Error{Kind: kind, Reason: reason, Err: cause}
}

// attribute records the transport address of the refused connection on a refusal that does not
// carry one yet. An error that is not an *Error — none is expected — becomes a refusal as not
// attested, so that no bare error leaves the wrapper.
func attribute(err error, peer net.Addr) *Error {
	var e *Error
	if !errors.As(err, &e) {
		e = refuse(ErrNotAttested, "the handshake failed", textCause(err))
	}
	if e.Peer == nil {
		e.Peer = peer
	}
	return e
}

// textCause reduces an error from the attestation library to its text, so no library error type
// leaves the wrapper.
func textCause(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(err.Error())
}
