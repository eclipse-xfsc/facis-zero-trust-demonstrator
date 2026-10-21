package atls

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

// classify turns a failed CMC handshake into one refusal. Sources, in order: timeout and context
// state, the wrapper's own identity check, the typed error codes of this connection's
// attestation result, then the text of the CMC error. Every text pattern below is pinned by a
// test against CMC v0.9.15 (classify_test.go), so an upgrade that rewords an error fails loudly
// instead of silently changing the refusal.
func classify(cmcErr error, rec *recorder, timedOut bool, ctx context.Context) *Error {
	if timedOut || ctx.Err() != nil {
		return timeoutError(ctx)
	}
	if err := rec.identityErr(); err != nil {
		return refuse(ErrIdentityMismatch, "peer certificate rejected", err)
	}
	if res := rec.lastFailed(); res != nil {
		return fromResult(res)
	}
	results, _ := rec.snapshot()
	return fromTextWith(cmcErr, len(results) > 0)
}

func timeoutError(ctx context.Context) *Error {
	if err := ctx.Err(); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return refuse(ErrHandshakeTimeout, "handshake aborted", err)
	}
	return refuse(ErrHandshakeTimeout, "handshake did not finish before the deadline", nil)
}

// fromResult classifies a failed or warn attestation result by its typed error codes.
func fromResult(res *ar.AttestationResult) *Error {
	codes := resultCodes(res)
	switch {
	case res.Freshness.Status == ar.StatusFail || slices.Contains(codes, ar.Freshness):
		return refuse(ErrBindingMismatch,
			"the peer's report nonce does not match this TLS session's channel binding", nil)
	case metadataExpired(res):
		return refuse(ErrEvidenceExpired, "the peer's evidence is past its validity", nil)
	default:
		return refuse(ErrNotAttested,
			fmt.Sprintf("attestation verdict %q with error codes %s", res.Summary.Status, codeList(codes)), nil)
	}
}

func resultCodes(res *ar.AttestationResult) []ar.ErrorCode {
	return slices.Concat(res.Summary.ErrorCodes, res.Freshness.ErrorCodes)
}

func codeList(codes []ar.ErrorCode) string {
	if len(codes) == 0 {
		return "[]"
	}
	parts := make([]string, len(codes))
	for i, c := range codes {
		parts[i] = c.String()
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// metadataExpired reports whether any metadata item failed its validity check as expired.
func metadataExpired(res *ar.AttestationResult) bool {
	expired := func(m *ar.MetadataResult) bool {
		return m != nil && slices.Contains(m.ValidityCheck.ErrorCodes, ar.Expired)
	}
	if expired(&res.Metadata.ImageDescriptionResult) || expired(res.Metadata.CompanyDescriptionResult) {
		return true
	}
	for i := range res.Metadata.ManifestResults {
		if expired(&res.Metadata.ManifestResults[i]) {
			return true
		}
	}
	return false
}

// Markers after which CMC embeds text the peer sent. Text past them is the peer's account and
// never decides whether the local attester, TLS or a timeout failed.
var peerTextMarkers = []string{
	"atls response returned error:", // attestation.go: the peer's response carried an error
	"reports failed attestation:",   // attestation.go: the peer's handshake-complete said failure
}

type textRule struct {
	kind     error
	reason   string
	patterns []string
	// whole matches the full message, peer text included.
	whole bool
	// completeStage marks failures of the final handshake-complete exchange; they apply only
	// when this side holds no attestation result.
	completeStage bool
}

// textRules are checked in order; the first match wins. Patterns are CMC v0.9.15 texts from
// attestedtls (attestation.go, dialer.go, listener.go, backend.go, grpc.go, libapi.go) and
// crypto/tls / net texts they wrap.
var textRules = []textRule{
	{kind: ErrAttesterUnavailable, reason: "the local attester could not be reached or failed", patterns: []string{
		"failed to fetch peer cache",          // grpc.go / attestation.go: first cmcd call
		"could not obtain attestation result", // grpc.go verifyAR
		"failed to obtain AR",                 // grpc.go obtainAR
		"failed to initialize CMC",            // libapi.go
		"failed to establish connection",      // grpc.go getCMCServiceConn
	}},
	{kind: ErrAttestModeMismatch, reason: "the peer requested another attestation mode", whole: true, patterns: []string{
		"mismatching attestation mode", // attestation.go checkAttestationMode
	}},
	{kind: ErrPeerUnreachable, reason: "no TCP connection to the peer", patterns: []string{
		"dial tcp", "connection refused", "no such host", "network is unreachable",
	}},
	{kind: ErrIdentityMismatch, reason: "the TLS handshake failed on a certificate", patterns: []string{
		"x509:", "bad certificate", "unknown certificate", "certificate required",
		"certificate unknown", "expired certificate", "revoked certificate", "unsupported certificate",
		"didn't provide a certificate",
	}},
	{kind: ErrHandshakeTimeout, reason: "the peer stopped answering", patterns: []string{
		"i/o timeout", "deadline exceeded",
	}},
	{kind: ErrPlainTLS, reason: "the TLS 1.3 handshake failed", patterns: []string{
		"protocol version", "unsupported versions", "first record does not look like a TLS handshake",
		"failed to establish tls connection", // dialer.go, any other TLS failure
		"TLS handshake failed",               // listener.go, any other TLS failure
	}},
	// CMC returns the real cause only when the handshake-complete exchange itself succeeds
	// (attestation.go aTlsHandshakeComplete). A peer that leaves before that exchange, without
	// any attestation result on this side, completed TLS 1.3 with a valid zone certificate and
	// then aborted: its attester is down, or it never spoke attestation. CMC hides which. With a
	// result on this side, see fromTextWith.
	{kind: ErrPeerAborted, reason: "the peer left without completing the attestation exchange", completeStage: true, patterns: []string{
		"failed to send handshake complete",    // attestation.go aTlsHandshakeComplete
		"failed to receive handshake complete", // attestation.go aTlsHandshakeComplete
	}},
	{kind: ErrPlainTLS, reason: "the peer did not send a valid attestation request", patterns: []string{
		"failed to receive attestation request", // attestation.go: first aTLS message from the peer
		"failed to send atls handshake request", // attestation.go: peer gone before any aTLS message
		"API version mismatch",                  // attestation.go CheckVersion
		"message length is zero",                // backend.go Read
	}},
}

// fromText classifies a CMC error by its text, for a handshake without an attestation result.
func fromText(err error) *Error { return fromTextWith(err, false) }

// fromTextWith classifies a CMC error by its text. hadResult reports whether this side verified
// the peer before the failure. Anything unrecognised is a refusal as not attested.
func fromTextWith(err error, hadResult bool) *Error {
	if err == nil {
		return refuse(ErrNotAttested, "handshake failed without an error", nil)
	}
	msg := err.Error()
	own := msg
	peerSaid := false
	for _, m := range peerTextMarkers {
		if i := strings.Index(own, m); i >= 0 {
			own = own[:i]
			peerSaid = true
		}
	}
	for _, r := range textRules {
		hay := own
		if r.whole {
			hay = msg
		}
		for _, p := range r.patterns {
			if !strings.Contains(hay, p) {
				continue
			}
			if r.completeStage && hadResult {
				return refuse(ErrNotAttested, "the peer left before confirming the attestation", textCause(err))
			}
			return refuse(r.kind, r.reason, textCause(err))
		}
	}
	if peerSaid {
		return refuse(ErrNotAttested, "the peer reported a failed attestation", textCause(err))
	}
	return refuse(ErrNotAttested, "attestation failed", textCause(err))
}
