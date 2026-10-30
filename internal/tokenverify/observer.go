package tokenverify

import (
	"context"
	"errors"
)

type refusalObserverKey struct{}

// WithRefusalObserver records a fixed reason code when Middleware refuses this request.
// The callback runs synchronously before the response is written. No credential, claim,
// error detail or caller-controlled string is passed to the observer.
func WithRefusalObserver(ctx context.Context, observer func(string)) context.Context {
	if observer == nil {
		return ctx
	}
	return context.WithValue(ctx, refusalObserverKey{}, observer)
}

// ReasonCode classifies a verifier failure without exposing arbitrary error text.
// The public OAuth error response remains unchanged.
func ReasonCode(err error) string {
	for _, entry := range []struct {
		err  error
		code string
	}{
		{ErrNoToken, "token_absent"}, {ErrNoProof, "proof_absent"},
		{ErrMalformed, "token_malformed"}, {ErrSignature, "signature_invalid"},
		{ErrExpired, "token_expired"}, {ErrIssuer, "issuer_mismatch"},
		{ErrAudience, "audience_mismatch"}, {ErrScope, "scope_insufficient"},
		{ErrKeyMismatch, "key_binding_mismatch"}, {ErrProof, "proof_invalid"},
		{ErrReplayed, "proof_replayed"}, {ErrKeySetUnavailable, "key_set_unavailable"},
		{ErrInvalidRequest, "request_invalid"}, {errReplayUnavailable, "replay_unavailable"},
	} {
		if errors.Is(err, entry.err) {
			return entry.code
		}
	}
	return "unclassified"
}
