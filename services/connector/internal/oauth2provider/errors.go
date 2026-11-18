package oauth2provider

import "net/http"

// Code is a machine-readable reason for a refusal.
type Code string

const (
	CodeInvalidRequest       Code = "invalid_request"
	CodeInvalidClient        Code = "invalid_client"
	CodeInvalidToken         Code = "invalid_token"
	CodeInsufficientScope    Code = "insufficient_scope"
	CodeRegistrationRejected Code = "registration_rejected"
	CodeServerError          Code = "server_error"

	// CodeDPoPInvalidProof: the proof fails the RFC 9449 section 4.3 checks
	// (signature, typ, htm, htu, iat window, ...).
	CodeDPoPInvalidProof Code = "dpop_invalid_proof"

	// CodeDPoPReplayed: the proof was already used.
	CodeDPoPReplayed Code = "dpop_replayed"

	// CodeDPoPUseNonce: the server requires a nonce it has issued.
	CodeDPoPUseNonce Code = "dpop_use_nonce"

	// CodeDPoPKeyMismatch: the proof is signed by a key other than the one
	// the access token is bound to.
	CodeDPoPKeyMismatch Code = "dpop_jkt_mismatch"

	// CodeDPoPInvalidATH: the proof's ath claim is missing or does not match
	// the presented access token.
	CodeDPoPInvalidATH Code = "dpop_invalid_ath"

	// The IF-03 reason codes of the verified-presentation grant, as the
	// reason-code registry names them.

	// CodeCredOutcomeSignature: the outcome's JWS does not verify with a
	// trusted issuer key, or the outcome is not in the IF-03 form.
	CodeCredOutcomeSignature Code = "CRED-OUTCOME-SIGNATURE"

	// CodeCredOutcomeNotVerified: the outcome's status is not verified.
	CodeCredOutcomeNotVerified Code = "CRED-OUTCOME-NOT-VERIFIED"

	// CodeCredOutcomeMismatch: the outcome's client, challenge or audience
	// differs from the request, or the challenge was not issued to this
	// client for this audience.
	CodeCredOutcomeMismatch Code = "CRED-OUTCOME-MISMATCH"

	// CodeCredOutcomeExpired: the outcome, or its challenge, is outside its
	// validity interval.
	CodeCredOutcomeExpired Code = "CRED-OUTCOME-EXPIRED"

	// CodeCredOutcomeConsumed: the outcome or its challenge was already used.
	CodeCredOutcomeConsumed Code = "CRED-OUTCOME-CONSUMED"
)

// ReasonField is the JSON member of an error response that carries the Code,
// alongside the members the OAuth 2.0 specifications define.
const ReasonField = "reason"

// Error is a refusal with its reason.
type Error struct {
	Code Code

	// Status is the HTTP status appropriate for the refusal.
	Status int

	// DPoPNonce is a fresh nonce to return in a DPoP-Nonce header. It is set
	// only when Code is CodeDPoPUseNonce.
	DPoPNonce string

	cause error
}

// NewError returns an Error wrapping cause.
func NewError(code Code, status int, cause error) *Error {
	if status == 0 {
		status = http.StatusBadRequest
	}

	return &Error{Code: code, Status: status, cause: cause}
}

func (e *Error) Error() string {
	if e.cause == nil {
		return string(e.Code)
	}

	return string(e.Code) + ": " + e.cause.Error()
}

func (e *Error) Unwrap() error { return e.cause }
