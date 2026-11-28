package trainresolve

import "errors"

// Reason codes of the attested-channel family, from the contracts' reason-code registry
// (docs/contracts/reason-codes.json). The caller maps a refusal to the channel state it reports.
const (
	// CodeMeasurementMismatch: the peer presented measurements, TRAIN holds expected values for it,
	// and none of them is equal.
	CodeMeasurementMismatch = "CHAN-MEASUREMENT-MISMATCH"
	// CodeMeasurementUnpublished: TRAIN answered, and holds no expected value for the peer: no entry
	// under its lookup key, or an entry without a TEEM-sha256 value (ZT-64).
	CodeMeasurementUnpublished = "CHAN-MEASUREMENT-UNPUBLISHED"
	// CodeZoneUnknown: no lookup key or trust-scheme pointer can be derived for the peer, or the
	// pointer resolved to no trust list (the zone is absent from TRAIN).
	CodeZoneUnknown = "CHAN-ZONE-UNKNOWN"
	// CodeTrustUnreachable: TRAIN could not be consulted, or its answer could not be trusted:
	// transport, status, size, syntax, an unverified trust list, a timeout, or the caller's deadline.
	CodeTrustUnreachable = "CHAN-TRUST-UNREACHABLE"
)

// Sentinels. Every refusal matches exactly one of them through errors.Is.
var (
	ErrMismatch    = errors.New("the peer's measurement is not among the published values")
	ErrUnpublished = errors.New("no expected measurement is published for the peer")
	ErrZoneUnknown = errors.New("the peer's zone is unknown to TRAIN")
	ErrUnreachable = errors.New("trust resolution failed")
)

// Error is every refusal this package returns. Kind is the sentinel it matches, Code the registered
// reason code of that sentinel, Reason the cause in words, Err the underlying cause when there is
// one. errors.Is works against the sentinel and against the cause; errors.As yields the *Error.
type Error struct {
	Code   string
	Kind   error
	Reason string
	Err    error
}

func (e *Error) Error() string {
	s := "trainresolve: " + e.Kind.Error()
	if e.Reason != "" {
		s += ": " + e.Reason
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

// Unwrap exposes the sentinel and the cause.
func (e *Error) Unwrap() []error {
	if e.Err == nil {
		return []error{e.Kind}
	}
	return []error{e.Kind, e.Err}
}

// CodeOf returns the reason code of a refusal of this package, or "" for any other error (nil
// included).
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func codeFor(kind error) string {
	switch kind {
	case ErrMismatch:
		return CodeMeasurementMismatch
	case ErrUnpublished:
		return CodeMeasurementUnpublished
	case ErrZoneUnknown:
		return CodeZoneUnknown
	default:
		return CodeTrustUnreachable
	}
}

// refuse builds the refusal for kind. err may be nil.
func refuse(kind error, reason string, err error) *Error {
	return &Error{Code: codeFor(kind), Kind: kind, Reason: reason, Err: err}
}

// asRefusal returns err as a refusal of this package: unchanged when it already is one, otherwise
// wrapped as ErrUnreachable, since an error a Source does not classify is a failure to consult
// TRAIN, never a verdict about the peer.
func asRefusal(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return refuse(ErrUnreachable, "the source failed", err)
}
