package oauth2provider

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by stores when a record does not exist.
var ErrNotFound = errors.New("oauth2provider: not found")

// ClientStore persists clients.
type ClientStore interface {
	GetClient(ctx context.Context, id string) (Client, error)
	CreateClient(ctx context.Context, client Client) error
	UpdateClient(ctx context.Context, client Client) error
	DeleteClient(ctx context.Context, id string) error
}

// TokenRecord is the persisted state of an issued token.
type TokenRecord struct {
	RequestID   string
	ClientID    string
	RequestedAt time.Time

	RequestedScopes   []string
	GrantedScopes     []string
	RequestedAudience []string
	GrantedAudience   []string

	// Session is the implementation's serialized session state, including
	// expiry and any key binding. It is opaque to the store.
	Session []byte
}

// TokenStore persists token records by token signature. The signature is
// not the token: a store never sees a usable credential.
type TokenStore interface {
	CreateToken(ctx context.Context, signature string, record TokenRecord) error
	GetToken(ctx context.Context, signature string) (TokenRecord, error)
	DeleteToken(ctx context.Context, signature string) error
}

// DPoPNonceStore persists server-issued DPoP nonces.
type DPoPNonceStore interface {
	CreateNonce(ctx context.Context, nonce string, exp time.Time) error
	IsNonceValid(ctx context.Context, nonce string) (bool, error)
}

// DPoPProofUse identifies one presentation of a DPoP proof (RFC 9449). The
// values are the ones the provider validated against the request, not the
// raw claims.
type DPoPProofUse struct {
	// Thumbprint is the RFC 7638 SHA-256 thumbprint of the proof key (jkt).
	Thumbprint string

	// Method is the HTTP method the proof was made for (htm).
	Method string

	// URI is the normalized target URI the proof was made for (htu), so two
	// spellings of one URI cannot occupy separate records.
	URI string

	// ID is the proof's jti claim.
	ID string

	// Nonce is the server-issued nonce the proof carries, empty when it
	// carries none.
	Nonce string

	// IssuedAt is the proof's iat claim.
	IssuedAt time.Time

	// NotAfter is the instant the proof stops being acceptable. A record
	// kept until then cannot be outlived by the proof it guards against.
	NotAfter time.Time
}

// DPoPReplayStore detects reuse of DPoP proofs.
type DPoPReplayStore interface {
	// MarkUsed atomically records the proof as used and reports whether it
	// was already recorded. The check and the insert happen in one critical
	// section, so that of any number of concurrent callers presenting the
	// same proof exactly one observes alreadyUsed == false.
	//
	// Two uses are the same proof when Thumbprint, Method, URI and ID are
	// equal; an implementation may also distinguish by Nonce. The record
	// must be kept at least until NotAfter.
	MarkUsed(ctx context.Context, use DPoPProofUse) (alreadyUsed bool, err error)
}

// Stores groups the persistence a Provider depends on.
type Stores struct {
	Clients            ClientStore
	AccessTokens       TokenStore
	RegistrationTokens TokenStore
	DPoPNonces         DPoPNonceStore
	DPoPReplay         DPoPReplayStore
}
