package oauth2provider

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// ErrNotFound is returned by stores when a record does not exist.
var ErrNotFound = errors.New("oauth2provider: not found")

// ErrConsumed is returned by stores when a single-use record, a challenge or a verification
// outcome, has been consumed before.
var ErrConsumed = errors.New("oauth2provider: already consumed")

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

	// ExpiresAt is when the token stops being valid. The provider sets it, so
	// a store can sweep expired records without reading Session.
	ExpiresAt time.Time

	// OutcomeID is the IF-03 outcome a verified-presentation grant issued the
	// token on, empty for every other grant. A store keeps it unique.
	OutcomeID string

	// GrantType is the grant the token was issued through, empty for a
	// registration access token. A store refuses a token of
	// VerifiedPresentationGrantType without an OutcomeID, and an OutcomeID on
	// a token of any other grant.
	GrantType string
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

// Challenge is a single-use value issued to a client for a verified-presentation grant, bound to
// that client and one audience.
type Challenge struct {
	Value     string
	ClientID  string
	Audience  string
	ExpiresAt time.Time

	// ConsumedAt is zero while the challenge is unconsumed.
	ConsumedAt time.Time
}

// ChallengeStore persists challenges. A consumed challenge is never reset or deleted.
type ChallengeStore interface {
	// CreateChallenge stores a new challenge; an existing value is an error, never overwritten.
	CreateChallenge(ctx context.Context, challenge Challenge) error

	// GetChallenge reads a challenge without locking it.
	GetChallenge(ctx context.Context, value string) (Challenge, error)

	// LockChallenge reads a challenge and, with a transaction context, holds it locked against
	// every other transaction's LockChallenge and ConsumeChallenge until the transaction ends.
	LockChallenge(ctx context.Context, value string) (Challenge, error)

	// ConsumeChallenge marks the challenge consumed at the instant at when it is bound to clientID
	// and audience, unconsumed and expires after at. Otherwise it returns ErrConsumed and changes
	// nothing. Of concurrent callers for one challenge, at most one succeeds.
	ConsumeChallenge(ctx context.Context, value, clientID, audience string, at time.Time) error
}

// VerifiedOutcome is a verified IF-03 outcome as the grant records it.
type VerifiedOutcome struct {
	ID             string
	Issuer         string
	ClientID       string
	Challenge      string
	Audience       string
	Claims         json.RawMessage
	CredentialRefs []string
	VerifiedAt     time.Time
	ExpiresAt      time.Time
}

// OutcomeStore is the ledger of consumed outcomes. A recorded outcome is never reset or deleted.
type OutcomeStore interface {
	// ConsumeOutcome records the outcome as verified and consumed at the instant at. An outcome id
	// recorded before is ErrConsumed. Of concurrent callers for one outcome id, at most one succeeds.
	ConsumeOutcome(ctx context.Context, outcome VerifiedOutcome, at time.Time) error
}

// Transactor runs store calls in one transaction. BeginTx returns a context that carries the
// transaction; every store call made with that context, nonces and replay records excepted, is part
// of it until Commit or Rollback is called with the same context.
type Transactor interface {
	BeginTx(ctx context.Context) (context.Context, error)
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// Stores groups the persistence a Provider depends on.
type Stores struct {
	Clients            ClientStore
	AccessTokens       TokenStore
	RegistrationTokens TokenStore
	DPoPNonces         DPoPNonceStore
	DPoPReplay         DPoPReplayStore

	// Challenges, Outcomes and Transactions are required only with
	// Config.VerifiedPresentation.
	Challenges   ChallengeStore
	Outcomes     OutcomeStore
	Transactions Transactor
}
