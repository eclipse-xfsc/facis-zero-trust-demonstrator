package oauth2provider

import (
	"context"
	"crypto/ecdsa"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
)

// RegistrationScope is the scope an access token must carry, together with
// the registration endpoint as its audience, to register a client.
const RegistrationScope = "connector:client_registration"

// MaxDPoPProofWindow is the longest a DPoP proof may stay acceptable after
// its iat: DPoPConfig.ProofLifespan plus DPoPConfig.ClockSkew may not exceed
// it. It bounds how long a replay store has to keep a record.
const MaxDPoPProofWindow = 90 * time.Second

// VerifiedPresentationGrantType is the grant type of the verified-presentation grant: an access
// token issued on a signed IF-03 verification outcome.
const VerifiedPresentationGrantType = "urn:facis:params:oauth:grant-type:verified-presentation"

// ChallengeLifetime is how long a challenge from the challenge endpoint stays usable.
const ChallengeLifetime = 120 * time.Second

// Config configures a Provider.
type Config struct {
	// Secret signs access tokens. At least 32 bytes.
	Secret []byte

	// AccessTokenLifespan defaults to one hour when zero.
	AccessTokenLifespan time.Duration

	DPoP         DPoPConfig
	Registration RegistrationConfig

	// Issuer is the iss claim of signed access tokens. Required when
	// AccessTokenSigner is set, unused otherwise.
	Issuer string

	// AccessTokenSigner, when set, makes access tokens RFC 9068 JWTs signed
	// with ES256 by this signer, and AccessTokenLifespan defaults to five
	// minutes. When nil, access tokens are opaque and signed with Secret.
	// Registration access tokens are opaque either way.
	AccessTokenSigner TokenSigner

	// VerifiedPresentation enables the verified-presentation grant and the
	// challenge endpoint when its TrustedIssuers is non-empty.
	VerifiedPresentation VerifiedPresentationConfig
}

// VerifiedPresentationConfig configures the verified-presentation grant. The grant issues signed
// tokens only, so it needs Config.AccessTokenSigner, and it needs Stores.Challenges,
// Stores.Outcomes and Stores.Transactions.
type VerifiedPresentationConfig struct {
	// TrustedIssuers are the IF-03 issuers whose outcomes are accepted, with their keys.
	TrustedIssuers if03.Issuers

	// Scopes maps an outcome's claims to the scopes the grant issues. An outcome whose claims match
	// no entry is refused. These scopes are never issued through client_credentials.
	Scopes []ClaimScopes
}

// ClaimScopes grants Scopes to an outcome whose role is Role and whose entitlement is Entitlement,
// both compared exactly; an empty Entitlement matches only an outcome without one. What is issued is
// further limited to the client's registered scopes.
type ClaimScopes struct {
	Role        string
	Entitlement string
	Scopes      []string
}

// TokenSigner signs access tokens with an ECDSA P-256 key whose private half
// may be held outside the process.
type TokenSigner interface {
	// KeyID is the kid of the signing key, as published in the key set.
	KeyID() string

	// Public is the signing key's public half.
	Public() *ecdsa.PublicKey

	// Sign signs the JWS signing input with ES256 and returns the 64-byte
	// R||S signature. ctx is the context of the request being served.
	Sign(ctx context.Context, signingInput []byte) ([]byte, error)
}

// DPoPConfig configures RFC 9449 behaviour.
type DPoPConfig struct {
	// Enforce requires a DPoP proof from every client. When false, a proof is
	// required only from clients registered with DPoP-bound access tokens.
	Enforce bool

	// NonceRequired makes the server challenge with a DPoP-Nonce.
	NonceRequired bool

	// ProofLifespan is how long after its iat a proof is accepted. The
	// implementation's default applies when zero.
	ProofLifespan time.Duration

	// ClockSkew is the tolerance applied on both sides of the iat window.
	// The implementation's default applies when zero. Together with
	// ProofLifespan it may not exceed MaxDPoPProofWindow.
	ClockSkew time.Duration

	// NonceLifespan is how long an issued nonce remains valid.
	NonceLifespan time.Duration

	// Algorithms lists the accepted proof signature algorithms. The
	// implementation's default applies when empty.
	Algorithms []string
}

// RegistrationConfig configures RFC 7591 client registration.
type RegistrationConfig struct {
	// Secret signs registration access tokens. At least 32 bytes and
	// different from Config.Secret.
	Secret []byte

	// EndpointURL is the absolute URL of the registration endpoint. It is
	// also the audience a token must carry to be accepted there.
	EndpointURL string

	// GrantTypes restricts the grant types a client may register for.
	GrantTypes []string

	// DelegableScopes is, per registrar client id, the scopes that registrar may grant to the
	// clients it registers, in addition to the scopes of the token it registers with. It is
	// consulted by registration only: the registrar itself is never issued these scopes. It is how
	// a client is registered for a verified-presentation scope, which client_credentials never
	// issues. RegistrationScope is never delegable.
	DelegableScopes map[string][]string
}
