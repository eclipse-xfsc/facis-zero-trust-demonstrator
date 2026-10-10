package oauth2provider

import "time"

// RegistrationScope is the scope an access token must carry, together with
// the registration endpoint as its audience, to register a client.
const RegistrationScope = "connector:client_registration"

// MaxDPoPProofWindow is the longest a DPoP proof may stay acceptable after
// its iat: DPoPConfig.ProofLifespan plus DPoPConfig.ClockSkew may not exceed
// it. It bounds how long a replay store has to keep a record.
const MaxDPoPProofWindow = 90 * time.Second

// Config configures a Provider.
type Config struct {
	// Secret signs access tokens. At least 32 bytes.
	Secret []byte

	// AccessTokenLifespan defaults to one hour when zero.
	AccessTokenLifespan time.Duration

	DPoP         DPoPConfig
	Registration RegistrationConfig
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
}
