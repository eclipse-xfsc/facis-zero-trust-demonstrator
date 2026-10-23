package oauth2provider

import "net/http"

// Provider is the OAuth 2.0 authorization surface of the connector.
type Provider interface {
	// TokenHandler serves the token endpoint.
	TokenHandler() http.Handler

	// RegistrationHandler serves the RFC 7591 client registration endpoint.
	RegistrationHandler() http.Handler

	// ChallengeHandler serves the challenge endpoint of the
	// verified-presentation grant.
	ChallengeHandler() http.Handler

	// ValidateResourceRequest authenticates a request to a protected
	// resource that presents a DPoP-bound access token. It returns an
	// *Error carrying a reason code when the request must be refused.
	ValidateResourceRequest(r *http.Request) (ResourceAccess, error)
}

// ResourceAccess describes a successfully validated resource request.
type ResourceAccess struct {
	// ClientID is the client the access token was issued to.
	ClientID string

	// Thumbprint is the RFC 7638 thumbprint of the key the token is bound to.
	Thumbprint string

	Scopes   []string
	Audience []string
}
