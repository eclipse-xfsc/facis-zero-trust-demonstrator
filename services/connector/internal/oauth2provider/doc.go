// Package oauth2provider is the connector's own contract for its OAuth 2.0
// authorization surface: dynamic client registration (RFC 7591) and
// DPoP-bound access tokens (RFC 9449).
//
// The package declares the types, storage interfaces and reason codes the
// rest of the connector programs against. It deliberately imports no
// third-party OAuth 2.0 library: a concrete implementation lives in a
// subpackage (see the authelia subpackage) and is the only place such a
// library may be imported. That boundary is enforced by a test.
//
// This is version 1 of the contract. The rest of the connector programs
// against it, and an implementation is chosen by importing a subpackage, so
// a change to the library is a new subpackage rather than a change here.
// Additions are ordinary changes; removing or altering an existing
// declaration is a breaking change, made deliberately and reviewed as such.
package oauth2provider
