# Connector OAuth2 provider

The connector issues its own OAuth 2.0 tokens instead of delegating to the identity provider
(see the [architecture decision on the OAuth2 surface](adr/0003-oauth2-authorisation-surface-in-the-go-connector.md)).
The library it is built on, and why, is recorded in the
[decision on the OAuth2 library](adr/0016-oauth2-library-behind-the-connector-provider-contract.md);
the endpoints as other components see them are defined in the
[connector contract](contracts/if02-connector.v1.openapi.yaml).
This page describes the part of that authorization surface that exists today: dynamic client
registration and DPoP-bound access tokens.

| Capability | Specification |
|---|---|
| Dynamic client registration | RFC 7591 |
| Client credentials grant | RFC 6749 section 4.4 |
| Sender-constrained access tokens (DPoP) | RFC 9449 |
| Resource-side validation of bound tokens | RFC 9449 section 7 |

Issuing tokens from a verified credential presentation is not part of this layer yet.

## Architecture

Connector code depends on a contract the project owns. The OAuth 2.0 library sits behind an adapter
and is invisible to everything else.

```
connector code ──depends on──▶ oauth2provider            contract: types, store interfaces, reason codes
                                     ▲ implements
                         oauth2provider/authelia ──▶ authelia.com/provider/oauth2
```

| Package (under `services/connector/internal/`) | Role |
|---|---|
| `oauth2provider` | The contract: `Provider`, `Config`, `Client`, the store interfaces and the reason codes. Imports no OAuth 2.0 library. |
| `oauth2provider/authelia` | The implementation. The only package allowed to import the library; its exported API names no library type. |
| `oauth2provider/memstore` | In-memory stores for tests and local development. Nothing is persisted. |
| `dpoptest` | Test helper that mints DPoP proofs, including deliberately defective ones, using the standard library only. |

The boundary is enforced, not just intended: a test inspects the imports every package declares and
fails if anything other than the adapter imports the library. It checks direct imports, since every
consumer of the adapter depends on the library transitively and legitimately.

The adapter's own API is checked as well: a second test type-checks the adapter and follows every
type a caller can reach from an exported identifier - through aliases, pointers, containers, type
arguments, and the exported fields and methods of unexported types on the way - and fails if any of
them is declared by the library, since that would hand the type to a caller without any import. The
check is itself tested against packages that hide the library behind an unexported alias, field,
method or interface. The adapter exports one function, `New`, which returns the contract's
`Provider` interface.

This is version 1 of the contract. Additions are ordinary changes; removing or altering an existing
declaration is a breaking change and is reviewed as one. Choosing a different library means a new
adapter package, not a change to the contract.

The freeze is checked as well. `api_v1.txt`, next to the contract, lists its exported API one
identifier per line, and a test regenerates the listing from the package and fails on any difference,
so the contract cannot change in passing. A struct field's line carries its position, so reordering
two fields of one type, which would silently swap them for a caller building the struct
positionally, is a difference too. To change it on purpose, describe the change here and
regenerate the listing:

```bash
OAUTH2PROVIDER_API_UPDATE=1 go test -run TestContractAPIIsFrozen ./services/connector/internal/oauth2provider
```

### Changing the library version

The pinned version is the one the conformance tests were run against, and a test fails when `go.mod`
names another. To move to a new release: bump the version, run `go test -race ./...`, and if it
passes, update the version the test expects, the entry in [OSS dependencies](dependencies.md), and
the [decision on the OAuth2 library](adr/0016-oauth2-library-behind-the-connector-provider-contract.md).

## Client registration

Registration is **not open**. The registration endpoint is itself a protected resource: it takes an
access token, issued by the token endpoint like any other, that

- names the registration endpoint as its audience, and
- carries the scope `connector:client_registration`.

A deployment provisions one client that is allowed to obtain such a token; participant backends
holding it can then register themselves without an operator creating each client by hand.

A registration cannot exceed the token that authorised it. Requested scopes must be within the scopes
of that token, the registration scope itself can never be registered, and grant types are limited to
those the deployment offers. Violations are refused with `invalid_client_metadata`.

A client that registers with `dpop_bound_access_tokens: true` can afterwards only obtain tokens by
presenting a DPoP proof.

The generated client secret is returned once, in the registration response. Only its bcrypt hash is
stored.

## DPoP behaviour

What follows is behaviour the conformance tests assert, not a restatement of the specification.

**Token endpoint.** A valid proof yields a token with `token_type` `DPoP`, bound to the thumbprint of
the proof's key. A proof is refused when

- its `htm` is not the request method;
- its `htu` is not the request URI. Query and fragment are ignored in the comparison, per RFC 9449
  section 4.2; a different path or host is refused;
- its `iat` lies outside the freshness window: accepted from `iat - ClockSkew` until
  `iat + ProofLifespan + ClockSkew`;
- it has been used before.

**Replay protection.** A proof is accepted once. The guarantee holds under concurrency: of one hundred
simultaneous presentations of the same proof, exactly one is accepted and the rest are refused as
replays. A `jti` is scoped to the URI and method the proof was made for, following RFC 9449 sections
4.2 and 11.1, and additionally to the proof key and nonce. Reusing a `jti` in a new proof for another
endpoint is therefore not a replay; presenting any proof a second time is.

**Server nonce.** With `NonceRequired`, a request without a nonce is answered with `400`
`use_dpop_nonce` and a `DPoP-Nonce` header. Retrying with that nonce succeeds. A nonce the server did
not issue, or one past `NonceLifespan`, is challenged again.

**Protected resources.** A resource accepts only key-bound tokens, presented under the `DPoP` scheme
with a proof that

- is signed by the key the token is bound to — a token presented with any other key is refused, which
  is what makes a stolen token useless;
- carries an `ath` claim matching the presented token;
- satisfies the same `htm`, `htu`, freshness and replay checks as at the token endpoint.

A bound token presented under the `Bearer` scheme is refused, with or without a proof next to it.

## Reason codes

Error responses keep the members the OAuth 2.0 specifications define and add a `reason` member with a
machine-readable code, in line with the project's [error conventions](api-docs.md#conventions). The
codes are derived from the library's OAuth 2.0 error names and from facts the adapter establishes
itself, never from message text. They are the values the
[connector contract](contracts/if02-connector.v1.openapi.yaml) publishes for `reason`, and a test
fails if the two lists differ.

| `reason` | Meaning |
|---|---|
| `dpop_invalid_proof` | The proof fails the RFC 9449 section 4.3 checks, or is missing where required |
| `dpop_replayed` | The proof was already used |
| `dpop_use_nonce` | A server-issued nonce is required |
| `dpop_jkt_mismatch` | The proof is signed by a key other than the one the token is bound to |
| `dpop_invalid_ath` | The `ath` claim is missing or does not match the presented token |
| `invalid_client` | Client authentication failed |
| `invalid_token` | The token is unknown, expired, not key-bound, or presented under the wrong scheme |
| `insufficient_scope` | The token lacks a required scope |
| `registration_rejected` | The submitted client metadata was refused |
| `invalid_request`, `server_error` | As named |

## Configuration

`oauth2provider.Config`:

| Field | Purpose |
|---|---|
| `Secret` | Signs access tokens. At least 32 bytes. |
| `AccessTokenLifespan` | Defaults to one hour. |
| `DPoP.Enforce` | Require a proof from every client, not only from clients registered for bound tokens. |
| `DPoP.NonceRequired` | Challenge with a server nonce. |
| `DPoP.ProofLifespan`, `DPoP.ClockSkew` | The freshness window. Together at most 90 seconds, the longest the token store keeps a replay record; a larger sum is refused at start-up. |
| `DPoP.NonceLifespan` | How long an issued nonce stays valid. |
| `DPoP.Algorithms` | Accepted proof signature algorithms. |
| `Registration.Secret` | Signs registration access tokens. At least 32 bytes and different from `Secret`. |
| `Registration.EndpointURL` | Absolute URL of the registration endpoint; also the audience a token must carry there. |
| `Registration.GrantTypes` | Grant types a client may register for. |

Persistence is supplied through small interfaces — clients, access tokens, registration tokens, DPoP
nonces and DPoP replay state. Stores are handed token signatures, never usable tokens, and the
request form is not persisted because it can carry client credentials.

The replay store receives a proof's identity as separate values — key thumbprint, method, normalized
target URI, `jti` and nonce — together with the proof's `iat` and the instant it stops being
acceptable. It decides atomically whether the proof was seen before; two uses are the same proof
when thumbprint, method, URI and `jti` are equal, and a store may also distinguish by nonce, as the
in-memory one does.

## Running the conformance tests

```sh
go test ./services/connector/...
go test -race ./services/connector/...
```

The tests run the provider behind a real HTTP server and drive it from the outside. Stale, future and
otherwise defective proofs are minted with the claims they need, and expiry is exercised by moving the
stores' clock, so no test waits for time to pass. Test names state the rule they check:
`TestDPoP_…`, `TestResource_…`, `TestRegistration_…`.

## Limitations

- The only stores are in-memory; nothing survives a restart.
- Only the `client_credentials` grant and `client_secret_basic` client authentication are wired.
  Client authentication by signed assertion is refused.
- Registration management (RFC 7592) and token introspection are not exposed. A registration
  response nevertheless carries a registration access token and a client configuration URI, which
  lead nowhere yet.
- Access tokens are opaque and validated by lookup, so a protected resource can only validate them
  through the connector. Signed tokens carrying the key binding, validated against a published key
  set, are the decided direction and not implemented yet.
- The proof URI is reconstructed from the request. Behind a proxy the scheme is taken from
  `X-Forwarded-Proto`, so that header must be set by a trusted hop only.
- The pinned `authelia.com/provider/oauth2` v0.3.2 requires Go 1.27.x.
