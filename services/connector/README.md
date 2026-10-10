# Connector

The Zero Trust Connector is the single controlled point through which a zone's traffic to and from
another zone passes. This folder holds its Go code.

## What is here

The connector's OAuth 2.0 authorization surface. The connector issues its own tokens rather than
delegating to the identity provider; the reasoning is recorded in the
[architecture decision on the OAuth2 surface](../../docs/adr/0003-oauth2-authorisation-surface-in-the-go-connector.md).

- **Dynamic client registration** (RFC 7591), so a participant backend can register itself.
- **DPoP-bound access tokens** (RFC 9449) on the client credentials grant, so a token is useless
  without the key it was issued to.
- **Resource-side validation** of bound tokens: key binding, `ath`, scheme, replay.

Behaviour, configuration, reason codes and limitations are described in
[docs/oauth2-provider.md](../../docs/oauth2-provider.md).

## Layout

| Path | Contents |
|---|---|
| `internal/oauth2provider` | The contract the connector programs against, at version 1. Imports no OAuth 2.0 library. |
| `internal/oauth2provider/authelia` | The implementation, and the only package allowed to import the OAuth 2.0 library. |
| `internal/oauth2provider/memstore` | In-memory stores for tests and local development. |
| `internal/dpoptest` | Test helper that mints DPoP proofs. |

## Setup

The Go module is declared at the repository root. The currently evaluated
`authelia.com/provider/oauth2` v0.3.2 requires Go 1.27.x; with Go 1.21 or later installed, the
`go` command fetches a matching toolchain by itself.

There are no environment variables and nothing to configure: this code is a library with tests, not
yet a deployable service.

## Tests

From the repository root:

```sh
go vet ./...
go test ./services/connector/...
go test -race ./services/connector/...
```

The conformance tests run the provider behind a real HTTP server. Their names state the rule they
check (`TestDPoP_…`, `TestResource_…`, `TestRegistration_…`). One test guards the architecture
rather than behaviour: it fails if any package other than the adapter imports the OAuth 2.0 library.
