# Connector

The Zero Trust Connector is the single controlled point through which a zone's traffic to and from
another zone passes. This folder holds its Go code.

## What is here

The connector's OAuth 2.0 authorization surface. The connector issues its own tokens rather than
delegating to the identity provider; the reasoning is recorded in the
[architecture decision on the OAuth2 surface](../../docs/adr/0003-oauth2-authorisation-surface-in-the-go-connector.md).

- **Dynamic client registration** (RFC 7591), so participant backends are registered through the
  registrar rather than created by hand, behind the connector's registration policy, with every
  decision audited.
- **DPoP-bound access tokens** (RFC 9449) on the client credentials grant, so a token is useless
  without the key it was issued to.
- **Resource-side validation** of bound tokens: key binding, `ath`, scheme, replay.

Behaviour, configuration, reason codes and limitations of the provider are described in
[docs/oauth2-provider.md](../../docs/oauth2-provider.md); the service around it (the registration
policy and audit, the security-state events, `connector register`, the chart and the identity) in
[docs/connector.md](../../docs/connector.md).

## Layout

| Path | Contents |
|---|---|
| `internal/oauth2provider` | The contract the connector programs against, at version 1. Imports no OAuth 2.0 library. |
| `internal/oauth2provider/authelia` | The implementation, and the only package allowed to import the OAuth 2.0 library. |
| `internal/oauth2provider/memstore` | In-memory stores for tests and local development. |
| `internal/oauth2provider/pgstore` | The PostgreSQL stores on the token store's schema, and the audit row writer. |
| `internal/dpoptest` | Test helper that mints DPoP proofs. |
| `main.go`, `serve.go`, `server.go` | The binary: `connector serve`, its configuration, listeners, readiness and route table. |
| `register.go`, `events.go` | The registration policy and its audit, and the IF-01 event sink. |
| `register_cmd.go` | `connector register`, the registrar's client that writes a participant's credentials file. |

## Setup

The Go module is declared at the repository root. The currently evaluated
`authelia.com/provider/oauth2` v0.3.2 requires Go 1.27.x; with Go 1.21 or later installed, the
`go` command fetches a matching toolchain by itself.

The binary is configured by flags with environment-variable defaults (`CONNECTOR_*`), documented in
[docs/oauth2-provider.md](../../docs/oauth2-provider.md#running-the-connector). The OpenBao token
and the connector's secrets come from files, never from flags or variables; the database URL comes
from a flag or a variable and is never logged. The chart `deployment/helm/connector` deploys it.

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
The tests of the binary against PostgreSQL and OpenBao run with `TOKEN_STORE_TEST_DATABASE_URL`,
`TRANSIT_TEST_ADDR` and `TRANSIT_TEST_TOKEN` set, and skip without them.
