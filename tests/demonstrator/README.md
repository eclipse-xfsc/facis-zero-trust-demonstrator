# Demonstrator component tests

Run from the repository root with Node.js:

```sh
node --test tests/demonstrator/*.test.cjs
```

No npm installation, cluster access, external service access or real account credentials are required.
Connector and replacement-adapter tests start disposable HTTP servers on numeric loopback addresses; local network binding must be permitted.
The tests generate disposable RSA keys and signed tokens. Literal test refresh tokens,
cookies and authorization values are synthetic fixtures, not deployed credentials.

## Coverage

- `replacement-adapters.test.cjs`: 21 local checks for both role replacements, interface discovery, request preservation, response contracts, refusal and transport failures.

- `protected-resource.test.cjs`: 29 local fixture checks for role combinations, credential/scope refusal, unavailable security, Journey/Evidence, reset and observer access.

- `connector-adapter.test.cjs`: 21 module and embedded-flow contract checks for registration, DPoP, nonce handling, refusal, deadlines and sanitized events.

- `identity-boundary.test.cjs`: PKCE, signature/issuer/audience/subject checks, roles, expiry, refresh and logout boundaries.
- `identity-lifecycle.test.cjs`: callback state/nonce/replay, CSRF, session isolation, refresh concurrency/failure, logout races, lifetimes and unavailable JWKS. Each case runs against standalone and embedded identity code.
- `participant-integration.test.cjs`: simulated sample-service responses, refusal reasons, correlation, observer access and late responses.
- `delivery-contract.test.cjs`: mandatory access-token subject, backend rejection of read-only configuration edits and referenced UI assets.
- `ui-behaviour.test.cjs`: session polling, field-local validation, branding assets and Vue template compilation.
- `ui-install.test.cjs`: all nine embedded UI assets match source bytes, installation messages use the correct paths, and completion waits for write acknowledgements.

## Verification

The Connector adapter is tested against a disposable local HTTP contract server, not a deployed Connector or the Go provider conformance suite.

The synchronized 21 October 2026 source passed **140 tests, zero failures and zero skipped** in the supplied Node v24.19.0 Linux run and an independent Node v24.19.0 Windows run. This is component validation; target-environment checks below remain separate.

The 12 October 2026 source passed **60 tests, zero failures and zero skipped** using
Node v24.19.0 on Windows. `.github/workflows/demonstrator-tests.yml` runs the same
suite with Node 22 on GitHub; that environment remains unverified until CI completes.

These are component tests. Identity-provider and Participant HTTP responses are
simulated. Passing them does not establish live Keycloak event delivery, cluster
installation, formal BDD acceptance or two-zone authorization.

## Target-environment checks

Use `ui/demonstrator/INSTALL.md` for fresh installation and live checks. Verify actual
refresh rotation/expiry, administrator-initiated logout, front/back-channel delivery,
and refusal of old-session commands. Run the formal BDD suite separately with the
approved accounts and environment. Never commit runtime credentials or token dumps.
