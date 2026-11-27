# Demonstrator component tests

Run from the repository root with Node.js:

```sh
node --test tests/demonstrator/*.test.cjs
```

No npm installation, cluster, external network access or real account credentials are required. Some adapter tests start disposable loopback HTTP servers and close them after the checks.
The tests generate disposable RSA keys and signed tokens. Literal test refresh tokens,
cookies and authorization values are synthetic fixtures, not deployed credentials.

## Coverage

- `participant-token.test.cjs`: 31 controlled checks for state/history, reset confirmation/timeout, TLS separation, report/summary validation, auth/CSRF, polling lifecycle and synchronized exports.

- `replacement-adapters.test.cjs`: 21 local checks for both role replacements, interface discovery, request preservation, response contracts, refusal and transport failures.

- `protected-resource.test.cjs`: 29 local fixture checks for role combinations, credential/scope refusal, unavailable security, Journey/Evidence, reset and observer access.

- `connector-adapter.test.cjs`: 21 module and embedded-flow contract checks for registration, DPoP, nonce handling, refusal, deadlines and sanitized events.

- `identity-boundary.test.cjs`: PKCE, signature/issuer/audience/subject checks, roles, expiry, refresh and logout boundaries.
- `identity-lifecycle.test.cjs`: callback state/nonce/replay, CSRF, session isolation, refresh concurrency/failure, logout races, lifetimes and unavailable JWKS. Each case runs against standalone and embedded identity code.
- `participant-integration.test.cjs`: simulated sample-service responses, refusal reasons, correlation, observer access and late responses.
- `delivery-contract.test.cjs`: mandatory access-token subject, backend rejection of read-only configuration edits and referenced UI assets.
- `ui-behaviour.test.cjs`: session polling, field-local validation, branding assets and Vue template compilation.
- `ui-install.test.cjs`: all nine staged UI assets match source bytes, installation messages use the correct paths, and completion waits for write acknowledgements. The test maps Linux runtime paths to the host filesystem so it also runs on Windows.

## Verification

The Connector adapter is tested against a disposable local HTTP contract server, not a deployed Connector or the Go provider conformance suite.

The 21 October delivery passed **140 component tests**. The 7 November token integration adds 31 Participant checks and two installer checks, for **173 tests**. Run the command above on the exact revision being reviewed; reported browser results are separate from this controlled suite.

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

Installer quality checks reject embedded asset blobs and flow-export lines above 64 KiB. Installation tests verify all nine staged assets byte for byte, including the Vue licence, and reject missing, empty or oversized assets before emitting any writes. Vendored third-party files retain their upstream format.
