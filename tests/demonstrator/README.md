# Demonstrator component tests

Run from the repository root with Node.js:

```sh
node --test tests/demonstrator/*.test.cjs
```

No npm installation, cluster, network access or real account credentials are required.
The tests generate disposable RSA keys and signed tokens. Literal test refresh tokens,
cookies and authorization values are synthetic fixtures, not deployed credentials.

## Coverage

- `identity-boundary.test.cjs`: PKCE, signature/issuer/audience/subject checks, roles, expiry, refresh and logout boundaries.
- `identity-lifecycle.test.cjs`: callback state/nonce/replay, CSRF, session isolation, refresh concurrency/failure, logout races, lifetimes and unavailable JWKS. Each case runs against standalone and embedded identity code.
- `participant-integration.test.cjs`: simulated sample-service responses, refusal reasons, correlation, observer access and late responses.
- `delivery-contract.test.cjs`: mandatory access-token subject, backend rejection of read-only configuration edits and referenced UI assets.
- `ui-install.test.cjs`: all five embedded UI assets match source bytes, installation messages use the correct paths, and completion waits for write acknowledgements.

## Verification

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
