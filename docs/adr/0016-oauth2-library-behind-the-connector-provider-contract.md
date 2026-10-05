# ADR-0016: OAuth2 library behind the connector's provider contract

- **Status:** Proposed. One dependent item remains open: moving issuance to signed access tokens
  (see Open items).
- **Date:** 2026-10-05
- **Deciders:** Delivery team, from the OAuth2 library evaluation of September 2026 and its
  follow-up comparison of library versions. Confirmation by the deciders of ADR-0003 is pending.
- **Requirement basis:** ZT-21, ZT-22
- **Related:** [ADR-0003](0003-oauth2-authorisation-surface-in-the-go-connector.md) — the OAuth2
  authorisation surface is implemented in the Go connector. This record settles how; it does not
  touch whether.

## Context

ADR-0003 places Dynamic Client Registration and DPoP-bound token issuance in the connector, which
means the connector has to implement RFC 7591 and RFC 9449 or build on a library that does. Both are
security protocols with many refusal cases — method and URI binding, a freshness window, replay under
concurrency, server nonces, key binding at the resource — and code of that kind is expensive to own.

Two Go libraries were candidates. `authelia.com/provider/oauth2` is a maintained fork of `ory/fosite`
that ships both RFCs, and is pre-1.0. `ory/fosite` is the original; it has neither RFC, and its last
release is from December 2024.

Whichever library is used, its types must not spread through the connector: a pre-1.0 dependency
changes, and the cost of a change has to stay in one place.

## Decision

### 1. The library

The connector's OAuth2 surface is built on **`authelia.com/provider/oauth2` v0.3.2** (Apache-2.0).

A conformance suite over real HTTP passes on it under the race detector: method and URI binding, the
freshness window, sequential and concurrent replay (of one hundred simultaneous presentations of one
proof exactly one is accepted), the server-nonce round trip, key binding, `ath` and scheme checks at
the resource, and the registration rules. The suite is in
`services/connector/internal/oauth2provider/authelia`.

The same suite was run against an adapter written on `ory/fosite`. It passed, but only after the
whole of RFC 9449 and RFC 7591 had been written by hand — about six hundred lines of security-protocol
code that the project would then own and maintain, on a library that is no longer released. That
adapter is the documented fallback and is not part of the repository.

### 2. The version

v0.3.0 is the first release with client registration; v0.3.2 was current when the evaluation started.
The suite passes unchanged on v0.3.0, v0.3.2 and v0.3.3. v0.3.2 is what was reviewed and merged, and
v0.3.3 (2026-09-19) adds features the connector does not use, so the pin stays.

Every one of the three requires a current Go: v0.3.2 and v0.3.3 declare Go 1.27, and v0.3.0, although
it declares Go 1.25, depends on a `golang.org/x/crypto` that needs Go 1.26. What that means for the
module and its pipeline is in [CI/CD — Go version](../ci-cd.md#go-version).

A test fails when `go.mod` pins any other version than the one the suite was verified against, so a
bump is a deliberate act: run the suite on the new release, then update the test, the dependency
table and this record.

### 3. The boundary

The library sits behind a contract the project owns, `services/connector/internal/oauth2provider`:
the `Provider` interface, the configuration, the client record, the store interfaces and the
reason codes. The contract imports no OAuth2 library. One adapter package,
`oauth2provider/authelia`, is the only importer.

Three tests hold that boundary:

- no package other than the adapter imports the library, test files included;
- no library type is reachable from the adapter's exported API, through aliases or the exported
  fields and methods of unexported types included — it exports one constructor, which returns the
  contract's `Provider`;
- the contract's exported API, struct field order included, equals a committed listing, so a change
  to it cannot happen in passing.

The contract is at version 1. An addition is an ordinary change; a removal or a changed signature is
a breaking one and is reviewed as such. Replacing the library means a second adapter package on the
same contract.

### 4. What the contract fixes towards other components

- **Reason codes.** The contract's codes are the values of the `reason` member in the connector's
  published interface ([IF-02](../contracts/if02-connector.v1.openapi.yaml)), and a test keeps the
  two lists equal. The library reports a replayed proof, a key mismatch and a bad `ath` under one
  OAuth error; the adapter tells them apart from facts it establishes itself, never from message
  text.
- **Replay detection.** The library leaves atomic replay detection to storage. The contract hands
  the replay store the proof's identity as separate values — key thumbprint, method, normalized
  target URI, `jti`, nonce — with the proof's `iat` and the instant it stops being acceptable, which
  is the shape the zone's token store offers
  ([token store API](../contracts/token-store.v1.openapi.yaml)). The library passes only the expiry;
  the adapter derives the `iat` from the same two settings the library used, and a test pins that
  derivation.
- **Freshness window.** The connector's DPoP configuration — proof lifespan and clock skew — is the
  single source of the window in which a proof is acceptable. The replay store applies no window of
  its own: it keeps a record until the instant it is handed, which is the instant the proof stops
  being acceptable, so the two cannot disagree and retuning the window is one change in one place.
  The token store's API takes that instant as `not_after` and, given it, does not apply the default
  window it otherwise would. The store accepts a `not_after` at most 90 seconds after the `iat`, so
  the contract carries the same bound: a configuration whose proof lifespan and clock skew add up to
  more is refused when the provider is built, not at the first token request.
- **Persistence.** Stores are handed token signatures, never usable tokens; the request form is not
  persisted, because it can carry client credentials; client secrets are stored as bcrypt hashes.

### 5. Access-token format

Access tokens are to be **signed tokens** (RFC 9068, `typ: at+jwt`) carrying the key binding as
`cnf.jkt`, so that a protected resource validates the signature against the connector's published
key set and the DPoP proof against the token, without a call back to the connector.

The pinned library does this: with its signed-token strategy switched on, a DPoP-bound client
receives a token of that form whose `cnf.jkt` equals the proof key's thumbprint, and the library's
resource-side proof check accepts it. This was run against v0.3.2.

The adapter does not issue such tokens yet. It issues opaque tokens validated by lookup, which is
what the conformance suite covers today. Moving to signed tokens adds to the contract — a signing
key in the configuration and a handler for the key set — and changes nothing that exists in it.

## Consequences

- Positive: both RFCs come from one maintained library with its own test corpus, so the
  security-protocol code the project owns stays small and reviewable.
- Positive: the connector's behaviour at its published interface is tested, not inferred — status per
  reason, the `WWW-Authenticate` challenges, key-bound registration tokens.
- Negative: the library is pre-1.0 and releases breaking changes — three bursts between May and
  September 2026, from a single maintainer. Mitigation: the boundary above, the version guard, and
  the adapter's use of the library's concrete configuration type rather than its extensible
  interfaces, which is what absorbed the breaks so far.
- Negative: the whole module follows the library's Go requirement, and the shared organisation
  workflows cannot process it. Recorded, with the departure it causes, in
  [Specification changes](../specifications.md) and [CI/CD](../ci-cd.md#go-version).
- Trigger to revisit: the library stops being maintained, or a release breaks the adapter in a way
  it cannot absorb. Either leads to the fallback adapter on the same contract.

## Open items

- **Signed access tokens.** Decision 5 is not implemented. It belongs to the token-issuance and
  resource-side validation work, together with where the signing key is held and how it rotates;
  the staleness matrix in the architecture already budgets for a key set cached by the guard. Until
  then the adapter's tokens can only be validated through the connector.

## References

- RFC 7591 — OAuth 2.0 Dynamic Client Registration; RFC 9449 — DPoP; RFC 7638 — JWK thumbprint;
  RFC 9068 — JWT profile for OAuth 2.0 access tokens
- [Connector OAuth2 provider](../oauth2-provider.md) — the behaviour as tested, the configuration
  and how to change the library version
- `authelia.com/provider/oauth2` v0.3.2 — the pinned release; `ory/fosite` v0.49.0 — the fallback
  measured against
- The evaluation's working material, held with the delivery team outside this repository — the
  release-by-release API comparison and the fallback measurement
