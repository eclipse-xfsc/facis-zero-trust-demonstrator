# Connector OAuth2 provider

The connector issues its own OAuth 2.0 tokens instead of delegating to the identity provider
(see the [architecture decision on the OAuth2 surface](adr/0003-oauth2-authorisation-surface-in-the-go-connector.md)).
The library it is built on, and why, is recorded in the
[decision on the OAuth2 library](adr/0016-oauth2-library-behind-the-connector-provider-contract.md);
the endpoints as other components see them are defined in the
[connector contract](contracts/if02-connector.v1.openapi.yaml).
This page describes the part of that authorization surface that exists today: dynamic client
registration, DPoP-bound access tokens, and the verified-presentation grant that exchanges a signed
IF-03 verification outcome for a token.

| Capability | Specification |
|---|---|
| Dynamic client registration | RFC 7591 |
| Client credentials grant | RFC 6749 section 4.4 |
| Sender-constrained access tokens (DPoP) | RFC 9449 |
| Resource-side validation of bound tokens | RFC 9449 section 7 |
| Signed access tokens, when a signer is configured | RFC 9068 |
| Verified-presentation grant and its challenge endpoint | RFC 6749 section 4.5 (extension grant), [IF-02 v1.1](api-docs.md#if-02-connector-authorization-surface) |

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
| `oauth2provider/memstore` | In-memory stores for tests and local development. Nothing is persisted. Transactions are serialised by one lock and undo-logged; they cover token creation and challenge and outcome consumption only, not client changes or token deletion. |
| `signing` | Access-token signers: `Transit` over an OpenBao transit key, and `Local` over an in-process key for tests only. |
| `oauth2provider/pgstore` | Clients, issued tokens, DPoP nonces, challenges and consumed outcomes in the zone's authorization database (`oauth2_client`, `oauth2_token`, `oauth2_dpop_nonce`, `oauth2_challenge`, `verified_outcome`; schema in the [token store](token-store.md)'s migrations). Validity is checked against the stores' clock, passed as a parameter. Its `Transactions` store runs a PostgreSQL transaction that every client, token, challenge and outcome call made with its context joins; nonce and replay writes never do. `Sweep` removes expired tokens, nonces and unconsumed challenges, never a consumed challenge or outcome. |
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
regenerate the listing. Changes so far: `TokenRecord.ExpiresAt` (field 8) was added so a store can
sweep expired records without reading the session; `Config.Issuer` (field 4),
`Config.AccessTokenSigner` (field 5) and the `TokenSigner` interface were added for signed access
tokens. For the verified-presentation grant: `Provider.ChallengeHandler` was added, a deliberate
change to the interface (an implementation outside this repository would have to add the method;
there is none); `Config.VerifiedPresentation` (field 6) with `VerifiedPresentationConfig` and
`ClaimScopes`; `TokenRecord.OutcomeID` (field 9); `Stores.Challenges`, `Stores.Outcomes` and
`Stores.Transactions` (fields 5 to 7) with the `ChallengeStore`, `OutcomeStore` and `Transactor`
interfaces and the `Challenge` and `VerifiedOutcome` types; `ErrConsumed`;
`VerifiedPresentationGrantType` and `ChallengeLifetime`; and the five `CodeCredOutcome*` reason
codes. With the review of that grant, before it was merged: `TokenRecord.GrantType` (field 10);
`RegistrationConfig.DelegableScopes` (field 3); `ChallengeStore.LockChallenge`; and
`ChallengeStore.ConsumeChallenge` and `OutcomeStore.ConsumeOutcome` take the instant they act at,
so the provider's one clock decides every validity question.

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

A deployment provisions one client that is allowed to obtain such a token, the registrar; whoever
holds the registrar's credentials registers participant backends without an operator creating each
client by hand (`connector register`, [Connector service](connector.md#registering-a-participant)).

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

**Replay protection.** A proof is accepted once. The guarantee holds under concurrency: of one
hundred simultaneous presentations of the same proof, exactly one is accepted and the rest are
refused as replays. A `jti` is scoped to the URI and method the proof was made for, following RFC
9449 sections 4.2 and 11.1, and additionally to the proof key (the in-memory store also to the
nonce). Reusing a `jti` in a new proof for another endpoint is therefore not a replay; presenting
any proof a second time is.

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

## Signed access tokens

With `Config.AccessTokenSigner` set, access tokens are RFC 9068 JWTs that a protected resource
validates against the connector's published key set and the DPoP proof, without calling the
connector (`internal/tokenverify` does this). Without it, access tokens stay opaque, as before.
Registration access tokens are opaque in both cases.

Header: `typ` `at+jwt`, `alg` `ES256`, `kid` the signer's `KeyID()`. Nothing else.

| Claim | Value |
|---|---|
| `iss` | `Config.Issuer`, required when a signer is set |
| `sub` | The client id. No end user is involved in the grant (RFC 9068 section 2.2) |
| `client_id` | The client id |
| `aud` | The granted audience |
| `scope` | The granted scopes as one space-separated string |
| `jti` | A random id per token |
| `iat`, `nbf`, `exp` | Integer seconds. The lifetime defaults to five minutes with a signer |
| `cnf.jkt` | The thumbprint of the key of the DPoP proof validated at the token endpoint |

`scope` is a string, as RFC 9068 section 2.2.3 defines it and as the resource-side verifier reads
it. The library's default is a JSON list under the same name, which the verifier refuses; the adapter
selects the string form.

Every signed token carries `cnf.jkt` and `aud`, so a signed token is issued only to a request that
presents a valid DPoP proof and names an audience the client is allowed. Without a proof the request
is refused with `invalid_dpop_proof` (`reason` `dpop_invalid_proof`) even when `DPoP.Enforce` is off
and the client is not registered for bound tokens; without an audience it is refused with
`invalid_request`. No default audience is assumed. A dynamically registered client therefore
registers the audiences it needs, and the token that authorises the registration must carry them.

The signer contract, `oauth2provider.TokenSigner`, is `KeyID()`, `Public()` (the P-256 public key)
and `Sign(ctx, signingInput)` returning the 64-byte `R||S` ES256 signature. `Sign` receives the
context of the request being served. The adapter refuses at start-up a signer with an empty key id or
a key that is not P-256.

`signing.Transit` implements it over one pinned version of an OpenBao transit key: the public key is
read once by `NewTransit`, the key id is its RFC 7638 thumbprint, and `Sign` asks transit to sign, so
the private key never enters the process. `signing.Local` holds the key in memory and is for tests
only.

The token is still recorded in the access-token store under its signature, like an opaque token, so
`ValidateResourceRequest` accepts it on the same terms: the record must exist, the signature must
verify against the configured key with exactly that `kid`, `alg` and `typ`, `iss` must match and the
token must not have expired. The algorithm and key are fixed by the adapter; whatever a registered
client's metadata says about access-token signing or encryption is not used.

## Verified-presentation grant

A client proves a credential presentation instead of only its secret. It obtains a challenge from
the connector, has its presentation verified against that challenge, and exchanges the signed IF-03
outcome ([IF-03](api-docs.md#if-03-signed-verification-outcome)) for an access token. The grant is
enabled by `Config.VerifiedPresentation` and is served by `TokenHandler`, with the challenge
endpoint served by `ChallengeHandler`.

**Challenge.** `POST` to the challenge endpoint with client authentication as at the token endpoint
(the library's own client authentication is reused) and one form value `audience`, which must be one
of the client's registered audiences. The client must be registered for the grant type. The answer
is `{"challenge": ..., "expires_in": 120}` with `Cache-Control: no-store`; the challenge is 256
random bits, base64url (43 characters), stored single-use in `oauth2_challenge` bound to the client
and the audience.

**Token request.** `grant_type=urn:facis:params:oauth:grant-type:verified-presentation`, `outcome`
(the compact JWS), `challenge` and `audience`, each exactly once, with a DPoP proof. `scope` and
`resource` are refused: the outcome's claims decide the scopes. The request is validated without any
write, in this order:

| Check | Refusal |
|---|---|
| The client is authenticated, confidential and registered for the grant | `invalid_client` 401, `unauthorized_client` 400 |
| The audience is one of the client's | `invalid_request` 400 |
| `internal/if03` verifies the JWS against the configured trusted issuers | `CRED-OUTCOME-SIGNATURE` |
| The outcome's status is `verified` | `CRED-OUTCOME-NOT-VERIFIED` |
| The outcome's `client_id`, `challenge` and `audience` equal the authenticated client and the form's; the stored challenge exists and is bound to that client and audience | `CRED-OUTCOME-MISMATCH` |
| The outcome's interval is sound and current; the challenge has not expired | `CRED-OUTCOME-EXPIRED` |
| The challenge is unconsumed | `CRED-OUTCOME-CONSUMED` |
| The claims map to at least one scope the client is registered for | `invalid_scope` 400 (`reason` `invalid_request`) |

Every `CRED-OUTCOME-*` refusal is `400 invalid_grant` with the code as `reason`. Error responses and
the errors behind them carry fixed text only, never anything of the outcome.

**Transaction.** `TokenHandler` begins a transaction only after `NewAccessRequest` has accepted a
request of this grant, so client authentication, the DPoP proof and its nonce and replay records stay
outside it. `NewAccessResponse` runs with the transaction's context. In it the grant checks that a
DPoP binding was validated (a token without `cnf.jkt` is never issued), then takes the challenge's
row lock (`SELECT ... FOR UPDATE`) **before** anything is judged, and only then reads the clock: every
check above runs again at that instant, so a request that waited behind another transaction is never
judged at the time it started waiting. It then consumes the challenge (a conditional update at the
same instant, passed to the database as a parameter), inserts the outcome into `verified_outcome`
already consumed (a second insert of one `outcome_id` is a no-op), reads the clock once more and
refuses `CRED-OUTCOME-EXPIRED` if the outcome or the challenge expired meanwhile, and only then signs
the token and stores it with `oauth2_token.outcome_id` and its `grant_type`. Validity, the challenge's
expiry and every instant written come from one clock, the provider's.

The transaction is settled before any response is written. It commits after `NewAccessResponse`
returns; on any error before that, it is rolled back and the error answered. A commit that reports
an error is cleaned up the same way, since a transactor may fail without settling; but a commit can
also have succeeded before its acknowledgement was lost. That request is answered `500 server_error`
without the token, and the consumption stands: nothing resets a consumption to compensate, so the
outcome and the challenge cannot be used again (IF-03, D10: the next attempt uses a fresh challenge
and outcome). A panic during the transaction rolls it back as well. The store adapter implements the
library's `storage.Transactional` by delegating to `Stores.Transactions`, and the grant refuses to
run outside a transaction. Of concurrent requests with one outcome or one challenge exactly one is
issued a token; the others wait for its row lock and are refused `CRED-OUTCOME-CONSUMED`. A refused
request is never signed.

**Token records.** `TokenHandler` records the grant it validated with every access token
(`TokenRecord.GrantType`, `oauth2_token.grant_type`), independently of the grant handler that adds
the outcome. A verified-presentation token without an outcome, or an outcome on any other token, is
refused by the adapter before the store is called, by the in-memory store, and in PostgreSQL by the
constraints `oauth2_token_vp_has_outcome` and `oauth2_token_outcome_only_vp`; `outcome_id` is unique
and references `verified_outcome`.

**Scopes.** `VerifiedPresentation.Scopes` maps an outcome's `role` and `entitlement`, compared exactly
(an empty entitlement matches only an outcome without one), to scopes. What is issued is that list
limited to the client's registered scopes; claims that match no entry, or leave the client nothing,
are refused. Every scope in the mapping is refused by `client_credentials`, however the client is
registered, and the mapping may not contain the registration scope.

**Requirements.** The grant issues signed tokens only, since the token must carry `cnf.jkt` and `aud`:
`New` refuses `VerifiedPresentation` without `AccessTokenSigner`, without the `Challenges`, `Outcomes`
and `Transactions` stores, without trusted issuers or a mapping, with a key id shared by two issuers,
or with a claim pair mapped twice. The token is the RFC 9068 JWT described below, with `sub` and
`client_id` the client, `aud` the one audience and `scope` the mapped scopes.

**Registration.** `Registration.GrantTypes` may include the grant type, so a client can register for
it dynamically. A client needs a mapped scope among its registered scopes to be issued it, and
registration limits a new client's scopes to those of the registrar's token, which can never carry a
verified-presentation scope (`client_credentials` refuses it). `Registration.DelegableScopes` closes
that gap: per registrar client id, the scopes the server lets that registrar grant to the clients it
registers, in addition to its token's. Only the registration endpoint consults it; the registrar is
never issued those scopes itself, and the registration scope is never delegable (refused at start-up,
and by the library whatever the ceiling).

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
| `CRED-OUTCOME-SIGNATURE` | The verification outcome's JWS does not verify with a trusted issuer key, or it is not an IF-03 outcome |
| `CRED-OUTCOME-NOT-VERIFIED` | The outcome's status is not `verified` |
| `CRED-OUTCOME-MISMATCH` | The outcome's client, challenge or audience differs from the request, or the challenge was not issued to this client for this audience |
| `CRED-OUTCOME-EXPIRED` | The outcome or the challenge is outside its validity |
| `CRED-OUTCOME-CONSUMED` | The outcome or the challenge was already used |
| `invalid_request`, `server_error` | As named |

## Configuration

`oauth2provider.Config`:

| Field | Purpose |
|---|---|
| `Secret` | Signs opaque access tokens. At least 32 bytes. |
| `AccessTokenLifespan` | Defaults to one hour, or five minutes with `AccessTokenSigner`. |
| `Issuer` | The `iss` of signed access tokens. Required with `AccessTokenSigner`. |
| `AccessTokenSigner` | Makes access tokens signed JWTs (see [Signed access tokens](#signed-access-tokens)). Opaque tokens when nil. |
| `DPoP.Enforce` | Require a proof from every client, not only from clients registered for bound tokens. |
| `DPoP.NonceRequired` | Challenge with a server nonce. |
| `DPoP.ProofLifespan`, `DPoP.ClockSkew` | The freshness window. Together at most 90 seconds, the longest the token store keeps a replay record; a larger sum is refused at start-up. |
| `DPoP.NonceLifespan` | How long an issued nonce stays valid. |
| `DPoP.Algorithms` | Accepted proof signature algorithms. |
| `Registration.Secret` | Signs registration access tokens. At least 32 bytes and different from `Secret`. |
| `Registration.EndpointURL` | Absolute URL of the registration endpoint; also the audience a token must carry there. |
| `Registration.GrantTypes` | Grant types a client may register for. |
| `Registration.DelegableScopes` | Per registrar client id, scopes it may grant to clients it registers beyond its token's scopes; never the registration scope. |
| `VerifiedPresentation.TrustedIssuers` | IF-03 issuers and their P-256 keys by `kid`. Non-empty enables the grant. |
| `VerifiedPresentation.Scopes` | Claims to scopes: `Role`, `Entitlement`, `Scopes` per entry. The challenge lifetime is fixed at 120 s (`ChallengeLifetime`). |

Persistence is supplied through small interfaces — clients, access tokens, registration tokens, DPoP
nonces and DPoP replay state, and for the verified-presentation grant challenges, consumed outcomes
and transactions. Stores are handed token signatures, never usable tokens, and the
request form is not persisted because it can carry client credentials.

The replay store receives a proof's identity as separate values — key thumbprint, method, normalized
target URI, `jti` and nonce — together with the proof's `iat` and the instant it stops being
acceptable. It decides atomically whether the proof was seen before; two uses are the same proof
when thumbprint, method, URI and `jti` are equal, and a store may also distinguish by nonce, as the
in-memory one does. `pgstore` records the use in the zone's shared `proof_jti` table
(`internal/replay`), the record the token store's replay check uses and a resource-side verifier
(`internal/tokenverify`) can be given, with the URI normalised once more by `dpopproof.NormalizeURI`
(the provider keeps an empty port, the shared form does not), so a proof seen by one is seen by all;
a URI that has no such form fails closed.

## Running the connector

`connector serve` (`services/connector`, image `deployment/docker/connector/Dockerfile`) runs the
provider on the PostgreSQL stores (`pgstore`, replay included) with access tokens signed through
`signing.Transit`. It has two plain-HTTP listeners and writes JSON records and security-state
events on stdout. Its registration policy, audit trail, chart, identity and the `connector register`
client are described in [Connector service](connector.md).

### Configuration

Every flag defaults to the environment variable of the same name; a flag set on the command line
wins, and the environment fills in after parsing, so no value, the database URL above all, ever
reaches the usage text. The database URL is never logged. Secrets never come from a flag or a
variable: the OpenBao token, the two HMAC secrets and the registrar's secret are read from files,
named below; the database URL, which holds a credential, comes from a flag or a variable and is
never logged. A trailing
line break in a secret file is not part of the secret.

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--addr` | `CONNECTOR_ADDR` | `:8080` | The API listener |
| `--ops-addr` | `CONNECTOR_OPS_ADDR` | `:9090` | The ops listener the kubelet probes: `/healthz` and `/readyz` |
| `--database-url` | `CONNECTOR_DATABASE_URL` | required | PostgreSQL connection URL of the zone's authorization database |
| `--openbao-url` | `CONNECTOR_OPENBAO_URL` | required | OpenBao, `http(s)://host[:port]` and nothing more |
| `--openbao-token-file` | `CONNECTOR_OPENBAO_TOKEN_FILE` | required | File holding the OpenBao token, read on every call, so a rotated token is picked up |
| `--issuer` | `CONNECTOR_ISSUER` | required | `iss` of the access tokens, an `https://` URL |
| `--signing-key` | `CONNECTOR_SIGNING_KEY` | required | Transit key that signs the access tokens |
| `--signing-key-version` | `CONNECTOR_SIGNING_KEY_VERSION` | required | Pinned version of that key, 1 or more |
| `--registration-endpoint` | `CONNECTOR_REGISTRATION_ENDPOINT` | required | Absolute URL of `POST /oauth2/register` as clients reach it; also the audience a registration token must carry |
| `--token-secret-file` | `CONNECTOR_TOKEN_SECRET_FILE` | required | File holding the HMAC secret of opaque tokens, 32 bytes or more |
| `--registration-secret-file` | `CONNECTOR_REGISTRATION_SECRET_FILE` | required | File holding the HMAC secret of registration access tokens, 32 bytes or more, different from the other |
| `--registrar-id` | `CONNECTOR_REGISTRAR_ID` | required | Client id of the registrar, seeded at start (below) |
| `--registrar-secret-file` | `CONNECTOR_REGISTRAR_SECRET_FILE` | required | File holding the registrar's client secret, 32 bytes or more |
| `--registrar-scopes` | `CONNECTOR_REGISTRAR_SCOPES` | required | Comma-separated scopes of the registrar; must include `connector:client_registration`, plus the scopes registered clients may receive |
| `--registrar-audiences` | `CONNECTOR_REGISTRAR_AUDIENCES` | required | Comma-separated audiences of the registrar: the registration endpoint plus the resource audiences registered clients may name. A registrar token can carry no other, and a client can only register an audience its registrar token carries |
| `--registrar-delegable-scopes` | `CONNECTOR_REGISTRAR_DELEGABLE_SCOPES` | none | Comma-separated scopes the registrar may grant to the clients it registers beyond its own token's: `Registration.DelegableScopes` for `--registrar-id`. This is how a client gets a verified-presentation scope. Never `connector:client_registration` |
| `--vp-trusted-issuers-file` | `CONNECTOR_VP_TRUSTED_ISSUERS_FILE` | none | JSON file of the IF-03 issuers and their keys (below). Set, it enables the verified-presentation grant; unset, the grant is off and the challenge endpoint refuses every request |
| `--vp-scope-map-file` | `CONNECTOR_VP_SCOPE_MAP_FILE` | none | JSON file mapping outcome claims to scopes (below); required with, and refused without, the issuers file |
| `--access-token-lifespan` | `CONNECTOR_ACCESS_TOKEN_LIFESPAN` | `300s` | Lifetime of an access token |
| `--dpop-enforce` | `CONNECTOR_DPOP_ENFORCE` | `true` | Require a proof from every client (`--dpop-enforce=false` to relax) |
| `--dpop-nonce` | `CONNECTOR_DPOP_NONCE` | `true` | Challenge with a server nonce |
| `--readiness-timeout` | `CONNECTOR_READINESS_TIMEOUT` | `2s` | Budget of one `/readyz` evaluation |
| `--drain-delay` | `CONNECTOR_DRAIN_DELAY` | `5s` | On SIGTERM, how long `/readyz` answers 503 while the listeners stay open |
| `--shutdown-timeout` | `CONNECTOR_SHUTDOWN_TIMEOUT` | `10s` | Drain of the listeners after that delay; what is still open then is closed |
| `--log-level` | `CONNECTOR_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `--zone` | `CONNECTOR_ZONE` | required | `a` or `b`: the source of the security-state events is `connector-<zone>`; their run id is minted at every start ([Connector service](connector.md#security-state-events)) |

The DPoP proof window is fixed at 60 s lifespan and 30 s skew. A missing, short or shared secret
file stops the process at start with exit 1; a usage error exits 2; a clean stop exits 0. A
database URL that cannot be parsed is refused as "invalid database configuration" and nothing
more: the driver's own error repeats the URL with only best-effort masking of the password.

### Verified-presentation files

Both files are read once at start and parsed strictly: valid UTF-8 JSON, no duplicate member at any
depth, no member other than those below, at most 1 MiB. A file that breaks a rule stops the process
with exit 2 and a fixed message naming the flag and the rule, never anything the file holds.

The trusted-issuers file is `VerifiedPresentation.TrustedIssuers`: an object whose members are the
issuer URIs (the outcomes' `iss`), each `{"keys": [...]}` with one or more public EC P-256 JWKs.
A key has exactly `kty`, `crv`, `x`, `y` and `kid`: a private member (`d`), another curve, a missing
`kid` or a `kid` used twice, within one issuer or across two, is refused.

```json
{
  "https://verifier.example": {
    "keys": [{"kty": "EC", "crv": "P-256", "x": "...", "y": "...", "kid": "verifier-2026-10"}]
  }
}
```

The scope-map file is `VerifiedPresentation.Scopes`: a non-empty array of `{"role", "entitlement",
"scopes"}`, `entitlement` optional (an entry without it matches only an outcome without one),
`scopes` one or more scopes without whitespace. A role and entitlement pair may appear once, and
`connector:client_registration` is never mapped.

```json
[
  {"role": "operator", "entitlement": "line-3", "scopes": ["resource.write"]},
  {"role": "operator", "scopes": ["resource.read"]}
]
```

With the grant on, clients may register for `urn:facis:params:oauth:grant-type:verified-presentation`
besides `client_credentials`. The registrar itself keeps `client_credentials` only: it never uses the
grant, and delegation does not need it to. To register a client for a mapped scope, list that scope
in `--registrar-delegable-scopes`; the registrar's own token can never carry it.

### Registrar bootstrap

Registration takes a token for the registration endpoint (above), so a fresh deployment needs one
client that can get such a token: the registrar (D12). At start the connector seeds it in the
background, retrying while the database is not there: client id `--registrar-id`, grant type
`client_credentials`, DPoP-bound, the configured scopes and audiences, and the secret from
`--registrar-secret-file` stored as a bcrypt hash (default cost). If the client already exists with
exactly these settings (the secret verifies against the stored hash, same scopes, audiences, grant
type and binding) nothing is written. If it exists with any other setting, it is never overwritten:
the connector logs `registrar client exists with other settings; not overwriting it, not becoming
ready` and stays not ready until an operator resolves it and restarts it.

The registrar asks for a token with a DPoP proof, `scope` including `connector:client_registration`
and `audience` naming the registration endpoint and the resource audience the new client will
register, then posts the client's metadata to `/oauth2/register` with that token. `connector
register` does exactly this and writes the new client's credentials file
([Connector service](connector.md#registering-a-participant)).

### Endpoints

| Listener | Path | Serves |
|---|---|---|
| API | `POST /oauth2/token` | The token endpoint (`Provider.TokenHandler`) |
| API | `POST /oauth2/register` | Client registration (`Provider.RegistrationHandler`) behind the connector's registration policy, every decision audited ([Connector service](connector.md#registration)) |
| API | `POST /oauth2/challenge` | The challenge endpoint (`Provider.ChallengeHandler`); refuses every request while the verified-presentation grant is off |
| API | `GET /.well-known/jwks.json` | The signing key as a JWK set: `kid` the signer's `KeyID()`, `use` `sig`, `alg` `ES256`; `Cache-Control: public, max-age=300` |
| API and ops | `GET /healthz`, `GET /readyz` | Liveness and readiness |

Every API request runs under a 5 s deadline, which bounds its database and transit calls.

### Start, readiness and drain

The connector never waits for its dependencies. It reads the pinned key's public half from transit
in the background, retrying with backoff up to 30 s, and until that succeeds every API path but the
health ones answers 503 and readiness is red; a connector started before OpenBao, or before the key
version exists, starts, stays up and becomes ready on its own.

`/readyz` answers 200 only when all four checks say `ok`, 503 otherwise, with the checks' words:

```json
{"ready": false, "checks": {"postgres": "ok", "openbao": "ok", "signing_key": "missing", "registrar": "ok"}}
```

- `postgres`: `ok`, `unreachable`, or `schema_behind` when the newest version in `schema_migrations`
  (written by `token-store migrate`) is below the one this build needs. The connector cannot import
  the token store's migration runner, so it checks the version only; checksum drift is the token
  store's readiness to report. A test keeps the needed version equal to the newest migration file,
  so a new migration fails it until someone decides whether the connector needs that migration.
- `openbao`: `/v1/sys/health`, `ok`, `unreachable`, `uninitialized` or `sealed`.
- `signing_key`: the pinned version is read again and its RFC 7638 thumbprint must equal the
  signer's `kid`: `ok`, `missing` (no such version), `mismatch`, `pending` (signer not built yet) or
  `unreachable`.
- `registrar`: the bootstrap's outcome, `ok`, `pending` (not seeded yet) or `conflict` (exists with
  other settings).

The signer and the route table built on it are published together, so readiness can never be green
while the API still answers 503. The first three checks run at once under the readiness budget; only a change of outcome is logged. On SIGTERM
`/readyz` answers 503 with `"draining": true` at once, both listeners keep answering for the drain
delay, then drain within the shutdown timeout, are force-closed if that runs out, and the pool closes.

### Upkeep

As in the token store: the replay epoch sentinel (`replay_epoch`) is checked at start, every 10 s
and whenever the pool opens a connection; a missing row is one warning naming the 120 s window in
which a proof could be replayed once. Every minute `pgstore.Sweep` removes expired tokens and nonces
and `replay.Sweep` expired proof records. Each of these database operations runs under a 2 s timeout.

### Records

One JSON object per line on stdout, with `service` `connector` and `instance` on all of them. A
request's records carry its `correlation_id`: the caller's `x-request-id` when it is 1 to 128 visible
ASCII characters, a minted one otherwise; the response echoes it. Every request ends with one
`request` record (`method`, `path`, `status`, `duration_ms`). No header, query or body is logged, so
no token, proof, client secret or `Authorization`/`DPoP` header reaches a record; a test runs the
binary against PostgreSQL and OpenBao and checks the records for canary secrets.

The challenge endpoint of the VP grant joins the route table in `services/connector/server.go`
(`apiRoutes`) as one line beside the token endpoint.

## Running the conformance tests

```sh
go test ./services/connector/...
go test -race ./services/connector/...
```

The tests run the provider behind a real HTTP server and drive it from the outside. Stale, future and
otherwise defective proofs are minted with the claims they need, and expiry is exercised by moving the
stores' clock, so no test waits for time to pass. Test names state the rule they check:
`TestDPoP_…`, `TestResource_…`, `TestRegistration_…`, `TestStore_…`, `TestVP_…`. The
verified-presentation tests run with a signer of their own whatever `CONNECTOR_TEST_TOKENS` says, and
sign IF-03 outcomes with an in-test issuer key; on PostgreSQL they also read `verified_outcome` and
`oauth2_token.outcome_id` directly.

The same suite runs on the PostgreSQL stores when `CONNECTOR_TEST_STORE=pg` and
`TOKEN_STORE_TEST_DATABASE_URL` names a server (each test gets a database of its own with the schema
applied); the token store's CI job runs it that way and fails on a skip:

```sh
CONNECTOR_TEST_STORE=pg TOKEN_STORE_TEST_DATABASE_URL=postgres://postgres:ci@127.0.0.1:5432/postgres?sslmode=disable \
  go test -race ./services/connector/...
```

`CONNECTOR_TEST_TOKENS=jwt` runs the same suite with signed access tokens from an in-process key
(`opaque`, the default, keeps opaque tokens). The two settings combine. A test checks that a signed
token is accepted by `internal/tokenverify` and refused by it for another proof key, a missing proof,
an expired token and another audience. With `TRANSIT_TEST_ADDR` and `TRANSIT_TEST_TOKEN` naming an
OpenBao dev server, the same check runs on a token signed through `signing.Transit`:

```sh
CONNECTOR_TEST_TOKENS=jwt go test -race ./services/connector/...
TRANSIT_TEST_ADDR=http://127.0.0.1:8200 TRANSIT_TEST_TOKEN=dev \
  go test -race -run TestSignedTokens ./services/connector/internal/oauth2provider/authelia
```

The binary's own tests (`services/connector`) need both servers for the end-to-end ones:

```sh
TOKEN_STORE_TEST_DATABASE_URL=postgres://postgres:ci@127.0.0.1:5432/postgres?sslmode=disable \
TRANSIT_TEST_ADDR=http://127.0.0.1:8200 TRANSIT_TEST_TOKEN=dev \
  go test -race ./services/connector
```

### Session records

A token record keeps the adapter's own encoding of the session, versioned (`v: 1`): the access token's
expiry, the subject and the key binding (`jkt`, or a certificate thumbprint). The library hands the
store different session types for one token and their JSON forms differ, so the adapter writes and
reads every field through the library's interfaces instead of storing the library's JSON. A record
of another version, or a binding the requested session type cannot carry, is refused: a bound token
never comes back looking unbound. `TestStore_BoundTokenStaysBoundAcrossRestart` proves it on both
stores, for opaque and signed tokens: a signed token is stored from the library's JWT session and read
back into its default session.

## Limitations

- `memstore` keeps replay detection, like everything else, in one process: with it a proof can be
  replayed once against another replica or after a restart. `connector serve` uses `pgstore`, whose
  replay record is the zone's shared `proof_jti` table in PostgreSQL.
- Only the `client_credentials` and verified-presentation grants and `client_secret_basic` client
  authentication are wired.
  Client authentication by signed assertion is refused.
- Registration management (RFC 7592) and token introspection are not exposed. A registration
  response nevertheless carries a registration access token and a client configuration URI, which
  lead nowhere yet.
- Without `AccessTokenSigner`, access tokens are opaque and validated by lookup, so a protected
  resource can only validate them through the connector. The key set handler that publishes the
  signer's public key is not part of this layer: `connector serve` serves it at
  `/.well-known/jwks.json`.
- The proof URI is reconstructed from the request. Behind a proxy the scheme is taken from
  `X-Forwarded-Proto`, so that header must be set by a trusted hop only.
- The pinned `authelia.com/provider/oauth2` v0.3.2 requires Go 1.27.x.
