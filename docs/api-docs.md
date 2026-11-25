# API documentation

## Interface registry

The demonstrator's cross-component interfaces are identified `IF-01` through `IF-08`. Except for
IF-07, version 1 of each is defined by machine-readable artefacts in `docs/contracts/` (IF-08's sit
beside this page in `docs/`), which CI validates on every change (see [Validation](#validation)).
Such a v1 contract changes only by a compatible addition; anything else is a v2. Version 1 of IF-07
is the Go interface of `internal/atls`, outside `docs/contracts/` and the `Contracts` job:
`TestExportedAPIFrozen` checks its exported API against its listing, and it changes only as
[its change policy](attested-channel.md#change-policy) states.

| Interface | Purpose | v1 artefacts | Status |
|---|---|---|---|
| IF-01 | Security-state event stream to the demonstrator UI | [event](contracts/if01-event.v1.schema.json), [event v2](contracts/if01-event.v2.schema.json), [snapshot](contracts/if01-snapshot.v1.schema.json), [feed API](contracts/if01-feed.v1.openapi.yaml) | v1 |
| IF-02 | Connector authorization surface — registration and token issuance | [connector API](contracts/if02-connector.v1.openapi.yaml), [rules](#if-02-connector-authorization-surface) | v1 (1.1.1) |
| IF-03 | Credential verification outcome | [JWS payload](contracts/if03-verification-outcome.v1.schema.json), [JWS header](contracts/if03-jws-header.v1.schema.json), [signing rules](#if-03-signed-verification-outcome) | v1 |
| IF-04 | Observability and evidence | The IF-01 event schema, as a JSON log line; [rules](#if-04-observability-and-evidence) | v1 |
| IF-05 | Policy decision input and output | [input](contracts/if05-policy-input.v1.schema.json), [decision](contracts/if05-policy-decision.v1.schema.json), [header rules](#header-propagation-guard-to-gateway) | v1 |
| IF-06 | Governed configuration change | [change](contracts/if06-config-change.v1.schema.json) | v1 |
| IF-07 | Attested channel control — v1: [Go interface of `internal/atls`](attested-channel.md); partner sign-off pending | [States and rules](#if-07-attested-channel-control) | v1, partner sign-off pending |
| IF-08 | Scenario driver hooks | [lifecycle command](lifecycle.openapi.yaml), [lifecycle result](lifecycle-result.schema.json) | v1 (delivered with the BDD pack) |

Internal to a zone, and not a numbered interface: the token store's API,
[token-store.v1.openapi.yaml](contracts/token-store.v1.openapi.yaml) — substitution for the guard
and DPoP replay detection for the connector and the guard. The database behind it, its schema and
how the schema is applied are described in [Token store](token-store.md).

Also not a numbered interface: the verification service's presentation API,
[verification.v1.openapi.yaml](contracts/verification.v1.openapi.yaml) — what a token store's
presentation hook calls to obtain an IF-03 outcome for a challenge
([rules](#presentation-hook-how-an-outcome-is-obtained)).

Three agreements are conventions rather than interfaces, and are documented where they live:

| Convention | Where |
|---|---|
| Identity provider realm, clients, roles and scopes | [Keycloak integration](keycloak.md) |
| Repository, CI and Helm conventions | [CI/CD](ci-cd.md), [Packaging and containers](packaging.md) |
| Acceptance evidence and its handover | [BDD acceptance](bdd.md) |

Upstream APIs are referenced and pinned, never redefined here: Envoy `ext_authz`
(`envoy/service/auth/v3`) and `ext_proc` (`envoy/service/ext_proc/v3`), Keycloak OIDC, SPIFFE
Workload API, the attested-TLS library, and the XFSC services' own APIs.

## Reason codes

Every refusal names a code from one registry, [reason-codes.json](contracts/reason-codes.json)
(schema: [reason-codes.v1.schema.json](contracts/reason-codes.v1.schema.json)). A family names the
layer that refuses, its default HTTP status and the state the UI shows; a code may override the
status.

| Family | Layer | Default HTTP | UI state | Overrides |
|---|---|---|---|---|
| `ADM` | admission | 403 | `BLOCKED-ADMISSION` | — |
| `MESH` | identity and mesh policy | none (connection refused) | `BLOCKED-IDENTITY` | — |
| `TOK` | token authentication | 401 | `DENIED-TOKEN` | `TOK-SCOPE` 403, `TOK-REQUEST-INVALID` 400, `TOK-REGISTRATION-REJECTED` 400, `TOK-NO-UPSTREAM` 409, `TOK-CALLER-DENIED` 403, `TOK-ROUTE-DENIED` 403, `TOK-STORE-UNAVAILABLE` 503, `TOK-SERVER-ERROR` 500, `TOK-KEYSET-UNAVAILABLE` 503 |
| `POL` | policy decision | 403 | `DENIED-POLICY` | `POL-PRESENTATION-REQUIRED` 401, `POL-PDP-UNAVAILABLE` 503, `POL-BUNDLE-STALE` 503 |
| `CRED` | credential verification | 403 | `DENIED-CREDENTIAL` | `CRED-REQUEST-INVALID` 400, `CRED-REQUEST-UNKNOWN` 404 |
| `CHAN` | attested channel | none (handshake refused) | `CHANNEL-DOWN` | — |
| `CFG` | configuration governance | 422 | `CHANGE-REJECTED` | `CFG-NOT-AUTHORISED` 403 |
| `APP` | application mock steps | none (reported step) | `APPLICATION-STATE` | the event state and application HTTP response carry the outcome |
| `VIS` | display | none (display state) | `UNKNOWN` | — |

The status is what a protected resource — the guard — returns to its caller. Three surfaces keep
statuses of their own: the connector's token and registration endpoints answer with the OAuth 2.0
statuses (400 for a DPoP proof or nonce problem at the token endpoint, for example; see
[IF-02](contracts/if02-connector.v1.openapi.yaml)), the token store's internal API states its
own, and the verification service's request endpoints answer with the two `CRED-REQUEST-*`
statuses above; the guard maps all of them to the caller's refusal.

The zone entry's TRAIN allow list ([Connector service](connector.md#train-allow-list-of-the-zone-entry-zt-18))
refuses a counter-connector after the TLS handshake, on its request, so it answers two `CHAN` codes
with a status: `CHAN-ZONE-UNKNOWN` 403 and `CHAN-TRUST-UNREACHABLE` 503.

Admission refusals, one code per cause: `ADM-UNSIGNED`, `ADM-NO-ATTESTATION`,
`ADM-ATTESTATION-INVALID`, `ADM-SBOM-MISSING`, `ADM-SBOM-INVALID`, `ADM-NOT-LINUX`,
`ADM-ARCH-UNSUPPORTED` (only `linux/amd64` is admitted), `ADM-INDEX-UNSUPPORTED` (only
single-platform manifests are admitted), `ADM-NOT-DIGEST`,
`ADM-REGISTRY-DENIED`, `ADM-NAME-INVALID`, and `ADM-PROVIDER-DOWN` when verification cannot run —
admission then fails closed.

### Mapping of existing vocabularies

The connector's error responses carry the OAuth 2.0 members plus a `reason` member
([Connector OAuth2 provider](oauth2-provider.md#reason-codes)). They map one to one onto the
registry's codes; the HTTP status stays the connector's:

| Connector `reason` | Registry code |
|---|---|
| `invalid_request` | `TOK-REQUEST-INVALID` |
| `invalid_client` | `TOK-CLIENT-INVALID` |
| `invalid_token` | `TOK-INVALID` (`TOK-MISSING` when no token was presented) |
| `insufficient_scope` | `TOK-SCOPE` |
| `registration_rejected` | `TOK-REGISTRATION-REJECTED` |
| `server_error` | `TOK-SERVER-ERROR` |
| `dpop_invalid_proof` | `TOK-PROOF-INVALID` |
| `dpop_replayed` | `TOK-REPLAY` |
| `dpop_use_nonce` | `TOK-NONCE` |
| `dpop_jkt_mismatch` | `TOK-JKT-MISMATCH` |
| `dpop_invalid_ath` | `TOK-ATH-MISMATCH` |
| `CRED-OUTCOME-SIGNATURE`, `CRED-OUTCOME-NOT-VERIFIED`, `CRED-OUTCOME-MISMATCH`, `CRED-OUTCOME-EXPIRED`, `CRED-OUTCOME-CONSUMED` | The same code (verified-presentation grant, below) |

IF-08 keeps the `errors.action` vocabulary it was delivered with (below); it reports the outcome of
an operator command, not an access refusal, so it is not part of the registry.

## IF-01 — security-state feed

Components write IF-01 events as JSON log lines. A feed bridge collects them per run and serves the
UI a snapshot followed by a server-sent event stream; WebSocket is not used, since the flow is one
way.

- **Order and delivery.** Ordering holds per `source` only; across sources, events are ordered for
  display by `ts` and `correlation_id`. Delivery is at least once and the UI deduplicates by
  `(run_id, seq)`.
- **Staleness.** On a sequence gap or a stale `ts` a panel shows `UNKNOWN`, never its last known
  value. When the bridge's buffer of 1000 events per run overflows, it drops the oldest and emits a
  `gap` event with `VIS-STALE`. On reconnect the UI reads the snapshot and resumes from
  `as_of_seq + 1`.
- **Content.** A decision or admission event is `allowed` or `denied`, and a denial names its
  reason code. Events carry no secrets or tokens; `detail` is at most 512 characters.

### Version 2: the decision fields

[`if01-event.v2.schema.json`](contracts/if01-event.v2.schema.json) is the v1 event with
`"version": 2` and, on a `decision`, five members that are always present: `caller_spiffe_id`,
`token_subject`, `resource` (method and configured target), `bundle_revision` and `rule_id`. A
member the request never reached — the token subject of a request refused before authentication,
the bundle and rule of one refused before policy, the caller of one whose mesh identity is not
allowed — is the literal `not_evaluated`, never omitted. v2 adds the sources `policy-a` and
`policy-b`, `participant-a/b` and `protected-resource-a/b`. v1 stays valid and unchanged; the guard and the policy evaluator write v2
(`hook.NewLogSinkV2`), the policy-hook verification probe writes v1, and the feed bridge serves
both.

The guard refuses some requests before policy. Its verifier's runtime codes are mapped to the
registry; the runtime code stays in the event's `detail`, so two causes under one code (a missing
and an invalid proof) remain distinguishable in the audit trail. The test
`TestRefusalsUseTheRegistry` (`services/guard`) holds the table to the registry.

| Runtime code (event `detail`) | Registry code | Status |
|---|---|---|
| `route_denied`, `host_denied` | `POL-RULE-DENY`, rule `guard-route-allowlist` | 403 |
| `mesh_caller_denied` | `MESH-PAIR-DENIED` | 403 |
| `token_absent` | `TOK-MISSING` | 401 |
| `token_malformed`, `signature_invalid`, `issuer_mismatch`, `audience_mismatch` | `TOK-INVALID` | 401 |
| `token_expired` | `TOK-EXPIRED` | 401 |
| `proof_absent`, `proof_invalid` | `TOK-PROOF-INVALID` | 401 |
| `key_binding_mismatch` | `TOK-JKT-MISMATCH` | 401 |
| `proof_replayed` | `TOK-REPLAY` | 401 |
| `scope_insufficient` | `TOK-SCOPE` | 403 |
| `request_invalid` | `TOK-REQUEST-INVALID` | 400 |
| `replay_unavailable` | `TOK-STORE-UNAVAILABLE` | 503 |
| `key_set_unavailable` | `TOK-KEYSET-UNAVAILABLE` | 503 |
| `unclassified` | `TOK-SERVER-ERROR` | 500 |

The M3 policy evaluator answers a denial with one rule per reason, so insufficient scope and a
policy rule are distinct: `m3-default-deny` (the request's shape, caller, audience or proof),
`m3-client-blocked` (a rule naming the client), `m3-presentation-required`
(`POL-PRESENTATION-REQUIRED`, the OID4VP link in the body), `m3-tenant-route` (the configured
route does not match the scope), `m3-tenant-membership` (the caller is not a member of the target
tenant) and `m3-scope-required` (no scope the policy grants). Every answer is one v2 event under the
guard's correlation id, with the rule id and the bundle revision.

A tenant guard (guard configuration `target_tenant`) sends the tenant its route belongs to as the
IF-05 input's `target_tenant`, from its configuration and never from the request; the evaluator's
`tenant_members` names the callers that are members of each tenant, and any other caller, a request
without a target tenant, or a target tenant the evaluator does not serve is denied by
`m3-tenant-membership`. The guard's and the evaluator's v2 events then carry `tenant`, the target
tenant of the decision.

### Feed bridge: versions, ownership and sequencing

The bridge is `cmd/feed-bridge` (`internal/feedbridge`), deployed in the mesh by
`deployment/helm/feed-bridge`. The client selects the feed version by path:
[v1](contracts/if01-feed.v1.openapi.yaml) (`/snapshot`, `/events`) stays valid against the v1
schemas — a v2 event is served in its v1 form and a source v1 does not name (policy evaluators and application mocks)
is left out — and [v2](contracts/if01-feed.v2.openapi.yaml) (`/v2/snapshot`, `/v2/events`,
[snapshot v2](contracts/if01-snapshot.v2.schema.json)) serves every line as written and every v2
source. Producers post their lines to `/ingest`. Ownership:

- **Sequence numbers are the producers'.** Each process names its own run (`guard-<start time>`,
  `policy-<start time>`) and numbers its events from 0, so `(run_id, seq)` is unique and the
  bridge never renumbers. A repeated seq is an at-least-once duplicate and is dropped; a seq that
  skips ahead is recorded as a `gap` event (`VIS-STALE`) under the first missing number.
- **Memory is the bridge's**, and bounded: the last 1000 events per run (a reader asking for older
  ones receives a `gap` event first), every run together within a byte budget (`--budget-bytes`,
  32 MiB by default) by dropping the least recently updated runs, which are answered `410`; a line
  over 64 KiB is drained and counted, never buffered.
- **Retention is the collectors'**, not the bridge's: the same lines travel the IF-04 path of the
  observability release (node collector → zone gateway → entry) into one file per zone on the
  entry's volume, rotated by size with nine backups (`deployment/helm/values/otel-entry.yaml`,
  `logExport`); `scripts/verify-observability` proves the export (`logs-exported`,
  `if01-fields-kept`). The bridge keeps nothing on disk.
- **Access is the mesh's**: the bridge authenticates nobody itself. Its chart sets STRICT mTLS and an
  AuthorizationPolicy that admits only the UI's identity to the feed and only the listed producers
  to `/ingest`; outside the mesh it binds to the loopback.
- **Known limit: no tenant authorisation.** The bridge selects runs by `run_id` alone: a reader it
  admits sees every run, every tenant's decisions included (the v2 events carry `tenant`, but the
  bridge filters nothing by it). It is a UI-only feed, reachable only through the mesh rule above or
  the loopback; a per-tenant view would need the reader's tenant bound to its identity and a filter
  on `tenant`, which is not built.

## IF-02 — connector authorization surface

The connector's token, registration and challenge endpoints
([connector API](contracts/if02-connector.v1.openapi.yaml), v1.1.1;
[Connector OAuth2 provider](oauth2-provider.md)). Version 1.1 adds, compatibly, the
verified-presentation grant, which consumes IF-03 outcomes; 1.1.1 names the `audience` member of
the client metadata, which registrations already carried:

- **Challenge.** `POST /oauth2/challenge`, client authentication as at the token endpoint, form
  `audience` — exactly one of the client's registered audiences. The client must be registered for
  the grant. The answer, `{"challenge", "expires_in": 120}` with `Cache-Control: no-store`, is a
  single-use value of at least 128 random bits, bound to that client and audience.
- **Grant.** `POST /oauth2/token` with
  `grant_type=urn:facis:params:oauth:grant-type:verified-presentation`, `outcome` (the IF-03 compact
  JWS), `challenge` and a single `audience`, and a DPoP proof, which this grant always requires. The
  checks run in this order, each refusing with `400 invalid_grant` and its code: signature
  (`CRED-OUTCOME-SIGNATURE`); status (`CRED-OUTCOME-NOT-VERIFIED`); the outcome's client, challenge
  and audience against the authenticated client and the form, and the stored challenge's binding to
  that client and audience (`CRED-OUTCOME-MISMATCH`); the outcome's and the challenge's validity
  (`CRED-OUTCOME-EXPIRED`); the outcome and the challenge unconsumed (`CRED-OUTCOME-CONSUMED`). A
  refusal never repeats the outcome.
- **Consumption.** The challenge, the outcome (recorded in `verified_outcome`) and the issued token
  (`oauth2_token.outcome_id`) are written in one transaction, which locks the challenge first and
  judges validity at an instant taken after the lock is held, and is settled before the response is
  written. A second use of an outcome or a challenge is `CRED-OUTCOME-CONSUMED` and is never signed
  again; of concurrent uses exactly one is issued a token. When the commit's outcome is unknown the
  answer is `500` without the token and the consumption stands; the client starts again with a fresh
  challenge and outcome.
- **Scopes.** The outcome's `role` and `entitlement` map to scopes by configuration, limited to the
  client's registered scopes; claims that map to nothing are refused (`invalid_scope`). Those scopes
  are never issued through `client_credentials`. The token is an RFC 9068 JWT with `cnf.jkt` and the
  one `aud`.
- **Registration.** A deployment may admit the grant type in dynamic registration. A registrar can
  grant a client a verified-presentation scope only through a delegation ceiling the server
  configures for it, since its own token can never carry such a scope. The connector's own
  registration policy ([Connector service](connector.md#the-policy)) requires a `client_name`,
  `grant_types`, a `client_secret_basic` client, `dpop_bound_access_tokens: true`, a `scope` and
  one or more absolute `audience` URLs, and admits no member outside those six; a violation is
  refused as `400 invalid_client_metadata` with the reason `registration_rejected` and a
  description naming the rule, the shape of the library's own refusal. Every registration
  decision is audited (`TOK-REGISTRATION-REJECTED` for a refused registration).
- **Why 1.1.1 is a compatible change.** The policy refuses metadata that 1.1.0 did not forbid in
  so many words. RFC 7591 section 3.2.2 lets an authorization server refuse any client metadata
  value with `invalid_client_metadata`, and IF-02 always allowed that refusal on this endpoint, so
  a refusal under the policy is one of the answers a 1.1.0 client already had to handle. Nothing a
  1.1.0 client receives changed shape, and the one member 1.1.1 adds, `audience`, was already sent
  by every registrar. A client that sends what the policy requires is accepted under both.

## IF-03 — signed verification outcome

The verification service signs the outcome of an OID4VP presentation check; the connector's
issuance consumes it. The outcome is an object, never a boolean.

- **Format.** A compact JWS (RFC 7515). The payload is the UTF-8 JSON of
  [if03-verification-outcome.v1.schema.json](contracts/if03-verification-outcome.v1.schema.json).
  The protected header has exactly `alg`, `kid` and `typ`
  ([if03-jws-header.v1.schema.json](contracts/if03-jws-header.v1.schema.json)): `alg` is `ES256`,
  `typ` is `facis-verification-outcome+jws`. Any other member — `crit`, `b64`, `jwk`, `jku`, `x5u`,
  `x5c` — is refused, so a key or a processing rule is never taken from the token itself.
- **Key selection.** The verifier holds a configured set of trusted issuers, each with its keys.
  `kid` selects one key; the payload's `iss` must be the issuer that key belongs to. An unknown
  `kid`, a key of another issuer, or a signature that does not verify → `CRED-OUTCOME-SIGNATURE`.
  A header or payload that does not follow its schema (an unknown or differently cased member, a
  `null` where a value is required, a malformed `uri` or `date-time`) is refused with the same code:
  whoever signed it, it is not an outcome in the agreed form, so nothing in it is used
  (`internal/if03`).
- **Consumption.** An outcome is consumed only when all hold, otherwise the grant is refused with
  the code named:
    - `status` is `verified` → else `CRED-OUTCOME-NOT-VERIFIED`;
    - `client_id`, `challenge` and `audience` equal those of the grant request → else
      `CRED-OUTCOME-MISMATCH`;
    - the validity interval is sound and current: `verified_at` is before `expires_at`, at most
      120 s before it, and not more than 30 s in the future (clock skew); now is before
      `expires_at` → else `CRED-OUTCOME-EXPIRED`;
    - `outcome_id` has not been consumed before; it is recorded in the same transaction that
      issues the grant → else `CRED-OUTCOME-CONSUMED`.
- A `failed` or `revoked` outcome carries its `CRED-*` reason; a `verified` one carries none.
- **Production.** The producer judges an SD-JWT VC presentation (`dc+sd-jwt`, a key-binding JWT
  whose `nonce` is the connector's challenge and whose `aud` is the audience, revocation through
  an IETF Token Status List; the profile is in
  [the conformance fixtures' README](../features/fixtures/oid4vp/README.md)) and writes one of
  four results: `verified`; `failed` with `CRED-ISSUER-UNTRUSTED` (the issuer or its `kid` is not
  in the trust set), `CRED-INVALID` (anything else about the presentation: signature, envelope,
  disclosures, key binding, missing role or status reference) or `CRED-STATUS-UNAVAILABLE` (the
  status list could not be fetched, verified or read; fail closed); `revoked` with
  `CRED-REVOKED` (the status entry is set). `claims` and `credential_refs` carry the credential's
  role, entitlement and `<iss>#<jti>` (`<iss>#<vct>` for a credential without `jti`) once the
  credential was read, so a `revoked` or
  status-unavailable outcome names the credential it is about. Before that point no role is known,
  and the schema requires one: such an outcome carries `claims.role` `unverified`, a sentinel a
  consumer never maps to an entitlement (it reaches no grant, since only a `verified` outcome
  does). The policy lives in `internal/presentation`; the fixtures under
  `features/fixtures/oid4vp/` pin it.

### Presentation hook: how an outcome is obtained

A verification service signs an outcome because a holder presented a credential for one connector
challenge. A token store route configured with the presentation hook does this by itself, at every
acquisition and every renewal, through the
[presentation API](contracts/verification.v1.openapi.yaml) of the verification service
([Token store](token-store.md#presentation-hook)); a route configured with the fixture signer
presents nothing and is for tests and the demo. The binding from the challenge to the outcome
is fixed, and every hop keeps it:

| Grant request | Verification request | Holder's key binding | IF-03 outcome |
|---|---|---|---|
| the challenge value | `challenge`, returned as `nonce` | `nonce` | `challenge` |
| the audience | `audience`, returned as `client_id` | `aud` | `audience` |
| the client the challenge was issued to | `client_id` | — | `client_id` |

- **One request, one presentation, one outcome.** A request is answered once; a second
  presentation for it is refused (`CRED-REQUEST-UNKNOWN`). Every outcome has a new `outcome_id`
  and is valid 60 to 120 s, so it serves one grant and no renewal.
- **Every presentation that is judged is answered with an outcome.** `verified`, `failed` and
  `revoked` are all signed; the consumer refuses the last two (`CRED-OUTCOME-NOT-VERIFIED`). A
  `vp_token` that is not a credential is judged: `failed`, `CRED-INVALID`. No outcome exists when
  nothing was judged: a malformed request or response form (`CRED-REQUEST-INVALID`), a request
  that is unknown, expired or already answered (`CRED-REQUEST-UNKNOWN`), or a service that could
  not sign or is not ready.
- **The holder.** One OID4VP request in, one `dc+sd-jwt` presentation out, with a key-binding JWT
  signed by the key the credential's `cnf` names. A holder presents only for a query naming its
  credential's type. Which wallet stands behind it is not part of this contract.
- **No outcome is no token.** An unreachable, refusing or silent service, an answer that is not
  bound to the challenge and a holder that presents nothing leave the caller without an outcome;
  the token store issues nothing and records it under a code of its own audit, outside this
  registry ([Token store](token-store.md#presentation-hook)).
- **Neither side is authenticated by this API.** That the caller reaches the real service, over a
  protected transport, is the deployment's to ensure. A misdirected caller discloses the
  credential it presents; it gets no token, because only an outcome signed by a trusted issuer is
  consumed.

## IF-04 — observability and evidence

- Every component logs JSON to stdout; security-relevant events use the IF-01 event schema, so the
  same record feeds the UI, the collector and the acceptance evidence.
- A mesh-layer denial is recorded as the destination proxy's access log, not yet as an IF-01 event:
  one JSON line with both SPIFFE IDs (`source`, `destination`), the authority, the code and the
  decision detail, read from the proxy container (`kubectl logs <pod> -c istio-proxy`;
  [Workload identity](workload-identity.md#mesh-authorization)). Its form as a security-state
  event is pending the observability work.
- `correlation_id` is the guard's `x-request-id` (see the header rules below) and joins the events
  of one request across components; W3C trace context (`traceparent`) links the spans.
- Acceptance evidence — reports, logs and the manifest — is described in
  [BDD acceptance](bdd.md).

## Header propagation, guard to gateway

The guard terminates the caller's TLS, authenticates the caller's DPoP-bound token, asks the policy
engine (IF-05), and forwards an allowed request towards the zone's gateway. What it forwards:

| Header | Rule |
|---|---|
| `Authorization`, `DPoP` | Removed from the caller's request after verification. With the `substitute_upstream_token` obligation they are replaced by the token store's values: the upstream token, and a new proof minted with the store's key for exactly the upstream method and URI. The caller's proof is never forwarded. Without a successful substitution the request is refused, not forwarded. |
| `DPoP-Nonce` | Not relayed to the caller. When the upstream answers with a nonce challenge, the guard asks the token store once more with that nonce (`upstream_nonce`) and retries with the new proof; a second challenge is a refusal. |
| `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `Forwarded` | Removed when they arrive from outside the mesh. Only the mesh ingress sets them. The proof's `htu` is rebuilt from configuration — `https://<published host><route path>` — never from these headers or `Host`. |
| `x-request-id` | Generated by the guard for a request from outside the mesh (an inbound value is replaced), then carried unchanged. It is the `correlation_id` of IF-01, IF-04 and IF-05. |
| `traceparent`, `tracestate` | Propagated (W3C Trace Context). |
| Any `x-facis-*` header | Removed from the caller's request; only the guard sets them. |

How the guard's policy hook applies these rules on an allow, what it answers on a deny, and the
proofs of both are in [Guard policy hook](policy-hook.md).

## IF-07 — attested channel control

Frozen at v1, with the partner sign-off under the interface-freeze process pending. The contract is
the Go interface of `internal/atls`: its exported identifiers and signatures are listed in
`internal/atls/api_v1.txt`, and [Attested channel control](attested-channel.md#stability) states what
is frozen and how the interface may change. Also fixed:

- **States:** `connecting → handshake → attested → draining → closed`, with error edges to
  `refused` (carrying a `CHAN-*` code) and `lost`. These are the `state` values of IF-01
  `channel_state` events.
- **Rules:** the evidence is bound to one TLS session, so a channel has a maximum lifetime and is
  replaced by a freshly attested one rather than refreshed. The gateway port speaks only the
  attested protocol; a plain TLS or plaintext client is refused (`CHAN-DOWNGRADE`).

## Attestation evidence

The mock attestation document — what a Trusted Execution Environment would emit, produced in
software because the demonstrator has no TEE hardware — is described by
[`contracts/mock-attestation.schema.json`](contracts/mock-attestation.schema.json), with one sample
per vendor profile in [`contracts/samples/`](contracts/samples/).

The two sides of the evidence path, the artefact attached to a release and verified at admission
and the report exchanged inside the attested channel, share CMC's `attestationreport` evidence and
collateral types ([ADR-0011](adr/0011-mock-tee-evidence-format-and-provisioning.md)), but they are
different documents. The artefact is the JSON document this schema describes: one `evidence` and one
`collateral` object, with the `mock` and `profile` wrapper fields. The channel carries the CBOR
`AttestationReport` that `cmcd` produces ([Pinned library](attested-channel.md#pinned-library)),
which has a different shape and which this schema does not validate.

Those shared types therefore underlie both IF-04 and IF-07. IF-04 is already frozen at v1 with the
IF-01 event schema as its contract, so this schema is not part of it. IF-07 is frozen at v1 with the
Go interface of `internal/atls` as its contract, and
[what that freeze covers](attested-channel.md#what-is-frozen) includes neither this schema nor the
format of the reports; whether IF-07 carries the evidence format of its reports as its own contract
is still open.

## IF-08 — deployment lifecycle command

The scenario driver hook that deploys and uninstalls a release through the ORCE workflow. It is
what the lifecycle acceptance scenarios (TDR-BDD-01..04) drive, and it is the same workflow an
operator uses.

- **Command:** `POST /lifecycle` on ORCE, HTTP Basic (`httpNodeAuth`), TLS 1.3, management plane
  only — [OpenAPI definition](lifecycle.openapi.yaml). The answer comes at once: `202` with
  `data.accepted`, or `400` with `errors.fields` naming each invalid parameter.
- **Result:** asynchronous, kept in the ORCE flow context under `lifecycle.jobs[requestId]` —
  [JSON Schema](lifecycle-result.schema.json). Read it with the ORCE admin API,
  `GET /context/flow/ztd-lifecycle-tab/lifecycle`, using a read-only bearer token.
- **Reason codes** (`errors.action`): `valuesSchemaRejected`, `dryRunRejected`, `deployFailed`,
  `uninstallFailed`, `releaseNotFound`, `clusterUnreachable`, `duplicateRequest`, `invalidAction`,
  `systemError`. A parameter the cluster refuses (for example a namespace outside the BDD pool)
  comes back in `errors.fields`.

## Validation

`npm run contracts` (and the `Contracts` CI job) checks that:

- every JSON Schema compiles as strict JSON Schema 2020-12 and its `$id` carries `v1`;
- under `contracts/fixtures/<schema>/`, every `valid-*` fixture passes and every `invalid-*`
  fixture fails, and each schema has at least one of each;
- the registry is well formed, every code sits in its family, and every reason code used in a
  fixture, an OpenAPI document or any Markdown page under `docs/` or `features/` is registered (a
  trailing `-*` is a glob and must match at least one registered code; dash look-alikes count as
  hyphens);
- every OpenAPI document parses without duplicate keys, validates against the official OpenAPI
  3.1 schema (vendored with its checksum), resolves every reference, and every Schema Object in it
  compiles as strict JSON Schema 2020-12.

## Conventions

- REST APIs are described with OpenAPI 3.1 (IF-08, delivered earlier, with OpenAPI 3.0); events
  and stored objects with JSON Schema 2020-12.
- Structured data carries a JSON-LD context and a SHACL shape where the content is meant to be
  interoperable rather than internal.
- Error responses use the shared reason-code registry, so a refusal is machine-readable and not
  just a status code.
