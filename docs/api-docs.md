# API documentation

## Interface registry

The demonstrator's cross-component interfaces are identified `IF-01` through `IF-08`. Version 1 of
each is defined by the machine-readable artefacts in `docs/contracts/`, which CI
validates on every change (see [Validation](#validation)). A v1 contract changes only by a
compatible addition; anything else is a v2.

| Interface | Purpose | v1 artefacts | Status |
|---|---|---|---|
| IF-01 | Security-state event stream to the demonstrator UI | [event](contracts/if01-event.v1.schema.json), [snapshot](contracts/if01-snapshot.v1.schema.json), [feed API](contracts/if01-feed.v1.openapi.yaml) | v1 |
| IF-02 | Connector authorization surface — registration and token issuance | [connector API](contracts/if02-connector.v1.openapi.yaml), [rules](#if-02-connector-authorization-surface) | v1 (1.1.1) |
| IF-03 | Credential verification outcome | [JWS payload](contracts/if03-verification-outcome.v1.schema.json), [JWS header](contracts/if03-jws-header.v1.schema.json), [signing rules](#if-03-signed-verification-outcome) | v1 |
| IF-04 | Observability and evidence | The IF-01 event schema, as a JSON log line; [rules](#if-04-observability-and-evidence) | v1 |
| IF-05 | Policy decision input and output | [input](contracts/if05-policy-input.v1.schema.json), [decision](contracts/if05-policy-decision.v1.schema.json), [header rules](#header-propagation-guard-to-gateway) | v1 |
| IF-06 | Governed configuration change | [change](contracts/if06-config-change.v1.schema.json) | v1 |
| IF-07 | Attested channel control | [States and rules](#if-07-attested-channel-control) | v0, not frozen |
| IF-08 | Scenario driver hooks | [lifecycle command](lifecycle.openapi.yaml), [lifecycle result](lifecycle-result.schema.json) | v1 (delivered with the BDD pack) |

Internal to a zone, and not a numbered interface: the token store's API,
[token-store.v1.openapi.yaml](contracts/token-store.v1.openapi.yaml) — substitution for the guard
and DPoP replay detection for the connector and the guard. The database behind it, its schema and
how the schema is applied are described in [Token store](token-store.md).

Three agreements are conventions rather than interfaces, and are documented where they live:

| Convention | Where |
|---|---|
| Identity provider realm, clients, roles and scopes | [Keycloak integration](keycloak.md) |
| Repository, CI and Helm conventions | [CI/CD](ci-cd.md), [Packaging and containers](packaging.md) |
| Acceptance evidence and its handover | [BDD acceptance](bdd.md) |

Upstream APIs are referenced and pinned, never redefined here: Envoy `ext_authz`
(`envoy/service/auth/v3`), Keycloak OIDC, SPIFFE Workload API, the attested-TLS library, and the
XFSC services' own APIs.

## Reason codes

Every refusal names a code from one registry, [reason-codes.json](contracts/reason-codes.json)
(schema: [reason-codes.v1.schema.json](contracts/reason-codes.v1.schema.json)). A family names the
layer that refuses, its default HTTP status and the state the UI shows; a code may override the
status.

| Family | Layer | Default HTTP | UI state | Overrides |
|---|---|---|---|---|
| `ADM` | admission | 403 | `BLOCKED-ADMISSION` | — |
| `MESH` | identity and mesh policy | none (connection refused) | `BLOCKED-IDENTITY` | — |
| `TOK` | token authentication | 401 | `DENIED-TOKEN` | `TOK-SCOPE` 403, `TOK-REQUEST-INVALID` 400, `TOK-REGISTRATION-REJECTED` 400, `TOK-NO-UPSTREAM` 409, `TOK-CALLER-DENIED` 403, `TOK-ROUTE-DENIED` 403, `TOK-STORE-UNAVAILABLE` 503, `TOK-SERVER-ERROR` 500 |
| `POL` | policy decision | 403 | `DENIED-POLICY` | `POL-PRESENTATION-REQUIRED` 401, `POL-PDP-UNAVAILABLE` 503, `POL-BUNDLE-STALE` 503 |
| `CRED` | credential verification | 403 | `DENIED-CREDENTIAL` | — |
| `CHAN` | attested channel | none (handshake refused) | `CHANNEL-DOWN` | — |
| `CFG` | configuration governance | 422 | `CHANGE-REJECTED` | `CFG-NOT-AUTHORISED` 403 |
| `VIS` | display | none (display state) | `UNKNOWN` | — |

The status is what a protected resource — the guard — returns to its caller. Two surfaces keep
statuses of their own: the connector's token and registration endpoints answer with the OAuth 2.0
statuses (400 for a DPoP proof or nonce problem at the token endpoint, for example; see
[IF-02](contracts/if02-connector.v1.openapi.yaml)), and the token store's internal API states its
own; the guard maps both to the caller's refusal.

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

## IF-04 — observability and evidence

- Every component logs JSON to stdout; security-relevant events use the IF-01 event schema, so the
  same record feeds the UI, the collector and the acceptance evidence.
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

## IF-07 — attested channel control

Not frozen: the channel's control surface is defined by the attested-channel component when it is
built. What is fixed now:

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

It is a single format serving both sides of the evidence path: the artefact attached to a release
and verified at admission, and the report exchanged inside the attested channel. It therefore
underlies both IF-04 and IF-07. IF-04 is already frozen at v1 with the IF-01 event schema as its
contract, so this format is not part of it; whether IF-07 carries it as its own contract is settled
when IF-07 is frozen.

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
  fixture, an OpenAPI document or this page is registered;
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
