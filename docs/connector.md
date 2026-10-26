# Connector service

The connector is the zone's OAuth2 authorization surface
([IF-02](contracts/if02-connector.v1.openapi.yaml)): participant backends register with it through
dynamic client registration and obtain DPoP-bound access tokens from it, and the zone's resources
verify those tokens against the key it publishes. The provider behind the endpoints, its grants and
its conformance suite are described in [Connector OAuth2 provider](oauth2-provider.md); the
database it shares with the token store in [Token store](token-store.md). This page describes
what the service adds around the provider: the registration policy and the audit of every
registration decision, the security-state events it emits, the client that registers a participant,
its deployment and identity, and how all of it is verified.

## Registration

Registration is not open: `POST /oauth2/register` takes a token from the connector's own token
endpoint whose audience is the registration endpoint and whose scope includes
`connector:client_registration`, and only the registrar, the one client the connector seeds at
start, can obtain such a token ([Registrar bootstrap](oauth2-provider.md#registrar-bootstrap)).
The library then holds a registration within that token: scopes, audiences and grant types
beyond it are refused as `invalid_client_metadata` with the reason `registration_rejected`.

### Order of the checks

1. **The caller.** The connector looks up the token the request carries in its own store. A request
   with no token, a malformed or unknown one, or one not granted the registration scope goes to the
   library as it is, with no policy verdict and no transaction: the library refuses it, for example
   `401 invalid_token`, `403 insufficient_scope` or a DPoP reason, and the conformance suite pins
   that it refuses such tokens. An expired registrar token is judged like a live one: the library's
   clock may still hold it valid for up to a second, and it refuses it inside the transaction when
   it is not. Should the library ever accept such a request, the
   credentials are withheld and the outcome is recorded as uncertain (below). A lookup the store
   cannot answer is `500 server_error`.
2. **The policy**, for a known token: the body is read once, bounded, and judged as a whole before
   the library sees it.
3. **The library**, in one of two registration slots and inside one transaction. A slot not free
   within the request's deadline is `500 server_error`. The bound keeps registrations from holding
   the database pool: each holds a connection for its whole run while the library's nonce and
   replay checks take another, so a burst could otherwise stall the token endpoint.

### The policy

The connector's own policy closes what the library's ceiling leaves open: a client without a
secret, without a name, without DPoP binding, with members outside the contract, or sent in a
lenient document. Each rule judges the value as the library will store it, never a cleaned copy;
the first rule broken names the refusal.

| Rule | Requires | `error_description` |
|---|---|---|
| `dcr.body_size` | At most 64 KiB | The client metadata is larger than 64 KiB. |
| `dcr.body` | One strict JSON object: valid UTF-8, no duplicate member, nothing after the object | The client metadata must be one JSON object without duplicate members. |
| `dcr.members` | Only `client_name`, `grant_types`, `token_endpoint_auth_method`, `scope`, `dpop_bound_access_tokens` and `audience` | The client metadata may contain only client_name, grant_types, token_endpoint_auth_method, scope, dpop_bound_access_tokens and audience. |
| `dcr.client_name` | A string of 1 to 128 printable characters, without leading or trailing space | client_name is required: 1 to 128 printable characters, without leading or trailing spaces. |
| `dcr.auth_method` | `token_endpoint_auth_method` absent or `client_secret_basic`: no public clients | token_endpoint_auth_method must be client_secret_basic. |
| `dcr.dpop_bound` | `dpop_bound_access_tokens` present and `true` | dpop_bound_access_tokens must be true: this connector issues DPoP-bound tokens only. |
| `dcr.grant_types` | A non-empty array of distinct grant types among those the deployment offers: `client_credentials` and, with the grant on, the verified-presentation grant | grant_types is required: client_credentials and/or the verified-presentation grant, each once. |
| `dcr.scope` | One or more distinct RFC 6749 scope tokens (no whitespace, quote or backslash) separated by single spaces, never `connector:client_registration` | scope is required: one or more distinct scope tokens separated by single spaces, never connector:client_registration. |
| `dcr.audience` | A non-empty array of distinct absolute `http(s)` URLs without credentials, query or fragment | audience is required: one or more distinct absolute http(s) URLs without query or fragment. |

A violation is answered as the library answers its own refusals, so a client sees one shape
whoever refused: `400`, `Cache-Control: no-store`, and

```json
{"error": "invalid_client_metadata", "error_description": "dpop_bound_access_tokens must be true: this connector issues DPoP-bound tokens only.", "reason": "registration_rejected"}
```

The library's refusals pass through unchanged: a missing or wrong token (`401 invalid_token` with a
`WWW-Authenticate` challenge), a token without the registration scope (`403 insufficient_scope`),
the DPoP reasons, and a registration beyond the registrar's token (`400 invalid_client_metadata`,
reason `registration_rejected`). The nonce handshake of a DPoP-bound registration token
(`401` with reason `dpop_use_nonce` and a fresh `DPoP-Nonce`) is not a decision and is passed
through without a trace.

### Audit

Every registration decision leaves one row in `audit_event`, the append-only table the connector
shares with the token store, and one event on the security-state feed (below).

| Decision | `kind` | `client_id` | `reason_code` | `detail` |
|---|---|---|---|---|
| Accepted | `registration.accepted` | the new client | none | `registrar`, `client_name`, `grant_types`, `scopes`, `audience`, `dpop_bound` as stored |
| Refused | `registration.refused` | the client whose token the request carried, when the store holds it with the registration scope | the registry code of the refusal | `rule` (a policy rule; `library` for the library's refusal; `read` for a body that could not be read; `lookup`, `busy`, `begin`, `stored` or `audit` for a failure of the connector's own), `reason`, `status`, `client_name` when the body named a valid one |
| Uncertain | `registration.uncertain` | the client that may exist | `TOK-SERVER-ERROR` | `registrar`, `client_name` |

An accepted registration and its row are one transaction: the library handler runs inside it, the
row is inserted beside the client, and the response that carries the client secret leaves only
after the commit. A row that cannot be written rolls the client back and answers `500 server_error`:
no credential leaves without its audit entry. A commit whose outcome is unknown answers `500`
without the credentials and is recorded as uncertain, not refused: the client may exist with a
secret nobody received, inert until an operator deletes its `oauth2_client` row. A refusal is
answered first, complete and with its length, and audited after it has left, best effort, within
two seconds and outside the request's deadline. Neither the row nor any record holds the body, the description, a header
or a secret; the token's client is named from the store's own record of the token, which decides
whether the request is judged but never authorises it: the library does.

A refusal is audited whoever the caller, an unauthenticated one included, so anyone who can reach
the endpoint can add rows to `audit_event`. The endpoint is reachable only through the lanes the
mesh admits (below); a rate limit in front of it is not part of the connector.

Reason codes follow the reason the refusal carries, as the
[reason-code registry](contracts/reason-codes.json) names them: `registration_rejected` is
`TOK-REGISTRATION-REJECTED`; `invalid_token` is `TOK-INVALID`, or `TOK-MISSING` when no
`Authorization` header was sent; `insufficient_scope` is `TOK-SCOPE`; `invalid_client` is
`TOK-CLIENT-INVALID`; `invalid_request` is `TOK-REQUEST-INVALID`; `server_error` is
`TOK-SERVER-ERROR`; the DPoP reasons are `TOK-PROOF-INVALID`, `TOK-REPLAY`, `TOK-NONCE`,
`TOK-JKT-MISMATCH` and `TOK-ATH-MISMATCH`.

## Security-state events

The connector writes IF-01 events ([event schema](contracts/if01-event.v1.schema.json)) as JSON
lines on stdout, beside its records, one per registration decision, as
[Scenario decisions](scenarios.md) lists them for the source `connector-<zone>`. The zone comes
from `--zone`; the run id is minted at every start (`connector-<zone>-<8 hex>`), so each process,
a restart or a second replica included, is its own run and `(run_id, seq)` stays unique; `seq`
counts from 0 per start; the `correlation_id` is the request's. The tests validate the events the
real binary writes against the schema.

```json
{"run_id":"connector-b-5f1c9a2e","seq":0,"ts":"2026-10-24T09:00:00Z","source":"connector-b","kind":"token_event","correlation_id":"reg-1","payload":{"state":"registered","detail":"client_id=3f9c…"}}
{"run_id":"connector-b-5f1c9a2e","seq":1,"ts":"2026-10-24T09:00:01Z","source":"connector-b","kind":"token_event","correlation_id":"reg-2","payload":{"state":"refused","reason_code":"TOK-REGISTRATION-REJECTED","rule_id":"dcr.dpop_bound","detail":"dpop_bound_access_tokens must be true: this connector issues DPoP-bound tokens only."}}
```

Only a policy refusal carries a `rule_id`, with the rule's text as the detail. A refusal the library
made carries its reason as the detail; a failure of the connector's own carries `server_error` and
the failed step, for example `server_error (busy)`. An uncertain outcome is the state `uncertain`
with `TOK-SERVER-ERROR` and the client id. A `detail` is cut at the schema's 512 characters. No
event names a token, a proof, a secret or a header.

## Registering a participant

`connector register`, a subcommand of the same binary and image, is the registrar's client: it
obtains a DPoP-bound registrar token for the registration scope plus the client's scopes, with the
registration endpoint plus the client's audiences as audience, posts the client metadata with that
token and a proof, and writes the credentials file the participant reads as
`PARTICIPANT_CREDENTIALS_FILE` ([Application services](application-services.md)): exactly
`{"client_id", "client_secret"}`, mode 0600. The file is written to a hidden temporary file beside
`--out`, created before any call, and hard-linked into place only when complete: an existing `--out`
or a directory that cannot take a hard link is refused before anything is registered, an existing
file is never overwritten, and a run killed half-way leaves at most the temporary file, never an
empty `--out` that would block the next run (only hidden files named after `--out`: the temporary
file, and in a narrow window its link probe). It runs where the connector's Service name resolves, since the proof's `htu` must name
the endpoint as the connector does.

```bash
connector register --connector http://ztd-connector.ztd-mgmt.svc:8080 \
  --registrar-id ztd-registrar --registrar-secret-file /var/run/secrets/connector/registrar-secret \
  --client-name "participant backend" --scope resource.read --audience https://resource.example \
  --out /out/credentials.json --request-id my-registration
```

| Flag | Environment | Meaning |
|---|---|---|
| `--connector` | `CONNECTOR_URL` | The connector's base URL; `/oauth2/token` and `/oauth2/register` below it |
| `--registration-endpoint` | `CONNECTOR_REGISTRATION_ENDPOINT` | The registration endpoint as the connector names it, when it differs from the base URL plus `/oauth2/register` |
| `--registrar-id`, `--registrar-secret-file` | `CONNECTOR_REGISTRAR_ID`, `CONNECTOR_REGISTRAR_SECRET_FILE` | The registrar's client id and the file holding its secret |
| `--client-name`, `--scope`, `--audience`, `--grant-types` | | The client's metadata: name, space- or comma-separated scopes, comma-separated audiences, comma-separated grant types (default `client_credentials`). Checked as the policy checks them before anything is sent; a scope or URL holding a comma cannot be given here, only in a metadata file |
| `--metadata-file` | | A JSON object sent as the client metadata as it is, instead of the four flags, which may then not be set; its `scope` and `audience` shape the registrar's token |
| `--delegable-scopes` | `CONNECTOR_REGISTRAR_DELEGABLE_SCOPES` | The scopes the connector lets the registrar delegate, its `--registrar-delegable-scopes`. They are left out of the registrar's token, which need not carry them (and cannot carry a verified-presentation scope); required to register a client for such a scope |
| `--out` | | The credentials file to write; refused when it exists |
| `--request-id` | | `X-Request-Id` of both calls, 1 to 128 visible ASCII characters (the connector would replace any other), the correlation id of the connector's records, rows and events |
| `--timeout` | | Deadline for both calls together, default 30 s; no per-call limit below it |

The command prints `registered client_id=<id> credentials=<path>` on success and the refusal's
reason, status and description on stderr otherwise; never the secret, a token, a proof or a header.
Exit codes:

| Code | Meaning |
|---|---|
| 0 | Registered and written |
| 1 | Refused by the connector: a 4xx with a reason IF-02 defines, printed with its status |
| 2 | Usage or configuration, an existing `--out` or a directory without hard links included; nothing was sent |
| 3 | No answer an IF-02 call gives: unreachable, a 5xx, a redirect or a 404 from something in front of the connector; or a local failure before anything was sent. After the registration call the message warns that the client may exist |
| 4 | Registered, but the credentials were not delivered: the 201 could not be read, or the file could not be written. The message says to delete the client's `oauth2_client` row and run again |

The registrar's token asks for the registration scope plus the client's scopes that are not
delegable, and for the registration endpoint plus the client's audiences. A registrar whose scopes
or audiences do not cover them is refused the token before anything is registered, and so is a
delegable scope not named in `--delegable-scopes`.

The participant registering itself at runtime is a later step of the journey; today it reads
provisioned credentials, which this command produces.

## Deployment and identity

The chart `deployment/helm/connector` (its README documents the values) runs the connector as a
Deployment with its own ServiceAccount, a Service on the API port and probes on the ops port, in
the management plane beside the token store, whose chart applies the schema first and whose
database Secret the connector reads. The chart never carries a credential: the database URL, the
key-value store token and the connector's three secrets (the two HMAC secrets and the registrar's
client secret) come from Secrets of the release namespace, mounted as files where they are secrets
of the connector's own. The transit key that signs the access tokens is created before the install,
`ecdsa-p256` and not exportable, and the key-value store token's policy allows reading
`transit/keys/<key>` and updating `transit/sign/<key>`.

Readiness is green only while all four checks answer `ok`
([Start, readiness and drain](oauth2-provider.md#start-readiness-and-drain)); a connector
installed before the schema, the key-value store or the key is up, stays up and becomes ready on its
own. On SIGTERM it drains as the token store does, and the chart derives the termination grace
period from the drain delay, the shutdown timeout and the readiness budget.

The connector runs as its own ServiceAccount, `ztd-connector`, with the pod label
`spiffe.io/spire-managed-identity: "true"`: under both mesh modes its SPIFFE ID is
`spiffe://<trust domain>/ns/ztd-mgmt/sa/ztd-connector`. The mesh terminates mTLS for it, as for
every zone workload ([ADR-0001](adr/0001-service-mesh-mode-istio-ambient-with-cilium.md), and the
sidecar mode proposed to supersede it): the listeners are plain HTTP inside the pod, the mesh
carries the traffic as mTLS, the pod mounts no ServiceAccount token, since the SVID comes from the
SPIFFE CSI driver, and the chart renders no mesh resource of its own. Participant backends in the
data plane reach it through a lane of the umbrella chart's allow matrix (data to management, port
8080, pods labelled `app.kubernetes.io/name: ztd-connector`), which joins the umbrella when the
connector joins a zone; until then the connector is reachable within the management plane.

## Verification

- **The policy and the gate**, in `services/connector`: a table over every rule, the accepted
  shapes of the existing clients included (a verified-presentation-only client, a client with both
  grants) and the values the library would store differently (whitespace in scopes, padded names);
  the reason-code mapping; the token signature split; and the gate against the in-memory stores: an
  accepted registration relayed with its audit row, a violation refused before the library and
  answered before its row is written, an unauthenticated request left to the library without a
  verdict or a transaction, a library refusal relayed and audited, a failed audit row rolling the
  client back, and each failure of the connector's own (no client in the 201, an unknown commit
  outcome, a failed lookup, no slot, an unreadable body). The audit row's transaction is tested on
  PostgreSQL in `pgstore`.
- **Against PostgreSQL and OpenBao**, with `TOKEN_STORE_TEST_DATABASE_URL`, `TRANSIT_TEST_ADDR`
  and `TRANSIT_TEST_TOKEN`, as the `Token store` workflow runs them in both token modes: the real
  binary registers a client and refuses five others (no DPoP binding, a public client, a member
  outside the contract, no token, an unknown token with metadata the policy would refuse); the
  `audit_event` rows hold the expected kinds, client ids, reason codes, rules and correlation ids;
  the nonce handshake left none; every IF-01 line validates against the schema and carries the
  expected state, code and rule; and the client secret, the registration access token and the
  registrar's token appear in no record and no row. `connector register` against the binary writes
  a file whose credentials obtain a token, and exits 1 on a refusal.
- **On kind**, `scripts/verify-connector/verify.sh`, which the `Connector` workflow runs: both
  charts installed against PostgreSQL and OpenBao from the pinned images, the connector ready on
  all four checks, a client registered by a pod running `connector register` out of the connector's
  image, a registration the policy refuses with its specific error, exactly the two audit rows and
  the two events for them, the identity (ServiceAccount, label, no restart), a clean drain, and an
  uninstall that leaves the schema empty. Its records are the run's artefact.
