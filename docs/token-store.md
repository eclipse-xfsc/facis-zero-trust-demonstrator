# Token store

The token store is the zone's keeper of upstream credentials
([token-store.v1.openapi.yaml](contracts/token-store.v1.openapi.yaml)): it holds the tokens the
peer zone minted to this zone, substitutes them for the guard so a caller's own proof is never
forwarded, and detects DPoP proof replay for the connector and the guard. It stands on one
PostgreSQL database that it shares with the connector's OAuth2 surface
([Connector OAuth2 provider](oauth2-provider.md)), whose clients and issued tokens live in the same
schema, and on the zone's key-value store ([Secrets](secrets.md)) for its key material. This page
describes that database and how its schema is applied, the service that stands on it (its
configuration, its liveness and readiness, its records and its identity), its endpoints (the
replay check and substitution, with acquisition and renewal behind them), and how all of it is
verified.

## One database, two owners

| Tables | Owner | What they hold |
|---|---|---|
| `oauth2_client`, `oauth2_token`, `oauth2_dpop_nonce` | the connector's OAuth2 surface | dynamically registered clients (secret as a bcrypt hash, the RFC 7591 metadata document as registered), issued access and registration tokens keyed by signature, with the grant they were issued through (a verified-presentation token always with its unique `outcome_id`, no other token with one), server-issued DPoP nonces |
| `oauth2_challenge` | the connector's OAuth2 surface | single-use challenges of the verified-presentation grant, bound to a client and one audience, valid 120 s; a consumed one is never reset or deleted (migration 3) |
| `signing_key` | the token store | references to the store's outbound signing keys in the key-value store, with their thumbprints; never key material; at most one `active` version per key (migration 5) |
| `verified_outcome` | the token store; in the issuing zone, the connector | verification outcomes received over IF-03, consumed at most once. The connector records each outcome its verified-presentation grant consumes here, in the transaction that issues the token |
| `upstream_token` | the token store | the upstream tokens held per route `(peer_zone, audience, tenant)`, as references into the key-value store, with state and the single-flight renewal claim; at most one live row (`active` or `renewing`) per route (migration 4) |
| `proof_jti` | the token store, on behalf of the connector and the guard | one-time DPoP proof identifiers, keyed `(jkt, htm, htu, jti)` and kept until `not_after`; the replay check of the store's API |
| `audit_event` | both | registration decisions, outcome consumption and refusal, every renewal attempt with its reason, every key rotation (`key.rotated`); append-only |

Four properties are the schema's own, not the services' good conduct:

- **An outcome is consumed exactly once.** The upstream token's reference to its outcome is unique,
  so a second token row for one outcome is refused by the database even on a path that skipped the
  consumption check. The intended path marks the outcome consumed and inserts the token in one
  transaction. The same holds for the connector's tokens: `oauth2_token.outcome_id` is unique and
  references the outcome, and only an access token may carry one.
- **A replayed proof is refused by the primary key.** The replay check is one insert; a conflict is a
  replay, and of any number of concurrent identical proofs exactly one is admitted. The table is
  unlogged on purpose: after a crash it is empty, so a proof can be replayed at most once inside its
  own acceptance window, as the API documents.
- **Renewal is single-flight.** A worker claims a due token with `FOR UPDATE SKIP LOCKED` and records
  the claim; a second worker sees nothing to do. A claim without a claimant, or the reverse, is a
  constraint violation, and a staleness sweep releases the claim of a worker that died.
- **One version of a key mints at a time.** A partial unique index allows one `active` row per key
  name, so a rotation that forgot to retire, or two that raced, is refused by the database
  ([key custody](#key-custody)).

The queries behind these properties, the substitution lookup included, are tested against the
migrated schema in `services/token-store/internal/schema` and are what the service's paths are built
on.

## Migrations

The schema is a sequence of versioned migrations embedded in the `token-store` binary:
`services/token-store/internal/schema/migrations/NNNN_name.up.sql` with its `.down.sql`, numbered
from `0001` without gaps. The binary applies them:

```bash
token-store migrate up [--to N]    # apply the migrations above the current version, up to N (default: all)
token-store migrate down --to N    # revert to version N; 0 leaves the schema empty
token-store migrate status         # the database against the embedded migrations, as JSON; exit 3 when behind
```

The connection URL comes from `--database-url` or `TOKEN_STORE_DATABASE_URL` and is never logged.
Each migration runs in its own transaction and is recorded in `schema_migrations` with the SHA-256
of its up file. A later run that finds a recorded checksum differing from the embedded file refuses
to continue: a migration is never edited, a schema change is a new migration. Concurrent runs take a
session-level advisory lock in turn, so two replicas of a hook Job, or a Job and an operator's
shell, cannot interleave. `down --to 0` drops `schema_migrations` as well, so a full revert leaves
nothing behind. A database ahead of the embedded migrations, migrated by a newer build, is current
for an older one: its `up` applies nothing and its `status` exits 0, while its `down` is refused,
since only the build that applied a migration knows how to revert it.

## The service

`token-store serve` runs the service from the same binary: two plain-HTTP listeners, a liveness
and a readiness answer, and JSON records on stdout. It serves the contract's `/healthz`, `/readyz`,
`/internal/replay-check` and `/internal/substitute`. It never waits for its dependencies at
start: a store that starts before its database or its key-value store still starts, listens, and
says it is not ready until they are there.

### Configuration

Every flag defaults to the environment variable of the same name; a flag set on the command line
wins. Neither URL is ever logged.

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--addr` | `TOKEN_STORE_ADDR` | `:8080` | The API listener, the address the store's callers reach it at |
| `--ops-addr` | `TOKEN_STORE_OPS_ADDR` | `:9090` | The ops listener the kubelet probes: `/healthz` and `/readyz` |
| `--database-url` | `TOKEN_STORE_DATABASE_URL` | required | PostgreSQL connection URL |
| `--openbao-url` | `TOKEN_STORE_OPENBAO_URL` | required | The key-value store's URL, `http(s)://host[:port]` and nothing more |
| `--readiness-timeout` | `TOKEN_STORE_READINESS_TIMEOUT` | `2s` | Budget of one `/readyz` evaluation |
| `--drain-delay` | `TOKEN_STORE_DRAIN_DELAY` | `5s` | On SIGTERM, how long `/readyz` answers 503 while the listeners stay open |
| `--shutdown-timeout` | `TOKEN_STORE_SHUTDOWN_TIMEOUT` | `10s` | Drain of the listeners after that delay |
| `--log-level` | `TOKEN_STORE_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `--replay-callers` | `TOKEN_STORE_REPLAY_CALLERS` | none | Comma-separated SPIFFE IDs allowed to call `/internal/replay-check` (the connector's, the guard's); with none, every call is refused |
| `--acquire-config` | `TOKEN_STORE_ACQUIRE_CONFIG` | none | The routes file ([below](#acquisition-of-upstream-tokens)), read at start: the routes `/internal/substitute` authorizes and acquires for, and with it the [renewal](#renewal) worker. Without it every substitution caller is refused and nothing is renewed |
| `--openbao-token-file` | `TOKEN_STORE_OPENBAO_TOKEN_FILE` | none | The OpenBao token, read on every call; required with `--acquire-config` |

The environment fills in after the command line is parsed, never as a flag's default, so a
malformed variable only matters when its flag is absent and no value, the connection URL above
all, is ever part of the usage text the flag package prints on an error. Exit codes: 0 after a
clean stop, 1 when a listener cannot be bound or fails or when the signing keys cannot resolve as
configured ([key custody](#key-custody)), 2 for a usage error. On SIGTERM or SIGINT
`/readyz` answers 503 with `"draining": true` at once, without asking the dependencies, so the
pod leaves the Service's endpoints, while both listeners keep answering for the drain delay, the
time routing needs to move away; then both listeners drain at once within the shutdown timeout,
and the connection pool closes.

### Liveness and readiness

`/healthz` answers 200 while the process serves and consults nothing, so no dependency outage
ever restarts the pod. `/readyz` answers 200 only when every dependency is there and in the state
the store needs, 503 otherwise, and names what it found:

```json
{"ready": false, "checks": {"postgres": "ok", "openbao": "sealed", "signing_key": "ok"}}
```

The words are the whole vocabulary: `ok`, `unreachable`, `schema_behind` and `schema_drift` for
PostgreSQL; `ok`, `unreachable`, `uninitialized` and `sealed` for the key-value store; `ok`,
`unreachable`, `missing`, `mismatch`, `unconfigured`, `retired`, `refused`, `starting` and
`shared_issuer_key` for the signing keys (the contract's `readiness` schema lists them). Nothing a
dependency says, no address and no credential, reaches the body. The three checks run at once under
the readiness budget, and a check that has not answered when the budget ends counts as
`unreachable`, whatever it is doing. One evaluation runs at a time: callers that arrive while it
runs share its result, so a burst of `/readyz` on the published port costs one connection and one
key-value store call rather than one each, and the kubelet's own probe never queues behind a
caller's. The key-value store is reached without a proxy, whatever the pod's environment says,
and a redirect is an answer the store does not follow. PostgreSQL is checked by reading the schema's status over a
pooled connection, the read-only, lock-free query behind `migrate status`: reachable and current,
or not. The key-value store is asked `/v1/sys/health` with every state mapped to 200, as the
umbrella chart's own verification asks it, and must be initialised and unsealed; a standby is
fine. Any other status is not the store speaking of itself but something in between, a proxy or
the mesh, and counts as `unreachable` rather than as a state. Only a change of outcome is logged,
so an outage is one record, not one per probe; a caller that goes away before the evaluation
ends gets its cut-off words but records no transition. A service that was asked to stop answers
`{"ready": false, "draining": true, ...}` whatever the dependencies say.

The contract describes a ready store as one where "PostgreSQL is reachable, migrations are
current and every active key reference resolves". The last clause is the `signing_key` check
(D9), read the way the store reads its key before it mints: every `active` row of `signing_key`
must name a version of the key it names whose public key has the row's `jkt` as RFC 7638
thumbprint, and the configured key must have a version the store can mint with. A version transit
does not have, a malformed reference, or a configured key transit does not have at all (or no
transit engine at the mount) is `missing`; another thumbprint, a key that is not a non-exportable
`ecdsa-p256` key, or rows that contradict transit (the latest version's thumbprint registered under
another reference) is `mismatch`; a configured key whose only registered version is retired, or
whose active version is below transit's signing floor (a rotation that did not finish), is
`retired`; a transit that refuses the request (the token's policy) is `refused`; active rows with
no transit key configured (no `--acquire-config`) are `unconfigured`; a key the peer Connector also
publishes is `shared_issuer_key` ([below](#key-material-separation-at-readiness)); until startup
has resolved the keys once the store answers `starting`; a database or transit that does not
answer is `unreachable`. The configured key is resolved by the same code the store resolves it
with before it mints, and the words come from the same table as the startup reasons, so `missing`,
`mismatch`, `retired` and `refused` are configuration faults here as there and stop the service at
[startup](#key-custody). A row of another key that this token may not read (a policy scoped to the
store's key) is not held against the store. No row at all of the configured key is `ok` when
transit has the key and nothing contradicts it: the next acquisition registers it; rows that are
all retired are `retired` until `keys rotate`. Only public keys enter the process. The store fails
closed: not ready means no traffic.

### Records and correlation

Every record is one JSON object on stdout, with `service` and `instance` (the pod's name) on all
of them. Every record written while a request is handled carries that request's
`correlation_id`: the `x-request-id` the guard mints for a request from outside the mesh and every
component after it carries unchanged ([Observability and evidence](api-docs.md)), kept when it
arrives as 1 to 128 visible ASCII characters and minted otherwise, so the kubelet's probes have
one too. When the caller passes a W3C `traceparent`, the record also carries its `trace_id` and
`span_id` (the parent span's, the one the mesh opened for the call), and the trace context is
forwarded unchanged, `tracestate` with it, on every call the store makes on the request's behalf.
The response echoes `x-request-id`. Every request ends with one `request` record (`method`,
`path`, `status`, `duration_ms`), so a request that logs nothing else still leaves a correlated
line, and a test refuses any log call in the service that takes no context, so no record can miss
the ids. These are the fields the mesh's spans, keyed by the same trace context and tagged with
the same request id, and the observability stack's collector join on when they arrive; the store
carries no tracing library of its own.

### Identity

The store runs as its own ServiceAccount, `ztd-token-store`, in the management plane, with the
pod label `spiffe.io/spire-managed-identity: "true"`: under both mesh modes its SPIFFE ID is
`spiffe://<trust domain>/ns/ztd-mgmt/sa/ztd-token-store`, and that name is what the allow-lists
of its callers and its dependencies will hold. The migration Jobs run as a second account,
`ztd-token-store-schema`, with the same label: the runner holds the schema's DDL and the service
never does, so the two are distinct principals an allow-list in front of PostgreSQL can tell
apart. The mesh terminates mTLS for both, as for every zone
workload ([ADR-0001](adr/0001-service-mesh-mode-istio-ambient-with-cilium.md), and the sidecar
mode proposed to supersede it): the listeners are plain HTTP inside the pod, the mesh carries the
traffic as mTLS, and the pod mounts no ServiceAccount token, since the SVID comes from the SPIFFE
CSI driver. The contract's "client certificate whose URI SAN is on the store's allow-list" is
therefore checked on the mesh-verified identity of the caller, an authorization policy on
principals and the forwarded client certificate in the handler (see the replay check below); the
connector token store's decision record, still to be written, is where this reading belongs.

## Deployment

The chart `deployment/helm/token-store` (its README documents the values) applies the schema as a
`pre-install,pre-upgrade` hook Job running `migrate up` from the same image the service uses, in
the platform band of the umbrella chart's
[hook-weight scheme](umbrella-chart.md#the-hook-weight-scheme), and runs the service as a
Deployment with its ServiceAccount and a Service on the API port. The Deployment is a regular
resource, never a hook: the schema Job has run before its first pod starts, and readiness is the
pod's own answer. The kubelet probes `/readyz` on the ops port every five seconds with a timeout
one second above the readiness budget, so it never cuts an evaluation short, and `/healthz` every
ten; `helm install --wait` returns once the schema Job succeeded and the pod is Ready, that is,
once both dependencies answered. A fresh environment gets the schema on install; an upgrade of a
current database changes nothing, which the lifecycle proof below checks to the timestamp. The
chart does not run PostgreSQL and never carries its credential: the database is the zone's, and
its connection URL reaches the Job and the service from a Secret of the release namespace, created
before the install and named in `database.existingSecret`. The key-value store's address is
`openbao.address`, by default the umbrella chart's OpenBao under the release name `ztd`, which the
umbrella ships disabled: it must be enabled there, or the address pointed at the zone's OpenBao,
or the service never becomes ready. The pod's termination grace period is derived from the drain
delay, the shutdown timeout and the readiness budget, the service's worst case before it exits.
With `schema.dropOnUninstall`, off by
default, a `pre-delete` Job reverts every migration on `helm uninstall` and the schema is empty
afterwards; without it the database outlives the release. A `helm rollback` runs no schema hook:
migrations only add, so an older build runs against a newer schema and treats it as current.

## Verification

Two proofs, both run by `.github/workflows/token-store.yml` on every change to the store, its image,
its chart or the pinned images:

- **The runner, the queries and the service against an ephemeral database.**
  `go test ./services/token-store/...` with `TOKEN_STORE_TEST_DATABASE_URL` set runs against a
  PostgreSQL from the pinned image: up on an empty database applies every migration, up again
  applies none and changes no record, down to zero leaves an empty schema, an edited migration is
  refused, concurrent runners serialise; then the store's queries above; then the service's
  readiness against that database, empty, migrated, with an edited checksum and unreachable, and
  the service serving and draining with both listeners answering. The key-value store is faked in
  these tests. Each test takes a database of its own and drops it. Without the variable the
  database tests skip, so the ordinary test job stays self-contained; the rest, the header rules,
  the readiness evaluation, the key-value store client against fakes and the service starting
  without its dependencies, runs everywhere.
- **The chart's lifecycle and the service's readiness on kind.**
  `scripts/verify-token-store/verify.sh` builds the image from the working tree, starts a kind
  cluster with a registry on its network, a PostgreSQL and an OpenBao in dev mode from the pinned
  images inside it, puts the connection URL in a Secret as a real deployment has it, and installs,
  upgrades and uninstalls the chart. The install applies the schema to an empty database and the
  service comes up ready, with the caller's `x-request-id` echoed; with PostgreSQL scaled away the
  pod leaves Ready, `/readyz` answers 503 naming it unreachable and `/healthz` stays 200, and the
  pod is Ready again once it is back; the same for OpenBao; the pod runs as its own ServiceAccount
  with the identity label and was never restarted; every record it wrote is JSON, every request
  record carries a `correlation_id`, the probe's `x-request-id`, `trace_id` and `span_id` are on
  its record, and the credential is on none. Then the upgrade leaves `schema_migrations` identical
  to the timestamp, the uninstall with `schema.dropOnUninstall` leaves an empty schema, and the
  default uninstall keeps it. Its last stage is [key custody](#key-custody) in runtime mode:
  transit mounted and two tokens minted from the policies below, `token-store keys ensure` run
  from the built image as an operator would (`key-ensure.txt`), one `signing_key` row with the
  reference and thumbprint (`key-row.txt`), the thumbprint equal to one computed from the public
  key with openssl alone (`key-thumbprint.txt`), the key `ecdsa-p256` and not exportable with
  export refused to the root token and to the service's (`key-public.txt`,
  `key-export-refused.txt`), the service ready through the service token alone
  (`runtime-install-readyz.json`), a database dump without key material or token
  (`key-material-scan.txt`), `keys rotate` leaving v1 retired and v2 the one active version with
  the service still ready (`key-rotate.txt`, `key-rows-after-rotate.txt`,
  `runtime-rotate-readyz.json`), `keys status` with both versions, transit's latest and the floor
  (`key-status.txt`), transit refusing to sign with the retired version and signing with the active
  one (`key-retired-sign-refused.txt`), the canary scan's positive control, and OpenBao scaled
  away: `/readyz` 503 with
  `openbao` and `signing_key` unreachable, `/healthz` 200, no restart, and the records with one
  `signing keys resolved`, no misconfiguration, and none of the canaries
  (`runtime-openbao-down-readyz.json`, `runtime-store-logs.txt`). The records and the verdict are
  the run's artefact and go to the job summary; nothing is committed. Locally, the script writes to
  the git-ignored `.dev/token-store-evidence/`.
- **Key custody in the Go tests.** Against a real OpenBao (`TRANSIT_TEST_ADDR`,
  `TRANSIT_TEST_TOKEN`): the transit client's rotation and signing floor
  (`TestOpenBaoMinSigningVersionRefusesOlderVersions`), the database refusing a second active
  version of a key (`TestOneActiveVersionPerSigningKey`), the active row deciding the minting
  version and a retired or malformed one refused (`TestLoadKeyFollowsTheActiveReferenceNotTransitLatest`,
  `TestLoadKeyRefusesARetiredKey`), an activation refusing a key retired during the grant
  (`TestActivationRefusesAKeyRetiredDuringTheGrant`), a rotation retiring the previous version and
  its tokens, moving past versions retired by hand, repairing a floor above the registered version
  and refusing a key transit does not have (`TestRotate*`), the startup assertion registering,
  stopping on a mismatch, a missing version or a version below the floor, and waiting out an
  outage (`TestStartup*` in `internal/server`), readiness answering `starting` and `retired`
  (`TestReadyz_*`), the commands end to end (`TestKeysEnsureRotateAndStatus`,
  `TestKeysStatusReportsAnAbsentKey`, `TestAcquireCommandDoesNotCreateTheKey`), a bad key name
  refused by the configuration (`TestLoadConfigRefusesABadKeyName`), migration 5 on a database with
  two active versions (`TestMigrationFiveKeepsOnlyTheHighestActiveVersion`), and the canary test's
  needles extended with the key's PEM body, its JWK coordinates and the test's own OpenBao token,
  searched in every 24-character window.

### Replay check

`POST /internal/replay-check` records a DPoP proof's `(jkt, htm, htu, jti)` and answers `fresh`, or
409 `TOK-REPLAY` when it was seen before; of concurrent identical calls exactly one is fresh. The
caller's window applies when it sends `not_after` (at most `iat` + 90 s, not in the past), the
contract's default otherwise (`now` - 60 s <= `iat` <= `now` + 30 s, kept until `iat` + 90 s);
anything else is 422 `TOK-PROOF-INVALID`, and a database it cannot write is 503
`TOK-STORE-UNAVAILABLE`. The connector uses the same table directly through the same code
(`internal/replay`), so a proof seen by either is seen by both. Every consumer of the table keys it
on the same normalised `htu`, `dpopproof.NormalizeURI` (RFC 9449 4.3; RFC 3986 6.2.2 and 6.2.3):
lowercase scheme and host, the default or an empty port removed, no query, fragment or userinfo,
percent escapes in uppercase hex with unreserved characters decoded, dot segments removed, an empty
path as `/`. The replay check normalises the `htu` it is sent, and refuses one with no such form
with 422 `TOK-PROOF-INVALID`; the resource-side verifier (`internal/tokenverify`) normalises before
it records; the connector normalises the provider's already normalised `htu` once more, since the
provider keeps an empty port. So `https://EXAMPLE.test:443/%7Eapi` and `https://example.test/~api`
are one proof. Refusals carry the reason code and the correlation id and nothing the caller sent.

**Caller.** The caller is authenticated before the body is read. The store takes its identity from
the `X-Forwarded-Client-Cert` its own sidecar sets from the client certificate it verified, and
admits it only if its SPIFFE ID is on `--replay-callers`; otherwise 403 `TOK-CALLER-DENIED`. That is
sound only under two deployment prerequisites, which the chart owes when the endpoints are
deployed: the store's sidecar replaces any such header a client sent (pod annotation
`proxy.istio.io/config: {"proxyHeaders":{"forwardedClientCert":"SANITIZE_SET"}}`, and no
ProxyConfig overriding it), and the API port is reachable only through the sidecar (STRICT mTLS and
a NetworkPolicy). As a second line the store accepts exactly one certificate element across every
header field: a client-supplied element next to the sidecar's, which the default `APPEND_FORWARD`
would produce, is refused.

**Lost replay state.** `proof_jti` is unlogged, so crash recovery empties it, and a proof can then
be replayed once inside its acceptance window: `iat` may lie 30 s ahead and the proof stays
acceptable 90 s after it, so 120 s. The store detects this with an unlogged sentinel,
`replay_epoch` (migration 2), which crash recovery empties together with `proof_jti`. It checks the
sentinel at start, every 10 s and whenever the pool opens a new connection; a missing row is
written back and logged once as a warning naming the window. A missing row also means a first start
on a new database, so the warning says "may have been lost". The postmaster's start time is not a
substitute: a backend crash recovers the cluster without restarting the postmaster. Checked by hand
on PostgreSQL 16.10 (the pinned image): with one row in each table, `kill -9` of a backend made the
postmaster reinitialise and recover, both tables came back empty, and `pg_postmaster_start_time()`
was unchanged. Expired records are swept every minute.

## Acquisition of upstream tokens

The store obtains the token it substitutes on a route from the peer zone's Connector through the
verified-presentation grant ([IF-02 v1.1](api-docs.md#if-02-connector-authorization-surface),
[Connector OAuth2 provider](oauth2-provider.md#verified-presentation-grant)). The code is
`services/token-store/internal/acquire`; `Acquirer.Acquire(ctx, route)` is what substitution calls
on demand and `Acquirer.Replace(ctx, route, fence)` what renewal calls, and there is no HTTP endpoint
for either.

The calls to the Connector (the challenge, the grant with its DPoP proof and one nonce retry, and the
response checks below) are the shared client `internal/connectorclient`, which the Participant also
uses with its own key; acquire maps its errors to the reason codes below. The fixture outcome signer
is `internal/if03/if03fixture`, and the zone-B harness of the tests is `internal/connectortest`
(`acquiretest` configures it for the store's route).

**Order.** For one route `(peer_zone, audience, tenant)`:

1. `POST /oauth2/challenge` at the peer Connector with the route's client credentials
   (`client_secret_basic`) and the route's audience.
2. The route's `OutcomeSource` returns a signed IF-03 outcome for that challenge.
3. The store verifies the outcome with `internal/if03` against its own trusted issuers (the peer's
   verifier keys) and the expected client, challenge and audience, and records its receipt in its
   own `verified_outcome`, status `verified`, unconsumed. An outcome it has seen before is refused
   (`CRED-OUTCOME-CONSUMED`) and never sent.
4. `POST /oauth2/token` with `grant_type=urn:facis:params:oauth:grant-type:verified-presentation`,
   the outcome, the challenge and the audience, and a fresh DPoP proof signed by the store's key
   through transit. A `use_dpop_nonce` answer is retried once with the server's nonce.
5. The answer must be `token_type` DPoP and the access token's payload must carry `cnf.jkt` equal to
   `signing_key.jkt`, the route's audience in `aud`, and an `exp` in the future. Only the payload is
   read: the signature is checked by the peer's resources (`internal/tokenverify`).
6. The token value is written to KV v2 at `ztd/token-store/upstream/<token_id>`, create-only.
7. One transaction consumes the receipt (conditionally: unconsumed, verified, for the route's audience
   and not expired at the store's clock), retires the route's live rows that have expired, and
   inserts the `upstream_token` row `active` with `token_ref` (the KV path), `key_ref`, the token's
   `iat` and `exp`, and `renew_after` at 75 % of its lifetime, together with the `upstream.acquired`
   audit row. A route has at most one live row (`active` or `renewing`; a unique index of migration
   4), so `Acquire` never replaces a token that is still valid: on such a route the insert is refused,
   the transaction is confirmed rolled back and the value deleted (`ACQ-ACTIVATION-FAILED`). That
   holds for `token-store acquire --route` too. Replacing a valid token is [renewal](#renewal)'s.

**The store's key.** The store's DPoP key is its transit key (`signing_key` in the configuration),
and the version it mints with is the one active `signing_key` row of that key, resolved through
transit before every acquisition; a row with another thumbprint or a retired one stops acquisition
(`ACQ-STORE-UNAVAILABLE`), and a key retired between the grant and the activation activates
nothing (`ACQ-KEY-RETIRED`). Proofs are signed by transit with the caller's context; no private
key enters the process. The rules, the startup assertion, rotation and the OpenBao policies are
[key custody](#key-custody).

**Recovery (D10).**

| What happened | What the store does |
|---|---|
| The peer's answer to the grant was lost or unreadable (transport error, cut connection, 5xx, a body that is not a token response) | Terminal for that outcome: audit `upstream.failed` `ACQ-PEER-RESPONSE-LOST`, the receipt stays unconsumed. The next attempt uses a fresh challenge and outcome; a consumed outcome is never reused, and the peer's consumption is never reset |
| The peer refused the grant | Audit `upstream.refused` with the peer's `CRED-OUTCOME-*` reason (or `ACQ-PEER-REFUSED`); nothing activated |
| The issued token fails a check of step 5 | Audit `upstream.refused` `ACQ-TOKEN-INVALID` with the failed check (`token_type`, `cnf.jkt`, `aud`, `exp`, `format`); nothing written |
| The KV write fails | Nothing activated (`ACQ-KV-WRITE`). A value written despite the error has no row and is swept |
| The store's key was retired between the grant and the activation (`keys rotate`) | Nothing activated: the activation holds the key's row `FOR SHARE` only while it is active, finds none, deletes the value and audits `upstream.failed` `ACQ-KEY-RETIRED`. The next attempt signs with the new version ([key custody](#key-custody)) |
| The transaction is confirmed rolled back: an error before COMMIT was sent, the receipt no longer consumable (`ACQ-ACTIVATION-REFUSED`), or COMMIT answered `ROLLBACK` because the transaction had already failed (`ACQ-ACTIVATION-FAILED`) | The KV value is deleted; audit `upstream.failed` |
| COMMIT was sent and any other answer came back: none, a transport error, or a server error. A server error is not proof of a rollback: a FATAL termination can arrive after the commit took effect | The value is kept until reconciliation decides. It waits until the transaction has ended (the transaction holds an advisory lock on `token_id` from its first statement; `statement_timeout` 5 s and `idle_in_transaction_session_timeout` 10 s bound it), then, in an explicit READ COMMITTED transaction and in a statement after the wait, reads `upstream_token` by `token_id`: a row means the token is active; no row means the value is deleted, while the lock is still held (`ACQ-ACTIVATION-FAILED`). A COMMIT refused with a deferred-constraint violation or a serialization failure ends here with no row. If it cannot tell, or the caller's context ends first (reconciliation runs under it; a caller already gone does not reconcile at all), the value stays (`ACQ-COMMIT-UNKNOWN`) for the sweep |
| A KV value under the prefix has no row | The orphan sweep first checks the value's age by its KV `created_time` (more than 10 minutes, longer than any transaction can stay open), then takes the same advisory lock in READ COMMITTED, checks again that no row exists, and deletes the value before releasing the lock, so an activation that committed after the sweep first looked keeps its value. A value with a row, in any state, is never touched (`upstream.orphan_deleted`, `ACQ-ORPHAN-DELETED`) |

Only a committed live row permits substitution: the route's `active` row, or its committed
`renewing` row, which stays the route's token until its replacement commits. Audit rows carry the route, the peer zone, the
audience, the outcome and token ids and the reason code; never the token, a proof, the client secret
or the outcome.

**Configuration.** A JSON file (`--acquire-config`, `TOKEN_STORE_ACQUIRE_CONFIG`) holds file paths,
never secrets:

```json
{
  "signing_key": "token-store",
  "connector_signing_key": "connector",
  "trusted_issuers": [
    {"issuer": "https://verifier.zone-b.example", "kid": "verifier-1", "public_key_file": "/etc/token-store/verifier-1.pem"}
  ],
  "routes": [{
    "name": "zone-b-api", "peer_zone": "zone-b", "audience": "https://api.zone-b.example", "tenant": "",
    "connector_url": "https://connector.zone-b.example",
    "client_id": "zone-a-token-store", "client_secret_file": "/var/run/secrets/zone-b-client/secret",
    "callers": ["spiffe://zone-a.example/ns/ztd-mgmt/sa/ztd-guard"],
    "methods": ["GET", "POST"], "target_prefix": "https://api.zone-b.example/v1",
    "fixture_outcomes": {"issuer": "https://verifier.zone-b.example", "kid": "verifier-1",
                         "private_key_file": "/etc/token-store/fixture-key.pem", "role": "participant-operator",
                         "entitlement": "write", "validity_seconds": 90}
  }]
}
```

`fixture_outcomes` is the fixture `OutcomeSource` for tests and the demo: it signs a verified IF-03
outcome for each challenge with the configured key, a new `outcome_id` per call, valid 60 to 120 s
(default 90 s). A route without an outcome source cannot be acquired. `callers`, `methods` and
`target_prefix` make the route substitutable ([Substitution](#substitution)); a route without
callers is acquired by the command line only, and `methods` or `target_prefix` without callers is
refused. Two routes with the same `(peer_zone, audience, tenant)` are refused, so a route key names
one route. Unknown members are refused.

**Commands.**

```bash
token-store acquire --route NAME   # acquire and activate one token; prints {"route","token_id","expires_at"}, never the token
token-store sweep-orphans          # run the orphan sweep once; prints {"deleted": N}
```

Both take `--database-url`, `--openbao-url`, `--openbao-token-file` (the OpenBao token, read on every
call, as for the connector) and `--acquire-config`, each defaulting to the `TOKEN_STORE_*` variable
of the same name, and `--timeout` (default 1m). Exit 0 on success, 1 on a failed acquisition (the
reason code is printed), 2 for a usage error.

**Verification.** `go test ./services/token-store/internal/acquire` with
`TOKEN_STORE_TEST_DATABASE_URL`, `TRANSIT_TEST_ADDR` and `TRANSIT_TEST_TOKEN` runs the real `connector` binary
as zone B (built once per run and started as a subprocess on a migrated database of its own, with a
transit signing key, the registrar, the trusted-issuers file and the scope map; the store's client is
registered through the registrar's DCR with the delegated verified-presentation scope) against a
zone-A database and OpenBao: the happy path including the nonce retry and the token accepted by
`internal/tokenverify` with a proof from the store key; each `CRED-OUTCOME-*` refusal by the peer;
an outcome A refuses itself; a lost and an unreadable answer followed by a fresh acquisition (the
peer's ledger shows every outcome consumed once); a failed KV write; a receipt expired before the
transaction; COMMIT committed with its acknowledgement lost or followed by a FATAL error, rolled
back, refused by a real deferred-constraint violation and by a real serialization failure, and
never delivered; a commit that lands while reconciliation waits on a database whose default
isolation is REPEATABLE READ; the orphan sweep, including an activation that commits between its
first look and its deletion;
the response checks; and a canary that no credential reaches logs, errors or audit rows.

## Key custody

The store's DPoP key is a transit key in the zone's OpenBao (`signing_key` in the acquisition
configuration): `ecdsa-p256`, not exportable, no plaintext backup, and the private half never
leaves OpenBao, which signs the store's proofs with it (ZT-11). PostgreSQL holds, in `signing_key`,
a reference to one version of that key, `transit:<name>:v<n>`, with that version's RFC 7638
thumbprint (`jkt`, the `cnf.jkt` the upstream tokens are bound to), its algorithm and its state,
`active` or `retired`. Only public keys enter the process, and no record, error or readiness body
carries one; the canary test and the lifecycle proof look for them.

**The active row decides.** At most one row of a key is `active` (a partial unique index,
migration 5), and that row is the version the store mints with: `LoadKey` reads it, resolves its
public key through transit and refuses a thumbprint that does not match the key, a reference that
is not of the form above, or a registered version that is retired with nothing newer registered.
It also refuses a version below transit's signing floor, which transit would not sign with.
Transit's latest version is advisory: a version rotated in OpenBao alone changes nothing until
`token-store keys rotate` registers it, and the service only notes it (`transit key is newer than
the registered version`). A key with no row at all is registered at its latest version with its
thumbprint (`ON CONFLICT DO NOTHING` lets two replicas race for it, and the row that won is read
back); a key whose rows are all retired is not: moving on from retired versions is `keys rotate`'s,
so a rotation is never skipped by the first acquisition after a retirement. More than one active
row of a key (a database migration 5 has not reached) is refused, never an arbitrary pick.

**Startup.** With an acquisition configuration the service, before it is ready, makes sure the
configured key exists in transit (the one place that may create it; see the policies below),
registers or verifies its active row and that it is not below transit's signing floor, resolves
every active `signing_key` row through the key it names, and notes a newer transit version
(`transit key is newer than the registered version; run token-store keys rotate`). Readiness
answers `starting` until this has succeeded once, so no traffic reaches a pod whose keys may yet
prove misconfigured. A misconfiguration stops the process: exit 1 with one record, `signing key
misconfigured; stopping`, with the key, the `key_ref` it concerns when one does, and a `reason`:
`missing` (a registered version transit does not have, no key at the configured name, or no
transit engine at the mount), `mismatch` (a registered thumbprint that is not the version's public
key, or rows that contradict transit), `malformed` (an active `key_ref` not of the form
`transit:<name>:v<n>`), `retired` (the registered version is retired with nothing newer registered,
or below transit's signing floor), `unsupported` (the key is not a non-exportable `ecdsa-p256`
key) or `refused` (transit answered 4xx other than 408 and 429: the token's policy; a 403 from a
proxy or a policy written after the pod started counts, and the crash loop recovers once it is
there). An outage is waited out instead: `unreachable`, `token` (the token file is missing,
unreadable or empty) or `database` (PostgreSQL answered with an error, the schema not applied yet
for one), retried with a pause growing from one to thirty seconds, one `startup signing key
unavailable` record per change of reason rather than per attempt, readiness `starting` meanwhile;
`signing keys resolved` is logged once, with the reference and the number of active rows. A name
transit would refuse (outside `[A-Za-z0-9._-]`, longer than 128) is refused when the configuration
is read, exit 2. No record names what a dependency said. The kubelet and `helm --wait` are the
loud part: a pod that stops is a crash loop whose last record is the reason, found at startup and
not at the first call. A runtime acquisition that cannot load the key logs one `store key
unavailable` record with the same reason word and fails `ACQ-STORE-UNAVAILABLE`.

**Minting under a retired key is refused at both layers.** The activation inserts the
`upstream_token` row from a locked read of the key's row (`FOR SHARE`, `state = 'active'`), so a
rotation that retires the key either waits for an activation in flight and then retires its token,
or came first and the activation inserts nothing: `ACQ-KEY-RETIRED`, the value deleted, the audit
row `upstream.failed`. Substitution reads a token only joined to an `active` key row. And transit
itself refuses to sign with a version below the key's `min_encryption_version`, which `keys rotate`
raises, so a retired version signs nothing new for any caller, inside the store or not.

**Operator commands.** `token-store keys ensure|rotate|status` take the flags of `acquire`
(`--database-url`, `--openbao-url`, `--openbao-token-file`, `--acquire-config`, `--timeout`) and
hold the only transit client that may create or rotate a key; the service and `acquire` sign
through a read-only one, so a deleted key is reported, never replaced on the way to a grant.

- `keys ensure` creates the key in transit if it is missing and registers its latest version;
  prints `{"key", "key_ref", "jkt", "state"}`. Run it before a runtime-mode install whose service
  token may not create keys.
- `keys rotate` moves the store to the next version inside one database transaction under the
  key's rotation lock (bounded on the server: statement, lock and idle-in-transaction timeouts, so
  a client that vanishes cannot keep the key locked), in this order: the key's registered rows are
  read; the next version exists in transit (adopted when transit is already ahead of every
  well-formed registered version, active or retired: a rotation done in OpenBao, or a previous
  `rotate` that did not commit; else created by rotation, which is also how the store moves past
  versions an operator retired by hand); every other active row of the key is retired with
  `retired_at` and the next version registered with its thumbprint; every live upstream token
  bound to another version of the key is retired (they are reacquired on demand; a renewal in
  flight ends `ACQ-KEY-RETIRED` if it had loaded the old key, or loses its claim, `ACQ-CLAIM-LOST`,
  if its row was retired first); the audit row `key.rotated` is written with the detail
  the command prints: `{"key", "active", "jkt", "retired": [...], "upstream_tokens_retired",
  "min_signing_version", "adopted"}`; the transaction commits; then transit's signing floor is
  raised to the next version (it only ever rises). Two rotations at once queue on the lock and each
  sees the other's result, so the registered version never moves backwards. A failure before the
  commit leaves the database as it was and transit at most a version ahead, which the next `rotate`
  adopts; a failure after it leaves the previous version signable in transit only, which the
  database already refuses, until the next `rotate`'s floor raise covers it (the floor only
  rises). A floor found above the registered version (set by hand) is reported by startup and
  readiness as `retired` and repaired by adopting. A key with nothing registered is
  registered, as `ensure` does, and retires nothing; a key transit does not have is refused, never
  created; a malformed reference that is retired is ignored, an active one refused. The running
  service needs no restart: the next acquisition reads the new active row, and readiness resolves
  it. The activation and the rotation take the key's row before any token row, so neither waits for
  the other in a cycle; an acquisition that finds the route's live token bound to a key that is no
  longer active retires it with the expired ones, so a route is never held by a token nothing can
  substitute. Migration 5 applies the same rule once to a database the earlier store wrote: of
  several active versions of a key only the highest stays active, the live tokens bound to the
  others are retired with them, and malformed references are left alone.
- `keys status` prints whether transit has the key (`present`), its latest version and signing
  floor (`min_signing_version`), and the registered versions newest first. Retired rows stay:
  proofs minted under them remain attributable.

**OpenBao policies.** The service's token reads its key, signs with it and owns its KV prefix; the
operator's token may create, rotate and configure the key, and nothing else. The lifecycle proof
writes exactly these and runs the service with the first alone:

```hcl
# token-store: the service's token
path "transit/keys/<signing_key>"         { capabilities = ["read"] }
path "transit/sign/<signing_key>"         { capabilities = ["update"] }
path "secret/data/<kv_prefix>/*"          { capabilities = ["create", "read"] }
path "secret/metadata/<kv_prefix>"        { capabilities = ["list"] }
path "secret/metadata/<kv_prefix>/*"      { capabilities = ["read", "list", "delete"] }

# token-store-admin: token-store keys ensure|rotate, never mounted in the service
path "transit/keys/<signing_key>"         { capabilities = ["create", "read", "update"] }
path "transit/keys/<signing_key>/rotate"  { capabilities = ["update"] }
path "transit/keys/<signing_key>/config"  { capabilities = ["update"] }
```

Startup creates the key only when it is missing, which needs `update` on
`transit/keys/<signing_key>` (transit creates a key on an update of its path; `create` alone is
refused); a key pre-provisioned with `keys ensure` keeps the service's token read-only there.
Readiness reads the key and never creates one.

**Limits, by choice.** Startup keeps provisioning a missing key, as the build before this one did,
so a fresh runtime install comes up without an operator step; the cost is the capability
(`update`) unless the key is pre-provisioned. A transit 4xx at startup is a misconfiguration except 408
and 429; a policy that appears later is reached through the kubelet's restarts, not an in-process
retry. Substitution's key cache and `KeyAt` read no row state: the lookup that chose the token
joined on an `active` key in the same statement, and transit's floor refuses a retired version
regardless. Retiring the last version of a key (decommissioning) has no command yet; `keys rotate`
always leaves one active version, and renaming `signing_key` leaves the old key's active row behind
until an operator retires it by hand (a token scoped to the new key cannot read it, which the store
reports as a warning, `an active row of another key cannot be read with this token`, not a fault;
a token that can read it still resolves it, and a row of a key deleted from transit is `missing`,
a fault, as the contract's clause reads).
The lifecycle proof's OpenBao runs in memory, so its key-custody stage shows readiness failing
closed when OpenBao is gone and does not bring it back.

## Substitution

`POST /internal/substitute` hands the guard the upstream credential of one configured route: the
route's token as `authorization` (`DPoP <token>`) and a fresh DPoP proof as `dpop`, minted with the
store's key for exactly the upstream request, with `expires_at` the token's expiry. The caller's own
proof is never forwarded. The code is `services/token-store/internal/substitute`, the handler
`internal/server/substitute.go`. Every answer carries `Cache-Control: no-store`.

**Order.** Nothing is read from the database or the key-value store, and nothing is signed, before
the request is authorized:

1. The caller is authenticated as for the replay check (the forwarded client certificate) and must
   be listed by some route's `callers`; otherwise 403 `TOK-CALLER-DENIED`, before the body is read.
2. The body is parsed strictly: at most 8 KiB, one JSON object and nothing after it, no unknown
   members, the contract's required members, `method` from its enum, `correlation_id` 1 to 128
   bytes, `upstream_nonce` 1 to 256 visible ASCII characters when present. A body that does not
   parse matches no route: 403 `TOK-ROUTE-DENIED` (the contract has no other refusal for it).
3. Authorization against the routes from configuration alone (D7): a route that lists the caller and
   equals the request's `peer_zone`, `audience` and `tenant` (absent or null is the empty tenant),
   allows its `method`, and whose `target_prefix` covers `target_uri`. Otherwise 403
   `TOK-ROUTE-DENIED`. `target_uri` must already be in canonical form, and the store refuses rather
   than normalises: an absolute `http`/`https` URI with lowercase scheme and host, no userinfo, no
   fragment, no default port, no dot segment in any spelling (`.`, `..`, `%2e`, with `;` parameters),
   no encoded `/` or `\` and no `\`, and unchanged by a parse and re-serialisation. The prefix
   matches on the same origin and whole path segments (`/v1` covers `/v1` and `/v1/x`, never `/v10`);
   the query is not compared.
4. The route's live row: `active`, or `renewing` (claimed by a renewal worker; it is still the
   route's token until its replacement commits), unexpired at the store's clock, bound to an
   `active` `signing_key`. A `failed` or `retired` row is never read, however long it would still be
   valid. Migration 4 allows one live row per route, so there is nothing older to fall back to.
5. No live row: the token is acquired on demand ([Acquisition](#acquisition-of-upstream-tokens)),
   once for all concurrent callers. In one process they queue on the route's gate, so waiters hold
   no database connection; across replicas the first takes a transaction-scoped advisory lock on the
   route (`lock_timeout` the caller's remaining deadline), looks again, and only then acquires; the
   others find the committed row when they get the lock. Before it takes a connection, a route also
   takes one of two process-wide acquisition slots: an acquisition holds at most two pooled
   connections (its route lock and one acquisition statement), the pool has eight, so however many
   routes are cold at once, four connections stay for the replay check, readiness, lookups and
   renewal. A route without an outcome source, or an acquisition the peer side definitively answered
   without a token (a `CRED-OUTCOME-*` refusal, another refusal, no challenge, a lost or unreadable
   answer, an issued token that failed the store's checks, an outcome source that failed), is 409
   `TOK-NO-UPSTREAM`; an acquisition that failed in the store's own dependencies (database, transit,
   KV, activation, an unknown commit) or ran out of the caller's deadline is 503
   `TOK-STORE-UNAVAILABLE`. The reason code is logged, and audited by acquisition.
6. The token is read from the key-value store by `token_ref` and must have the contract's
   `authorization` form; the store key version named by `key_ref` is checked against its recorded
   thumbprint (cached per version); the proof carries `htm` the method, `htu` the target without
   query, `ath` the token's hash, `nonce` the `upstream_nonce` when given, and a new random `jti`.
7. The clock is read again before the answer leaves. A token that has expired since the lookup, or
   expires within 1 s, is discarded: 409 `TOK-NO-UPSTREAM`, with no credential in the body. It is
   not reacquired in the same call; the caller's retry finds no live row and acquires.

Every database, key-value store and transit operation is bounded (2 s each) and the whole call by
10 s, the on-demand acquisition included: acquisition runs under the caller's deadline, a commit
whose outcome is unknown when the caller is gone is not reconciled synchronously (its value stays for
the orphan sweep, the D10 rule), and only the cleanup that must survive the deadline (a rollback,
deleting the value of a transaction confirmed rolled back, the failure's audit row) runs on, at most
2 s per step. A dependency that fails is 503 `TOK-STORE-UNAVAILABLE`, fail closed. Records name the route and the `token_id`, never the token, the proof or the
`authorization` value; refusals carry the reason code and the correlation id and nothing the caller
sent.

**Verification.** `go test ./services/token-store/internal/server` with the three variables above
runs substitution through the service against zone A's database, OpenBao and the real `connector`
binary as zone B: a valid token yields `DPoP <token>` and a proof by the store key for the target
(method, `htu` without the query, `ath`, nonce), two calls give two distinct `jti`s, and B's
`internal/tokenverify` accepts the token with each proof; a token whose expiry the store's clock
passes, or comes within 1 s of, while the proof is signed answers 409 `TOK-NO-UPSTREAM` with no
credential and no new acquisition; with zone B stopped, an expired-only, a
failed-only and a retired-only route answer 409 `TOK-NO-UPSTREAM`; with the database pool closed and
OpenBao counting its calls, every caller refusal is 403 `TOK-CALLER-DENIED` and every wrong method,
target (a dot-segment escape included), peer zone, audience, tenant or malformed body is 403
`TOK-ROUTE-DENIED`, with no OpenBao call, while an authorized request answers 503; twelve concurrent
callers on two store replicas sharing the database, with only an expired row, cause exactly one
acquisition at B, all get that token, the expired row is retired and one live row remains; eight
cold routes substituted at once each acquire within the deadline while the replay check keeps
answering within a second; a hanging KV write, a hanging transit signature and an activation blocked
by a table lock each answer 503 within the deadline (2 s in the test) with no live row, no value
and no advisory lock left, and the route acquires once the fault is gone; injected database, transit
and KV failures answer 503 and a peer refusing the outcome 409; the
`no-store` header; and a canary that no token, proof or client secret reaches a record or a refusal.
`internal/caller` tests the router and the canonical-target rule on their own.

## Renewal

Every `token-store serve` with a routes file runs the renewal worker (`services/token-store/internal/renew`,
D11), in every replica; the replica's pod name is its `claimed_by`. Each cycle, every 15 s:

1. **Staleness sweep.** A claim older than 5 minutes belongs to a worker taken to be dead: the row
   goes back to `active` with the claim cleared when the token is still valid (it is due, so the next
   claim renews it; audit `renewal.released`, `REN-CLAIM-STALE`), or to `failed` when it has expired
   (`renewal.failed`, `REN-EXPIRED`). A live worker never holds a claim that long: a renewal is at
   most three attempts of 30 s each with 2 s and 4 s of backoff.
2. **Claim**, one token at a time and up to four per cycle, so no claim waits behind another
   renewal:

   ```sql
   UPDATE upstream_token SET state = 'renewing', claimed_by = $instance, claimed_at = $now, updated_at = $now
   WHERE token_id IN (SELECT token_id FROM upstream_token
       WHERE state = 'active' AND claimed_at IS NULL AND renew_after <= $now
       ORDER BY renew_after FOR UPDATE SKIP LOCKED LIMIT 1)
     AND state = 'active' AND claimed_at IS NULL
   RETURNING token_id, peer_zone, audience, tenant, claimed_by, claimed_at
   ```

   A row another worker is claiming at that moment is skipped, not waited for; the outer conditions
   repeat the inner ones, so a row that changed meanwhile is never claimed twice. The returned
   `(claimed_by, claimed_at)` is the claim's fence.
3. **Renew** through `Acquirer.Replace(route, fence)`: a full acquisition with a fresh challenge and
   outcome and a new `token_id`. Its transaction consumes the receipt, retires the old row **only if
   it is still `renewing` under exactly this fence**, inserts the new row `active` and audits
   `upstream.renewed` (with `replaces`, the old `token_id`), in one commit: the route goes from the old
   live row to the new one, never through none or two (migration 4 refuses two). If the fence no
   longer holds the transaction is confirmed rolled back and the new value deleted, the D10 rule
   (`ACQ-CLAIM-LOST`, audit `renewal.claim_lost`). Each attempt is audited by acquisition with its
   reason code and `replaces`. Before each attempt the worker checks that its fence still holds and
   stops if not.
4. **Fail.** After three failed attempts, with 2 s then 4 s of backoff, the row becomes `failed`,
   again only under the worker's fence, audited `renewal.failed` with the last attempt's reason code
   in the same statement. `failed` is terminal: substitution never reads it, and the route's next
   substitution acquires on demand, or answers `TOK-NO-UPSTREAM` while the peer is down. A row whose
   route is no longer configured fails at once (`REN-NO-ROUTE`).

While a row is `renewing` it is still the route's token: substitution keeps serving it until the
replacement commits (see [Substitution](#substitution)). The worker also runs the orphan sweep of
acquisition every 5 minutes, bounded to 2 minutes a run. Every statement of the worker is bounded to
5 s, every attempt to 30 s; a cycle interrupted by shutdown leaves its claim to the staleness sweep.

**Operations.** A token stuck `renewing` beyond the staleness window is released by the next cycle
of any replica. A `failed` token stays `failed` (it is history, as `retired` is); the route recovers
by the next substitution acquiring on demand once the peer answers, or by
`token-store acquire --route NAME`. `audit_event` holds the whole trail of a route: `upstream.acquired`,
`upstream.renewed`, `upstream.failed` and `upstream.refused` per attempt, `renewal.*` for the
worker's own decisions, all with the reason code.

**Verification.** `go test ./services/token-store/internal/renew` with the three variables above,
against zone A's database, OpenBao and the real `connector` binary as zone B: two workers started
together on one due token make exactly one renewal attempt per cycle, three cycles in a row; a claim
never waits for a row another worker holds locked; with zone B stopped the token ends `failed` after
three audited attempts, a later cycle leaves it alone, and substitution answers `TOK-NO-UPSTREAM`; a
crashed worker's claim is released after the window and the next worker renews, while a stale claim
on an expired token is failed and not renewed; a slow worker whose claim was taken over, whether the
other worker has already renewed or is still renewing, has its late completion refused
(`ACQ-CLAIM-LOST`) and its value deleted, and its late failure changes nothing; a sampler running
through three renewals never sees the route with no live row, two live rows or two active rows, and a
second live row is refused by the index; and `Run` renews and sweeps orphans on its own.
`internal/server` checks that a served store renews a due token at start.

## What follows

The lane from the guard to the store across the planes, and the deployment prerequisites of the
replay check and substitution (the sidecar's `SANITIZE_SET` and the network policy, above), each
building on the tables, the queries and the service above.

### Key material separation at readiness

Runtime readiness resolves the store's current transit key and every active key
reference, then reads each route Connector's `/.well-known/jwks.json`. Any matching
RFC 7638 thumbprint returns `signing_key: shared_issuer_key`; unavailable or malformed
JWKS returns `unreachable`. Requests share the readiness deadline and redirects
are refused. No key material or token is returned in the readiness response.

`connector_signing_key` is now optional defence in depth: when supplied it must
differ from `signing_key`, but operator-entered names do not establish separation.
Existing configs may retain it. Readiness now depends on Connector JWKS access
even before the first token is acquired; provision keys and network lanes first.

Readiness reads `transit/keys/<store-key>` and never creates a key; which token may create, rotate
and sign is [key custody](#key-custody). Issuer-separation successes are cached for at most five
minutes; any change in the store's active public-key set forces an immediate check of each route's
Connector JWKS. Distinct endpoints are fetched concurrently. A shared key returns
`shared_issuer_key` and logs a warning without key material. Non-EC-P-256 issuer entries are
skipped with a log record. An unavailable issuer fails readiness once no fresh passing check
remains.
