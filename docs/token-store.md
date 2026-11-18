# Token store

The token store is the zone's keeper of upstream credentials
([token-store.v1.openapi.yaml](contracts/token-store.v1.openapi.yaml)): it holds the tokens the
peer zone minted to this zone, substitutes them for the guard so a caller's own proof is never
forwarded, and detects DPoP proof replay for the connector and the guard. It stands on one
PostgreSQL database that it shares with the connector's OAuth2 surface
([Connector OAuth2 provider](oauth2-provider.md)), whose clients and issued tokens live in the same
schema, and on the zone's key-value store ([Secrets](secrets.md)) for its key material. This page
describes that database and how its schema is applied, the service that stands on it (its
configuration, its liveness and readiness, its records and its identity), and how all of it is
verified; the service's endpoints are documented as they land.

## One database, two owners

| Tables | Owner | What they hold |
|---|---|---|
| `oauth2_client`, `oauth2_token`, `oauth2_dpop_nonce` | the connector's OAuth2 surface | dynamically registered clients (secret as a bcrypt hash, the RFC 7591 metadata document as registered), issued access and registration tokens keyed by signature, server-issued DPoP nonces |
| `signing_key` | the token store | references to the store's outbound signing keys in the key-value store, with their thumbprints; never key material |
| `verified_outcome` | the token store | verification outcomes received over IF-03, consumed at most once |
| `upstream_token` | the token store | the upstream tokens held per route `(peer_zone, audience, tenant)`, as references into the key-value store, with state and the single-flight renewal claim |
| `proof_jti` | the token store, on behalf of the connector and the guard | one-time DPoP proof identifiers, keyed `(jkt, htm, htu, jti)` and kept until `not_after`; the replay check of the store's API |
| `audit_event` | both | registration decisions, outcome consumption and refusal, every renewal attempt with its reason; append-only |

Three properties are the schema's own, not the services' good conduct:

- **An outcome is consumed exactly once.** The upstream token's reference to its outcome is unique,
  so a second token row for one outcome is refused by the database even on a path that skipped the
  consumption check. The intended path marks the outcome consumed and inserts the token in one
  transaction.
- **A replayed proof is refused by the primary key.** The replay check is one insert; a conflict is a
  replay, and of any number of concurrent identical proofs exactly one is admitted. The table is
  unlogged on purpose: after a crash it is empty, so a proof can be replayed at most once inside its
  own acceptance window, as the API documents.
- **Renewal is single-flight.** A worker claims a due token with `FOR UPDATE SKIP LOCKED` and records
  the claim; a second worker sees nothing to do. A claim without a claimant, or the reverse, is a
  constraint violation, and a staleness sweep releases the claim of a worker that died.

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
and a readiness answer, and JSON records on stdout. It serves the contract's `/healthz` and
`/readyz` and nothing else yet; the endpoints follow. It never waits for its dependencies at
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

The environment fills in after the command line is parsed, never as a flag's default, so a
malformed variable only matters when its flag is absent and no value, the connection URL above
all, is ever part of the usage text the flag package prints on an error. Exit codes: 0 after a
clean stop, 1 when a listener cannot be bound or fails, 2 for a usage error. On SIGTERM or SIGINT
`/readyz` answers 503 with `"draining": true` at once, without asking the dependencies, so the
pod leaves the Service's endpoints, while both listeners keep answering for the drain delay, the
time routing needs to move away; then both listeners drain at once within the shutdown timeout,
and the connection pool closes.

### Liveness and readiness

`/healthz` answers 200 while the process serves and consults nothing, so no dependency outage
ever restarts the pod. `/readyz` answers 200 only when every dependency is there and in the state
the store needs, 503 otherwise, and names what it found:

```json
{"ready": false, "checks": {"postgres": "ok", "openbao": "sealed"}}
```

The words are the whole vocabulary: `ok`, `unreachable`, `schema_behind` and `schema_drift` for
PostgreSQL; `ok`, `unreachable`, `uninitialized` and `sealed` for the key-value store. Nothing a
dependency says, no address and no credential, reaches the body. Both checks run at once under
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
current and every active key reference resolves". The last clause presupposes a reachable
key-value store and belongs to key custody, which follows; until then readiness is the first two
clauses and the key-value store being usable. The store fails closed either way: not ready means
no traffic.

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
principals and the forwarded client certificate in the handler, when the endpoints land; the
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
  default uninstall keeps it. The records and the verdict are the run's artefact and go to the job
  summary; nothing is committed. Locally, the script writes to the git-ignored
  `.dev/token-store-evidence/`.

## What follows

Key custody against the key-value store, which is when "every active key reference resolves"
joins readiness; the endpoints of the API with the allow-list of their callers on the mesh
identity; and the lane from the guard to the store across the planes, each building on the
tables, the queries and the service above.
