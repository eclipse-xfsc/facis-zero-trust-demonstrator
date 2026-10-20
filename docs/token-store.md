# Token store

The token store is the zone's keeper of upstream credentials
([token-store.v1.openapi.yaml](contracts/token-store.v1.openapi.yaml)): it holds the tokens the
peer zone minted to this zone, substitutes them for the guard so a caller's own proof is never
forwarded, and detects DPoP proof replay for the connector and the guard. It stands on one
PostgreSQL database that it shares with the connector's OAuth2 surface
([Connector OAuth2 provider](oauth2-provider.md)), whose clients and issued tokens live in the same
schema. This page describes that database, how its schema is applied and how both are verified;
the service's endpoints are documented as they land.

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

## Deployment

The chart `deployment/helm/token-store` (its README documents the values) applies the schema as a
`pre-install,pre-upgrade` hook Job running `migrate up` from the same image the service uses, in
the platform band of the umbrella chart's
[hook-weight scheme](umbrella-chart.md#the-hook-weight-scheme). A fresh environment gets the
schema on install; an upgrade of a current database changes nothing, which the lifecycle proof
below checks to the timestamp. The chart does not run PostgreSQL and
never carries its credential: the database is the zone's, and its connection URL reaches the Job
from a Secret of the release namespace, created before the install and named in
`database.existingSecret`. With `schema.dropOnUninstall`, off by default, a `pre-delete` Job
reverts every migration on `helm uninstall` and the schema is empty afterwards; without it the
database outlives the release. A `helm rollback` runs no schema hook: migrations only add, so an
older build runs against a newer schema and treats it as current.

## Verification

Two proofs, both run by `.github/workflows/token-store.yml` on every change to the store, its image,
its chart or the pinned images:

- **The runner and the queries against an ephemeral database.** `go test ./services/token-store/...`
  with `TOKEN_STORE_TEST_DATABASE_URL` set runs against a PostgreSQL from the pinned image: up on an
  empty database applies every migration, up again applies none and changes no record, down to zero
  leaves an empty schema, an edited migration is refused, concurrent runners serialise; then the
  store's queries above. Each test takes a database of its own and drops it. Without the variable
  the database tests skip, so the ordinary test job stays self-contained.
- **The chart's lifecycle on kind.** `scripts/verify-token-store/verify.sh` builds the image from
  the working tree, starts a kind cluster with a registry on its network and a PostgreSQL from the
  pinned image inside it, puts the connection URL in a Secret as a real deployment has it, and
  installs, upgrades and uninstalls the chart: the install applies the
  schema to an empty database, the upgrade leaves `schema_migrations` identical to the timestamp,
  the uninstall with `schema.dropOnUninstall` leaves an empty schema, and the default uninstall
  keeps it. The records and the verdict are the run's artefact and go to the job summary; nothing
  is committed. Locally, the script writes to the git-ignored `.dev/token-store-evidence/`.

## What follows

The service itself: its configuration surface, liveness and readiness (readiness requires the
database reachable and the schema current, which `migrate status` already answers), the mesh
identity, the key custody against the key-value store, and the endpoints of the API, each building
on the tables and queries above.
