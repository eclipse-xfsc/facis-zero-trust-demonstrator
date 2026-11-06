# token-store

The zone's token store ([services/token-store](../../../services/token-store)). The chart carries
the authorization database's schema, applied by a hook Job before every install and upgrade so a
fresh environment gets it automatically and an upgrade of a current database changes nothing, and
the service: a Deployment with its own ServiceAccount and identity label, a Service on its API
port, and liveness and readiness probes, where readiness is green only while PostgreSQL is
reachable with the schema current and the key-value store is initialised and unsealed. The
service's endpoints land on top of it; the design is in
[docs/token-store.md](../../../docs/token-store.md).

Install into the zone's management plane after the umbrella chart, with the PostgreSQL the store
owns reachable, its connection URL in a Secret of the release namespace, and the key-value store
answering at `openbao.address`. The default address is the umbrella chart's OpenBao under the
release name `ztd`, which the umbrella ships **disabled** (`openbao.enabled: false`): enable it
there, or point `openbao.address` at the zone's OpenBao, or the service never becomes ready and
`--wait` times out with `/readyz` saying `openbao: unreachable`. The chart never carries the
database credential: the Secret exists before the install and the Jobs and the service read it.

```bash
kubectl -n ztd-mgmt create secret generic token-store-database \
  --from-literal=url='postgres://token_store:...@postgres.ztd-mgmt:5432/tokenstore'
helm upgrade --install token-store deployment/helm/token-store -n ztd-mgmt \
  --set image.digest=sha256:... \
  --set database.existingSecret=token-store-database \
  --wait --wait-for-jobs
```

`--wait` returns once the schema Job has succeeded and the service's pod is Ready, that is, once
both dependencies answered.

## Values

| Key | Default | Meaning |
|---|---|---|
| `image.repository` | the project's `token-store` image | Image of the service and the migration Jobs |
| `image.digest` | none, required | `sha256:` digest; the chart refuses a tag |
| `database.existingSecret` | none, required | Secret in the release namespace holding the connection URL under `database.secretKey` |
| `database.secretKey` | `url` | Key of the connection URL in that Secret |
| `openbao.address` | `http://ztd-openbao.ztd-mgmt.svc:8200` | The key-value store's base URL, `http(s)://host[:port]` without a path; the chart refuses anything else |
| `replicas` | `1` | Pods of the service |
| `server.readinessTimeoutSeconds` | `2` | Budget of one `/readyz` evaluation; the probe's `timeoutSeconds` is this plus one |
| `server.drainDelaySeconds` | `5` | On SIGTERM, how long `/readyz` answers 503 while the listeners stay open, so routing leaves the pod before it stops answering |
| `server.shutdownTimeoutSeconds` | `10` | Drain of the listeners after that delay; `terminationGracePeriodSeconds` is the drain delay plus this plus the readiness budget plus five |
| `server.logLevel` | `info` | `debug`, `info`, `warn` or `error` |
| `serviceAccount.name` | `ztd-token-store` | The ServiceAccount the service runs as, always; the last segment of the store's SPIFFE ID |
| `serviceAccount.schemaName` | `ztd-token-store-schema` | The ServiceAccount the migration Jobs run as: the schema's identity, distinct from the service's |
| `serviceAccount.create` | `true` | Create both ServiceAccounts; off, they are managed outside the chart and must exist |
| `identity.spireManagedIdentity` | `true` | Set the pod label `spiffe.io/spire-managed-identity: "true"` the SPIRE registration selects |
| `schema.dropOnUninstall` | `false` | Run `migrate down --to 0` on `helm uninstall`, leaving an empty schema; on in `ci/values.yaml` |
| `schema.hookWeight` | `41` | Hook weight of the Jobs, inside the umbrella chart's platform band (40 to 59) |
| `schema.timeout` | `2m` | Deadline of one migration run, lock wait included |
| `schema.backoffLimit` | `2` | Retries of a failed Job pod |
| `resources` | small | Requests and limits of the service's container and the Job's |

## How the service behaves

- **Startup.** The pod starts whether or not PostgreSQL and the key-value store are there: the
  service binds its listeners and reports not ready until both answer. Nothing waits in a loop,
  and no URL is logged.
- **Readiness.** The kubelet probes `/readyz` on the ops port every five seconds. The service
  asks both dependencies at once within `server.readinessTimeoutSeconds` and answers 200 only
  when PostgreSQL is reachable with the schema current and the key-value store is initialised and
  unsealed; otherwise 503 with the words of each check (`ok`, `unreachable`, `schema_behind`,
  `schema_drift`; `ok`, `unreachable`, `uninitialized`, `sealed`). Callers that arrive while an
  evaluation runs share it, so a burst of `/readyz` on the API port costs one connection and one
  key-value store call, not one each. A pod that is not ready leaves the Service's endpoints and
  rejoins them when the dependency is back.
- **Liveness.** `/healthz` answers 200 while the process serves and consults nothing, so a
  dependency outage never restarts the pod.
- **Stop.** On SIGTERM `/readyz` answers 503 with `"draining": true` at once, without asking
  the dependencies, so the pod leaves the Service's endpoints, while both listeners keep
  answering for `server.drainDelaySeconds`; then the service drains both at once within
  `server.shutdownTimeoutSeconds` and exits 0.
- **Records.** JSON on stdout, one object per line, every one naming the service and the pod;
  every record of a request carries its `correlation_id`, and its `trace_id` and `span_id` when
  the caller sent a trace context. The database credential is never among them.

## Identity

The service's pod runs as the ServiceAccount `serviceAccount.name`, `ztd-token-store` by
default, in the management plane, with the label `spiffe.io/spire-managed-identity: "true"`:
under both mesh modes its SPIFFE ID is `spiffe://<trust domain>/ns/<namespace>/sa/ztd-token-store`.
The migration Jobs run as a second account, `serviceAccount.schemaName`
(`ztd-token-store-schema`), with the same label: the runner holds the schema's DDL and the
service never does, so an allow-list in front of PostgreSQL can tell them apart. That account is
a `pre-install,pre-upgrade` hook one weight below the Jobs, because Helm creates hooks before the
release's own resources and the Jobs must find it; like the Secret, it stays when the release is
uninstalled. The mesh terminates mTLS for both, as for every zone workload: the listeners are
plain HTTP inside the pod, no ServiceAccount token is mounted (the SVID comes from the SPIFFE CSI
driver), and the pods carry no sidecar annotation and exclude no port. The label is harmless on a
cluster without SPIRE, as the lifecycle proof's kind cluster is, and required on one with it.

## How the hooks behave

- **Install and upgrade.** A `pre-install,pre-upgrade` Job runs `token-store migrate up` before
  the service's resources are created or updated, as the schema's own ServiceAccount, itself a
  hook one weight below. The migrations are embedded in the image, so the schema applied is the
  one the deployed build expects. Concurrent runs take an advisory lock in turn; a database
  already at the embedded version is left as it is. A failing Job fails the release and stays for
  inspection; a succeeded Job is removed.
- **Rollback.** `helm rollback` runs no schema hook: migrations only add, so an older build runs
  against a newer schema, and its `migrate up`, `migrate status` and readiness treat that database
  as current. Reverting a migration is an operator's `migrate down` with the build that applied
  it; an older build refuses to revert what it does not know.
- **Uninstall.** With `schema.dropOnUninstall`, a `pre-delete` Job runs `migrate down --to 0`
  and the schema is empty afterwards, `schema_migrations` included. Off by default. The Secret
  with the connection URL is not the chart's and stays.

## Verify

Without a cluster, the migration runner, the store's queries and the service's readiness against
a database run against any PostgreSQL; the key-value store is faked in the tests:

```bash
TOKEN_STORE_TEST_DATABASE_URL='postgres://postgres:secret@127.0.0.1:5432/postgres?sslmode=disable' \
  go test -count=1 -race ./services/token-store/...
```

The chart's lifecycle and the service's readiness are proven on a throwaway kind cluster by
`scripts/verify-token-store/verify.sh`: install on an empty database with the service coming up
ready, not ready and still alive while PostgreSQL and then the key-value store are gone, ready
again when they are back, the caller's `x-request-id` and trace context on the service's records,
the pod running as its own ServiceAccount with the identity label, an upgrade as a no-op and an
uninstall to an empty schema. The `Token store` workflow runs it on every change to the store, the
chart or the pinned images.
