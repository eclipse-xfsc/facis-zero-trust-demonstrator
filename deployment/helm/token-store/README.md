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
  service binds its listeners and reports not ready until both answer. No URL is logged. In
  runtime mode it also resolves its signing keys before it is ready: the configured transit key
  exists (created if missing), its active `signing_key` row is registered or verified and every
  active row resolves; `/readyz` answers `starting` until then. An outage is retried with a growing
  pause and one record per change of reason; a misconfiguration (`missing`, `mismatch`,
  `malformed`, `retired`, `unsupported`, `refused`) stops the process with exit 1 and one
  `signing key misconfigured; stopping` record naming the key and the row, so a bad key is a crash
  loop at install time and not a failure at the first call
  ([key custody](../../../docs/token-store.md#key-custody)).
- **Readiness.** The kubelet probes `/readyz` on the ops port every five seconds. The service
  asks both dependencies at once within `server.readinessTimeoutSeconds` and answers 200 only
  when PostgreSQL is reachable with the schema current and the key-value store is initialised and
  unsealed; otherwise 503 with the words of each check (`ok`, `unreachable`, `schema_behind`,
  `schema_drift`; `ok`, `unreachable`, `uninitialized`, `sealed`; and for the signing keys `ok`,
  `unreachable`, `missing`, `mismatch`, `unconfigured`, `retired`, `refused`, `starting`,
  `shared_issuer_key`). Callers that arrive while an
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

Without a cluster, the migration runner, the store's queries, the service's readiness and the
key custody run against any PostgreSQL and an OpenBao in dev mode with transit mounted; without
the variables the tests that need them skip (CI fails on a skip):

```bash
TOKEN_STORE_TEST_DATABASE_URL='postgres://postgres:secret@127.0.0.1:5432/postgres?sslmode=disable' \
TRANSIT_TEST_ADDR=http://127.0.0.1:8200 TRANSIT_TEST_TOKEN=... \
  go test -count=1 -race ./services/token-store/...
```

The chart's lifecycle and the service's readiness are proven on a throwaway kind cluster by
`scripts/verify-token-store/verify.sh`: install on an empty database with the service coming up
ready, not ready and still alive while PostgreSQL and then the key-value store are gone, ready
again when they are back, the caller's `x-request-id` and trace context on the service's records,
the pod running as its own ServiceAccount with the identity label, an upgrade as a no-op and an
uninstall to an empty schema; then, in runtime mode with a least-privilege service token, the key
created in transit by `token-store keys ensure` and registered by reference and thumbprint only,
the thumbprint recomputed with openssl, export refused, `keys rotate` retiring the previous version
with transit no longer signing with it, and readiness failing closed with OpenBao gone while no key
material or token reaches the database or the records. The `Token store` workflow runs it on every
change to the store, the chart or the pinned images.

## Acquisition and renewal runtime

The default remains the schema/readiness service. Set `runtime.enabled: true` to run
acquisition, substitution and renewal. Supply an existing ConfigMap containing
`acquisition.json` and an existing Secret containing the OpenBao token and private
files referenced by that configuration. The chart never creates either object.
Public issuer keys can be included in the ConfigMap; use absolute paths below
`/etc/token-store`. Mount private route and signing files below
`/var/run/token-store/credentials`; do not put credentials in values or ConfigMaps.

Runtime mode requires SPIRE identity and NetworkPolicy. It renders STRICT
PeerAuthentication and enforces inbound `SANITIZE_SET` for XFCC, preserving other
JSON `proxy.istio.io/config` fields. This annotation is a prerequisite, not proof
of effective mesh configuration: verify the injected proxy and refuse forged XFCC
before live use. `runtime.replayCallers` lists allowed SPIFFE service accounts;
acquisition route callers remain in the acquisition configuration.

Configure explicit ingress peers and egress rules for PostgreSQL, OpenBao,
Connector and mesh control traffic. DNS allows both service port 53 and Gardener's
translated port 8053. Set `networkPolicy.schemaEgress` to the schema Jobs' database peers. A separate
egress-only NetworkPolicy hook is created one weight before migrate/drop Jobs;
it permits DNS and, in runtime mode, istiod TCP 15012 in
`networkPolicy.istiodNamespace`. It never inherits server or OpenBao lanes.
The schema policy is retained after uninstall for hook ordering, like the schema
ServiceAccount; remove both explicitly when retiring the owned namespace. `podAnnotations` and `nodeSelector` apply to the server and both schema
Jobs, including per-pod admitted sidecar image overrides.

`ci/runtime-values.yaml`, layered over `ci/values.yaml`, exercises runtime rendering
with placeholder references. It is not a deployable environment or an admission
proof. Roll back runtime wiring by restoring a proven release or removing the
slice; do not leave a token endpoint exposed while removing its identity controls.

**Key custody.** The store's signing key lives in transit and is referenced from PostgreSQL by
version and thumbprint. Before a runtime-mode install, register it with the operator's token:
`token-store keys ensure` (from the image, with the same flags as `acquire`); the service's own
token then needs only `read` on `transit/keys/<signing_key>`, `update` on
`transit/sign/<signing_key>` and its KV prefix. Without that step the service creates the key at
startup, which needs `update` on the key path. `token-store keys rotate` moves to the next version
and retires the previous one with its tokens in one transaction, then raises transit's signing
floor; `keys status` lists the versions, transit's latest and the floor. The two policies, the
startup rules and the repair of an interrupted rotation are in
[docs/token-store.md](../../../docs/token-store.md#key-custody). The chart runs none of these
commands.

Acquisition JSON accepts `kv_prefix` to isolate stored tokens and orphan sweeps.
An isolated deployment can use `example/token-store/upstream`; omission preserves the existing
`ztd/token-store/upstream` default. Prefixes contain only non-empty plain path
segments; slash escapes, traversal and query delimiters are rejected. The scoped
OpenBao policy must permit only the selected prefix.


The acquisition ConfigMap is mounted in full at `/etc/token-store`, including
public issuer key files referenced by `trusted_issuers[].public_key_file`.
`runtime.configKey` selects its acquisition JSON file. Keep private fixture keys
and client secrets in the credentials Secret, never this ConfigMap. Configure
`connector_signing_key` with the issuer's transit key name; the optional name check rejects equality with the store's `signing_key`.
Readiness independently compares the public key material against every route
Connector JWKS, and fails closed on overlap or unavailable keys. These roles need separate
non-exportable keys and separate scoped credentials.

Runtime schema Job pods request native Istio sidecars so the proxy does not hold
Job completion open. This rendering is tested; live Job completion under the
platform's injector still needs deployment evidence.

For a guarded deployment, register acquisition clients only for
`https://resource.facis.invalid` and set every acquisition/substitution route's
`audience` to that identifier. Participant clients use the separate
`https://guard.facis.invalid` audience. Use the guard's published base URL for
route target binding; do not derive the upstream audience from that URL. Never
mount the provisioning registrar's credentials into the store or Participant.
