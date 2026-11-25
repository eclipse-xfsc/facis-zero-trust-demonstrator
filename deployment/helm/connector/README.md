# Connector

Standalone deployment of `services/connector`, following the token-store chart. It publishes a
private ClusterIP API on port 8080: `POST /oauth2/register`, `POST /oauth2/challenge`,
`POST /oauth2/token`, and `GET /.well-known/jwks.json`. Port 9090 serves pod readiness/liveness
and is not published by the Service. The application also has API health routes; do not expose
this Service publicly to serve the Participant demo.

Provide the database URL as an existing Secret. The issuer PostgreSQL schema is applied by the
chart when `schema.enabled` is set ([Schema](#schema)), and otherwise by the token-store chart where
the two share a database. Connector stores OAuth clients, challenges,
nonces and replay records in PostgreSQL directly; it has no token-store HTTP address flag.
The guard calls the token store, whose acquisition routes point to this Connector. Do not introduce
an unused Connector-to-store chart value or conflate the issuer and requester ledgers.

Required references: the zone (`zone`), image digest, database Secret, credential Secret, OpenBao transit key name and
version, issuer and registration URLs, registrar audience ceiling, and the public verification
ConfigMap. The credential Secret has OpenBao token, access-token HMAC, registration HMAC and
registrar-secret keys; the three HMAC/client secrets must be at least 32 bytes. Values carry names
only. The mounted Secret volume can rotate the OpenBao token; keys are not exported from transit.
With `openbao.auth.method: kubernetes` and `openbao.auth.role` the Connector holds no OpenBao token:
it logs in with a projected service-account token for `openbao.auth.audience` and logs in again
before each OpenBao token expires, and the Secret's OpenBao token key is not mounted
([Secrets: Kubernetes auth](../../../docs/secrets.md#kubernetes-auth)).
Public IF-03 JWKs and scope mapping JSON use the format read by `services/connector/vpconfig.go`.
The fixture verifier's private key belongs to the caller, not this ConfigMap or chart.

Set explicit `networkPolicy.ingressFrom` and dependency `egress` rules. Defaults allow DNS only,
so PostgreSQL/OpenBao/control-plane connectivity will fail closed until lanes are provided. Other
NetworkPolicies are additive; inspect the namespace's full policy set. A meshed namespace requires
the platform's injection/registration labels, STRICT mTLS and reachable Istiod/SPIRE. `podAnnotations`
supports per-pod image overrides; every injected image must satisfy the existing admission policy.
The chart does not install the mesh, admission policy, database, OpenBao, TLS edge or namespace.

The mesh callers are declared with `trustDomain` and `callers`, by namespace and service account:
`callers.oauth` may use `/oauth2/*` and the key set (the Participant, the token store),
`callers.keySet` only `GET /.well-known/jwks.json` (the guard, the protected resource, which only
verify tokens). They render the AuthorizationPolicy `ztd-connector-callers` on port 8080; with both
lists empty none renders and the mesh default deny refuses every caller.

The chart is standalone because token-store and application-service are standalone. Do not upgrade
the zone's umbrella to deploy it. `ci/values.yaml` contains render-only references and a zero digest;
it is not a live deployment file. Update the deployment when public verification configuration
changes; the process reads those files at startup.

```bash
helm lint deployment/helm/connector -f deployment/helm/connector/ci/values.yaml
helm template ztd-connector deployment/helm/connector -n <namespace> \
  -f deployment/helm/connector/ci/values.yaml >/dev/null
scripts/ci/check-charts.sh deployment/helm/connector
```

For a reviewed live values file and explicit cluster context, uninstall the standalone release with
`helm uninstall ztd-connector -n <namespace> --kubeconfig "$KUBECONFIG"`. It retains externally provided
Secrets, ConfigMap, database and transit key. The complete slice's teardown additionally removes
only resources owned by its deployment inventory.

## Schema

The connector's database carries the token store's schema ([Token store: one database, two
owners](../../../docs/token-store.md#one-database-two-owners)), whose migrations are embedded in the
token-store image and in no other. With `schema.enabled: true` the chart applies them itself: a
`pre-install,pre-upgrade` hook Job, `ztd-connector-migrate`, runs `token-store migrate up` from
`schema.image` (by digest only) against the database Secret, before the connector is created or
updated, so a new connector never meets a database behind the version it expects (`/readyz`:
`postgres: schema_behind`). A database that is current is left as it is. Set `schema.image.digest`
to a token-store build whose migrations reach that version: the build released with the connector.

The Job runs as its own ServiceAccount, `schema.serviceAccountName` (created as a hook with
`serviceAccount.create`; it replaces an account of that name made by hand), under its own
egress-only NetworkPolicy `ztd-connector-schema`: DNS and `schema.egress`, which must carry the
database lane, and istiod's where the namespace is meshed. Its pods are named
`app.kubernetes.io/name: ztd-connector-schema`, so no selector of the connector takes them, and are
marked as native-sidecar pods so that a meshed Job completes. A meshed database must admit that
account (the token-store chart's `database.mesh.callers`, or the zone's own rule), and SPIRE must
register it as it registers the connector's.

`helm rollback` runs no hook and reverts no migration: a database ahead of an older connector is
current for it. The chart never drops the schema; the database outlives the release. Leave
`schema.enabled` off where the token-store chart migrates the same database.

## Guarded client provisioning

For the guarded path, configure `oauth.exclusiveAudiences` with the guard and
Resource audiences. Use separate operator-only registrar identities: each may
name its role's audience plus the registration endpoint. Register Participants
only for the guard audience and token-store clients only for the Resource
audience. Neither workload receives registrar credentials or registration scope.
The Connector refuses dual-role registration and issuance in code.

The Connector enforces the registration token's audience ceiling and the stored
client audience at challenge and grant time, including verified-presentation
renewal. Changing the audience in a Participant request cannot obtain a Resource
token. Existing broad workload registrations must be retired and replaced before
activating the guarded path; changing chart values does not narrow database rows.
The bootstrap refuses to overwrite a registrar with conflicting settings.

### Exclusive audiences for guarded access

Set `CONNECTOR_EXCLUSIVE_AUDIENCES` (chart `oauth.exclusiveAudiences`) to the guard's inbound audience and the Resource's upstream audience. `Config.ExclusiveAudiences` is an additive provider contract field. A client may hold at most one member of this set. Registration returns `invalid_client_metadata` for a dual-role request, even with a registrar token authorizing both. Both grant handlers return `invalid_request` for existing clients holding both; the migration flag never relaxes issuance.

The Participant requests only the guard's `inbound_audience`. The store requests only its route's upstream audience, equal to both the guard's `upstream_audience` and `PROTECTED_RESOURCE_AUDIENCE`. The audiences must differ. Provision separate registrar identities for each role; the bootstrap registrar in the guarded example provisions Participants. `/readyz` reports conflicting client IDs and count, and fails until their registrations are repaired. `CONNECTOR_ALLOW_AUDIENCE_MIGRATION=true` (chart `oauth.allowAudienceMigration`) explicitly downgrades this readiness failure to `migration_warning`; use only during a controlled migration. The report and warning contain no credentials.

## Zone and security-state events

`zone` names the zone the connector serves, `a` or `b`. It is the source `connector-<zone>` of the
IF-01 security-state events the connector writes on stdout, one per registration decision; the
chart refuses any other value.

## Registration policy and audit

`POST /oauth2/register` sits behind the connector's own policy gate: a request whose token the
connector's store does not know goes to the library unjudged; for a known token the metadata must
be one strict JSON object with only the contract's members, a `client_name`, a `client_secret_basic`
client, `dpop_bound_access_tokens: true`, offered grant types, scope tokens never naming the
registration scope, and one or more absolute audiences. A violation is refused with 400
`invalid_client_metadata`, reason `registration_rejected`. Every decision writes an `audit_event`
row and one IF-01 `token_event` line. The rules are in
[docs/connector.md](../../../docs/connector.md#registration).

## Registering a client

The same image registers a client the way a participant obtains its credentials: a Pod or Job
running `connector register` with the registrar's secret mounted from the credentials Secret (key
`registrar-secret`) writes the strict `{"client_id","client_secret"}` file the participant reads as
`PARTICIPANT_CREDENTIALS_FILE`.

```bash
connector register --connector http://ztd-connector.ztd-mgmt.svc:8080 \
  --registrar-id ztd-registrar --registrar-secret-file /var/run/connector/credentials/registrar-secret \
  --client-name "participant backend" --scope resource.read --audience https://resource.example \
  --out /out/credentials.json --request-id my-registration
```

The registrar's token must carry the client's scopes and audiences, so `oauth.registrarScopes` and
`oauth.registrarAudiences` must cover them; a client for a verified-presentation scope needs
`--delegable-scopes` naming `oauth.registrarDelegableScopes`. A mounted Secret is owned by root: a
pod running the command as a non-root user needs `fsGroup` to read it, as the chart's own
Deployment sets. Flags and exit codes: [docs/connector.md](../../../docs/connector.md#registering-a-participant).
The proof `scripts/verify-connector/verify.sh` installs this chart on kind and runs the path end to end.
