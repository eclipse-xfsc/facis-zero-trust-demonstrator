# Connector

Standalone deployment of `services/connector`, following the token-store chart. It publishes a
private ClusterIP API on port 8080: `POST /oauth2/register`, `POST /oauth2/challenge`,
`POST /oauth2/token`, and `GET /.well-known/jwks.json`. Port 9090 serves pod readiness/liveness
and is not published by the Service. The application also has API health routes; do not expose
this Service publicly to serve the Participant demo.

Before installation, provision the issuer PostgreSQL schema using the token-store migration image,
and provide the database URL as an existing Secret. Connector stores OAuth clients, challenges,
nonces and replay records in PostgreSQL directly; it has no token-store HTTP address flag.
The guard calls the token store, whose acquisition routes point to this Connector. Do not introduce
an unused Connector-to-store chart value or conflate the issuer and requester ledgers.

Required references: image digest, database Secret, credential Secret, OpenBao transit key name and
version, issuer and registration URLs, registrar audience ceiling, and the public verification
ConfigMap. The credential Secret has OpenBao token, access-token HMAC, registration HMAC and
registrar-secret keys; the three HMAC/client secrets must be at least 32 bytes. Values carry names
only. The mounted Secret volume can rotate the OpenBao token; keys are not exported from transit.
Public IF-03 JWKs and scope mapping JSON use the format read by `services/connector/vpconfig.go`.
The fixture verifier's private key belongs to the caller, not this ConfigMap or chart.

Set explicit `networkPolicy.ingressFrom` and dependency `egress` rules. Defaults allow DNS only,
so PostgreSQL/OpenBao/control-plane connectivity will fail closed until lanes are provided. Other
NetworkPolicies are additive; inspect the namespace's full policy set. A meshed namespace requires
the platform's injection/registration labels, STRICT mTLS and reachable Istiod/SPIRE. `podAnnotations`
supports per-pod image overrides; every injected image must satisfy the existing admission policy.
The chart does not install the mesh, admission policy, database, OpenBao, TLS edge or namespace.

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
