# FACIS ZTD Keycloak Helm chart

This chart replaces the realm-configuration Bash script. Install and update it with
Helm. All delivered files are Helm templates, YAML/JSON configuration and documentation;
there are no shell, Python or JavaScript programs and no shell commands embedded in Jobs.
The post-install/post-upgrade Job runs the standard adorsys keycloak-config-cli image
through its normal container entrypoint.

The identity contract is defined in `docs/identity-model.md` and `docs/keycloak.md`.
This chart supplies realm configuration and deployment support for the demonstrator.

## Install on the existing IONOS cluster

The existing Deployment `keycloak`, StatefulSet `postgres`, Services `keycloak` and
`postgres`, Ingress `keycloak`, runtime Secret `keycloak-secrets` and the database
PVCs are already in namespace `keycloak`. This chart can take those resources into
Helm while retaining their specs, image references, credentials and volume bindings.

Use Helm 3.17+ or Helm 4, the existing IONOS kubeconfig and the credentials JSON file
already created on your computer. Keep that file outside Git. Check the current
context before adopting resources:

```bash
kubectl config current-context
```

Run from the repository root using the chart source:

```bash
helm upgrade --install ztd-identity ./deployment/helm/facis-ztd-keycloak \
  --namespace keycloak \
  --take-ownership \
  --set deployment.mode=adopt \
  --set-file personas.credentialsJSON="$HOME/.config/facis-ztd/keycloak-credentials.json" \
  --wait --timeout 20m
```

Helm performs all deployment work. There is no setup script or `kubectl apply`
step. The credential file's persona passwords are imported, preserving the four
accounts set up earlier; the apply Job reads the existing admin password directly
from `keycloak-secrets`. Both the realm and client are enabled by default.

The ownership migration uses Helm `lookup` to preserve the live objects and refuses
resources annotated as belonging to another Helm release. A local
`helm template`/client dry-run cannot discover those objects and intentionally fails
in `adopt` mode. To inspect the real migration, use `helm upgrade --install` with
`--dry-run=server --hide-secret` and the same flags. A dry-run can still contain private
values in rendered output; keep its output private.

Continue using `deployment.mode=adopt` for this release. It deliberately keeps live
workload specs, including immutable StatefulSet/PVC fields. Do not switch this
release to `new` mode. Optional nonempty `keycloak.image` and `postgresql.image`
replace the first container image in the existing workloads on subsequent upgrades.
The default pins stock Keycloak 26.7.4; set `keycloak.image=""` explicitly if the
initial migration must preserve the exact current server image. PostgreSQL remains
empty by default and preserves its current image. Other workload changes in adopt mode
must be made in the retained live spec or by extending the adoption template.

## What is managed

| Object | Result |
|---|---|
| Realm | `facis-ztd`, enabled |
| UI client | `ztd-ui`, public, enabled; authorization code + PKCE S256 |
| Disabled grants | Implicit, direct access/password, service account, device, CIBA |
| Roles | `ztd-operator`, `ztd-observer` |
| Personas | `demo-operator`, `demo-observer`, `bdd-operator`, `bdd-observer`; one ZTD role each |
| Claims | Subject (`sub`), authentication time (`auth_time`), username, realm roles and UI audience |
| Scopes | `openid` protocol scope; `basic`, `profile` and `roles` default client scopes; no optional scopes |
| Lifetimes | Access 300 seconds; SSO/client idle 1800 seconds; maximum 28800 seconds |
| Refresh | Native rotation enabled, max reuse zero; replay/session behavior needs live acceptance testing |
| Logout | Exact front-channel, back-channel and post-logout URLs |
| Service access | ORCE lifecycle Basic authentication and connector/guard contracts unchanged |

The realm configuration is a secret-free ConfigMap. Runtime password substitution
uses JSON-encoded Secret keys, so quotes, newlines and other special characters remain
valid and are preserved. Nested substitution is disabled, preventing password content
from being interpreted as another substitution expression. The CLI's remote state is
encrypted using a retained Secret, HTTP debug logging is disabled, and the apply Job
has no Kubernetes API token or RBAC permissions.

Configuration is reconciled on every Helm install/upgrade. The apply Job is retained
for inspection and replaced on the next upgrade. The CLI manages the objects declared
here; deletion of clients, roles, client scopes and required actions is disabled to
preserve other existing objects in the realm. Unrelated users are not declared and
remain present. Direct grants/groups on the four managed personas are reconciled.
External composite role grants must still be checked during live role acceptance.

## ORCE integration contract

Default issuer:
`https://keycloak.85.215.131.155.sslip.io/realms/facis-ztd`

Default UI origin: `https://orce.85-215-131-155.sslip.io`.

| Purpose | Exact path under the UI origin |
|---|---|
| Callback | `/dev/ztd/oidc/callback` |
| Front-channel logout | `/dev/ztd/oidc/frontchannel-logout` |
| Back-channel logout | `/dev/ztd/oidc/backchannel-logout` |
| After logout | `/dev/facis-demo/` |

These are the routes requested in the updated contract on 10 October 2026. The demonstrator flows implement these handlers separately. The chart configures Keycloak to use them and publishes the
connection settings in ConfigMap `ztd-identity-keycloak-connection`; it does not
implement ORCE's UI handlers or change its editor authentication. The ORCE
integration must validate token signature, issuer, audience and expiry, enforce roles,
and implement the front/back-channel logout handlers. The back-channel handler must
validate the signed logout token rather than trusting an arbitrary incoming request.
The HTTP lifecycle API's current Basic contract must remain intact.

Override any exact URL using the `ui.*Url` values. All callback/logout URLs must be
under the same UI origin; wildcard redirects are rejected.

If release `ztd-identity` is already installed, update it without replacing existing
deployment or credential settings. The explicit URL values file overrides any prior
URL overrides retained in the release:

```bash
helm upgrade ztd-identity ./deployment/helm/facis-ztd-keycloak \
  --namespace keycloak --reuse-values \
  -f ./deployment/helm/facis-ztd-keycloak/examples/dev-contract.yaml \
  --wait --timeout 20m
```

The connection ConfigMap and realm configuration are rendered from the chart source.
Use the chart for deployment; private Secret references supply the persona passwords.
No credential values are included in this contribution.

## Update 0.1.2: basic default client scope

The `basic` OIDC client scope is declared with Keycloak's standard `sub` and
`auth_time` protocol mappers and assigned to `ztd-ui` as a **Default** client scope.
It applies automatically without adding `basic` to ORCE's requested
`openid profile roles` scope string. Its `include.in.token.scope` attribute is
`false`, matching Keycloak's built-in scope.

The chart realm template includes this setting.
The existing connection URLs, PKCE settings, role grants and credential handling
remain unchanged. Apply the update to an installed release with:

```bash
helm upgrade ztd-identity ./deployment/helm/facis-ztd-keycloak \
  --namespace keycloak --reuse-values \
  --wait --timeout 20m
```

In Keycloak, check Clients > ztd-ui > Client scopes: `basic` must show **Default**.
Then sign in again and inspect the newly issued access token for `sub` and
`auth_time`; existing tokens are not rewritten. Package validation covers Helm lint and
rendering of the realm configuration. The live import and
new token claims must be verified on the cluster.

References:
- https://www.keycloak.org/docs/26.1.5/upgrading/#new-default-client-scope-basic
- https://github.com/adorsys/keycloak-config-cli/issues/1073

## Other deployment modes

`deployment.mode=existing` is the default: manage only identity, using a running
Keycloak. It does not take ownership of workloads. This is useful where another Helm
release already owns the server/database.

`deployment.mode=new` creates stock Keycloak, PostgreSQL with persistent storage, a
Service and TLS Ingress. It generates bootstrap/database passwords once and preserves
them on upgrades with `lookup`. Supply approved image references and the correct
StorageClass. No image for a new server is guessed:

```bash
helm upgrade --install ztd-identity ./deployment/helm/facis-ztd-keycloak \
  --namespace keycloak --create-namespace \
  --set deployment.mode=new \
  --set keycloak.publicUrl=https://keycloak.example.org \
  --set ui.origin=https://orce.example.org \
  --set keycloak.image=quay.io/keycloak/keycloak@sha256:YOUR_APPROVED_DIGEST \
  --set postgresql.image=docker.io/library/postgres@sha256:YOUR_APPROVED_DIGEST \
  --set postgresql.storageClass=YOUR_STORAGE_CLASS \
  --wait --timeout 20m
```

The ingress controller, default `ztd-public` IngressClass and, unless using an existing
TLS Secret, ready `ztd-public-acme` ClusterIssuer must already exist. DNS must resolve
to that controller. This chart creates no shared controller, mesh or admission policy.
Fresh mode is a one-replica demonstration deployment, with a persistent PostgreSQL
database; it is not an HA database design. Choose a stock Keycloak version compatible
with the config-cli image and a Debian PostgreSQL 16/17 image using UID/GID 999.

The server image is stock `quay.io/keycloak/keycloak:26.7.4`, pinned by digest.
The separate import Job uses `adorsys/keycloak-config-cli:6.5.1-26`, also pinned by
digest. The `-26` suffix selects its Keycloak 26 build; `-21` targets Keycloak 21.
The server image cannot replace the config CLI in this Job. Both references were
verified in their registries on 12 October 2026. Image availability is not proof
of a successful import against the deployed server: verify that on the target
environment. Project admission/signing approval remains a separate release check.

## Credentials and OpenBao

The default configuration uses Kubernetes Secrets. The identity contract specifies
OpenBao injection; retain this as an interim deviation until that integration is verified.

- `personas.credentialsJSON`: import the existing local JSON once (or on updates).
  This input, including its unused admin section, is retained in Helm release metadata.
  Restrict access to Helm release Secrets and keep the file and dry-run output private.
- `personas.existingSecret`: use an externally provisioned Secret in this namespace.
  It must contain `demo-operator-json`, `demo-observer-json`, `bdd-operator-json` and
  `bdd-observer-json`, each containing a complete JSON string literal, including the
  surrounding quotes and appropriate escaping. No locally generated persona Secret
  is created in this mode.
- With neither source, the chart generates passwords on first install. Later upgrades
  read and preserve them from the existing generated Secret. For the current realm,
  import the existing file to avoid changing the previously assigned passwords.

Generated persona Secrets contain both raw `<persona>` and JSON `<persona>-json`
keys. Bootstrap/runtime, persona, remote-state Secrets and adopted PVCs have the
`helm.sh/resource-policy: keep` annotation. Helm uninstall removes the managed
workloads and realm ConfigMaps, but retains those Secrets and PVCs and does not delete
the Keycloak realm. A fresh StatefulSet's generated PVC is retained by Kubernetes'
default StatefulSet PVC retention policy.

Once OpenBao and External Secrets Operator are ready, configure a SecretStore using
KV v2 mount `secret`, then use `examples/openbao.yaml`. Paths
are `keycloak/admin` and `keycloak/personas/<persona>`; the store converts them to
`secret/data/...` API paths. Each persona contains `password`; admin contains
`username` and `password`. Populate OpenBao with the existing values before switching.
Use `--reset-values` when switching sources and explicitly restate `deployment.mode`
and any customized settings so a prior `personas.credentialsJSON` is not retained:

```bash
helm upgrade ztd-identity ./deployment/helm/facis-ztd-keycloak \
  --namespace keycloak --reset-values \
  --set deployment.mode=adopt \
  -f ./deployment/helm/facis-ztd-keycloak/examples/openbao.yaml \
  --wait --timeout 20m
```

ExternalSecret refresh updates Kubernetes Secrets; the apply Job runs on Helm upgrades,
not on every external rotation. After rotating source passwords, run `helm upgrade`
again to reconcile them into Keycloak. OpenBao admin credentials must match the live
Keycloak master-realm account; importing a new value does not rotate that account.

## Inspect and validate

```bash
helm status ztd-identity -n keycloak
kubectl -n keycloak logs job/ztd-identity-keycloak-apply
kubectl -n keycloak get configmap ztd-identity-keycloak-connection -o yaml
```

Local checks cover Helm lint, rendered manifests, realm contract and
missing-image/invalid-URL rejection. Offline adoption correctly refuses to proceed
without live objects; no live ownership migration has been tested. Live image pull, config-cli import and ORCE acceptance must be
verified on the cluster. Browser acceptance still includes both demo logins, operator
versus observer actions, expired/denied UI states, refresh replay and logout at both ends.

## Primary implementation references

- https://github.com/adorsys/keycloak-config-cli/blob/v6.5.1/README.md
- https://github.com/adorsys/keycloak-config-cli/blob/v6.5.1/docs/MANAGED.md
- https://github.com/adorsys/keycloak-config-cli/releases/tag/v6.5.1
- https://www.keycloak.org/server/containers
- https://www.keycloak.org/server/hostname
- https://external-secrets.io/main/guides/templating/

