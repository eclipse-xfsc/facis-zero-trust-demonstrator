# ORCE — interim minimal install

Plain manifests for running the first-party ORCE image (`deployment/docker/orce`) in a cluster,
used on IONOS until the ORCE Helm chart replaces them. They carry no secret and no
cluster-specific value; the steps and their checks are in
[docs/environments/ionos.md](../../docs/environments/ionos.md#3-orce).

| File | Contents |
|---|---|
| `base.yaml` | the management namespace `ztd-orce`; ServiceAccounts `orce` (the identity ORCE deploys with) and `ztd-bdd-observer` (the acceptance runner's read-only identity); a Role letting the observer read ORCE's pods and log, nothing else in this namespace |
| `orce.yaml` | the ORCE `Deployment` (one replica, non-root, all capabilities dropped, RuntimeDefault seccomp, no ingress), its `Service` on port 1880, and a `NetworkPolicy` admitting only pods of `ztd-orce` |

`orce.yaml` expects:

- `__IMAGE__` replaced by the ORCE image **by digest**;
- a Secret `orce-credentials` in `ztd-orce` with `ORCE_ADMIN_USER`, `ORCE_ADMIN_PASSWORD_HASH`,
  `ORCE_HTTP_USER`, `ORCE_HTTP_PASSWORD_HASH` (bcrypt) and `ORCE_READ_TOKEN`. ORCE refuses to
  start when one is missing.

ORCE deploys with its own ServiceAccount; the BDD pool chart binds it as the deployer of the pool
namespaces ([bdd-pool](../helm/bdd-pool/README.md)). There is no ingress and no TLS endpoint yet:
ORCE is reached with `kubectl port-forward` by an administrator. Exposing it over TLS 1.3 to the
pipeline comes with the ORCE chart.
