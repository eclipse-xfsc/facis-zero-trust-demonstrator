# ORCE — namespace and identities

What the ORCE chart ([deployment/helm/orce](../helm/orce/README.md)) expects to exist before it is
installed, applied once by a cluster administrator. It carries no secret and no cluster-specific
value; the steps and their checks are in
[docs/environments/ionos.md](../../docs/environments/ionos.md#3-orce).

| File | Contents |
|---|---|
| `base.yaml` | the management namespace `ztd-orce`; ServiceAccounts `orce` (the identity ORCE deploys with) and `ztd-bdd-observer` (the acceptance runner's read-only identity); a Role letting the observer read ORCE's pods and log, nothing else in this namespace |

The interim `orce.yaml` manifest that ran ORCE itself is replaced by the chart, which keeps its
object names and its Deployment selector.
