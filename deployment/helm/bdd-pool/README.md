# bdd-pool

Namespaces and least-privilege identities for the cluster acceptance scenarios (TDR-BDD-01..04 and
TDR-BDD-06, see [docs/bdd.md](../../../docs/bdd.md)). It is installed next to ORCE by whoever
administers the cluster; that installer is the only actor that creates namespaces and bindings.
Neither identity below can.

## What it installs

| Object | Scope | Purpose |
|---|---|---|
| One `Namespace` per entry of `namespaces` | cluster | a dedicated namespace per acceptance row; runs are serialised per cluster, so a namespace is never shared by two runs |
| `Role`/`RoleBinding` `ztd-lifecycle-deployer` | each pool namespace | the identity ORCE deploys with: Deployments, Services, ConfigMaps and Secrets read-write; ReplicaSets, Pods, Events, Endpoints and EndpointSlices read-only |
| `Role`/`RoleBinding` `ztd-bdd-observer` | each pool namespace | the identity the acceptance runner observes with: `get`, `list`, `watch` on every resource, and nothing else |
| `ClusterRole`/`ClusterRoleBinding` `<identity>-<release>` | cluster | for both identities, read-only: the CRD list (the uninstall row asserts it is unchanged) and `get` on the named namespaces — the pool and `kube-system`, whose UID identifies the cluster |
| `ServiceAccount` per identity | release namespace | only when `create` is `true` |

The deployer cannot create namespaces, RBAC objects, CRDs or any cluster-scoped object, cannot
touch a namespace outside the pool, and cannot create Pods or StatefulSets directly. Every pool
namespace enforces the **restricted** Pod Security Standard, so a Deployment it creates cannot run a
privileged pod, mount a host path or join a host namespace. The observer
cannot write anything. The observer does read the Secrets of the pool namespaces, because the Helm
release records it checks are Secrets; nothing else is stored there.

## Values

| Value | Default | Meaning |
|---|---|---|
| `namespaces` | `ztd-bdd-tdr-001` … `004`, `ztd-bdd-tdr-006` | the pool: one namespace per cluster row, named after the row's Annex evidence path |
| `deployer.serviceAccount.create` | `true` | create the deployer ServiceAccount; set `false` and point `name`/`namespace` at ORCE's own ServiceAccount when ORCE is installed |
| `deployer.serviceAccount.name` | `ztd-lifecycle-deployer` | the ServiceAccount bound as deployer |
| `deployer.serviceAccount.namespace` | `""` (the release namespace) | its namespace |
| `observer.serviceAccount.create` | `true` | create the observer ServiceAccount |
| `observer.serviceAccount.name` | `ztd-bdd-observer` | the ServiceAccount bound as observer; its token is a CI secret |
| `observer.serviceAccount.namespace` | `""` (the release namespace) | its namespace |

## Install

```bash
helm upgrade --install bdd-pool deployment/helm/bdd-pool --namespace ztd-orce \
  --set deployer.serviceAccount.create=false --set deployer.serviceAccount.name=orce \
  --set observer.serviceAccount.create=false --wait
```

The example binds ORCE's ServiceAccount `orce` as deployer and an existing `ztd-bdd-observer`, as on
the IONOS cluster ([environments/ionos.md](../../../docs/environments/ionos.md)). A local kind
cluster installs it with the defaults (`scripts/dev/kind-up.sh`).

**Verify:** each pool namespace holds exactly the baseline the scenarios expect, and the identities
can do what the table says and no more:

```bash
kubectl get namespaces -l app.kubernetes.io/name=bdd-pool   # the pool namespaces
kubectl -n ztd-bdd-tdr-001 get serviceaccount,configmap,role,rolebinding
kubectl auth can-i create namespaces --as=system:serviceaccount:ztd-orce:orce           # no
kubectl auth can-i create deployments -n ztd-bdd-tdr-001 --as=system:serviceaccount:ztd-orce:orce  # yes
kubectl auth can-i create deployments -n default --as=system:serviceaccount:ztd-orce:orce          # no
kubectl auth can-i delete pods -n ztd-bdd-tdr-001 --as=system:serviceaccount:ztd-orce:ztd-bdd-observer  # no
```
