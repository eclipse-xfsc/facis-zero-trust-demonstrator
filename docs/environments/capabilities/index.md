# Capability sheets

What each cluster actually provides, measured by `scripts/baseline/capabilities.sh` rather than written
down: Kubernetes version, nodes, CNI, whether NetworkPolicy is enforced, storage, LoadBalancer and
ingress classes. Each capability is **measured**, **unsupported** (affirmative evidence only),
**forbidden** (the identity may not look) or **unknown** (inconclusive, with the reason).

```bash
scripts/baseline/capabilities.sh <kubeconfig>              # cluster rights: works in its own namespace
scripts/baseline/capabilities.sh <kubeconfig> <namespace>  # namespace-scoped: only its labelled resources
```

The NetworkPolicy check proves connectivity first, applies a deny policy and proves the path closed,
then removes it and proves the path open again; a result that cannot separate enforcement from other
policies in the namespace is reported as unknown.

| Sheet | Cluster | Identity | Status |
|---|---|---|---|
| [IONOS](ionos.md) | IONOS, CI/CD and visualization | cluster rights | measured 8 October 2026 |
| [OSC shared namespace](osc-shared-namespace.md) | interim namespace on a shared OSC cluster | namespace-scoped | measured 8 October 2026 |
| [Local zone](local-zone.md) | kind zone of the local two-zone setup | cluster rights | measured 8 October 2026 |
| OSC zone A, OSC zone B | the two target zone clusters | — | not provided yet |

Reachability from CI is **unverified**: these runs were made from a workstation. The OSC zone clusters
are not provided, so their sheets, and their reachability from CI, are open.

## For the mesh decision

What the sheets support for the service mesh mode (ADR-0001, and the proposed ADR-0009):

- **IONOS** runs Calico with NetworkPolicy enforced, on a single node; it runs no mesh, so it says
  nothing about Cilium chaining or SPIRE under the mesh.
- **The local zone** runs Cilium with `cni.exclusive=false` and enforces NetworkPolicy; it is where the
  mesh mode can be exercised before the zones exist, and is not target evidence.
- **The OSC shared namespace** cannot show the CNI or the nodes to its identity, and its own policies
  make enforcement unknown; it cannot inform the mesh decision.
- **Unknown until the zone clusters exist:** the CNI and its configuration on the targets, kernel and
  node prerequisites for the mesh, and LoadBalancer behaviour there.
