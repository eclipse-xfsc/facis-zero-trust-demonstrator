# Deployment and teardown

How a zone is installed and removed, whichever cluster it is on. For the step-by-step setup of a
specific cluster, with the check that proves each stage, see [Environments](environments/index.md).

## Preconditions

- Kubernetes **1.29 or later** on each target cluster.
- A CNI that supports the mesh baseline recorded in
  [ADR-0009](adr/0009-service-mesh-mode-istio-sidecar-with-cilium.md): Cilium with
  `cni.exclusive=false`, Istio in sidecar mode chained behind it.
- Kubernetes **1.33 or later** on a cluster that runs the mesh, for the native sidecar containers
  that record decides on; 1.29 stays the floor for a cluster without the mesh.
- A container registry reachable from the clusters, with credentials available to the cluster.
- DNS delegation for the trust zone.

## Installing a zone

A zone installs as seven Helm releases, in a fixed order, from one zone file, with one command:

```bash
ZONE_VALUES=deployment/helm/ztd/zones/<zone>.yaml KUBE_CONTEXT=<context> \
  scripts/install-zone/install.sh install
```

| # | Release | Namespace | What it installs |
|---|---|---|---|
| 1 | `ztd` | `ztd-system` | the umbrella chart: the plane namespaces and the control-plane namespaces, default deny, declared openings, allow-matrix lanes, hook-weight bands |
| 2 | `spire-crds` | `spire-system` | the SPIRE controller-manager's CRDs (upstream chart) |
| 3 | `spire` | `spire-system` | SPIRE server, agents, CSI driver, controller-manager (upstream chart) |
| 4 | `istio-base` | `istio-system` | Istio's CRDs (upstream chart) |
| 5 | `istiod` | `istio-system` | the mesh control plane, sidecar mode, SPIRE as the certificate source (upstream chart) |
| 6 | `istio-cni` | `istio-system` | the Istio CNI plugin, chained behind Cilium (upstream chart) |
| 7 | `zone-policy` | `istio-system` | the workload registration, mesh-wide STRICT mTLS, the identity-band checks |

The umbrella lays the zone down first: the management and data planes as distinct namespaces,
default-deny network policies in both directions, the allow-matrix lanes between the planes, and
the hook-weight bands that order the jobs within each release; the installer orders the releases.
Every release runs through the deployment lifecycle step (`scripts/lifecycle.sh`), the same step the
ORCE workflow below runs, and the installer stops at the first release that fails and names it. A
second run changes nothing. That workload identity exists before any workload becomes ready is a
property of the identity path, not of an install order, as the
[hook-weight scheme](umbrella-chart.md#the-hook-weight-scheme) explains.

The upstream charts are installed as they ship, pinned by version, each owning, upgrading and
removing its own CRDs ([OSS dependencies](dependencies.md#identity-and-service-mesh)); the values
the repository sets on them live in `deployment/helm/values/`. The release namespace of the
umbrella holds its release and its hook jobs and is not a plane namespace. The zone file is written
from what the cluster baseline recorded; the charts have no defaults for it. The design, the
hook-weight scheme and the evidence are in [Umbrella chart](umbrella-chart.md) and
[Workload identity](workload-identity.md), and chart values are documented with each chart under
`deployment/helm/`.

### Through the ORCE workflow

The same install, redeploy and uninstall run through ORCE with zero manual steps: a
`POST /lifecycle` command ([IF-08](api-docs.md)) that the `ztd-lifecycle` node validates, checks
with a server-side dry-run and applies with Helm, reporting a machine-readable result in the ORCE
context. The `helm` commands on this page are the engine-level equivalent.

## Teardown

Components uninstall in the reverse order of their installation; the layout goes last:

```bash
ZONE_VALUES=deployment/helm/ztd/zones/<zone>.yaml KUBE_CONTEXT=<context> \
  scripts/install-zone/install.sh uninstall
```

Teardown must leave no orphaned namespaces, CRDs or secrets. Every CRD leaves with the release that
brought it; the installer removes the ones Istio's `base` chart marks to be kept by Helm. This is
verified by the mesh identity evidence and by an acceptance scenario rather than by inspection.

## Reproducibility

Every environment is reproducible from this repository plus its values files. No step is performed
by hand against a cluster; anything that cannot be expressed in a chart or a script belongs in
`scripts/`.
