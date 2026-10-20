# Deployment and teardown

How a zone is installed and removed, whichever cluster it is on. For the step-by-step setup of a
specific cluster, with the check that proves each stage, see [Environments](environments/index.md).

## Preconditions

- Kubernetes **1.29 or later** on each target cluster.
- A CNI that supports the mesh baseline recorded in
  [ADR-0001](adr/0001-service-mesh-mode-istio-ambient-with-cilium.md).
- A container registry reachable from the clusters, with credentials available to the cluster.
- DNS delegation for the trust-framework zone, as described in [TRAIN DNS zone](train-dns.md).

## Installing a zone

The demonstrator installs as a single umbrella Helm chart per zone. The chart lays the zone down
first: the management and data planes as distinct namespaces, default-deny network policies in
both directions, the allow-matrix lanes between the planes, and the hook-weight bands that order
the jobs of the components after it. The platform components install after it, into the layout it
made. That workload identity exists before any workload becomes ready is a property of the
identity path, not of an install order, as the
[hook-weight scheme](umbrella-chart.md#the-hook-weight-scheme) explains.

```bash
helm upgrade --install ztd deployment/helm/ztd -n ztd-system --create-namespace \
  -f deployment/helm/ztd/zones/<zone>.yaml --wait
```

The release namespace holds the release and its hook jobs and is not a plane namespace. The zone
file is written from what the cluster baseline recorded; the chart has no defaults for it. The
design, the hook-weight scheme and the evidence are in [Umbrella chart](umbrella-chart.md), and
chart values are documented with each chart under `deployment/helm/`.

### Through the ORCE workflow

The same install, redeploy and uninstall run through ORCE with zero manual steps: a
`POST /lifecycle` command ([IF-08](api-docs.md)) that the `ztd-lifecycle` node validates, checks
with a server-side dry-run and applies with Helm, reporting a machine-readable result in the ORCE
context. The `helm` commands on this page are the engine-level equivalent.

## Teardown

Components uninstall in the reverse order of their installation; the layout goes last:

```bash
helm uninstall ztd -n ztd-system
```

Teardown must leave no orphaned namespaces, CRDs or secrets; this is verified by an acceptance
scenario rather than by inspection.

## Reproducibility

Every environment is reproducible from this repository plus its values files. No step is performed
by hand against a cluster; anything that cannot be expressed in a chart or a script belongs in
`scripts/`.
