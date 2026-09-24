# Deployment and teardown

How a zone is installed and removed, whichever cluster it is on. For the step-by-step setup of a
specific cluster, with the check that proves each stage, see [Environments](environments/index.md).

## Preconditions

- Kubernetes **1.29 or later** on each target cluster.
- A CNI that supports the mesh baseline recorded in
  [ADR-0001](adr/0001-service-mesh-mode-istio-ambient-with-cilium.md).
- A container registry reachable from the clusters, with credentials available to the cluster.
- DNS delegation for the trust zone.

## Installing a zone

The demonstrator installs as a single umbrella Helm chart per zone. The chart separates the
management and data planes into distinct namespaces and orders installation so that workload
identity exists before any workload starts.

```bash
helm install ztd deployment/helm/ztd -n ztd-mgmt --create-namespace -f <values file>
```

Chart values are documented with each chart under `deployment/helm/`.

### Through the ORCE workflow

The same install, redeploy and uninstall run through ORCE with zero manual steps: a
`POST /lifecycle` command ([IF-08](api-docs.md)) that the `ztd-lifecycle` node validates, checks
with a server-side dry-run and applies with Helm, reporting a machine-readable result in the ORCE
context. The `helm` commands on this page are the engine-level equivalent.

## Teardown

```bash
helm uninstall ztd -n ztd-mgmt
```

Teardown must leave no orphaned namespaces, CRDs or secrets; this is verified by an acceptance
scenario rather than by inspection.

## Reproducibility

Every environment is reproducible from this repository plus its values files. No step is performed
by hand against a cluster; anything that cannot be expressed in a chart or a script belongs in
`scripts/`.
