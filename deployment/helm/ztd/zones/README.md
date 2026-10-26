# Zone values files

One file per zone, created at stand-up from what the cluster baseline recorded, and
passed to every release of the zone by the zone installer:

```bash
ZONE_VALUES=deployment/helm/ztd/zones/<zone>.yaml KUBE_CONTEXT=<context> \
  scripts/install-zone/install.sh install
```

The installer runs the seven releases in order (the umbrella, `spire-crds`, `spire`,
`istio-base`, `istiod`, `istio-cni`, `zone-policy`; `scripts/install-zone/README.md`). The umbrella
reads the whole file; the SPIRE, Istio and `zone-policy` releases read the zone facts they need
from it (the trust domain), so the three cannot disagree.

The chart has no defaults for the zone record on purpose. `zone.kubernetesVersion`,
`zone.storageClass` and `zone.loadBalancer.type` are facts about the cluster, and the chart
refuses to render until the file states them, so a zone is never installed on assumed values.
Where the mesh runs (`mesh.mode` other than `none`) the file must also state:

- `zone.trustDomain`: the zone's SPIFFE trust domain, which is the DNS zone delegated to that trust
  zone (the one in which the trust framework publishes its records). It is not read off the
  cluster; the Technical Design Authority confirms it, and until the delegation exists the field
  has no value and the chart does not render. It is fixed at the first SPIRE install.
- `networkPolicy.kubeApi.enabled: true`, with the API server's port (and, without Cilium, its
  addresses): SPIRE and istiod call the API.
- `cni.cilium.enabled: true`: the control-plane openings are Cilium policies by entity; a zone on
  another CNI needs a declared derogation first.
- `zone.kubernetesVersion` 1.33 or later in sidecar mode (native sidecar containers).
- `planes.extra` with `spire-system` and `istio-system` as management-plane namespaces with
  `mesh: false`, and the openings `meshControlPlane`, `controlPlaneWebhooks` and `identityServer`
  enabled (`docs/workload-identity.md`).

`zone-a.example.yaml` shows the shape with the command that reads each fact off the cluster; the
local kind cluster uses `../ci/values.yaml` (trust domain `kind.facis-ztd.local`).

A zone file records a cluster; it does not mean the chart is installed there. `ionos.yaml` is
recorded from the IONOS cluster and validated against its API with a server-side dry run, but the
chart is not installed on that cluster (see the file's header); it runs no mesh, so it carries no
trust domain. The files for zone A and zone B are added when the OSC clusters are provided.
