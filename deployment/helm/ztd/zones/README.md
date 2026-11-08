# Zone values files

One file per zone, created at stand-up from what the cluster baseline recorded, and
passed to every release of the zone by the zone installer:

```bash
ZONE_VALUES=deployment/helm/ztd/zones/<zone>.yaml KUBE_CONTEXT=<context> \
  scripts/install-zone/install.sh install
```

The installer runs the eight releases in order (the umbrella, `spire-crds`, `spire`,
`istio-base`, `istiod`, `istio-cni`, `zone-policy`, `ztd-openbao`; `scripts/install-zone/README.md`).
The umbrella reads the whole file; the SPIRE, Istio, `zone-policy` and `ztd-openbao` releases read
the zone facts they need from the umbrella's defaults with this file on top (the trust domain, the
storage class, the management namespace, the Cilium switch), so they cannot disagree.

The secret store is not an umbrella value: the umbrella's schema refuses `openbao.enabled` and the
other values it once took for OpenBao. Every zone the installer installs gets the release
`ztd-openbao` (`deployment/helm/ztd-openbao`), with the zone's `zone.storageClass`; the one OpenBao
key a zone file may carry is `openbao.pinToMeshNode`, which the installer reads (below).

The chart has no defaults for the zone record on purpose. `zone.kubernetesVersion`,
`zone.storageClass` and `zone.loadBalancer.type` are facts about the cluster, and the chart
refuses to render until the file states them, so a zone is never installed on assumed values.
Where the mesh runs (`mesh.mode` other than `none`) the file must also state:

- `zone.trustDomain`: the zone's SPIFFE trust domain, a name under the DNS zone delegated to the
  trust framework, one per zone (`zone-a.<zone>`, `zone-b.<zone>`). It is never resolved, so no
  second delegation is requested for it; it is not read off the cluster, and the Technical Design
  Authority confirms it. It is fixed in the SPIRE root CA at install: a zone installed on one name is
  re-installed (a new SPIRE CA, new SVIDs) to move to another.
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
trust domain.

`zone-a.yaml` and `zone-b.yaml` record the two participant clusters on the Open Sovereign Cloud
(contexts `zerotrust-a` and `zerotrust-b`): Kubernetes `v1.34.7`, StorageClass `default`,
`loadBalancer.type: cloud` (not yet exercised), Cilium 1.18.8 installed by the provider with
`cni-exclusive=false`, the mesh in sidecar mode, the two control-plane namespaces and the three
openings, and the API lane on port 443 by entity, with no address in the file. Two facts of the
provider's platform are recorded with them: CoreDNS listens on 8053 (`networkPolicy.dns.ports`),
and the zone's namespaces carry Gardener's opt-out label
`apiserver-proxy.networking.gardener.cloud/inject: disable` (`planes.namespaceLabels`), so that the
provider's webhook leaves the pods on the `kubernetes` Service and they reach the API through the
`kubeApi` lane. Both set `openbao.pinToMeshNode: true`: the provider's pod network masquerades
cross-node pod traffic, so the installer pins the OpenBao server and its jobs to istiod's node until
the network is fixed (`docs/environments/osc.md`). `ionos.yaml` carries no OpenBao value: the
installer does not install that cluster, which runs the visualization only.

| Zone file | `zone.trustDomain` | Status |
|---|---|---|
| `zone-a.yaml` | `zone-a.trust.invalid` | interim, until the delegated trust-framework zone is named and the Technical Design Authority confirms `zone-a.<zone>` |
| `zone-b.yaml` | `zone-b.trust.invalid` | interim, until the delegated trust-framework zone is named and the Technical Design Authority confirms `zone-b.<zone>` |

The interim names let SPIRE and the mesh go onto the clusters before the delegated zone is named.
`.invalid` is a reserved top-level domain that can never resolve or be delegated, so an interim
name cannot be taken for a real one, and the proof recognises it by its `.trust.invalid` suffix. The
mesh-identity proof may leave a zone installed on its interim name, behind its keep opt-in
(`ZTD_KEEP_ZONE`, [scripts/verify-mesh-identity](../../../../scripts/verify-mesh-identity/README.md));
because the name is fixed in the SPIRE root CA, that zone is re-installed with the final name once
it is confirmed. Every re-run of the proof with the keep opt-in also regenerates the SPIRE root CA
and reissues every SVID, which costs nothing while no other workload runs on the clusters.
