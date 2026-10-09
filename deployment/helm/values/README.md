# Values of the upstream releases

The SPIRE and Istio releases of a zone are the upstream charts, installed as they ship, one Helm
release per chart. The charts are pinned by version and by the sha256 of their archive in
`scripts/install-zone/install.sh` and in `docs/dependencies.md`; the container images they run are
pinned by tag and digest here, in the values files (see "Images" below). No wrapper chart and no
subchart: each release installs, upgrades and removes its own CRDs. This folder holds one values
file per release; this README lists every upstream value the repository sets and why. Anything not
listed is the chart's default.

**Images.** Every image a release runs is pinned by tag and digest, the digest being the
multi-arch index digest of that tag as its registry serves it (`docker buildx imagetools inspect
<image>:<tag>`). The tags are the charts' own defaults for the pinned chart versions, except the
SPIRE server's `kubectl` hook image (below). The SPIRE charts take the pin in the image's `tag`
value as `<tag>@sha256:<digest>`; the Istio charts take a full reference in their `image` value.
Images the charts already pin by digest (`cgr.dev/chainguard/bash`) are left as they ship. One
image stays a tag: `busybox:1.28` in Istio's `grpc-simple` injection template, which runs only in a
pod that chooses its injection templates, which the `zone-policy` admission policy refuses in every
plane namespace. An upgrade of a chart re-reads every digest.

| Release | Value | Image |
|---|---|---|
| `spire` | `spire-server.image.tag` | `ghcr.io/spiffe/spire-server:1.15.3` |
| `spire` | `spire-server.controllerManager.image.tag` | `ghcr.io/spiffe/spire-controller-manager:0.7.0` |
| `spire` | `spire-server.chown.image.tag` | `busybox:1.37.0-uclibc` (the datastore volume's ownership, init container) |
| `spire` | `spire-server.tools.kubectl.image.tag` | `registry.k8s.io/kubectl:v1.35.5` (install, upgrade and delete hooks); the chart's default follows the cluster's version, so the image would change with the cluster; the pin is the kind node's version, within kubectl's one-minor skew of zones at 1.34 to 1.36 |
| `spire` | `spire-agent.image.tag` | `ghcr.io/spiffe/spire-agent:1.15.3` |
| `spire` | `spiffe-csi-driver.image.tag` | `ghcr.io/spiffe/spiffe-csi-driver:0.2.7` |
| `spire` | `spiffe-csi-driver.nodeDriverRegistrar.image.tag` | `registry.k8s.io/sig-storage/csi-node-driver-registrar:v2.15.0` |
| `istiod` | `pilot.image` | `docker.io/istio/pilot:1.31.1` |
| `istiod` | `global.proxy.image` | `docker.io/istio/proxyv2:1.31.1@sha256:d86c…`, the injected proxy; the whole reference, digest included, is mirrored in `zone-policy` `proxySocketPolicy.proxyImage` |
| `istiod` | `global.proxy_init.image` | `docker.io/istio/proxyv2:1.31.1`, the injected `istio-validation` init container (the chart would otherwise build it from hub and tag, without a digest) |
| `istio-cni` | `cni.image` | `docker.io/istio/install-cni:1.31.1` |

| Release | Chart | Source | Namespace |
|---|---|---|---|
| `spire-crds` | `spire-crds` 0.6.1 | `https://spiffe.github.io/helm-charts-hardened/` | `spire-system` |
| `spire` | `spire` 0.30.2 (SPIRE v1.15.3) | `https://spiffe.github.io/helm-charts-hardened/` | `spire-system` |
| `istio-base` | `base` 1.31.1 | Istio 1.31.1 release archive, `manifests/charts/base` | `istio-system` |
| `istiod` | `istiod` 1.31.1 | Istio 1.31.1 release archive, `manifests/charts/istio-control/istio-discovery` | `istio-system` |
| `istio-cni` | `cni` 1.31.1 | Istio 1.31.1 release archive, `manifests/charts/istio-cni` | `istio-system` |

The namespaces are created by the umbrella chart as management-plane namespaces without the mesh
label; no release here creates a namespace. The Istio 1.31 charts come from the release archive
because Istio's Helm repository and OCI registry do not carry them; the archive is pinned by its
published sha256.

**Zone facts.** A value marked *zone fact* is empty in its file and filled by the installer from
the zone file; the installer refuses to render the release when the zone file does not state it,
naming the fact:

| Release | Value | Zone fact |
|---|---|---|
| `spire` | `global.spire.trustDomain` | `zone.trustDomain` |
| `spire` | `global.spire.clusterName` | `zone.name` |
| `spire` | `global.spire.persistence.storageClass` | `zone.storageClass` |
| `spire` | `global.spire.caSubject.commonName` | `zone.trustDomain` |
| `istiod` | `meshConfig.trustDomain` | `zone.trustDomain` |
| `zone-policy` (project chart) | `trustDomain` | `zone.trustDomain` |

## `spire-crds.yaml`

| Value | Set to | Why |
|---|---|---|
| `annotations` | `helm.sh/resource-policy: null`, `ztd.facis.io/removed-with-release: spire-crds` | the chart annotates its CRDs `helm.sh/resource-policy: keep` by default, which would leave them on the cluster after `helm uninstall`; the CRDs belong to this release and leave with it. Helm merges a values map with the chart's default, so `{}` would keep the key; setting it to null deletes it. The chart cannot render an empty annotations map, so one annotation of the zone takes its place |

## `spire.yaml`

| Value | Set to | Why |
|---|---|---|
| `global.spire.trustDomain` | zone fact | the zone's trust domain (`docs/workload-identity.md`); shared with the mesh, fixed at first install |
| `global.spire.clusterName` | zone fact | the cluster name in the agents' node-attestation IDs and the controller-manager's entries |
| `global.spire.recommendations.enabled` | `false` | keeps every component in the release namespace `spire-system`; the recommended layout would split server and agents across `spire-server` and `spire-system` and label the namespaces |
| `global.spire.namespaces.create` | `false` | the umbrella creates `spire-system`, a management-plane namespace under the default deny |
| `global.spire.persistence.storageClass` | zone fact | the server's datastore volume (SQLite, the chart's default) on the zone's storage class |
| `global.spire.caSubject.organization` | `FACIS ZTD` | the subject of the server's CA, which every SVID names as issuer (the SVIDs themselves carry `O = SPIRE`); the chart's placeholder `Example` is replaced |
| `global.spire.caSubject.commonName` | zone fact | the trust domain, so that the issuer names the zone; the country stays the chart's placeholder |
| `spire-server.telemetry.prometheus.enabled` | `true` | the server's metrics on pod port 9988, the contract with the observability collector |
| `spire-server.federation.enabled` | `false` | each zone is its own trust domain; zones never federate |
| `spire-server.ingress.enabled` | `false` | the agents reach the server inside the cluster only |
| `spire-server.tornjak.enabled` | `false` | no management UI |
| `spire-server.controllerManager.enabled` | `true` | reconciles the zone's `ClusterSPIFFEID` (release `zone-policy`) into entries |
| `spire-server.controllerManager.identities.clusterSPIFFEIDs.default.enabled` | `false` | the chart's catch-all registration would give every pod of every namespace an identity, the opposite of "no label, no entry" |
| `spire-server.controllerManager.identities.clusterSPIFFEIDs.oidc-discovery-provider.enabled` | `false` | no OIDC discovery provider is installed |
| `spire-server.controllerManager.identities.clusterSPIFFEIDs.test-keys.enabled` | `false` | no test registrations in a zone |
| `spire-agent.hostNetwork` | `auto` (the default, stated) | the agents run on the host network, so they reach the kubelet over the host's loopback and need no kubelet opening; the umbrella opens the server to them by node entity (`identityServer`) |
| `spire-agent.kubeletAddress.mode` | `auto` (the default, stated) | `localhost` off OpenShift: workload attestation through the kubelet on 127.0.0.1 |
| `spire-agent.sds.enabled` | `true` | the Envoy SDS endpoint the mesh proxy reads its certificate and bundle from; off by default |
| `spire-agent.sds.defaultSVIDName` | `default` | the name Istio's proxy asks for its workload certificate (the SDS contract) |
| `spire-agent.sds.defaultBundleName` | `"null"` | the string `null` disables the own-bundle resource, which would otherwise also answer `ROOTCA` |
| `spire-agent.sds.defaultAllBundlesName` | `ROOTCA` | the name Istio's proxy asks for its validation context, served with every bundle so that federation later changes nothing |
| `spire-agent.telemetry.prometheus.enabled` | `true` | the agents' metrics on port 9988 of each node, the contract with the observability collector |
| `spire-agent.telemetry.prometheus.host` | `127.0.0.1` | the agent runs on the host network, where the chart's `0.0.0.0` would open an unauthenticated metrics endpoint on every node address, out of reach of any network policy; on the loopback it answers only a collector on the node's host network |
| `spiffe-csi-driver.enabled` | `true` | mounts the agent's Workload API socket into pods as the read-only `csi.spiffe.io` volume |
| `spiffe-oidc-discovery-provider.enabled` | `false` | no JWT consumer outside the zone |
| `tornjak-frontend.enabled` | `false` | no management UI |
| `upstream.enabled` | `false` | no nested SPIRE |

The telemetry endpoints (server 9988, agents 127.0.0.1:9988 on the node, controller-manager 8082) are switched
on and their ports fixed here as the contract the observability work scrapes with its collector;
the collector and its lane into `spire-system` are not part of this folder.

## `istio-base.yaml`

| Value | Set to | Why |
|---|---|---|
| `defaultRevision` | `default` | the default revision's validation, selected together with the default injector by the `istio-injection=enabled` label the umbrella sets |
| `base.validationFailurePolicy` | `Fail` | the chart renders its validation webhook fail-open (`Ignore`) on a first install only and omits the policy on upgrades, so a second install would change the manifest; `Fail` makes every run render alike and the webhook fail closed |

The chart marks its CRDs `helm.sh/resource-policy: keep` in its files, not in a value; the
installer's uninstall removes the CRDs the release owned.

## `istiod.yaml`

| Value | Set to | Why |
|---|---|---|
| `meshConfig.trustDomain` | zone fact | the mesh's trust domain equals SPIRE's; a mismatch fails silently at the first mTLS handshake |
| `meshConfig.meshMTLS.minProtocolVersion` | `TLSV1_3` | the security baseline sets TLS 1.3 as the minimum (ADR 005, `docs/adr/tdr-decisions.md`) and Istio's default minimum for mesh mTLS is TLS 1.2; the CI render asserts the value in the rendered `istio` ConfigMap, and `scripts/verify-mesh-identity/verify.sh` shows a TLS 1.3 handshake accepted and one capped at TLS 1.2 refused. Only mesh mTLS is set: `tlsDefaults` governs traffic that is not `ISTIO_MUTUAL`, of which the zone has none |
| `pilot.env.ENABLE_NATIVE_SIDECARS` | `"true"` | the proxy is injected as an init container with `restartPolicy: Always` (Kubernetes 1.33 or later) |
| `pilot.cni.enabled` | `true` | traffic redirection by the Istio CNI plugin (release `istio-cni`), so the injected pod has no privileged `istio-init` container |
| `sidecarInjectorWebhook.templates.spire` | a patch of the pod's `workload-socket` volume into the `csi.spiffe.io` read-only volume | the default sidecar template mounts `workload-socket` into the proxy at `/var/run/secrets/workload-spiffe-uds`; with the SPIRE agent's socket there the proxy takes its certificate and bundle from SPIRE over SDS and never from istiod's CA |
| `base.validationFailurePolicy` | `Fail` | as in `istio-base`: identical manifests on every run, and the webhook fails closed |
| `sidecarInjectorWebhook.defaultTemplates` | `[sidecar, spire]` | the `spire` template applies to every injection, so a workload does not lose the SPIRE socket by leaving out an annotation; a pod that names its own templates (`inject.istio.io/templates`) is refused in the plane namespaces by the `zone-policy` admission policy `proxy-takes-spire-socket`, because istiod's CA, which also signs istiod's own serving certificates, cannot be switched off |

`global.proxy.statusPort` is not set and stays at Istio's default, `15020`. The `zone-policy` chart
mirrors it in `proxySocketPolicy.statusPort`: its admission policy admits a pod in a plane namespace
only when the injector's `traffic.sidecar.istio.io/excludeInboundPorts` is that port alone (the
capture rule, `deployment/helm/zone-policy/README.md`). Changing the status port here without
changing it there refuses every injected pod in the plane namespaces.

`global.proxy.image` is mirrored the same way in `zone-policy` `proxySocketPolicy.proxyImage`: the
proxy rule of the same policy admits a mesh proxy only with that exact image reference, digest
included, so an Istio upgrade changes both, or every injected pod in the plane namespaces is
refused. `scripts/install-zone/install.sh` compares both pairs (image and status port) before it
renders or installs, and refuses a zone where they differ.

## `istio-cni.yaml`

| Value | Set to | Why |
|---|---|---|
| `cni.chained` | `true` | append the Istio plugin to the configuration Cilium wrote (Cilium runs with `cni.exclusive=false`), never replace it |
| `cni.cniBinDir` | `/opt/cni/bin` | the CNI binary directory of the nodes (kind's, and the chart's default); a zone whose nodes differ overrides it |
| `cni.cniConfDir` | `/etc/cni/net.d` | the CNI configuration directory of the nodes, as above |
| `cni.ambient.enabled` | `false` | sidecar mode (ADR-0009); ambient is parked |

## Rendering

The CI chart job renders every release from its pinned chart with these files and the kind zone's
facts, and never installs:

```bash
scripts/install-zone/install.sh render            # all seven releases, no cluster
scripts/install-zone/install.sh render spire      # one release
```
