# install-zone

Installs one cluster of the demonstrator from its zone file. The zone file's `zone.role` chooses the
sequence: a **participant zone** (the default; zone A, zone B, kind) or the **demonstrator cluster**
(IONOS; see [The demonstrator role](#the-demonstrator-role)). A participant zone is installed, from an
empty cluster that already runs its CNI, as ten Helm releases in a fixed order, each through the
deployment lifecycle step
(`scripts/lifecycle.sh`: a server-side dry run, then `helm upgrade --install --wait` with rollback
on failure), each waiting on the previous:

| # | Release | Namespace | Chart | Values |
|---|---|---|---|---|
| 1 | `ztd` | `ztd-system` | `deployment/helm/ztd` (the umbrella) | the zone file |
| 2 | `spire-crds` | `spire-system` | `spire-crds` 0.6.1, SPIFFE hardened charts | `deployment/helm/values/spire-crds.yaml` |
| 3 | `spire` | `spire-system` | `spire` 0.30.2 (SPIRE v1.15.3) | `deployment/helm/values/spire.yaml` + zone facts |
| 4 | `istio-base` | `istio-system` | `base` 1.31.1, Istio release archive | `deployment/helm/values/istio-base.yaml` |
| 5 | `istiod` | `istio-system` | `istiod` 1.31.1 | `deployment/helm/values/istiod.yaml` + zone facts |
| 6 | `istio-cni` | `istio-system` | `cni` 1.31.1 | `deployment/helm/values/istio-cni.yaml` |
| 7 | `zone-policy` | `istio-system` | `deployment/helm/zone-policy` | chart defaults + zone facts; also waits for its Jobs |
| 8 | `ztd-openbao` | the management namespace (`ztd-mgmt`) | `deployment/helm/ztd-openbao`, its `openbao` 0.28.3 dependency built from `Chart.lock` | chart defaults + zone facts (+ the node pin); also waits for its Jobs |
| 9 | `otel-node` | `ztd-otel-node` | `opentelemetry-collector` 0.176.1 (pinned in `scripts/tools/pins.env`) | `deployment/helm/values/otel-node.yaml` + derived values |
| 10 | `otel-gateway` | the management namespace | `opentelemetry-collector` 0.176.1 | `deployment/helm/values/otel-gateway.yaml` + derived values (+ the node pin) |

The umbrella creates every namespace the later releases install into; the lifecycle step never
creates one. `ztd-openbao` and the zone gateway come after istiod and the registration rule of
`zone-policy`, so their pods are created with a sidecar, a SPIRE entry and an SVID
(`docs/secrets.md`). The two telemetry releases (the node collectors and the zone gateway,
`docs/adr/0012-central-observability-backends.md`) export to the demonstrator cluster's entry with
the zone's client certificate, the Secret `ztd-telemetry-client` in `ztd-otel-node` and the management
namespace, which the demonstrator role's step `telemetry-client-certs` creates. `install` stops before
`otel-node` when that Secret is missing, says so and prints the command; the releases before it stay
installed. The only namespace the installer creates is the umbrella's release namespace,
`ztd-system`, which holds the release record and its verification job.

## Usage

```bash
ZONE_VALUES=deployment/helm/ztd/zones/<zone>.yaml KUBE_CONTEXT=<context> scripts/install-zone/install.sh plan
ZONE_VALUES=deployment/helm/ztd/zones/<zone>.yaml KUBE_CONTEXT=<context> scripts/install-zone/install.sh install
ZONE_VALUES=deployment/helm/ztd/zones/<zone>.yaml KUBE_CONTEXT=<context> scripts/install-zone/install.sh uninstall
scripts/install-zone/install.sh render [release...]     # no cluster: what CI runs
scripts/install-zone/install.sh install [release...]    # only the named releases, in plan order
```

On the local kind cluster the defaults apply (`ZONE_VALUES` is the kind zone,
`deployment/helm/ztd/ci/values.yaml`; `KUBE_CONTEXT` is `kind-ztd`):

```bash
scripts/dev/kind-cilium-up.sh
scripts/install-zone/install.sh install
```

| Variable | Default | Meaning |
|---|---|---|
| `ZONE_VALUES` | `deployment/helm/ztd/ci/values.yaml` | the zone file |
| `KUBE_CONTEXT` | `kind-ztd` | the kubectl context of the zone's cluster |
| `STEP_TIMEOUT` | `10m` | the timeout of each release |
| `RENDER_DIR` | unset | with `render`, write each release's manifest there |
| `INSTALL_ZONE_CACHE` | `~/.cache/ztd-install-zone` | where the pinned charts and the built OpenBao dependency are kept |
| `TELEMETRY_ZONES` | unset | demonstrator role: `<zone>=<context>[,...]`, the zones whose client certificate `telemetry-client-certs` copies |
| `TELEMETRY_ZONE_MGMT_NAMESPACE` | `ztd-mgmt` | demonstrator role: the zones' management namespace for that copy |

- **`install`** first renders all the role's releases (or the named ones) with their zone facts, so a missing fact stops the
  run before anything is installed; then installs them in order. It stops at the first release
  that does not reach a ready state, exits non-zero and names the release and the lifecycle step's
  error; the failed release is rolled back. It exits 0 only when every pod in the plane and
  control-plane namespaces is Ready (finished Job pods aside). With release names it installs only
  those, in plan order, and judges each by its own release.
- **Idempotent.** Run again, it upgrades every release in place with identical manifests.
- **`render`** renders every release, or only the ones named; a name that is not one of the role's
  releases (participant: `ztd`, `spire-crds`, `spire`, `istio-base`, `istiod`, `istio-cni`,
  `zone-policy`, `ztd-openbao`, `otel-node`, `otel-gateway`)
  stops it with a non-zero exit and the list of valid names, before anything is rendered.
- **`plan`** lists the role's steps without touching a cluster; `install` against an unreachable
  cluster prints the same list and refuses to continue, changing nothing.
- Every command first checks that the zone file exists, and stops with `zone file not found:
  <path>` and a non-zero exit when it does not. `help` (or `-h`, `--help`) prints the usage and
  exits 0; any other word prints the usage and `unknown command '<word>'` on stderr and exits 2.
- **`uninstall`** removes the releases in reverse order (`otel-gateway`, `otel-node`, `ztd-openbao`, `zone-policy`, `istio-cni`,
  `istiod`, `istio-base`, `spire`, `spire-crds`, then the umbrella, which takes the namespaces, the
  OpenBao volume and its bootstrap Secret with it) and
  removes the CRDs each release owned, including the ones Istio's `base` chart marks to be kept by
  Helm. Delete the workloads in the plane namespaces first: a pod that still mounts the SPIFFE CSI
  volume when the driver goes holds its namespace in `Terminating`.

## The demonstrator role

A zone file with `zone.role: demonstrator` (`deployment/helm/ztd/zones/ionos.yaml`; on kind
`deployment/helm/ztd/ci/demonstrator-values.yaml`, in the same cluster as the kind zone) installs the
central observability backends, all into `observabilityBackends.namespace` (`ztd-observability`)
except the umbrella:

| # | Release | Chart | Values |
|---|---|---|---|
| 1 | `ztd-demonstrator` (in `ztd-system`) | `deployment/helm/ztd`, demonstrator role: the backends' namespace and its policies only | the zone file |
| 2 | `telemetry-issuers` | `deployment/helm/telemetry-issuers` (cert-manager resources) | zone facts: the zones, the server name |
| 3 | `otel-entry` | `opentelemetry-collector` 0.176.1 | `deployment/helm/values/otel-entry.yaml` + derived values: one mutual-TLS listener and its pipelines per zone, the Service's ports and source ranges |
| 4 | `prometheus` | `prometheus` 29.37.0 | `deployment/helm/values/prometheus.yaml` + zone facts (retention, size bound, volume, storage class) + one silent-zone rule per zone |
| 5 | `alertmanager` | `alertmanager` 2.1.1 | `deployment/helm/values/alertmanager.yaml` + zone facts |
| 6 | `jaeger` | `jaeger` 4.16.1 | `deployment/helm/values/jaeger.yaml` + derived values (volume) |

Then, when `TELEMETRY_ZONES` names the zones, the step **`telemetry-client-certs`** (also a command of
its own): for each `<zone>=<context>` it waits for the zone's client certificate, and creates or
updates the Secret `ztd-telemetry-client` (`tls.crt`, `tls.key`, and `ca.crt` the telemetry root's
certificate, never its key) in `ztd-otel-node` and the management namespace of that context. The
material passes through a temporary directory readable by the user alone and removed on exit, and
the Secret is applied server-side, so no copy lands in a `last-applied` annotation. A zone namespace
that does not exist stops the step: install the zone's umbrella first. The collectors read the
certificate at start: after a copy that replaced one (a renewal, or the demonstrator role
reinstalled with a new CA), restart them (`kubectl -n ztd-otel-node rollout restart
ds/otel-node-agent`, `kubectl -n ztd-mgmt rollout restart deploy/otel-gateway`). On kind an
`uninstall` of the demonstrator role followed by an `install` left no release behind and reinstalled
every release (2026-10-21). The log store is not
installed; it is an open point of ADR-0012.

The demonstrator cluster needs cert-manager (it runs its own, v1.21.2); `install` refuses a cluster
without its CRDs. On kind `scripts/dev/kind-cert-manager-up.sh` installs the pinned version. A
demonstrator zone file on a cluster with a LoadBalancer is refused while
`observabilityBackends.entry.sourceRanges` is empty, so the entry is never published without them.

**Order across clusters.** Install the zone's umbrella (`install.sh install ztd`, or the zone without
its telemetry releases), install the demonstrator role with `TELEMETRY_ZONES`, then install the zone
again (or `install.sh install otel-node otel-gateway`). On kind:

```bash
scripts/dev/kind-cilium-up.sh && scripts/dev/kind-cert-manager-up.sh
scripts/install-zone/install.sh install ztd spire-crds spire istio-base istiod istio-cni zone-policy ztd-openbao
ZONE_VALUES=deployment/helm/ztd/ci/demonstrator-values.yaml TELEMETRY_ZONES=kind=kind-ztd \
  scripts/install-zone/install.sh install
scripts/install-zone/install.sh install otel-node otel-gateway
```

On kind this ran on 2026-10-21: every demonstrator release deployed, every pod of `ztd-observability`
Ready, the client certificate copied into `ztd-otel-node` and `ztd-mgmt`, then both telemetry
releases deployed (the zone gateway with its sidecar, 2/2).

## The OpenBao dependency

`deployment/helm/ztd-openbao` wraps the upstream `openbao` chart, recorded in its `Chart.lock`; the
checkout carries no `charts/` folder. Before it renders or installs the release, the installer runs
`helm dependency build` on a copy of `Chart.yaml` and `Chart.lock` in its cache, with a repository
configuration of its own (the user's Helm repositories are neither read nor changed). Helm refuses a
lock whose digest does not match the chart's dependencies, and the run stops naming the chart. That
digest covers the list of dependencies, not the archive's bytes, so the archive is pinned on its own:
its sha256 is committed in `deployment/helm/ztd-openbao/dependencies.sha256`, and
`scripts/ci/verify-chart-dependencies.sh` refuses an archive with another digest, a missing one, or
anything else in the chart's `charts/` folder (an unpacked chart directory included). The build runs
once per `Chart.yaml` and `Chart.lock`; nothing in the cache is trusted on its own. Each run copies
the chart from the checkout into its work directory, copies the built archives in, and checks that
copy against the committed pins before Helm reads it, so the bytes installed are the bytes checked
and the chart's own templates and values are always the checkout's. The upstream repository is
reached at the first build, as SPIRE's and Istio's are at their first fetch.

## The node pin of OpenBao and the zone gateway

When the zone file sets `openbao.pinToMeshNode: true` (zone A and zone B), `install` reads the node
istiod runs on once the istiod release is deployed and sets the `ztd-openbao` value
`global.pin.node` to it: the server and both jobs get a required node affinity on
`kubernetes.io/hostname`. When istiod has no node the value is `istiod-node-not-found`, which matches
no node, so nothing runs unpinned; `render` and the pre-install render use that placeholder and
touch no cluster. The reason is the provider's pod network, which masquerades pod traffic between
nodes: a meshed pod on another node than istiod never passes its proxy's readiness. The pin is
temporary and falls when that network is fixed (`docs/environments/osc.md`); the kind zone is not
pinned. The zone gateway (`otel-gateway`) takes the same pin, as a `nodeSelector` on
`kubernetes.io/hostname`, for the same reason: the workloads and the proxies reach it under mTLS.

## What the installer accepts

The installer installs sidecar mode with the default, unrevisioned istiod (release 5) and the Istio
CNI plugin with ambient off (release 6, `deployment/helm/values/istio-cni.yaml`). Of the zone
file's mesh settings it therefore accepts only:

| Key | Accepted |
|---|---|
| `mesh.mode` | `sidecar`, or absent (the umbrella's default is sidecar) |
| `mesh.revision` | empty, or absent |

`plan`, `render` and `install` refuse any other value before anything is fetched, rendered or
installed, exit non-zero and name the key, its value and the reason, for example:

```text
install-zone: the zone file sets mesh.revision "canary", but this installer installs the default, unrevisioned istiod in sidecar mode only; a revisioned mesh needs its own installer support
```

A revisioned or ambient zone would otherwise be labelled by the umbrella for an injector that is
never installed, and the install would report success with no proxy in any plane namespace. A zone
without a mesh (`mesh.mode: none`, such as the IONOS zone) is not installed by this installer: it
installs the umbrella alone through `scripts/lifecycle.sh`. CI runs both refusals (a revision, and
ambient) against copies of the kind zone file.

## The facts a zone file must carry

The umbrella reads the whole file (`deployment/helm/ztd/zones/README.md`). Where the mesh runs, it
must also state `zone.trustDomain` (a name under the DNS zone delegated to the trust framework, one per zone), the API lane
(`networkPolicy.kubeApi.enabled: true` with its port), `cni.cilium.enabled: true`, a
`zone.kubernetesVersion` of 1.33 or later, the control-plane namespaces in `planes.extra` and the
openings. The other releases read these zone facts from the umbrella's defaults
(`deployment/helm/ztd/values.yaml`) with the zone file deep-merged on top, the zone file winning, so a
fact the umbrella defaults (the management namespace, the Cilium switch) needs no repeating, while a
fact the umbrella leaves empty (`zone.trustDomain`, `zone.name`, `zone.storageClass`) must be stated
by the zone file:

| Release | Value | Zone fact |
|---|---|---|
| `spire` | `global.spire.trustDomain`, `global.spire.caSubject.commonName` | `zone.trustDomain` |
| `spire` | `global.spire.clusterName` | `zone.name` |
| `spire` | `global.spire.persistence.storageClass` | `zone.storageClass` |
| `istiod` | `meshConfig.trustDomain` | `zone.trustDomain` |
| `zone-policy` | `trustDomain` | `zone.trustDomain` |
| `ztd-openbao` | `managementNamespace`, `openbao.global.namespace` (and its release namespace) | `planes.management.namespace` |
| `ztd-openbao` | `openbao.server.dataStorage.storageClass` | `zone.storageClass` |
| `ztd-openbao` | `cilium.enabled` | `cni.cilium.enabled` |
| `ztd-openbao` | `global.pin.node` (istiod's node) | `openbao.pinToMeshNode` |
| `otel-node`, `otel-gateway` | the exporter's endpoint and server name; the client certificate's Secret | `telemetryExport.entry` (`address` or `inCluster.host`, `port`, `serverName`), `telemetryExport.clientSecret` |
| `otel-gateway` | the revocation probe's URL; `nodeSelector` (istiod's node) | `telemetryExport.revocationStatusListUrl`; `openbao.pinToMeshNode` |
| `telemetry-issuers` | `zones`, `serverName` | `observabilityBackends.entry.zones`, `.serverName` |
| `otel-entry` | the listeners, pipelines, ports, CA mounts; the Service type and source ranges | `observabilityBackends.entry.zones`, `.sourceRanges`; `zone.loadBalancer.type` |
| `prometheus` | retention, size bound, volume size, storage class; the silent-zone rules | `observabilityBackends.retention`, `.retentionSize`, `.volumes.prometheus`, `zone.storageClass`; `observabilityBackends.entry.zones` |
| `alertmanager`, `jaeger` | volume size, storage class | `observabilityBackends.volumes.*`, `zone.storageClass` |

The telemetry releases of a participant zone also need `telemetryExport.entry` (an address, or
`inCluster` on kind), `telemetryExport.revocationStatusListUrl`, the namespace `ztd-otel-node` with
`mesh: false` in `planes.extra` and `networkPolicy.observabilityScrape.enabled`; whenever a run
includes `otel-node` or `otel-gateway` (every run without release names), a zone file without them is
refused before anything is rendered, naming what is missing. Zone A and zone B leave the entry's
address and the URL empty until the demonstrator role is installed, so their telemetry releases are
refused and their other releases are not.

A release whose zone fact is missing does not render, and the message names the fact and the
release.

## Pins

The chart versions and digests of SPIRE and Istio are at the top of `install.sh`, those of the
observability stack in `scripts/tools/pins.env` with their images (the installer sets the images on
the charts), all listed in `docs/dependencies.md` (the upstream OpenBao chart: in
`deployment/helm/ztd-openbao/Chart.lock`); the identity and mesh images are pinned by tag and digest in
the values files under `deployment/helm/values/`. The SPIRE
charts come from `https://spiffe.github.io/helm-charts-hardened/` and are checked against their
sha256. The Istio 1.31 charts are not in Istio's Helm repository or OCI registry; they come from
the release archive `istio-1.31.1-linux-amd64.tar.gz`, checked against its published sha256. An
upgrade changes a version and its digest here and reruns `scripts/verify-mesh-identity/verify.sh`.

## Tools

`bash` 3.2 or later (macOS's `/bin/bash` is the floor), `helm` (v4.3.0, the pipeline's),
`kubectl`, `jq`, `curl`, `python3` with PyYAML, and `sha256sum` or `shasum`. No CI runner ships
bash 3.2, so the floor is checked by hand: `render` with no release names, the path `install` takes
first, is run once under a bash 3.2 binary (a Mac, or the `bash:3.2` container with the host's
`helm` and the chart cache mounted), from the repository root:

```bash
docker run --rm -v "$PWD:/repo" -w /repo -v "$(command -v helm):/usr/local/bin/helm:ro" \
  -v "$HOME/.cache/ztd-install-zone:/cache" -e INSTALL_ZONE_CACHE=/cache bash:3.2 \
  sh -c 'apk add --no-cache python3 py3-yaml curl >/dev/null && bash --version | head -1 && bash scripts/install-zone/install.sh render'
```

Last run (2026-10-21, `bash:3.2` container, GNU bash 3.2.57(1)-release, repository mounted
read-only): exit 0; the kind zone's ten releases rendered (`ztd` 47 objects, `spire-crds` 3, `spire`
36, `istio-base` 17, `istiod` 17, `istio-cni` 7, `zone-policy` 15, `ztd-openbao` 13, `otel-node` 3,
`otel-gateway` 6) and the kind demonstrator's six (`ztd-demonstrator` 10, `telemetry-issuers` 10,
`otel-entry` 4, `prometheus` 5, `alertmanager` 5, `jaeger` 5). The run before (2026-10-17, `bash:3.2` container, GNU bash 3.2.57(1)-release, repository mounted
read-only, the chart cache mounted writable): exit 0, all eight releases rendered (`ztd` 38 objects,
`spire-crds` 3, `spire` 36, `istio-base` 17, `istiod` 17, `istio-cni` 7, `zone-policy` 14,
`ztd-openbao` 12), no `unbound variable`; `render ztd-openbao` rendered the one release, and `plan`
with zone A's file listed the node pin. An earlier run (2026-10-09) also showed a zone copy with
`mesh.revision: canary` exiting 1 naming the key with nothing rendered; the script before that fix
stopped there with `want[@]: unbound variable` and still exited 0 having rendered nothing.

On a kind host, raise `fs.inotify.max_user_instances` to 512 first
(`sudo sysctl -w fs.inotify.max_user_instances=512`): every kind node shares the host kernel, and
the Istio CNI agent fails to start below that limit. On any other cluster the limit is the node's;
read it on every node through the node's Cilium agent (read-only):

```bash
for p in $(kubectl --context <context> -n kube-system get pod -l k8s-app=cilium -o name); do
  kubectl --context <context> -n kube-system exec "$p" -c cilium-agent -- cat /proc/sys/fs/inotify/max_user_instances
done
```

The participant clusters of zone A and zone B (contexts `zerotrust-a`, `zerotrust-b`) have their
zone files, `deployment/helm/ztd/zones/zone-a.yaml` and `zone-b.yaml`, on interim trust domains.
The installer has no guard of its own; the proof `scripts/verify-mesh-identity/verify.sh` installs
there only behind its participant-cluster opt-in (`ZTD_CONFIRM_CLUSTER`), and leaves the zone
installed only behind its keep opt-in (`ZTD_KEEP_ZONE`) when every check passed; an interrupted or
failed run tears down. A zone left installed is removed with `install.sh uninstall` (the command
above, with its zone file and context) followed by `kubectl --context <context> delete namespace
ztd-system`; a new run of the proof does that itself in its clean-slate section. The proof writes the
record of each run (`evidence.md`, `environment.json`) to a run directory outside the repository,
`ZTD_EVIDENCE_DIR` or a new directory under `${XDG_STATE_HOME:-$HOME/.local/state}`, printed as its
last line; the repository holds no record of a run (see `scripts/verify-mesh-identity/README.md`).
