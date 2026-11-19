# install-zone

Installs one zone of the demonstrator, from an empty cluster that already runs its CNI, as eight
Helm releases in a fixed order, each through the deployment lifecycle step
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
| 8 | `ztd-openbao` | the management namespace (`ztd-mgmt`) | `deployment/helm/ztd-openbao`, its `openbao` 0.28.3 dependency built from `Chart.lock` | chart defaults + zone facts; also waits for its Jobs |

The umbrella creates every namespace the later releases install into; the lifecycle step never
creates one. `ztd-openbao` comes last so that its server and its jobs are created after istiod and
the registration rule of `zone-policy`, each with a sidecar, a SPIRE entry and an SVID
(`docs/secrets.md`). The only namespace the installer creates is the umbrella's release namespace,
`ztd-system`, which holds the release record and its verification job.

## Usage

```bash
ZONE_VALUES=deployment/helm/ztd/zones/<zone>.yaml KUBE_CONTEXT=<context> scripts/install-zone/install.sh plan
ZONE_VALUES=deployment/helm/ztd/zones/<zone>.yaml KUBE_CONTEXT=<context> scripts/install-zone/install.sh install
ZONE_VALUES=deployment/helm/ztd/zones/<zone>.yaml KUBE_CONTEXT=<context> scripts/install-zone/install.sh uninstall
scripts/install-zone/install.sh render [release...]     # no cluster: what CI runs
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

- **`install`** first renders all eight releases with their zone facts, so a missing fact stops the
  run before anything is installed; then installs them in order. It stops at the first release
  that does not reach a ready state, exits non-zero and names the release and the lifecycle step's
  error; the failed release is rolled back. It exits 0 only when every pod in the plane and
  control-plane namespaces is Ready (finished Job pods aside).
- **Idempotent.** Run again, it upgrades every release in place with identical manifests.
- **`render`** renders every release, or only the ones named; a name that is not one of the eight
  releases (`ztd`, `spire-crds`, `spire`, `istio-base`, `istiod`, `istio-cni`, `zone-policy`,
  `ztd-openbao`)
  stops it with a non-zero exit and the list of valid names, before anything is rendered.
- **`plan`** lists the eight steps without touching a cluster; `install` against an unreachable
  cluster prints the same list and refuses to continue, changing nothing.
- Every command first checks that the zone file exists, and stops with `zone file not found:
  <path>` and a non-zero exit when it does not. `help` (or `-h`, `--help`) prints the usage and
  exits 0; any other word prints the usage and `unknown command '<word>'` on stderr and exits 2.
- **`uninstall`** removes the releases in reverse order (`ztd-openbao`, `zone-policy`, `istio-cni`,
  `istiod`, `istio-base`, `spire`, `spire-crds`, then the umbrella, which takes the namespaces, the
  OpenBao volume and its bootstrap Secret with it) and
  removes the CRDs each release owned, including the ones Istio's `base` chart marks to be kept by
  Helm. Delete the workloads in the plane namespaces first: a pod that still mounts the SPIFFE CSI
  volume when the driver goes holds its namespace in `Terminating`.

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

## Placement

No release is placed on a node: the installer sets no node affinity or node selector, and the
scheduler places every pod, the OpenBao server and both of its jobs included. A zone file that still
carries a key under `openbao` is refused by the umbrella's values schema before anything is rendered.

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

A release whose zone fact is missing does not render, and the message names the fact and the
release.

## Pins

The chart versions and digests are at the top of `install.sh` and in `docs/dependencies.md` (the
upstream OpenBao chart: in `deployment/helm/ztd-openbao/Chart.lock`); the
container images are pinned by tag and digest in the values files under `deployment/helm/values/`. The SPIRE
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

Last run (2026-10-26, `bash:3.2` container, GNU bash 3.2.57(1)-release, repository mounted
read-only, the chart cache mounted writable): exit 0, all eight releases rendered (`ztd` 38 objects,
`spire-crds` 3, `spire` 36, `istio-base` 17, `istiod` 17, `istio-cni` 7, `zone-policy` 14,
`ztd-openbao` 13), no `unbound variable`; `plan` with zone A's file listed the eight steps and no
placement. An earlier run (2026-10-17) also rendered `ztd-openbao` alone with `render ztd-openbao`,
and one before it (2026-10-09) showed a zone copy with
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
