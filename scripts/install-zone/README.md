# install-zone

Installs one zone of the demonstrator, from an empty cluster that already runs its CNI, as seven
Helm releases in a fixed order, each through the deployment lifecycle step
(`scripts/lifecycle.sh`: a server-side dry run, then `helm upgrade --install --wait` with rollback
on failure), each waiting on the previous:

| # | Release | Namespace | Chart | Values |
|---|---|---|---|---|
| 1 | `ztd` | `ztd-system` | `deployment/helm/ztd` (the umbrella) | the zone file |
| 2 | `spire-crds` | `spire-system` | `spire-crds` 0.6.1, SPIFFE hardened charts | `deployment/helm/values/spire-crds.yaml` |
| 3 | `spire` | `spire-system` | `spire` 0.30.2 (SPIRE v1.15.3) | `deployment/helm/values/spire.yaml` + zone facts |
| 4 | `istio-base` | `istio-system` | `base` 1.31.4, Istio release archive | `deployment/helm/values/istio-base.yaml` |
| 5 | `istiod` | `istio-system` | `istiod` 1.31.4 | `deployment/helm/values/istiod.yaml` + zone facts |
| 6 | `istio-cni` | `istio-system` | `cni` 1.31.4 | `deployment/helm/values/istio-cni.yaml` |
| 7 | `zone-policy` | `istio-system` | `deployment/helm/zone-policy` | chart defaults + zone facts; also waits for its Jobs |

The umbrella creates every namespace the later releases install into; the lifecycle step never
creates one. The only namespace the installer creates is the umbrella's release namespace,
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
| `INSTALL_ZONE_CACHE` | `~/.cache/ztd-install-zone` | where the pinned charts are kept |

- **`install`** first renders all seven releases with their zone facts, so a missing fact stops the
  run before anything is installed; then installs them in order. It stops at the first release
  that does not reach a ready state, exits non-zero and names the release and the lifecycle step's
  error; the failed release is rolled back. It exits 0 only when every pod in the plane and
  control-plane namespaces is Ready (finished Job pods aside).
- **Idempotent.** Run again, it upgrades every release in place with identical manifests.
- **`render`** renders every release, or only the ones named; a name that is not one of the seven
  releases (`ztd`, `spire-crds`, `spire`, `istio-base`, `istiod`, `istio-cni`, `zone-policy`)
  stops it with a non-zero exit and the list of valid names, before anything is rendered.
- **`plan`** lists the seven steps without touching a cluster; `install` against an unreachable
  cluster prints the same list and refuses to continue, changing nothing.
- Every command first checks that the zone file exists, and stops with `zone file not found:
  <path>` and a non-zero exit when it does not. `help` (or `-h`, `--help`) prints the usage and
  exits 0; any other word prints the usage and `unknown command '<word>'` on stderr and exits 2.
- **`uninstall`** removes the releases in reverse order (`zone-policy`, `istio-cni`, `istiod`,
  `istio-base`, `spire`, `spire-crds`, then the umbrella, which takes the namespaces with it) and
  removes the CRDs each release owned, including the ones Istio's `base` chart marks to be kept by
  Helm. Delete the workloads in the plane namespaces first: a pod that still mounts the SPIFFE CSI
  volume when the driver goes holds its namespace in `Terminating`.

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
openings. The other releases read these zone facts from it:

| Release | Value | Zone fact |
|---|---|---|
| `spire` | `global.spire.trustDomain`, `global.spire.caSubject.commonName` | `zone.trustDomain` |
| `spire` | `global.spire.clusterName` | `zone.name` |
| `spire` | `global.spire.persistence.storageClass` | `zone.storageClass` |
| `istiod` | `meshConfig.trustDomain` | `zone.trustDomain` |
| `zone-policy` | `trustDomain` | `zone.trustDomain` |

A release whose zone fact is missing does not render, and the message names the fact.

## Pins

The chart versions and digests are at the top of `install.sh` and in `docs/dependencies.md`; the
container images are pinned by tag and digest in the values files under `deployment/helm/values/`. The SPIRE
charts come from `https://spiffe.github.io/helm-charts-hardened/` and are checked against their
sha256. The Istio 1.31 charts are not in Istio's Helm repository or OCI registry; they come from
the release archive `istio-1.31.4-linux-amd64.tar.gz`, checked against its published sha256. An
upgrade changes a version and its digest here and reruns `scripts/verify-mesh-identity/verify.sh`.

## Upgrading a zone in place

A zone moves to a new Istio pin without an uninstall: rerun the installer from the commit that
carries the pin, then restart the mesh proxies.

```bash
KUBE_CONTEXT=<context> scripts/install-zone/install.sh install
KUBE_CONTEXT=<context> scripts/install-zone/roll-proxies.sh
```

The installer upgrades `istio-base`, `istiod`, `istio-cni` and `zone-policy` in order, but it never
restarts a workload, so that a routine rerun does not restart a zone: a running pod keeps the
proxy it was injected with, and a fix in the proxy or its interception reaches the pod only when the
pod is recreated. `roll-proxies.sh` takes the pinned image from `zone-policy`'s
`proxySocketPolicy.proxyImage` and restarts (`kubectl rollout restart`, then `rollout status`)
only the Deployments, StatefulSets and DaemonSets whose pods carry a `proxyv2` container on another
image, init or regular: the proxies are native sidecars, so `istio-proxy` and `istio-validation` are
init containers. A workload whose pods carry no proxy is left alone, since restarting it in a
namespace with the injection label would inject a proxy it does not have. The script then lists
every pod in the cluster and exits non-zero, naming the pod, its namespace, the container and the
image, while any container still runs a `proxyv2` image other than the pinned one. Bare pods and
Job pods are not restarted; the check names them, and the operator deletes them once they may go.
`KUBE_CONTEXT` has no default in this script: it refuses to run without it.

A restarted workload that needs a manual step before it is Ready holds `rollout status` until that
step is done (`ROLLOUT_TIMEOUT`, 10 minutes by default). An OpenBao server that carries the mesh
proxy is one: it seals itself on every restart, so run `scripts/secrets/unseal.sh` while the script
waits on it. `unseal.sh` acts on kubectl's current context, not on `KUBE_CONTEXT`, so run it only
behind a check that the current context is the zone being upgraded (in a second shell, while
`roll-proxies.sh` waits; set `zone` to the context given to it as `KUBE_CONTEXT`):

```bash
zone=<context>
if [ "$(kubectl config current-context)" = "$zone" ]; then
  scripts/secrets/unseal.sh
else
  echo "the current context is not $zone: not unsealing" >&2
fi
```

The check looks at running pods only: a pod that has finished (`Succeeded` or `Failed`, such as a
completed Job's pod) runs no proxy, so its old image is not counted. It keeps the old image in its
spec until it is deleted or its Job is cleaned up.

**Short admission refusals.** Between the `istiod` step and the `zone-policy` step, the injector
already writes the new proxy image while the `proxy-takes-spire-socket` policy still admits only
the old one, so a plane pod created in that interval (a rescheduled or scaled pod) is refused with
a `FailedCreate` event. Nothing is lost: the pod's controller (its ReplicaSet, StatefulSet,
DaemonSet or Job) retries the creation with a growing backoff, and the first retry after the
`zone-policy` step is admitted. Because of the backoff, such a pod can stay missing for a minute or
two after that step; on kind the interval was about a minute between the first refusal and the
`zone-policy` step, and about three minutes until the pod was back. A bare pod is not retried;
`roll-proxies.sh` names any pod left on the old image. The policy is not widened to admit both
images during the move, because that would mean a template and schema change to a security policy
and a second step to narrow it again.

**A hook pod on a rerun.** On the first install the umbrella runs before istiod, so its hook pods
get no proxy; on a rerun a hook pod created in a meshed namespace gets the proxy injected. The
umbrella's OpenBao verification hook `ztd-verify-openbao` (with `openbao.enabled: true`, as in the
kind file `deployment/helm/ztd/ci/values.yaml`) therefore carries the identity label
`spiffe.io/spire-managed-identity: "true"` and runs with a ServiceAccount of its own: SPIRE issues
its proxy an SVID, and the hook completes. Without the label its pod would stay at `Init:1/2` and
the rerun would fail at step 1 (`docs/troubleshooting.md`). CI checks that every hook the umbrella
renders into a meshed namespace carries the label (`scripts/ci/check-hook-identity.sh`). The
OpenBao bootstrap is a regular Job, not a hook: a rerun leaves it alone unless its script or values
change, and it carries no identity label, so such a change on an installed zone is not covered.

**Rollback.** Rerun the installer from the previous commit (the previous pin), then
`roll-proxies.sh` from the same commit, so that the proxies return to the previous image. A release
that does not become Ready during an upgrade is already rolled back by the installer's lifecycle
step.

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

Last run (2026-10-09, `bash:3.2` container, GNU bash 3.2.57(1)-release, repository mounted
read-only): exit 0, all seven releases rendered (`ztd` 38 objects, `spire-crds` 3, `spire` 36,
`istio-base` 17, `istiod` 17, `istio-cni` 7, `zone-policy` 14), no `unbound variable`;
`render spire-crds` rendered the one release, and a zone copy with `mesh.revision: canary` exited 1
naming the key with nothing rendered. The script before the fix stopped there with
`want[@]: unbound variable` and still exited 0 having rendered nothing.

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
