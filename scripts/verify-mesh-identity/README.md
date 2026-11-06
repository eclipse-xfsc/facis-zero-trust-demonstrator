# verify-mesh-identity

Evidence that the mesh identities of a zone are SPIRE's, on the local kind cluster from
`scripts/dev/kind-cilium-up.sh` (Kubernetes v1.35.8, Cilium 1.20.2 with `cni.exclusive=false`) or on
one of the two participant clusters of zone A and zone B (Kubernetes v1.34.7, Cilium 1.18.8 installed
by the provider with `cni-exclusive=false`). `verify.sh` installs the zone from an empty cluster with
`scripts/install-zone/install.sh`, twice, runs the stand-in pods of `fixtures/stand-ins.yaml`,
proves each check below, and tears the zone down again (or, on a participant cluster with the keep
opt-in, records what it leaves installed).

## The run directory

Each run writes its record, `evidence.md` and `environment.json`, to a run directory outside the
repository and prints that directory as the last line of its output, alone, so a caller takes it
with `tail -n 1`:

- `ZTD_EVIDENCE_DIR` when set: created if missing and used as given (a relative path is the
  caller's); a directory inside the repository is refused (exit 125);
- otherwise a new directory per run,
  `${XDG_STATE_HOME:-$HOME/.local/state}/ztd/verify-mesh-identity/<context>/<UTC start>/`, the start
  written `YYYYMMDDTHHMMSSZ`; a run never reuses or changes an earlier run's directory.

On a participant cluster every IPv4 address in the record is written as `<address>`, except the
loopback `127.0.0.1`, which is no address of the cluster.

**The repository holds no record of a run.** A record is proof of a state at a time: what one
cluster looked like when one commit was run against it. It goes with the task that asked for that
state (its ticket notes), not into the repository, which keeps what lasts: this script and the
description below of what a run shows. A run changes nothing in the repository: `git status` after
it is what it was before.

## What a run shows

`evidence.md` has one section per step, each check written `PASS` or `FAIL` with what it read:

- **Header**: the cluster kind (kind, or the participant cluster with its zone and the keep opt-in),
  the context, the zone file and its trust domain, the commit and whether the tree was dirty; on a
  participant cluster the node the proof's pods are pinned to and why, and, for a trust domain
  ending in `.trust.invalid`, that it is interim.
- **0. Preconditions**: the cluster's Kubernetes version against the zone file's
  `zone.kubernetesVersion`, the cluster's Cilium (image and version, `cni-exclusive=false`, the
  pod-to-pod routing as found) and the inotify limit on every node.
- **1. Clean slate** and **2. `install-order-idempotent`**: the zone uninstalled, then installed
  from the empty cluster as seven releases, twice, with identical manifests.
- **3.** the identity-band checks of `zone-policy` on the install; **4.** the layout of the control
  planes; **5.** the stand-in pods, with the capture rule's refusal of the three proxyless ones,
  the per-node SVID stand-ins (`svid-on-<node>` in `spire-system`, one per node with a SPIRE agent,
  unmeshed, placed by their own node affinity, never pinned), and on a participant cluster the pin
  to istiod's node.
- **6.** to **12.** the checks of the table below: `svid-over-csi-socket` (with the SPIRE server's
  trust domain, the SVID's SPIFFE ID and the mesh's trust domain agreeing on the zone file's name,
  and, node by node, the SVID of the per-node stand-in in the zone's trust domain, chained to the
  SPIRE CA),
  `native-sidecar-version`, `mesh-identity-issued-by-spire`, `unregistered-workload-cut-off`,
  `traffic-through-the-proxies`, `default-deny-with-chained-cni` and
  `control-planes-under-default-deny` (with `metrics-endpoints-answer`: the SPIRE server's 9988 and
  the controller-manager's 8082 answering from the host of the server's node, beside the agents'
  loopback answer on every node).
- **13.** a declared registration without its entry failing the release; **14.** the render guards.
- **15. Teardown** (kind, a participant cluster without the keep opt-in, or any failed check; 16
  when a check of the record of what remains failed):
  nothing of the zone left behind, then the cluster's CNI read again, unchanged.
- **15. What remains installed** (participant cluster with the keep opt-in and every check passed):
  the CNI read back unchanged, then the seven releases `deployed`, SPIRE ready on every node, one
  attested agent per node, the three metrics endpoints answering again (server 9988,
  controller-manager 8082, the agents on each node's loopback), nothing of the proof's fixtures left
  (no stand-in pod, Service or ServiceAccount in either plane or in `spire-system`, no `kube-public`
  pod, no scratch namespace, no SPIRE entry for a stand-in identity), the trust domain in use
  (marked interim when it ends in `.trust.invalid`), and the pin with its limitation: the mesh is
  proven node-locally on these clusters, cross-node meshed traffic is not, until the provider
  changes its pod network. A kept zone on an interim trust domain is re-installed with its final
  name once that is confirmed, and is not acceptance evidence until then.
- **Result**: the number of failed checks and whether the zone was kept, and if not, why.

## Reading `environment.json`

`commit` and `dirty` describe the code that ran (the checked-out commit and whether the tree had
uncommitted changes); a run is never refused for the state of the tree. `date` and `finished` are
the UTC start and end. `host.kind` is the operator's machine; `tools` and `charts` the versions
used; `images` the images found running. `cluster` is the cluster as found: the context, `kind`
(`kind` or `provider`), the provider, the Kubernetes server version, the nodes and the CNI image; on
kind also `kindNodeImage` and `tools.kind`. `zone` names the zone file, its name and trust domain,
`trustDomainInterim`, `kept` and, when not kept, `notKept`. `result.failures` is the failed-check
count, also the exit status. For example:

```bash
d=$(scripts/verify-mesh-identity/verify.sh | tail -n 1)
jq '{commit, dirty, kept: .zone.kept, failures: .result.failures}' "$d/environment.json"
```

## Running it

On kind:

```bash
sudo sysctl -w fs.inotify.max_user_instances=512   # kind hosts: the Istio CNI agent needs it
scripts/dev/kind-cilium-up.sh
scripts/verify-mesh-identity/verify.sh             # destructive: uninstalls the zone first
scripts/verify-mesh-identity/verify.sh --help      # usage; touches nothing
```

On a participant cluster (zone B: `zerotrust-b` and `zone-b.yaml`):

```bash
# torn down at the end, as on kind
KUBE_CONTEXT=zerotrust-a ZTD_CONFIRM_CLUSTER=zerotrust-a \
  ZONE_VALUES=deployment/helm/ztd/zones/zone-a.yaml scripts/verify-mesh-identity/verify.sh
# left installed when every check passed
KUBE_CONTEXT=zerotrust-a ZTD_CONFIRM_CLUSTER=zerotrust-a ZTD_KEEP_ZONE=zerotrust-a \
  ZONE_VALUES=deployment/helm/ztd/zones/zone-a.yaml scripts/verify-mesh-identity/verify.sh
```

The run uninstalls and reinstalls the zone, so before it reads or writes anything it refuses every
context except:

- a kind cluster: the context is named `kind-<name>` and every node's provider ID starts with
  `kind://`;
- a confirmed participant cluster: the context is `zerotrust-a` or `zerotrust-b` and four facts
  hold: `ZTD_CONFIRM_CLUSTER` equals the context name (typed for this run); the context's API
  server host begins with `api.<context>.`; every node's provider ID begins with `onmetal://`; and
  every node name contains `--<context>-`. The last three bind the local context name to the
  cluster it points at, so a renamed context is caught without any address or domain in the
  repository. The zone file's `zone.name` must also be the context's zone (`zone-a` for
  `zerotrust-a`).

**The pin, on a participant cluster.** After the install the proof reads the node istiod runs on and
gives every pod it creates (the stand-ins, their `-capture-check` copies, the probe of the scratch
namespace, the `kube-public` pod of the registration step) a required node affinity on
`kubernetes.io/hostname` to that node. The provider's pod network masquerades pod traffic between
nodes to the node's address, so a meshed pod on another node would reach istiod as `remote-node`,
which no opening admits, and never start. A record says so in its header, the stand-ins section
and the record of what remains: the mesh is proven node-locally there, and cross-node meshed traffic
is not proven until the provider changes its pod network, after which the pin is removed. The pin
lives in `verify.sh` alone (the chart, the policies and the zone files carry none of it), and on
kind the scheduler places the pods as before. The one exception is the per-node SVID stand-ins
(`svid-on-<node>` in `spire-system`): each is placed on its own node by a required node affinity,
one per node with a SPIRE agent, and never pinned, so the SVID is shown on every node of the
cluster.

Every refusal names what was expected and exits 125; the IONOS cluster and the shared
namespace-only cluster are refused like any other name, whatever `ZTD_CONFIRM_CLUSTER` holds.

**The keep opt-in.** `ZTD_KEEP_ZONE` set to the context name leaves the zone installed on a
participant cluster, and only when every check passed: the teardown section is replaced by "What
remains installed", which records the seven releases `deployed`, the SPIRE server and the
controller-manager ready, the agent and CSI driver DaemonSets ready on every node, one attested
agent per node, the metrics endpoints answering (server 9988, controller-manager 8082, the agents on
each node's loopback), nothing of the proof's fixtures left in the zone, and the trust domain in use
(marked interim when it ends in `.trust.invalid`), after the cluster's CNI as found is read again.
Each of those is a check too; if one fails, the run tears the zone down after all. The zone counts
as kept only once its record is written to the run directory: an interrupt before then, or a failed
write, tears it down too. Without the opt-in, when any check failed, or when the run ends early (an
error, INT or TERM), the run leaves the cluster as it found it: on a participant cluster the exit
trap uninstalls the releases and deletes `ztd-system`. The keep opt-in is refused on kind (exit
125), and any value other than the context name is refused. The evidence and `environment.json`
(`zone.kept`, `zone.notKept`) say whether the zone was kept and, if not, why. A zone kept on an
interim trust domain is re-installed with the final name once it is confirmed, and is not acceptance
evidence until then.

A kept zone is removed by hand with:

```bash
KUBE_CONTEXT=zerotrust-a ZONE_VALUES=deployment/helm/ztd/zones/zone-a.yaml scripts/install-zone/install.sh uninstall
kubectl --context zerotrust-a delete namespace ztd-system
```

A re-run of the proof on a cluster that holds a kept zone needs neither: its clean-slate section
uninstalls the zone first and proceeds as from an empty cluster.

The script reads the cluster's CNI and never writes it: the Cilium DaemonSet (image, generation)
and `cilium-config` (resource version) are read before the clean slate and checked unchanged:
with the keep opt-in, as a check of the record of what remains, before the zone is declared kept;
otherwise after the uninstall. The inotify instance limit is read on every node, through the node's
own Cilium agent (`kubectl -n kube-system exec <cilium pod> -c cilium-agent -- cat
/proc/sys/fs/inotify/max_user_instances`), and must be 512 or more everywhere; on kind every node
shares this machine's kernel, hence the `sysctl` above.

It takes no arguments: `--help` or `-h` prints the usage, any other argument prints it and exits 125,
in both cases before the cluster is touched.

| Check | What it proves |
|---|---|
| `install-order-idempotent` | the seven releases install from an empty cluster with no manual step, every pod is Ready, every SPIRE and Istio image is pinned by digest, and a second run leaves every release's manifest identical |
| `svid-over-csi-socket` | a labelled pod mounts `csi.spiffe.io` and gets over that socket the SVID of its service account in the zone's trust domain, chained to the SPIRE CA; an unlabelled pod gets no entry and no SVID; on every node with a SPIRE agent a per-node stand-in (`svid-on-<node>`, one per node, unmeshed, in `spire-system`, placed by its own node affinity and not pinned) is Ready and gets over its node's socket `spiffe://<trust domain>/ns/spire-system/sa/stand-in`, chained to the SPIRE CA, one check per node |
| `native-sidecar-version` | the server is 1.33 or later; the proxy is an init container with `restartPolicy: Always` |
| `mesh-identity-issued-by-spire` | read with `istioctl proxy-config secret`: the proxy's certificate has `O = SPIRE`, the SPIRE CA as issuer, the SVID's URI SAN; its `ROOTCA` bundle is the SPIRE CA, and istiod's CA did not issue it; a pod that chooses its injection templates, brings its own proxy without the SPIRE socket, or runs Istio's agent under another container name is refused at admission; so is, under the capture rule (`capture-at-injector-defaults`), a pod that excludes an application port from the capture, switches the capture off (`NONE`), moves the status port, overrides its proxy's configuration, opts out of injection, swaps its proxy's image or brings its own `istio-proxy` container, and, under the proxy rule, an `istio-proxy` of another image on the SPIRE socket, a second proxy under another name, and an `istio-proxy` of the injector's image with its own `postStart` hook or `NET_ADMIN` (next to the same pre-set status with nothing added, admitted), and, under the socket rule, an `istio-proxy` that mounts the SPIRE socket volume with a `subPath`, while a pod annotated `prometheus.io/scrape` and `prometheus.io/port` is admitted with the injector's `ISTIO_PROMETHEUS_ANNOTATIONS`, while an ordinary pod is admitted carrying the injector's status-port exclusion and `REDIRECT`, and the istiod and `istio-cni` pods, which opt out of injection, are admitted in `istio-system` (no injection label) and refused in the data plane; a label added to a running pod is admitted (an update is checked for what it changes), an added excluded port refused, the same through the `pods/status` subresource refused, a status update that changes no annotation admitted, and the removal of `sidecar.istio.io/status` from a running injected pod refused; outside the plane namespaces istiod's 15012 is not reachable; a certificate signed with istiod's CA key for the caller's SPIFFE ID is refused by the meshed peer, the caller's SPIRE SVID accepted |
| `unregistered-workload-cut-off` | an unlabelled pod's proxy has no certificate, its application never starts, and the peer refuses a call from its network namespace under STRICT; the labelled pod's call succeeds |
| `traffic-through-the-proxies` | the peer sees the caller's SPIFFE ID in `X-Forwarded-Client-Cert`; both proxies count the request, as mTLS |
| `default-deny-with-chained-cni` | the Istio plugin is chained after Cilium on the node, `cni-exclusive=false`, and the umbrella's cross-plane denial and matrix lane hold with the proxies in place |
| `control-planes-under-default-deny` | `spire-system` and `istio-system` hold only the declared openings; no SPIRE pod has a sidecar; every agent is attested; the proxies are SYNCED; a stand-in pod's TCP probes to the SPIRE server and istiod on every port but istiod's xDS port are denied; the agents' metrics port listens on each node's loopback only and answers there with `spire_agent` samples; `metrics-endpoints-answer`: the SPIRE server's metrics (pod port 9988) answer with `spire_server_` samples and the controller-manager's (8082) with `controller_runtime_` samples, read from the host of the server pod's node through its Cilium agent (read-only `kubectl exec`, no lane, no pod), while the same ports stay denied from both planes |

It also shows the identity-band checks of `zone-policy` passing on the install and failing the
release when a declared registration has no entry, the render guards (no trust domain, Kubernetes
below 1.33, no Cilium, a `planes.namespaceLabels` key the umbrella sets itself; and, for every
shipped zone file, the DNS bypass on its resolver port, the webhook relay `fromEndpoints` only where
the file names it, and its namespace labels on every namespace), and a teardown in reverse order that deletes `ztd-system` last and leaves
no plane, control-plane or release namespace, no SPIRE or Istio CRD and no admission webhook
behind. The registration-failure step labels `kube-public` (ignored by the controller-manager on
every cluster) as a plane for its duration, and unlabels and empties it again.

Needs `kind` (on kind), `kubectl`, `helm` (v4.3.0), the `cilium` CLI, `istioctl` 1.31.1, `jq`, `openssl`,
`python3` with PyYAML and `git`; the versions are recorded in `environment.json`. It refuses to run under
CI (`CI` set): the evidence is the record of a run on a cluster, never written by a pipeline. The
exit status is 0 when every check passed, the number of failed checks (1 to 124, capped at 124)
otherwise, 125 when the run was refused or not started (an argument, `CI`, the context guard, a
run directory inside the repository: nothing written), and 130 or 143 when it was interrupted.

The stand-in pods run the images the umbrella's own verification uses (agnhost, curl) and SPIRE's
agent image as the Workload API client; nothing about them is consumed by a zone.

Three stand-ins have no proxy (`unregistered-svid` and the two `probe` pods): they opt out of
injection, which the capture rule refuses in a plane namespace. The proof shows them refused as
written, creates them with only the capture validation lifted from `proxy-takes-spire-socket`, puts
the validation back unchanged and shows them refused again, all in section 5 of the evidence. The
refusals are asked with a server-side dry-run create of a renamed copy of the three, so each is a
real admission request even once the stand-ins exist. Each API server replica takes up a policy
change on its own (a provider's control plane runs more than one), so the create is retried while
the capture rule still refuses it, and the check of the restore requires the refusal to hold five
times in a row, a second apart; the validation is lifted for at most about 45 seconds. If the run
exits while the validation is lifted (an interrupt included), its exit trap puts the validation
back, and says so on stderr when it cannot. The status port the
admitted-pod check expects is read from the installed `zone-policy` release
(`helm get values --all`), not from the chart's defaults.
