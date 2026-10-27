# T-Systems Open Sovereign Cloud — zone A and zone B

The two demonstration zones. Zone A holds the participant backend that makes the call; zone B holds
the protected resource it calls. Each is a separate cluster with its own workload identity,
admission control and policy enforcement, and the interesting part of the demonstrator is what
happens between them.

The two clusters were provided on 9 October 2026 and the facts on this page were read off them on
10 October 2026; the provider's Cilium was read again on 25 October 2026, after the provider moved it
to 1.19.6 and to a VXLAN overlay on 21 October. Steps 1 to 4 have been run on both: the proof on
every node has been run on the local kind cluster with the default kind zone file and on zone A and
zone B with their zone files and the keep opt-in, the release `ztd-openbao` included, and every check
passed; both zones are left installed on their interim trust domains (see
[What has been run](#what-has-been-run)).
Steps 5 to 7 have not been run.

## Before you start

You need:

- a kubeconfig for each of the two clusters, with rights to create namespaces and cluster-scoped
  resources. This guide uses the context names the delivered kubeconfigs carry: `zerotrust-a` for
  zone A and `zerotrust-b` for zone B; the mesh-identity proof accepts those two names only;
- network reachability from both clusters to the registries the pinned images are pulled from;
- the zone files `deployment/helm/ztd/zones/zone-a.yaml` and `zone-b.yaml`. Their trust domains
  are **interim**, `zone-a.trust.invalid` and `zone-b.trust.invalid`, until the DNS zone delegated
  to the trust framework is named and the Technical Design Authority confirms the final names
  `zone-a.<zone>` and `zone-b.<zone>`; a zone installed on an interim name is re-installed with the
  final one ([Workload identity](../workload-identity.md#the-trust-domain));
- the DNS zone delegation for the trust framework in place before the trust-list steps (5 to 7),
  which resolve the trust framework's records;
- Helm v4.3.0, the version the pipeline pins, kubectl, `jq`, `curl`, `openssl` and `python3` with
  PyYAML (the zone installer and the proof), istioctl 1.31.1 and the `cilium` CLI;
- this repository checked out.

Check the version first — everything below assumes 1.29 or later, and the mesh needs 1.33 or later:

```bash
kubectl --context zerotrust-a version -o json | jq -r '.serverVersion.gitVersion'   # v1.34.7
```

## 1. CNI: verify the provider's Cilium

Cilium on these clusters is installed and upgraded by the provider (Gardener). It is **not**
installed by us and must not be re-installed, upgraded or reconfigured: the zone only verifies it.
The Istio CNI plugin chains behind it, which needs `cni-exclusive=false`, and the provider already
sets it. For each context:

```bash
kubectl --context zerotrust-a -n kube-system get ds cilium \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'          # .../cilium:v1.19.6
kubectl --context zerotrust-a -n kube-system get cm cilium-config \
  -o jsonpath='{.data.cni-exclusive} {.data.bpf-lb-sock-hostns-only}{"\n"}'   # false true
kubectl --context zerotrust-a -n kube-system get cm cilium-config \
  -o jsonpath='{.data.routing-mode} {.data.tunnel-protocol} {.data.ipv4-native-routing-cidr}{"\n"}'   # tunnel vxlan
kubectl --context zerotrust-a -n kube-system get ds cilium                 # 3 desired, 3 ready
```

**Verify:** the image tag is `v1.19.6`, `cni-exclusive` is `false`, `bpf-lb-sock-hostns-only` is
`true` (socket load-balancing stays in the host namespace, so the sidecars see service traffic),
the routing mode is `tunnel` with the `vxlan` protocol and no native-routing range, and every Cilium
pod is ready. In tunnel mode a pod's traffic to a pod on another node keeps the pod's address, so
the destination sees the source pod and its identity, and the policies that admit pods by namespace
or label match across nodes. In native routing with masquerading on, a node whose pod range lies
outside `ipv4-native-routing-cidr` would reach the other nodes' pods with the node's address
instead; the proof's routing check fails on that, naming the nodes. The proof reads the same values
and checks at its end that the DaemonSet and its ConfigMap are unchanged by the run.

Facts read off both clusters on 10 October 2026:

| Fact | zone A (`zerotrust-a`) and zone B (`zerotrust-b`) | Read with |
|---|---|---|
| Kubernetes | `v1.34.7` | `kubectl version` |
| Nodes | three workers, Garden Linux 2150.7.0, containerd 2.2.6, provider IDs `onmetal://` | `kubectl get nodes -o wide` |
| Cilium (read on 25 October 2026) | 1.19.6, the provider's DaemonSet, `cni-exclusive=false`, `bpf-lb-sock-hostns-only=true`, kube-proxy replacement, `policy-cidr-match-mode=nodes`; tunnel routing (`routing-mode=tunnel`, `tunnel-protocol=vxlan`, no `ipv4-native-routing-cidr`), with iptables masquerading on (`enable-ipv4-masquerade=true`, `enable-bpf-masquerade=false`) for traffic that leaves the node outside the tunnel | `kubectl -n kube-system get ds cilium`, `get cm cilium-config`; `cilium-dbg status` in a Cilium pod (`Routing: Network: Tunnel [vxlan]`) |
| StorageClass | `default` (the default class, `csi.onmetal.de`) | `kubectl get storageclass` |
| CoreDNS | in `kube-system`, labelled `k8s-app=kube-dns` (the chart default), listening on 8053 behind the Service's port 53 | `kubectl -n kube-system get svc kube-dns` |
| Pod mutation by the provider | `kubernetes-service-host.resources.gardener.cloud` sets `KUBERNETES_SERVICE_HOST` to the API server's public name in every new pod, except in namespaces labelled `apiserver-proxy.networking.gardener.cloud/inject: disable` | `kubectl get mutatingwebhookconfiguration gardener-resource-manager-shoot` |
| API server | outside the cluster, reached through the provider's `apiserver-proxy` pods; the `kubernetes` Service's endpoint port is 443 | `kubectl get endpointslices -n default -l kubernetes.io/service-name=kubernetes` |
| inotify instances | 8192 on every node | through each node's Cilium agent (below) |
| Before the first install | empty: no namespace beyond `default`, `kube-system`, `kube-public`, `kube-node-lease` | `kubectl get ns` |

The inotify instance limit is read on every node through its Cilium agent, read-only:

```bash
for p in $(kubectl --context zerotrust-a -n kube-system get pod -l k8s-app=cilium -o name); do
  kubectl --context zerotrust-a -n kube-system exec "$p" -c cilium-agent -- cat /proc/sys/fs/inotify/max_user_instances
done
```

## 2. The zone layout

Steps 2 to 4 and the secret store are one command. The zone installer installs the zone from its
zone file as eight Helm releases, in this order, each through the deployment lifecycle step (`scripts/lifecycle.sh`: a
server-side dry run, then `helm upgrade --install --wait` with rollback on failure), each waiting on
the previous, and stops at the first release that fails, naming it:

| # | Release | Namespace | Chart | Step |
|---|---|---|---|---|
| 1 | `ztd` | `ztd-system` | `deployment/helm/ztd`, the umbrella | 2 |
| 2 | `spire-crds` | `spire-system` | `spire-crds` 0.6.1 | 3 |
| 3 | `spire` | `spire-system` | `spire` 0.30.2 (SPIRE v1.15.3) | 3 |
| 4 | `istio-base` | `istio-system` | Istio `base` 1.31.1 | 4 |
| 5 | `istiod` | `istio-system` | Istio `istiod` 1.31.1 | 4 |
| 6 | `istio-cni` | `istio-system` | Istio `cni` 1.31.1 | 4 |
| 7 | `zone-policy` | `istio-system` | `deployment/helm/zone-policy` | 3 and 4 |
| 8 | `ztd-openbao` | `ztd-mgmt` | `deployment/helm/ztd-openbao`, wrapping `openbao` 0.28.3 (OpenBao v2.5.4) | [the secret store](#the-secret-store) |

The zone files record each cluster: `deployment/helm/ztd/zones/zone-a.yaml` and `zone-b.yaml`
(`zones/zone-a.example.yaml` shows each fact with the command that reads it). Each states:

- `zone.name` `zone-a` or `zone-b`, `zone.kubernetesVersion: v1.34.7`, `zone.storageClass: default`,
  `zone.loadBalancer.type: cloud` (the provider provisions LoadBalancer Services; nothing in the
  zone exercises one yet);
- `zone.trustDomain`: the zone's SPIFFE trust domain, a name under the DNS zone delegated to the
  trust framework, one per zone, today the interim `zone-a.trust.invalid` / `zone-b.trust.invalid`.
  It is fixed in the SPIRE root CA at install
  ([Workload identity](../workload-identity.md#the-trust-domain)); without it nothing renders;
- `mesh.mode: sidecar`, `cni.cilium.enabled: true`, the control-plane namespaces `spire-system`
  and `istio-system` in `planes.extra` with `mesh: false`, and the openings `meshControlPlane`,
  `controlPlaneWebhooks` and `identityServer` enabled;
- `networkPolicy.kubeApi` enabled with port 443 and no address: under Cilium the API lane and the
  openings are entity policies, and no IP-based rule is written;
- the DNS bypass to CoreDNS (`k8s-app=kube-dns`, the chart default) on port **8053**, the port its
  pods listen on behind the `kube-dns` Service's port 53 (a network policy matches the pod's port);
- `planes.namespaceLabels` with `apiserver-proxy.networking.gardener.cloud/inject: disable` on every
  namespace the umbrella creates. Without it the provider's webhook
  `kubernetes-service-host.resources.gardener.cloud` sets `KUBERNETES_SERVICE_HOST` in every new pod
  to the API server's public name, which Cilium sees as `world`: SPIRE and istiod could not reach
  the API through the `kubeApi` lane, which admits the `kube-apiserver` entity only. With the label
  the pods use the `kubernetes` Service, as on any other cluster.

The releases after the umbrella read the zone facts they need from the umbrella's defaults with the
zone file on top, so the management namespace (`ztd-mgmt`) and the Cilium switch reach `ztd-openbao`
without the zone file repeating them; `zone.storageClass` it states.

Then plan, and install:

```bash
ZONE_VALUES=deployment/helm/ztd/zones/zone-a.yaml KUBE_CONTEXT=zerotrust-a \
  scripts/install-zone/install.sh plan
ZONE_VALUES=deployment/helm/ztd/zones/zone-a.yaml KUBE_CONTEXT=zerotrust-a \
  scripts/install-zone/install.sh install
```

(zone B: `zone-b.yaml` and `zerotrust-b`). The installer itself has no cluster guard; the
mesh-identity proof below runs it behind an explicit opt-in.

The installer exits 0 only when every release is deployed and every pod of the plane and
control-plane namespaces is Ready; run again, it changes nothing. Its
[README](https://github.com/eclipse-xfsc/facis-zero-trust-demonstrator/tree/main/scripts/install-zone)
lists the tools it needs.

The first release, the umbrella, lays the zone down before any component is installed: the
management and data-plane namespaces and the two control-plane namespaces, default-deny network
policies in both directions, the declared openings, the allow-matrix lanes from the data plane
into the management plane, and the hook-weight bands the jobs of the components plug into. It
creates every namespace the later releases install into; they create none.

**Verify:** `ztd-mgmt` and `ztd-data` exist with their `ztd.facis.io/plane` label and the mesh
label for the zone's mode, `spire-system` and `istio-system` with the plane label and without the
mesh label, each holds a `default-deny` NetworkPolicy, and the release's post-install verification
job completed; the release fails on its own if the layout is not what the chart declared. The
design, the bands and the evidence script are in [Umbrella chart](../umbrella-chart.md).

## 3. Workload identity

Releases 2 and 3 install SPIRE into `spire-system`, in this order: `spire-crds` (its CRDs), then
`spire` (the server, the agents on every node, the SPIFFE CSI driver and the controller-manager), so
that SVIDs reach workloads through a mounted volume rather than through a secret. Release 7,
`zone-policy`, registers the workloads by
selector: every pod with `spiffe.io/spire-managed-identity: "true"` in a plane namespace gets
`spiffe://<trust domain>/ns/<namespace>/sa/<service account>`. The registration is a regular
resource that the controller-manager reconciles into entries, never a hook job; the jobs that check
the server, the trust bundle and the entries sit in the `identity` band of the hook-weight scheme
and fail the release when identity is not there. Details: [Workload identity](../workload-identity.md).

The zone facts this step needs, in the zone file `deployment/helm/ztd/zones/<zone>.yaml`:

- `zone.trustDomain`: the zone's SPIFFE trust domain, a name under the DNS zone delegated to the
  trust framework (interim `zone-a.trust.invalid` / `zone-b.trust.invalid` until the Technical Design
  Authority confirms the final names), fixed in the SPIRE root CA at install;
- `spire-system` in `planes.extra` with `mesh: false`, and the openings `identityServer` and
  `controlPlaneWebhooks` enabled;
- `networkPolicy.kubeApi` enabled with the API server's port, which the agents and the
  controller-manager need.

The same installer command as step 2 installs these releases, after `ztd`:

```bash
ZONE_VALUES=deployment/helm/ztd/zones/<zone>.yaml KUBE_CONTEXT=<context> \
  scripts/install-zone/install.sh install
```

**Verify:** the installer reports `spire-crds`, `spire` and `zone-policy` deployed (the identity checks passed);
`kubectl -n spire-system exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server agent
list` shows one attested agent per node that runs workloads; a labelled test pod receives, over the
mounted socket, an SVID whose SPIFFE ID matches its service account
([Checking an identity](../workload-identity.md#checking-an-identity)). The record of the mesh-identity
proof now carries the registration inventory too (section 14, `registration-inventory`): every
entry on the server next to the pod that holds it and its certificate in use, by SPIFFE ID
([declared workloads](../workload-identity.md#declared-workloads-and-the-registration-inventory)).

## 4. Mesh

Releases 4 to 6 install Istio in sidecar mode, with the default, unrevisioned istiod (sidecar under
[ADR-0009](../adr/0009-service-mesh-mode-istio-sidecar-with-cilium.md), which superseded the ambient
baseline of ADR-0001; ambient is the parked alternative) into `istio-system`: its CRDs, istiod, and
the Istio CNI plugin chained behind Cilium. Sidecar mode is the only mode the installer installs:
it refuses, before it renders or installs anything, a zone file whose `mesh.mode` is not `sidecar`
(absent counts as sidecar) or whose `mesh.revision` is set, and names the setting. The plane namespaces already carry the matching label,
`istio-injection=enabled`. Sidecars are injected as native sidecar containers, which is why the
cluster's Kubernetes version is recorded in the zone file against that requirement. The sidecar
takes its certificate and its trust bundle from the SPIRE agent over SDS, never from istiod, and
release 7 makes mutual TLS `STRICT` mesh-wide, so a workload without a SPIRE entry has no mesh
identity and no mesh connection. Exactly one component enforces L7 policy on any given traffic
path — where the sidecar does it, Cilium is held to L3/L4 for that path, and the assignment is
recorded in the mesh configuration.

**Verify:** every pod in a plane namespace carries the injected proxy as a native sidecar
(`istio-proxy` among its init containers with `restartPolicy: Always`); `istioctl proxy-config
secret <pod>` shows `default` and `ROOTCA` issued by the SPIRE CA; a request between two meshed
workloads carries a SPIRE-issued identity. The mesh identity proof shows all of it, on kind and on
these clusters: the next section.

### The secret store

Release 8, `ztd-openbao`, installs OpenBao into the management plane after `zone-policy`, so its
server, its bootstrap Job and its verification hook are created with a sidecar, a SPIRE entry and an
SVID ([Secrets](../secrets.md)). The bootstrap initialises and unseals the server and keeps the unseal
key in the Secret `ztd-openbao-bootstrap`; the verification hook fails the release unless the store is
unsealed with KV version 2 and transit.

**Verify:** the installer reports `ztd-openbao` deployed (the verification hook passed);
`kubectl -n ztd-mgmt logs job/ztd-verify-openbao -c verify` ends with `OpenBao verified`; the
mesh-identity proof lists `ztd-mgmt/ztd-openbao-0` as a matched declared workload. After a restart
the installer did not cause, the server is sealed until `scripts/secrets/unseal.sh` is run against
the zone's cluster (the script uses the current kube context).

**Placement.** No release of the zone is held to a node: the OpenBao server and both of its jobs
carry no node affinity or node selector, and the scheduler places them. The server's volume
(StorageClass `default`, `csi.onmetal.de`, `WaitForFirstConsumer`) has no node affinity, and the
three nodes of a zone share one availability zone, so a server that lands on another node finds its
volume there.

Earlier the zone files of zone A and zone B held the server and its jobs on istiod's node, a
temporary pin set while the provider's pod network masqueraded pod traffic between nodes (a meshed
pod on another node than istiod could not reach istiod on 15012 and stayed in `Init:1/2`). The pin
went once the proof on every node had passed on both zones (26 October 2026, with the pin in place),
and a zone file that still sets it is refused by the umbrella's schema. The zones as installed by
those runs still carry it: their OpenBao pods stay on istiod's node until the zone is installed
again. The next `scripts/install-zone/install.sh install` of a zone, an upgrade of the release,
drops the placement: the server restarts wherever the scheduler places it, its volume attaches
there, and the bootstrap unseals it with the stored key, so the store keeps its data. Only a proof
run, whose clean slate uninstalls the zone, resets the store. Neither has been run on the zones
since ([What has been run](#what-has-been-run)).

## Proving steps 2 to 4: the mesh-identity proof

`scripts/verify-mesh-identity/verify.sh` installs the zone from the empty cluster with the zone
installer, twice, and proves every verification of steps 2 to 4 with stand-in pods: the SVID over
the CSI socket, the proxy's certificate from SPIRE, the trust domain shared by SPIRE, the SVID and
the mesh, the Istio plugin chained behind the provider's Cilium, the default deny with both
control planes inside it, the server version against the native-sidecar floor, and the provider's
CNI unchanged. It places a meshed stand-in on every node and shows each one Ready with a
SPIRE-issued certificate, a call from every node to the next one across a node boundary, and the
refused paths with the caller on another node than the peer; no pod is held to istiod's node. Its
routing check fails the run when the pod network would masquerade pod traffic between nodes, and
stops it among the preconditions, before anything is uninstalled or installed. It refuses these
clusters unless the run is confirmed: the context is `zerotrust-a`
or `zerotrust-b`, `ZTD_CONFIRM_CLUSTER` equals it, the API server host begins with
`api.<context>.`, and every node is an `onmetal://` node named for that cluster
([verify-mesh-identity](https://github.com/eclipse-xfsc/facis-zero-trust-demonstrator/tree/main/scripts/verify-mesh-identity)).

Run and torn down, leaving the cluster as it was found (empty):

```bash
KUBE_CONTEXT=zerotrust-a ZTD_CONFIRM_CLUSTER=zerotrust-a \
  ZONE_VALUES=deployment/helm/ztd/zones/zone-a.yaml scripts/verify-mesh-identity/verify.sh
```

Run and left installed, when every check passed:

```bash
KUBE_CONTEXT=zerotrust-a ZTD_CONFIRM_CLUSTER=zerotrust-a ZTD_KEEP_ZONE=zerotrust-a \
  ZONE_VALUES=deployment/helm/ztd/zones/zone-a.yaml scripts/verify-mesh-identity/verify.sh
```

With `ZTD_KEEP_ZONE`, a run whose every check passed leaves the eight releases installed in
`ztd-system`, `spire-system`, `istio-system` and `ztd-mgmt` with the two plane namespaces, removes its
stand-in pods, and ends its evidence with "What remains installed": the releases `deployed`, the
OpenBao server ready, the SPIRE
server and controller-manager ready, one agent and one CSI driver pod ready per node, one attested
agent per node, and the trust domain in use. A run that stops before its clean slate (a failed
routing check, or an error or interrupt among the preconditions) uninstalls and installs nothing:
the cluster is left as found, a zone it already runs included. Past the clean slate, a failed check
or an interrupted run tears the zone down whatever the opt-in; without it the run always does. A kept zone runs on its **interim trust
domain** until the re-install with the final name; it is not acceptance evidence until then. A
re-run of the proof on a kept zone starts from its clean slate, which uninstalls the zone first
(and so regenerates the SPIRE root CA and every SVID).

SPIRE's metrics endpoints are exposed on fixed ports (the server and the agents on 9988, the
agents' bound to the node's loopback; the controller-manager on 8082) but nothing in the zone
scrapes them yet: that belongs to the observability work.

Each run writes its record (`evidence.md`, `environment.json`) to a run directory outside the
repository, `ZTD_EVIDENCE_DIR` when set, else a new directory under
`${XDG_STATE_HOME:-$HOME/.local/state}/ztd/verify-mesh-identity/<context>/`, and prints that
directory as its last line; every IPv4 address of the cluster is written as `<address>` in it. The
repository holds no record of a run: a record is proof of a state at a time and goes with the task
that asked for it. What a run shows, section by section, is in
`scripts/verify-mesh-identity/README.md`.

### What has been run

Both zones are **left installed** on their interim trust domains by the runs of the proof on every
node below. The provider's Cilium routes in tunnel mode (VXLAN), read off both clusters on 25 October
2026 and again by the routing check of those runs.

The proof on every node, with none of its own pods pinned, has been run on the local kind cluster (two workers, a
fresh cluster from `scripts/dev/kind-cilium-up.sh`) with the default kind zone file
(`deployment/helm/ztd/ci/values.yaml`), and on 26 October 2026 on zone A and zone B (three nodes
each) with `zones/zone-a.yaml` and `zones/zone-b.yaml` and the keep opt-in, each time with the eight
releases, `ztd-openbao` included, from a clean tree, and every check passed. In each run the routing
check passed in tunnel mode, the store's bootstrap reached `configured` and its verification hook
passed, a meshed stand-in ran Ready on every node with a SPIRE-issued certificate, each node's
stand-in called the next node's across the node boundary (three calls on each zone) with the
caller's SPIFFE ID seen by the receiver and both proxies counting mutual TLS, and the cross-plane call
and the unregistered workload's call were refused from a node other than the peer's. On both zones
the OpenBao server and its jobs ran on istiod's node, where the zone files and the installer of that
date still pinned them, and the record of what remains found the eight releases deployed and none of
the proof's fixtures left; the zones were kept. A run on a zone resets its secret store: the clean
slate uninstalls the zone, and the reinstall bootstraps a new, empty store. What a run shows, section
by section, is in `scripts/verify-mesh-identity/README.md`.

That pin has since been removed ([the secret store](#the-secret-store)): no release of a zone is held
to a node, and the proof checks on every cluster that no pod of `ztd-openbao` carries a node
affinity. After the removal the proof was run again on a fresh kind cluster with the default kind
zone file from a clean tree, and every check passed, that one included. Zone A and zone B have not been installed again since, so
their OpenBao pods still run on istiod's node as those runs left them. An install of a zone frees
them from istiod's node without resetting the store, and a proof run frees them and resets it; neither has
been made yet. The proof's own placement is in the proof alone, and the charts
and the policies carry none of it.

The lanes admit no workload by address and are not widened to node addresses, which would admit
every pod on every node (the one address the chart admits is the kubelet probe address of the parked
ambient mode, rendered only in that mode). They need the pod network to keep a pod's address between
nodes, as the tunnel does; should the provider's routing change to masquerade pod traffic between
nodes, the proof's routing check fails and [troubleshooting](../troubleshooting.md) gives the
diagnosis. The re-install on the final trust-domain names is a run of its own.

## 5. Admission control

OPA Gatekeeper is installed together with the signature-verification external-data provider. From
this point an image whose Cosign signature does not verify against the client key material cannot
start.

**Verify:** deploy an unsigned image and confirm it is refused, and that the refusal names the
reason code rather than a generic admission error. A cluster where that image starts is not
configured.

## 6. The demonstrator workloads

The demonstrator services install into the data plane as regular resources; the jobs they bring
sit in the `workloads` band of the hook-weight scheme. A workload cannot become READY before its
identity exists: its container does not start until the SPIFFE CSI driver has mounted the socket
directory, and it holds no SVID until the agent answers on that socket with a matching
registration.

**Verify:** the management and data-plane namespaces both reconcile, no pod is in `CrashLoopBackOff`,
and the demonstrator UI answers.

## 7. The trust boundary between the zones

With both zones up, the attested channel between them is exercised. Both ends present evidence of
the software they are running, and that evidence is bound to the TLS connection it was presented on.

**Verify:** run the successful journey end to end from zone A, then the tampered-measurement
journey, and confirm the second one aborts the handshake before any application traffic flows.

## Teardown

Components uninstall in the reverse order of their installation; the layout goes last. The
installer does it for the eight releases, `ztd-openbao` first, which destroys the store (its volume
and its bootstrap Secret go with the management namespace). Helm removes the SPIRE CRDs with
`spire-crds`; Istio's `base` chart marks its CRDs to be kept by Helm, so the installer deletes the
CRDs that release owned:

```bash
ZONE_VALUES=deployment/helm/ztd/zones/<zone>.yaml KUBE_CONTEXT=<context> \
  scripts/install-zone/install.sh uninstall
```

The umbrella's release namespace `ztd-system` remains: the installer creates it before the first
release and no release owns it. It holds nothing once the umbrella is uninstalled; delete it last
(this is also how a zone kept by the proof is removed by hand; the proof's own teardown does both):

```bash
kubectl --context <context> delete namespace ztd-system
```

**Verify:** no namespace, CRD or secret belonging to the demonstrator survives. This is asserted by
an acceptance scenario, not by eye.

## Operations

- **Logs and traces** are collected by the OpenTelemetry Collector and read through the Prometheus
  and Jaeger interfaces; there is no Grafana in this deployment, and
  [why](../specifications.md#readings-and-additions) is recorded.
- **A refusal is diagnosed by its reason code**, not by grepping for stack traces — see
  [Troubleshooting](../troubleshooting.md).
- **Certificate and key material** lives in OpenBao and is never written into a chart value or a
  container image.
