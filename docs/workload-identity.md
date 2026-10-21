# Workload identity

Every workload of a zone proves who it is with an X.509 SVID that SPIRE issues, and the service
mesh uses that SVID, and nothing else, for its mutual TLS. This page describes the identity path as
the repository installs it: where its parts live and why, how the zone's trust domain is named, how
a workload is registered, which network openings the two control planes need under the default
deny, the contract between the SPIRE agent and the mesh proxy, and how to check on a live cluster
that an identity is SPIRE's. [ADR-0009](adr/0009-service-mesh-mode-istio-sidecar-with-cilium.md)
records why the mesh runs in sidecar mode; the [evidence](evidences/mesh-identity/README.md) is
the executed proof on the kind cluster.

## The identity path

```
SPIRE server ◄── agent (DaemonSet, host network) ──► kubelet (localhost): attests the pod
(spire-system)        │ Workload API socket
     ▲                ▼
     │      SPIFFE CSI driver ── read-only volume csi.spiffe.io ──► istio-proxy of the pod
controller-manager                                                 (native sidecar)
  reconciles the ClusterSPIFFEID                                   │ SDS: "default", "ROOTCA"
  into entries on the server                                       ▼
                                                     mesh mTLS with the SPIRE SVID, STRICT
istiod (istio-system): configuration (xDS) and injection only, never a workload certificate
```

1. A pod that carries `spiffe.io/spire-managed-identity: "true"` in a plane namespace is selected by
   the zone's `ClusterSPIFFEID`; the SPIRE controller-manager writes a registration entry for it on
   the SPIRE server.
2. The injected proxy mounts the SPIFFE CSI driver's volume, which carries the SPIRE agent's
   Workload API socket. The agent attests the calling pod through the kubelet and, when an entry
   matches, serves its SVID and the trust bundle over the Envoy SDS API.
3. The proxy uses that certificate for every mesh connection. The mesh-wide `PeerAuthentication`
   is `STRICT`, so a proxy without a certificate can neither reach a peer nor be reached.

## Where the control planes live

Both control planes are management-plane namespaces of the umbrella chart, created through
`planes.extra` with `mesh: false`: `spire-system` holds the SPIRE server, the controller-manager,
the agents and the CSI driver; `istio-system` holds istiod and the Istio CNI node agent. They get
the plane label, the default deny and the baseline lanes, and no injection label, so no SPIRE or
mesh control-plane pod receives a sidecar; the umbrella's verification job fails the release if
either carries one.

The reason is the test the [architecture](architecture.md) uses for the management plane: whether
reaching a component grants the ability to alter what the system runs, trusts or holds. The SPIRE
server issues every identity of the zone, and istiod pushes the configuration of every proxy; both
pass that test. A separate namespace for each keeps the openings each one needs (below) scoped to
it, instead of applying them to every management component in `ztd-mgmt`. `istio-system` keeps its
name because Istio's mesh root namespace, and with it the mesh-wide `PeerAuthentication`, lives
there by convention.

## The trust domain

Each zone is its own SPIFFE trust domain; zones never federate. The **trust domain of a zone is
the DNS zone delegated to that trust zone**: the zone the trust framework already requires as a
precondition, in which the trust-list pointers and the connector's `did:web` identifier are
published. One name, one owner, no second namespace of names. The trust domain itself is never
resolved; only the trust framework's records are.

| Zone | `zone.trustDomain` |
|---|---|
| kind (local proof) | `kind.facis-ztd.local`, the local fixture zone the trust-list verification uses; a `.local` name is acceptable here and nowhere else |
| zone A, zone B | the delegated DNS name, recorded in the zone file when the delegation exists and confirmed by the Technical Design Authority; until then the field is empty and the umbrella does not render |
| IONOS | none: `mesh.mode: none`, no identity path |

`zone.trustDomain` is a zone fact with no default; the umbrella's schema requires it wherever
`mesh.mode` is not `none`. The zone installer passes the same value to SPIRE
(`global.spire.trustDomain`) and to the mesh (`meshConfig.trustDomain`), so the three cannot
disagree; a mismatch would otherwise fail only at the first mTLS handshake. **The name is fixed at
the first install:** it is baked into the SPIRE server's root CA, so changing it means
reinstalling SPIRE and reissuing every identity. The `spiffe://zone-a…` examples in the attested
channel documentation and in test fixtures are illustrative.

## Registration

The `zone-policy` chart renders one `ClusterSPIFFEID`, `plane-workloads`:

| Field | Value |
|---|---|
| SPIFFE ID | `spiffe://<trust domain>/ns/<namespace>/sa/<service account>` |
| pod selector | `spiffe.io/spire-managed-identity: "true"` |
| namespace selector | the umbrella's plane label `ztd.facis.io/plane` exists |

The label, not the namespace alone, is the switch: a pod without it gets no entry, no SVID and,
under STRICT, no mesh connection, even in a meshed plane namespace. The demonstrator workloads'
charts set the label on their pods. The registration is a regular resource that the
controller-manager reconciles, never a hook job: a workload waiting for an entry that a hook
creates would make `helm install --wait` time out ([umbrella chart](umbrella-chart.md#the-hook-weight-scheme)).
The SPIRE chart's own registrations (one of which would give every pod an identity) are switched
off in its values file. No registration exists for an ingress gateway, because none is installed:
the edge of the demonstrator is the Zero Trust Connector.

## The identity-band checks

`zone-policy` carries three post-install and post-upgrade Jobs in the `identity` band of the
hook-weight scheme (through a copy of the umbrella's hook helper). They only read, through the
Kubernetes API, and a failure fails the release:

| Job | Weight | Asserts |
|---|---|---|
| `server-healthy` | 20 | the SPIRE server's StatefulSet is Ready (its readiness probe is the server's health endpoint) and every agent is Ready |
| `trust-bundle-published` | 25 | the server has published its trust bundle (`spire-bundle`), and the controller-manager and the mesh both run with the zone's trust domain |
| `registrations-reconciled` | 30 | the controller-manager has reconciled the `ClusterSPIFFEID` with no entry or render failure, and every running labelled pod of the plane namespaces is selected, so its entry exists on the server |

**What the Jobs read.** The Jobs hold no SPIRE credential and never call the SPIRE server, so they
read Kubernetes objects that stand for the server's state: `server-healthy` reads the readiness of
the server's StatefulSet, which the server's own health endpoint drives through the readiness
probe, not the endpoint itself; `registrations-reconciled` reads the counters the controller-manager
writes into the `ClusterSPIFFEID` status after it has set the entries on the server, not the entries
themselves. On a zone with no running labelled pod (a fresh install, before any workload),
`registrations-reconciled` has nothing to compare and passes on the absence of failures alone. The
entries themselves are read on the server by the evidence run (`spire-server entry show`, in
[the mesh identity evidence](evidences/mesh-identity/README.md)).

## Openings under the default deny

The control planes sit under the same default deny as every plane namespace. These openings are
added, each only when the zone file enables it, and nothing else opens toward `spire-system` or
`istio-system`. They are declared openings of the network baseline, entries of the
cluster-administration class of the connector bypass list, listed beside the DNS bypass in the
[architecture](architecture.md#declared-openings-of-the-network-baseline); they are not rows of the
allow matrix.

| Opening | Source | Destination | Port | Rendered as |
|---|---|---|---|---|
| `meshControlPlane` | every pod of a plane namespace with the mesh label | istiod | 15012 (xDS) | `NetworkPolicy` egress in each meshed namespace, ingress in `istio-system` |
| `controlPlaneWebhooks` | the API server: entities `kube-apiserver`, `host`, `remote-node` | istiod's webhook; the controller-manager's webhook (in the SPIRE server pod) | 15017; 9443 | `CiliumNetworkPolicy` ingress in `istio-system` and `spire-system` |
| `identityServer` | the SPIRE agents on the host network: entities `host`, `remote-node` | the SPIRE server | 8081 | `CiliumNetworkPolicy` ingress in `spire-system` |
| `kubeApi` | every pod of a management-plane namespace | the API server: entity `kube-apiserver` | the API server's port (6443 on kind) | `CiliumNetworkPolicy` egress; required wherever `mesh.mode` is not `none` |

**Why by entity.** The API server and the host-networked agents are not pods, so a Kubernetes
`NetworkPolicy` cannot name them: a `podSelector` does not match them, and an `ipBlock` matches
node addresses under Cilium only with `policy-cidr-match-mode=nodes`, a cluster setting the client
clusters may not offer. Cilium names them as identities (entities). The proof showed one more fact:
a self-hosted API server runs on the host network of a control-plane node, and its calls into a pod
on another node arrive with that node's identity (`remote-node`; `host` on its own node), not as
`kube-apiserver`, which matches only the API server's own address. The webhook opening therefore
names the three entities, on the webhook port of the webhook pod only. The price is that any
host-networked endpoint of any node may open a connection to those two ports; every other port of
both control planes stays closed. A zone whose API server is managed outside its nodes can narrow
`networkPolicy.controlPlaneWebhooks.fromEntities` to `[kube-apiserver]` in its zone file. Every Cilium rule sets
`enableDefaultDeny` false: it adds its lane and leaves the deny to the baseline's `default-deny`.

**Nothing else.** The sidecar reaches its agent over the mounted socket and the agent reaches the
kubelet over the host's loopback (the chart's `hostNetwork: auto` with `kubeletAddress.mode: auto`),
so neither needs an opening. A stand-in pod in a plane namespace reaches neither control plane on
any port but istiod's xDS port.

**Another CNI.** With a mesh and without Cilium (`cni.cilium.enabled: false`) the umbrella refuses
to render: the control planes cannot be opened under the default deny. A zone on another CNI needs
a declared derogation of the preferred stack, written with the client before the zone is
installed, with its own way of expressing these openings.

## The SDS contract

Istio's proxy asks the agent's SDS endpoint for fixed resource names: `default` for its workload
certificate and `ROOTCA` for its validation context. The agent's own defaults serve its own bundle
under `ROOTCA` and every bundle, federated ones included, under `ALL`. The `spire` release's values
file fixes the names as the contract with the mesh, so that every bundle is served under the name
the proxy asks for and federation would later change nothing:

| Agent value | Set to | Why |
|---|---|---|
| `spire-agent.sds.enabled` | `true` | the SDS endpoint is off by default |
| `defaultSVIDName` | `default` | the name the proxy asks for its workload certificate |
| `defaultAllBundlesName` | `ROOTCA` | the name the proxy asks for its validation context; served with every bundle, so federation later changes nothing |
| `defaultBundleName` | `null` (the string) | disables the own-bundle resource, which defaults to `ROOTCA`, so that no two resources answer one name |

**What a wrong name produces.** If the agent serves nothing under `ROOTCA` (the name changed on
either side), the proxy holds an SVID and no root bundle, and every handshake fails
certificate validation, a failure that looks like a trust-domain or namespace mistake. If it served
nothing under `default`, the proxy would hold no certificate at all and never become ready.
`istioctl proxy-config secret <pod>` shows either at once: both `default` and `ROOTCA` must be
`ACTIVE` (see [Troubleshooting](troubleshooting.md)). The proof reads the root bundle back from the
proxy, so a missing bundle cannot pass unnoticed.

## The proxy

The `istiod` release configures the mesh for SPIRE:

- **SPIRE as the only certificate source.** The `spire` injection template, added to the default
  templates mesh-wide rather than chosen per pod (so a workload does not leave it out by leaving out
  an annotation), turns the proxy's `workload-socket` volume into the CSI driver's read-only volume
  at `/var/run/secrets/workload-spiffe-uds`. When the proxy finds the agent's socket there, it takes its
  certificate (`default`) and its trust bundle (`ROOTCA`) over SDS and never asks istiod's CA.
- **No mesh proxy without the socket in a plane namespace.** istiod's CA cannot be switched off: it
  also signs istiod's own serving certificates (xDS on 15012, the webhooks on 15017), and with
  `ENABLE_CA_SERVER=false` istiod starts without them and its webhooks fail. A pod that named its
  own injection templates (`inject.istio.io/templates: sidecar`), overrode the `istio-proxy`
  container, or ran Istio's agent itself (the `proxyv2` image, `proxy sidecar`) under another
  container name with its own `istio-token` volume would get an agent without the socket, and that
  agent would take a certificate from istiod's CA. The `zone-policy` release therefore installs the
  admission policy `proxy-takes-spire-socket`: in every namespace with the plane label, a pod may
  not carry `inject.istio.io/templates`, and every mesh proxy of a pod must mount the
  `csi.spiffe.io` volume at `/var/run/secrets/workload-spiffe-uds`. A mesh proxy is any container,
  init container or ephemeral container named `istio-proxy`, running the `proxyv2` image (any
  registry or tag), or naming `pilot-agent` in its command or arguments; the injector's
  `istio-validation` init container, which only checks the traffic redirection, is exempt. Pod
  creation, pod updates and ephemeral containers are all checked.
- **What the policy does not cover, and why it holds anyway.** Outside the plane namespaces the
  policy does not apply, and istiod still injects a pod labelled `sidecar.istio.io/inject: "true"`
  there with the templates it names, but such a proxy cannot reach istiod's CA: the
  `meshControlPlane` opening admits the plane namespaces only. Inside a plane namespace, a program
  that bears none of the policy's marks (Istio's agent copied into another image under another
  name, or any other client of the CA API) can still call istiod's CA on 15012 with its pod's
  service-account token and obtain a certificate under istiod's root. No peer trusts that root:
  every proxy's `ROOTCA` is SPIRE's bundle only, so such a certificate opens no mesh connection.
  The proof shows it: a certificate signed with istiod's CA key for an enrolled pod's own SPIFFE
  ID is refused by a meshed peer, while that pod's SPIRE SVID is accepted
  ([evidence](evidences/mesh-identity/README.md)). Closing the CA itself needs istiod's serving
  certificates from another issuer, left to a later change.
- **STRICT.** The mesh-wide `PeerAuthentication` `default` in `istio-system` is `STRICT`. A workload
  without an entry gets no certificate, so its proxy never becomes ready and, being a native
  sidecar, holds the application container back; any plaintext connection from its network
  namespace is refused by the peer. In the default permissive mode a peer would accept plaintext.
  A future plaintext exception is a namespaced `PeerAuthentication`, recorded per path. Mesh mTLS
  runs at TLS 1.3 at least (`meshConfig.meshMTLS.minProtocolVersion: TLSV1_3` in the `istiod`
  release, the security baseline of ADR 005; Istio's default is TLS 1.2): the proof shows a peer's
  proxy accepting a TLS 1.3 handshake with a SPIRE SVID and refusing one capped at TLS 1.2
  ([evidence](evidences/mesh-identity/README.md)).
- **Native sidecars.** `ENABLE_NATIVE_SIDECARS=true` in istiod injects the proxy as an init
  container with `restartPolicy: Always`: it starts before the application and stops after it, and
  Jobs end. This needs Kubernetes 1.33 or later; the umbrella refuses to render sidecar mode for a
  zone whose recorded `zone.kubernetesVersion` is older, and the proof asserts the live version.
- **The CNI plugin, chained.** The `istio-cni` release appends the Istio plugin to the CNI
  configuration Cilium wrote (`cni.chained: true`; Cilium runs with `cni.exclusive=false`), so no
  `istio-init` container needs elevated privileges. The plugin redirects the pod's traffic through
  its proxy; Cilium keeps enforcing the network policies.

### The capture rule

STRICT protects only the traffic that goes through the proxy, and which traffic does is decided by
the pod's capture annotations, which the CNI plugin reads to build its redirect rules. A registered
pod annotated `traffic.sidecar.istio.io/excludeInboundPorts: "8080"` has that port delivered
straight to the application: the peer's proxy never sees the connection, and an unregistered pod of
the same namespace reaches it in plaintext through the intra-plane lane. A pod could get the same
effect by switching the capture off (`sidecar.istio.io/interceptionMode: NONE`), by moving the
proxy's status port onto an application port (`status.sidecar.istio.io/port`, since the status port
is the one inbound port the injector excludes), or by having no proxy at all
(`sidecar.istio.io/inject: "false"`).

The admission policy `proxy-takes-spire-socket` therefore holds a third rule in every namespace
with the plane label. It cannot refuse the capture annotations' presence: the injector writes four
of them onto **every** pod it injects (`sidecar.istio.io/interceptionMode`,
`traffic.sidecar.istio.io/includeInboundPorts`, `excludeInboundPorts` and
`includeOutboundIPRanges`), from the pod's own value when the pod sets one and from the chart default
otherwise, and the policy runs after the injector, so a requested value and a written one look the
same. The rule is an equality with the injector's defaults instead:

- each of the four that the pod carries must equal its default: `REDIRECT`, `*`, the status port
  alone (`15020`, the `zone-policy` value `proxySocketPolicy.statusPort`, which must equal the
  `istiod` release's `global.proxy.statusPort`), and `*`;
- none of the annotations the injector writes only on request may be present:
  `traffic.sidecar.istio.io/excludeOutboundIPRanges`, `includeOutboundPorts`,
  `excludeOutboundPorts`, `excludeInterfaces`, `kubevirtInterfaces` and
  `istio.io/reroute-virtual-interfaces`;
- nor those that move or replace the capture or the proxy: `status.sidecar.istio.io/port`;
  `proxy.istio.io/config`, which can point the proxy at another discovery server;
  `sidecar.istio.io/proxyImage`, which swaps the proxy's image; `sidecar.istio.io/bootstrapOverride`,
  which replaces Envoy's bootstrap; `sidecar.istio.io/userVolume` and `userVolumeMount`, which mount
  the pod's own volumes into the proxy; and `proxy.istio.io/overrides`, which the injector writes
  when the pod brings its own container named `istio-proxy` and merges it over the injected proxy,
  the pod's image, environment and mounts winning. The injector writes none of these on a pod that
  does not ask for them;
- nor, in a namespace with the injection label (`istio-injection` or `istio.io/rev`), the injection
  opt-out `sidecar.istio.io/inject`, as an annotation or a label and whatever its value: a pod
  without a proxy there is reachable in plaintext like an excluded port, and `"true"` is already the
  namespace default.

The opt-out is refused only in injected namespaces because the plane entries the zone file declares
`mesh: false` (`istio-system`, `spire-system`) carry the plane label but no injection label, and
Istio's own pods there, istiod and the `istio-cni` node agents, carry `sidecar.istio.io/inject:
"false"`: refusing it there would stop their controllers from recreating them, and without istiod
no plane pod could be injected at all. The umbrella writes the injection label from the plane
entry's `mesh` field, its verification hook fails the release when a `mesh: false` namespace
carries one or a meshed namespace lacks it, and relabelling a namespace is the privilege that
already removes the plane label the policy is bound on, so the scope adds no new trust. Every other
clause of the rule applies in those namespaces too.

A fourth rule of the same policy, the proxy rule, holds every mesh proxy to the injector's own. A
proxy of another image, or a second `proxyv2` container with its own `--templateFile`,
`PROXY_CONFIG` or bootstrap, that mounts the SPIRE socket would pass the socket rule and could
accept plaintext on the inbound capture port; and `proxy.istio.io/overrides` does not catch every
path, since a pod that arrives with `sidecar.istio.io/status` already set has its own `istio-proxy`
merged over the injected one without that annotation. A mesh proxy is therefore admitted only in a
namespace with the injection label, only under the name `istio-proxy` (no second proxy under
another name), with the image `proxySocketPolicy.proxyImage` (which must equal the `istiod`
release's `global.proxy.image`; the installer refuses a zone where they differ), no command, the
arguments the 1.31.1 injector writes (`proxy sidecar --domain $(POD_NAMESPACE).svc.<cluster
domain>` and the three log-level flags, with only `--stsPort`, `--log_as_json` or
`--outlierLogPath` besides), no `envFrom`, only the environment variables the injector writes, with
`PILOT_CERT_PROVIDER`, `CA_ADDR`, `ISTIO_META_INTERCEPTION_MODE` and `TRUST_DOMAIN` at the
injector's values and `PROXY_CONFIG` an empty object (the zone sets no per-pod proxy
configuration), and only the injector's volume mounts at the injector's paths, none with `subPath`,
`subPathExpr` or mount propagation, over volumes of the injector's kinds (the SPIRE socket a
`csi.spiffe.io` volume, `istio-podinfo` the downward API, `istio-token` a projected service-account
token only, the CA root and CRL their configMaps, the rest `emptyDir`). The socket rule itself
requires the socket mount whole: with a `subPath` the agent would find a file or a subdirectory of
the volume where it looks for the socket, no socket, and fall back to istiod's CA. The allowed
variables include the two the injector's code adds from pod annotations after the template,
`ISTIO_KUBE_APP_PROBERS` (rewritten application probes) and `ISTIO_PROMETHEUS_ANNOTATIONS` (a pod
annotated `prometheus.io/*`, since the mesh merges the application's metrics). The proxy's
lifecycle, probes and `securityContext` are pinned as well, so that no command of the pod runs in
the proxy container as UID 1337 and the proxy gains no capability: the lifecycle is none, or the
injector's `pilot-agent wait` (`postStart`) and `pilot-agent request … POST drain` (`preStop`); no
liveness probe, and startup and readiness probes only as `httpGet /healthz/ready` on `15021`; the
`securityContext` UID and GID 1337, non-root, without privilege escalation, read-only, every
capability dropped and none added. A pod annotated `sidecar.istio.io/capNetBindService: "true"`, for
which the injector runs the proxy as root, is refused by this rule.

The policy also runs on every pod update, and on every update of `pods/status`, which can change a
pod's annotations and labels too (the agent rereads its annotations from the downward-API file
`istio-podinfo` whenever the proxy restarts). The capture and proxy rules look only at what an
update changes: an annotation or label whose value is unchanged, and a container whose name and
image are unchanged (nothing else of an existing container can change), is not checked again. A pod
admitted before an Istio upgrade, whose proxy still runs the previous image, therefore keeps taking
labels, annotations and finalizer changes; an update that adds a refused annotation, changes an
image or adds an ephemeral proxy is checked in full. An update may not remove
`sidecar.istio.io/status` or a capture annotation the injector wrote, nor change
`sidecar.istio.io/status`: without the status annotation the CNI plugin sets up no redirect the
next time it runs for the pod, and the proxy would run with nothing captured. The template and
socket rules do not run on a status update, which cannot change the pod's spec, so the kubelet's and
the controllers' status updates of a running pod are never refused.

An ordinary pod satisfies both rules with exactly what the injector writes, and the proof shows it
admitted with the status-port exclusion and `REDIRECT`, next to the refusal of an excluded
application port, capture mode `NONE`, a moved status port, a proxy-config override, an opt-out, a
swapped proxy image and a pod-supplied `istio-proxy`, the proxy rule's refusal of an
`istio-proxy` with another image, of a second proxy, and of an `istio-proxy` of the injector's
image with a pod-supplied `postStart` hook or `NET_ADMIN`, the socket rule's refusal of a socket
mount with a `subPath`, the admission of a pod with
`prometheus.io/*` annotations, the admission of the istiod and
`istio-cni` pods in `istio-system` and their refusal in the data plane, and a label admitted on a
running pod while an added exclusion is refused, through `pods/status` as well, and the removal of
`sidecar.istio.io/status` from a running injected pod refused ([evidence](evidences/mesh-identity/README.md)). A workload that needs a capture exception or a
proxy setting gets it mesh-wide through the charts (`meshConfig.defaultConfig`, or a value that
widens the rule) in its own change, never through a pod annotation. Interception mode `TPROXY`,
which also captures, is refused with the rest: the zone does not use it.

What the rule does not cover: capture is iptables inside the pod's network namespace, so a
host-networked pod or a container with `NET_ADMIN` steps around it without any annotation. And the
redirect rules let the proxy's own UID and GID, 1337, leave without capture (otherwise the proxy
would capture itself), so an application container that runs as UID or GID 1337, through its
`securityContext` or its image's `USER`, sends its outbound traffic past the proxy. The injector
also skips host-networked pods, so such a pod could bring its own `istio-proxy` with its own
environment. Those belong to a Pod Security Admission level on the plane namespaces, with a rule on
`runAsUser` and `runAsGroup` (an image's `USER` is not visible at admission, so that rule must
require an explicit non-1337 user), which the namespaces do not carry today and which is the next
change, not this policy. And with the mesh's `enablePrometheusMerge`, the proxy's agent fetches the
metrics path a pod names in its `prometheus.io/*` annotations from the application and serves it on
the status port, which is outside the capture, so that one path is readable in plaintext, as on any
Istio sidecar with the merge on. The probe rewrite (`ISTIO_KUBE_APP_PROBERS`, on by default, and
needed because the kubelet's plaintext probes would otherwise meet STRICT) does the same for every
`httpGet` probe path of an application container: the agent fetches it from the application and
serves it on the status port (`/app-health/<container>/readyz`, `livez`, `startupz`), readable in
plaintext by any pod of the namespace. The pod chooses its probe paths and the injector writes
whatever they are, so the variable is not pinned; a probe path must reveal nothing beyond health.
The proxy's other environment values (`ISTIO_META_CLUSTER_ID`, `ISTIO_META_NODE_NAME`,
`ISTIO_META_WORKLOAD_NAME`, `ISTIO_META_OWNER`, `OTEL_RESOURCE_ATTRIBUTES`, also through
`valueFrom`) are not pinned either: they change how istiod files and labels the proxy (registry
lookup, telemetry), not its certificate, which SPIRE issues for the pod's service account. And an
ephemeral container that targets `istio-proxy`, or `shareProcessNamespace`, lets another container
(as root, or as UID 1337) reach the proxy's process; refusing those belongs to the same Pod Security
follow-up.

## Telemetry

The `spire` release switches on the Prometheus endpoint of the server and of the agents. The ports
are the contract with the observability collector of the management plane, which scrapes them; the
collector, and its lane into `spire-system`, belong to the observability work and are not rendered
by this change. The agents run on the host network, where no network policy reaches them, so their
endpoint is bound to the node's loopback rather than the chart's `0.0.0.0`: it answers only a
collector that runs on the node's host network, never a pod or another host.

| Component | Endpoint |
|---|---|
| SPIRE server | pod port 9988, `/metrics` |
| SPIRE agents | `127.0.0.1:9988` on each node (host network, loopback only) |
| SPIRE controller-manager | pod port 8082 (the chart's default) |

## Installing it

The zone installer, `scripts/install-zone/install.sh`, installs the identity path with the rest of
the zone, from one zone file, as seven releases in order; see
[its README](https://github.com/eclipse-xfsc/facis-zero-trust-demonstrator/tree/main/scripts/install-zone)
and the [zone installation guide](environments/osc.md#3-workload-identity). The upstream charts and
their pins are in [OSS dependencies](dependencies.md#identity-and-service-mesh); every value the
repository sets on them is listed with its reason in `deployment/helm/values/README.md`.

## Checking an identity

Read a pod's SVID through the socket, with a Workload API client in a container that mounts the
`csi.spiffe.io` volume (the proof's stand-in uses SPIRE's agent image):

```bash
kubectl -n ztd-data exec <pod> -c <client> -- \
  /opt/spire/bin/spire-agent api fetch x509 -socketPath /run/spiffe/socket
```

It prints the SPIFFE ID, `spiffe://<trust domain>/ns/<namespace>/sa/<service account>`. Then read
what the proxy presents in the mesh and confirm it is SPIRE's:

```bash
istioctl proxy-config secret <pod> -n ztd-data            # "default" and "ROOTCA", both ACTIVE
istioctl proxy-config secret <pod> -n ztd-data -o json \
  | jq -r '.dynamicActiveSecrets[] | select(.name == "default")
           | .secret.tlsCertificate.certificateChain.inlineBytes' \
  | base64 -d | openssl x509 -noout -subject -issuer -ext subjectAltName
kubectl -n spire-system exec spire-server-0 -c spire-server -- \
  /opt/spire/bin/spire-server bundle show                 # the SPIRE CA the issuer must name
```

A SPIRE-issued certificate has `O = SPIRE` in its subject, the SPIRE server CA as its issuer, the
pod's SPIFFE ID as its URI SAN, and the `ROOTCA` bundle is the SPIRE server's CA, not istiod's
(`istio-ca-root-cert`).

## What the evidence proves

`scripts/verify-mesh-identity/verify.sh` installs the zone on the kind cluster from an empty
cluster, twice, and writes [the record](evidences/mesh-identity/evidence.md):

| Check | Proves |
|---|---|
| `install-order-idempotent` | the seven releases install in order with no manual step, every pod is Ready, and a second run leaves every release's manifest identical |
| `svid-over-csi-socket` | a labelled pod gets, over the mounted socket, the SVID of its service account in the zone's trust domain, chained to the SPIRE CA; an unlabelled pod gets no entry and no SVID |
| `native-sidecar-version` | the server is 1.33 or later and the proxy is an init container with `restartPolicy: Always` |
| `mesh-identity-issued-by-spire` | the proxy's certificate has `O = SPIRE`, the SPIRE CA as issuer and the SVID's URI SAN, and its `ROOTCA` bundle is the SPIRE CA; under the capture rule (`capture-at-injector-defaults`), a pod in a plane namespace with an excluded application port, capture mode `NONE`, a moved status port, a proxy-config override, an injection opt-out, a swapped proxy image or a pod-supplied `istio-proxy` is refused at admission, an ordinary pod is admitted carrying the injector's status-port exclusion and `REDIRECT`, and the istiod and `istio-cni` pods, which opt out of injection, are admitted in `istio-system` |
| `unregistered-workload-cut-off` | an unlabelled pod's proxy has no certificate, its application never starts, and the peer refuses a call from it, while the labelled pod's call succeeds |
| `traffic-through-the-proxies` | the peer sees the caller's SPIFFE ID in `X-Forwarded-Client-Cert` and both proxies count the request as mTLS |
| `default-deny-with-chained-cni` | the Istio plugin runs after Cilium, `cni-exclusive=false`, and the umbrella's cross-plane denial and matrix lane hold with the proxies in place |
| `control-planes-under-default-deny` | only the declared openings exist in the two namespaces, the agents and the proxies are served, and a stand-in pod's probes on every other port are denied |

It also shows the identity-band checks failing a release when a declared registration has no
entry, the render guards, and a teardown that leaves no namespace, no SPIRE or Istio CRD and no
webhook behind.
