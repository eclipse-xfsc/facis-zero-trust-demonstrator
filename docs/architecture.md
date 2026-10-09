# Architecture

## 6. Plane separation and staleness windows

### Trust boundaries (diagram 03)

Each trust zone is its own SPIFFE trust domain. The two domains meet only through the attested
channel and a TRAIN verdict; they are never merged. Data-plane calls into the management plane are
denied by default, and a workload without an SVID or running an unsigned image cannot join or
start.

![Trust boundaries](diagrams/03-trust-boundaries.svg)

Source: [`diagrams/03-trust-boundaries.mmd`](diagrams/03-trust-boundaries.mmd).

### Allow matrix (data plane → management plane)

Default DENY at both layers: the Kubernetes network policy layer and the mesh AuthorizationPolicy
layer. ZT-55 names the *Kubernetes network policy layer*, a layer and not a resource kind: in the
zones it is enforced by Cilium, through Kubernetes `NetworkPolicy` objects and, where a source is
not a pod, `CiliumNetworkPolicy` objects. These are the only permitted paths:

| From data-plane workload → | Allowed? | Layer that enforces |
|---|---|---|
| PDP adapter → TSA policy engine | ALLOW (mTLS, named pair) | mesh policy |
| aTLS gateway → cmcd / TCR resolve | ALLOW (named pair) | mesh policy |
| workloads → OTel collector (export only) | ALLOW (declared bypass, ZT-26) | mesh policy, egress-restricted |
| workloads → DNS | ALLOW (declared bypass) | network policy layer, port 53 |
| backend → Keycloak token endpoint / verification service | ALLOW (named pairs) | mesh policy |
| anything else data → management (SPIRE server, ArgoCD, OpenBao, TSPA, Harbor, estserver, admin APIs) | **DENY** | both layers; ZT-55 matrix test |

### Declared openings of the network baseline

Beside the DNS bypass, the network baseline of a meshed zone has four declared openings for the two
control planes: the identity control plane (`spire-system`) and the mesh control plane
(`istio-system`), both management-plane namespaces under the default deny. They are entries of the
**cluster-administration** class of the Zero Trust Connector bypass list (ZT-26: administrative
APIs), each listed with its reason; they are not rows of the allow matrix, which governs paths from
data-plane workloads into the management plane and whose catch-all denial still holds. In
particular a data-plane workload reaches the SPIRE server on no port. Each opening is rendered by
the umbrella chart only when the zone file enables it, and is proven by the named check of the
[mesh identity evidence](evidences/mesh-identity/README.md):

| Opening | Source | Destination | Port | Network policy layer | Proving check |
|---|---|---|---|---|---|
| `meshControlPlane` | pods of every plane namespace with the mesh label | istiod (`istio-system`) | 15012 (xDS) | egress in the source namespaces, ingress in `istio-system` (Kubernetes `NetworkPolicy`) | `control-planes-under-default-deny` (proxies SYNCED; no other istiod port reachable) |
| `controlPlaneWebhooks` | the API server (entities `kube-apiserver`, `host`, `remote-node`) | istiod's webhook; the SPIRE controller-manager's webhook | 15017; 9443 | ingress in `istio-system` and `spire-system` (`CiliumNetworkPolicy`) | `control-planes-under-default-deny`, `install-order-idempotent` (injection and admission work) |
| `identityServer` | the SPIRE agents on the host network (entities `host`, `remote-node`) | the SPIRE server | 8081 | ingress in `spire-system` (`CiliumNetworkPolicy`) | `control-planes-under-default-deny` (every agent attested) |
| `kubeApi` | pods of the management-plane namespaces | the API server (entity `kube-apiserver`) | the API server's port | egress in each management-plane namespace (`CiliumNetworkPolicy`) | `install-order-idempotent` (the controllers reconcile) |

The sources of the last three are not pods, so they are expressed as Cilium entities rather than
addresses ([Workload identity](workload-identity.md#openings-under-the-default-deny)). The sidecar
reaches its SPIRE agent over a mounted socket and the agent reaches the kubelet over the host's
loopback, so neither needs an opening.

### Staleness matrix

Maximum window in which a revoked or rotated artefact still authorises. All values are proposed.

| Artefact | Rotation/lifetime | Cache | Max stale-authorisation window |
|---|---|---|---|
| SVID | 1 h TTL | in-process | ≤ 1 h (mesh) |
| Keycloak/issuer JWKS | rotate on demand | guard cache 5 min | ≤ 5 min |
| Access token | 300 s lifetime | — | ≤ 300 s after revocation of its basis |
| Policy bundle | poll 60 s | TSA cache | ≤ 60 s |
| Trust list / measurement | TTL 300 s | TCR/gateway | ≤ 300 s + channel lifetime 15 min ⇒ ≤ ~20 min for an established channel (bounded by channel re-establishment) |
| Credential revocation | checked per verification | outcome TTL 120 s | ≤ renewal interval (≤ token lifetime 300 s) + 120 s |
