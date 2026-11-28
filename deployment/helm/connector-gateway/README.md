# Connector gateway

The Zero Trust Connector's zone gateway: the Envoy that forwards application traffic across the zone
boundary ([Architecture §6, Zero Trust Connector routing](../../../docs/architecture.md#zero-trust-connector-routing-zt-26)).
A release has one role.

**Egress** (`egress.enabled`): admits the callers of `egress.callers` (their pods' labels at the network
layer, their service accounts at the mesh layer) on `egress.port`, plain HTTP over mesh mutual TLS, and
forwards every request to the peer zone's entry over TLS that the gateway originates and verifies: the CA
in `egress.peer.caCert`, the subject alternative name `egress.peer.serverName` (default: the address).
Its one lane out of the cluster, to `egress.peer.address`/32 on `egress.peer.port`, is the
CiliumNetworkPolicy `<name>-peer`, which selects the gateway's service account, not a label another pod
could carry; the address is a zone fact given at install, never committed. `<name>-callers` (NetworkPolicy
and AuthorizationPolicy) admit the callers. Each policy carries its hop (`ztd.facis.io/connector-hop`) and
that hop's L7 owner: caller-to-gateway `sidecar`, gateway-to-peer `none`; in the ingress role
outside-to-entry `none` (`<name>-entry`, `<name>-public`) and entry-to-upstream `sidecar` (`<name>-upstream`).
`scripts/ci/check-policy-l7-owner.sh` holds every rendering to that mapping.

**Ingress** (`ingress.enabled`): the zone's entry. TLS terminated with `ingress.tlsSecret` on
`ingress.port` behind a Service of `ingress.service.type`, every request routed to the Service
`ingress.upstream.name` of the namespace, whose own rules must admit this release's identity
(`<trust domain>/ns/<namespace>/sa/<name>`) and pods. Mutual TLS is off on the entry's port only
(`<name>-tls`); `<name>-public` admits that port.

**The TRAIN allow list** (`ingress.peerAllowList`, off by default; ZT-18): the entry demands a client
certificate issued by `clientCaCert` and asks `connector admit-peers`, a second container of the pod (the
connector image), before forwarding each request. The peer is admitted only when a subject alternative
name of its certificate is an active service of the framework's trust list, retrieved from `tspaUrl` and
verified under `issuerDid`; refused otherwise (403 `CHAN-ZONE-UNKNOWN`, or 503 `CHAN-TRUST-UNREACHABLE`
while the list cannot be retrieved or verified). `<name>-trust-list` is the pod's lane to the TSPA and the
DID document's host, given as NetworkPolicy rules in `egress` (selectors, no addresses). The egress role
presents its certificate with `egress.peer.clientTlsSecret`. See
[TRAIN allow list of the zone entry](../../../docs/connector.md#train-allow-list-of-the-zone-entry-zt-18).

Both roles log one JSON line per request on stdout (time, method, path, status, upstream, user agent,
request id; no credential, body or other header). Envoy reads its configuration at start, so the pod
carries the configuration's digest and a route change rolls it.

The namespace provides the DNS lane and the xDS lane to istiod (a plane namespace's baseline, or
`ztd-dns`/`ztd-mesh-control` in `ztd-m3-b`); the chart opens neither. The image is the pinned Envoy by
digest; an admission-labelled namespace needs the admitted mirror and the injected images' overrides in
`podAnnotations`.

Adopting an entry applied by hand (zone B's `ztd-edge`): `helm upgrade --install ztd-edge . --take-ownership
--force-conflicts` with `name: ztd-edge` and the ingress values; the Service is updated in place, so it
keeps its UID, node port and load-balancer address, and the Deployment rolls once. The hand-applied pod
has no preStop pause, so a call in flight while it is replaced can fail; the chart's pod pauses 5 s before
it stops, and its own rollouts lose no call. An uninstall keeps the entry's Service (`helm.sh/resource-policy: keep`). Remove the hand-applied
rule `ztd-m3-edge-public` afterwards: `ztd-edge-public` replaces it. `scripts/verify-connector-routing/kind.sh`
rehearses exactly this.

`ci/values.yaml` (egress), `ci/ingress-values.yaml`, `ci/allowlist-values.yaml` and `ci/client-cert-values.yaml` carry documentation addresses for rendering only;
`ci/refused/` holds the values the chart refuses.
