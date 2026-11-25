# verify-connector-routing

The ZT-26 proof (BDD-ZT-026) of the Zero Trust Connector routing in
[Architecture §6](../../docs/architecture.md#zero-trust-connector-routing-zt-26): application traffic
crosses the zone boundary through the connector gateway only, the direct paths around it are refused, and
the declared bypasses (name resolution, observability export) work over their own paths. It runs against
an installed zone and installs nothing; its stand-ins (`fixtures/stand-ins.yaml`, and
`fixtures/otel-stand-in.yaml` where no collector runs) are removed on exit. Each check's outcome class is
read from curl's own exit code, as the other cluster proofs do (`scripts/lib/probe.sh`); a network drop
cites Hubble's policy drop when the node's Cilium agent answers `hubble observe`.

| Section | Runs when | Passes when |
|---|---|---|
| egress-route | `ROLE=egress` (the gateway `GATEWAY` must exist in `ROUTE_NAMESPACE`) | its NetworkPolicy has one egress lane; the caller's request through it is served by the peer; the gateway's access log records it with the peer as upstream; the peer's log (`PEER_LOG_CMD`) records its arrival; an impostor with the caller's labels is refused by the gateway's proxy (403 and a denial line naming it) |
| direct-path | both roles (a denial counts only with Hubble's policy drop or the destination's denial line) | the caller's direct attempt at the peer entry and at each `DIRECT_EXTERNAL` is dropped (and absent from the peer's log); each `DIRECT_TARGETS` Service is unreachable |
| entry | `ROLE=ingress` | the entry forwards to one upstream; every `LoadBalancer`/`NodePort` port of the cluster is the entry's or declared in `DECLARED_FILE` (and every declared one is exposed), and each declared entry passes every assertion of its scope, sent from outside the cluster |
| exemptions | always | the caller resolves cluster names; it reaches the collector (or a stand-in with the export row's labels and identity) on 4318 |

On a participant cluster the context guard of `scripts/lib/proof.sh` applies (`ZTD_CONFIRM_CLUSTER`), and
the record is masked of addresses. Zone A (egress role):

```bash
KUBECONFIG=<zone A> KUBE_CONTEXT=zerotrust-a ZTD_CONFIRM_CLUSTER=zerotrust-a \
ROUTE_METHOD=POST ROUTE_PATH=/demo ROUTE_BODY='{"resource":"sample-report","action":"read"}' ROUTE_EXPECT='"outcome":"success"' \
PEER_LOG_CMD='kubectl --kubeconfig <zone B> -n ztd-m3-b logs deploy/ztd-edge -c envoy' \
scripts/verify-connector-routing/verify.sh
```

Zone B (ingress role; no gateway): `ENTRY_NAMESPACE=ztd-m3-b ENTRY_NAME=ztd-edge
DECLARED_FILE=scripts/verify-connector-routing/declared/zone-b.txt` (the zone's declared public entries as
(Service, port, protocol) tuples, and every scope assertion each must pass: the TSPA entry's DID document,
its published trust list and VC with `TSPA_FRAMEWORK`, every TSPA write route with a body answering 404 or
405, TLS 1.2 refused; the DNS listener's zone answered and other names refused), `DIRECT_TARGETS` (each
`<ns>/<svc>:<port>/<http|https>`) and `DIRECT_EXTERNAL` (`<IPv4>:<port>/<proto>`); the exact invocation is in
the zone B record under `docs/evidences/connector-routing/`.

`kind.sh` rehearses both roles on a kind zone (`scripts/dev/kind-cilium-up.sh`, then
`scripts/install-zone/install.sh install ztd spire-crds spire istio-base istiod istio-cni zone-policy`):
a peer entry in a container on the kind network, the egress release routed to it, zone B's hand-applied
entry adopted by the chart under a client calling it every half second, then this proof on both.
