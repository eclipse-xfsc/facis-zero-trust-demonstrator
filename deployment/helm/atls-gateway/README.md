# Attested-channel gateway

The zone's attested-channel gateway (ZT-28, ZT-65; [docs/atls-gateway.md](../../../docs/atls-gateway.md)):
the binary `cmd/connector-gateway` over the attested-channel library `internal/atls`
([Attested channel control](../../../docs/attested-channel.md)). One release holds the zone's roles; at
least one is enabled. Every channel is mutual attestation over TLS 1.3; there is no plain-TLS mode, no
one-sided mode and no switch for either.

**Ingress** (`ingress.enabled`): the zone's attested entry. The peer zone's egress reaches
`ingress.port` behind a Service of `ingress.service.type` (`externalTrafficPolicy` Local keeps the
peer's source address as the lane sees it); each channel is terminated here, its peer's certificate
checked for `ingress.peerIdentity` and its evidence verified by the zone's cmcd, and the stream is
forwarded as it is, bytes intact, to `ingress.upstream` (`name` is both the Service dialled and the
pods' `app.kubernetes.io/name` label of the network lane; `port` the port of both), whose own rules
must admit this release's identity (`<trust domain>/ns/<namespace>/sa/atls-gateway`). The upstream's
Service port must be a TCP port of the mesh (name `tcp-…`, or `appProtocol: tcp`): the bytes carry the
peer zone's Host header, and an HTTP port would make the ingress's sidecar route by that header. Mesh mutual TLS
is off on the entry's port only (`<name>-tls`: the channel's own TLS 1.3 and attestation take its
place); `<name>-public` admits that port; `<name>-entry` is the network lane from
`ingress.sourceRanges`; `<name>-upstream` the lane to the upstream.

**Egress** (`egress.enabled`): admits the callers of `egress.callers` (their pods' labels at the
network layer, their service accounts at the mesh layer) on `egress.port`, plain TCP over mesh mutual
TLS, and carries each stream to the peer zone's ingress at `egress.peer.address`:`egress.peer.port`
over a channel it originates and attests, the peer's certificate checked for `egress.peer.identity`.
Its one lane out of the cluster, to that address/32 on that port, is the CiliumNetworkPolicy
`<name>-peer`, bound to the gateway's service account; the address is a zone fact given at install,
never committed. `<name>-callers` (NetworkPolicy and AuthorizationPolicy) admit the callers.

**Identity and trust.** The gateway's own certificate is `tlsSecret`, a `kubernetes.io/tls` Secret
issued by the zone PKI with the URI subject alternative name `spiffe://<zone>/gateway`
([ADR-0010](../../../docs/adr/0010-session-attestation-through-cmcd.md), decision 5: a static zone
certificate, never the mesh SVID); `trustCaCert` holds the CA(s) of both zones' gateway certificates.
The zone's attester is `cmcd.address`, the Service of [deployment/helm/cmcd](../cmcd/README.md) in the
management plane, reached over the umbrella's lane `atls-gateway-to-cmcd`; the pods carry the label
`app.kubernetes.io/name=atls-gateway` and the service account `atls-gateway` that lane names
([docs/umbrella-chart.md](../../../docs/umbrella-chart.md)). Workload names start with `name`
(`ztd-…`, the zone's naming rule): `<name>-ingress`, `<name>-egress`.

**Startup check** (`attestation`, on by default): before a role serves, it obtains a fresh report
from the zone's cmcd and requires its measured values to be exactly those of `attestation.zone`, the
zone's attestation configuration as kept in Git (`deployment/attestation/<zone>.json`; the installer
passes the file), verified against `attestation.metadataCaCert`
([Attestation evidence provisioning](../../../docs/attestation-provisioning.md), step 5). A zone whose
evidence is not the one in Git does not serve: the pod exits 2 (report rejected) or 3 (no report) and
records why. Off (`attestation.enabled: false`) only for a render with no attester to ask.

Every decision is one JSON line on stdout: `started` with `evidence_verified`; `established` with
`mutual_attestation`, the peer identity, the channel binding and the TLS version; `refused` with the
reason (`atls: peer does not speak attested TLS 1.3`, `atls: handshake timed out`,
`atls: local attester unavailable`, `evidence_rejected`, `channel_expired`, …). No application byte, header
or credential is logged. The gateway reads its configuration at start, so the pod carries the
configuration's digest and a change rolls it. Neither channel port has a probe: a connect to the ingress
port is an attested handshake the gateway records as a refusal, and a connect to the egress port
opens a channel to the peer. Readiness is `GET /healthz` on `healthPort`, which the gateway opens only
once the startup check passed and the role listens: a rollout keeps the verified pod until the new
one serves, and a pod that refuses to serve is never Ready. The pod carries the digest of its
configuration and of the material it reads at start (trust anchors, the zone's attestation
configuration, the metadata CA), so a change of any of them rolls it.

Each policy carries its hop (`ztd.facis.io/connector-hop`) and that hop's single L7 owner:
caller-to-gateway and entry-to-upstream `sidecar`, gateway-to-peer and outside-to-entry `none`;
`scripts/ci/check-policy-l7-owner.sh` holds every rendering to that mapping, and
`scripts/ci/check-policy-addresses.sh` declares the two hops that leave the mesh as the only policies
that name an address (ZT-25 governs the mesh). The namespace provides the DNS lane, the xDS lane to
istiod and the lanes to cmcd and to the TCR (the umbrella's); the chart opens none of them.

## From the zone file

`scripts/install-zone/install.sh` installs this chart as release `ztd-atls-gateway` when the zone
file sets `atlsGateway.install: true`, into `atlsGateway.namespace` (the data plane), with
`atlsGateway.values` as this chart's values, `trustDomain` from `zone.trustDomain` and, unless the
values give it, `attestation.zone` from `deployment/attestation/<zone.name>.json`; `install.sh render
ztd-atls-gateway` renders it the same way, and the policy checks (`scripts/ci/render-zones.sh`) render
it for every shipped zone file that sets it. The attester release `ztd-cmcd` is installed first
(`cmcd.install`). The two Secrets, `tlsSecret` and the attester's material, are the zone's facts:
created before the releases, never committed.

`ci/values.yaml` (both roles), `ci/ingress-only-values.yaml` and `ci/no-startup-check-values.yaml`
carry documentation addresses and placeholder material for rendering only; `ci/refused/` holds the
values the chart refuses. `scripts/verify-atls-gateway/verify.sh --kind` installs two zones on kind and
proves the channel between them.
