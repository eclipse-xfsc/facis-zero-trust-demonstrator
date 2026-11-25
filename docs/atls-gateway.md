# Attested-channel gateway

The gateway is the one endpoint of a zone that speaks attested TLS to the peer zone (ZT-28, ZT-65;
SRS 5.2). It carries application streams between the zones over a channel whose two ends have
verified each other's evidence, bound to the TLS session; the streams themselves, HTTP or gRPC,
headers, bodies and trailers, cross byte for byte. The channel itself is the library `internal/atls`
([Attested channel control](attested-channel.md)); this page is the process around it, its image,
its chart, the attester beside it, and the proof that two zones establish the channel.

## The process

`cmd/connector-gateway` runs one role per process over `internal/connectorgateway`:

| Role | Listens | Dials | What it is |
|---|---|---|---|
| `ingress` | an attested listener (`atls.Listen`) on the entry port | plain TCP to one in-zone upstream, through the mesh | the zone's attested entry |
| `egress` | plain TCP from the zone's callers, through the mesh | an attested channel (`atls.Dial`) to the peer zone's ingress | the zone's attested exit |

Both roles require mutual attestation and refuse to start in any other mode; neither has a plain-TLS
path. Each stream's lifetime is bounded by the channel verdict's (`ValidUntil`, 15 minutes by
default): a pooled HTTP/2 stream does not outlive the evidence it was admitted on.

The configuration is one JSON file (`--config`, default `/etc/gateway/gateway.json`, unknown fields
refused): `role`, `listen`, `target`, `certificate`, `key`, `ca`, `cmcd`, `peerIdentity`, and the
optional `attestation` block of the startup check below.

**Decisions.** Every decision is one JSON line on stdout, never application metadata or
credentials:

| `decision` | `reason` | When |
|---|---|---|
| `started` | `evidence_verified` | the startup check passed; the role serves |
| `refused` | `evidence_rejected`, `attester_unavailable` | the startup check failed; the process exits (2, 3) and serves nothing |
| `established` | `mutual_attestation` | a channel opened: `peer` (the identity expected and found), `binding` (RFC 9266, the same at both ends), `tlsVersion` (772, TLS 1.3) |
| `refused` | the refusal's sentinel (`atls: peer does not speak attested TLS 1.3`, `atls: handshake timed out`, `atls: local attester unavailable`, `atls: peer certificate identity rejected`, …), `upstream_unavailable`, `channel_expired` | a handshake or stream was refused or ended by the gateway |

The record is the proof's input: the two zones' records of one channel must carry the same binding.

**Startup check (fail closed).** With the `attestation` block, the role first does what
[Attestation evidence provisioning](attestation-provisioning.md) calls step 5: it obtains a fresh
report from the zone's cmcd and verifies it in process (`provision.Check`) against the metadata CA
(`metadataCA`) and the zone's attestation configuration as kept in Git (`zone`,
`deployment/attestation/<zone>.json`): every verified measured value must be exactly the configured
one, and the aggregate the evidence signs must be the configuration's. A zone whose evidence is not
the one in Git does not serve: exit status 2 when a report was obtained and rejected, 3 when none
could be obtained, after recording the refusal. The check runs at start, and the readiness endpoint
(`health`, `GET /healthz`) opens only after it passed and the role listens; the chart puts the
digest of the configuration and of the material read at start (trust anchors, the zone's
attestation configuration, the metadata CA) on the pod, so a change of any of them rolls the pod,
and the new pod checks the new inputs before it is Ready. The rollout keeps the previously verified
pod serving until then: a change that the attester's evidence does not match leaves the new pod
exiting 2 and the entry on the configuration it was verified against.

The unit tests of the binary (`cmd/connector-gateway/main_test.go`) run two processes' worth of roles
over the test attesters and hold the decisions, the refusals, the configuration refusals and the
startup gating; `TestGatewayProof` (`internal/connectorgateway`) and the ZT-19 BDD row hold the
channel itself over two real `cmcd` processes.

## Image

`deployment/docker/atls-gateway`: the binary at `/atls-gateway` on an empty base, user 65532, built
with CGO off and CMC's tags `nodefaults,grpc` (the gRPC attester stays; the in-process backend and
the TEE drivers, one of which needs cgo, are left out; [attester selection](attested-channel.md#attester-selection-and-builds)).
The path and user are those the zone's attestation configuration measures
(`deployment/attestation/<zone>.json`); its `rootfs_sha256` stays a mock value, since nothing measures
a running container ([ADR-0011](adr/0011-mock-tee-evidence-format-and-provisioning.md)). The image is
built, scanned, signed and released by the pipeline like every other context under
`deployment/docker/` ([CI/CD](ci-cd.md)).

`deployment/docker/cmcd`: CMC's `cmcd` at the version `go.mod` pins, built in a scratch module from
that version, with the tags `nodefaults,grpc,socket,sw` (the `socket` tag is required by cmcd's gRPC
server at this version). The configuration selects the gRPC API alone.

## Charts

Two releases of a participant zone, installed by the zone installer from the zone file
([deployment/helm/atls-gateway/README.md](../deployment/helm/atls-gateway/README.md),
[deployment/helm/cmcd/README.md](../deployment/helm/cmcd/README.md)):

| Release | Plane | Zone file | Pods |
|---|---|---|---|
| `ztd-cmcd` | management | `cmcd.install`, `cmcd.namespace`, `cmcd.values` | `app.kubernetes.io/name=cmcd`, service account `cmcd`, Service `cmcd` |
| `ztd-atls-gateway` | data | `atlsGateway.install`, `atlsGateway.namespace`, `atlsGateway.values` | `app.kubernetes.io/name=atls-gateway`, service account `atls-gateway`; one Deployment per role |

The labels and accounts are the umbrella's contract for the lanes `atls-gateway-to-cmcd` and
`atls-gateway-to-tcr` ([Umbrella chart](umbrella-chart.md)): the network lane and the mesh allow rule
from the data plane to cmcd are the umbrella's and zone-policy's, not the charts'. What the gateway
chart adds is its own two edges and their hops:

| Hop | Policy | Layer | L7 owner |
|---|---|---|---|
| caller-to-gateway (egress) | `<name>-callers` NetworkPolicy by the callers' labels; `<name>-callers` AuthorizationPolicy by their principals | mesh mutual TLS | sidecar |
| gateway-to-peer (egress) | `<name>-peer` CiliumNetworkPolicy: the gateway's service account to the peer ingress's address/32 and port, the namespace's one lane out | the attested channel | none |
| outside-to-entry (ingress) | `<name>-entry` NetworkPolicy from `ingress.sourceRanges`; `<name>-tls` PeerAuthentication STRICT with the entry port DISABLE; `<name>-public` AuthorizationPolicy for that port | the attested channel | none |
| entry-to-upstream (ingress) | `<name>-upstream` NetworkPolicy to the upstream's pods and port; the upstream's Service port is a TCP port of the mesh (`tcp-…`), since the bytes carry the peer zone's Host header and an HTTP port would have the sidecar route by it | mesh mutual TLS | sidecar |

Mesh mutual TLS is off on the entry port because the peer's egress is not a workload of this mesh:
the channel's own TLS 1.3, its mutual authentication under the zone PKI and its mutual attestation
replace it on that port and nowhere else. The capture annotations that would exclude the port from
the sidecar are refused at admission in a plane namespace (zone-policy's capture rule), so the
port-level setting is the one mechanism. The two hops that leave the mesh are the only policies of
a zone that name an address; `scripts/ci/check-policy-addresses.sh` declares them as the connector
gateway's and refuses every other address, and `scripts/ci/check-policy-l7-owner.sh` holds each hop
to its owner.

The attester's material and the gateway's certificate are zone facts, Secrets created before the
releases and never committed: `cmcd-material` (the signed reference metadata, the measurement log
and the metadata CA, as the pipeline delivers them) in the management plane, and the
`kubernetes.io/tls` Secret of the gateway's zone certificate (URI SAN `spiffe://<zone>/gateway`,
issued by the zone PKI) in the data plane. Both zones' gateway CAs are the trust anchors each
gateway is given.

## Proof: two zones on kind

`scripts/verify-atls-gateway/verify.sh --kind [--out DIR]` creates two kind clusters with Cilium as
the zones run it, installs each as a participant zone through `scripts/install-zone` (umbrella,
SPIRE, Istio sidecar mode, zone-policy), provisions each zone's evidence as the pipeline does (render
from Git, sign with `metatool` under a metadata CA created for the run), hands it over as Secrets,
installs `ztd-cmcd` and `ztd-atls-gateway` (both roles) from the zone file, and runs:

| Check | Shows |
|---|---|
| startup | each gateway role recorded `started`/`evidence_verified` before serving |
| A → B, B → A | a caller's HTTP request in one zone, through its egress and the peer's ingress, answered by the peer's echo; both ends recorded one channel: mutual attestation, TLS 1.3, the same binding, the peer identity each expected |
| plain TLS | a TLS client outside the zone PKI, speaking no attestation, at zone B's entry from outside the mesh: no application answer, the refusal recorded |
| attester | zone A's cmcd scaled to zero: the next channel is refused (`atls: local attester unavailable`), the caller gets no answer; the attester back, the next call goes through |
| tamper | zone A's attestation configuration changed in place (another rootfs digest) and the ingress restarted: the new pod exits 2 with `evidence_rejected` and is never Ready, so the rollout keeps the verified pod serving; restored, the new pod serves and zone B's call is answered again |

The peer is reached at the peer zone's worker node and the entry's NodePort over kind's Docker
network; the entry's network lane admits that network, and `externalTrafficPolicy: Local` keeps the
source address the lane sees. The run's records (the gateways' decisions, the installer and tool logs,
`environment.json`, `verdict.txt`) go to `--out`; the committed evidence is
[docs/evidences/atls-gateway-kind-2026-11-25](evidences/atls-gateway-kind-2026-11-25/README.md) (17
checks, all passed, ten and a half minutes from two empty clusters).
On the zones the same releases take the peer's entry address and the zone PKI's certificates as zone
facts; the CUG interconnect (SRS 2.4.3) is the transport this hop will run over.

## Not covered here

- **TRAIN at the handshake.** The peer's measurement is verified against the configuration the
  attester holds, not yet against TRAIN: the resolver of the TRAIN work plugs into
  `atls.Config.PeerVerifier` ([Attested channel control, interface](attested-channel.md#interface))
  when that work lands.
- **The Connector's routing.** How the attested channel composes with the Connector's zone gateway
  (Envoy, its per-request routing record) is the chaining work that follows; on the zones the
  inter-zone hop is still the Connector routing over verified TLS until then.
- **The TCR lane** stays reserved until the TCR has a chart.
- **Real measurement.** The attester signs a measurement log rendered from Git; nothing measures the
  running container.
