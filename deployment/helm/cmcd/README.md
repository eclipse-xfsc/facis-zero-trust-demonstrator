# Attester (cmcd)

The zone's attester: CMC's `cmcd` ([Fraunhofer-AISEC/cmc](https://github.com/Fraunhofer-AISEC/cmc)) at
the version `go.mod` pins, built by [deployment/docker/cmcd](../../docker/cmcd/Dockerfile) with the
software driver only (no TEE; [ADR-0011](../../../docs/adr/0011-mock-tee-evidence-format-and-provisioning.md)).
It runs in the management plane as release `ztd-cmcd`: the attested-channel gateway asks it for the
zone's own evidence and has the peer zone's evidence verified by it, over the umbrella's lane
`atls-gateway-to-cmcd` ([docs/umbrella-chart.md](../../../docs/umbrella-chart.md)), whose destination
this chart's pods are (label `app.kubernetes.io/name=cmcd`, service account `cmcd`, Service `cmcd` on
`port`). Nothing else reaches it: the mesh default deny admits the lane's identity only, and the
gRPC API, plain on the pod, is under mesh mutual TLS between the two sidecars (`<name>`
PeerAuthentication STRICT).

**Material** (`materialSecret`, required): a Secret the pipeline, or a proof, creates and the chart
never renders, with four keys. `manifest.json` and `image-description.json` are the zone's reference
metadata, rendered from `deployment/attestation/<zone>.json` and signed by the pipeline's metadata
signer (CMC's `metatool`); `measurements.json` is the container measurement log rendered from the same
file, which the software driver measures; `metadata-ca.pem` is the CA the signer chains to, the only
root the daemon trusts. The signed metadata is read from files (`file://`), so no enrolment server
runs in the zone and the daemon fetches nothing: the material is what the pipeline delivered, verified
against the CA on every report ([Attestation evidence provisioning](../../../docs/attestation-provisioning.md)).
The daemon's writable state (its software attestation key, caches) lives in an `emptyDir`: a new pod
creates a new key, which the signed metadata does not pin, so evidence stays verifiable across restarts.

| Value | Meaning |
|---|---|
| `name` | the Deployment and ConfigMap name, `ztd-…` (the zone's naming rule) |
| `image.repository`, `image.digest` | the cmcd image, by digest only |
| `port` | the gRPC API's port, the Service port and the only port of the pod |
| `materialSecret` | the Secret described above |
| `logLevel` | cmcd's log level |
| `podAnnotations`, `nodeSelector`, `resources` | as in the other workload charts |

## From the zone file

`scripts/install-zone/install.sh` installs this chart as release `ztd-cmcd` when the zone file sets
`cmcd.install: true`, into `cmcd.namespace` (the management plane), with `cmcd.values` as this chart's
values, before the gateway release; `install.sh render ztd-cmcd` renders it the same way. `ci/values.yaml`
is a render-only placeholder; `ci/refused/` holds the values the chart refuses.
`scripts/verify-atls-gateway/verify.sh --kind` provisions a zone's material as the pipeline does and
installs this release in each of its two zones.
