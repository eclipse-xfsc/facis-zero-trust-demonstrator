# TRAIN allow list row as executable BDD (2026-11-23)

The G3 row ZT-18 of the family *trust-lists* runs as a Go scenario in the cluster mode
(`BDD_MODE=cluster`, steps in `internal/bdd/trust_lists_cluster_test.go`). The functionality it needs
was added with it: `connector admit-peers` and the `ingress.peerAllowList` values of the
`connector-gateway` chart ([TRAIN allow list of the zone entry](../../connector.md#train-allow-list-of-the-zone-entry-zt-18)).
Its proof is `scripts/verify-train-allow-list/verify.sh`: our TSPA image and Keycloak's test realm on
Docker, a trust list naming one counter-connector published through the TSPA's API, two
counter-connectors (the chart's egress role on the pinned Envoy, one client certificate each) and an
entry (the chart's ingress role with the allow list, `connector admit-peers` built from the working
tree in the entry's network namespace). The scenario runs the verifier and decides the row from its
record.

| | |
|---|---|
| Run | `zt18-20261123T140456Z`, target `local-services` |
| Commit | `97a0edf5` (clean tree) |
| Where | project lead's workstation (Darwin arm64, Go 1.27.0), Docker 28.5.1 linux/arm64: `ztd-tspa:local` (`sha256:efbfb7c1f233bee223e978d4ee6b7b62ef33b67a597f8649b38b4fb339cc1e01`), `quay.io/keycloak/keycloak:26.0.8@sha256:09a381c715ab0b111835b70f2905955274843a219c6f27efb348e4d9f4086858`, `docker.io/envoyproxy/envoy:v1.36.10@sha256:3a76238cdf52c7a3e33951f44c02d694108e6481feffe6663bf9319f55ec1394`. **No Kubernetes cluster**: no kube-system UID applies; no zone was touched |
| Result | 1 scenario, 3 steps, all passed (`bundles/bdd/zt18-cluster-report.json`); the verifier 10 of 10 |
| Evidence | `bundles/bdd/evidence/bdd-zt-018/local-services/zt18-20261123T140456Z/` (git-ignored, delivered with the submission): `run.txt`, `record.json`, `events.jsonl`, `vc.json`, `trust-list.json` |

```bash
BDD_TARGET=local-services BDD_RUN_ID=<run> BDD_MODE=cluster GODOG_CUCUMBER_OUT=bundles/bdd/zt18-cluster-report.json \
  go test ./internal/bdd -timeout 30m -godog.tags='@ZT-18'
```

A missing input fails the scenario and is named; the cluster dry run lists the row as not run.

## Row

| Step | What it runs | Decided from |
|---|---|---|
| GIVEN a TRAIN trust list naming the permitted counter-connector | the verifier, whole run | `trust-list.json`, the list the TSPA served: `did:web:connector-a.facis-ztd.local` is the `ServiceTypeIdentifier` of an `active` service |
| WHEN connections are attempted from a listed and from an unlisted counter-connector | — | `record.json` holds an answered attempt of each |
| THEN the listed peer is admitted on the basis of the retrieved trust list AND the unlisted peer is refused. | — | `record.json`, per case the status, the reason code of the answer, the requests that reached the upstream and the decision event of `connector admit-peers`; the verifier's exit status |

| Case | Answer | Decision event | Upstream |
|---|---|---|---|
| listed peer | 200 | `allowed`: the peer, the framework, the issuer, valid until the VC's expiry (`2026-12-23T14:05:30Z`, equal to the published VC's `expirationDate`) | 1 request |
| unlisted peer (a certificate of the same CA) | 403 `CHAN-ZONE-UNKNOWN` | `denied`, `CHAN-ZONE-UNKNOWN`, the peer named | none |
| withdrawn peer (its entry deleted at the TSPA) | 403 `CHAN-ZONE-UNKNOWN` | `denied`, `CHAN-ZONE-UNKNOWN` | none |
| peer listed again | 200 | `allowed` | 1 request |
| trust list unavailable (the TSPA stopped) | 503 `CHAN-TRUST-UNREACHABLE` | `denied`, `CHAN-TRUST-UNREACHABLE` | none |

The verifier also checks, outside `record.json`: the chart renders the entry with the check and a
required client certificate, and a client without a certificate does not complete the TLS handshake.

## Limits

- Not a cluster run: no mesh, no NetworkPolicy. The lane `<name>-trust-list`, the second container of
  the entry's pod and the client certificate mount are proven by the chart's render checks only
  (`scripts/ci/check-charts.sh`, the policy address and L7 owner checks on the chart's renders).
- Not deployed on a zone: zone B's entry does not demand a client certificate, zone A's gateway holds
  none, and zone B's TSPA still runs the upstream image, whose trust lists must not be trusted.
- The trust list issuer's DID is configuration; the TCR's DNS walk from the trust framework pointer is
  not part of this path. The DID document is served by a stand-in under a run CA.
- `ztd-tspa:local` is the image present on the workstation, identified by its id above; it was not
  rebuilt for this run.
- The counter-connectors' certificates come from a run CA and carry a `did:web` URI as their name;
  which CA and which names the zones use is not decided.
- A verified list is kept for the refresh interval (2 s in this run, 5 minutes by default): a
  withdrawal or an outage takes effect when it has passed.
