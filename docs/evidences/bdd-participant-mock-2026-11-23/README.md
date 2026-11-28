# Participant backend mock row as executable BDD (2026-11-23)

Row ZT-74 (*Participant Backend Mock*, G3) runs as a Go scenario in the cluster mode
(`BDD_MODE=cluster`, steps in `internal/bdd/participant_mock_cluster_test.go`) on a throwaway kind
cluster. The scenario runs the participant-backend mock proof,
[`scripts/verify-guard-catalogue/verify.sh --participant`](https://github.com/eclipse-xfsc/facis-zero-trust-demonstrator/blob/main/scripts/verify-guard-catalogue/README.md),
and decides the row from the records the proof writes (`decideParticipantMock`, held to those records
by `TestDecideParticipantMock`, which runs in the strict mode), not from its exit status alone.

The trusted channel of this row is the in-zone mesh path, as decided by the Project Leader on 23 Nov
and as for ZT-73: mutual TLS between workload identities and a DPoP-bound token through the
Connector's guard. It is not the attested inter-zone channel.

| | |
|---|---|
| Run | `zt74-20261123T160944Z`, target `kind`, 16:09-16:13 UTC |
| Commit | `1800544a` (clean tree) |
| Where | kind cluster `ztd-zt74` (one node, Kubernetes v1.35.8, Istio 1.31.1 with istiod's CA, trust domain `cluster.local`), `kube-system` UID `e1da1595-7e50-4480-9591-9c512115f200`, namespace `ztd-m3`; created and deleted by the run, own kubeconfig, no zone touched |
| Result | 1 scenario, 3 steps, all passed (`bundles/bdd/zt74-cluster-report-zt74-20261123T160944Z.json`); the proof's verdict PASS, 25 checks |
| Evidence | `bundles/bdd/evidence/bdd-zt-074/kind/zt74-20261123T160944Z/` (git-ignored, delivered with the submission) |

```bash
GUARD_CATALOGUE_KIND_CLUSTER=ztd-zt74 GUARD_CATALOGUE_REGISTRY_NAME=kind-registry-zt74 GUARD_CATALOGUE_HOST_REGISTRY=127.0.0.1:5074 \
BDD_TARGET=kind BDD_RUN_ID=<run> BDD_MODE=cluster GODOG_CUCUMBER_OUT=bundles/bdd/zt74-cluster-report-<run>.json \
  go test ./internal/bdd -count=1 -timeout 60m -godog.tags='@ZT-74'
```

## The row

| Step | What runs | Result |
|---|---|---|
| Given the participant-backend mock is configured with the approved Connector endpoints | requires the run's inputs (target, run id); the configuration itself is the first record decided below | passed |
| When the demonstrator scenario runs | `verify.sh --participant`: kind with the mesh (namespace STRICT, the zone's XFCC sanitization), PostgreSQL, OpenBao, the Connector, the token store, the Protected Resource in token mode, the guard chart with its policy evaluator; then the Participant service from this branch (`services/participant`, image built by the run) installed from `deployment/helm/application-service` in token mode under the Participant's service account. It bootstraps at the Connector by itself, is asked by the operator's identity for one report, which it fetches through the guard, and for one more while the policy evaluator is scaled to zero | passed |
| Then the mock behaves as a participant backend using the trusted channel and publishes its registration/request/status events to the visualization | `decideParticipantMock` over the record | passed |

As recorded:

- **Configured** (`config.json`, read from the running Deployment): `PARTICIPANT_ADAPTER_MODE=token`,
  `PARTICIPANT_CONNECTOR_URL=http://ztd-connector:8080`, `PARTICIPANT_RESOURCE_URL=http://ztd-guard:8080`
  (the Connector's guard, not the resource), audience `https://guard.facis.invalid`. Its network
  policy (`participant-networkpolicy.json`) opens the Connector, the guard and istiod and nothing else.
  Its credentials are the client the Connector registered in this run for the guard's audience.
- **Behaves as a participant backend** (`state.json`): mode `token`, `registering`, `registered`,
  `presenting`, `acquiring_token`, `ready`. `served.http`: 200, outcome `success`,
  `RESOURCE_SUMMARY_RETURNED`, the summary of the sample report, under
  `c6420604172e064ca2ec33dc39c27b0c`; `resource.log` holds that id.
- **Fail closed** (`refused.http`): with the policy evaluator away, 503, outcome `unavailable`,
  `TOKEN_RESOURCE_UNAVAILABLE`, empty `safeData`, under `78d480004fc04247fce48e71947c4938`; the
  resource's log does not hold that id.
- **Using the trusted channel** (`hops.jsonl`, the receivers' sidecar counters `istio_requests_total`,
  reporter destination; `mesh-policies.json`):

  | Caller identity | Receiver identity | Security | Answer | Requests |
  |---|---|---|---|---|
  | `spiffe://cluster.local/ns/ztd-m3/sa/ztd-participant` | `…/sa/ztd-connector` | `mutual_tls` | 200 | 2 (challenge, grant) |
  | `…/sa/ztd-participant` | `…/sa/ztd-connector` | `mutual_tls` | 400 | 1 (the grant's DPoP nonce round) |
  | `…/sa/ztd-participant` | `…/sa/ztd-guard` | `mutual_tls` | 200 | 1 |
  | `…/sa/ztd-participant` | `…/sa/ztd-guard` | `mutual_tls` | 503 | 1 |
  | `…/sa/ztd-guard` | `…/sa/ztd-protected-resource` | `mutual_tls` | 200 | 1 |

  The guard's and the resource's AuthorizationPolicies admit one identity each (the Participant's,
  the guard's). The token is the Participant's own, DPoP-bound to a key generated in its process.
- **Publishes its events** (`feed.jsonl`, 11 events read by the UI's identity from the bridge's
  `/v2/events`; ingest `{"accepted":11,"refused":0}`), source `participant-b`, IF-01 v2, one run id
  `participant-b-a2292b591597716d65abfaa6`:

  | Event | State | Correlation id |
  |---|---|---|
  | registration | `registering`, `registered` | the run id |
  | status | `presenting`, `acquiring_token`, `ready` | the run id |
  | request | `success`, `APP-RESOURCE-SUMMARY-RETURNED` | `c6420604…`, also the id of the resource's access event (`access role=viewer`, `success`) |
  | request | `unavailable`, `APP-TOKEN-RESOURCE-UNAVAILABLE` | `78d48000…`, on no other event |

  The feed also holds exactly two guard decisions for the caller
  `spiffe://cluster.local/ns/ztd-m3/sa/ztd-participant` with the token of the Participant's client:
  one `allowed` (rule `m3-report-summary`, with the policy's decision under the same guard id) and
  one `denied`, `POL-PDP-UNAVAILABLE`.

The row is held only when every item above is in the record; `TestDecideParticipantMock` fails it on
each missing record and on 20 contrary ones (sample mode, another endpoint, a plain-text hop, another
caller identity, a missing or foreign event, a refused request that reached the resource, and so on).

## What the row needed that did not exist

- The proof's `--participant` mode (`3f6ad1c6`, `1800544a`): the first run in which the Participant
  service itself, not a curl pod with its service account, calls through the guard in the mesh with
  its lines read back from the feed bridge. No service code changed: the events are those added for
  ZT-75.

## Earlier runs of the day

- `zt74-20261123T155836Z` (commit `a420400f`): the proof passed 24 of 24, the row's decision failed on
  reading the answer's `safeData`; fixed in `72f6724b`, and the decision then held on that record.
- `zt74-20261123T160433Z` (commit `72f6724b`): the proof failed 5 checks. The first post to the
  bridge was answered `no healthy upstream` by the operator's sidecar right after the bridge's
  rollout, so the feed stayed empty. The post is now repeated until the bridge answers (`1800544a`).

## Checks

| Command | Result |
|---|---|
| `go build ./...` | pass |
| `go vet ./internal/bdd` | pass |
| `go run ./cmd/bddpack -check` | pass |
| `go test ./internal/bdd` | pass |
| `BDD_MODE=catalogue go test ./internal/bdd` | pass |
| `BDD_MODE=cluster-dryrun go test ./internal/bdd` | pass, the row listed as not run |
| `golangci-lint run ./...` (pinned build) | pass |
| `shellcheck scripts/verify-guard-catalogue/participant.sh` | pass |
| `BDD_MODE=cluster go test ./internal/bdd -godog.tags=@ZT-74` | pass, the run above |

## Limits

- kind only: Istio's own CA with trust domain `cluster.local`, not the zone's SPIRE chain; no
  admission policy; unsigned local images. Nothing was deployed on a zone.
- The in-zone mesh path, not the attested inter-zone channel.
- The guard's Envoy gives each request its own id, so the guard's decisions do not carry the
  Participant's correlation id. They are joined by caller identity and token subject (exactly two in
  the run); the Participant's id is shared by its request event, the resource's access event and the
  resource's log.
- "Visualization" is proven at the feed: the events are served by the bridge's `/v2/events`. No
  browser rendering was observed. No log forwarder runs on kind: the proof posts the producers'
  container log lines to `/ingest` under the bridge's producer identity.
- Registration is the provisioned-client form: the client was registered at the Connector by the
  run's registrar, and the Participant's registration step confirms it with an authenticated
  challenge. A rejected registration is on the feed in the ZT-75 run, not here.
- The role-carrying outcome is an IF-03 fixture outcome signed by a run key, as in the guard
  catalogue.
