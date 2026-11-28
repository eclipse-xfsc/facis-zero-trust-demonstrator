# Mesh rows ZT-01, ZT-27 and ZT-58 as executable BDD scenarios

2026-11-23, local kind clusters `kind-ztd-mesh2` (three nodes, Kubernetes v1.35.8, Cilium 1.20.2
chained, from `scripts/dev/kind-cilium-up.sh`), commit `c44866b6` (tree clean), trust domain
`kind.facis-ztd.local`. Two clusters of that name were used, one after the other, and the last was
deleted after its run:

| Run | Rows | UTC | `kube-system` UID | Result |
|---|---|---|---|---|
| `mesh2-20261123-obs1` | ZT-27 | 14:56-15:04 | `82270097-33f1-459b-b096-a68881430533` | passed |
| `mesh2-20261123-id2` | ZT-01, ZT-58 (and ZT-24, ZT-57, ZT-59, ZT-60 again) | 15:46-15:58 | `223d5fbf-156d-4c16-9ff9-1f3884ce743d` | all six passed |

The three rows left pending in the [mesh record](../bdd-mesh-2026-11-23/README.md) are implemented in
`features/annex/annex-a.json` as cluster rows (`@cluster`). Each needed a small addition before an
existing proof could decide it; the additions are below, with the row.

## ZT-01 Secure Service Mesh

*Then the in-mesh call is carried over the mesh under mutual TLS AND the out-of-mesh call is blocked
and logged.*

The mesh identity proof showed the call of a pod without a certificate refused, and stated that
nothing was logged for it. Two additions:

- **The mesh logs the refusal.** `zone-policy`'s `Telemetry` `mesh-default` gains a third clause,
  `response.code_details == "filter_chain_not_found"`: a connection without mutual TLS matches no
  filter chain of a STRICT listener, and the listener now writes it to the denial log. The
  `denial-log` provider of the `istiod` release gains the label `address`
  (`%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%`), all such a line holds of the caller. The chart gate
  (`scripts/ci/chartcheck`, `TestDenialLogFilter`) holds the filter to exactly its three clauses.
- **The proof makes the same call from outside the mesh.** Section 9 of
  `scripts/verify-mesh-identity/verify.sh`, `out-of-mesh-call-blocked-and-logged`: the proxy-less
  stand-in `probe` in `ztd-data`, with no proxy and no identity, calls
  `http://peer.ztd-data.svc:8080/hostname`, the call the meshed `caller` makes, open at the network
  layer for both.

The steps (`internal/bdd/workload_identity_cluster_test.go`) run that proof once per test process, as
for the workload identity rows, and decide the row from sections 0, 1, 2, 5, 8, 9 and 10 of its
`evidence.md`: no failed check in them, and these `PASS` lines among them:

| Clause | Checks | In the run |
|---|---|---|
| workload identities issued | the proxy's certificate has `O = SPIRE` | passed |
| the in-mesh call under mutual TLS | the labelled pod's call to the peer succeeds; the peer sees the caller's own SPIFFE ID in `X-Forwarded-Client-Cert`; both proxies counted the request; the peer's proxy records it as `mutual_tls`; the served call left no denial line | `200 peer`, passed |
| the out-of-mesh call blocked | the call of the proxy-less `probe` is refused; the call from the network namespace of the pod without a certificate, on another node, is refused | `denied(56)` both |
| and logged | the peer's proxy wrote a line for each, without a source identity, with the caller's pod address, `detail` `filter_chain_not_found`, `flags` `NR` | passed, both |

Passed on 98 checks.

## ZT-58 Service Mesh Setup

*Then service traffic is captured on each node and protected with workload-certificate-based mutual
TLS.*

Nothing was added: the record of the mesh identity proof already holds it. Decided from sections 0,
1, 2, 4, 7, 10, 11 and 12: every SPIRE agent attested and the mesh on the zone's trust domain; the
proxy a native sidecar; the Istio CNI plugin, which sets up the capture, chained after Cilium in the
CNI configuration of each of the three nodes; on each node with a SPIRE agent a meshed stand-in
Ready with a certificate issued by the SPIRE CA under its own SPIFFE ID; each of those nodes calling
the next across the node boundary, the receiver seeing the caller's SPIFFE ID and both proxies
counting the request as mutual TLS; every proxy `SYNCED` with istiod. Passed on 120 checks.

The whole run `mesh2-20261123-id2`: 226 checks, 0 failed. ZT-24, ZT-57, ZT-59 and ZT-60 ran in the
same process and passed (128, 36, 92 and 39 checks), so the additions did not break them.

```bash
KUBE_CONTEXT=kind-ztd-mesh2 BDD_TARGET=kind BDD_RUN_ID=mesh2-20261123-id2 BDD_MODE=cluster \
  GODOG_CUCUMBER_OUT=bundles/bdd/go-cluster-mesh-identity-kind-mesh2-20261123-id2.json \
  go test ./internal/bdd -count=1 -timeout 150m -run TestFeatures \
  -godog.tags='@ZT-01,@ZT-58,@ZT-24,@ZT-57,@ZT-59,@ZT-60'
```

## ZT-27 Observability

*Then traces and metrics are exported from the cluster through the Collector, metrics are retained in
Prometheus and traces are queryable in the tracing backend AND a component emitting no telemetry is
visible as a gap in the correlated trace.*

The steps (`internal/bdd/observability_cluster_test.go`) check that the node collectors, the zone
gateway, the entry, Prometheus and Jaeger are ready, run `scripts/verify-observability/verify.sh`,
and decide the row from its `record.json`; the decision is held by `TestDecideObservability`. Two
additions to the proof:

- **`silent-component-is-a-gap`**, the clause no check covered. The client application of the
  correlated request hands on a span ID in `traceparent` and exports nothing. The check reads the
  stored trace from Jaeger and requires that this span ID is the one parent the trace's spans name
  that the trace does not hold. The control is the same request with the caller's span exported
  through the gateway: that trace has no missing parent.
- **The proof's own mesh pairs** (`fixtures/mesh-pairs.yaml`: client to echo, zone gateway to status
  list). On this base the mesh default deny refused both fixtures (the echo answered 403, the status
  list was never reported up), so the proof could not pass on kind at all; a first trial showed it.

| Clause | Checks of the record | In the run |
|---|---|---|
| traces and metrics exported through the Collector | `spire-agents-scraped`, `spire-server-scraped`, `workload-otlp-accepted`, `prometheus-scrapes-no-zone` | passed |
| logs exported through the Collector (the criterion's "OTEL logs available") | `pod-logs-collected`, `if01-fields-kept`, `logs-exported` | passed |
| metrics retained in Prometheus | `metrics-survive-restart` | passed: 8 samples of the minute before a restart, the same after |
| traces queryable in the tracing backend | `correlated-trace` | passed: trace `865e2500166f128b343d954600d24d1d` |
| a silent component is a gap | `silent-component-is-a-gap` | passed: span `15764ffe6ff63fe0` the only missing parent; control trace `51bb6d48a025f883455bbadfed158cca` whole |

Proof run `obs-20261123T145636Z-4641`: 24 checks passed, 1 failed. The failed one,
`zone-taken-from-listener`, is not one the row is decided on: the span that claims another zone was
not stored within the check's 60 s. It is sent just after the full-queue test, behind the spans that
test left queued. It passed in the first trial and failed in the second and in this run; the cause
was not established and CI's own run of the proof should be watched for it.

```bash
KUBE_CONTEXT=kind-ztd-mesh2 BDD_TARGET=kind BDD_RUN_ID=mesh2-20261123-obs1 BDD_MODE=cluster \
  GODOG_CUCUMBER_OUT=bundles/bdd/go-cluster-observability-kind-mesh2-20261123-obs1.json \
  go test ./internal/bdd -count=1 -timeout 90m -run TestFeatures -godog.tags='@ZT-27'
```

The cluster was prepared as `scripts/verify-observability/README.md` says (cert-manager, the kind
zone, the demonstrator role, the telemetry releases, the echo image built for the host's
architecture).

## Records

Git-ignored, delivered with the milestone submission: the cucumber reports named above, the mesh
identity record (`bundles/bdd/evidence/workload-identity/kind/mesh2-20261123-id2/`), the
observability record (`bundles/bdd/evidence/bdd-zt-027/kind/mesh2-20261123-obs1/`: `evidence.md`,
`record.json`, `run.log`, `render/`, `decision.txt`) and each row's decision
(`bundles/bdd/evidence/bdd-zt-0NN/kind/<run>/decision.txt`).

## Limits

- **Kind only.** The rows speak of each target cluster. The mesh identity proof reinstalls the zone
  and the observability proof stops and restores its components; neither was run on zone A or
  zone B. The zones also run no collector, Prometheus or tracing backend yet, and their installed
  `zone-policy` has neither the new filter clause nor the `address` label until they are upgraded.
- **One run of the mesh identity rows failed for the environment, not the rows.** A run started
  on the cluster that still held the observability stack (`mesh2-20261123-id1`) could not reach a
  clean slate and every row was decided failed; the cluster was recreated for `id2`.
- **ZT-01: the out-of-mesh workloads are stand-ins inside the data-plane namespace**, admitted there
  only with the capture rule lifted for their creation. A workload in another namespace is stopped
  earlier, by the network default deny, which this row's log does not cover. The log line holds the
  caller's address, not an identity: it has none.
- **ZT-27: the security decisions are the proof's.** The traffic is the proof's echo request through
  the mesh; the decision events are the two IF-01 records a fixture writes and the revocation probe,
  not a policy decision of the demonstrator's own services. The gap shown is a span the trace names
  and does not hold; a component that neither emits nor hands on the trace context splits the trace
  in two instead, which is not shown.
- **macOS host.** The observability proof uses GNU `date`, `realpath -m` and `wc`; the run used
  shims for them outside the repository. Nothing in the repository was changed for it.
- The plane-separation proof reads any new denial line after a proxy-less network probe as "the
  mesh refused it". A plain-text connection that reaches a meshed pod now writes one, which is the
  correct reading; that proof was not rerun.
- The cluster dry run lists the three rows and skips every step.
