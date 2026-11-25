# Guard negative-case catalogue on kind

Records of `scripts/verify-guard-catalogue/verify.sh` (verdict PASS, every check), run 2026-11-22
00:20-00:43 UTC on a disposable kind cluster on an arm64 Mac (Docker Desktop), commit `a69861b0`
with the script as committed in `56f8c000` (the run's tree was dirty only by that script and this
folder). What ran, what it proves and what it does not: `scripts/verify-guard-catalogue/README.md`.

| File | What it is |
|---|---|
| `catalogue.tsv` | one row per case: status, reason code, rule, correlation id, the guard's and the policy's IF-01 v2 event, the expectation and the verdict |
| `responses/<case>.http` | each answer as the caller received it (headers and body; no credential is echoed) |
| `events/guard-events.jsonl`, `events/policy-events.jsonl` | every decision line the guard and the evaluator wrote during the run |
| `events/feed-v1-*.txt`, `events/snapshot-v1-*.json`, `events/feed-v2-*.txt`, `events/snapshot-v2-*.json` | the feed bridge's streams and snapshots per run in both feed versions, regenerated from those lines by the versioned bridge (the run's own `/snapshot` files named a policy panel, which v1 does not allow, and were replaced); `TestArchivedEvidenceValidatesInBothVersions` validates them |
| `resource-record.json` | the resource's record of the allowed request, under the guard's correlation id |
| `latency.tsv` | the presentation-required decision through the guard against a mesh round trip without it |
| `guard-values.yaml` | the guard chart's values: the whole configuration of the deployed chain |
| `environment.json`, `verdict.txt` | the run's pins and checks |
| `go-test/catalogue.json` | the same catalogue from `TestGuardWithRealConnectorStorePolicyPostgresAndOpenBao` (real connector, token store, PostgreSQL and OpenBao in containers), including the guard's own `MESH-PAIR-DENIED` and `TOK-INVALID` (wrong audience) cases that a meshed kind caller cannot reach |

## One correlation id across the chain

The allowed request `e29234a01b9060c7f07bf213fc41c1a0`: the guard's v2 decision event (`allowed`,
caller SPIFFE id, token subject, resource, rule `m3-report-summary`, bundle `kind-catalogue-1`),
the policy evaluator's event under the same id, the resource's request record
(`requestId`/`correlationId`), and both events on the feed bridge's streams.

## Latency

Conditions: 100 sequential samples each, measured by curl inside the participant's pod (through
its sidecar), kind single node on a shared, loaded laptop (other clusters running). Guarded: a
presentation-required denial (Envoy, ext_authz hook, token and DPoP check, replay record in
PostgreSQL, policy decision; 401 with the OID4VP link). Baseline: a mesh round trip from the same
pod to the connector's key set (200), without the guard.

| | p50 | p99 |
|---|---|---|
| guarded (401) | 7.0 ms | 38.2 ms |
| baseline (200) | 2.2 ms | 14.0 ms |

Added p99 about 24 ms under these conditions. A laptop kind cluster is not the zones' network; the
number is indicative.
