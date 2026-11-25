# Authorized upstreaming row as executable BDD (2026-11-23)

Row ZT-73 (*Authorized Upstreaming over the Zero Trust Connector*, G3) runs as a Go scenario in the
cluster mode (`BDD_MODE=cluster`, steps in `internal/bdd/upstreaming_cluster_test.go`) against the guarded
path installed on zone B: Participant in token mode, guard with the policy evaluator and the token store,
protected resource, every hop inside the SPIRE-backed mesh. The scenario runs
`scripts/verify-guard-bypass/verify.sh` and decides the row from the records the script writes
(`decideUpstreaming`, held to those records by `TestDecideUpstreaming`), not from its exit status alone.

| | |
|---|---|
| Run | `zt73-20261123T140237Z`, target `zone-b`, 14:02-14:07 UTC, probe run `e80ab33a` |
| Commit | `cabc93c9` (clean tree) |
| Where | zone B, context `zerotrust-b`, `kube-system` UID `a39ae8ea-ac02-4aec-9c13-cda127b17e2d`, namespace `ztd-m3-b` (UID `ef71dd81-5629-4f9e-9b10-6adeb3e8298a`); the releases deployed there since 27 Oct, not reinstalled |
| Result | 1 scenario, 3 steps, all passed (`bundles/bdd/zt73-cluster-report-zt73-20261123T140237Z.json`); the script's verdict PASS, 12 checks |
| Evidence | `bundles/bdd/evidence/bdd-zt-073/zone-b/zt73-20261123T140237Z/` (git-ignored, delivered with the submission) |

```bash
KUBECONFIG=<zone B> KUBE_CONTEXT=zerotrust-b BDD_UPSTREAM_NAMESPACE=ztd-m3-b BDD_UPSTREAM_URL=https://160.44.12.245 \
BDD_UPSTREAM_CA=<CA of the edge certificate> BDD_PROBE_IMAGE=<admitted image with bash> \
BDD_TARGET=zone-b BDD_RUN_ID=<run> BDD_MODE=cluster GODOG_CUCUMBER_OUT=bundles/bdd/zt73-cluster-report-<run>.json \
  go test ./internal/bdd -godog.tags=@ZT-73
```

A missing input fails the scenario and is named; the cluster dry run lists the row as not run. The probe
image was the zone's own `postgres-runtime` image, by digest.

## The row

| Step | What runs | Decided from | Result |
|---|---|---|---|
| Given a registered participant backend with valid authorization and an available protected resource | `kubectl get deployment ztd-participant ztd-guard ztd-protected-resource`: each has an available replica | the cluster; the registration itself is the first record below | passed |
| When the backend calls through the Zero Trust Connector | `verify.sh`: resets the Participant, calls `POST /demo` on its public route, then calls the guard without a token and the resource past the guard from its own probe Jobs | exit status not 125 | passed |
| Then ... authorized ... AND an unauthorized request does not return protected data | `decideUpstreaming` over the record | see below | passed |

Authorized, as recorded:

- `state.json`: after the reset the Participant, mode `token`, went `presenting`, `acquiring_token`,
  `ready` (it presented its credential and obtained its DPoP-bound token from the connector).
- `guarded-status.txt`, `guarded-response.json`: `200`, outcome `success`, `RESOURCE_REPORT_RETURNED`,
  the report `FACIS-SAMPLE-REPORT-001` (request `5f8416fd-2735-42b5-940c-e52d458590c1`).
- `guarded-guard-record.jsonl`: the guard's decision event `allowed`, rule `m3-report-read`
  (event `e75e0d844210815c1521f8fc3277e1eb`).
- `guarded-resource-record.jsonl`: the resource served that request id for client `ztd-store`, the token
  store's substituted upstream token, which only the guard obtains.
- `guarded-stats-*`: the inbound `rbac.allowed` counter rose at the guard's sidecar (51 to 52) and at the
  resource's (49 to 50). Their AuthorizationPolicies admit one SPIFFE identity each (the Participant's at
  the guard, the guard's at the resource) under mutual TLS `STRICT`, so each hop was admitted by the
  identity its peer presented.

Unauthorized, as recorded:

- Through the guard, `tokenless-response.txt`: a meshed probe under the Participant's identity, with no
  token, got `401`, `reason_code` `token_absent`, no resource data. `tokenless-guard-record.jsonl`: the
  guard's `denied` event with that code under the correlation id the caller received
  (`253d9e079b3de32e336e87c409a1512c`).
- Past the guard, `meshed-response.txt`: the same identity calling the resource directly got
  `403 RBAC: access denied`. `meshed-receiver-log.txt`: the resource's sidecar logged
  `rbac_access_denied_matched_policy[none]` with source
  `spiffe://zone-b.trust.invalid/ns/ztd-m3-b/sa/ztd-participant` and destination
  `spiffe://zone-b.trust.invalid/ns/ztd-m3-b/sa/ztd-protected-resource`; `rbac.denied` 3 to 4.
- `resource-app-log-during-probes.txt` is empty: neither call reached the resource application.
- `unmeshed-events.json`: a probe without the mesh could not be created (admission rule
  `proxy-takes-spire-socket`).

The namespace was left as found: `objects.diff` is empty and no probe object remains.

## Changes to the proof script

`scripts/verify-guard-bypass/verify.sh` now also records the Participant's state after the reset, the
guarded answer's status and body, the guard's allowed event, the two sidecars' `rbac.allowed` counters, and
the tokenless call through the guard with the guard's denied event. Its node selector line produced
invalid YAML when `--node` was omitted; that is fixed.

## Limits

- The trusted channel of this run is zone B's mesh (mutual TLS between SPIFFE identities, DPoP-bound
  tokens on top), inside one zone. It is not the attested inter-zone channel (ZT-04, ZT-19 pending).
- The sidecars log refusals only, so the allowed hops are shown by the `rbac.allowed` counters and the
  one-identity policies, not by an access-log line naming both identities; the refused hop has that line.
  Another caller in the same seconds would also raise the counters.
- The zone's guard image (27 Oct) names the missing token by its runtime code `token_absent`; the registry
  code `TOK-MISSING` is the current guard's. The decider accepts either, and requires the response and the
  event to name the same one.
- That guard names its decision by its own correlation id, not the Participant's request id, so the
  allowed event is matched by time: the allowed decision in the five seconds up to the resource's record.
- The unauthorized calls are a missing token and a skipped guard. A valid token refused by policy on the
  live path is not in this run (the [guard catalogue on kind](../guard-catalogue-kind-2026-11-22-r2/README.md) has it).
- The tokenless probe carries the Participant's pod labels, the only caller the guard's network policy
  admits; it is never ready, so never a Service endpoint, and is deleted on exit.
- The connector and token store on zone B run on OpenBao tokens that expire on 28 Nov; a rerun after that
  fails at the Participant's reset until they are reissued.
