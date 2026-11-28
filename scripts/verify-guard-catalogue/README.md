# verify-guard-catalogue

The guard's negative-case catalogue through the deployed chain on a throwaway kind
cluster: the guard chart (Envoy with the ext_authz hook, the policy evaluator) installed from values
only, the protected resource, the token store and the connector from the working tree, PostgreSQL
and OpenBao from the pinned images, every pod meshed by Istio 1.31.1 with STRICT mTLS and the zone's
XFCC sanitization (`zone-policy`, EnvoyFilter `xfcc-sanitize-set`).

```sh
scripts/verify-guard-catalogue/verify.sh [--out DIR]     # default .dev/guard-catalogue (git-ignored)
```

Needs docker, go, helm, kind, kubectl, curl, jq and openssl. `KEEP=1` leaves the cluster running.
`GUARD_CATALOGUE_KIND_CLUSTER`, `GUARD_CATALOGUE_REGISTRY_NAME` and `GUARD_CATALOGUE_HOST_REGISTRY`
rename the cluster, the registry container and its host port; the script keeps its own kubeconfig.

## What it proves

| Case | Caller's answer | Decision events (IF-01 v2) |
|---|---|---|
| allowed (control) | 200 from the resource | guard `allowed`, policy rule `m3-report-summary`; the same id in the resource's record and on the feed bridge |
| no token | 401 `TOK-MISSING` | guard, bundle and rule `not_evaluated` |
| missing proof | 401 `TOK-PROOF-INVALID` | guard, detail `proof_absent` |
| proof signed by the wrong key | 401 `TOK-JKT-MISMATCH` | guard |
| insufficient scope | 403 `POL-RULE-DENY`, rule `m3-scope-required` | guard and policy |
| policy-only denial | 403 `POL-RULE-DENY`, rule `m3-client-blocked` | guard and policy |
| presentation required | 401 `POL-PRESENTATION-REQUIRED`, the OID4VP link in the body | guard and policy |
| replayed proof | 401 `TOK-REPLAY` | guard |
| wrong mesh caller | 403 `RBAC: access denied` from the guard's sidecar | none: refused before the hook |
| policy engine down | 503 `POL-PDP-UNAVAILABLE` | guard |
| token store down | 503 `TOK-STORE-UNAVAILABLE` | guard |
| expired token | 401 `TOK-EXPIRED` | guard |

A token for the wrong audience cannot be obtained by a participant at all (the connector refuses it
the challenge); `TestGuardWithRealConnectorStorePolicyPostgresAndOpenBao` covers that case and the
guard's own `MESH-PAIR-DENIED` on the token path with the real connector, store, PostgreSQL and
OpenBao, and writes the same catalogue to `$GUARD_CATALOGUE_OUT/catalogue.json`.

The feed bridge is then installed from its chart (`deployment/helm/feed-bridge`) in the mesh: the
producer identity posts the guard's and the policy's lines to `/ingest`, the UI's identity reads
both feed versions and finds the allowed request's events, and the Participant's identity (feed) and
another identity (`/ingest`) are refused by the bridge's sidecar (`403 RBAC: access denied`).

The run also records the latency of the presentation-required decision through the guard (the
whole chain, denied at policy, 401) against a mesh round trip from the same pod to another service
without the guard (the connector's key set, 200), `GUARD_CATALOGUE_SAMPLES` (100) of each,
sequential, measured by curl inside the participant's pod.

## Guarding through the TSA: `--tsa`

```sh
BIN=<dir with a linux cosign> scripts/verify-guard-catalogue/verify.sh --tsa [--out DIR]
```

The same chain, with three differences: the policy evaluator decides through the XFSC TSA policy
service (`deployment/helm/tsa-policy`, in the mesh, its own namespace) and a Rego bundle packed from
`policies/tsa/facis/guard/1.0`, signed and published for the run; the guard chart's own policy rules
are not set, so the rule, the revision and the OID4VP link of every decision can only be the
bundle's; and the guard serves a gRPC method of the Protected Resource
(`/grpc.health.v1.Health/Check`, the resource's `PROTECTED_RESOURCE_GRPC_ADDRESS`) beside `/demo`.
It runs the guarding cases instead of the catalogue, the feed and the latency, each over REST
(curl) and over gRPC (curl, HTTP/2 prior knowledge, one framed request) from the Participant's pod:

| Case | REST | gRPC | Decision events (IF-01 v2), bundle revision `kind-guarding-1` |
|---|---|---|---|
| authorized | 200 from the resource | `grpc-status: 0`, `SERVING` from the resource | guard and policy `allowed`, rule `m3-report-summary`; the same id in the resource's record |
| unauthorized (a token whose scope the policy has no rule for) | 403 `POL-RULE-DENY` | `grpc-status: 7`, `x-facis-reason-code: POL-RULE-DENY` | guard and policy `denied`, rule `m3-default-deny`; the id is not in the resource's record |
| presentation required | 401 `POL-PRESENTATION-REQUIRED`, the OID4VP link in the body and in `x-facis-oid4vp-link` | `grpc-status: 16`, the link in `x-facis-oid4vp-link` | guard and policy `denied`, rule `m3-presentation-required`; not in the resource's record |

The record is `cases.jsonl` (one line per case: the answer, the correlation id, both events,
whether the resource's log holds the id, the verdict), each answer (`<case>.http`), the events, the
resource's log, the bundle sidecar's log (`bundle activated`), the bundle's data
(`bundle-data.json`), the namespace's objects as installed and `environment.json`. The row ZT-20
of the BDD pack runs this and decides from `cases.jsonl`.

## The participant-backend mock: `--participant`

```sh
scripts/verify-guard-catalogue/verify.sh --participant [--out DIR]
```

The same chain, with the Participant service itself (`services/participant`, the working tree's
image) as the caller: installed from `deployment/helm/application-service` in token mode, in the
mesh under the Participant's service account, configured with the Connector's and the guard's
addresses, its network policy opening those two and istiod. It runs this instead of the catalogue
and the latency:

- the Participant bootstraps by itself at the Connector: it checks its registration (the client the
  Connector registered in this run, mounted as credentials), presents and obtains its DPoP-bound token;
- the operator's identity asks it for one report, which it fetches through the guard (200, the
  resource's data), and for one more while the policy evaluator is scaled to zero (503
  `TOKEN_RESOURCE_UNAVAILABLE`, no data, nothing at the resource);
- each receiver's sidecar (Connector, guard, resource) is asked for its request counters
  (`istio_requests_total`, reporter destination): requests answered 200 over `mutual_tls` from the
  Participant's identity to the Connector and to the guard, and from the guard's to the resource;
- the feed bridge is installed from its chart and the producer identity posts the Participant's, the
  resource's, the guard's and the policy's lines to `/ingest` (no log forwarder runs on kind); the UI's
  identity reads `/v2/events` back and finds, under the Participant's one run id, its registration
  event and its status events up to `ready`, and under each request's id its request event with the
  outcome; the served request's id is also on the resource's access event. The guard's Envoy names
  each request itself, so its two decisions are found by caller and token: one `allowed` and one
  denied `POL-PDP-UNAVAILABLE` for the Participant's SPIFFE identity with its client's token.

The record is `run.json`, `config.json` (the Deployment's `PARTICIPANT_*` environment), `state.json`,
`served.http`, `refused.http`, `hops.jsonl`, `feed.jsonl`, `resource.log`, the producers' lines,
`mesh-policies.json` and `environment.json`. The row ZT-74 of the BDD pack runs this and decides
from those records.

## Not proven here

The mesh is Istio's own CA with trust domain `cluster.local`, not the zone's SPIRE chain
(`scripts/verify-mesh-identity`); no admission policy runs; the cluster's CNI is kind's. The live
proofs on the zones are archived under `docs/evidences/`.

## The record

`verdict.txt`, `catalogue.tsv` (one row per case: status, reason code, rule, correlation id, the
guard's and the policy's event, the verdict), each response (`<case>.http`), the guard's and the
policy's event lines, the resource's record of the allowed request, the feed bridge's snapshot and
stream per run, `latency.tsv` and `environment.json`. Exit status: the number of failed checks.
