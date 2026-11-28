# Guarding Functionality (ZT-20) as an executable BDD scenario

2026-11-23 14:05-14:19 UTC, throwaway kind cluster `ztd-zt20` (one node, Kubernetes v1.35.8, Istio
1.31.1 with istiod's CA, trust domain `cluster.local`), `kube-system` UID
`c55e5f52-4727-41e6-8cce-7bc611f71f24`, commit `c3a7cf37` (tree clean), run id
`guarding-20261123T140516Z`, target `kind`. The cluster was deleted after the run; no zone was touched.

The row is implemented in `features/annex/annex-a.json` as a cluster row (`@cluster`). Its steps
(`internal/bdd/guarding_cluster_test.go`) run the guarding proof,
[`scripts/verify-guard-catalogue/verify.sh --tsa`](https://github.com/eclipse-xfsc/facis-zero-trust-demonstrator/blob/main/scripts/verify-guard-catalogue/README.md),
and decide the row from the `cases.jsonl` it records, case by case, not from the proof's own verdict
alone. The decision is held by `TestDecideGuarding`, which runs in the strict mode.

```bash
BIN=<dir with a linux cosign> BDD_TARGET=kind BDD_RUN_ID=guarding-20261123T140516Z BDD_MODE=cluster \
  GODOG_CUCUMBER_OUT=bundles/bdd/guarding-cluster-report.json \
  go test ./internal/bdd -count=1 -timeout 60m -godog.tags='@ZT-20'
```

Result: 1 scenario, 3 steps, passed (`bundles/bdd/guarding-cluster-report.json`); the proof 17 of 17
checks. The record is `bundles/bdd/evidence/bdd-zt-020/kind/guarding-20261123T140516Z/` (git-ignored, delivered
with the submission).

## What ran

| Step | What it does |
|---|---|
| Given a protected resource behind the Connector guard | requires the run's inputs (`BIN` with cosign, target, run id) |
| When a request with matching authorization and a request without matching authorization are executed | runs the proof: a kind cluster with the mesh (STRICT mTLS, the zone's XFCC sanitization); PostgreSQL, OpenBao, the connector and the token store; the Protected Resource in token mode with its REST route and its gRPC method; the TSA policy service from `deployment/helm/tsa-policy` (pinned TSA image `tsa/policy:1.1.4@sha256:0275b144…`) in its own meshed namespace with a Rego bundle packed from `policies/tsa/facis/guard/1.0`, signed and published for the run (revision `kind-guarding-1`), verified and activated by the bundle sidecar; the guard chart from values only with `tsa.evaluationURL` and `grpc.methods`, and no policy rule of its own. A Participant pod obtains its tokens through the verified-presentation grant and sends each request once over REST and once over gRPC |
| Then the authorized request passes the PEP/PDP policy chain AND the unauthorized request is denied before the protected resource returns data | decides from `cases.jsonl` (below) |

## The cases, as recorded

| Case | Answer to the caller | Policy rule, bundle revision | Decision events under the id | Resource's record |
|---|---|---|---|---|
| `rest-authorized` | 200 | `m3-report-summary`, `kind-guarding-1` | guard and policy `allowed`, `3420ecedd354d3db912a820f305e76a4` | holds the id |
| `rest-unauthorized` | 403 `POL-RULE-DENY` | `m3-default-deny`, `kind-guarding-1` | guard and policy `denied`, `db7cba8ef651290d1cc29c474f84aef5` | no line |
| `rest-presentation-required` | 401 `POL-PRESENTATION-REQUIRED`, the OID4VP link in the body and in `x-facis-oid4vp-link` | `m3-presentation-required`, `kind-guarding-1` | guard and policy `denied`, `4d7d3036385dd4e75df10c47a43b07fc` | no line |
| `grpc-authorized` | `grpc-status: 0`, `SERVING` | `m3-report-summary`, `kind-guarding-1` | guard and policy `allowed`, `cb37927fadc48aa45752cbb40f90635b` | holds the id |
| `grpc-unauthorized` | `grpc-status: 7`, `x-facis-reason-code: POL-RULE-DENY` | `m3-default-deny`, `kind-guarding-1` | guard and policy `denied`, `2399e73fe1e1754e771a40876d064d38` | no line |
| `grpc-presentation-required` | `grpc-status: 16`, the OID4VP link in `x-facis-oid4vp-link` | `m3-presentation-required`, `kind-guarding-1` | guard and policy `denied`, `319762cfce458d4a8da01715b8f15721` | no line |

The row is held only when, for both protocols: the authorized request has the guard's and the
policy's `allowed` events under one id and the resource's log holds that id; each denied request has
the guard's and the policy's `denied` events with the answered reason code under the id the caller
received and the resource's log does not hold it; every policy event names a rule and the revision
of the run's bundle (the chart's `policyRevision` was another value, `kind-catalogue-1`, and the
chart carried no policy rule, so the decisions and the link can only be the bundle's); and the
presentation-required answer carries an `openid4vp:` or `https:` link. The evaluator logged the six
decisions as `engine: tsa`, and the bundle sidecar logged `bundle activated` for the revision.

The unauthorized request is a participant whose verified role maps to a scope the policy has no
rule for (`other:read`): its token and proof are valid, so the denial is the policy's.

## What the row needed that did not exist

- gRPC through the guard: the commit of the upstream gRPC work, carried onto this branch with its
  author, `6a277cc9`.
- The Rego policy decides the gRPC methods the zone's data lists and the presentation-required
  denial with its link (`3cd06096`); the evaluator's decision event names the gRPC method.
- The refusal carries the link in a header too, which a gRPC caller receives as metadata
  (`687c2da8`).
- The Protected Resource serves a gRPC method behind its token and proof verification
  (`4b90c75b`); the proof's `--tsa` mode (`df4d07ea`).

## Limits

- kind only: Istio's own CA, not the zone's SPIRE chain; no admission policy; unsigned local images
  and a bundle signed with a key generated for the run. Nothing was deployed on a zone.
- The gRPC method is the standard health service's unary `Check`; streaming methods are not
  supported by the guard (its 15 s route timeout).
- The gRPC caller is curl speaking HTTP/2 with one framed request, not a gRPC library client; a
  library client against the guard's Envoy is `TestGuardedGRPCThroughEnvoy`, without the mesh.
- The role-carrying outcomes are IF-03 fixture outcomes signed by a run key, as in the guard
  catalogue; the OID4VP link is the bundle's configured link, not a live verifier session.
- The 503 answers (TSA or token store down) over gRPC are not exercised; over REST they are the
  guard catalogue's and the TSA policy proof's.
