# Token store on zone B: health, mesh identity and the replay check

2026-11-24 10:22-10:23 UTC, zone B (context `zerotrust-b`, namespace `ztd-m3-b`), commit `243478b1`,
verdict PASS (14 checks, `run/verdict.txt`). Records of [`observe.sh`](observe.sh) in [`run/`](run/).
No release was changed: the store is the one deployed on the zone (release `ztd-token-store` revision 7,
chart `token-store-0.3.0`, logging in to OpenBao with its service-account token: `openbaoAuth` in
`run/pod.json`). The AuthorizationPolicies, PeerAuthentications, NetworkPolicies, Deployments, Services
and Helm releases of the namespace have the same resourceVersion and revision before and after
(`run/before`, `run/after`, `run/objects.diff` empty).

Two rows of the [evidence index](../../evidence-m3.md) were proven on kind only. This run shows on the
zone the part of each that needs no dependency stopped.

## Health and mesh identity (read only)

| Check | Result | Record |
|---|---|---|
| The pod is Ready and nothing restarted | condition `Ready` true, every container ready with restart count 0, as read at the start of the run; pod started 23 Nov 16:35 UTC | `pod.json` |
| Readiness is green with its dependencies reachable | the application's `/readyz`: `200`, `postgres` `ok`, `openbao` `ok`, `signing_key` `ok` | `readyz-status.txt`, `readyz.json` |
| Liveness | the application's `/healthz`: `200` | `healthz-status.txt` |
| Mesh identity | the store's proxy serves `spiffe://zone-b.trust.invalid/ns/ztd-m3-b/sa/ztd-token-store`; the certificate verified against the X.509 authority the zone's SPIRE server publishes (`spire-system/spire-bundle`) | `identity.txt`, `identity-verify.txt` |
| Correlation ids on the request records | each of the 4596 request records among the store's last 5000 log lines carries one | `request-records.txt` |

The health paths are the application's own handlers, read through a port-forward to the pod's ops port
(9090). The kubelet reaches the same handlers through the sidecar's probe rewrite
(`/app-health/server/...` on 15020, `pod.json`), a path this run did not take. Only the public
certificate chain was read from the proxy (the proxy redacts the key); the chain and the bundle were
verified during the run and not kept, so `identity-verify.txt` is the verification's output, not a
reproducible input. The log's other records (a token acquired or renewed) name their route and token
id and carry no correlation id: they belong to no request.

## Replay check of the internal API

One probe Job ran in the namespace under the guard's service account and pod label, meshed: the
identity the store's network policy, its `AuthorizationPolicy` and the store's own caller list
(`TOKEN_STORE_REPLAY_CALLERS`) name, `spiffe://zone-b.trust.invalid/ns/ztd-m3-b/sa/ztd-guard`. Its
readiness never passes; before the calls it was listed in the guard's EndpointSlice as not ready, beside
the guard's one ready endpoint (`guard-endpoints.json`). It called `POST /internal/replay-check` only,
with made-up proof values (`jkt`, `jti`) for the guard's route target `http://ztd-guard:8080/demo`.

| Case | Answer | Record |
|---|---|---|
| A proof not seen before | `200` `{"fresh":true}` | `replay-calls.txt`, line `first` |
| The same proof again | `409` `TOK-REPLAY` | line `second` |
| 20 identical proofs at once (a second `jti`) | exactly one `200` `{"fresh":true}`, 19 times `409` `TOK-REPLAY` | lines `concurrent` |
| A proof issued 120 s ago; one dated 120 s ahead | `422` `TOK-PROOF-INVALID` each (the store accepts 60 s back and 30 s ahead; the edges themselves were not probed) | lines `stale`, `early` |
| A target outside the guard's routes | `403` `TOK-ROUTE-DENIED` | line `off-route` |

The store recorded 25 requests on the path in the window, with the statuses of the 25 answers. Each of
the 23 refusals is in the store's own request record exactly once, under the correlation id its answer
carried and with the same status (`replay-store-records.jsonl`). The two admitted calls carry no id in
their answer; they are the two `200` records of the window.

```bash
ZTD_CONFIRM_CONTEXT=zerotrust-b docs/evidences/token-store-zone-b-2026-11-24/observe.sh \
  --namespace ztd-m3-b --probe-image <admitted image with bash> --out <new directory>
```

The probe image and the commit are in `run/run.txt` (the zone's own PostgreSQL runtime image, by
digest). The whole script ran 23 s; the probe lived for part of that.

## Limits

- **The failure half stays on kind.** Readiness turning red with PostgreSQL or OpenBao unreachable,
  and the bounded-exposure warning after a database restart, need a dependency of the zone stopped
  or cut off (the kind proof scales PostgreSQL to zero, crash-restarts it, and takes OpenBao's Service
  away from it), which would interrupt the zone's guarded path. Neither was done here. They are in the
  [T6 lifecycle record](../m3-t6-openbao-kubernetes-auth/README.md) and the failure catalogue
  (`scripts/verify-token-store-failures/verify.sh`), both on kind.
- **The replay check at the store, not at issuance.** The Connector's own replay refusal at the token
  endpoint needs a client's credentials and was not exercised on the zone; it stays with
  `TestDPoP_*` in CI. The `not_after` form of the request was not sent.
- **The probe holds the guard's identity; it is not the guard.** The calls prove the store's API and
  its record on the zone for the caller the zone configures. The run kept neither the policies' specs
  nor the store's sidecar counters, so it does not show by itself that no other caller is admitted;
  that the deployed guard's path goes through the store is the one guarded call of the
  [guard bypass](../guard-bypass-zone-b-2026-11-22/README.md) record.
- **Rows left in the replay record.** Each admitted proof leaves one row until a periodic sweep after
  its 90 s window; no sweep was observed. This run left two. The script was run twice before
  it the same morning, and the 50 replay requests among the counts of `request-records.txt` (read
  before this run's own calls) are theirs. Their records were not kept, so the rest is the
  operator's account: the first failed one check of the script's own (it expected the issuer's
  organisation to read `SPIRE`; the zone's SPIRE CA is named `O=FACIS ZTD, CN=zone-b.trust.invalid`,
  so the check now verifies against the published bundle), the second passed and was repeated after
  a review tightened five checks.
- Interim trust domain `zone-b.trust.invalid`.
