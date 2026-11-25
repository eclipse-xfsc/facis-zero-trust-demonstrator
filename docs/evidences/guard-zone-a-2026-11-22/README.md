# Second guard instance on zone A from values only

2026-11-22 00:57-01:00 UTC, context `zerotrust-a`. The guard chart was installed as release
`ztd-guard` (revision 1) into the data plane `ztd-data` by
`ZONE_VALUES=deployment/helm/ztd/zones/zone-a.yaml KUBE_CONTEXT=zerotrust-a scripts/install-zone/install.sh install ztd-guard`:
the installer's lifecycle step (server-side dry run, then `helm upgrade --install --wait`), with the
zone file's `guard.values` and `trustDomain` from `zone.trustDomain`. Nothing else was installed or
changed; `install.log` is the run, `ztd-guard-values.yaml` and `ztd-guard-manifest.yaml` what Helm
recorded. Images: the M3 close-out builds of the guard and the policy evaluator (by digest) and zone
B's Envoy runtime.

| Check | Result |
|---|---|
| Guard (Envoy, hook, sidecar) and policy evaluator ready | 3/3 and 2/2, admitted by the zone's admission policies |
| A meshed caller under the Participant's service account, no token | `401 {"reason_code":"TOK-MISSING"}`, `x-request-id 823016c0658ab513a2e526b842bbccab` (`ztd-participant.http`) |
| The decision event | IF-01 v2 from `guard-a`, caller `spiffe://zone-a.trust.invalid/ns/ztd-data/sa/ztd-participant` (the zone's SPIRE identity), token subject, bundle and rule `not_evaluated` (`guard-decision-event.json`) |
| A meshed caller under another service account | `403 RBAC: access denied` from the guard's sidecar (`intruder.http`) |

The connector, token store and resource the guard would call are not deployed in zone A, so a
request with a token is refused (fail closed); a full positive path in zone A waits for those
services. The probe pods, their service accounts and their one egress policy were removed after the
run (none remain). Rollback of the instance: `helm uninstall ztd-guard -n ztd-data`.

## Revision 2 (2026-11-22 01:29 UTC, after the review)

`ztd-guard` upgraded to revision 2 from the zone file, the same command, with the reviewed builds
(guard `sha256:a885b465…`, evaluator `sha256:5f77bbe8…`): a missing key set now answers 503
`TOK-KEYSET-UNAVAILABLE` (it answered 500 before), a refusal after policy keeps its rule, and the
evaluator writes v2 events in either engine. Checked again with a short-lived probe (removed): a
signed-looking token with no key set reachable (no connector in zone A) is refused 503
`TOK-KEYSET-UNAVAILABLE` (`revision-2/keyset.http`), no token 401 `TOK-MISSING`, both with their
`guard-a` v2 events (`revision-2/guard-events.jsonl`). `revision-2/history-before.txt` is the
release history before the upgrade. Rollback to revision 1: `helm rollback ztd-guard 1 -n ztd-data`;
removal: `helm uninstall ztd-guard -n ztd-data`.
