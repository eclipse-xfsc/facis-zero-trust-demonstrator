# Trust list of `trust.facis.cloud` published on zone B, weekly renewal, ZT-26 rerun: 24 Nov 2026

Zone B (`zerotrust-b`, kube-system UID `a39ae8ea-ac02-4aec-9c13-cda127b17e2d`), namespace `ztd-train`, between
09:55 and 10:38 UTC, authorised by the project lead. Until this run the row ZT-26 failed on zone B only
because the trust list of `trust.facis.cloud` and its VC answered 404 through the public entry `tspa-public`
([mesh rows, 23 Nov](../bdd-mesh-2026-11-23/README.md)). TSPA there is our image
(digest `sha256:cbe575d4…`, at `ghcr.io/fune5tiatlas/facis-zero-trust-demonstrator/tspa` since 15:56Z; during the run the
same digest came from a temporary public copy while that package was private; issuer `did:web:tspa.facis.cloud`, key
`trust-list-1`, `trustlist.vc.validity` `P30D`; [Publishing to TRAIN](../../tspa-publish-api.md), section 11),
with an empty store. What is not in a record beside this file was read by the operator on the cluster;
`live-records.txt` keeps those readings, without secrets, tokens or addresses.

## What was changed on the zone

All in `ztd-train`; the objects were saved before the change. Nothing else on the zone was changed by this
work; the routing proof's stand-ins were created and removed by the proof.

| Object | Change |
|---|---|
| Keycloak realm `ztd-train` | a client of its own for publication, `ztd-trustlist-publisher` (confidential, service account with the realm role `enrolltf`, no audience mapper), created through the admin CLI and added to the realm import (Secret `keycloak-realm`, replaced, not applied) so that a restart keeps it |
| Secret `tspa-republish-client` | new: that client's secret, for the job (created, not applied) |
| TSPA data | `PUT /trustframework/trust.facis.cloud` 201, `PUT /init/json/trust.facis.cloud/trust-list` 201, `PUT /trust.facis.cloud/trust-list/tsp` 201 (09:59:28-30Z), with the publisher client's token; one entry, test data (`trust-list.json`) |
| Helm release `tspa-republish` (revision 2) | the chart [`deployment/helm/tspa-republish`](../../../deployment/helm/tspa-republish/README.md) with `zones/zone-b.yaml`: ConfigMap and CronJob `tspa-republish`, Mondays 03:17 UTC |

The release `tspa`, the zone manager and its keys, the TSPA configuration and the public entry were not touched.

## What was run and what it showed

| Check | Result | Record |
|---|---|---|
| The list and its VC through the public entry (`GET https://tspa.facis.cloud/tspa-service/tspa/v1/trust.facis.cloud/trust-list` and `/vc/trust-list`, sent to the entry's load-balancer address) | 200 `application/json` both; the VC's issuer is `did:web:tspa.facis.cloud`, its proof `JsonWebSignature2020` by `did:web:tspa.facis.cloud#trust-list-1`, its window 30 days from the publication | `vc.json`, `trust-list.json`, `did.json`: the bytes as served at 10:33Z (the list's SHA-256 multihash is the VC's `hash`) |
| The VC verified, not only read | `internal/trustlist` (`Verifier.TrustList`, the verification service's own check: pinned contexts in safe mode, issuer, window, the EdDSA proof against the key the DID document served by the entry lists under `assertionMethod`, the list's multihash) accepted it at 10:33:05Z: expiry `2026-12-24T10:09:20Z`, the entry `did:web:connector-b.trust.facis.cloud` listed active | `verifier-run.txt`; the test is `verifier-live_test.go.txt` (not part of the suite; see the limits for how the list was fetched) |
| The renewal job, run by hand | `kubectl create job --from=cronjob/tspa-republish`, twice (chart revisions 1 and 2): both succeeded; each `PATCH` answered 200 and moved the window (09:59:30Z to 10:01:51Z, then to 10:09:20Z, each plus 30 days) | `republish-jobs.txt` |
| ZT-26 as a BDD scenario on zone B | `go test ./internal/bdd -godog.tags=@ZT-26`, `BDD_MODE=cluster`, `BDD_TARGET=zone-b`, run `trustlist-b-20261124-r5` at `b3cbdcef` (10:32-10:37Z), the inputs of the 23 Nov runs (`ROLE=ingress`, entry `ztd-m3-b/ztd-edge`, `declared/zone-b.txt`, `TSPA_FRAMEWORK=trust.facis.cloud`, the five direct targets, `1.1.1.1:443/https`): **passed**, `go test` exit 0. Routing run `20261124T103249Z-21005`: 34 PASS, `Result: 0 failed check(s).`; the two lines that failed before now read `answered 200 application/json` and `valid from 2026-11-24T11:09:20+01:00 until 2026-12-24T11:09:20+01:00` | `connector-routing-r5.md`, `decision-r5.txt`, the runner's output in `live-records.txt` |

### The runs before it

Runs `r1` to `r3` (10:05-10:21Z) failed, for two reasons that are not the zone's (their decisions are in
`live-records.txt`; the diagnosis is the operator's, from the proof's records and one flow capture, not kept):

- **The proof compared the VC's window as text.** `verify.sh` compared `issuanceDate` with a UTC `now` as
  strings; TSPA writes its local offset (`+01:00`), so a VC issued within the last hour read as not yet valid
  (`r1`: `valid from 2026-11-24T11:09:20+01:00`, refused at 10:09Z). Fixed in `cbf3faa1`: the window is compared
  as instants (`b3cbdcef`: fractions of a second kept). `r2` onwards pass that line.
- **A wrong input of this rerun.** `r1` to `r3` gave the entry's own load-balancer address as `DIRECT_EXTERNAL`
  instead of the 23 Nov runs' `1.1.1.1:443/https`. The caller's attempt was dropped (`denied(28)`), but the
  node translates that address to the entry's pod before the policy decides, so Hubble records the drop
  against `ztd-m3-b/ztd-edge-…:8443` (seen in a flow capture during `r3`:
  `ztd-data/route-backend:41834 <> ztd-m3-b/ztd-edge-779c79d6b8-nszxj:8443 Policy denied DROPPED`) and the proof's
  filter on the address finds none. `r4` (10:21-10:26Z, at `cbf3faa1`) used the 23 Nov input and passed, 34 PASS;
  `r5` is the same run at the final proof.

## Limits

- **What the row's pass shows.** The routing proof reads the list and the VC over HTTPS without verifying the
  certificate and checks the status, the media type and the window; it does not verify the signature, resolve
  the DID or discover the list from DNS. The signature is shown by the verifier run above, once.

- **Only ZT-26 was rerun here.** The four rows on the plane-separation verifier (ZT-23, ZT-25, ZT-61, ZT-62)
  were being run on zone B by another track at the same time, with the same fixture names; their last result
  on record here is the fourth rerun of 23 Nov (passed).
- **The name is not yet pointed at the entry.** `tspa.facis.cloud` still resolves to the domain's wildcard
  address, so every request above was sent to the entry's load-balancer address with the name as SNI and Host,
  and the entry serves a certificate of its own internal CA (ACME cannot complete before the record exists);
  certificate verification was off. A verifier that resolves `did:web:tspa.facis.cloud` itself does not reach
  this DID document yet.
- **The VC's `trustlistURI` is `http://localhost:16003/…`** (TSPA's `request.get.mapping`, unchanged). The
  verifier check above fetched the list through a port-forward of the TSPA Service on that local port; a
  verifier elsewhere cannot follow it. The proof's `created` is `2026-11-24T11:09:21Z`: TSPA's local time written
  as UTC, an hour ahead of the signing; the verifier does not judge that field. The hash and the signature are over the list the public entry serves.
- **No scheme pointer in DNS.** `PUT /trustframework/trust.facis.cloud` answered 201 and TSPA stored the
  scheme, but the zone holds no `_scheme._trust.trust.facis.cloud PTR` (NXDOMAIN at the zone's server, SOA
  serial unchanged); the zone manager logged nothing. Not investigated further: the zone is delegated and
  signed, and it still validates (`ad`). A TCR cannot discover the list from the pointer yet.
- **The entry is test data** (placeholder measurement values, `PolicyOrLegalNotice`: test data only).
- **The schedule itself has not fired yet**: both runs of the job were started by hand; the first scheduled
  run is Monday 30 Nov 03:17 UTC. The job is one more writer of the framework (the chart's README, on writers).
- Keycloak in `ztd-train` runs in dev mode; TSPA logs the bearer token it sends to the zone manager (upstream).
