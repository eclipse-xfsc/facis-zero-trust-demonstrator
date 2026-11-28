# Mesh rows as executable BDD scenarios: runs of 23 Nov 2026

The Annex A rows of the family *Mesh enrolment and segmentation* that an existing proof can decide on
the participant zones now run as `@cluster` scenarios (`features/go/mesh.feature`), with their steps in
`internal/bdd/mesh_cluster_test.go` and the decision rules held offline by `internal/bdd/mesh_decide_test.go`.
The rows are about the participant zone clusters A and B (Istio sidecar mode with SPIRE, Cilium). The IONOS
cluster runs ambient mesh without SPIRE under its own declared deviation and is not a target of these
scenarios.

| Row | Mode | Proof the steps run | Decided from |
|---|---|---|---|
| ZT-23 Service Mesh Implementation | cluster | `scripts/verify-plane-separation/verify.sh` | `matrix.csv`: every legitimate caller served over mTLS and counted by its proxy to the destination's SPIFFE ID; every plain-text request without an identity let through by the network (Hubble `FORWARDED`) and reset by the destination's proxy under mTLS `STRICT`; the verifier's run with no failed check |
| ZT-25 Routing Policies | cluster | the same run, plus `scripts/ci/check-policy-addresses.sh` | the legitimate callers (as above), every impostor refused `403 RBAC` with a denial line naming both SPIFFE IDs, every unlabelled caller and every proxy-less probe dropped by the network policy (Hubble policy drop cited); no address in a policy, in the zone file's render and in the live NetworkPolicies, CiliumNetworkPolicies, CiliumClusterwideNetworkPolicies and AuthorizationPolicies of the plane namespaces and cluster-wide (the Connector's two declared edge hops reported `EDGE`) |
| ZT-61 Traffic routed via Service Mesh | cluster | the same run | legitimate callers counted over mTLS; impostors refused by the mesh; unlabelled callers dropped by the network |
| ZT-62 Limited Communication within Mesh | cluster | the same run | the ALLOW rows that have an impostor (the export row admits every identity and has none): the permitted identity served over mTLS, the other refused by mesh policy with both identities logged |
| ZT-26 Ingress and Egress | cluster | `scripts/verify-connector-routing/verify.sh`, `ROLE=egress` on zone A, `ROLE=ingress` on zone B | the record: the role's section, the direct paths (each drop cited from Hubble) and both exemptions (DNS, observability export) present, no failed check, `Result: 0 failed check(s).` |

The four rows on the plane-separation verifier share one run per target and run id within a test process.
Each row writes `bundles/bdd/evidence/bdd-zt-0xx/<target>/<run>/decision.txt`; the verifier's record is in
`bundles/bdd/evidence/bdd-mesh/<target>/<run>/plane-separation/`, the routing record in
`bundles/bdd/evidence/bdd-zt-026/<target>/<run>/connector-routing/` (all git-ignored). In the cluster dry run
every step is skipped.

## The runs

Commit `b9f0bb8b`, `BDD_MODE=cluster`, `-godog.tags=@ZT-23,@ZT-25,@ZT-26,@ZT-61,@ZT-62`, the zone file of
the zone (`deployment/helm/ztd/zones/zone-<a|b>.yaml`). The Connector routing inputs are those of the
21 Nov records ([connector-routing](../connector-routing/README.md)): zone A `POST /demo` with the peer log
read from zone B's entry; zone B the entry `ztd-m3-b/ztd-edge`, `declared/zone-b.txt`,
`TSPA_FRAMEWORK=trust.facis.cloud`, the five direct targets of `ztd-m3-b` and one external address on 443.

| Target | kube-system UID | BDD run id | Plane-separation run | Routing run |
|---|---|---|---|---|
| `zerotrust-a` | `3fbf9fda-5cd2-459a-87f0-769126697d9a` | `mesh-a-20261123-r2` (13:26-13:59Z) | `rfcec4809`: 101 pass, 8 fail, 11 n/a, 3 declared | `20261123T135615Z-90119`: 0 failed |
| `zerotrust-b` | `a39ae8ea-ac02-4aec-9c13-cda127b17e2d` | `mesh-b-20261123-r2` (13:12-13:28Z) | `rcb2d7bdb`: 31 pass, 8 fail, 5 n/a, 1 declared | `20261123T132407Z-86899`: 2 failed |

| Row | zone A | zone B |
|---|---|---|
| ZT-23 | failed | failed |
| ZT-25 | failed | failed |
| ZT-61 | failed | failed |
| ZT-62 | failed | failed |
| ZT-26 | **passed** | failed |

### Why the rows fail

- **The zones run an older allow matrix than the zone files of this commit.** On both zones the same 8 lines
  fail: the legitimate caller and the impostor of `pdp-adapter-to-tsa`, `token-store-to-verification-service`,
  `connector-to-openbao` and `token-store-to-openbao` are dropped at the network (`denied(28)`). The zone files
  render the `pdp-adapter-to-tsa` pair on the label `app.kubernetes.io/name=ztd-policy-evaluator`; the live pair
  still selects `pdp-adapter`. The three other rows have no NetworkPolicy pair on the zones. Every other lane
  holds: the other ALLOW rows' legitimate callers served over mTLS, their impostors refused `403 RBAC` with both SPIFFE IDs,
  their unlabelled callers dropped with Hubble's policy drop, every proxy-less probe dropped, every plain-text
  request reset under `STRICT` (13 on zone A, 2 on zone B). The rows pass only after the umbrella release of each
  zone is upgraded to this zone file, which this work does not do.
- **ZT-26 on zone B**: the trust list of `trust.facis.cloud` and its VC answer 404 through `tspa-public`, as on
  21 Nov. Every other check of the ingress role passed (25 entry checks, the 6 direct paths dropped with Hubble's
  drop, DNS and the export lane).
- **No address in any mesh policy** held on both zones (zone A 60 live policies, zone B 71; the render of each
  zone file) and is part of ZT-25's decision, which fails only on the lanes above.

Two earlier runs the same day (`mesh-a-20261123`, `mesh-b-20261123`, commit `e0a7a21d`) are void: the
worktree had no built chart dependencies, so the umbrella did not render, and the routing record was not
found (the proof does not take `ZTD_EVIDENCE_DIR` on a host without GNU `realpath`; the scenario now reads the
run directory the proof prints and copies the record in).

## Rerun after the zone upgrade (23 Nov 2026, 16:31-17:10Z)

Both zones were upgraded earlier the same day from the current zone files (umbrella `ztd` and `zone-policy`:
zone A `ztd` revision 6 and `zone-policy` revision 10, zone B `ztd` revision 5 and `zone-policy` revision 5).
The five rows were run again with the same inputs, environment and command as above, at commit `04839b66`.
The runs above stay as the history of the state before the upgrade.

| Target | kube-system UID | BDD run id | Plane-separation run | Routing run |
|---|---|---|---|---|
| `zerotrust-a` | `3fbf9fda-5cd2-459a-87f0-769126697d9a` | `mesh-a-20261123-r3` (16:31-17:10Z) | `r643bac3e`: 119 pass, 2 fail, 14 n/a, 3 declared | `20261123T170721Z-58093`: 0 failed |
| `zerotrust-b` | `a39ae8ea-ac02-4aec-9c13-cda127b17e2d` | `mesh-b-20261123-r3` (16:31-16:49Z) | `r3ad90096`: 39 pass, 2 fail, 6 n/a, 1 declared | `20261123T164412Z-40857`: 2 failed |

| Row | zone A | zone B |
|---|---|---|
| ZT-23 | failed | failed |
| ZT-25 | failed | failed |
| ZT-61 | failed | failed |
| ZT-62 | failed | failed |
| ZT-26 | **passed** | failed |

### What the upgrade fixed

The four lanes that were dropped at the network before now carry traffic on both zones. `pdp-adapter-to-tsa`
and `token-store-to-verification-service`: the legitimate caller is served `200` over mTLS and counted to the
destination's SPIFFE ID, the impostor is refused `403 RBAC` with both SPIFFE IDs, the unlabelled caller is
dropped with Hubble's policy drop. `connector-to-openbao` and `token-store-to-openbao`: the impostor is
refused `403 RBAC` by OpenBao's proxy with both SPIFFE IDs, the unlabelled caller is dropped with Hubble's
policy drop, and the legitimate caller's request reaches OpenBao over mTLS (counted by its proxy to
`spiffe://zone-<a|b>.trust.invalid/ns/ztd-mgmt/sa/ztd-openbao`). The failed lines went from 8 to 2 per zone.

### Why the rows still fail

- **ZT-23, ZT-61, ZT-62, both zones: the verifier expects `200` from a destination that answers `307`.** The
  two failing lines per zone are the legitimate callers of `connector-to-openbao` and `token-store-to-openbao`:

  `"connector-to-openbao","Secret store","ztd-data","legitimate caller",...,"8200","200 over mTLS, destination principal spiffe://zone-b.trust.invalid/ns/ztd-mgmt/sa/ztd-openbao","307 <a href=""/ui/"">Temporary Redirect</a>.","control channel","the caller's proxy counted 1 request(s) to destination_principal ...","real","fail"`

  (the same for `token-store-to-openbao`, and on zone A with `zone-a.trust.invalid`). These two rows are the
  only ALLOW rows probed against a **real** destination (`ztd-mgmt/ztd-openbao-0`); the verifier sends
  `GET /` and passes the line only on status `200` (`scripts/verify-plane-separation/verify.sh`, the
  legitimate-caller branch), and OpenBao answers `GET /` with a redirect to `/ui/`. The lane itself holds: the
  request crossed the network policy, was carried over mTLS and was answered by OpenBao. The defect is in the
  probe's expectation for a real destination, not in the zone.
- **ZT-25, both zones: the same two lines, and the address check of the live policies.** Since the earlier
  runs the address check declares the Connector's two edge hops only in the connector-gateway chart's own
  render (`--edge-manifest`); the scenario scans the live policies with `--manifest`, so the two hops, which
  were reported `EDGE` before, now fail:

  `FAIL live-zone-a: live-policies CiliumNetworkPolicy ztd-data/ztd-connector-gateway-peer: key toCIDR at spec.egress.0.toCIDR` and `address <address>/32 at spec.egress.0.toCIDR.0`

  `FAIL live-zone-b: live-policies NetworkPolicy ztd-m3-b/ztd-edge-entry: key ipBlock at spec.ingress.0.from.0.ipBlock` and `address <address>/0 at spec.ingress.0.from.0.ipBlock.cidr`

  Both policies predate the upgrade (created 21 Nov by the gateway releases) and are unchanged; no other live
  policy and no policy of either zone file's render names an address. Whether the live scan may declare the
  two hops is a decision on the check, not a change of the zones.
- **ZT-26 on zone B**: unchanged. The trust list of `trust.facis.cloud` and its VC answer `404 application/json`
  through `tspa-public` (`valid from none until none`); `Result: 2 failed check(s).` This is the data held by
  the TRAIN instance (the framework and its list are not published on it), not a routing defect: the other
  23 entry checks, the 6 direct paths (each with Hubble's drop), DNS and the export lane passed. Nothing was
  published to TRAIN.

### State of the zones after the rerun

On both zones `kubectl get validatingadmissionpolicy proxy-takes-spire-socket -o json --show-managed-fields`
lists the managers `helm` and `validatingadmissionpolicy-status` only, and the policy's spec is identical to
the one read before the run (the generation rose by 2 on each zone: the lift and the restore). No probe pod
remains, and the release revisions are those listed above.

## Second rerun (harness fixes) (23 Nov 2026, 17:14-17:53Z)

Two harness fixes landed after the rerun above (commit `30931034`): the plane-separation verifier's legitimate
caller requests `/v1/sys/health` on the two OpenBao lanes, and the ZT-25 scenario scans the live policies owned
by a connector-gateway Helm release with `--edge-manifest` and every other live policy with `--manifest`. The
five rows were run again at that commit with the same inputs, environment and command; the zones were not
changed (same release revisions as above). The runs above stay as history.

| Target | kube-system UID | BDD run id | Plane-separation run | Routing run |
|---|---|---|---|---|
| `zerotrust-a` | `3fbf9fda-5cd2-459a-87f0-769126697d9a` | `mesh-a-20261123-r4` (17:14-17:53Z) | `r816c8192`: 120 pass, 1 fail, 14 n/a, 3 declared | `20261123T175008Z-84736`: 0 failed |
| `zerotrust-b` | `a39ae8ea-ac02-4aec-9c13-cda127b17e2d` | `mesh-b-20261123-r4` (17:14-17:32Z) | `r9a554da6`: 40 pass, 1 fail, 6 n/a, 1 declared | `20261123T172704Z-73347`: 2 failed |

| Row | zone A | zone B |
|---|---|---|
| ZT-23 | failed | failed |
| ZT-25 | failed | failed |
| ZT-61 | failed | failed |
| ZT-62 | failed | failed |
| ZT-26 | **passed** | failed |

### What the fixes settled

- **The OpenBao lanes pass on both zones.** The legitimate callers of `connector-to-openbao` and
  `token-store-to-openbao` are answered `200` on `/v1/sys/health` over mTLS (`"initialized":true,"sealed":false`)
  and counted by their proxy to `spiffe://zone-<a|b>.trust.invalid/ns/ztd-mgmt/sa/ztd-openbao`.
- **The live address check passes on both zones.** Zone A: 69 live policies scanned strictly, no undeclared
  address; the 3 policies of the gateway release report `EDGE ... CiliumNetworkPolicy
  ztd-data/ztd-connector-gateway-peer: declared Connector edge hop gateway-to-peer`. Zone B: 80 live policies
  scanned strictly, no undeclared address; the 3 gateway-owned policies report `EDGE ... NetworkPolicy
  ztd-m3-b/ztd-edge-entry: declared Connector edge hop outside-to-entry`. The render of each zone file names no
  undeclared address.

### Why the rows still fail

Each zone's verifier run has one failed line, a different one on each zone, and both lines passed in the rerun
above. The four rows on the plane-separation verifier require the verifier's run to have no failed check, so
one line fails all four. In both lines the probe's outcome is the expected refusal; what is missing is the
record of it.

- **Zone A, `management-to-data` to `ztd-data/ztd-policy-evaluator`: the denial line was not read.**

  `"management-to-data","any data-plane workload (from the management plane)","ztd-mgmt","behind a probe-scoped opening","mesh-prober-0","ztd-data/ztd-policy-evaluator","8080","refused by the destination's proxy, a denial line with both SPIFFE IDs, the opening removed","403 RBAC: access denied","mesh","no denial line naming the prober in any of the 1 pod(s) the Service selects; opening removed: yes","real","fail"`

  The prober was answered `403 RBAC: access denied` and the opening was removed, but the verifier found no line
  naming the prober in the destination proxy's log. In the rerun above the same line carried the proxy's
  denial with both SPIFFE IDs; the other five lines of this probe (gateway, guard, tenant data, `tspa`) carry
  it in this run. The verifier reads the proxy's log once, 3 s after the request
  (`scripts/verify-plane-separation/verify.sh`, the probe-scoped opening); a log line written later than that
  is the likely cause, not established.
- **Zone B, `token-store-to-verification-service`, unlabelled caller: Hubble's drop was not read.**

  `"token-store-to-verification-service","OCM","ztd-data","unlabelled (service account ztd-token-store, no row labels)","token-store-to-verification-service-unlabelled","verification-service.ztd-mgmt.svc","8080","dropped, no denial line","denied(28)","network","dropped, but Hubble, available on the caller's node, recorded no policy drop for the flow: ...; no new denial line of spiffe://zone-b.trust.invalid/ns/ztd-data/sa/ztd-token-store in the destination's proxy","stand-in","fail"`

  The call timed out (`denied(28)`) and no denial line appeared, as expected, but `hubble observe` returned no
  drop for the flow. In the rerun above the same line cited `Policy denied DROPPED (TCP Flags: SYN)`; the other
  five unlabelled callers of this run cite theirs. The verifier asks Hubble once after the probe; a flow not
  yet, or no longer, in the node's flow buffer is the likely cause, not established.
- **ZT-26 on zone B**: unchanged and expected. The trust list of `trust.facis.cloud` and its VC answer `404`
  through `tspa-public`; `Result: 2 failed check(s).` The other 23 entry checks, the 6 direct paths (each with
  Hubble's drop) and both exemptions passed. Nothing was published to TRAIN.

Neither failed line is in the scope of the two fixes, so the harness was left as it is and the runs were not
repeated. Whether these two reads need a retry in the verifier is open.

### State of the zones after the rerun

On both zones `kubectl get validatingadmissionpolicy proxy-takes-spire-socket -o json --show-managed-fields`
lists the managers `helm` and `validatingadmissionpolicy-status` only, and the policy's spec is identical to
the one read before the run (the generation rose by 2 on each zone: the lift and the restore). No probe pod
remains, and the release revisions are unchanged.

## Third rerun (evidence polling) (23 Nov 2026, 17:57-18:36Z)

After the second rerun the plane-separation verifier was changed to read its evidence until it appears
instead of once after a fixed delay (commits `a973ab85`, `e9e25363`): the denial line of a mesh probe and of
an impostor, and Hubble's drop of a dropped flow, are each read up to five times, 3 s apart. The five rows
were run again at `e9e25363` with the same inputs, environment and command; the zones were not changed (same
release revisions as above). The runs above stay as history.

| Target | kube-system UID | BDD run id | Plane-separation run | Routing run |
|---|---|---|---|---|
| `zerotrust-a` | `3fbf9fda-5cd2-459a-87f0-769126697d9a` | `mesh-a-20261123-r5` (17:57-18:36Z) | `r29d0e965`: 120 pass, 1 fail, 14 n/a, 3 declared | `20261123T183331Z-19583`: 0 failed |
| `zerotrust-b` | `a39ae8ea-ac02-4aec-9c13-cda127b17e2d` | `mesh-b-20261123-r5` (17:57-18:15Z) | `r514b3622`: 41 pass, 0 fail, 6 n/a, 1 declared | `20261123T181016Z-7406`: 2 failed |

| Row | zone A | zone B |
|---|---|---|
| ZT-23 | failed | **passed** |
| ZT-25 | failed | **passed** |
| ZT-61 | failed | **passed** |
| ZT-62 | failed | **passed** |
| ZT-26 | **passed** | failed |

### What the polling settled

- **Zone B: the four plane-separation rows pass.** The verifier's run has no failed line. The unlabelled
  caller of `token-store-to-verification-service`, whose drop was not read in the second rerun, cites it:
  `Hubble drop: Nov 23 18:03:07.022: ztd-data/token-store-to-verification-service-unlabelled:49706 (ID:28798) <> ztd-mgmt/verification-service:8080 (ID:50883) Policy denied DROPPED (TCP Flags: SYN)`.
- **ZT-26 on zone B**: unchanged and expected. `declared entry ztd-train/tspa-public: GET the trust list of
  trust.facis.cloud answers 200 with a JSON or XML body` and `GET the VC of trust.facis.cloud's trust list
  answers 200 with a credential valid now` were each answered `404 application/json`; `Result: 2 failed
  check(s).` The other 23 entry checks, the 6 direct paths (each with Hubble's drop) and both exemptions
  passed. Nothing was published to TRAIN.

### Why the rows still fail on zone A

The same single line as in the second rerun failed, and it fails the four rows on the plane-separation
verifier:

`"management-to-data","any data-plane workload (from the management plane)","ztd-mgmt","behind a probe-scoped opening","mesh-prober-0","ztd-data/ztd-policy-evaluator","8080","refused by the destination's proxy, a denial line with both SPIFFE IDs, the opening removed","403 RBAC: access denied","mesh","no denial line naming the prober in any of the 1 pod(s) the Service selects; opening removed: yes","real","fail"`

The polling rules out a late read: the line was not written at all. The log of the destination's proxy
(`ztd-data/ztd-policy-evaluator-9cfd75b4d-cmq48`, container `istio-proxy`, the pod not restarted in 41 h), read
after the run, holds exactly two denial lines naming `spiffe://zone-a.trust.invalid/ns/ztd-mgmt/sa/mesh-prober`,
stamped `13:55:26.155Z` and `17:04:00.313Z`: the two runs in which this line passed (`mesh-a-20261123-r2` and
`-r3`). It holds none for the first run, for `-r4` or for this run, whose probe fell between 18:29:40Z and
18:32:21Z (the probes before and after it in the record). In the same window the proxy did write its other denial lines (`filter_chain_not_found` for the
three plain-text probes of this run, at 18:25:27, 18:27:44 and 18:32:36Z), and the proxies of the gateway, the
guard and the two tenant data services wrote theirs for the same prober (the other five lines of this probe
pass).

So the prober is answered `403 RBAC: access denied` on this destination in every run, the opening is removed,
and the destination's proxy records the refusal in two runs out of five. The refusal holds; its record is
missing, and the row asserts on the record. Why the proxy writes no line in some runs is not established:
the same prober (`mesh-prober-0`), destination pod and `Telemetry` filter
(`response.code_details.startsWith("rbac_access_denied") || ...`) are in place in the passing and the failing
runs, and Hubble's flow buffer on the destination's node no longer held the probe's flows when it was read
after the run (oldest flow 18:35:06Z), so which proxy produced the `403` could not be read back. A further
read in the verifier would not change the result. Nothing was changed in the harness or on the zone.

### State of the zones after the rerun

On both zones `kubectl get validatingadmissionpolicy proxy-takes-spire-socket -o json --show-managed-fields`
lists the managers `helm` and `validatingadmissionpolicy-status` only, and the policy's spec is identical to
the one read before the run (the generation rose by 2 on each zone, 17 to 19 on zone A and 15 to 17 on zone
B: the lift and the restore). No probe pod remains, and the release revisions are unchanged.

### Cause of the missing record on zone A (23 Nov 2026, 18:50-19:00Z)

The record was not lost: in the failing runs the destination's proxy never received the request. The Service
`ztd-data/ztd-policy-evaluator` selects `app.kubernetes.io/name: ztd-policy-evaluator` alone, and the verifier's
stand-in caller and impostor of the row `pdp-adapter-to-tsa` carry exactly that label (the row's), so during a
run the Service had three ready endpoints, while the probe plan, built before the callers exist, read the one
real pod's log only. The prober's proxy spread its request over the three, each proxy refused it with
`403 RBAC: access denied` under the mesh-wide default deny, and the line was written by whichever proxy
answered: the real one in about one run out of three (two of five observed). The real proxy's counter
`http.inbound_0.0.0.0_8080;.rbac.denied` stood at 2 after the five runs, the number of its denial lines.
Reproduced on `zerotrust-a` with a meshed prober of its own (admitted as written, the admission policy not
lifted: generation 19 before and after) behind a probe-scoped opening: with the real pod alone, 6 of 6 requests
reached it (the prober's `rq_total` of the endpoint) and each left a line; with one stand-in carrying the label,
6 of 8 reached the real pod and 2 the stand-in, whose proxy logged those two under its own identity; with the
same stand-in held out of the Service by a readiness gate (`ready=false` in the EndpointSlice,
`failed_eds_health` at the prober), 6 of 6 reached the real pod again. The fix is in the verifier: every
stand-in caller, impostor and unlabelled pod of `fixtures/rows/*.yaml` now holds a readiness gate nothing sets,
so it runs and is never a Service endpoint, and the verifier waits for `ContainersReady` instead of `Ready`
(`verify_test.sh` holds the fixtures to it). Before the fix a run also sent two thirds of the guard's decision
calls to the stand-ins for its length; the evaluator's proxy counted no such call that day. The probe objects
were removed; the rerun with the fix is the next section.

## Fourth rerun (stand-ins out of Services) (23 Nov 2026, 19:03-19:42Z)

Commit `159a37ce` gives every stand-in caller, impostor and unlabelled pod of the plane-separation fixtures a
readiness gate nothing sets, so none of them is ever an endpoint of a zone Service (the cause recorded just
above). The five rows were run again at `2f514aa9` with the same inputs, environment and command; the zones
were not changed (same release revisions as above). The runs above stay as history.

| Target | kube-system UID | BDD run id | Plane-separation run | Routing run |
|---|---|---|---|---|
| `zerotrust-a` | `3fbf9fda-5cd2-459a-87f0-769126697d9a` | `mesh-a-20261123-r6` (19:03-19:42Z) | `rf285a874`: 121 pass, 0 fail, 14 n/a, 3 declared | `20261123T193927Z-84587`: 0 failed |
| `zerotrust-b` | `a39ae8ea-ac02-4aec-9c13-cda127b17e2d` | `mesh-b-20261123-r6` (19:03-19:21Z) | `rdf1526e2`: 41 pass, 0 fail, 6 n/a, 1 declared | `20261123T191645Z-56759`: 2 failed |

| Row | zone A | zone B |
|---|---|---|
| ZT-23 | **passed** | **passed** |
| ZT-25 | **passed** | **passed** |
| ZT-61 | **passed** | **passed** |
| ZT-62 | **passed** | **passed** |
| ZT-26 | **passed** | failed |

### What the fix settled

- **Zone A: the four plane-separation rows pass**, and with ZT-26 the whole run passes (`go test` exit 0). The
  verifier's run has no failed line. The line that failed in three of the five earlier runs now cites the
  record of the destination's own proxy:
  `"management-to-data","any data-plane workload (from the management plane)","ztd-mgmt","behind a probe-scoped opening","mesh-prober-0","ztd-data/ztd-policy-evaluator","8080","refused by the destination's proxy, a denial line with both SPIFFE IDs, the opening removed","403 RBAC: access denied","mesh","{""authority"":""ztd-policy-evaluator.ztd-data.svc:8080"",""code"":403,""destination"":""spiffe://zone-a.trust.invalid/ns/ztd-data/sa/ztd-policy-evaluator"",""detail"":""rbac_access_denied_matched_policy[none]"",""flags"":""-"",""source"":""spiffe://zone-a.trust.invalid/ns/ztd-mgmt/sa/mesh-prober"",""termination"":null,""time"":""2026-11-23T19:36:03.281Z""}; opening removed: yes","real","pass"`.
  This is one passing run; before the fix the line passed in about one run out of three by chance, so the
  result rests on the cause and its reproduction above as much as on this run.
- **Zone B: the four plane-separation rows pass** again, with the same counts as the third rerun.
- **ZT-26 on zone B**: unchanged and expected. `declared entry ztd-train/tspa-public: GET the trust list of
  trust.facis.cloud answers 200 with a JSON or XML body` and `GET the VC of trust.facis.cloud's trust list
  answers 200 with a credential valid now` were each answered `404 application/json`; `Result: 2 failed
  check(s).` The other 23 entry checks, the 6 direct paths (each with Hubble's drop) and both exemptions
  passed. Nothing was published to TRAIN.

### State of the zones after the rerun

On both zones `kubectl get validatingadmissionpolicy proxy-takes-spire-socket -o json --show-managed-fields`
lists the managers `helm` and `validatingadmissionpolicy-status` only, and the policy's spec is identical to
the one read before the run (the generation rose by 2 on each zone, 19 to 21 on zone A and 17 to 19 on zone
B: the lift and the restore). No object labelled `app.kubernetes.io/part-of=verify-plane-separation` or
`verify-connector-routing` remains, and the release revisions are unchanged.

## ZT-26 on zone B after the trust list's publication (24 Nov 2026)

The trust list of `trust.facis.cloud` was published on 24 Nov, with a weekly renewal job deployed; ZT-26 was run again on
zone B alone and **passed** (run `trustlist-b-20261124-r5`, routing run `20261124T103249Z-21005`: 34 PASS, 0
failed). The record, with what was changed on the zone and its limits, is
[trust-list-zone-b-2026-11-24](../trust-list-zone-b-2026-11-24/README.md).

## Rows left pending

- **ZT-01 Secure Service Mesh**: needs "a workload outside the mesh attempts the same call" as an in-mesh pair.
  No proof that runs on the zones without reinstalling them makes a proxy-less workload attempt an ALLOW lane's
  call: the plane-separation verifier sends proxy-less probes only to DENY and catch-all destinations, and
  `verify-mesh-identity`'s `unregistered-workload-cut-off` reinstalls the zone. The guard bypass record shows
  an unmeshed pod cannot be created at all, which is a different refusal.
- **ZT-27 Observability**: no OpenTelemetry Collector, Prometheus or tracing backend runs on zone A or B; the
  observability proof (`scripts/verify-observability/verify.sh`) stops and restores the zone's SPIRE server,
  an agent, a node collector and the zone gateway; and no proof asserts "a component emitting no telemetry is
  visible as a gap in the correlated trace".
- **ZT-58 Service Mesh Setup**: the per-node proof (`mesh-on-every-node`, `cross-node-calls`) is
  `scripts/verify-mesh-identity/verify.sh`, which uninstalls and reinstalls the zone on every run; it can only
  run on kind or under an approved reinstall of a participant zone (`ZTD_KEEP_ZONE`).

## Limits

- The destinations of most ALLOW rows are the verifier's stand-ins, not the real services.
- Trust domains are the interim `zone-*.trust.invalid` names.
- The plane-separation verifier lifts the capture validation of `proxy-takes-spire-socket` for under a minute
  per run, as documented in its README; both zones were checked after the runs: no probe object remains.
