# Zone runs of 24 Nov 2026: the mesh rows ZT-01, ZT-27, ZT-58 and the rows proven on kind only

2026-11-24, zone A (`zerotrust-a`, kube-system UID `3fbf9fda-5cd2-459a-87f0-769126697d9a`) and zone B
(`zerotrust-b`, `a39ae8ea-ac02-4aec-9c13-cda127b17e2d`), commit `243478b1`. The tree was clean for the
`r8` runs; the `r9` runs record `dirty: true`, the uncommitted files being documents under `docs/` only (the two record folders of this day and, for zone
A's `r9`, the evidence index); no script, chart, zone file or step file differed from the commit.
The aim was to move rows that were proven on kind only to the participant zones without reinstalling
anything. The outcome per row:

| Row | On the zones | Why |
|---|---|---|
| `zone-policy` upgrade for the new log clause | **not needed**: both zones already run it | the releases were upgraded on 23 Nov; the live objects equal the render of this commit ([below](#zone-policy-on-the-zones)) |
| ZT-01 Secure Service Mesh | **scenario not run**; its two halves observed without a reinstall | the scenario's proof uninstalls the zone ([below](#zt-01-and-zt-58)) |
| ZT-58 Service Mesh Setup | **scenario not run**; a read-only view of the mesh per node | the same proof |
| ZT-27 Observability | **not run** | no collector, Prometheus or tracing backend on either zone ([below](#zt-27)) |
| Token-store health and mesh identity | **read back on zone B** | [record](../token-store-zone-b-2026-11-24/README.md); the failure half stays on kind |
| Replay window | **the store's internal API on zone B** | the same record; the database restart and the issuance side stay on kind and CI |
| Guard decision stream, negative-case catalogue | **not run on zone B** | [below](#rows-proven-on-kind-only-zone-b) |
| ZT-20 Guarding | **not run on zone B** | [below](#rows-proven-on-kind-only-zone-b) |
| ZT-24, ZT-57, ZT-59, ZT-60 | out of scope | their proof reinstalls the zone; the zones are on placeholder trust domains |

No release of either zone was installed, upgraded, rolled back or uninstalled by this work.

## zone-policy on the zones

The [kind record](../bdd-mesh-kind-2026-11-23/README.md) of ZT-01 said the zones lacked the third
clause of the denial-log filter (`response.code_details == "filter_chain_not_found"`) until
`zone-policy` was upgraded. They were upgraded later the same day, with the mesh rows' zone upgrade
(the [mesh record](../bdd-mesh-2026-11-23/README.md), "Rerun after the zone upgrade"):

| Zone | Release | Revision | Deployed (UTC) | `Telemetry` `mesh-default` |
|---|---|---|---|---|
| A | `zone-policy` in `istio-system`, chart `zone-policy-0.3.0` | 10 | 23 Nov 16:20 | three clauses, last applied by Helm 23 Nov 16:13 |
| B | the same | 5 | 23 Nov 16:28 | three clauses, last applied by Helm 23 Nov 16:28 |

Checked on 24 Nov before anything else, per zone, against the render of this commit
(`scripts/install-zone/install.sh render zone-policy` with `deployment/helm/ztd/zones/zone-<a|b>.yaml`):

- the release's stored values equal the rendered values file;
- the release's stored manifest holds the render's 17 objects that are not hooks, each equal;
- a server-side dry run of those 17 objects (`kubectl diff --server-side --field-manager helm`) differs
  from the live objects only in the `meta.helm.sh` annotations Helm adds when it applies.

The read-back of each zone is [`state/zone-a-zone-policy.txt`](state/zone-a-zone-policy.txt) and
[`state/zone-b-zone-policy.txt`](state/zone-b-zone-policy.txt); the release's values and manifest were
saved outside the repository before the runs.

An upgrade would have changed nothing and would have run the chart's post-upgrade hooks on both zones
for no gain, so none was made. The revisions are still 10 and 5.

**What the zones do not have.** The `address` label of the denial line
(`%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%`) is a value of the `istiod` release, not of `zone-policy`.
The `istiod` release of both zones (revision 2) still holds the earlier values: against this commit's
render it lacks the `address` label and the `ztd-otel-gateway` provider, and names the proxy image with
its tag before the digest ([`state/zone-a-istiod-values.diff`](state/zone-a-istiod-values.diff),
[`state/zone-b-istiod-values.diff`](state/zone-b-istiod-values.diff)). So a refused plain-text connection is logged on the zones without the
caller's address. Upgrading `istiod` changes the mesh configuration and the injector's image
reference; it was not part of this work and is left open.

## ZT-01 and ZT-58

**The scenarios were not run on the zones.** Both are decided from one run of
`scripts/verify-mesh-identity/verify.sh`, which states: "DESTRUCTIVE, it uninstalls the zone from the
cluster first and again at the end" (`ZTD_KEEP_ZONE` only replaces the last teardown). On zone B that
would take the mesh, SPIRE and OpenBao away from under the Connector, the token store, the guard and
the partner-facing Participant; on both zones the reinstall issues a new SPIRE CA. This is the reason ZT-24, ZT-57, ZT-59 and ZT-60 have no zone
run, and it applies unchanged to these two rows, which run in the same test process. They stay
**kind only** as BDD rows.

What the zones show without a reinstall is below. It is evidence about the zones, not a decision of
the rows.

### ZT-01: the in-mesh call under mutual TLS, the plain-text call refused and logged

The plane-separation verifier (`scripts/verify-plane-separation/verify.sh`, which installs nothing)
already makes both kinds of call on a zone: each ALLOW lane's legitimate caller, served over mutual
TLS, and plain-text requests without an identity from a proxy-less probe to meshed pods, behind a
probe-scoped opening. Its record says the second kind is reset; it does not read the log. So the four
rows it decides (ZT-23, ZT-25, ZT-61, ZT-62; not ZT-26) were run again as BDD scenarios, with a
follower beside the run that read the `filter_chain_not_found` lines of every proxy of the plane
namespaces while the run went on. [`match.py`](match.py) pairs each plain-text probe of the
verifier's `matrix.csv` with the line of its destination's proxy (same pod, within one second of the
time Hubble gives for the forwarded request).

| Zone | Run | Legitimate callers served over mTLS, counted to the destination's SPIFFE ID | Plain-text probes reset under `STRICT` | of them with the proxy's denial line | Pairing |
|---|---|---|---|---|---|
| A | `mesh-a-20261124-r8` (10:03-10:34Z) | 8 lines | 19, all to real workloads (tenant data of both tenants, the connector gateway, the guard on 8080 and 9090, the policy evaluator) | **19** | [`zone-a-r8-plaintext-denials.txt`](zone-a-r8-plaintext-denials.txt) |
| A | `mesh-a-20261124-r9` (10:34-11:05Z) | 8 lines | 19, to the same workloads | **19** | [`zone-a-r9-plaintext-denials.txt`](zone-a-r9-plaintext-denials.txt) |
| B | `mesh-b-20261124-r8` (10:03-10:14Z) | 8 lines | 3, to the verifier's stand-in `ztd-data/data-target` | 2 | [`zone-b-r8-plaintext-denials.txt`](zone-b-r8-plaintext-denials.txt) |
| B | `mesh-b-20261124-r9` (10:15-10:26Z) | 8 lines | 3, to the same stand-in | 2 | [`zone-b-r9-plaintext-denials.txt`](zone-b-r9-plaintext-denials.txt) |

A line, as the zones write it (zone A, the guard's proxy):

```json
{"authority":null,"code":0,"destination":null,"detail":"filter_chain_not_found","flags":"NR","source":null,"termination":null,"time":"2026-11-24T10:26:25.902Z"}
```

No source identity, the detail and the flag of the kind record, and no `address` (see above). Every
paired line's time is within 2 ms of the forwarded request's.

On zone B the third probe of each run has no line in the collection. The likely cause, not
established: the stand-in it called is removed at the end of the verifier's run, 25 to 40 s after
that probe, and the follower, which read every proxy in turn every 30 s or more, did not come back to
it in time. The collection cannot tell a line that was not read from one that was not written. Each zone B collection also holds one such line of the
stand-in collector's proxy (`ztd-mgmt/otel-collector`) that belongs to no plain-text probe of the
matrix; what made that connection was not established.

**Against the row.** The row pairs an in-mesh call with *the same call* from outside the mesh. Here
the two halves are different calls: the legitimate callers are the verifier's stand-ins on the ALLOW
lanes, the plain-text requests go from a proxy-less probe in a management-plane namespace to pods of
the data plane. On zone A the refused destinations are the zone's real workloads; on zone B the one
data-plane destination the verifier has is its stand-in (`ztd-m3-b`, where the zone's real workloads
run, is labelled plane `m3`; the verifier probes the planes `data` and `management`). The out-of-mesh caller is a probe inside the cluster,
admitted with the capture rule lifted for the probes' creation, as in every run of this verifier.

### ZT-58: the mesh per node, read only

[`zone-a-mesh-readback.txt`](zone-a-mesh-readback.txt) and
[`zone-b-mesh-readback.txt`](zone-b-mesh-readback.txt), written by [`readback.sh`](readback.sh): per zone the nodes, the Istio CNI and SPIRE
agent DaemonSets, the mutual-TLS mode, and for every running meshed pod of a namespace with a plane
label (`ztd.facis.io/plane`, any value, so zone B's `ztd-m3-b` is in) its node, whether the proxy is a native sidecar, the SPIFFE ID in the proxy's certificate and
whether that certificate verifies against the X.509 authority the zone's SPIRE server publishes.

| | Zone A | Zone B |
|---|---|---|
| Nodes, all Ready | 3 | 3 |
| Istio CNI node agent / SPIRE agent ready | 3 of 3 / 3 of 3 | 3 of 3 / 3 of 3 |
| Mesh-wide mutual TLS | `STRICT` (`istio-system/default`) | `STRICT` (`istio-system/default`) |
| Meshed pods read | 6 | 9 |
| with the SPIFFE ID of their own service account, verified against the SPIRE bundle | 6 | 9 |
| with a native sidecar | 6 | 9 |
| Nodes holding such a pod | 3 of 3 | 2 of 3 |

This is not the row's proof. It does not show the traffic capture in each node's CNI configuration,
nor a call across each node boundary with the caller's identity at the receiver (the proof places a
stand-in on every node for that); on zone B one node holds no meshed pod at all, and the pods read are the zones' own few workloads (6 and 9). The certificates'
issuer is the zone's SPIRE CA under its own subject (`O=FACIS ZTD, CN=zone-<a|b>.trust.invalid`), so
the kind proof's check on the organisation `SPIRE` does not apply; the chain was verified instead.

### The four rows of the verifier, again

They were not the aim; they were run to make the calls above.

| Target | BDD run id | Plane-separation run | ZT-23 | ZT-25 | ZT-61 | ZT-62 |
|---|---|---|---|---|---|---|
| `zerotrust-a` | `mesh-a-20261124-r8` | `r68f02b7a`: 121 pass, 0 fail, 14 n/a, 3 declared; 1 failed check | failed | failed | failed | failed |
| `zerotrust-a` | `mesh-a-20261124-r9` | `rfa16d8e6`: 121 pass, 0 fail, 14 n/a, 3 declared; 0 failed checks | **passed** | **passed** | **passed** | **passed** |
| `zerotrust-b` | `mesh-b-20261124-r8` | `rf84a1864`: 41 pass, 0 fail, 6 n/a, 1 declared; 1 failed check | failed | failed | failed | failed |
| `zerotrust-b` | `mesh-b-20261124-r9` | `r9b8b11fa`: 41 pass, 0 fail, 6 n/a, 1 declared; 0 failed checks | **passed** | **passed** | **passed** | **passed** |

The `r8` runs failed for the host, not the zones: the one failed check of each, "every proxy of the
data-plane namespaces holds a configuration SYNCED with istiod", read `proxies 0` because `istioctl`
was not on the path of the machine that ran them (`environment.json`: `"istioctl":""`), and the
verifier does not test for the tool. Every line of both matrices passed. The `r9` runs are the same
command with `istioctl` 1.31.1 on the path. An attempt before `r8` (`-r7`) was refused by the verifier
before it read the zone (the first `python3` on the path had no YAML module, so the zone file's name
read empty).

```bash
KUBECONFIG=<zone> KUBE_CONTEXT=zerotrust-<a|b> ZTD_CONFIRM_CLUSTER=zerotrust-<a|b> \
BDD_ZONE_FILE=deployment/helm/ztd/zones/zone-<a|b>.yaml BDD_TARGET=zone-<a|b> BDD_RUN_ID=<run> BDD_MODE=cluster \
GODOG_CUCUMBER_OUT=bundles/bdd/mesh-zone-<a|b>-<run>.json \
  go test ./internal/bdd -count=1 -timeout 120m -run TestFeatures -godog.tags='@ZT-23,@ZT-25,@ZT-61,@ZT-62'
```

## ZT-27

Not run. The scenario first requires the node collectors, the zone gateway, the entry, Prometheus and
Jaeger to be ready, then runs `scripts/verify-observability/verify.sh`. Neither zone runs any of them:
no `otel-node` or `otel-gateway` release is installed, the namespace `ztd-otel-node` the umbrella
creates is empty on both (the `telemetry` line of `state/zone-<a|b>-after.txt`), and no cluster holds the demonstrator role (the entry, Prometheus, the
tracing backend) for a zone to export to. The proof also stops and restores the zone's SPIRE server,
an agent, a node collector and the gateway's egress to raise its alerts. Running the row on a zone
means installing the telemetry releases on the zone and the demonstrator role somewhere first, which
is an installation, not a run. The row stays **kind only**.

## Rows proven on kind only: zone B

Zone B's namespace `ztd-m3-b` runs the Connector, the token store, the guard with its policy
evaluator, the Participant and the protected resource. For each row proven on kind only, what the zone
could show without a release installed, upgraded or stopped:

| Row | Zone B | Reason |
|---|---|---|
| Token-store service with health and mesh identity | **run, read only**: [record](../token-store-zone-b-2026-11-24/README.md) | readiness green with both dependencies, liveness, no restart, the SPIRE-issued identity, correlation ids. The other half (readiness red with PostgreSQL or OpenBao unreachable) needs a dependency of the zone stopped or cut off (the kind proof scales PostgreSQL to zero and takes OpenBao's Service away from it), which would interrupt the zone's guarded path: not done |
| Replay window at issuance and internal APIs | **run for the store's internal API**: the same record | a seen proof refused, one of 20 concurrent identical proofs admitted, the window and the route held. The database restart with its bounded-exposure log restarts the zone's PostgreSQL: not done. The Connector's refusal at issuance needs a client's credentials: not done |
| Guard decision stream, negative-case catalogue, PDP adapter latency | **not run** | `scripts/verify-guard-catalogue/verify.sh` builds its own cluster and chain. Its cases need what the zone's deployment does not have or must not lose: the guard's policy rules of the run (`m3-scope-required`, `m3-client-blocked`, `m3-presentation-required`), a caller that holds a token and signs its own proofs, the evaluator and the store scaled to zero for `pdp-down` and `store-down`, a short-lived token for `expired-token`, and the feed bridge, which the zone does not run. The zone's guard is the image deployed with release revision 2 on 27 Oct, which still writes the runtime code `token_absent`. Two of the cases are on the zone already: the allowed call with the guard's decision event and the tokenless call refused, in the [guard bypass](../guard-bypass-zone-b-2026-11-22/README.md) and [ZT-73](../bdd-upstreaming-2026-11-23/README.md) records |
| BDD row ZT-20 (guarding) | **not run** | the row is decided by the Rego bundle in the TSA policy service, over REST and gRPC. Zone B has no `tsa-policy` release and no signed bundle, and its guard configuration serves the one REST route `/demo` with the chart's own policy (`ztd-guard-config`, `ztd-policy-config`; read back in [`state/zone-b-guard.txt`](state/zone-b-guard.txt)). Running the row means installing the policy service and upgrading the guard release, which this work must not do |

## State of the zones after the runs

- Helm: on zone A every release has the revision it had before. On zone B the same, except
  `tspa-republish` in `ztd-train` (1 to 2), a namespace this work did not touch
  ([`state/zone-a-after.txt`](state/zone-a-after.txt), [`state/zone-b-after.txt`](state/zone-b-after.txt),
  each against a list taken before the runs and kept outside the repository).
- `ValidatingAdmissionPolicy` `proxy-takes-spire-socket`: the verifier lifts its capture validation
  for under a minute per run and restores it. On both zones its spec equals the one read before the
  runs and its managers are `helm` and `validatingadmissionpolicy-status`; the generation rose by 2
  per run (zone A 21 to 25, zone B 19 to 23).
- No object labelled `app.kubernetes.io/part-of=verify-plane-separation` remains, and no probe Job or
  Pod of the token-store record.

## Limits

- **ZT-01, ZT-27 and ZT-58 have no zone run as BDD rows.** Their status in the evidence index stays
  kind only. What is recorded here for ZT-01 and ZT-58 is supporting evidence of the zones' state.
- **No caller address in the zones' denial line** until the `istiod` release carries this commit's
  values.
- The denial lines were read by a follower run beside the verifier, kept outside the repository with
  the run's records; only the pairings are committed. The node keeps a proxy's log for some hours
  (the lines of 23 Nov were gone by the morning of the 24th), so the lines themselves cannot be read
  back later.
- Trust domains are the interim `zone-*.trust.invalid` names.
- Records outside the repository (git-ignored, delivered with the milestone submission): the
  cucumber reports `bundles/bdd/mesh-zone-<a|b>-<run>.json`, the verifier's records
  `bundles/bdd/evidence/bdd-mesh/zone-<a|b>/<run>/plane-separation/`, the rows' decisions, and the
  collected lines `bundles/bdd/evidence/bdd-zt-001/zone-<a|b>/<run>/denial-lines.txt`.
