# Workload identity rows as executable BDD scenarios

2026-11-23 12:59-13:09 UTC, local kind cluster `kind-ztd-wid` (three nodes, Kubernetes v1.35.8,
Cilium 1.20.2 chained, from `scripts/dev/kind-cilium-up.sh`), `kube-system` UID
`958bda3b-4978-4877-a8cd-654b9ca45d05`, commit `ad301bd4` (tree clean), run id `wid-20261123-2`,
trust domain `kind.facis-ztd.local`. The cluster was deleted after the run.

The four rows of the workload identity family, ZT-24, ZT-57, ZT-59 and ZT-60, are implemented in
`features/annex/annex-a.json` as cluster rows (`@cluster`). Their steps
(`internal/bdd/workload_identity_cluster_test.go`) run the mesh identity proof,
`scripts/verify-mesh-identity/verify.sh`, once per test process, and decide each row from the sections
of the `evidence.md` it records: a row passes only when every section it names is present with at least
one check and no failed one, and every check it names is a `PASS` line. Sections 0 to 2
(preconditions, clean slate, the zone installed from the empty cluster twice) are named by every row.
The decision is held by `TestDecideIdentityRow`, which runs in the strict mode.

```bash
KUBE_CONTEXT=kind-ztd-wid BDD_TARGET=kind BDD_RUN_ID=wid-20261123-2 BDD_MODE=cluster \
  GODOG_CUCUMBER_OUT=bundles/bdd/go-cluster-workload-identity-kind.json \
  go test ./internal/bdd -count=1 -timeout 150m -godog.tags='@ZT-24,@ZT-57,@ZT-59,@ZT-60'
```

The proof needs the umbrella's dependencies built first (`helm dependency build deployment/helm/ztd`);
a first run without them (`wid-20261123-1`) failed at the install and every row was decided failed,
as it should be.

| Row | Sections decided on | Checks it requires (among others in those sections) | Result |
|---|---|---|---|
| ZT-24 SPIFFE/SPIRE Deployment | 0, 1, 2, 4, 6, 8, 9, 12, 14 | every agent attested by the server; SPIRE and mesh on the zone's trust domain; an entry from the `ClusterSPIFFEID` for the labelled pod; the proxy's certificate `O = SPIRE` and its `ROOTCA` the SPIRE CA; no entry and no SVID for the unlabelled pods; the registration inventory | passed, 124 checks |
| ZT-57 SPIFFE/SPIRE Setup | 0, 1, 2, 4, 6 | every agent attested; a per-node SVID stand-in Ready on every node with an agent, each fetching its SVID over its node's socket, chained to the SPIRE CA; the labelled pod mounts `csi.spiffe.io` | passed, 36 checks |
| ZT-59 Successful Identification | 0, 1, 2, 6, 8, 10 | the entry for the labelled pod; its SVID carries its service account's SPIFFE ID and chains to the SPIRE CA; the proxy holds a SPIRE-issued certificate; the peer sees the caller's own SPIFFE ID in `X-Forwarded-Client-Cert` | passed, 92 checks |
| ZT-60 Unsuccessful Identification | 0, 1, 2, 6, 9 | no entry and no SVID for the unlabelled pods; its proxy never served a certificate, the agent's SDS refusal in its log; its application never starts; its call to the peer refused in the handshake under STRICT, with no denial line naming it (no identity was presented); the labelled pod's call to the same peer served | passed, 35 checks |

The whole run: 222 checks, 0 failed (`environment.json` `result.failures` 0). The cucumber report
(`bundles/bdd/go-cluster-workload-identity-kind.json`), the record
(`bundles/bdd/evidence/workload-identity/kind/wid-20261123-2/`: `evidence.md`, `environment.json`,
`verify.log`) and each row's decision (`bundles/bdd/evidence/bdd-zt-0NN/kind/wid-20261123-2/decision.txt`)
are git-ignored and delivered with the milestone submission.

The two failures the M3 plan listed for this proof on the base do not occur on this base: the
registration count `17` against `16` appears only in section 13, where it is the intended refusal of a
declared registration without its entry (that check passes), and the three SPIRE CRDs carry no
`helm.sh/resource-policy: keep` (section 16, passed). Nothing was changed for them.

## Limits

- **Kind only.** The rows speak of each target cluster; this run is the local substitute. The proof
  uninstalls and reinstalls the zone, so it was not run on zone A or zone B, which hold the installed
  zone and other work. A zone run (`KUBE_CONTEXT=zerotrust-a ZTD_CONFIRM_CLUSTER=zerotrust-a
  ZONE_VALUES=deployment/helm/ztd/zones/zone-a.yaml`, with `ZTD_KEEP_ZONE` to keep it) is a deliberate
  reinstall and needs its own window. The zone runs of 12-26 October predate this harness.
- **Placeholder trust domains.** Zone A and zone B still run on `zone-a.trust.invalid` and
  `zone-b.trust.invalid`, because the final names are not yet given. A zone record on them is marked
  interim by the proof and is rerun once the names are confirmed.
- **Stand-ins.** The identities shown are the proof's stand-in workloads and the OpenBao server; each
  service proves its own enrolment.
- The cluster dry run lists the four rows and skips every step, so a pull request reports them as
  not run.
