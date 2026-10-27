# M3 evidence: platform baseline on the zone clusters

What the platform baseline on the two OSC zone clusters (`zerotrust-a`, `zerotrust-b`) shows at M3, how
each item is reproduced, and where a run's record lands. Run records are not committed: the evidence
pack writes under `bundles/` (ignored by Git), and the records of the M3 runs are delivered with the
milestone submission, identified by the run, the commit and the cluster's `kube-system` UID.

Everything here is signed with the **interim key**
([docs/contracts/keys/interim-cosign.pub](contracts/keys/interim-cosign.pub)), not the client trust chain,
until the client's signing key and registry are delivered.

## What is shown

| Item | Shows | Reproduce | Record |
|---|---|---|---|
| Capability sheets | Kubernetes version, nodes, CNI and NetworkPolicy enforcement, storage, LoadBalancer and ingress of each zone; the Cilium configuration beside it | `scripts/baseline/capabilities.sh <kubeconfig> > sheet.md`; the Cilium settings with `kubectl --kubeconfig=<same kubeconfig> -n kube-system get configmap cilium-config -o yaml` | committed: [Capability sheets](environments/capabilities/index.md) |
| Admission control installed | Gatekeeper and the image-verification provider on each zone; both webhooks select only the admission namespaces (`ztd-adm-001`, `ztd-adm-002`); the validation webhook has `failurePolicy: Fail` (the namespace-label guard keeps the chart's `Ignore`); response cache off; every constraint enforced by every webhook replica; provider reached over mutual TLS | `scripts/admission/install.sh` (inputs in [IONOS §6](environments/ionos.md#6-admission-proof-non-target)) | its output on the terminal |
| ZT-72 secure pod startup | a signed image starts; unsigned, untrusted-key, mutable-tag, missing-SBOM and missing-mock-attestation images are refused by the API server with their reason codes before any pod exists | `scripts/admission/evidence-pack.sh <target>` | `bundles/admission/<target>/zt-072/` |
| Fail-closed and recovery | provider down → `ADM-PROVIDER-DOWN`; Gatekeeper down → refused; trusted key removed while the cache is warm → refused; break-glass and restore; at the provider-down, Gatekeeper-down and break-glass steps, a pod in each namespace outside admission (`kube-system`, `ztd-mgmt`, `ztd-data`) is admitted (server-side dry run); a load of 200 admissions checks that all are admitted and that the p99 of Gatekeeper's validation requests is below 1.5 s | same command | `bundles/admission/<target>/faults/` |
| Reachability from the pipeline | the API server answers GitHub Actions and the observer authenticates | `cluster-reachability` job ([CI/CD](ci-cd.md#cluster-reachability)) | job summary |

## Running the pack on a zone

After `install.sh` on the zone, with the administrator kubeconfig of that zone and the fixture list the
`admission-fixtures` workflow publishes:

```bash
ADMIN_KUBECONFIG=<zone administrator> FIXTURES=fixtures.txt BIN=<dir with the pinned Gatekeeper chart> \
PROVIDER_IMAGE=ghcr.io/<owner>/facis-zero-trust-demonstrator/admission-provider@sha256:<digest> \
TRUST_REPOSITORY=ghcr.io/<owner>/facis-zero-trust-demonstrator \
TRUST_KEY=docs/contracts/keys/interim-cosign.pub \
OUTSIDE_NAMESPACES="kube-system ztd-mgmt ztd-data" CLUSTER_KIND=target \
scripts/admission/evidence-pack.sh zone-a
```

**Verify:** the script prints the path of `bundles/admission/zone-a/index.md` and exits 0; the index
shows both parts passed, lists every fault case, and records the run, the commit, the cluster's
`kube-system` UID and the provider image. The fault script restores the provider and Gatekeeper to their
recorded replica counts, the trusted key and the webhook on any exit; a `FAIL  restore:` line means the
restore could not complete (for example the API server was unreachable) and an operator re-runs
`install.sh` before anything else.

## Not in this baseline

- Admission enforcement on the zone's own data plane (`ztd-data`) and its configuration through the
  umbrella chart: follows the umbrella integration.
- The secrets baseline (OpenBao) on the zones: OpenBao moves out of the umbrella chart into a release of
  its own, installed after the zone's identity components, so it has its workload identity before it
  starts; until then it stays off on the zones.
- The client signing key and registry (Harbor): the interim key and ghcr are used until delivery.
