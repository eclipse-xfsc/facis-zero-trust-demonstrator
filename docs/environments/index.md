# Environments

The demonstrator runs across **three managed Kubernetes clusters**: two on T-Systems Open Sovereign
Cloud carrying the two demonstration zones, and one on IONOS Cloud carrying the CI/CD and
visualization environment. The reasoning for three rather than two is recorded in
[ADR-0005](../adr/0005-three-cluster-reading-of-the-target-environment.md).

| Environment | Clusters | Role | Guide |
|---|---|---|---|
| T-Systems Open Sovereign Cloud | 2 | Zone A and zone B — the two demonstration zones and their trust boundary | [OSC setup](osc.md) — provided (contexts `zerotrust-a`, `zerotrust-b`); both zones installed and kept on interim trust domains, on the provider's VXLAN overlay (Cilium 1.19.6, tunnel routing); the proof on every node, with the OpenBao release, has run on kind and on both zones with the keep opt-in, every check passed; the proof: [the guide's proving step](osc.md#proving-steps-2-to-4-the-mesh-identity-proof) and `scripts/verify-mesh-identity/README.md` |
| IONOS Cloud | 1 | CI/CD and the visualization environment | [IONOS setup](ionos.md) — provided; ORCE and the BDD pool installed; the ambient mesh installed and proven (2026-11-15) |

Application services that run before the zones exist, and how they are installed without cluster
rights, are described in [Application workloads](application-workloads.md).

Each guide is written to be followed start to finish by someone who has not seen the cluster before.
Where a step cannot be executed yet it says so, rather than reading as though it had been done.

## What is common to all three

- **Kubernetes 1.29 or later.** Older versions are not supported; the mesh and admission baselines
  assume it. A cluster that runs the mesh in sidecar mode needs **1.33 or later**, for the native
  sidecar containers of [ADR-0009](../adr/0009-service-mesh-mode-istio-sidecar-with-cilium.md).
- **Cilium as CNI** on the participant clusters, configured with `cni.exclusive=false` so the
  Istio CNI plugin can chain behind it, and **Istio in sidecar mode** with SPIRE on top
  ([ADR-0009](../adr/0009-service-mesh-mode-istio-sidecar-with-cilium.md); ambient with Cilium is the
  parked alternative). The IONOS cluster keeps its provider-managed Calico and gets **Istio in
  ambient mode without SPIRE**, the Istio CNI agent chained behind Calico, under a declared CNI
  derogation ([ADR-0018](../adr/0018-service-mesh-on-the-demonstrator-cluster.md); [the mesh and
  SPIRE on each cluster](../specifications.md#the-mesh-and-spire-on-each-cluster)); see its guide.
- **The clusters are client-provided.** Provisioning them is out of scope; these guides begin at the
  point where a kubeconfig is in hand.
- **Nothing is applied by hand.** Every step below is a chart, a script in `scripts/` or a pipeline
  run. A step that cannot be expressed that way is a defect in the step, not a reason to click.

## Installing a zone

A zone is installed by one command from one zone file: `scripts/install-zone/install.sh install`,
which runs, on the sidecar path of the participant zones, eight Helm releases in order — the umbrella
`ztd`, `spire-crds`, `spire`, `istio-base`, `istiod`, `istio-cni`, `zone-policy`, `ztd-openbao` (the
secret store, last, so it is created with its mesh identity) — each through the deployment lifecycle
step, and exits 0 only when every pod of the zone is Ready. A zone file with `mesh.mode: ambient`
(the IONOS cluster) selects the ambient path instead: the umbrella, `istio-base`, `istiod`,
`istio-cni`, `ztunnel` and `zone-policy`, with no SPIRE and no OpenBao ([IONOS
guide](ionos.md#7-the-service-mesh-ambient-no-spire)). The zone file records the cluster's facts (Kubernetes version, storage class, load
balancer) and, where the mesh runs, the zone's trust domain (a name under the DNS zone delegated to
the trust framework, one per zone) and the API server's port; the releases after the umbrella read
the facts they need from the umbrella's defaults with the zone file on top. The [OSC guide](osc.md#2-the-zone-layout)
walks through it step by step with each step's verification; the identity path is described in
[Workload identity](../workload-identity.md).

## Reproduction and verification

ZT-16 asks for documentation from which the setup of each cluster can be reproduced step by step.
Each guide therefore pairs every stage with the check that proves the stage worked — the command,
and what its output has to say. A stage without a check is not finished.
