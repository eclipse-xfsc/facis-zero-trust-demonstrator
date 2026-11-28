# Admission constraints

Gatekeeper policy for the workloads of opted-in namespaces: which images may run, from where, under
which names. Every denial names its reason code from
[reason-codes.json](../../docs/contracts/reason-codes.json).

| Constraint | Template | Denies | Code |
|---|---|---|---|
| `ztd-image-digest` | `templates/image-digest.yaml` | an image not referenced as `host/repository@sha256:<digest>` | `ADM-NOT-DIGEST` |
| `ztd-allowed-repositories` | `templates/allowed-repositories.yaml` | an image outside the allowed repository prefixes that is not one of the allow-listed exact digest references (`allowedDigests`) | `ADM-REGISTRY-DENIED` |
| `ztd-naming` | `templates/naming.yaml` | a workload or pod name outside the convention (default `^ztd-[a-z0-9-]+$`; a generated pod name is checked through its `generateName`) | `ADM-NAME-INVALID` |
| `ztd-verified-images` | `templates/verified-images.yaml` | an image the provider does not verify: signature by a trusted key, SBOM and mock attestations, single-platform linux/amd64 | the provider's code (`ADM-UNSIGNED`, `ADM-SBOM-MISSING`, `ADM-SBOM-INVALID`, `ADM-NO-ATTESTATION`, `ADM-ATTESTATION-INVALID`, `ADM-NOT-LINUX`, `ADM-ARCH-UNSUPPORTED`, `ADM-INDEX-UNSUPPORTED`); a provider system error, an error or a missing answer is `ADM-PROVIDER-DOWN` |

All four apply to Pods and to the pod templates of Deployments, ReplicaSets, StatefulSets, DaemonSets
and Jobs, and to every container, init container and ephemeral container in them.

## Third-party images: the digest allow-list

Platform images the project does not build or sign, such as the Istio proxy the injector adds to
every meshed pod, are admitted by an explicit list of exact references
(`host/repository@sha256:<digest>`, no tag), not re-signed. The list is one input,
`ALLOWED_DIGESTS` of [install.sh](../../scripts/admission/install.sh) - in the umbrella layout,
`admissionProvider.trust.allowedDigests` of the zone file - written to two places:

- the provider's `trust.allowedDigests` ([deployment/helm/admission](../helm/admission#digest-allow-list)):
  an identical reference is answered `verified` without the signature, attestation and platform
  checks, and logged as an allow-listed admission;
- the `allowedDigests` parameter of `ztd-allowed-repositories`: an identical reference passes the
  repository check.

`ztd-image-digest` and `ztd-naming` are unchanged: an allow-listed image is still a digest
reference with a registry host, and the workload still follows the naming convention. Another
digest of a listed repository, the same digest under another repository, or the listed reference
with a tag added, is not on the list and is checked as any other image. The list is empty by
default.

## Scope

Two layers, both positive:

- **Webhook** ([gatekeeper-values.yaml](gatekeeper-values.yaml)): Gatekeeper is called only for
  namespaces labelled `facis.ztd/admission-proof=true` and only for the workload resources above
  (including `pods/ephemeralcontainers`), with `failurePolicy: Fail`. A Gatekeeper or provider outage
  therefore denies admission there and nowhere else: system, ORCE and lifecycle-pool workloads keep
  scheduling. The chart's values can only exclude namespaces, so the positive label selector is added
  to both of the chart's webhooks (the policy webhook and the one guarding the
  `admission.gatekeeper.sh/ignore` namespace label) by the Helm post-renderer plugin in
  [webhook-scope/](webhook-scope), which fails unless it scoped exactly those two.
- **Constraints:** each matches the same label.

Which namespaces carry the label: the admission pool's `ztd-adm-*` namespaces
([deployment/helm/admission-pool](../helm/admission-pool)) and, when the zone opts in with
`admission.enforceDataPlane: true` in the umbrella chart ([deployment/helm/ztd](../helm/ztd)), the
zone's data-plane namespace only. The management plane, `gatekeeper-system`, `istio-system`,
`spire-system` and `kube-system` never carry it. Before opting the data plane in, run
`scripts/admission/preflight-data-plane.sh <namespace>`: it lists every image the namespace's pods
and workload templates use and names those the policy would deny, applying both the provider's and
the constraint's repository rule and allow-list, and fails when the two allow-lists differ. Meshed pods there need the Istio
proxy digest of [istiod.yaml](../helm/values/istiod.yaml) in `ALLOWED_DIGESTS`.

[exemptions.yaml](exemptions.yaml) lists what is exempt and why (`kube-system`, `gatekeeper-system`);
it is reviewed with every change.

## Install

Two layouts. **Umbrella** (a zone file with `admission.install: true`): the zone installer installs
this policy, Gatekeeper, the provider and the admission pool as one release, `gatekeeper` of the
umbrella chart in `gatekeeper-system`, in four stages, with the same values and post-renderer as
below; the umbrella reads the policy here through `deployment/helm/ztd/files/admission` (links, one
copy). See [Admission in the umbrella](../../docs/umbrella-chart.md#admission-in-the-umbrella), with
the migration and rollback runbook. Where an Argo CD keeps this policy from Git (zone A, zone B:
`admission.policy.managedBy: argocd`), the umbrella installs Gatekeeper, the provider and the pool
only. **Standalone** (every zone until it migrates):
[install.sh](../../scripts/admission/install.sh), which is what the commands below do.

Order: Gatekeeper, the provider ([deployment/helm/admission](../helm/admission)), the templates, the
constraints.

```bash
. scripts/tools/pins.env
helm plugin install deployment/admission/webhook-scope
helm install gatekeeper gatekeeper-$GATEKEEPER_CHART_VERSION.tgz -n gatekeeper-system --create-namespace \
  -f deployment/admission/gatekeeper-values.yaml \
  --set image.release="${GATEKEEPER_IMAGE#*:}" \
  --set preInstall.crdRepository.image.repository="${GATEKEEPER_CRDS_IMAGE%%:*}" \
  --set preInstall.crdRepository.image.tag="${GATEKEEPER_CRDS_IMAGE#*:}" \
  --set postInstall.labelNamespace.image.tag="${GATEKEEPER_CRDS_IMAGE#*:}" \
  --set postUpgrade.labelNamespace.image.tag="${GATEKEEPER_CRDS_IMAGE#*:}" \
  --set postInstall.probeWebhook.enabled=false --post-renderer ztd-webhook-scope --wait
helm install admission deployment/helm/admission -n gatekeeper-system -f <provider values>
kubectl apply -f deployment/admission/templates/
kubectl apply -f deployment/admission/exemptions.yaml
kubectl apply -k deployment/admission/constraints
```

`scripts/admission/install.sh` runs this order with the checks that prove each step, and substitutes the
zone's trusted repository prefix into the allowed-repositories constraint. From then on the policy is
kept equal to Git by the reconciler in [deployment/argocd](../argocd/README.md): a merged change to the
templates, the exemptions or the constraints reaches the cluster without a manual step, and a
hand-edited constraint is put back.

**Break-glass:** delete the `gatekeeper-validating-webhook-configuration` ValidatingWebhookConfiguration,
then `helm uninstall gatekeeper -n gatekeeper-system`.

## Tests

- `gator verify deployment/admission` — the constraints that need only the object
  ([suite.yaml](suite.yaml)), including `ztd-allowed-repositories` with an `allowedDigests` list
  (listed digest admitted; another digest, a lookalike repository and the tagged form denied); the
  `gator` job in CI.
- `scripts/admission/kind-e2e.sh` — the whole catalogue in a real Gatekeeper on kind, with the
  provider and a local registry of test images signed with the release script and an ephemeral key:
  signed (admitted and Running), unsigned, untrusted key, mutable tag, each attestation missing,
  non-Linux, image index, registry, allow-listed digest (admitted; another digest and the tagged form denied), naming, init container, ephemeral container, Deployment template,
  the webhook scope (a labelled namespace of any name is enforced, an unlabelled `ztd-adm-*` one is
  not), provider down, trusted key removed while the provider cache is warm (the next admission after
  the provider logs the new policy revision is denied), and Gatekeeper down (denied in labelled
  namespaces, admitted elsewhere); the `admission-kind` job in CI. `LAYOUT=umbrella` runs it on a clean
  install of the umbrella's admission release, `LAYOUT=migrate` after the umbrella adopted a
  standalone install (same Deployments, provider CA and constraints), `LAYOUT=rollback` after the way
  back to standalone.
