# Admission constraints

Gatekeeper policy for the workloads of opted-in namespaces: which images may run, from where, under
which names. Every denial names its reason code from
[reason-codes.json](../../docs/contracts/reason-codes.json).

| Constraint | Template | Denies | Code |
|---|---|---|---|
| `ztd-image-digest` | `templates/image-digest.yaml` | an image not referenced as `host/repository@sha256:<digest>` | `ADM-NOT-DIGEST` |
| `ztd-allowed-repositories` | `templates/allowed-repositories.yaml` | an image outside the allowed repository prefixes | `ADM-REGISTRY-DENIED` |
| `ztd-naming` | `templates/naming.yaml` | a workload or pod name outside the convention (default `^ztd-[a-z0-9-]+$`; a generated pod name is checked through its `generateName`) | `ADM-NAME-INVALID` |
| `ztd-verified-images` | `templates/verified-images.yaml` | an image the provider does not verify: signature by a trusted key, SBOM and mock attestations, single-platform linux/amd64 | the provider's code (`ADM-UNSIGNED`, `ADM-SBOM-MISSING`, `ADM-SBOM-INVALID`, `ADM-NO-ATTESTATION`, `ADM-ATTESTATION-INVALID`, `ADM-NOT-LINUX`, `ADM-ARCH-UNSUPPORTED`, `ADM-INDEX-UNSUPPORTED`); a provider system error, an error or a missing answer is `ADM-PROVIDER-DOWN` |

All four apply to Pods and to the pod templates of Deployments, ReplicaSets, StatefulSets, DaemonSets
and Jobs, and to every container, init container and ephemeral container in them.

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

[exemptions.yaml](exemptions.yaml) lists what is exempt and why (`kube-system`, `gatekeeper-system`);
it is reviewed with every change.

## Install

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
kubectl apply -f deployment/admission/exemptions.yaml -f deployment/admission/constraints/
```

**Break-glass:** delete the `gatekeeper-validating-webhook-configuration` ValidatingWebhookConfiguration,
then `helm uninstall gatekeeper -n gatekeeper-system`.

## Tests

- `gator verify deployment/admission` — the constraints that need only the object
  ([suite.yaml](suite.yaml)); the `gator` job in CI.
- `scripts/admission/kind-e2e.sh` — the whole catalogue in a real Gatekeeper on kind, with the
  provider and a local registry of test images signed with the release script and an ephemeral key:
  signed (admitted and Running), unsigned, untrusted key, mutable tag, each attestation missing,
  non-Linux, image index, registry, naming, init container, ephemeral container, Deployment template,
  the webhook scope (a labelled namespace of any name is enforced, an unlabelled `ztd-adm-*` one is
  not), provider down, trusted key removed while the provider cache is warm (the next admission after
  the provider logs the new policy revision is denied), and Gatekeeper down (denied in labelled
  namespaces, admitted elsewhere); the `admission-kind` job in CI.
