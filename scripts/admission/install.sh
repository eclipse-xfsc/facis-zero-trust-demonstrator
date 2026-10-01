#!/usr/bin/env bash
# Install admission control on the current kube context, in the reviewed order: Gatekeeper (pinned
# chart, gatekeeper-values.yaml, the webhook-scope post-renderer, every image pinned by digest), the
# image-verification provider, the constraint templates, the exemptions, the constraints, then the
# admission pool (namespaces and tester identity). Re-running it upgrades in place. It stops at the
# first check that fails: an unpinned image, a webhook not scoped to the admission label, a Gatekeeper
# response cache that is on, or a constraint not enforced.
#
#   BIN=<dir holding the Gatekeeper chart archive> PROVIDER_IMAGE=<repository@sha256:...> \
#   TRUST_REPOSITORY=<host/path> TRUST_KEY=<cosign public key file> \
#   [GATEKEEPER_REPLICAS=2] [PROVIDER_REPLICAS=2] [PLAIN_HTTP_REGISTRY=host:port] scripts/admission/install.sh
#
# Break-glass: delete the ValidatingWebhookConfiguration gatekeeper-validating-webhook-configuration,
# then helm uninstall gatekeeper -n gatekeeper-system.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env
: "${BIN:?set BIN}" "${PROVIDER_IMAGE:?set PROVIDER_IMAGE}" "${TRUST_REPOSITORY:?set TRUST_REPOSITORY}" "${TRUST_KEY:?set TRUST_KEY}"
chart="$BIN/gatekeeper-$GATEKEEPER_CHART_VERSION.tgz"
case "$PROVIDER_IMAGE" in *@sha256:*) ;; *) echo "PROVIDER_IMAGE must be a digest reference" >&2; exit 2 ;; esac

# The webhook-scope post-renderer is a Helm plugin; it lives in this run's own Helm directory.
helm_home="$(mktemp -d)"
trap 'rm -rf "$helm_home"' EXIT
export HELM_DATA_HOME="$helm_home" HELM_PLUGINS="$helm_home/plugins"
helm plugin install deployment/admission/webhook-scope >/dev/null

echo "== Gatekeeper"
gatekeeper_values=(-f deployment/admission/gatekeeper-values.yaml --set replicas="${GATEKEEPER_REPLICAS:-2}"
  --set image.release="${GATEKEEPER_IMAGE#*:}"
  --set preInstall.crdRepository.image.repository="${GATEKEEPER_CRDS_IMAGE%%:*}"
  --set preInstall.crdRepository.image.tag="${GATEKEEPER_CRDS_IMAGE#*:}"
  --set postInstall.labelNamespace.image.tag="${GATEKEEPER_CRDS_IMAGE#*:}"
  --set postUpgrade.labelNamespace.image.tag="${GATEKEEPER_CRDS_IMAGE#*:}"
  --set postInstall.probeWebhook.enabled=false --post-renderer ztd-webhook-scope)
unpinned=$(helm template gatekeeper "$chart" -n gatekeeper-system "${gatekeeper_values[@]}" | grep -E '^\s*image:' | grep -v '@sha256:' || true)
[ -z "$unpinned" ] || { echo "Gatekeeper images not pinned by digest:" >&2; echo "$unpinned" >&2; exit 1; }
helm upgrade --install gatekeeper "$chart" -n gatekeeper-system --create-namespace "${gatekeeper_values[@]}" --wait --timeout 8m >/dev/null
# Both webhooks must select only the admission namespaces.
unscoped=$(kubectl get validatingwebhookconfiguration gatekeeper-validating-webhook-configuration -o json | jq -r '
  .webhooks[] | select(any(.namespaceSelector.matchExpressions[]?; .key == "facis.ztd/admission-proof" and .operator == "In" and .values == ["true"]) | not) | .name')
[ -z "$unscoped" ] || { echo "webhooks not scoped to facis.ztd/admission-proof=true: $unscoped" >&2; exit 1; }
ttl=$(kubectl -n gatekeeper-system get deploy gatekeeper-controller-manager -o jsonpath='{.spec.template.spec.containers[0].args}' | tr ',' '\n' | grep -o 'response-cache-ttl=[^"]*' || true)
[ "$ttl" = "response-cache-ttl=0s" ] || { echo "Gatekeeper response cache is not off: '$ttl'" >&2; exit 1; }
echo "webhooks scoped to facis.ztd/admission-proof=true; $ttl"

echo "== Provider"
provider_values=(--set replicas="${PROVIDER_REPLICAS:-2}" --set image.repository="${PROVIDER_IMAGE%@*}" --set image.digest="${PROVIDER_IMAGE#*@}"
  --set-json "trust.repositories=[\"$TRUST_REPOSITORY\"]" --set-file trust.publicKeys="$TRUST_KEY")
[ -z "${PLAIN_HTTP_REGISTRY:-}" ] || provider_values+=(--set insecurePlainHTTPRegistry="$PLAIN_HTTP_REGISTRY")
helm upgrade --install admission deployment/helm/admission -n gatekeeper-system "${provider_values[@]}" --wait --timeout 5m >/dev/null

echo "== Policy"
kubectl apply -f deployment/admission/templates/ >/dev/null
for kind in k8sztdimagedigest k8sztdallowedrepositories k8sztdnaming k8sztdverifiedimages; do
  for _ in $(seq 60); do kubectl get crd "$kind.constraints.gatekeeper.sh" >/dev/null 2>&1 && break; sleep 2; done
  kubectl wait --for=condition=established --timeout=120s "crd/$kind.constraints.gatekeeper.sh" >/dev/null
done
kubectl apply -f deployment/admission/exemptions.yaml >/dev/null
sed "s|ghcr.io/eclipse-xfsc/facis-zero-trust-demonstrator|$TRUST_REPOSITORY|" deployment/admission/constraints/allowed-repositories.yaml | kubectl apply -f - >/dev/null
for c in image-digest naming verified-images; do kubectl apply -f "deployment/admission/constraints/$c.yaml" >/dev/null; done
# Each constraint must be acknowledged, current and error-free, by every Ready webhook replica.
status_dir="$helm_home/status"
mkdir -p "$status_dir"
for c in k8sztdimagedigest/ztd-image-digest k8sztdallowedrepositories/ztd-allowed-repositories k8sztdnaming/ztd-naming k8sztdverifiedimages/ztd-verified-images; do
  ok=
  for _ in $(seq 90); do
    kubectl get "$c" -o json > "$status_dir/constraint.json"
    kubectl -n gatekeeper-system get pods -l control-plane=controller-manager -o json > "$status_dir/pods.json"
    if scripts/admission/enforced.sh "$status_dir/constraint.json" "$status_dir/pods.json"; then ok=1; break; fi
    sleep 2
  done
  [ -n "$ok" ] || { echo "constraint $c is not enforced by every Ready webhook replica" >&2; exit 1; }
done
echo "constraints enforced by every webhook replica"

echo "== Admission pool"
helm upgrade --install admission-pool deployment/helm/admission-pool -n gatekeeper-system --wait >/dev/null
kubectl get namespaces -l facis.ztd/admission-proof=true -o name
