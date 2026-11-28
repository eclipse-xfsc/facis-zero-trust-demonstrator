#!/usr/bin/env bash
# cert-manager on the local kind cluster, for the demonstrator role that shares the cluster with the
# kind zone (deployment/helm/ztd/ci/demonstrator-values.yaml): its telemetry issuers
# (deployment/helm/telemetry-issuers) need cert-manager, which the demonstrator cluster runs on its
# own (found at v1.21.2) and kind does not. Installs the chart pinned in scripts/tools/pins.env, by
# version and archive digest, with every image pinned by digest, into the namespace cert-manager.
# Idempotent. Refuses any context that is not a kind cluster.
#   KUBE_CONTEXT   kubectl context (default: kind-ztd)
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=scripts/tools/pins.env disable=SC1091
. "$here/../tools/pins.env"
CONTEXT=${KUBE_CONTEXT:-kind-ztd}
case $CONTEXT in kind-?*) ;; *) echo "kind-cert-manager-up: refusing context $CONTEXT: kind only" >&2; exit 1;; esac
for tool in kubectl helm sha256sum; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
helm pull cert-manager --repo "$CERT_MANAGER_CHART_REPO" --version "$CERT_MANAGER_CHART_VERSION" --destination "$work" >/dev/null
archive="$work/cert-manager-$CERT_MANAGER_CHART_VERSION.tgz"
echo "$CERT_MANAGER_CHART_SHA256  $archive" | sha256sum -c - >/dev/null \
  || { echo "kind-cert-manager-up: chart digest is not the pinned $CERT_MANAGER_CHART_SHA256" >&2; exit 1; }
digest() { echo "${1#*@}"; }
kubectl --context "$CONTEXT" get namespace cert-manager >/dev/null 2>&1 \
  || kubectl --context "$CONTEXT" create namespace cert-manager >/dev/null
helm --kube-context "$CONTEXT" upgrade --install cert-manager "$archive" --namespace cert-manager --wait --timeout 5m \
  --set crds.enabled=true \
  --set image.digest="$(digest "$CERT_MANAGER_CONTROLLER_IMAGE")" \
  --set cainjector.image.digest="$(digest "$CERT_MANAGER_CAINJECTOR_IMAGE")" \
  --set webhook.image.digest="$(digest "$CERT_MANAGER_WEBHOOK_IMAGE")" \
  --set startupapicheck.image.digest="$(digest "$CERT_MANAGER_STARTUPAPICHECK_IMAGE")" \
  --set acmesolver.image.digest="$(digest "$CERT_MANAGER_ACMESOLVER_IMAGE")" >/dev/null
echo "cert-manager $CERT_MANAGER_CHART_VERSION installed on $CONTEXT"
