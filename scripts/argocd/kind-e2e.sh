#!/usr/bin/env bash
# The admission reconciler end to end in a throwaway kind cluster: Gatekeeper (pinned chart,
# gatekeeper-values.yaml, the webhook-scope post-renderer, as scripts/admission/install.sh installs it;
# no provider, the policy is applied, not exercised), then Argo CD handed the admission policy of a Git
# revision by scripts/argocd/install.sh, which proves every Application Synced and Healthy, the zone's
# repository prefix in the allowed-repositories constraint and the sync status in the metrics. Then the
# catalogue in the cluster is compared with the checkout, a hand-edited constraint is put back
# (scripts/argocd/drift-check.sh), and a change on the parent is reverted too.
#
#   BIN=<dir with kind kubectl and the Gatekeeper and Argo CD charts> REPO_URL=<git url> REVISION=<ref> \
#   scripts/argocd/kind-e2e.sh
#
# REPO_URL and REVISION are what the cluster's Argo CD fetches; the checkout must be that revision, or
# the comparison is meaningless. Needs docker and helm. KEEP=1 leaves the cluster for inspection.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env
: "${REPO_URL:?set REPO_URL}" "${REVISION:?set REVISION}"
bin="$(cd "${BIN:-.tools/bin}" && pwd)"
export PATH="$bin:$PATH"

cluster=ztd-gitops
trust_repository=registry.ztd.test/zone-e2e   # a prefix the files in Git do not name, so the patch is visible
work="$(mktemp -d)"
export KUBECONFIG="$work/kubeconfig"
# The webhook-scope post-renderer is a Helm plugin; it lives in this run's own Helm directory.
export HELM_DATA_HOME="$work/helm" HELM_PLUGINS="$work/helm/plugins"

cleanup() {
  if [ -n "${KEEP:-}" ]; then
    echo "kept: cluster $cluster, KUBECONFIG=$KUBECONFIG"
    return
  fi
  kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

failures=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; failures=$((failures + 1)); }
step() { echo; echo "== $*"; }

step "Cluster"
kind create cluster --name "$cluster" --image "$KIND_NODE_IMAGE" --wait 180s

step "Gatekeeper"
helm plugin install deployment/admission/webhook-scope >/dev/null
helm upgrade --install gatekeeper "$bin/gatekeeper-$GATEKEEPER_CHART_VERSION.tgz" -n gatekeeper-system --create-namespace \
  -f deployment/admission/gatekeeper-values.yaml --set replicas=1 \
  --set image.release="${GATEKEEPER_IMAGE#*:}" \
  --set preInstall.crdRepository.image.repository="${GATEKEEPER_CRDS_IMAGE%%:*}" \
  --set preInstall.crdRepository.image.tag="${GATEKEEPER_CRDS_IMAGE#*:}" \
  --set postInstall.labelNamespace.image.tag="${GATEKEEPER_CRDS_IMAGE#*:}" \
  --set postUpgrade.labelNamespace.image.tag="${GATEKEEPER_CRDS_IMAGE#*:}" \
  --set postInstall.probeWebhook.enabled=false --post-renderer ztd-webhook-scope --wait --timeout 8m >/dev/null
echo "gatekeeper deployed"

step "Argo CD and the admission policy of $REVISION"
BIN="$bin" TRUST_REPOSITORY="$trust_repository" REPO_URL="$REPO_URL" REVISION="$REVISION" scripts/argocd/install.sh

step "The catalogue in the cluster is the checkout"
# kubectl diff exits 1 on a difference; the files that are zone-independent must match as they are.
for f in deployment/admission/templates/ deployment/admission/exemptions.yaml \
  deployment/admission/constraints/image-digest.yaml deployment/admission/constraints/naming.yaml \
  deployment/admission/constraints/verified-images.yaml; do
  if kubectl diff -f "$f" >/dev/null 2>&1; then pass "$f equal in the cluster"; else fail "$f differs in the cluster"; kubectl diff -f "$f" || true; fi
done
if kubectl diff -f deployment/admission/constraints/allowed-repositories.yaml 2>/dev/null | grep -q "^-.*$trust_repository"; then
  pass "allowed-repositories carries the zone's prefix $trust_repository and nothing else differs"
else
  fail "allowed-repositories does not carry the zone's prefix"
fi

step "A hand-edited constraint is put back"
if scripts/argocd/drift-check.sh; then pass "drift check"; else fail "drift check"; fi

step "A hand-edited child Application is put back"
# The parent manages the children: a sync policy removed from one by hand comes back.
kubectl -n argocd patch application admission-templates --type json -p '[{"op":"remove","path":"/spec/syncPolicy/automated"}]' >/dev/null
restored=
for _ in $(seq 180); do
  if [ "$(kubectl -n argocd get application admission-templates -o jsonpath='{.spec.syncPolicy.automated.selfHeal}')" = "true" ]; then restored=1; break; fi
  sleep 1
done
if [ -n "$restored" ]; then pass "admission-templates sync policy put back by the parent"; else fail "admission-templates sync policy not put back within 180s"; fi

echo
if [ "$failures" -ne 0 ]; then echo "$failures check(s) failed"; exit 1; fi
echo "every check passed"
