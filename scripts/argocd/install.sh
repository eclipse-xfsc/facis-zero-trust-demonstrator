#!/usr/bin/env bash
# Install Argo CD on the current kube context and hand it the zone's admission policy: the pinned chart
# (deployment/argocd/argocd-values.yaml, every image pinned by digest), then the parent Application that
# renders deployment/helm/admission-gitops from Git - the app-of-apps whose children keep Gatekeeper's
# constraint templates, exemptions and constraints equal to the revision the zone follows, and put back
# what is changed by hand. Re-running it upgrades in place. It stops at the first check that fails: an
# unpinned image, an Application that does not reach Synced and Healthy, the zone's repository prefix
# missing from the allowed-repositories constraint, or a sync status missing from the metrics the
# controller exports.
#
#   BIN=<dir holding the Argo CD chart archive> TRUST_REPOSITORY=<host/path> \
#   [REPO_URL=https://github.com/eclipse-xfsc/facis-zero-trust-demonstrator.git] [REVISION=main] \
#   [CILIUM=1 | KUBE_API_CIDRS=a/32,b/32] [NAMESPACE_LABELS="key=value ..."] scripts/argocd/install.sh
#
# The lane to the Kubernetes API is a zone fact: CILIUM=1 applies deployment/argocd/kube-api-lane.cilium.yaml,
# a CiliumNetworkPolicy to the kube-apiserver entity, the only form that selects the API server under
# Cilium; KUBE_API_CIDRS opens a NetworkPolicy to those addresses (the endpoint of the kubernetes
# Service, and its cluster address) where the CNI selects it by address, kind's among them. Neither:
# no lane, only for a CNI that enforces no policy at all. NAMESPACE_LABELS go on the argocd
# namespace before anything runs in it; on a Gardener cluster that is
# apiserver-proxy.networking.gardener.cloud/inject=disable, so the pods reach the API server through the
# kubernetes Service, inside the lane, and not through a node-local proxy outside it.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env
: "${BIN:?set BIN}" "${TRUST_REPOSITORY:?set TRUST_REPOSITORY}"
repo_url="${REPO_URL:-https://github.com/eclipse-xfsc/facis-zero-trust-demonstrator.git}"
revision="${REVISION:-main}"
chart="$BIN/argo-cd-$ARGOCD_CHART_VERSION.tgz"
ns=argocd
apps=(ztd-admission admission-templates admission-exemptions admission-constraints)

echo "== Namespace"
kubectl get namespace "$ns" >/dev/null 2>&1 || kubectl create namespace "$ns" >/dev/null
for label in ${NAMESPACE_LABELS:-}; do kubectl label namespace "$ns" "$label" --overwrite >/dev/null; done
if [ -n "${CILIUM:-}" ]; then
  kubectl apply -f deployment/argocd/kube-api-lane.cilium.yaml >/dev/null
  echo "kube API lane: CiliumNetworkPolicy to the kube-apiserver entity"
elif [ -n "${KUBE_API_CIDRS:-}" ]; then
  {
    cat <<POLICY
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-kube-api-egress
  namespace: $ns
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - to:
POLICY
    for cidr in ${KUBE_API_CIDRS//,/ }; do echo "        - ipBlock: {cidr: \"$cidr\"}"; done
    echo "      ports:"
    echo "        - {port: 443, protocol: TCP}"
    echo "        - {port: 6443, protocol: TCP}"
  } | kubectl apply -f - >/dev/null
  echo "kube API lane: NetworkPolicy to $KUBE_API_CIDRS"
else
  echo "kube API lane: none (only right for a CNI that enforces no policy)"
fi

echo "== Argo CD"
values=(-f deployment/argocd/argocd-values.yaml
  --set global.image.tag="${ARGOCD_IMAGE#*:}" --set redis.image.tag="${ARGOCD_REDIS_IMAGE#*:}")
unpinned=$(helm template argocd "$chart" -n "$ns" "${values[@]}" | grep -E '^\s*image:' | grep -v '@sha256:' || true)
[ -z "$unpinned" ] || { echo "Argo CD images not pinned by digest:" >&2; echo "$unpinned" >&2; exit 1; }
helm upgrade --install argocd "$chart" -n "$ns" "${values[@]}" --wait --timeout 8m >/dev/null
echo "every image pinned by digest; release argocd deployed"

echo "== Admission policy from $repo_url at $revision"
# The parent: Argo CD renders deployment/helm/admission-gitops from Git with the zone's values and
# keeps the children it renders. Its finalizer makes `kubectl delete application ztd-admission` a
# cascade: the children go, and with them the policy they manage.
kubectl apply -f - >/dev/null <<APP
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: ztd-admission
  namespace: $ns
  finalizers:
    - resources-finalizer.argocd.argoproj.io
spec:
  project: default
  source:
    repoURL: "$repo_url"
    targetRevision: "$revision"
    path: deployment/helm/admission-gitops
    helm:
      valuesObject:
        git:
          repoURL: "$repo_url"
          targetRevision: "$revision"
        trust:
          repositories:
            - "$TRUST_REPOSITORY"
  destination:
    server: https://kubernetes.default.svc
    namespace: $ns
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    retry:
      limit: 10
      backoff:
        duration: 10s
        factor: 2
        maxDuration: 3m
APP
# Every Application Synced and Healthy: the parent, then the three children it creates.
for app in "${apps[@]}"; do
  ok=
  for _ in $(seq 120); do
    state=$(kubectl -n "$ns" get application "$app" -o jsonpath='{.status.sync.status}/{.status.health.status}' 2>/dev/null || true)
    if [ "$state" = "Synced/Healthy" ]; then ok=1; break; fi
    sleep 5
  done
  if [ -z "$ok" ]; then
    echo "application $app is '$state', not Synced/Healthy" >&2
    kubectl -n "$ns" get application "$app" -o jsonpath='{.status.conditions}{"\n"}{.status.operationState.message}{"\n"}' >&2 || true
    exit 1
  fi
  echo "$app Synced/Healthy at $(kubectl -n "$ns" get application "$app" -o jsonpath='{.status.sync.revision}')"
done
live=$(kubectl get k8sztdallowedrepositories ztd-allowed-repositories -o jsonpath='{.spec.parameters.repositories}')
[ "$live" = "[\"$TRUST_REPOSITORY\"]" ] || { echo "allowed repositories are $live, not [\"$TRUST_REPOSITORY\"]" >&2; exit 1; }
echo "allowed repositories: $live"

echo "== Sync status in the metrics"
# The controller exports one argocd_app_info series per Application, with its sync and health status,
# on the metrics Service; read from inside the namespace, the only place the network layer admits.
metrics=$(kubectl -n "$ns" run ztd-argocd-metrics-check --rm -i --restart=Never --quiet --pod-running-timeout=3m \
  --image "$CURL_IMAGE" --command -- curl -sf http://argocd-application-controller-metrics:8082/metrics \
  | grep '^argocd_app_info{' || true)
for app in "${apps[@]}"; do
  line=$(grep "name=\"$app\"" <<<"$metrics" | grep 'sync_status="Synced"' || true)
  [ -n "$line" ] || { echo "no argocd_app_info series with sync_status=Synced for $app" >&2; printf '%s\n' "$metrics" >&2; exit 1; }
  echo "$(sed -E 's/.*health_status="([^"]*)".*sync_status="([^"]*)".*/'"$app"': sync=\2 health=\1/' <<<"$line")"
done
