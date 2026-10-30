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
#   [CILIUM=1 | KUBE_API_CIDRS=a/32,b/32] [KUBE_API_PORTS=443,6443] [NAMESPACE_LABELS="key=value ..."] \
#   scripts/argocd/install.sh
#
# TRUST_REPOSITORY must be one of the provider's trust.repositories when the admission provider is
# installed (release admission in gatekeeper-system): the constraint and the provider then agree, and
# a prefix changed on one side only is refused instead of being reverted by the reconciler.
#
# The lane to the Kubernetes API is a zone fact. CILIUM=1 writes a CiliumNetworkPolicy to the
# kube-apiserver entity, the only form that selects the API server under Cilium; KUBE_API_CIDRS writes
# a NetworkPolicy to those addresses (the endpoint of the kubernetes Service, and its cluster address)
# where the CNI selects it by address, kind's among them. Both open KUBE_API_PORTS: the Service port
# and the endpoint port, as the umbrella's lane does, since Cilium sees the Service port with
# kube-proxy and the endpoint port without it. Neither is accepted only on a cluster without Cilium,
# for a CNI that enforces no policy at all. NAMESPACE_LABELS go on the argocd namespace before anything
# runs in it; on a Gardener cluster that is apiserver-proxy.networking.gardener.cloud/inject=disable, so
# the pods reach the API server through the kubernetes Service, inside the lane, and not through a
# node-local proxy outside it.
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
api_ports="${KUBE_API_PORTS:-443,6443}"

echo "== Trusted repository"
# The provider's trust.repositories, when the admission provider is installed; the prefix given here
# must be among them, or the constraint and the provider would disagree.
provider_repos=$(helm get values admission -n gatekeeper-system -o json 2>/dev/null | jq -r '(.trust.repositories // [])[]' 2>/dev/null || true)
if [ -n "$provider_repos" ]; then
  grep -qxF -- "$TRUST_REPOSITORY" <<<"$provider_repos" \
    || { echo "TRUST_REPOSITORY $TRUST_REPOSITORY is not among the provider's trust.repositories: $(paste -sd, <<<"$provider_repos")" >&2; exit 2; }
  echo "$TRUST_REPOSITORY, the same prefix the admission provider trusts"
else
  echo "$TRUST_REPOSITORY (no admission provider release to compare with)"
fi

echo "== Namespace"
kubectl get namespace "$ns" >/dev/null 2>&1 || kubectl create namespace "$ns" >/dev/null
for label in ${NAMESPACE_LABELS:-}; do kubectl label namespace "$ns" "$label" --overwrite >/dev/null; done
cilium_crd=ciliumnetworkpolicies.cilium.io
if [ -n "${CILIUM:-}" ]; then
  kubectl get crd "$cilium_crd" >/dev/null 2>&1 || { echo "CILIUM=1 but the cluster has no $cilium_crd" >&2; exit 2; }
  # Cilium does not select the API server by address: it is the kube-apiserver entity, and a
  # NetworkPolicy ipBlock never matches it (the umbrella's lane for the plane namespaces). Only the
  # API ports: every port would open every port of the node the API server runs on. enableDefaultDeny
  # off: this policy adds a lane and leaves the deny to the NetworkPolicies of the namespace.
  {
    cat <<POLICY
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-kube-api-egress
  namespace: $ns
spec:
  description: "argocd pods -> the API server, by entity"
  endpointSelector: {}
  enableDefaultDeny:
    egress: false
    ingress: false
  egress:
    - toEntities:
        - kube-apiserver
      toPorts:
        - ports:
POLICY
    for port in ${api_ports//,/ }; do echo "            - {port: \"$port\", protocol: TCP}"; done
  } | kubectl apply -f - >/dev/null
  echo "kube API lane: CiliumNetworkPolicy to the kube-apiserver entity, ports $api_ports"
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
    for port in ${api_ports//,/ }; do echo "        - {port: $port, protocol: TCP}"; done
  } | kubectl apply -f - >/dev/null
  echo "kube API lane: NetworkPolicy to $KUBE_API_CIDRS, ports $api_ports"
else
  # Without a lane the controller never reaches the API and the install only fails after its timeout;
  # Cilium is detectable up front, so refuse here.
  if kubectl get crd "$cilium_crd" >/dev/null 2>&1; then
    echo "the cluster runs Cilium: set CILIUM=1 (or KUBE_API_CIDRS) so the argocd namespace gets its lane to the API server" >&2
    exit 2
  fi
  echo "kube API lane: none (right only for a CNI that enforces no policy)"
fi

echo "== Argo CD"
values=(-f deployment/argocd/argocd-values.yaml
  --set global.image.tag="${ARGOCD_IMAGE#*:}" --set redis.image.tag="${ARGOCD_REDIS_IMAGE#*:}")
unpinned=$(helm template argocd "$chart" -n "$ns" "${values[@]}" | grep -E '^\s*image:' | grep -v '@sha256:' || true)
[ -z "$unpinned" ] || { echo "Argo CD images not pinned by digest:" >&2; echo "$unpinned" >&2; exit 1; }
helm upgrade --install argocd "$chart" -n "$ns" "${values[@]}" --wait --timeout 8m >/dev/null
echo "every image pinned by digest; release argocd deployed"

echo "== Admission policy from $repo_url at $revision"
# The bootstrap project confines the parent: one source repository, this namespace as the only
# destination, and only Applications and AppProjects as what it may create. The parent: Argo CD renders
# deployment/helm/admission-gitops from Git with the zone's values and keeps the children it renders.
# Its finalizer makes `kubectl delete application ztd-admission` a cascade: the children go, and with
# them the policy they manage.
kubectl apply -f - >/dev/null <<APP
apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata:
  name: ztd-bootstrap
  namespace: $ns
spec:
  description: The app-of-apps of the admission policy, and nothing else
  sourceRepos:
    - "$repo_url"
  destinations:
    - server: https://kubernetes.default.svc
      namespace: $ns
  clusterResourceWhitelist: []
  namespaceResourceWhitelist:
    - group: argoproj.io
      kind: Application
    - group: argoproj.io
      kind: AppProject
---
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: ztd-admission
  namespace: $ns
  finalizers:
    - resources-finalizer.argocd.argoproj.io
spec:
  project: ztd-bootstrap
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

echo "== No users"
# The admin account is disabled in the values; the password Secret the API server wrote at its first
# start is deleted too, so no credential for the API exists anywhere.
kubectl -n "$ns" delete secret argocd-initial-admin-secret --ignore-not-found >/dev/null
echo "admin disabled; the initial password Secret is gone"

echo "== Sync status in the metrics"
# The controller exports one argocd_app_info series per Application, with its sync and health status,
# on the metrics Service; read from inside the namespace, the only place the network layer admits.
# A probe pod left by an interrupted run is removed first, so a re-run never fails on its name.
kubectl -n "$ns" delete pod ztd-argocd-metrics-check --ignore-not-found --now >/dev/null 2>&1 || true
metrics=$(kubectl -n "$ns" run ztd-argocd-metrics-check --rm -i --restart=Never --quiet --pod-running-timeout=3m \
  --image "$CURL_IMAGE" --command -- curl -sf http://argocd-application-controller-metrics:8082/metrics \
  | grep '^argocd_app_info{' || true)
for app in "${apps[@]}"; do
  line=$(grep "name=\"$app\"" <<<"$metrics" | grep 'sync_status="Synced"' || true)
  [ -n "$line" ] || { echo "no argocd_app_info series with sync_status=Synced for $app" >&2; printf '%s\n' "$metrics" >&2; exit 1; }
  echo "$(sed -E 's/.*health_status="([^"]*)".*sync_status="([^"]*)".*/'"$app"': sync=\2 health=\1/' <<<"$line")"
done
