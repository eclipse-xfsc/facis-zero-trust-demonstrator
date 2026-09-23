#!/usr/bin/env bash
# Bring up the local developer cluster for the lifecycle scenarios: a kind cluster on the
# Kubernetes minor of the client targets, the BDD namespace pool, and a kubeconfig for each
# least-privilege identity. Runs are developer checks only, never acceptance evidence.
#
#   scripts/dev/kind-up.sh      # safe to re-run; it only refreshes the identity tokens
set -euo pipefail

cluster="${KIND_CLUSTER:-ztd-bdd}"
# Kubernetes 1.35, the minor the IONOS target runs; the newest kind default is ahead of it.
node_image="kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95"
system_namespace="ztd-bdd-system"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="$root/.dev/kind"
context="kind-$cluster"

if ! kind get clusters | grep -qx "$cluster"; then
  kind create cluster --name "$cluster" --image "$node_image" --wait 120s
fi

kubectl --context "$context" create namespace "$system_namespace" --dry-run=client -o yaml \
  | kubectl --context "$context" apply -f - >/dev/null
helm --kube-context "$context" upgrade --install bdd-pool "$root/deployment/helm/bdd-pool" \
  --namespace "$system_namespace" --wait >/dev/null

# One kubeconfig per identity, so a scenario can only do what that identity is allowed to do.
mkdir -p "$out"
chmod 700 "$out"
server="$(kubectl config view --raw -o jsonpath="{.clusters[?(@.name==\"$context\")].cluster.server}")"
ca="$(kubectl config view --raw -o jsonpath="{.clusters[?(@.name==\"$context\")].cluster.certificate-authority-data}")"
for identity in ztd-lifecycle-deployer ztd-bdd-observer; do
  file="$out/kubeconfig-$identity"
  token="$(kubectl --context "$context" -n "$system_namespace" create token "$identity" --duration 12h)"
  umask 077
  cat >"$file" <<KUBECONFIG
apiVersion: v1
kind: Config
clusters:
  - name: $context
    cluster:
      server: $server
      certificate-authority-data: $ca
users:
  - name: $identity
    user:
      token: $token
contexts:
  - name: $identity
    context:
      cluster: $context
      user: $identity
current-context: $identity
KUBECONFIG
done

echo "cluster $context ready; identity kubeconfigs in ${out#"$root"/}/"
