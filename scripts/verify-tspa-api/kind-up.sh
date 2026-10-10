#!/usr/bin/env bash
# A local TSPA for roundtrip.sh: kind cluster ztd-tspa, upstream's TSPA image built from its Dockerfile,
# installed with upstream's Helm chart and values-kind.yaml, and Keycloak with upstream's test realm.
# The user's default kubeconfig is not touched; the cluster's is written to .dev/tspa/kubeconfig.
#
#   TSPA_REPO=<clone of eclipse-xfsc/train-trust-framework-manager, with train-shared in shared/> \
#     scripts/verify-tspa-api/kind-up.sh      # first image build takes about 15 minutes
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
repo="$(cd "${TSPA_REPO:?set TSPA_REPO to a clone of train-trust-framework-manager}" && pwd)"
cluster=ztd-tspa
node_image="kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95"
out="$root/.dev/tspa"
export KUBECONFIG="$out/kubeconfig"

for tool in kind kubectl helm docker; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done
# The trust-list model classes come from train-shared; upstream's clone does not fetch them (§8).
[[ -d "$repo/shared/src" ]] || { echo "clone eclipse-xfsc/train-shared into $repo/shared first" >&2; exit 1; }

mkdir -p "$out"
chmod 700 "$out"
if kind get clusters | grep -qx "$cluster"; then
  kind export kubeconfig --name "$cluster" >/dev/null
else
  kind create cluster --name "$cluster" --image "$node_image" --wait 120s
fi
chmod 600 "$KUBECONFIG"

docker build -t tspa-service:local "$repo"
kind load docker-image tspa-service:local --name "$cluster"

kubectl create namespace tspa --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n tspa create configmap keycloak-realm --from-file=realm-export.json="$repo/keycloak/realm-export.json" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n tspa apply -f "$here/keycloak.yaml" >/dev/null
# The realm is imported at start only; a changed export rolls Keycloak through this annotation.
realm_sha="$(shasum "$repo/keycloak/realm-export.json" | cut -c1-12)"
kubectl -n tspa patch deploy keycloak --type merge \
  -p "{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\"realm-sha\":\"$realm_sha\"}}}}}" >/dev/null
kubectl -n tspa rollout status deploy/keycloak --timeout=5m

# Upstream's NOTES.txt calls a template the chart does not define ("train-tspa.name"), which fails every
# install; the chart is installed from a copy without it.
rm -rf "$out/chart" && cp -R "$repo/deployment/helm/tspa-service" "$out/chart" && rm "$out/chart/templates/NOTES.txt"
# The configuration reaches the pod through a ConfigMap and the image keeps its tag; the values hash and the
# image ID on the pod roll it when either changes.
image_id="$(docker image inspect -f '{{.Id}}' tspa-service:local | cut -c8-19)"
helm upgrade --install tspa "$out/chart" -n tspa -f "$here/values-kind.yaml" \
  --set-string "podAnnotations.values-sha=$(shasum "$here/values-kind.yaml" | cut -c1-12)" \
  --set-string "podAnnotations.image-id=$image_id" \
  --wait --timeout 10m
echo "TSPA ready in kind cluster $cluster, namespace tspa; run scripts/verify-tspa-api/roundtrip.sh"
