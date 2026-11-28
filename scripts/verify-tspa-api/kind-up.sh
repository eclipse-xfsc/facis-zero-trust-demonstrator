#!/usr/bin/env bash
# A local TSPA for roundtrip.sh: kind cluster ztd-tspa, upstream's TSPA image built from its Dockerfile,
# installed with upstream's Helm chart and values-kind.yaml, and Keycloak with upstream's test realm.
# The user's default kubeconfig is not touched; the cluster's is written to .dev/tspa/kubeconfig.
#
#   TSPA_REPO=<clone of eclipse-xfsc/train-trust-framework-manager, with train-shared in shared/> \
#     scripts/verify-tspa-api/kind-up.sh      # first image build takes about 15 minutes
#   TSPA_SKIP_BUILD=1 reuses a tspa-service:local image already present instead of building.
#   TSPA_ZONE_MANAGER=1 also installs upstream's zone manager beside the TSPA (the DNS kit under
#     scripts/verify-train-dns/kind, serving the zone TSPA_ZONE, default facis-ztd.local, with the local
#     Keycloak as its issuer) and points the TSPA at it (values-zone-manager.yaml), so PUT /trustframework
#     and PUT /{fw}/did publish records instead of failing with 500. ZONE_MANAGER_REPO names a checkout
#     of eclipse-xfsc/train-dns-trust-zone-manager at the kit's pinned commit; without it the kit fetches one.
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

# TSPA_SKIP_BUILD=1 reuses an image already present (CI restores it from its cache); without it
# the image is always built, which Docker's own layer cache keeps short after the first time.
if [ "${TSPA_SKIP_BUILD:-}" = 1 ] && docker image inspect tspa-service:local >/dev/null 2>&1; then
  echo "TSPA_SKIP_BUILD=1: using the tspa-service:local image already present"
else
  docker build -t tspa-service:local "$repo"
fi
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
values=(-f "$here/values-kind.yaml")
if [ "${TSPA_ZONE_MANAGER:-}" = 1 ]; then
  # The zone manager first, in the same namespace, so the TSPA's health check and writes find it.
  KIND_CONTEXT="kind-$cluster" NAMESPACE=tspa ZONE="${TSPA_ZONE:-facis-ztd.local}" \
    ISSUER_URL=http://keycloak:8080/realms/gxfs-dev-test CLIENT_ID=xfsctest \
    UPSTREAM="${ZONE_MANAGER_REPO:-}" "$root/scripts/verify-train-dns/kind/zone-manager-up.sh"
  # The client's secret, from upstream's realm export, through a private file: never an argument.
  umask 077
  secret_file="$(mktemp)"
  python3 -c "import json,sys;print([c for c in json.load(open(sys.argv[1]))['clients'] if c['clientId']=='xfsctest'][0]['secret'],end='')" \
    "$repo/keycloak/realm-export.json" > "$secret_file"
  values+=(-f "$here/values-zone-manager.yaml" --set-file "application.properties.zonemanager.client-secret=$secret_file")
fi
helm upgrade --install tspa "$out/chart" -n tspa "${values[@]}" \
  --set-string "podAnnotations.values-sha=$(cat "$here/values-kind.yaml" "$here/values-zone-manager.yaml" | shasum | cut -c1-12)-${TSPA_ZONE_MANAGER:-0}" \
  --set-string "podAnnotations.image-id=$image_id" \
  --wait --timeout 10m
rm -f "${secret_file:-}"
echo "TSPA ready in kind cluster $cluster, namespace tspa; run scripts/verify-tspa-api/roundtrip.sh"
[ "${TSPA_ZONE_MANAGER:-}" = 1 ] && echo "zone manager beside it: DNS at nsd-service-dns:53 (udp+tcp), REST at nsd-service-rest:16001, zone ${TSPA_ZONE:-facis-ztd.local}"
true
