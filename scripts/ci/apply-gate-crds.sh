#!/usr/bin/env bash
# The CRDs of the chart gate's cluster that the Cilium, Gatekeeper and Istio manifests do not cover:
# SPIRE's (zone-policy renders a ClusterSPIFFEID) and cert-manager's (telemetry-issuers renders
# Certificates and Issuers). Both come from the pinned, digest-verified charts: spire-crds through
# the zone installer's render, cert-manager from the chart scripts/tools/pins.env pins, with only its
# CustomResourceDefinitions applied (no controller: the gate is a server dry run). Waits until every
# applied CRD is established.
#   KUBE_CONTEXT   kubectl context (default: the current one)
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# shellcheck source=scripts/tools/pins.env disable=SC1091
. "$root/scripts/tools/pins.env"
for tool in kubectl helm sha256sum python3; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done
python3 -c 'import yaml' 2>/dev/null || python3 -m pip install --user --quiet pyyaml
ctx=()
[ -z "${KUBE_CONTEXT:-}" ] || ctx=(--context "$KUBE_CONTEXT")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

RENDER_DIR="$work/render" "$root/scripts/install-zone/install.sh" render spire-crds >/dev/null

helm pull cert-manager --repo "$CERT_MANAGER_CHART_REPO" --version "$CERT_MANAGER_CHART_VERSION" --destination "$work" >/dev/null
archive="$work/cert-manager-$CERT_MANAGER_CHART_VERSION.tgz"
echo "$CERT_MANAGER_CHART_SHA256  $archive" | sha256sum -c - >/dev/null \
  || { echo "apply-gate-crds: cert-manager chart digest is not the pinned $CERT_MANAGER_CHART_SHA256" >&2; exit 1; }
helm template cert-manager "$archive" --namespace cert-manager --set crds.enabled=true >"$work/cert-manager.yaml"

python3 - "$work/render/spire-crds.yaml" "$work/cert-manager.yaml" >"$work/crds.yaml" <<'PY'
import sys, yaml
n = 0
for path in sys.argv[1:]:
    for d in yaml.safe_load_all(open(path)):
        if isinstance(d, dict) and d.get("kind") == "CustomResourceDefinition":
            print("---"); print(yaml.safe_dump(d, sort_keys=False)); n += 1
if n == 0:
    sys.exit("apply-gate-crds: no CustomResourceDefinition rendered")
PY
kubectl "${ctx[@]}" apply --server-side -f "$work/crds.yaml" >/dev/null
kubectl "${ctx[@]}" wait --for condition=established --timeout=60s -f "$work/crds.yaml" >/dev/null
echo "apply-gate-crds: $(grep -c '^kind: CustomResourceDefinition' "$work/crds.yaml") CRDs established (spire-crds, cert-manager $CERT_MANAGER_CHART_VERSION)"
