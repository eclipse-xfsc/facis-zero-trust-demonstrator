#!/usr/bin/env bash
# The licence and pinning gate over the observability releases' rendered manifests, without a cluster
# (CI). Renders the telemetry releases of a participant zone (deployment/helm/ztd/ci/values.yaml) and
# the demonstrator role (deployment/helm/ztd/zones/ionos.yaml, with a documentation address as the
# zones' egress range) through scripts/install-zone/install.sh, and fails when an image:
#   - is not pinned by digest (@sha256:<64 hex>);
#   - is not in the list below, which names each accepted image repository with its licence
#     (docs/dependencies.md, "Observability"); a new image is added here with its licence, reviewed;
#   - is a Grafana or Loki component (AGPL-3.0, excluded by the Apache-2.0 compatibility rule).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
python3 - "$repo/deployment/helm/ztd/zones/ionos.yaml" "$work/ionos.yaml" <<'PY'
import sys, yaml
z = yaml.safe_load(open(sys.argv[1]))
z["observabilityBackends"]["entry"]["sourceRanges"] = ["203.0.113.0/24"]
yaml.safe_dump(z, open(sys.argv[2], "w"))
PY
RENDER_DIR="$work/zone" "$repo/scripts/install-zone/install.sh" render otel-node otel-gateway >/dev/null
RENDER_DIR="$work/demonstrator" ZONE_VALUES="$work/ionos.yaml" "$repo/scripts/install-zone/install.sh" render >/dev/null
python3 - "$work" <<'PY'
import glob, re, sys, yaml
ACCEPTED = {
    "docker.io/otel/opentelemetry-collector-contrib": "Apache-2.0",
    "quay.io/prometheus/prometheus": "Apache-2.0",
    "quay.io/prometheus/alertmanager": "Apache-2.0",
    "quay.io/prometheus-operator/prometheus-config-reloader": "Apache-2.0",
    "docker.io/jaegertracing/jaeger": "Apache-2.0",
    "jaegertracing/jaeger": "Apache-2.0",
    "docker.io/curlimages/curl": "MIT",           # the umbrella's verification job
}
EXCLUDED = re.compile(r"grafana|loki", re.I)
def images(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "image" and isinstance(v, str): yield v
            else: yield from images(v)
    elif isinstance(node, list):
        for v in node: yield from images(v)
bad, seen = [], {}
for path in sorted(glob.glob(f"{sys.argv[1]}/*/*.yaml")):
    for doc in yaml.safe_load_all(open(path)):
        if not doc: continue
        if EXCLUDED.search(str(doc.get("metadata", {}).get("name", ""))):
            bad.append(f"{path}: {doc['kind']} {doc['metadata']['name']} is a Grafana or Loki component")
        for ref in images(doc):
            repo = re.split(r"[:@]", ref, 1)[0]
            if not re.search(r"@sha256:[0-9a-f]{64}$", ref): bad.append(f"{ref}: not pinned by digest")
            if EXCLUDED.search(ref): bad.append(f"{ref}: Grafana and Loki are excluded (AGPL-3.0)")
            elif repo not in ACCEPTED: bad.append(f"{ref}: not in the accepted list with a licence")
            seen[ref] = ACCEPTED.get(repo, "?")
for ref, lic in sorted(seen.items()):
    print(f"  {lic:11} {ref}")
if bad:
    sys.exit("rendered images: " + "; ".join(sorted(set(bad))))
print(f"rendered images: {len(seen)} images, every one pinned by digest and under an accepted licence; no Grafana or Loki")
PY
