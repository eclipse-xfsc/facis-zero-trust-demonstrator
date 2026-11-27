#!/usr/bin/env bash
# A hook pod in a meshed namespace must carry the identity label (render only, no cluster).
#
#   scripts/ci/check-hook-identity.sh [zone-file...]
#
# Helm runs an install or upgrade hook again on every upgrade. The first install of a zone runs the
# umbrella before istiod exists, so its hook pods get no proxy; on every rerun of the installer the
# injector adds the mesh proxy to a hook pod created in a namespace with the injection label. That
# proxy is a native sidecar that stays unready until the SPIRE agent hands it an SVID, and the
# agent does so only for a pod the zone-policy registration rule (ClusterSPIFFEID plane-workloads)
# selects: one carrying the identity label. A hook pod without it stays at Init:1/2, the hook times
# out and the upgrade is rolled back.
#
# The check renders the umbrella (deployment/helm/ztd, or $CHART) with each zone file - by default
# its ci/values.yaml and every shipped zone file under zones/ but the example - and fails, naming
# the hook, when a Job or Pod hook of an install or upgrade phase is rendered into a namespace the
# same render labels for injection (istio-injection=enabled, or istio.io/rev) and its pod lacks the
# identity label. The label's key and value are read from zone-policy's registration.identityLabel.
# Helm test pods (hook phase test) run only under `helm test` and are not checked.
#
# Exit status: 0 when every such hook carries the label, 1 when one does not or a render fails.
# Needs helm and python3 with PyYAML; the umbrella's dependencies must be built (charts/).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
chart=${CHART:-$root/deployment/helm/ztd}
policy_values=${POLICY_VALUES:-$root/deployment/helm/zone-policy/values.yaml}

zones=("$@")
if [ ${#zones[@]} -eq 0 ]; then
  zones=("$chart/ci/values.yaml")
  for zone in "$chart"/zones/*.yaml; do
    [ "$(basename "$zone")" = zone-a.example.yaml ] && continue
    zones+=("$zone")
  done
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0
for zone in "${zones[@]}"; do
  if ! helm template ztd "$chart" -f "$zone" > "$work/render.yaml" 2> "$work/render.err"; then
    echo "FAIL $zone: the umbrella does not render" >&2
    sed 's/^/  /' "$work/render.err" >&2
    failures=$((failures + 1))
    continue
  fi
  if ! python3 - "$work/render.yaml" "$policy_values" "$zone" <<'PY'
import sys, yaml

render, policy_values, zone = sys.argv[1:]
label = yaml.safe_load(open(policy_values))["registration"]["identityLabel"]
key, value = label["key"], str(label["value"])
docs = [d for d in yaml.safe_load_all(open(render)) if isinstance(d, dict)]

meshed = set()
for d in docs:
    if d.get("kind") != "Namespace":
        continue
    labels = d["metadata"].get("labels") or {}
    if labels.get("istio-injection") == "enabled" or "istio.io/rev" in labels:
        meshed.add(d["metadata"]["name"])

phases = {"pre-install", "post-install", "pre-upgrade", "post-upgrade"}
checked, missing = [], []
for d in docs:
    kind = d.get("kind")
    if kind not in ("Job", "Pod"):
        continue
    meta = d["metadata"]
    hook = {p.strip() for p in str((meta.get("annotations") or {}).get("helm.sh/hook", "")).split(",")}
    if not hook & phases or meta.get("namespace") not in meshed:
        continue
    pod_meta = ((d.get("spec") or {}).get("template") or {}).get("metadata") or {} if kind == "Job" else meta
    name = f"{kind} {meta['namespace']}/{meta['name']}"
    checked.append(name)
    if str((pod_meta.get("labels") or {}).get(key)) != value:
        missing.append(name)

for name in missing:
    print(f"FAIL {zone}: hook {name} runs in a meshed namespace without {key}: \"{value}\"", file=sys.stderr)
if missing:
    sys.exit(1)
print(f"ok   {zone}: {len(checked)} hook pod(s) in meshed namespaces carry {key}" +
      (f" ({', '.join(checked)})" if checked else ""))
PY
  then
    failures=$((failures + 1))
  fi
done
[ "$failures" -eq 0 ]
