#!/usr/bin/env bash
# Unit tests of the alert rules and of the detection budget, without a cluster (CI):
#   1. renders the demonstrator role of deployment/helm/ztd/zones/ionos.yaml (with a documentation
#      address as the zones' egress range) with
#      scripts/install-zone/install.sh, takes the alert rules out of the prometheus release, and runs
#      `promtool test rules` with alert-rules.test.yaml (promtool from the pinned PROMETHEUS_IMAGE, run
#      with docker, or a promtool on PATH);
#   2. checks that the rendered intervals are the ones the detection budget states
#      (docs/troubleshooting.md, docs/adr/0012-central-observability-backends.md): scrapes and the
#      revocation probe every 5 s, collector batches of 1 s, rule evaluation every 5 s, for: 10s (the
#      silent-zone rules: a 15 s window and for: 5s), Alertmanager group_wait 2 s, and that the
#      worst-case sums stay below 30 s.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
# shellcheck source=../tools/pins.env disable=SC1091
. "$repo/scripts/tools/pins.env"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# ionos.yaml with a documentation address (TEST-NET-3) as the zones' egress range, which the installer
# requires before it renders the demonstrator role of a cluster with a LoadBalancer.
python3 - "$repo/deployment/helm/ztd/zones/ionos.yaml" "$work/ionos.yaml" <<'PY'
import sys, yaml
z = yaml.safe_load(open(sys.argv[1]))
z["observabilityBackends"]["entry"]["sourceRanges"] = ["203.0.113.0/24"]
yaml.safe_dump(z, open(sys.argv[2], "w"))
PY
RENDER_DIR="$work/demonstrator" ZONE_VALUES="$work/ionos.yaml" \
  "$repo/scripts/install-zone/install.sh" render prometheus alertmanager >/dev/null 2>&1 \
  || { echo "the demonstrator releases do not render" >&2; exit 1; }
RENDER_DIR="$work/zone" ZONE_VALUES="$repo/deployment/helm/ztd/ci/values.yaml" \
  "$repo/scripts/install-zone/install.sh" render otel-node otel-gateway >/dev/null 2>&1 \
  || { echo "the zone's telemetry releases do not render" >&2; exit 1; }
python3 - "$work" <<'PY'
import sys, yaml
work = sys.argv[1]
def docs(path): return [d for d in yaml.safe_load_all(open(path)) if d]
def cm(path, key):
    for d in docs(path):
        if d.get("kind") == "ConfigMap" and key in (d.get("data") or {}):
            return yaml.safe_load(d["data"][key])
    sys.exit(f"{path}: no ConfigMap with {key}")
rules = cm(f"{work}/demonstrator/prometheus.yaml", "alerting_rules.yml")
open(f"{work}/rules.yml", "w").write(yaml.safe_dump(rules))
prom = cm(f"{work}/demonstrator/prometheus.yaml", "prometheus.yml")
am = cm(f"{work}/demonstrator/alertmanager.yaml", "alertmanager.yml")
node = cm(f"{work}/zone/otel-node.yaml", "relay")
gw = cm(f"{work}/zone/otel-gateway.yaml", "relay")
bad = []
def expect(what, got, want):
    if str(got) != str(want): bad.append(f"{what} is {got!r}, the budget states {want!r}")
expect("Prometheus evaluation_interval", prom["global"]["evaluation_interval"], "5s")
for g in rules["groups"]:
    expect(f"rule group {g['name']} interval", g.get("interval"), "5s")
    for r in g["rules"]:
        if "alert" in r:
            expect(f"for of {r['alert']}", r.get("for"), "5s" if r["alert"] == "ZoneSilent" else "10s")
silent = [r for g in rules["groups"] for r in g["rules"] if r.get("alert") == "ZoneSilent"]
if sorted(r["labels"]["zone"] for r in silent) != ["zone-a", "zone-b"]:
    bad.append("one silent-zone rule per zone of ionos.yaml is expected")
if any("[15s]" not in r["expr"] for r in silent): bad.append("the silent-zone window is not 15 s")
expect("Alertmanager group_wait", am["route"]["group_wait"], "2s")
for name, c in (("otel-node", node), ("otel-gateway", gw)):
    for job in c["receivers"]["prometheus"]["config"]["scrape_configs"]:
        expect(f"{name} scrape {job['job_name']}", job["scrape_interval"], "5s")
    expect(f"{name} batch timeout", c["processors"]["batch"]["timeout"], "1s")
expect("revocation probe interval", gw["receivers"]["http_check/revocation"]["collection_interval"], "5s")
expect("k8s_cluster interval", gw["receivers"]["k8s_cluster"]["collection_interval"], "5s")
# Worst cases (seconds): a missing target: scrape 5 + batch 1 + export 2 + evaluation 5 + for 10 +
# group_wait 2; a silent zone or a vanished agent: window 15 (10) + for 5 (10) + evaluation 5 +
# group_wait 2; the probe: interval 5 + batch 1 + export 2 + evaluation 5 + for 10 + group_wait 2.
budgets = {"missing target": 5 + 1 + 2 + 5 + 10 + 2, "silent zone": 15 + 5 + 5 + 2,
           "vanished agent": 10 + 10 + 5 + 2, "revocation probe": 5 + 1 + 2 + 5 + 10 + 2}
for k, v in budgets.items():
    if v >= 30: bad.append(f"the worst case of {k} is {v} s, not below 30 s")
if bad: sys.exit("detection budget: " + "; ".join(bad))
print("detection budget: rendered intervals match; worst cases " + ", ".join(f"{k} {v} s" for k, v in budgets.items()))
PY
cp "$here/alert-rules.test.yaml" "$work/"
if command -v promtool >/dev/null; then
  (cd "$work" && promtool test rules alert-rules.test.yaml)
else
  chmod -R a+rX "$work"   # the image runs as nobody
  docker run --rm --entrypoint promtool -v "$work:/w:ro" -w /w "$PROMETHEUS_IMAGE" test rules alert-rules.test.yaml
fi
