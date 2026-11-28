#!/usr/bin/env bash
# Unit tests of the alert rules and of the detection budget, without a cluster (CI):
#   1. renders the demonstrator role of deployment/helm/ztd/zones/ionos.yaml (with a documentation
#      address as the zones' egress range) with
#      scripts/install-zone/install.sh, takes the alert rules out of the prometheus release, and runs
#      `promtool test rules` with alert-rules.test.yaml (promtool from the pinned PROMETHEUS_IMAGE, run
#      with docker, or a promtool on PATH);
#   2. checks that the rendered intervals are the ones the detection budget states
#      (docs/troubleshooting.md, docs/adr/0017-central-observability-backends.md): scrapes and the
#      revocation probe every 5 s, the probe's request bounded to 2 s, collector batches of 1 s, rule evaluation every 5 s, for: 10s (the
#      silent-zone rules: a 15 s window and for: 5s), no alert sender in the Prometheus configuration
#      (the firing state is the alert), and that the
#      worst-case sums stay below 30 s;
#   3. checks that the alerts read only the collectors' own signals, in two layers: every selector
#      in the rules of a health metric or of a rule's own series (ztd:*) carries
#      ztd_source="collector", which the collectors stamp on their scrapes, k8s_cluster and the probe
#      and the zone gateway's OTLP pipeline (the data plane's, untrusted) overwrites with workload;
#      and that pipeline's filter drops every name the rules read, every ztd:* series and ALERTS /
#      ALERTS_FOR_STATE, in each spelling that Prometheus stores under that name (other separators,
#      leading or trailing ones, another case). The promtool tests add forged workload series,
#      recorded-series names included, that neither hide a failure nor raise an alert.
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
  "$repo/scripts/install-zone/install.sh" render prometheus >/dev/null 2>&1 \
  || { echo "the demonstrator releases do not render" >&2; exit 1; }
RENDER_DIR="$work/zone" ZONE_VALUES="$repo/deployment/helm/ztd/ci/values.yaml" \
  "$repo/scripts/install-zone/install.sh" render otel-node otel-gateway >/dev/null 2>&1 \
  || { echo "the zone's telemetry releases do not render" >&2; exit 1; }
python3 - "$work" <<'PY'
import re, sys, yaml
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
# The vanished-agent alert waits until the agent's last sample has left the reporting window: that
# window is the first term of its budget, so every window of the reporting rule must be 10 s.
reporting = [r for g in rules["groups"] for r in g["rules"] if r.get("record") == "ztd:spire_agents_reporting:count"]
windows = sorted(set(re.findall(r"\[(\d+s)\]", reporting[0]["expr"]))) if reporting else []
if windows != ["10s"]: bad.append(f"the agents' reporting window is {windows or 'missing'}, the budget states 10 s")
if "alerting" in prom: bad.append("the Prometheus configuration has an alerting block; the firing state of a rule is the alert")
for name, c in (("otel-node", node), ("otel-gateway", gw)):
    for job in c["receivers"]["prometheus"]["config"]["scrape_configs"]:
        expect(f"{name} scrape {job['job_name']}", job["scrape_interval"], "5s")
    expect(f"{name} batch timeout", c["processors"]["batch"]["timeout"], "1s")
expect("revocation probe interval", gw["receivers"]["http_check/revocation"]["collection_interval"], "5s")
probes = gw["receivers"]["http_check/revocation"]["targets"]
for t in probes: expect(f"revocation probe timeout of {t.get('endpoint') or 'the target'}", t.get("timeout"), "2s")
expect("k8s_cluster interval", gw["receivers"]["k8s_cluster"]["collection_interval"], "5s")
# Worst cases (seconds), with no routing stage: a missing target: scrape 5 + batch 1 + export 2 +
# evaluation 5 + for 10; a silent zone: window 15 + evaluation 5 + for 5; a vanished agent: reporting
# window 10 + evaluation 5 + for 10; the probe: interval 5 + timeout 2 + batch 1 + export 2 +
# evaluation 5 + for 10.
budgets = {"missing target": 5 + 1 + 2 + 5 + 10, "silent zone": 15 + 5 + 5,
           "vanished agent": 10 + 5 + 10, "revocation probe": 5 + 2 + 1 + 2 + 5 + 10}
for k, v in budgets.items():
    if v >= 30: bad.append(f"the worst case of {k} is {v} s, not below 30 s")
if bad: sys.exit("detection budget: " + "; ".join(bad))
# The alerts read only the collectors' own signals.
trust = []
health = r"(?:up|k8s_[a-z_]+|httpcheck_[a-z_]+|otelcol_[a-z_]+|ztd:[a-z_]+:[a-z_]+)"
exprs = [r["expr"] for g in rules["groups"] for r in g["rules"]]
names = set()
for e in exprs:
    for m in re.finditer(r"(?<![\w\"])(" + health + r")\b(\{[^}]*\})?", e):
        if m.group(1) in ("by", "on"): continue
        names.add(m.group(1))
        if 'ztd_source="collector"' not in (m.group(2) or ""):
            trust.append(f"the selector {m.group(0)!r} does not require ztd_source=\"collector\"")
    for m in re.finditer(r"\{__name__=~\"(" + health + r")[^\"]*\"([^}]*)\}", e):
        names.add(m.group(1))
        if 'ztd_source="collector"' not in m.group(2):
            trust.append(f"the selector {m.group(0)!r} does not require ztd_source=\"collector\"")
if not names: trust.append("no health metric found in the rules")
# Every alert carries ztd_source="collector", so ALERTS{ztd_source="collector"} holds only the rules'.
for g in rules["groups"]:
    for r in g["rules"]:
        if "alert" in r and (r.get("labels") or {}).get("ztd_source") != "collector":
            trust.append(f"the alert {r['alert']} does not label itself ztd_source=collector")
stamp = {"key": "ztd.source", "value": "collector", "action": "upsert"}
for name, c in (("otel-node", node), ("otel-gateway", gw)):
    for pname, pl in c["service"]["pipelines"].items():
        if not pname.startswith("metrics") or not pl: continue
        if "otlp" in pl["receivers"]:
            if pl["receivers"] != ["otlp"]:
                trust.append(f"{name} pipeline {pname} merges OTLP with the collector's own receivers")
            for proc in ("filter/reserved", "transform/workload"):
                if proc not in pl["processors"]: trust.append(f"{name} pipeline {pname} lacks {proc}")
        elif not any(stamp in (c["processors"].get(p, {}).get("attributes") or []) for p in pl["processors"]):
            trust.append(f"{name} pipeline {pname} does not stamp ztd.source=collector")
cond = " ".join(gw["processors"]["filter/reserved"]["metrics"]["metric"])
patterns = re.findall(r'IsMatch\(name, "([^"]+)"\)', cond)
recorded = {r["record"] for g in rules["groups"] for r in g["rules"] if "record" in r}
reserved = sorted(names | recorded | {"ALERTS", "ALERTS_FOR_STATE"})
def dropped(form): return any(re.search(p, form) for p in patterns)
for n in reserved:
    forms = {n, n + ".", n + "-", "_" + n, "." + n, n.upper(), n.lower(), n + ":x", n + "/x"}
    for sep in (".", "-", "/", ":"):
        forms.add(n.replace("_", sep))
    for form in sorted(forms):
        if not dropped(form):
            trust.append(f"the gateway's OTLP filter lets {form!r} through, stored as {n!r}")
for form in ("uptime", "request_count", "ztdx", "ztd_proof_zone_claim"):   # unreserved names pass (the last is the proof's)
    if dropped(form): trust.append(f"the gateway's OTLP filter drops the unreserved name {form!r}")
wl = gw["processors"]["transform/workload"]["metric_statements"]
if not any('set(resource.attributes["ztd.source"], "workload")' in st for b in wl for st in b["statements"]):
    trust.append("the gateway's OTLP pipeline does not set ztd.source=workload")
if trust: sys.exit("trusted signals: " + "; ".join(trust))
print("trusted signals: the rules read " + ", ".join(sorted(names)) + " with ztd_source=\"collector\" only; OTLP is stamped workload and drops " + ", ".join(reserved) + " in every spelling")
print("detection budget: rendered intervals match; worst cases " + ", ".join(f"{k} {v} s" for k, v in budgets.items()))
PY
cp "$here/alert-rules.test.yaml" "$work/"
if command -v promtool >/dev/null; then
  (cd "$work" && promtool test rules alert-rules.test.yaml)
else
  chmod -R a+rX "$work"   # the image runs as nobody
  docker run --rm --entrypoint promtool -v "$work:/w:ro" -w /w "$PROMETHEUS_IMAGE" test rules alert-rules.test.yaml
fi
