#!/usr/bin/env bash
# The tenant releases of a zone file as the zone installer renders them (ZT-53): zone A's file
# with tenants.guard.install turned on renders, per tenant, ztd-tenant-<name> and ztd-guard-<name> in
# tenant mode - target tenant <name>, its policy's only member that tenant's Participant, the other
# tenant's Participant admitted to the guard alone - and with it off renders no tenant guard.
#
#   scripts/install-zone/tenants_test.sh [zone file]   default deployment/helm/ztd/zones/zone-a.yaml
#
# Needs helm and python3 with PyYAML. Exit status: the number of failed checks.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
zone=${1:-$root/deployment/helm/ztd/zones/zone-a.yaml}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0

python3 - "$zone" "$work/on.yaml" <<'PY'
import sys, yaml
z = yaml.safe_load(open(sys.argv[1]))
z["tenants"]["guard"]["install"] = True
yaml.safe_dump(z, open(sys.argv[2], "w"), sort_keys=False)
PY
tenants=$(python3 -c 'import sys,yaml; print(" ".join(yaml.safe_load(open(sys.argv[1]))["tenants"]["names"]))' "$zone")
releases=""
for t in $tenants; do releases="$releases ztd-tenant-$t ztd-guard-$t"; done
# shellcheck disable=SC2086 # one word per release
ZONE_VALUES="$work/on.yaml" RENDER_DIR="$work/on" KUBE_CONTEXT=none "$root/scripts/install-zone/install.sh" render ztd $releases > "$work/on.log" 2>&1 \
  || { grep -v 'symbolic link' "$work/on.log" | tail -5; echo "FAIL  render with tenants.guard.install"; exit 1; }

python3 - "$work/on" "$tenants" <<'PY' || failures=$((failures + 1))
import json, sys, yaml
d, tenants = sys.argv[1], sys.argv[2].split()
docs = lambda f: [x for x in yaml.safe_load_all(open(f"{d}/{f}.yaml")) if x]
td = yaml.safe_load(open(f"{d}/ztd-guard-{tenants[0]}.values.yaml"))["trustDomain"]
participant = lambda t: f"spiffe://{td}/ns/{t}/sa/ztd-participant"
ns = {x["metadata"]["name"]: x["metadata"]["labels"] for x in docs("ztd") if x["kind"] == "Namespace"}
for t in tenants:
    others = [o for o in tenants if o != t]
    assert ns[t]["ztd.facis.io/plane"] == "data", f"{t}: not a data-plane namespace"
    guard = {x["metadata"]["name"]: x for x in docs(f"ztd-guard-{t}")}
    g = json.loads(guard["ztd-guard-config"]["data"]["config.json"])
    p = json.loads(guard["ztd-policy-config"]["data"]["config.json"])
    assert g["target_tenant"] == t, g
    assert g["published_base_url"] == f"http://ztd-guard.{t}:8080" and g["scope_tenants"] == {"report:read": f"{t}-read", "report:summary": f"{t}-summary"}, g
    assert sorted(g["allowed_callers"]) == sorted(participant(x) for x in [t] + others), g["allowed_callers"]
    assert p["tenant_members"] == {t: [participant(t)]}, p["tenant_members"]
    assert sorted(p["participant_callers"]) == sorted(g["allowed_callers"]), p
    ap = guard["ztd-guard-caller"]["spec"]["rules"][0]["from"][0]["source"]["principals"]
    assert sorted(ap) == sorted(participant(x)[len("spiffe://"):] for x in [t] + others), ap
    members = {x["metadata"]["name"]: x for x in docs(f"ztd-tenant-{t}")}["tenant-data-members"]["spec"]["rules"][0]["from"][0]["source"]["principals"]
    assert members == [participant(t)[len("spiffe://"):]], members
    tenant_values = yaml.safe_load(open(f"{d}/ztd-tenant-{t}.values.yaml"))
    assert tenant_values["guardNamespaces"] == others, tenant_values
    print(f"PASS  {t}: ztd-tenant-{t} and ztd-guard-{t} (target tenant {t}, member {participant(t)} of the guard and the data service, {', '.join(others)} admitted to the guard only)")
PY

ZONE_VALUES="$zone" KUBE_CONTEXT=none "$root/scripts/install-zone/install.sh" plan > "$work/off.log" 2>&1 || true
if grep -q 'ztd-guard-tenant' "$work/off.log"; then
  echo "FAIL  tenants.guard.install off still plans a tenant guard"; failures=$((failures + 1))
elif grep -q 'ztd-tenant-' "$work/off.log"; then
  echo "PASS  tenants.guard.install off: tenant releases planned, no tenant guard"
else
  echo "FAIL  the plan lists no tenant release: $(tail -3 "$work/off.log")"; failures=$((failures + 1))
fi
exit "$failures"
