#!/usr/bin/env bash
# Cases for check-policy-addresses.sh: an ipBlock planted in a rendering it is given fails the check,
# naming the policy; a zone file that turns the API lane on without Cilium (the derogation branch of
# the umbrella, an ipBlock to the API server's address) is reported, naming the zone file and the
# policy; the committed zone files pass. Every input is written to a temporary directory.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
check=$here/check-policy-addresses.sh
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

command -v helm >/dev/null || { echo 'helm is not on PATH - the cases need it' >&2; exit 1; }
python3 -c 'import yaml' 2>/dev/null || { echo 'python3 needs PyYAML - the cases need it' >&2; exit 1; }

failures=0
fail() { # case detail
  echo "FAIL  $1 ($2)"
  sed 's/^/        /' "$work/log"
  failures=$((failures + 1))
}
# expect <case> <want-exit> <grep pattern the output must hold> <check argument...>
expect() {
  local name=$1 want=$2 pattern=$3 got
  shift 3
  if "$check" "$@" >"$work/log" 2>&1; then got=0; else got=$?; fi
  if [ "$got" != "$want" ]; then fail "$name" "exit $got, want $want"
  elif ! grep -qE -- "$pattern" "$work/log"; then fail "$name" "the output does not match /$pattern/"
  else echo "ok    $name"; fi
}

# 1. A planted ipBlock: the CI zone's umbrella rendering with one ingress rule of the matrix lane
#    pdp-adapter-to-tsa widened to an address block.
helm template ztd "$root/deployment/helm/ztd" -n ztd-system -f "$root/deployment/helm/ztd/ci/values.yaml" >"$work/clean.yaml"
python3 - "$work/clean.yaml" "$work/ztd.yaml" <<'PY'
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
planted = False
for d in docs:
    if d.get("kind") == "NetworkPolicy" and d["metadata"]["name"] == "allow-pdp-adapter-to-tsa-ingress":
        d["spec"]["ingress"][0]["from"].append({"ipBlock": {"cidr": "10.0.0.0/8"}})
        planted = True
if not planted:
    sys.exit("the test found no allow-pdp-adapter-to-tsa-ingress to plant an ipBlock in")
yaml.safe_dump_all(docs, open(sys.argv[2], "w"), sort_keys=False)
PY
expect "a planted ipBlock fails, naming the policy" 1 \
  'FAIL planted: ztd NetworkPolicy ztd-mgmt/allow-pdp-adapter-to-tsa-ingress: key ipBlock' \
  --manifest planted "$work/ztd.yaml"
expect "the same rendering without it passes" 0 'planted: [0-9]+ policies, no address' \
  --manifest planted "$work/clean.yaml"

# 2. The derogation branch: the API lane on, Cilium off (and so no mesh, which the umbrella refuses
#    without Cilium). The umbrella renders the ipBlock lane and the check reports it.
python3 - "$root/deployment/helm/ztd/ci/values.yaml" "$work/derogated.yaml" <<'PY'
import sys, yaml
zone = yaml.safe_load(open(sys.argv[1]))
zone.setdefault("cni", {}).setdefault("cilium", {})["enabled"] = False
zone.setdefault("mesh", {})["mode"] = "none"
api = zone.setdefault("networkPolicy", {}).setdefault("kubeApi", {})
api["enabled"] = True
api["cidrs"] = ["172.18.0.0/16"]
for opening in ("meshControlPlane", "controlPlaneWebhooks", "identityServer"):
    zone["networkPolicy"].setdefault(opening, {})["enabled"] = False
yaml.safe_dump(zone, open(sys.argv[2], "w"), sort_keys=False)
PY
expect "a zone with the API lane and no Cilium is reported" 1 \
  "FAIL $work/derogated.yaml: ztd NetworkPolicy [a-z-]+/allow-kube-api-egress: key ipBlock" \
  "$work/derogated.yaml"

# 3. The committed zone files and the CI zone file.
expect "every committed zone file passes" 0 'no policy of any zone names an address'

if [ "$failures" -ne 0 ]; then
  echo "$failures case(s) failed"
  exit 1
fi
echo "every case passed"
