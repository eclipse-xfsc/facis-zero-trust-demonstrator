#!/usr/bin/env bash
# No address in a policy (ZT-25: the policies that govern interactions in the mesh MUST NOT use an
# IP address). Renders the umbrella (deployment/helm/ztd) with every shipped zone file under
# deployment/helm/ztd/zones/ (the example excepted) and with the CI zone file
# deployment/helm/ztd/ci/values.yaml, and, for each of those whose mesh.mode is sidecar (absent
# counts as sidecar, the umbrella's default), zone-policy and ztd-openbao through
# scripts/install-zone/install.sh render with the zone facts. A zone without a mesh (ionos.yaml,
# mesh.mode none) has no mesh policies and is checked through the umbrella alone; the installer
# refuses any other mode before it renders. Then fails when any NetworkPolicy, CiliumNetworkPolicy,
# CiliumClusterwideNetworkPolicy or AuthorizationPolicy document carries a key ipBlock, ipBlocks,
# remoteIpBlocks, toCIDR, toCIDRSet, fromCIDR or fromCIDRSet, or a string holding an IPv4 or IPv6
# address or a CIDR, naming the zone file, the release, the policy and what it found.
#
# The non-Cilium branch of the umbrella's API lane (networkPolicy.kubeApi without Cilium, an
# ipBlock; the derogation path of a zone whose CNI is not Cilium) stays in the template: this check
# proves that no shipped zone renders it. The parked ambient host-probe address renders only with
# scripts/verify-umbrella/ambient-values.yaml, which is not a zone file and so not an input here.
#
#   scripts/ci/check-policy-addresses.sh [zone-file...]
#       the zone files given, or by default the shipped ones and the CI zone file; one line per zone
#   scripts/ci/check-policy-addresses.sh --manifest <label> <rendered-file>...
#       check rendered manifests as they stand, named <label> in the report (the test uses it)
#
# Exit status: 0 when no policy names an address, 1 when one does or a render fails, 2 for a bad
# argument. Needs helm, python3 with PyYAML, and what scripts/install-zone/install.sh needs.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
umbrella=$root/deployment/helm/ztd
# shellcheck source=scripts/ci/render-zones.sh
. "$root/scripts/ci/render-zones.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# scan <label> <file>...: the policies of the rendered files; one FAIL line per finding on stdout,
# then a summary line "<n> policies" on the last line; exit 1 when anything was found.
scan() {
  python3 - "$@" <<'PY'
import ipaddress, re, sys, yaml
label, files = sys.argv[1], sys.argv[2:]
KINDS = {"NetworkPolicy", "CiliumNetworkPolicy", "CiliumClusterwideNetworkPolicy", "AuthorizationPolicy"}
KEYS = {"ipBlock", "ipBlocks", "remoteIpBlocks", "toCIDR", "toCIDRSet", "fromCIDR", "fromCIDRSet"}
CANDIDATE = re.compile(r"[0-9A-Fa-f:.]*[.:][0-9A-Fa-f:.]*(?:/[0-9]{1,3})?")
def address(text):
    for token in CANDIDATE.findall(text):
        if token.count(".") < 3 and token.count(":") < 2:
            continue
        try:
            (ipaddress.ip_network if "/" in token else ipaddress.ip_address)(token.strip(".:") if "/" not in token else token)
            return token
        except ValueError:
            continue
    return None
def walk(node, path, found):
    if isinstance(node, dict):
        for k, v in node.items():
            if k in KEYS:
                found.append(f"key {k} at {path}{k}")
            if isinstance(k, str) and address(k):
                found.append(f"address {address(k)} in the key {path}{k}")
            walk(v, f"{path}{k}.", found)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            walk(v, f"{path}{i}.", found)
    elif isinstance(node, str):
        a = address(node)
        if a:
            found.append(f"address {a} at {path.rstrip('.')}")
policies, bad = 0, 0
for f in files:
    release = f.rsplit("/", 1)[-1].removesuffix(".yaml")
    try:
        docs = list(yaml.safe_load_all(open(f)))
    except (OSError, yaml.YAMLError) as e:
        print(f"FAIL {label}: {release}: the rendering cannot be read: {e}")
        bad += 1
        continue
    for d in docs:
        if not isinstance(d, dict) or d.get("kind") not in KINDS:
            continue
        policies += 1
        meta = d.get("metadata") or {}
        name = f"{d['kind']} {meta.get('namespace', '<cluster>')}/{meta.get('name')}"
        found = []
        walk(d, "", found)
        for what in found:
            print(f"FAIL {label}: {release} {name}: {what}")
            bad += 1
print(f"{policies} policies")
sys.exit(1 if bad else 0)
PY
}

if [ "${1:-}" = --manifest ]; then
  [ $# -ge 3 ] || { echo "usage: $0 --manifest <label> <rendered-file>..." >&2; exit 2; }
  label=$2; shift 2
  out=$(scan "$label" "$@"); rc=$?
  grep '^FAIL' <<<"$out"
  [ $rc -eq 0 ] && echo "$label: $(tail -1 <<<"$out"), no address"
  exit $rc
fi
case ${1:-} in -*) echo "unknown option: $1" >&2; exit 2;; esac

zones=("$@")
[ ${#zones[@]} -gt 0 ] || mapfile -t zones < <(default_zones "$umbrella")

failures=0
for zone in "${zones[@]}"; do
  label=${zone#"$root"/}
  [ -f "$zone" ] || { echo "FAIL $label: no such zone file"; failures=$((failures + 1)); continue; }
  if ! render_zone "$root" "$zone" "$work/$(printf '%s' "$label" | tr '/' '_')"; then
    echo "FAIL $label: $render_error"
    failures=$((failures + 1)); continue
  fi
  out=$(scan "$label" "${render_files[@]}"); rc=$?
  grep '^FAIL' <<<"$out"
  if [ $rc -eq 0 ]; then
    echo "$label (mesh.mode $render_mode): $(tail -1 <<<"$out") rendered by $render_releases, no address"
  else
    failures=$((failures + 1))
  fi
done
if [ "$failures" -gt 0 ]; then
  echo "$failures zone file(s) render a policy that names an address" >&2
  exit 1
fi
echo "no policy of any zone names an address"
