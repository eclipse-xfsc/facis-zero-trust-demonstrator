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
# notIpBlocks, remoteIpBlocks, notRemoteIpBlocks, toCIDR, toCIDRSet, fromCIDR or fromCIDRSet, or a
# string holding an IPv4 or IPv6 address (with or without a port: 10.0.0.1:8080, [::1]:8080) or a
# CIDR, naming the zone file, the release, the policy and what it found.
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
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# scan <label> <file>...: the policies of the rendered files; one FAIL line per finding on stdout,
# then a summary line "<n> policies" on the last line; exit 1 when anything was found.
scan() {
  python3 - "$@" <<'PY'
import ipaddress, re, sys, yaml
label, files = sys.argv[1], sys.argv[2:]
KINDS = {"NetworkPolicy", "CiliumNetworkPolicy", "CiliumClusterwideNetworkPolicy", "AuthorizationPolicy"}
KEYS = {"ipBlock", "ipBlocks", "notIpBlocks", "remoteIpBlocks", "notRemoteIpBlocks",
        "toCIDR", "toCIDRSet", "fromCIDR", "fromCIDRSet"}
# A run of address characters, optionally bracketed ([IPv6]) and followed by a port or a prefix;
# and, wherever it sits in a string (host:port, a prefix of hex letters, a URL), an IPv4 address.
CANDIDATE = re.compile(r"\[[0-9A-Fa-f:.]+\](?::[0-9]+)?|[0-9A-Fa-f:.]*[.:][0-9A-Fa-f:.]*(?:/[0-9]{1,3})?")
IPV4 = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?(?![0-9]|\.[0-9])")
def readings(token):
    """The ways a token can hold an address: bracketed IPv6 (with or without a port); a CIDR as it
    stands; otherwise without the sentence dots around it and without a lone colon at either end
    (a "::" is part of an IPv6 address and stays)."""
    if token.startswith("["):
        yield token[1:token.index("]")]
        return
    if "/" in token:
        yield token
        return
    t = token.strip(".")
    if t.startswith(":") and not t.startswith("::"):
        t = t[1:]
    if t.endswith(":") and not t.endswith("::"):
        t = t[:-1]
    yield t
def parses(t):
    try:
        ipaddress.ip_network(t, strict=False) if "/" in t else ipaddress.ip_address(t)
        return True
    except ValueError:
        return False
def address(text):
    for token in CANDIDATE.findall(text):
        if not token.startswith("[") and token.count(".") < 3 and token.count(":") < 2:
            continue
        if any(parses(t) for t in readings(token)):
            return token
    for token in IPV4.findall(text):
        if parses(token):
            return token
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
if [ ${#zones[@]} -eq 0 ]; then
  for z in "$umbrella"/zones/*.yaml; do
    case $(basename "$z") in *.example.yaml) continue;; esac
    zones+=("$z")
  done
  zones+=("$umbrella/ci/values.yaml")
fi

failures=0
for zone in "${zones[@]}"; do
  label=${zone#"$root"/}
  [ -f "$zone" ] || { echo "FAIL $label: no such zone file"; failures=$((failures + 1)); continue; }
  dir=$work/$(printf '%s' "$label" | tr '/' '_')
  mkdir -p "$dir"
  if ! helm template ztd "$umbrella" -n ztd-system -f "$zone" >"$dir/ztd.yaml" 2>"$dir/ztd.err"; then
    echo "FAIL $label: the umbrella does not render: $(grep -v '^$' "$dir/ztd.err" | head -3 | tr '\n' ' ')"
    failures=$((failures + 1)); continue
  fi
  files=("$dir/ztd.yaml"); releases=ztd
  mode=$(python3 -c 'import sys,yaml
z = yaml.safe_load(open(sys.argv[1])) or {}
print((z.get("mesh") or {}).get("mode") or "sidecar")' "$zone")
  if [ "$mode" = sidecar ]; then
    if ! ZONE_VALUES=$zone RENDER_DIR=$dir/mesh "$root/scripts/install-zone/install.sh" render zone-policy ztd-openbao \
        >"$dir/mesh.log" 2>&1; then
      echo "FAIL $label: zone-policy or ztd-openbao does not render: $(grep -v '^$' "$dir/mesh.log" | tail -3 | tr '\n' ' ')"
      failures=$((failures + 1)); continue
    fi
    files+=("$dir/mesh/zone-policy.yaml" "$dir/mesh/ztd-openbao.yaml"); releases="ztd, zone-policy, ztd-openbao"
  fi
  out=$(scan "$label" "${files[@]}"); rc=$?
  grep '^FAIL' <<<"$out"
  if [ $rc -eq 0 ]; then
    echo "$label (mesh.mode $mode): $(tail -1 <<<"$out") rendered by $releases, no address"
  else
    failures=$((failures + 1))
  fi
done
if [ "$failures" -gt 0 ]; then
  echo "$failures zone file(s) render a policy that names an address" >&2
  exit 1
fi
echo "no policy of any zone names an address"
