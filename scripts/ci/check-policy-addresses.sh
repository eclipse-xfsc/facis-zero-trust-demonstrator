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
# CIDR, naming the zone file, the release, the policy and what it found. Only in the render of the
# connector-gateway chart (and with --edge-manifest), two hops that leave the mesh are declared as EDGE
# lines instead of failing, and only in the exact shape that chart renders: the egress-only
# CiliumNetworkPolicy annotated ztd.facis.io/connector-hop: gateway-to-peer (one /32 to the peer
# zone's entry, TCP ports, selected by service account) and the ingress-only NetworkPolicy annotated
# outside-to-entry (ipBlock sources and TCP ports only); both carry ztd.facis.io/connector-route, and
# only their address fields are excused. ZT-25 governs the mesh; these two hops are outside it.
# The component charts the
# zone render does not cover (every chart under deployment/helm/ with a ci/values.yaml, except ztd,
# zone-policy and ztd-openbao) are scanned too, rendered with ci/values.yaml and with each
# ci/<variant>-values.yaml layered on it, as scripts/ci/check-charts.sh renders them.
#
# The non-Cilium branch of the umbrella's API lane (networkPolicy.kubeApi without Cilium, an
# ipBlock; the derogation path of a zone whose CNI is not Cilium) stays in the template: this check
# proves that no shipped zone renders it. The parked ambient host-probe address renders only with
# scripts/verify-umbrella/ambient-values.yaml, which is not a zone file and so not an input here.
#
#   scripts/ci/check-policy-addresses.sh [zone-file...]
#       the zone files given, or by default the shipped ones and the CI zone file; one line per zone
#   scripts/ci/check-policy-addresses.sh --manifest <label> <rendered-file>...
#   scripts/ci/check-policy-addresses.sh --edge-manifest <label> <rendered-file>...
#       the same, as a connector-gateway render: its two edge hops may be declared
#       check rendered manifests as they stand, named <label> in the report (the test uses it)
#
# Exit status: 0 when no policy names an undeclared address, 1 when one does or a render fails, 2 for a bad
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
import ipaddress, os, re, sys, yaml
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
def hop_of(d):
    return ((d.get("metadata") or {}).get("annotations") or {}).get("ztd.facis.io/connector-hop")
def edge_fields(d):
    """The address findings a Connector gateway edge hop may carry, and only those; empty unless this
    scan is of the connector-gateway chart's own render (EDGE_HOPS=1) and the policy has exactly the
    shape the chart renders for that hop (ZT-25 covers the mesh; these two hops leave it)."""
    if os.environ.get("EDGE_HOPS") != "1":
        return set()
    ann = (d.get("metadata") or {}).get("annotations") or {}
    spec, hop = d.get("spec") or {}, hop_of(d)
    if not ann.get("ztd.facis.io/connector-route"):
        return set()
    def one_port(p):  # one TCP port, 1-65535: zero, null or empty opens every port
        return isinstance(p, (int, str)) and not isinstance(p, bool) and re.fullmatch(r"[1-9][0-9]{0,4}", str(p)) and int(p) <= 65535
    def tcp_ports(ports):
        return isinstance(ports, list) and ports and all(
            isinstance(p, dict) and set(p) == {"port", "protocol"} and p["protocol"] == "TCP" and one_port(p["port"]) for p in ports)
    if hop == "gateway-to-peer" and d.get("kind") == "CiliumNetworkPolicy" and set(spec) == {"endpointSelector", "egress"}:
        sel, eg = spec["endpointSelector"], spec["egress"]
        if not (sel == {"matchLabels": {"io.cilium.k8s.policy.serviceaccount": (sel.get("matchLabels") or {}).get("io.cilium.k8s.policy.serviceaccount")}}
                and isinstance(eg, list) and len(eg) == 1 and set(eg[0]) == {"toCIDR", "toPorts"}):
            return set()
        cidr, tp = eg[0]["toCIDR"], eg[0]["toPorts"]
        if not (isinstance(cidr, list) and len(cidr) == 1 and str(cidr[0]).endswith("/32")
                and isinstance(tp, list) and len(tp) == 1 and set(tp[0]) == {"ports"} and tcp_ports(tp[0]["ports"])):
            return set()
        try:
            ipaddress.IPv4Network(cidr[0])
        except ValueError:
            return set()
        return {"key toCIDR at spec.egress.0.toCIDR", f"address {cidr[0]} at spec.egress.0.toCIDR.0"}
    if hop == "outside-to-entry" and d.get("kind") == "NetworkPolicy" and set(spec) == {"podSelector", "policyTypes", "ingress"}:
        ing = spec["ingress"]
        if not (spec["policyTypes"] == ["Ingress"] and isinstance(ing, list) and len(ing) == 1
                and set(ing[0]) == {"from", "ports"} and tcp_ports(ing[0]["ports"]) and ing[0]["from"]):
            return set()
        allowed = set()
        for i, src in enumerate(ing[0]["from"]):
            if not (isinstance(src, dict) and set(src) == {"ipBlock"} and set(src["ipBlock"] or {}) == {"cidr"}):
                return set()
            allowed |= {f"key ipBlock at spec.ingress.0.from.{i}.ipBlock", f"address {src['ipBlock']['cidr']} at spec.ingress.0.from.{i}.ipBlock.cidr"}
        return allowed
    return set()
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
        found = [w for w in found if w not in edge_fields(d)]
        if not found and edge_fields(d):
            print(f"EDGE {label}: {release} {name}: declared Connector edge hop {hop_of(d)}")
            continue
        for what in found:
            print(f"FAIL {label}: {release} {name}: {what}")
            bad += 1
print(f"{policies} policies")
sys.exit(1 if bad else 0)
PY
}

edge_hops=
if [ "${1:-}" = --edge-manifest ]; then shift; set -- --manifest "$@"; edge_hops=1; fi
if [ "${1:-}" = --manifest ]; then
  [ $# -ge 3 ] || { echo "usage: $0 --manifest <label> <rendered-file>..." >&2; exit 2; }
  label=$2; shift 2
  out=$(EDGE_HOPS=$edge_hops scan "$label" "$@"); rc=$?
  grep -E '^(FAIL|EDGE)' <<<"$out"
  [ $rc -eq 0 ] && echo "$label: $(tail -1 <<<"$out"), no undeclared address"
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
  out=$(EDGE_HOPS= scan "$label" "${render_files[@]}"); rc=$?
  grep -E '^(FAIL|EDGE)' <<<"$out"
  if [ $rc -eq 0 ]; then
    echo "$label (mesh.mode $render_mode): $(tail -1 <<<"$out") rendered by $render_releases, no undeclared address"
  else
    failures=$((failures + 1))
  fi
done
# The component charts (only in the default run: zone files given name zones only).
if [ $# -eq 0 ]; then
  for chart in "$root"/deployment/helm/*/; do
    chart=${chart%/}; name=$(basename "$chart")
    case $name in ztd|zone-policy|ztd-openbao) continue;; esac
    [ -f "$chart/ci/values.yaml" ] || continue
    for variant in "" "$chart"/ci/*-values.yaml; do
      [ -z "$variant" ] || [ -f "$variant" ] || continue
      label=${chart#"$root"/}${variant:+ (ci/$(basename "$variant"))}
      file=$work/chart-$name-$(basename "${variant:-values.yaml}")
      if ! helm template "$name" "$chart" -f "$chart/ci/values.yaml" ${variant:+-f "$variant"} >"$file" 2>"$file.err"; then
        echo "FAIL $label: render failed: $(head -1 "$file.err")"
        failures=$((failures + 1)); continue
      fi
      out=$(EDGE_HOPS=$([ "$name" = connector-gateway ] && echo 1) scan "$label" "$file"); rc=$?
      grep -E '^(FAIL|EDGE)' <<<"$out"
      if [ $rc -eq 0 ]; then echo "$label: $(tail -1 <<<"$out"), no undeclared address"; else failures=$((failures + 1)); fi
    done
  done
fi
if [ "$failures" -gt 0 ]; then
  echo "$failures zone file(s) or chart rendering(s) render a policy that names an address" >&2
  exit 1
fi
echo "no policy of any zone or component chart names an undeclared address"
