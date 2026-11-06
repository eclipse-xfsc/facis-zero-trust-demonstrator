#!/usr/bin/env bash
# One L7 owner per path (SRS 2.3.3, Table 4: L7 policies MUST NOT be enforced by both the mesh and
# Cilium; ADR-0009, point 2: the owner is recorded per traffic path in the mesh configuration). Renders
# the umbrella (deployment/helm/ztd), and zone-policy and ztd-openbao through
# scripts/install-zone/install.sh render, with every shipped zone file under
# deployment/helm/ztd/zones/ (the example excepted) and with the CI zone file
# deployment/helm/ztd/ci/values.yaml, the same way scripts/ci/check-policy-addresses.sh does (the shared
# render path is scripts/ci/render-zones.sh). Then fails on:
#   - a CiliumNetworkPolicy or CiliumClusterwideNetworkPolicy whose spec, or any entry of its specs, carries
#     under ingress, egress, ingressDeny or egressDeny a toPorts[] field that sends the port's traffic to
#     Cilium's L7 proxy: rules.http, .kafka, .l7 or .l7proto (the L7 rule kinds of the Cilium CRDs),
#     listener, serverNames, terminatingTLS or originatingTLS (rules.dns is not L7 enforcement
#     on a meshed path and passes);
#   - a CiliumEnvoyConfig or CiliumClusterwideEnvoyConfig, in any namespace (it sends Service traffic to
#     Cilium's Envoy proxy; the charts render none);
#   - a rendered allow-matrix policy (a NetworkPolicy annotated ztd.facis.io/allow-matrix, or an
#     AuthorizationPolicy annotated ztd.facis.io/pair) without the annotation ztd.facis.io/l7-owner, or with
#     a value other than sidecar or none.
# Each finding names the zone file, the release, the policy's kind, namespace and name, and what it found.
# On success it lists every rendered allow-matrix policy with its owner.
# The zone's admission rule l7-owner-is-the-mesh (zone-policy) refuses the same fields on the cluster,
# and every Envoy configuration in a plane namespace or cluster-wide, whoever applies them; this check
# proves that the charts themselves render none.
#
#   scripts/ci/check-policy-l7-owner.sh [zone-file...]
#       the zone files given, or by default the shipped ones and the CI zone file
#   scripts/ci/check-policy-l7-owner.sh --manifest <label> <rendered-file>...
#       check rendered manifests as they stand, named <label> in the report (the test uses it)
#
# Exit status: 0 when no Cilium object sends traffic to Cilium's L7 proxy and every allow-matrix policy
# names its owner,
# 1 when one does not or a render fails, 2 for a bad argument. Needs helm, python3 with PyYAML, and what
# scripts/install-zone/install.sh needs.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
umbrella=$root/deployment/helm/ztd
# shellcheck source=scripts/ci/render-zones.sh
. "$root/scripts/ci/render-zones.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# scan <label> <file>...: one FAIL line per finding and one OWNER line per allow-matrix policy on
# stdout, then a summary line "<n> Cilium objects, <m> allow-matrix policies"; exit 1 on a finding.
scan() {
  python3 - "$@" <<'PY'
import sys, yaml
label, files = sys.argv[1], sys.argv[2:]
CILIUM = {"CiliumNetworkPolicy", "CiliumClusterwideNetworkPolicy"}
ENVOY = {"CiliumEnvoyConfig", "CiliumClusterwideEnvoyConfig"}
L7 = ("http", "kafka", "l7", "l7proto")
PROXY = ("listener", "serverNames", "terminatingTLS", "originatingTLS")
DIRECTIONS = ("ingress", "egress", "ingressDeny", "egressDeny")
OWNERS = {"sidecar", "none"}
cilium = matrix = bad = 0
for f in files:
    release = f.rsplit("/", 1)[-1].removesuffix(".yaml")
    try:
        docs = list(yaml.safe_load_all(open(f)))
    except (OSError, yaml.YAMLError) as e:
        print(f"FAIL {label}: {release}: the rendering cannot be read: {e}")
        bad += 1
        continue
    for d in docs:
        if not isinstance(d, dict):
            continue
        kind = d.get("kind")
        meta = d.get("metadata") or {}
        name = f"{kind} {meta.get('namespace', '<cluster>')}/{meta.get('name')}"
        if kind in CILIUM:
            cilium += 1
            specs = ([("spec", d["spec"])] if isinstance(d.get("spec"), dict) else []) + \
                    [(f"specs.{i}", s) for i, s in enumerate(d.get("specs") or []) if isinstance(s, dict)]
            for where, spec in specs:
                for direction in DIRECTIONS:
                    for r, rule in enumerate(spec.get(direction) or []):
                        for p, port in enumerate((rule or {}).get("toPorts") or []):
                            rules = (port or {}).get("rules") or {}
                            for k in L7:
                                if k in rules:
                                    print(f"FAIL {label}: {release} {name}: L7 rule {k} at "
                                          f"{where}.{direction}.{r}.toPorts.{p}.rules.{k}")
                                    bad += 1
                            for k in PROXY:
                                if k in (port or {}):
                                    print(f"FAIL {label}: {release} {name}: redirect to Cilium's proxy {k} at "
                                          f"{where}.{direction}.{r}.toPorts.{p}.{k}")
                                    bad += 1
        if kind in ENVOY:
            cilium += 1
            print(f"FAIL {label}: {release} {name}: an Envoy configuration of Cilium (it sends Service traffic to Cilium's proxy)")
            bad += 1
        annotations = meta.get("annotations") or {}
        if kind in ("NetworkPolicy", "AuthorizationPolicy") and (
                "ztd.facis.io/allow-matrix" in annotations or "ztd.facis.io/pair" in annotations):
            matrix += 1
            row = annotations.get("ztd.facis.io/allow-matrix") or annotations.get("ztd.facis.io/pair")
            owner = annotations.get("ztd.facis.io/l7-owner")
            if owner is None:
                print(f"FAIL {label}: {release} {name}: allow-matrix policy of {row} without the annotation ztd.facis.io/l7-owner")
                bad += 1
            elif owner not in OWNERS:
                print(f"FAIL {label}: {release} {name}: allow-matrix policy of {row} names the L7 owner {owner!r}, not sidecar or none")
                bad += 1
            else:
                print(f"OWNER {label}: {release} {name} ({row}): {owner}")
print(f"{cilium} Cilium objects, {matrix} allow-matrix policies")
sys.exit(1 if bad else 0)
PY
}

# report <label> <mode text> <file>...: prints the findings, or the owners and a summary line; status of scan
report() {
  local label=$1 what=$2 out rc
  shift 2
  out=$(scan "$label" "$@"); rc=$?
  grep '^FAIL' <<<"$out"
  if [ $rc -eq 0 ]; then
    grep '^OWNER' <<<"$out" | sed 's/^OWNER /  /'
    echo "$label$what: $(tail -1 <<<"$out"), none sends traffic to Cilium's L7 proxy, every allow-matrix policy names its L7 owner"
  fi
  return $rc
}

if [ "${1:-}" = --manifest ]; then
  [ $# -ge 3 ] || { echo "usage: $0 --manifest <label> <rendered-file>..." >&2; exit 2; }
  label=$2; shift 2
  report "$label" "" "$@"
  exit $?
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
  report "$label" " (mesh.mode $render_mode, rendered by $render_releases)" "${render_files[@]}" || failures=$((failures + 1))
done
if [ "$failures" -gt 0 ]; then
  echo "$failures zone file(s) render a Cilium object that sends traffic to Cilium's L7 proxy, or an allow-matrix policy without its L7 owner" >&2
  exit 1
fi
echo "no Cilium object of any zone sends traffic to Cilium's L7 proxy, and every allow-matrix policy names its single L7 owner"
