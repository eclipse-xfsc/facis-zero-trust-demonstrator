# shellcheck shell=bash
# The zone's recorded Cilium version against the running one, for the mesh identity proof
# (scripts/verify-mesh-identity/verify.sh, section 0, after "Cilium is the CNI"). Sourced, never run.
# Reads nothing from the cluster: the caller passes the image and the zone file. Needs python3 with
# PyYAML.
#
#   cilium_image_version <image>
#       the version of a Cilium image reference: its tag, without any digest and without a leading v
#       (quay.io/cilium/cilium:v1.19.6@sha256:... -> 1.19.6); empty when the reference has no tag
#   cilium_zone_version <chart values> <zone file>
#       the zone's cni.cilium.version, or nothing when the zone does not enable Cilium
#       (cni.cilium.enabled, the chart's default when the zone file does not set it); status 2 when
#       the zone enables Cilium and records no version
#   cilium_version_matches <recorded> <image>
#       status 0 when the image's version equals the recorded one; prints the detail of the check,
#       naming both versions, and on a difference the step that follows it

cilium_image_version() {
  local ref=${1%%@*} tag
  tag=${ref##*/}
  case $tag in *:*) tag=${tag##*:};; *) return 0;; esac
  printf '%s\n' "${tag#v}"
}

cilium_zone_version() {
  python3 - "$1" "$2" <<'PY'
import sys, yaml
def cilium(path):
    v = (yaml.safe_load(open(path)) or {}).get("cni") or {}
    return v.get("cilium") or {}
chart, zone = cilium(sys.argv[1]), cilium(sys.argv[2])
enabled = zone.get("enabled", chart.get("enabled", False))
if enabled is not True:
    sys.exit(0)
version = zone.get("version")
if version in (None, ""):
    sys.exit(2)
print(version)
PY
}

cilium_version_matches() {
  local recorded=$1 running
  running=$(cilium_image_version "$2")
  if [ -n "$running" ] && [ "$running" = "$recorded" ]; then
    printf 'zone file %s, running %s (%s)\n' "$recorded" "$running" "$2"
    return 0
  fi
  printf 'zone file %s, running %s (%s): Cilium differs from the version the zone is verified against; update cni.cilium.version in the zone file, then re-run this proof, whose section 11 (default-deny-with-chained-cni) is the re-check of the CNI chain\n' \
    "${recorded:-none}" "${running:-unread}" "$2"
  return 1
}
