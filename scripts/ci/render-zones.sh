# shellcheck shell=bash
# The render path shared by the policy checks (check-policy-addresses.sh, check-policy-l7-owner.sh):
# the zone files a check covers by default, and one zone rendered the way the zone installs it. Sourced,
# never run; needs helm, python3 with PyYAML, and what scripts/install-zone/install.sh needs.
#
#   default_zones <umbrella>      prints every shipped zone file under <umbrella>/zones/ (the example
#                                 excepted) and the CI zone file <umbrella>/ci/values.yaml, one per line
#   render_zone <root> <zone> <dir>
#                                 renders the umbrella with <zone> into <dir>/ztd.yaml and, when the
#                                 zone's mesh.mode is sidecar (absent counts as sidecar, the umbrella's
#                                 default), zone-policy and ztd-openbao through the installer's render with
#                                 the zone facts into <dir>/mesh/. Sets render_files (the rendered files),
#                                 render_releases (their names, comma-separated) and render_mode; on a
#                                 failure sets render_error (one line) and returns 1. A zone without a mesh
#                                 (ionos.yaml, mesh.mode none) is rendered through the umbrella alone; the
#                                 installer refuses any other mode before it renders.

default_zones() {
  local z
  for z in "$1"/zones/*.yaml; do
    case $(basename "$z") in *.example.yaml) continue;; esac
    printf '%s\n' "$z"
  done
  printf '%s\n' "$1/ci/values.yaml"
}

render_zone() {
  local root=$1 zone=$2 dir=$3 umbrella=$1/deployment/helm/ztd
  render_files=(); render_releases=""; render_mode=""; render_error=""
  mkdir -p "$dir"
  if ! helm template ztd "$umbrella" -n ztd-system -f "$zone" >"$dir/ztd.yaml" 2>"$dir/ztd.err"; then
    render_error="the umbrella does not render: $(grep -v '^$' "$dir/ztd.err" | head -3 | tr '\n' ' ')"
    return 1
  fi
  render_files=("$dir/ztd.yaml"); render_releases=ztd
  render_mode=$(python3 -c 'import sys,yaml
z = yaml.safe_load(open(sys.argv[1])) or {}
print((z.get("mesh") or {}).get("mode") or "sidecar")' "$zone")
  if [ "$render_mode" = sidecar ]; then
    if ! ZONE_VALUES=$zone RENDER_DIR=$dir/mesh "$root/scripts/install-zone/install.sh" render zone-policy ztd-openbao \
        >"$dir/mesh.log" 2>&1; then
      render_error="zone-policy or ztd-openbao does not render: $(grep -v '^$' "$dir/mesh.log" | tail -3 | tr '\n' ' ')"
      return 1
    fi
    render_files+=("$dir/mesh/zone-policy.yaml" "$dir/mesh/ztd-openbao.yaml"); render_releases="ztd, zone-policy, ztd-openbao"
  fi
  return 0
}
