#!/usr/bin/env bash
# Cases for check-charts.sh against charts written here (plan: a set that lints and renders is
# packaged at the version with matching checksums, a pre-release version included; a chart that
# fails the render, or lint, is refused; one failing chart refuses the whole set, at the source and
# once packaged at the release version; a failing chart fails the check with no package asked for;
# a version that is not semantic versioning - build metadata, leading zeros, empty identifiers - or
# a package directory without a version, is refused before anything is checked).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
shopt -s nullglob

command -v helm >/dev/null || { echo 'helm is not on PATH - the cases need it' >&2; exit 1; }

chart() { # name Chart.yaml template
  mkdir -p "$work/$1/templates"
  printf '%s\n' "$2" > "$work/$1/Chart.yaml"
  printf '%s\n' "$3" > "$work/$1/templates/resource.yaml"
}
configmap='apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}
data:
  key: value'
chart good-a $'apiVersion: v2\nname: good-a\nversion: 0.1.0' "$configmap"
chart good-b $'apiVersion: v2\nname: good-b\nversion: 0.1.0' "$configmap"
chart no-render $'apiVersion: v2\nname: no-render\nversion: 0.1.0' '{{ .Values.missing.key }}'
chart no-lint $'apiVersion: v2\nversion: 0.1.0' "$configmap"
# Renders at its Chart.yaml version and at no other, so only the check of the package catches it.
bound="{{- if ne .Chart.Version \"0.1.0\" }}{{ fail \"renders at 0.1.0 only\" }}{{ end }}
$configmap"
chart version-bound $'apiVersion: v2\nname: version-bound\nversion: 0.1.0' "$bound"
# Variants: ci/<variant>-values.yaml on top of ci/values.yaml, and a variant's post-renderer plugin.
plugin() { # name exit-status
  mkdir -p "$work/plugin-$1"
  # shellcheck disable=SC2016 # ${HELM_PLUGIN_DIR} is Helm's, expanded when it runs the plugin
  printf 'apiVersion: v1\ntype: postrenderer/v1\nname: %s\nversion: 0.1.0\nruntime: subprocess\nruntimeConfig:\n  platformCommand:\n    - command: ${HELM_PLUGIN_DIR}/render.sh\n' "$1" > "$work/plugin-$1/plugin.yaml"
  printf '#!/bin/sh\ncat\nexit %s\n' "$2" > "$work/plugin-$1/render.sh"
  chmod +x "$work/plugin-$1/render.sh"
}
plugin passes 0
plugin refuses 1
variant='{{- if .Values.broken }}{{ fail "the variant does not render" }}{{ end }}
'"$configmap"
variant_chart() { # name variant-values [post-renderer plugin]
  chart "$1" "apiVersion: v2"$'\n'"name: $1"$'\n'"version: 0.1.0" "$variant"
  mkdir -p "$work/$1/ci"
  echo '{}' > "$work/$1/ci/values.yaml"
  printf '%s\n' "$2" > "$work/$1/ci/extra-values.yaml"
  [ -z "${3:-}" ] || echo "$work/plugin-$3" > "$work/$1/ci/extra-post-renderer"
}
variant_chart variant-good 'broken: false'
variant_chart variant-broken 'broken: true'
variant_chart variant-rendered 'broken: false' passes
variant_chart variant-render-refused 'broken: false' refuses

out="$work/out"
failures=0
fail() { # name detail
  echo "FAIL  $1 ($2)"
  sed 's/^/        /' "$work/log"
  failures=$((failures + 1))
}
expect() { # name want-exit want-packages check-charts-argument...
  local name=$1 want=$2 packages=$3 got
  local -a built
  shift 3
  rm -rf "$out"
  if "$here/check-charts.sh" "$@" >"$work/log" 2>&1; then got=0; else got=$?; fi
  built=("$out"/*.tgz)
  if [ "$got" = "$want" ] && [ "${#built[@]}" = "$packages" ]; then
    echo "ok    $name"
  else
    fail "$name" "exit $got with ${#built[@]} package(s), want exit $want with $packages"
  fi
}
check() { # name command...
  local name=$1
  shift
  if "$@" >"$work/log" 2>&1; then echo "ok    $name"; else fail "$name" "the check did not hold"; fi
}
checksums() (
  cd "$out"
  if command -v sha256sum >/dev/null; then sha256sum -c SHA256SUMS; else shasum -a 256 -c SHA256SUMS; fi
)
version_inside() { # package version
  local metadata
  metadata=$(helm show chart "$1")
  grep -qx "version: $2" <<<"$metadata"
}

expect "a set that lints and renders is packaged" 0 2 --package "$out" --version 1.2.3 "$work/good-a" "$work/good-b"
check "the packages are named for the version" test -f "$out/good-a-1.2.3.tgz" -a -f "$out/good-b-1.2.3.tgz"
check "the chart inside carries the version" version_inside "$out/good-a-1.2.3.tgz" 1.2.3
check "the checksums match the packages" checksums
expect "a chart whose template does not render is refused" 1 0 --package "$out" --version 1.2.3 "$work/no-render"
expect "a chart that fails lint is refused" 1 0 --package "$out" --version 1.2.3 "$work/no-lint"
expect "one failing chart refuses the whole set" 1 0 --package "$out" --version 1.2.3 "$work/good-a" "$work/no-render"
expect "a failing chart fails the check with no package asked for" 1 0 "$work/no-render"
expect "a pre-release version is accepted" 0 2 --package "$out" --version 1.2.3-rc.1 "$work/good-a" "$work/good-b"
expect "a chart that renders only at its source version is refused once packaged, and the set with it" 1 0 --package "$out" --version 1.2.3 "$work/good-a" "$work/version-bound"
expect "a version that is not semantic versioning is refused" 2 0 --package "$out" --version v1 "$work/good-a"
expect "a version with build metadata is refused" 2 0 --package "$out" --version 1.2.3+build.7 "$work/good-a"
expect "a version with a leading zero is refused" 2 0 --package "$out" --version 01.2.3 "$work/good-a"
expect "a pre-release identifier with a leading zero is refused" 2 0 --package "$out" --version 1.2.3-01 "$work/good-a"
expect "a pre-release with an empty identifier is refused" 2 0 --package "$out" --version 1.2.3-alpha..1 "$work/good-a"
expect "a package directory without a version is refused" 2 0 --package "$out" "$work/good-a"
expect "a chart whose variants render is packaged" 0 1 --package "$out" --version 1.2.3 "$work/variant-good"
expect "a variant that does not render refuses the chart" 1 0 --package "$out" --version 1.2.3 "$work/variant-broken"
expect "a variant rendered through its post-renderer is packaged" 0 1 --package "$out" --version 1.2.3 "$work/variant-rendered"
expect "a variant whose post-renderer refuses refuses the chart" 1 0 --package "$out" --version 1.2.3 "$work/variant-render-refused"
cp "$work/log" "$work/refused.log"
# shellcheck disable=SC2016 # the script's own $1
check "the post-renderer runs for the variant only, not the base" sh -c \
  'grep -q "variant extra (post-renderer refuses)" "$1" && [ "$(grep -c "^  ok    helm template" "$1")" -eq 1 ]' _ "$work/refused.log"
[ "$failures" -eq 0 ]
