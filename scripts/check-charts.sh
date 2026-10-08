#!/usr/bin/env bash
#
# Lints and dry-run renders every chart and, only once all of them pass, packages the release
# charts. Check and package are one script so the pull-request gate and the release job cannot
# drift apart: a chart that fails lint or render in a pull request is the same chart that is refused
# a package at release.
#
# Usage:
#   scripts/check-charts.sh                                  lint and render (the CI chart job)
#   scripts/check-charts.sh --package DIR --version X.Y.Z    ...then package the release charts into DIR
#   scripts/check-charts.sh [options] CHART_DIR...           the same, on the given charts only
#
# Without chart arguments the charts under deployment/helm/ and the fixture charts under
# features/fixtures/charts/ are checked - the TDR's lint and dry-run rule applies to every chart the
# pipeline installs - and only the charts under deployment/helm/ are packaged: a fixture is never
# released. Charts named on the command line are both checked and packaged.
#
# A chart whose values have no defaults ships its valid baseline in ci/values.yaml. Every package
# carries the given version, so one release delivers one version across the set.

set -euo pipefail

package_dir=""
version=""
charts=()

while [ $# -gt 0 ]; do
  case "$1" in
    --package) package_dir="${2:?--package needs a directory}"; shift 2 ;;
    --version) version="${2:?--version needs a version}"; shift 2 ;;
    -h|--help) sed -n '3,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) charts+=("$1"); shift ;;
  esac
done

if [ -n "$package_dir" ] || [ -n "$version" ]; then
  if [ -z "$package_dir" ] || [ -z "$version" ]; then
    echo '--package and --version go together' >&2
    exit 2
  fi
  # Helm packages under any version string; the release tag is checked here so a tag that is
  # not semantic versioning stops before it names a package. Build metadata is refused: the
  # charts put their version into the helm.sh/chart label, and '+' cannot appear in a label value.
  case "$version" in
    *+*)
      echo "FAIL  version '$version' carries build metadata ('+'), which a Kubernetes label cannot hold" >&2
      exit 2 ;;
  esac
  # The SemVer 2.0.0 grammar without build metadata: no leading zeros, no empty identifiers.
  identifier='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
  semver="^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-$identifier(\.$identifier)*)?$"
  if [[ ! "$version" =~ $semver ]]; then
    echo "FAIL  version '$version' is not semantic versioning (X.Y.Z[-prerelease], no leading zeros, no empty identifiers)" >&2
    exit 2
  fi
fi

shopt -s nullglob
check=()
release=()
if [ ${#charts[@]} -gt 0 ]; then
  check=("${charts[@]}")
  release=("${charts[@]}")
else
  for chart in deployment/helm/*/Chart.yaml; do
    check+=("$(dirname "$chart")")
    release+=("$(dirname "$chart")")
  done
  for chart in features/fixtures/charts/*/Chart.yaml; do
    check+=("$(dirname "$chart")")
  done
fi

if [ ${#check[@]} -eq 0 ]; then
  echo 'No chart yet - nothing to check.'
  exit 0
fi

# An empty array expanded with "${values[@]}" is an unbound variable to bash 3.2, which macOS
# ships; ${values[@]+"${values[@]}"} expands to nothing there and to the values everywhere.
status=0
for dir in "${check[@]}"; do
  values=()
  if [ -f "$dir/ci/values.yaml" ]; then
    values=(-f "$dir/ci/values.yaml")
  fi
  if helm lint "$dir" ${values[@]+"${values[@]}"} && helm template "$dir" ${values[@]+"${values[@]}"} >/dev/null; then
    echo "OK    $dir lints and renders"
  else
    echo "FAIL  $dir does not lint or render" >&2
    status=1
  fi
done

if [ $status -ne 0 ]; then
  if [ -n "$package_dir" ]; then
    echo 'FAIL  a chart failed its gate - nothing is packaged' >&2
  fi
  exit $status
fi

[ -n "$package_dir" ] || exit 0

# Package every chart, then check each package as the source was checked: the version now differs
# from Chart.yaml, and a template that reads it renders differently. One failing package takes this
# run's packages with it, so a release is all or nothing.
mkdir -p "$package_dir"
packages=()
for dir in ${release[@]+"${release[@]}"}; do
  package=""
  if output=$(helm package "$dir" --version "$version" --app-version "$version" --destination "$package_dir" 2>&1); then
    package=$(printf '%s\n' "$output" | sed -n 's/^Successfully packaged chart and saved it to: //p')
  else
    printf '%s\n' "$output" >&2
  fi
  if [ -z "$package" ] || [ ! -f "$package" ]; then
    echo "FAIL  $dir did not package" >&2
    status=1
    continue
  fi
  packages+=("$package")
  values=()
  if [ -f "$dir/ci/values.yaml" ]; then
    values=(-f "$dir/ci/values.yaml")
  fi
  if helm lint "$package" ${values[@]+"${values[@]}"} && helm template "$package" ${values[@]+"${values[@]}"} >/dev/null; then
    echo "OK    $package lints and renders at $version"
  else
    echo "FAIL  $package does not lint or render at $version" >&2
    status=1
  fi
done

if [ $status -ne 0 ]; then
  [ ${#packages[@]} -eq 0 ] || rm -f "${packages[@]}"
  echo 'FAIL  a packaged chart failed its gate - nothing is packaged' >&2
  exit $status
fi

# One checksum file beside the packages, so a downloaded chart can be checked against the
# release before it is installed.
(
  cd "$package_dir"
  if command -v sha256sum >/dev/null; then sha256sum ./*.tgz; else shasum -a 256 ./*.tgz; fi
) | sed 's| \./| |' > "$package_dir/SHA256SUMS"

echo "OK    ${#release[@]} chart(s) packaged into $package_dir at version $version"
