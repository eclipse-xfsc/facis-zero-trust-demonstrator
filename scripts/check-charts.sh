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
  # not semantic versioning stops before it names a package.
  if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
    echo "FAIL  version '$version' is not semantic versioning (X.Y.Z[-prerelease][+build])" >&2
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

mkdir -p "$package_dir"
for dir in ${release[@]+"${release[@]}"}; do
  helm package "$dir" --version "$version" --app-version "$version" --destination "$package_dir"
done

# One checksum file beside the packages, so a downloaded chart can be checked against the
# release before it is installed.
(
  cd "$package_dir"
  if command -v sha256sum >/dev/null; then sha256sum ./*.tgz; else shasum -a 256 ./*.tgz; fi
) | sed 's| \./| |' > "$package_dir/SHA256SUMS"

echo "OK    ${#release[@]} chart(s) packaged into $package_dir at version $version"
