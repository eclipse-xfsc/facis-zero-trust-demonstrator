#!/usr/bin/env bash
# The chart quality gate (TDR-BDD-11): every chart is linted, rendered and - in release mode -
# dry-run against a real API server; when a release is packaged, each package is checked the same
# way at its release version. One script for the pull-request job, the release gate and the chart
# release, so none of them can drift apart.
#
#   scripts/ci/check-charts.sh [--server-dry-run] [--evidence DIR] [--package DIR --version X.Y.Z] [chart-dir...]
#
# Without chart directories it checks every chart under deployment/helm/ and features/fixtures/charts/
# and packages only the charts under deployment/helm/: a fixture is never released. Charts named on
# the command line are both checked and packaged. A chart's valid baseline values are its
# ci/values.yaml when it has one; a chart with dependencies is built from its committed Chart.lock
# first.
#
# --server-dry-run makes `helm install --dry-run=server` mandatory: the current kube context is used,
# and no reachable cluster is a failure, never a pass. Without it the server dry-run is recorded as
# not-run. A server dry-run renders, discovers the API and its schemas and checks existing resources;
# it does not run admission webhooks or hooks and proves nothing about the release at runtime.
#
# --evidence DIR writes one <chart>.json per chart: chart, version, and each check as
# passed | failed | not-run. Nothing rendered is printed or kept: rendered Secrets stay out of the logs.
#
# --package DIR --version X.Y.Z packages the release charts into DIR at that version, only once every
# chart has passed, then checks each package as its source was checked: the version now differs from
# Chart.yaml, and a template that reads it renders differently. One failing package removes this run's
# packages, so a release is all or nothing; a SHA256SUMS file is written beside the packages. The
# version must be semantic versioning without build metadata: the charts put it into the
# helm.sh/chart label, and '+' cannot appear in a label value.
#
# Exit status: 0 when every check that ran passed, 1 when a check failed, 2 for a bad argument.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
server=false
evidence=""
package_dir=""
release_version=""
charts=()
while [ $# -gt 0 ]; do
  case "$1" in
    --server-dry-run) server=true ;;
    --evidence) evidence="$2"; shift ;;
    --package) package_dir="$2"; shift ;;
    --version) release_version="$2"; shift ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) charts+=("${1%/}") ;;
  esac
  shift
done

if [ -n "$package_dir" ] || [ -n "$release_version" ]; then
  if [ -z "$package_dir" ] || [ -z "$release_version" ]; then
    echo '--package and --version go together' >&2
    exit 2
  fi
  # Helm packages under any version string; the release tag is checked here so a tag that is not
  # semantic versioning stops before it names a package.
  case "$release_version" in
    *+*)
      echo "FAIL version '$release_version' carries build metadata ('+'), which a Kubernetes label cannot hold" >&2
      exit 2 ;;
  esac
  # The SemVer 2.0.0 grammar without build metadata: no leading zeros, no empty identifiers.
  identifier='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
  semver="^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-$identifier(\.$identifier)*)?$"
  if [[ ! "$release_version" =~ $semver ]]; then
    echo "FAIL version '$release_version' is not semantic versioning (X.Y.Z[-prerelease], no leading zeros, no empty identifiers)" >&2
    exit 2
  fi
fi

release=()
if [ ${#charts[@]} -gt 0 ]; then
  release=("${charts[@]}")
else
  shopt -s nullglob
  for chart in "$root"/deployment/helm/*/Chart.yaml; do
    charts+=("$(dirname "$chart")")
    release+=("$(dirname "$chart")")
  done
  for chart in "$root"/features/fixtures/charts/*/Chart.yaml; do
    charts+=("$(dirname "$chart")")
  done
  shopt -u nullglob
  if [ ${#charts[@]} -eq 0 ]; then
    echo 'No chart yet - nothing to check.'
    exit 0
  fi
fi

if [ "$server" = true ] && ! kubectl version >/dev/null 2>&1; then
  echo "FAIL server dry-run requested but no cluster is reachable from the current kube context" >&2
  exit 1
fi

[ -z "$evidence" ] || mkdir -p "$evidence"
failures=0

# record <name> <command...>: runs a check quietly, prints its result and stores it in $result.
record() {
  local name=$1 out
  shift
  if out=$("$@" 2>&1); then
    result=passed
    echo "  ok    $name"
  else
    result=failed
    failures=$((failures + 1))
    echo "  FAIL  $name"
    # Helm's own diagnostics only: a failed render prints its error, never the manifests.
    printf '%s\n' "$out" | grep -vE '^\s*$' | sed 's/^/        /' | tail -20
  fi
}

# gate <chart> <release-name> [values...]: the lint, render and - when requested - server dry-run
# of one chart, a directory or a package. The same three checks for the source and for the package.
gate() {
  local chart=$1 name=$2
  shift 2
  record "helm lint" helm lint "$chart" "$@"
  lint=$result
  record "helm template" sh -c 'helm template "$@" >/dev/null' _ check "$chart" "$@"
  template=$result
  dryrun=not-run
  if [ "$server" = true ]; then
    record "helm install --dry-run=server" sh -c 'helm install "$@" --dry-run=server --hide-secret >/dev/null' _ \
      "gate-$name" "$chart" -n default "$@"
    dryrun=$result
  fi
}

for dir in "${charts[@]}"; do
  [ -f "$dir/Chart.yaml" ] || { echo "FAIL $dir: no Chart.yaml" >&2; failures=$((failures + 1)); continue; }
  name=$(sed -n 's/^name: *//p' "$dir/Chart.yaml" | head -1)
  version=$(sed -n 's/^version: *//p' "$dir/Chart.yaml" | head -1)
  echo "$name $version ($dir)"
  values=()
  [ -f "$dir/ci/values.yaml" ] && values=(-f "$dir/ci/values.yaml")

  deps=not-run
  if grep -q '^dependencies:' "$dir/Chart.yaml"; then
    # Helm resolves a dependency's repository by URL only once the repository is known to it.
    sed -n 's/^ *repository: *"\{0,1\}\(https:[^"]*\)"\{0,1\}$/\1/p' "$dir/Chart.yaml" | sort -u | while read -r url; do
      helm repo add "dep-$(printf '%s' "$url" | sha256sum | cut -c1-8)" "$url" >/dev/null 2>&1 || true
    done
    record "dependencies built from Chart.lock" helm dependency build "$dir"
    deps=$result
  fi

  gate "$dir" "$name" ${values[@]+"${values[@]}"}

  if [ -n "$evidence" ]; then
    printf '{"chart":"%s","version":"%s","path":"%s","dependencies":"%s","lint":"%s","template":"%s","serverDryRun":"%s"}\n' \
      "$name" "$version" "${dir#"$root"/}" "$deps" "$lint" "$template" "$dryrun" > "$evidence/$name.json"
  fi
done

if [ "$failures" -ne 0 ]; then
  echo "$failures check(s) failed${package_dir:+ - nothing is packaged}"
  exit 1
fi
echo "every chart passed"
[ -n "$package_dir" ] || exit 0

# Package every release chart, then check each package as its source was checked. A chart's
# dependencies are already under its charts/ from the build above, so the package carries them.
mkdir -p "$package_dir" || exit 1
packages=()
for dir in ${release[@]+"${release[@]}"}; do
  name=$(sed -n 's/^name: *//p' "$dir/Chart.yaml" | head -1)
  values=()
  [ -f "$dir/ci/values.yaml" ] && values=(-f "$dir/ci/values.yaml")
  package=""
  if out=$(helm package "$dir" --version "$release_version" --app-version "$release_version" --destination "$package_dir" 2>&1); then
    package=$(printf '%s\n' "$out" | sed -n 's/^Successfully packaged chart and saved it to: //p')
  fi
  if [ -z "$package" ] || [ ! -f "$package" ]; then
    failures=$((failures + 1))
    echo "  FAIL  helm package $dir"
    printf '%s\n' "$out" | grep -vE '^\s*$' | sed 's/^/        /' | tail -20
    continue
  fi
  packages+=("$package")
  echo "$name $release_version ($package)"
  gate "$package" "$name" ${values[@]+"${values[@]}"}
done

if [ "$failures" -ne 0 ]; then
  # One failing package takes this run's packages with it, so a release is all or nothing.
  [ ${#packages[@]} -eq 0 ] || rm -f "${packages[@]}"
  echo "$failures check(s) failed - nothing is packaged"
  exit 1
fi

# One checksum file beside the packages, so a downloaded chart can be checked against the release
# before it is installed.
(
  cd "$package_dir" || exit 1
  if command -v sha256sum >/dev/null; then sha256sum ./*.tgz; else shasum -a 256 ./*.tgz; fi
) | sed 's| \./| |' > "$package_dir/SHA256SUMS" || exit 1
echo "${#packages[@]} chart(s) packaged into $package_dir at version $release_version"
