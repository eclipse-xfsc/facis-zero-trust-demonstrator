#!/usr/bin/env bash
# The chart quality gate (TDR-BDD-11): every chart is linted, rendered and - in release mode -
# dry-run against a real API server. One script for the pull-request job and the release gate, so the
# two cannot drift apart.
#
#   scripts/ci/check-charts.sh [--server-dry-run] [--evidence DIR] [chart-dir...]
#
# Without chart directories it checks every chart under deployment/helm/ and features/fixtures/charts/.
# A chart's valid baseline values are its ci/values.yaml when it has one; a chart with dependencies is
# built from its committed Chart.lock first.
#
# --server-dry-run makes `helm install --dry-run=server` mandatory: the current kube context is used,
# and no reachable cluster is a failure, never a pass. Without it the server dry-run is recorded as
# not-run. A server dry-run renders, discovers the API and its schemas and checks existing resources;
# it does not run admission webhooks or hooks and proves nothing about the release at runtime.
#
# --evidence DIR writes one <chart>.json per chart: chart, version, and each check as
# passed | failed | not-run. Nothing rendered is printed or kept: rendered Secrets stay out of the logs.
# Exit status: 0 when every check that ran passed.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
server=false
evidence=""
charts=()
while [ $# -gt 0 ]; do
  case "$1" in
    --server-dry-run) server=true ;;
    --evidence) evidence="$2"; shift ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) charts+=("${1%/}") ;;
  esac
  shift
done

if [ ${#charts[@]} -eq 0 ]; then
  shopt -s nullglob
  for chart in "$root"/deployment/helm/*/Chart.yaml "$root"/features/fixtures/charts/*/Chart.yaml; do
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

  record "helm lint" helm lint "$dir" ${values[@]+"${values[@]}"}
  lint=$result
  record "helm template" sh -c 'helm template "$@" >/dev/null' _ check "$dir" ${values[@]+"${values[@]}"}
  template=$result

  dryrun=not-run
  if [ "$server" = true ]; then
    record "helm install --dry-run=server" sh -c 'helm install "$@" --dry-run=server --hide-secret >/dev/null' _ \
      "gate-$name" "$dir" -n default ${values[@]+"${values[@]}"}
    dryrun=$result
  fi

  if [ -n "$evidence" ]; then
    printf '{"chart":"%s","version":"%s","path":"%s","dependencies":"%s","lint":"%s","template":"%s","serverDryRun":"%s"}\n' \
      "$name" "$version" "${dir#"$root"/}" "$deps" "$lint" "$template" "$dryrun" > "$evidence/$name.json"
  fi
done

[ "$failures" -eq 0 ] || { echo "$failures check(s) failed"; exit 1; }
echo "every chart passed"
