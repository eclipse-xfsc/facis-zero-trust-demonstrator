#!/usr/bin/env bash
# Deploy or uninstall one Helm release. The ORCE lifecycle Builder Node runs this script; it can
# also be run by hand to reproduce a single step.
#
#   LIFECYCLE_RELEASE=r LIFECYCLE_NAMESPACE=ns LIFECYCLE_CHART=path|oci://… \
#   LIFECYCLE_VALUES_FILE=values.json scripts/lifecycle.sh deploy
#   LIFECYCLE_RELEASE=r LIFECYCLE_NAMESPACE=ns scripts/lifecycle.sh uninstall
#
# Protocol on stdout: zero or more `EVENT_JSON=<json>` progress lines, then exactly one
# `RESULT_JSON=<json>` line, also on failure. Exit status 0 means ok:true, 1 a reported failure.
# Everything else goes to stderr. Secrets are masked before anything is printed.
#
# The namespace must already exist: this script never creates or deletes namespaces. The BDD
# pool chart provisions them together with the bindings this identity needs.
set -euo pipefail

action="${1:-}"
release="${LIFECYCLE_RELEASE:-}"
namespace="${LIFECYCLE_NAMESPACE:-}"
chart="${LIFECYCLE_CHART:-}"
values_file="${LIFECYCLE_VALUES_FILE:-}"
timeout="${LIFECYCLE_TIMEOUT:-5m}"

work="$(mktemp -d)"
result_printed=false

# Exactly one result line, whatever happens: an unexpected failure after this point still
# reports ok:false instead of leaving the caller without an outcome.
finish() {
  local status=$?
  if [ "$result_printed" = false ]; then
    printf 'RESULT_JSON=%s\n' "$(jq -cn --arg action "$action" \
      '{ok: false, action: $action, error: {code: "systemError", message: "the lifecycle script stopped unexpectedly"}}')"
    status=1
  fi
  rm -rf "$work"
  exit "$status"
}
trap finish EXIT

event() {
  printf 'EVENT_JSON=%s\n' "$(jq -cn --arg action "$action" --arg step "$1" --arg status "$2" \
    '{action: $action, step: $step, status: $status}')"
}

# Mask anything that looks like a credential before it can reach a log, the ORCE context or
# the evidence: key=value and key: value pairs, quoted or not (Helm output quotes values), bearer
# tokens, and JWTs. The Builder Node masks the same way.
mask() {
  sed -E \
    -e 's/((password|passwd|secret|token|apikey|api-key|client-secret)[^=:]{0,20}[=:][[:space:]]*["'"'"']?)[^[:space:],"'"'"'}]+/\1[masked]/Ig' \
    -e 's/(Bearer[[:space:]]+)[A-Za-z0-9._~+/=-]+/\1[masked]/g' \
    -e 's/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/[masked-jwt]/g'
}

# sha256sum in the ORCE image, shasum on a developer's Mac.
sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

cluster_id() {
  kubectl get namespace kube-system -o jsonpath='{.metadata.uid}' 2>/dev/null || true
}

# result <ok> <extra-json>: print the one result line and exit accordingly.
result() {
  local ok="$1" extra="$2" output=""
  [ -f "$work/helm.out" ] && output="$(mask <"$work/helm.out" | tail -c 8000)"
  result_printed=true
  printf 'RESULT_JSON=%s\n' "$(jq -cn \
    --argjson ok "$ok" --arg action "$action" --arg release "$release" \
    --arg namespace "$namespace" --arg cluster "$(cluster_id)" \
    --arg helm "$(helm version --short 2>/dev/null || true)" --arg output "$output" \
    --argjson extra "$extra" \
    '{ok: $ok, action: $action, release: $release, namespace: $namespace,
      clusterId: $cluster, helmVersion: $helm, output: $output} + $extra')"
  [ "$ok" = true ] && exit 0 || exit 1
}

# fail <code> <message> [field]: a reported failure. A field names the parameter at fault.
fail() {
  local field="${3:-}"
  event "$action" failed
  result false "$(jq -cn --arg code "$1" --arg message "$2" --arg field "$field" \
    '{error: ({code: $code, message: $message} + (if $field == "" then {} else {field: $field} end))}')"
}

# The parameters are checked here as well as in the Builder Node, so a hand-run of the script
# refuses the same inputs.
[[ "$action" == deploy || "$action" == uninstall ]] \
  || fail invalidAction "action must be deploy or uninstall" action
[[ "$release" =~ ^[a-z0-9]([-a-z0-9]{0,51}[a-z0-9])?$ ]] \
  || fail invalidParameter "release must be a DNS-1123 label of at most 53 characters" release
[[ "$namespace" =~ ^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$ ]] \
  || fail invalidParameter "namespace must be a DNS-1123 label" namespace

event validate running
if ! kubectl get namespace "$namespace" -o name >"$work/ns.out" 2>&1; then
  if grep -qi forbidden "$work/ns.out"; then
    fail namespaceNotPermitted "this identity may not deploy into namespace $namespace" namespace
  fi
  if grep -qi notfound "$work/ns.out"; then
    fail namespaceNotFound "namespace $namespace does not exist; it is provisioned, never created here" namespace
  fi
  fail clusterUnreachable "the Kubernetes API could not be reached"
fi

if [ "$action" = uninstall ]; then
  event uninstall running
  if ! helm status "$release" --namespace "$namespace" >/dev/null 2>&1; then
    fail releaseNotFound "no release $release in namespace $namespace"
  fi
  if ! helm uninstall "$release" --namespace "$namespace" --wait=watcher --timeout "$timeout" \
      >"$work/helm.out" 2>&1; then
    fail uninstallFailed "helm uninstall did not complete"
  fi
  event uninstall succeeded
  result true '{}'
fi

# deploy
[ -n "$chart" ] || fail invalidParameter "chart is required" chart
[ -f "$values_file" ] || fail invalidParameter "values file is required" values

# The release hash evidence: what was deployed (chart) with what (values).
if [ -d "$chart" ]; then
  chart_digest="sha256:$(cd "$chart" && find . -type f -print0 | LC_ALL=C sort -z \
    | xargs -0 bash -c "$(declare -f sha256); sha256 \"\$@\"" _ | sha256 | cut -d' ' -f1)"
elif [ -f "$chart" ]; then
  chart_digest="sha256:$(sha256 "$chart" | cut -d' ' -f1)"
elif [[ "$chart" == oci://*@sha256:* ]]; then
  chart_digest="${chart##*@}"
else
  fail invalidParameter "chart must be a local chart or an oci:// reference pinned by digest" chart
fi
values_hash="sha256:$(sha256 "$values_file" | cut -d' ' -f1)"

# Server-side dry-run first: the chart's schema, rendering and the API server's admission are all
# checked before anything is persisted (the TDR's QA dry-run, on every deployment).
event dry-run running
if ! helm upgrade "$release" "$chart" --install --namespace "$namespace" \
    --values "$values_file" --dry-run=server >"$work/helm.out" 2>&1; then
  if grep -q "values don't meet the specifications of the schema" "$work/helm.out"; then
    fail valuesSchemaRejected "the chart rejected the deployment values; nothing was created"
  fi
  fail dryRunRejected "the server-side dry-run refused the release; nothing was created"
fi

event deploy running
if ! helm upgrade "$release" "$chart" --install --namespace "$namespace" \
    --values "$values_file" --rollback-on-failure --wait=watcher --timeout "$timeout" \
    >"$work/helm.out" 2>&1; then
  if grep -q "values don't meet the specifications of the schema" "$work/helm.out"; then
    fail valuesSchemaRejected "the chart rejected the deployment values; nothing was created"
  fi
  fail deployFailed "helm did not reach a ready release and rolled it back"
fi

# The expected inventory: every top-level object the release rendered, with its live identity.
# It is returned so that absence can still be checked after the release record is gone.
helm get manifest "$release" --namespace "$namespace" >"$work/manifest.yaml"
# Rendered objects usually carry no namespace; they live in the release namespace.
kubectl get --namespace "$namespace" --filename "$work/manifest.yaml" --output json >"$work/live.json"
revision="$(helm status "$release" --namespace "$namespace" --output json | jq '.version')"
event deploy succeeded
result true "$(jq -c --arg chart "$chart_digest" --arg values "$values_hash" --argjson revision "$revision" \
  '{revision: $revision, chartDigest: $chart, valuesHash: $values,
    expected: [(.items // [.])[] | {apiVersion, kind, namespace: .metadata.namespace,
                           name: .metadata.name, uid: .metadata.uid}]}' "$work/live.json")"
