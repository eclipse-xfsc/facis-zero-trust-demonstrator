#!/usr/bin/env bash
# Deploy or uninstall one Helm release. The ORCE lifecycle Builder Node runs this script; it can
# also be run by hand to reproduce a single step.
#
#   LIFECYCLE_RELEASE=r LIFECYCLE_NAMESPACE=ns LIFECYCLE_CHART=path|oci://… \
#   LIFECYCLE_VALUES_FILE=values.json scripts/lifecycle.sh deploy
#   LIFECYCLE_RELEASE=r LIFECYCLE_NAMESPACE=ns scripts/lifecycle.sh uninstall
#
# Optional: LIFECYCLE_TIMEOUT (default 5m); LIFECYCLE_WAIT_FOR_JOBS=true also waits for the
# release's Jobs to complete (the zone installer sets it for the zone-policy release).
# LIFECYCLE_PUBLISH_RECORD=<measurement record> adds the TRAIN publication step around a deploy
# (scripts/train-publish/publish.sh, docs/train-publish.md): the record's reference measurement is
# published, and proven published, before the server dry-run, and the entry is pruned to it once
# the release is ready. The publisher reads its own variables from the environment (TSPA_URL,
# TSPA_FRAMEWORK, OIDC_TOKEN_URL with OIDC_CLIENT_ID and OIDC_CLIENT_SECRET, or TSPA_TOKEN_FILE).
# A publication that is not proven fails the deployment before helm runs anything. An uninstall
# leaves the TRAIN entry as it is: removing a component's measurement is an operator's decision.
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
wait_for_jobs=()
[ "${LIFECYCLE_WAIT_FOR_JOBS:-false}" = true ] && wait_for_jobs=(--wait-for-jobs)
publish_record="${LIFECYCLE_PUBLISH_RECORD:-}"
publisher="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/train-publish/publish.sh"
publication='{}'   # the publisher's evidence line per step, carried in the result

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
    --argjson extra "$extra" --argjson publication "$publication" \
    '{ok: $ok, action: $action, release: $release, namespace: $namespace,
      clusterId: $cluster, helmVersion: $helm, output: $output} + $extra
     + (if $publication == {} then {} else {publication: $publication} end)')"
  [ "$ok" = true ] && exit 0 || exit 1
}

# fail <code> <message> [field]: a reported failure. A field names the parameter at fault.
fail() {
  local field="${3:-}"
  event "$action" failed
  result false "$(jq -cn --arg code "$1" --arg message "$2" --arg field "$field" \
    '{error: ({code: $code, message: $message} + (if $field == "" then {} else {field: $field} end))}')"
}

# train_publish <publish|prune>: the TRAIN publication step with the record. The publisher proves
# its own action by reading the trust list back and writes one evidence line, with no secret in
# it; that line lands in the result under publication.<step>. Its exit status is returned:
# 0 proven, 1 not proven or the TSPA unreachable, 2 a record or configuration it refused.
train_publish() {
  local step="$1" rc=0 line
  event "$step" running
  "$publisher" "$step" --record "$publish_record" --out "$work/train-publish" \
    >"$work/$step.out" 2>"$work/$step.err" || rc=$?
  line="$(sed -n 's/^EVENT_JSON=//p' "$work/$step.out" | tail -1)"
  if ! jq -e . <<<"$line" >/dev/null 2>&1; then line='{"outcome": "none"}'; fi   # refused before any call
  publication="$(jq -c --arg s "$step" --argjson e "$line" '. + {($s): $e}' <<<"$publication")"
  return "$rc"
}
# train_note: what a Helm failure after a proven publication leaves in TRAIN, for its message.
train_note() {
  if [ "$(jq -r '.publish.outcome // empty' <<<"$publication")" = published ]; then
    printf '; the TRAIN entry keeps the previous and the new measurement until the next proven publication or a prune by hand'
  fi
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

# The TRAIN publication step, when a record is named: the reference measurement of the version
# about to roll out is published, and proven published, before anything is persisted, so a peer
# can resolve it the moment the new pods serve (ZT-35). What is written now is the union of the
# values in force, so both versions of a rolling update are accepted; the entry is pruned to the
# new value once the release is ready. Not proven means the deployment stops here.
# The record is this script's environment, not a field of the command, so no failure here names a
# field: the node would ask the caller to correct one it never sent.
if [ -n "$publish_record" ]; then
  [ -f "$publish_record" ] \
    || fail publishRefused "LIFECYCLE_PUBLISH_RECORD names no existing measurement record ($publish_record); nothing was created"
  # The publisher lives beside this script (the ORCE image copies both); a missing one is this
  # installation's fault, not the record's, and must not read as a publication that was not proven.
  [ -x "$publisher" ] \
    || fail systemError "the TRAIN publication step is not installed beside this script ($publisher); nothing was created"
  rc=0; train_publish publish || rc=$?
  case "$rc" in
    0) event publish succeeded ;;
    2) event publish failed
       fail publishRefused "the publication step refused its record or configuration ($(mask <"$work/publish.err" | tail -1)); nothing was created" ;;
    *) event publish failed
       fail publishNotProven "the reference measurement was not proven published in TRAIN (outcome: $(jq -r '.publish.outcome // "none"' <<<"$publication")); nothing was created" ;;
  esac
fi

# Server-side dry-run first: the chart's schema, rendering and the API server's admission are all
# checked before anything is persisted (the TDR's QA dry-run, on every deployment).
event dry-run running
if ! helm upgrade "$release" "$chart" --install --namespace "$namespace" \
    --values "$values_file" --dry-run=server >"$work/helm.out" 2>&1; then
  if grep -q "values don't meet the specifications of the schema" "$work/helm.out"; then
    fail valuesSchemaRejected "the chart rejected the deployment values; nothing was created$(train_note)"
  fi
  fail dryRunRejected "the server-side dry-run refused the release; nothing was created$(train_note)"
fi

event deploy running
if ! helm upgrade "$release" "$chart" --install --namespace "$namespace" \
    --values "$values_file" --rollback-on-failure --wait=watcher ${wait_for_jobs[@]+"${wait_for_jobs[@]}"} \
    --timeout "$timeout" >"$work/helm.out" 2>&1; then
  if grep -q "values don't meet the specifications of the schema" "$work/helm.out"; then
    fail valuesSchemaRejected "the chart rejected the deployment values; nothing was created$(train_note)"
  fi
  fail deployFailed "helm did not reach a ready release and rolled it back$(train_note)"
fi

# The expected inventory: every top-level object the release rendered, with its live identity.
# It is returned so that absence can still be checked after the release record is gone.
helm get manifest "$release" --namespace "$namespace" >"$work/manifest.yaml"
# Rendered objects usually carry no namespace; they live in the release namespace. A chart that
# also renders objects into other namespaces (the umbrella) names them explicitly, which
# `kubectl --namespace` refuses. The manifest is split on Helm's `---` separators into the objects
# whose metadata names a namespace and the others, and each part is read on its own, so the step
# needs no kubeconfig context or namespace of its own (in-cluster credentials work as before).
awk -v named="$work/named.yaml" -v unnamed="$work/unnamed.yaml" '
  function flush() { if (doc != "") printf "---\n%s", doc > (ns ? named : unnamed); doc = ""; ns = 0; meta = 0 }
  /^---/ { flush(); next }
  /^metadata:/ { meta = 1 }
  /^[^ #]/ && !/^metadata:/ { meta = 0 }
  meta && /^  namespace:/ { ns = 1 }
  { doc = doc $0 "\n" }
  END { flush() }' "$work/manifest.yaml"
for part in unnamed named; do
  [ -s "$work/$part.yaml" ] || continue
  if [ "$part" = unnamed ]; then
    kubectl get --namespace "$namespace" --filename "$work/$part.yaml" --output json || exit 1
  else
    kubectl get --filename "$work/$part.yaml" --output json || exit 1
  fi
done | jq -s '{apiVersion: "v1", kind: "List", items: [.[] | (.items // [.])[]]}' >"$work/live.json"
revision="$(helm status "$release" --namespace "$namespace" --output json | jq '.version')"
inventory="$(jq -c --arg chart "$chart_digest" --arg values "$values_hash" --argjson revision "$revision" \
  '{revision: $revision, chartDigest: $chart, valuesHash: $values,
    expected: [(.items // [.])[] | {apiVersion, kind, namespace: .metadata.namespace,
                           name: .metadata.name, uid: .metadata.uid}]}' "$work/live.json")"

# The release is ready: the previous measurement leaves the TRAIN entry, so it does not become a
# standing allow-list. A prune that is not proven is reported as a failure of this step, with the
# release left as it is (deployed, ready, its inventory in the result all the same): the entry
# still accepts the new version, and the leftover is seen rather than swallowed.
if [ -n "$publish_record" ]; then
  rc=0; train_publish prune || rc=$?
  if [ "$rc" != 0 ]; then
    event prune failed
    result false "$(jq -cn --argjson inv "$inventory" --arg revision "$revision" \
      --arg outcome "$(jq -r '.prune.outcome // "none"' <<<"$publication")" \
      '$inv + {error: {code: "pruneNotProven", message: ("the release is deployed and ready (revision " + $revision + "), but the TRAIN entry was not proven pruned to the new measurement (outcome: " + $outcome + "); run prune again")}}')"
  fi
  event prune succeeded
fi
event deploy succeeded
result true "$inventory"
