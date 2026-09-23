#!/usr/bin/env bash
# Observe a BDD pool namespace and decide whether it is in the expected state, waiting up to a
# deadline for the controllers to converge. Run it with the read-only observer identity.
#
#   cluster-state.sh --namespace ns --release r --expect present --expected expected.json
#   cluster-state.sh --namespace ns --release r --expect absent  --expected expected.json
#   cluster-state.sh --namespace ns --release r --expect absent  --record-baseline baseline.json
#
# Prints one JSON document: the cluster identity, the CRD names, the classified inventory and
# the violations (see scripts/bdd/inventory.jq). Exit status: 0 the predicate holds, 1 it still
# does not hold at the deadline (the last inventory is printed), 2 the cluster could not be
# observed. An API or authorization error is never retried into a pass.
set -euo pipefail

namespace="" release="" expect="" expected_file="" baseline_file="" record_file=""
deadline="${CLUSTER_STATE_DEADLINE:-120}" interval=3
while [ $# -gt 0 ]; do
  case "$1" in
    --namespace) namespace="$2"; shift 2 ;;
    --release) release="$2"; shift 2 ;;
    --expect) expect="$2"; shift 2 ;;
    --expected) expected_file="$2"; shift 2 ;;
    --baseline) baseline_file="$2"; shift 2 ;;
    --record-baseline) record_file="$2"; shift 2 ;;
    --deadline) deadline="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$namespace" && -n "$release" && "$expect" =~ ^(present|absent)$ ]] \
  || { echo "usage: --namespace ns --release r --expect present|absent [--expected f] [--baseline f] [--record-baseline f]" >&2; exit 2; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fatal() {
  jq -cn --arg message "$1" --arg detail "$(tail -c 2000 "$work/err" 2>/dev/null || true)" \
    '{fatal: true, message: $message, detail: $detail}'
  exit 2
}

# The pool's documented baseline, as the bdd-pool chart and Kubernetes create it.
documented='[
  {"kind": "ServiceAccount", "name": "default"},
  {"kind": "ConfigMap", "name": "kube-root-ca.crt"},
  {"kind": "Role", "name": "ztd-lifecycle-deployer"},
  {"kind": "Role", "name": "ztd-bdd-observer"},
  {"kind": "RoleBinding", "name": "ztd-lifecycle-deployer"},
  {"kind": "RoleBinding", "name": "ztd-bdd-observer"}
]'
expected='[]'
[ -n "$expected_file" ] && expected="$(jq -c '.' "$expected_file")"
recorded='null'
[ -n "$baseline_file" ] && recorded="$(jq -c '.' "$baseline_file")"

# Every namespaced type that can be listed, except computed telemetry (metrics.k8s.io), so an
# object of an unanticipated persisted type still lands in "unexplained".
kubectl api-resources --namespaced --verbs=list -o name >"$work/types" 2>"$work/err" \
  || fatal "cannot discover the namespaced resource types"
types="$(grep -v '\.metrics\.k8s\.io$' "$work/types" | paste -sd, -)"

cluster_id="$(kubectl get namespace kube-system -o jsonpath='{.metadata.uid}' 2>"$work/err")" \
  || fatal "cannot read the cluster identity"

observe() {
  kubectl get "$types" --namespace "$namespace" --output json >"$work/objects.json" 2>"$work/err" \
    || fatal "cannot list the objects in namespace $namespace"
  if ! helm history "$release" --namespace "$namespace" --output json >"$work/history.json" 2>"$work/err"; then
    grep -q "release: not found" "$work/err" || fatal "cannot read the helm history of $release"
    echo '[]' >"$work/history.json"
  fi
  kubectl get customresourcedefinitions -o jsonpath='{.items[*].metadata.name}' >"$work/crds" 2>"$work/err" \
    || fatal "cannot list the CRDs"
  jq -n -f "$here/inventory.jq" \
    --argjson objects "$(jq -c '.items' "$work/objects.json")" \
    --argjson expected "$expected" --argjson documented "$documented" --argjson recorded "$recorded" \
    --argjson history "$(jq -c '[.[] | {revision, status}]' "$work/history.json")" \
    --arg release "$release" --arg mode "$expect" >"$work/state.json"
}

start="$(date +%s)"
while :; do
  observe
  elapsed=$(( $(date +%s) - start ))
  converged="$(jq '.violations | length == 0' "$work/state.json")"
  if [ "$converged" = true ] || [ "$elapsed" -ge "$deadline" ]; then
    break
  fi
  sleep "$interval"
done

if [ "$converged" = true ] && [ -n "$record_file" ]; then
  jq '[.classes.baseline[] | {kind, name, uid}]' "$work/state.json" >"$record_file"
fi

jq --arg cluster "$cluster_id" --arg namespace "$namespace" --arg release "$release" \
  --arg expect "$expect" --argjson elapsed "$elapsed" --argjson converged "$converged" \
  --arg crds "$(cat "$work/crds")" \
  '{clusterId: $cluster, namespace: $namespace, release: $release, expect: $expect,
    converged: $converged, elapsedSeconds: $elapsed,
    crds: ($crds | split(" ") | map(select(. != "")))} + .' "$work/state.json"
[ "$converged" = true ]
