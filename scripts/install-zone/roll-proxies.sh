#!/usr/bin/env bash
# Move a zone's mesh proxies to the pinned Istio release after an in-place upgrade, then prove that
# none is left on another image.
#
# A rerun of scripts/install-zone/install.sh upgrades istiod, istio-cni and the admission policy,
# but a running pod keeps the proxy it was injected with until it is recreated. This script:
#
#   1 reads the pinned proxy image, proxySocketPolicy.proxyImage in
#     deployment/helm/zone-policy/values.yaml (which the installer keeps equal to istiod's
#     global.proxy.image);
#   2 finds every Deployment, StatefulSet and DaemonSet whose pods carry a container, init or
#     regular, with a proxyv2 image other than the pinned one (the proxies are native sidecars, so
#     istio-proxy and istio-validation are init containers), restarts only those with
#     kubectl rollout restart, and waits on kubectl rollout status. A workload whose pods carry no
#     proxy is never restarted: restarting it in a namespace with the injection label would inject a
#     proxy it does not have;
#   3 waits for the replaced pods to go, then lists every pod in the cluster and fails, naming the
#     pod, its namespace, the container and the image, while any container still runs a proxyv2
#     image other than the pinned one. Bare pods and Job pods are never restarted; this check names
#     them so that the operator can delete them. A pod that has finished (Succeeded or Failed) runs
#     no container and is not counted.
#
# Usage:
#   KUBE_CONTEXT=<context> scripts/install-zone/roll-proxies.sh
#   scripts/install-zone/roll-proxies.sh -h | --help      this text
#
# Environment:
#   KUBE_CONTEXT     kubectl context (required, no default: the script names no cluster)
#   ROLLOUT_TIMEOUT  timeout of each rollout status          (default: 10m)
#   DRAIN_TIMEOUT    seconds to wait for replaced pods to go  (default: 180)
#
# Needs kubectl, jq and python3 with PyYAML. Exit status: 0 when no container in the cluster runs a
# proxyv2 image other than the pinned one; 1 otherwise or on a failed restart; 2 on a usage error.
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
POLICY_VALUES=$REPO/deployment/helm/zone-policy/values.yaml
ROLLOUT_TIMEOUT=${ROLLOUT_TIMEOUT:-10m}
DRAIN_TIMEOUT=${DRAIN_TIMEOUT:-180}

say() { printf '%s\n' "$*"; }
die() { printf 'roll-proxies: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,/^# proxyv2 image other than the pinned one; 1 otherwise/p' "$0" | sed 's/^# \{0,1\}//'; }

for arg in "$@"; do
  case $arg in
    -h | --help | help) usage; exit 0 ;;
    *) printf 'roll-proxies: unknown argument: %s (see --help)\n' "$arg" >&2; exit 2 ;;
  esac
done

# The context first, before any kubectl call: there is no default cluster.
[ -n "${KUBE_CONTEXT:-}" ] || { printf 'roll-proxies: KUBE_CONTEXT is not set; name the cluster explicitly (see --help)\n' >&2; exit 2; }
case $DRAIN_TIMEOUT in '' | *[!0-9]*) printf "roll-proxies: DRAIN_TIMEOUT must be a number of seconds, not '%s' (see --help)\n" "$DRAIN_TIMEOUT" >&2; exit 2 ;; esac
for tool in kubectl jq python3; do command -v "$tool" >/dev/null || die "$tool is required"; done

PINNED=$(python3 - "$POLICY_VALUES" <<'PY'
import sys, yaml
values = yaml.safe_load(open(sys.argv[1])) or {}
image = ((values.get("proxySocketPolicy") or {}).get("proxyImage") or "").strip()
if not image:
    sys.exit(f"roll-proxies: {sys.argv[1]} sets no proxySocketPolicy.proxyImage")
print(image)
PY
) || exit 1

kc() { kubectl --context "$KUBE_CONTEXT" "$@"; }

# The jq definitions shared by both passes: a proxyv2 image is one whose repository's last path
# element is proxyv2, whatever its registry, tag or digest. ($pinned is jq's, not the shell's.)
# shellcheck disable=SC2016
JQ_DEFS='
  def is_proxy: test("(^|/)proxyv2([:@]|$)");
  def stale($pinned): [ ((.spec.initContainers // [])[] | {name, image, kind: "init"}),
                        ((.spec.containers // [])[] | {name, image, kind: "container"}) ]
                      | map(select((.image | is_proxy) and .image != $pinned));
  def live: select(.status.phase != "Succeeded" and .status.phase != "Failed");
'

say "Context: $KUBE_CONTEXT"
say "Pinned proxy image: $PINNED"

# ---- 1. The workloads to restart.
pods=$(kc get pods --all-namespaces -o json) || die "could not list the pods"
replicasets=$(kc get replicasets --all-namespaces -o json) || die "could not list the replica sets"

# One line per workload: <kind> <namespace> <name>. A pod owned by a ReplicaSet is resolved to the
# ReplicaSet's Deployment; a pod of a bare ReplicaSet, a Job or no owner is left to the final check.
# The replica sets go in as a file, not as an argument: a zone's list is larger than the kernel
# allows for one argument.
workloads=$(jq -r --arg pinned "$PINNED" --slurpfile rs <(printf '%s' "$replicasets") "$JQ_DEFS"'
  ($rs[0].items | map({key: "\(.metadata.namespace)/\(.metadata.name)",
                    value: ((.metadata.ownerReferences // []) | map(select(.controller == true and .kind == "Deployment")) | first | .name)})
             | from_entries) as $deploy
  | [ .items[] | live | select(.metadata.deletionTimestamp == null) | select((stale($pinned) | length) > 0)
      | .metadata.namespace as $ns
      | ((.metadata.ownerReferences // []) | map(select(.controller == true)) | first) as $owner
      | if $owner == null then empty
        elif $owner.kind == "ReplicaSet" then ($deploy["\($ns)/\($owner.name)"] // null) as $d
             | if $d == null then empty else "deployment \($ns) \($d)" end
        elif $owner.kind == "StatefulSet" then "statefulset \($ns) \($owner.name)"
        elif $owner.kind == "DaemonSet" then "daemonset \($ns) \($owner.name)"
        else empty end ]
  | unique | .[]' <<<"$pods")

if [ -z "$workloads" ]; then
  say "No Deployment, StatefulSet or DaemonSet runs a proxy on another image; nothing to restart."
else
  say "Restarting the workloads whose proxies run another image:"
  while read -r kind ns name; do
    say "  $kind/$name in $ns"
    kc -n "$ns" rollout restart "$kind/$name" >/dev/null || die "rollout restart $kind/$name in $ns failed"
    kc -n "$ns" rollout status "$kind/$name" --timeout="$ROLLOUT_TIMEOUT" >/dev/null \
      || die "$kind/$name in $ns did not roll out within $ROLLOUT_TIMEOUT (kubectl -n $ns get events)"
  done <<<"$workloads"
fi

# ---- 2. The check, cluster-wide: wait for replaced pods to go, then fail on any stale proxy.
deadline=$((SECONDS + DRAIN_TIMEOUT))
while :; do
  pods=$(kc get pods --all-namespaces -o json) || die "could not list the pods"
  report=$(jq -r --arg pinned "$PINNED" "$JQ_DEFS"'
    .items[] | live | . as $p | stale($pinned)[]
    | [ (if $p.metadata.deletionTimestamp == null then "running" else "terminating" end),
        $p.metadata.namespace, $p.metadata.name, .kind, .name, .image ] | @tsv' <<<"$pods")
  [ -n "$report" ] || break
  # Only replaced pods still terminating: wait for them, bounded.
  if ! grep -q '^running' <<<"$report" && [ "$SECONDS" -lt "$deadline" ]; then
    sleep 5
    continue
  fi
  printf 'roll-proxies: these containers run a proxyv2 image other than %s:\n' "$PINNED" >&2
  while IFS=$'\t' read -r state ns pod kind container image; do
    printf '  pod %s in namespace %s, %s %s: %s (%s)\n' "$pod" "$ns" "$kind" "$container" "$image" "$state" >&2
  done <<<"$report"
  printf 'roll-proxies: a bare pod or a Job pod is not restarted by this script; delete it once it may go.\n' >&2
  exit 1
done

say "No container in the cluster runs a proxyv2 image other than $PINNED."
