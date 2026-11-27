#!/usr/bin/env bash
# The refusals and the choices of scripts/install-zone/roll-proxies.sh, with no cluster: kubectl is a
# stub on PATH that answers from files this test writes and logs every call it gets.
#
#   - no KUBE_CONTEXT, an empty one, an unknown argument and a DRAIN_TIMEOUT that is not a number:
#     exit 2, and kubectl is never called;
#   - --help: exit 0;
#   - a Deployment whose pods' istio-validation init container runs another proxyv2 image, next to
#     a Deployment whose pods carry no proxy, in the same namespace: only the first is restarted;
#     when its pods still run the other image afterwards, the script fails and names the pod, the
#     namespace, the container and the image; when they run the pinned image, it exits 0;
#   - a replica set list larger than one command-line argument may be: still resolved to its owner;
#   - nothing on another image: nothing is restarted, exit 0;
#   - a StatefulSet's and a DaemonSet's pods on another image: both workloads are restarted;
#   - a bare pod and a Job's pod on another image: neither is restarted, the check names both and
#     fails;
#   - a finished (Succeeded) Job pod on another image: ignored, exit 0;
#   - a terminating pod on another image: waited on while it goes (exit 0), and named as
#     terminating when it outlasts DRAIN_TIMEOUT.
#
# Usage: scripts/install-zone/roll-proxies-test.sh     (needs jq and python3 with PyYAML)
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
script=$here/roll-proxies.sh
pinned=$(python3 -c 'import sys, yaml; print(yaml.safe_load(open(sys.argv[1]))["proxySocketPolicy"]["proxyImage"])' \
  "$here/../../deployment/helm/zone-policy/values.yaml")
old=docker.io/istio/proxyv2:1.0.0-test@sha256:0000000000000000000000000000000000000000000000000000000000000000
[ "$pinned" != "$old" ]

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
fails=0
fail() { printf 'FAIL: %s\n' "$*" >&2; fails=$((fails + 1)); }
pass() { printf 'ok: %s\n' "$*"; }
# expect <pass message> <fail message> <command...>: the command must succeed.
expect() { local ok=$1 ko=$2; shift 2; if "$@"; then pass "$ok"; else fail "$ko"; fi; }
# refuse <fail message> <command...>: the command must fail.
refuse() { local ko=$1; shift; if "$@"; then fail "$ko"; fi; }

# The stub: the n-th `get pods` answers pods-call-<n>.json when that file exists; otherwise
# pods-after.json once a restart has been logged, pods-before.json until then. `get replicasets`
# answers replicasets.json; rollout restart and status succeed. sleep is a stub that logs its call
# and returns at once, so the drain wait costs no time.
cat >"$tmp/bin/kubectl" <<'STUB'
#!/usr/bin/env bash
dir=$(cd "$(dirname "$0")/.." && pwd)
printf '%s\n' "$*" >>"$dir/calls.log"
args=" $* "
case $args in
  *" get pods "*)
    n=$(grep -c ' get pods ' "$dir/calls.log")
    if [ -f "$dir/pods-call-$n.json" ]; then cat "$dir/pods-call-$n.json"
    elif grep -q 'rollout restart' "$dir/calls.log"; then cat "$dir/pods-after.json"
    else cat "$dir/pods-before.json"; fi ;;
  *" get replicasets "*) cat "$dir/replicasets.json" ;;
  *" rollout restart "* | *" rollout status "*) exit 0 ;;
  *) echo "stub kubectl: unexpected call: $*" >&2; exit 3 ;;
esac
STUB
chmod +x "$tmp/bin/kubectl"
cat >"$tmp/bin/sleep" <<'STUB'
#!/usr/bin/env bash
printf 'sleep %s\n' "$*" >>"$(cd "$(dirname "$0")/.." && pwd)/calls.log"
STUB
chmod +x "$tmp/bin/sleep"

# pods <istio-validation image of web's pod>: web-5d8f (Deployment web, proxy and istio-validation as
# native-sidecar init containers) and plain-7c4b (Deployment plain, no proxy), both in tenant-a.
pods() {
  jq -n --arg pinned "$pinned" --arg validation "$1" '{items: [
    {metadata: {name: "web-5d8f-x1", namespace: "tenant-a",
                ownerReferences: [{kind: "ReplicaSet", name: "web-5d8f", controller: true}]},
     spec: {initContainers: [{name: "istio-validation", image: $validation},
                             {name: "istio-proxy", image: $pinned}],
            containers: [{name: "app", image: "docker.io/library/nginx:1.29"}]},
     status: {phase: "Running"}},
    {metadata: {name: "plain-7c4b-y2", namespace: "tenant-a",
                ownerReferences: [{kind: "ReplicaSet", name: "plain-7c4b", controller: true}]},
     spec: {containers: [{name: "app", image: "docker.io/library/busybox:1.37"}]},
     status: {phase: "Running"}}]}'
}
jq -n '{items: [
  {metadata: {name: "web-5d8f", namespace: "tenant-a", ownerReferences: [{kind: "Deployment", name: "web", controller: true}]}},
  {metadata: {name: "plain-7c4b", namespace: "tenant-a", ownerReferences: [{kind: "Deployment", name: "plain", controller: true}]}}]}' \
  >"$tmp/replicasets.json"

run() { # run <expected status: a number, or nonzero> <label> <context, or - for unset> [args...]
  local want=$1 label=$2 context=$3 status=0
  shift 3
  : >"$tmp/calls.log"
  local -a envs=(env -u KUBE_CONTEXT)
  [ "$context" = - ] || envs+=("KUBE_CONTEXT=$context")
  "${envs[@]}" PATH="$tmp/bin:$PATH" DRAIN_TIMEOUT="${DRAIN:-0}" "$script" "$@" >"$tmp/out" 2>&1 || status=$?
  if { [ "$want" = nonzero ] && [ "$status" -ne 0 ]; } || [ "$want" = "$status" ]; then
    pass "$label (exit $status)"
  else
    fail "$label: exit $status"; sed 's/^/    /' "$tmp/out" >&2
  fi
}

# 1. No context: refused before any kubectl call.
pods "$old" >"$tmp/pods-before.json"; cp "$tmp/pods-before.json" "$tmp/pods-after.json"
run 2 "refuses to run without KUBE_CONTEXT" -
expect "no kubectl call without KUBE_CONTEXT" "kubectl called without KUBE_CONTEXT" test ! -s "$tmp/calls.log"
expect "the refusal names KUBE_CONTEXT" "the refusal does not name KUBE_CONTEXT" grep -q KUBE_CONTEXT "$tmp/out"
run 2 "refuses an empty KUBE_CONTEXT" ''
expect "no kubectl call with an empty KUBE_CONTEXT" "kubectl called with an empty KUBE_CONTEXT" test ! -s "$tmp/calls.log"

# 2. An unknown argument: refused before any kubectl call.
run 2 "refuses an unknown argument" stub --all
expect "no kubectl call on an unknown argument" "kubectl called on an unknown argument" test ! -s "$tmp/calls.log"

# 2b. A DRAIN_TIMEOUT that is not a number of seconds: a usage error (exit 2) before any kubectl call.
DRAIN=x run 2 "refuses a DRAIN_TIMEOUT that is not a number" stub
expect "no kubectl call on a bad DRAIN_TIMEOUT" "kubectl called on a bad DRAIN_TIMEOUT" test ! -s "$tmp/calls.log"
expect "the refusal names DRAIN_TIMEOUT" "the refusal does not name DRAIN_TIMEOUT" grep -q DRAIN_TIMEOUT "$tmp/out"

# 3. --help.
run 0 "--help exits 0" - --help
expect "--help describes KUBE_CONTEXT" "--help does not describe KUBE_CONTEXT" grep -q KUBE_CONTEXT "$tmp/out"

# 4. istio-validation still on another image after the restart: fails, naming it; plain untouched.
run nonzero "fails while istio-validation runs another proxyv2 image" stub
expect "restarts the Deployment whose proxy runs another image" "deployment/web was not restarted" \
  grep -q -- '--context stub -n tenant-a rollout restart deployment/web' "$tmp/calls.log"
expect "leaves the Deployment without a proxy alone" "restarted deployment/plain, which has no proxy" \
  test -z "$(grep 'deployment/plain' "$tmp/calls.log")"
refuse "a kubectl call without --context stub" grep -v -q -- '^--context stub ' "$tmp/calls.log"
expect "names the pod, the namespace, the container and the image" "the failure does not name the stale container" \
  grep -q "pod web-5d8f-x1 in namespace tenant-a, init istio-validation: $old" "$tmp/out"

# 5. Every proxy on the pinned image after the restart: exit 0, plain still untouched.
pods "$pinned" >"$tmp/pods-after.json"
run 0 "passes once every proxy runs the pinned image" stub
refuse "restarted deployment/plain, which has no proxy" grep -q 'deployment/plain' "$tmp/calls.log"

# 6. A replica set list larger than one argument may be (a zone's is ~400 KB): still resolved.
cp "$tmp/replicasets.json" "$tmp/replicasets.small.json"
jq --argjson n 3000 '.items += [range($n) | {metadata: {name: "filler-\(.)-0123456789abcdef", namespace: "filler-namespace-\(.)",
  ownerReferences: [{kind: "Deployment", name: "filler-deployment-\(.)", controller: true}]}}]' \
  "$tmp/replicasets.small.json" >"$tmp/replicasets.json"
size=$(wc -c <"$tmp/replicasets.json")
expect "the large replica set list is over 128 KiB ($size bytes)" "the large list is only $size bytes" test "$size" -gt 131072
run 0 "resolves the workloads from a replica set list over 128 KiB" stub
expect "restarts deployment/web from the large list" "deployment/web was not restarted with the large list" \
  grep -q -- 'rollout restart deployment/web' "$tmp/calls.log"
cp "$tmp/replicasets.small.json" "$tmp/replicasets.json"

# 7. Nothing stale at all: nothing restarted.
cp "$tmp/pods-after.json" "$tmp/pods-before.json"
run 0 "nothing to restart when every proxy runs the pinned image" stub
refuse "restarted a workload although no proxy was stale" grep -q rollout "$tmp/calls.log"

# pod <name> <owner kind, or - for none> <owner name> <phase> <proxy image> [terminating]: one pod
# in tenant-b whose istio-proxy and istio-validation init containers run <proxy image>.
pod() {
  jq -n --arg name "$1" --arg kind "$2" --arg owner "$3" --arg phase "$4" --arg image "$5" --arg gone "${6:-}" '
    {metadata: ({name: $name, namespace: "tenant-b"}
                + (if $kind == "-" then {} else {ownerReferences: [{kind: $kind, name: $owner, controller: true}]} end)
                + (if $gone == "" then {} else {deletionTimestamp: "2026-11-24T00:00:00Z"} end)),
     spec: {initContainers: [{name: "istio-validation", image: $image}, {name: "istio-proxy", image: $image}],
            containers: [{name: "app", image: "docker.io/library/busybox:1.37"}]},
     status: {phase: $phase}}'
}
# items <pod json>...: the pod list kubectl returns.
items() { jq -s '{items: .}'; }
reset() { rm -f "$tmp"/pods-call-*.json; }

# 8. A StatefulSet's and a DaemonSet's pods on another image: both restarted, then exit 0.
reset
{ pod db-0 StatefulSet db Running "$old"; pod agent-k2 DaemonSet agent Running "$old"; } | items >"$tmp/pods-before.json"
{ pod db-0 StatefulSet db Running "$pinned"; pod agent-k3 DaemonSet agent Running "$pinned"; } | items >"$tmp/pods-after.json"
run 0 "restarts a StatefulSet and a DaemonSet whose proxies run another image" stub
expect "restarts statefulset/db" "statefulset/db was not restarted" \
  grep -q -- '--context stub -n tenant-b rollout restart statefulset/db' "$tmp/calls.log"
expect "waits on statefulset/db" "no rollout status for statefulset/db" \
  grep -q -- '--context stub -n tenant-b rollout status statefulset/db' "$tmp/calls.log"
expect "restarts daemonset/agent" "daemonset/agent was not restarted" \
  grep -q -- '--context stub -n tenant-b rollout restart daemonset/agent' "$tmp/calls.log"

# 9. A bare pod and a Job's pod on another image: neither restarted, both named, non-zero.
{ pod debug - - Running "$old"; pod migrate-x7 Job migrate Running "$old"; } | items >"$tmp/pods-before.json"
cp "$tmp/pods-before.json" "$tmp/pods-after.json"
run nonzero "fails while a bare pod and a Job pod run another proxyv2 image" stub
refuse "restarted something for a bare pod or a Job pod" grep -q rollout "$tmp/calls.log"
expect "names the bare pod" "the failure does not name the bare pod" \
  grep -q "pod debug in namespace tenant-b, init istio-proxy: $old (running)" "$tmp/out"
expect "names the Job pod" "the failure does not name the Job pod" \
  grep -q "pod migrate-x7 in namespace tenant-b, init istio-proxy: $old (running)" "$tmp/out"

# 10. A finished Job pod on another image: ignored, nothing restarted, exit 0.
pod migrate-x8 Job migrate Succeeded "$old" | items >"$tmp/pods-before.json"
cp "$tmp/pods-before.json" "$tmp/pods-after.json"
run 0 "ignores a Succeeded pod on another proxyv2 image" stub
refuse "restarted something for a Succeeded pod" grep -q rollout "$tmp/calls.log"
refuse "named the Succeeded pod" grep -q migrate-x8 "$tmp/out"

# 11. A terminating pod on another image that goes on the next poll: not restarted, waited on, exit 0.
pod web-5d8f-x1 ReplicaSet web-5d8f Running "$old" terminating | items >"$tmp/pods-before.json"
cp "$tmp/pods-before.json" "$tmp/pods-call-2.json"
pod web-5d8f-x9 ReplicaSet web-5d8f Running "$pinned" | items >"$tmp/pods-call-3.json"
DRAIN=60 run 0 "waits for a terminating pod on another proxyv2 image to go" stub
refuse "restarted the workload of a pod that is already terminating" grep -q rollout "$tmp/calls.log"
expect "polled again after a wait" "did not wait for the terminating pod" grep -q '^sleep ' "$tmp/calls.log"
expect "read the pods three times" "did not poll until the pod was gone" \
  test "$(grep -c ' get pods ' "$tmp/calls.log")" -eq 3

# 12. A terminating pod that outlasts DRAIN_TIMEOUT: named as terminating, non-zero.
reset
cp "$tmp/pods-before.json" "$tmp/pods-after.json"
run nonzero "fails when a terminating pod outlasts DRAIN_TIMEOUT" stub
expect "names the pod as terminating" "the failure does not name the terminating pod" \
  grep -q "pod web-5d8f-x1 in namespace tenant-b, init istio-proxy: $old (terminating)" "$tmp/out"
refuse "waited although DRAIN_TIMEOUT is 0" grep -q '^sleep ' "$tmp/calls.log"

[ "$fails" -eq 0 ] || { printf '%d check(s) failed\n' "$fails" >&2; exit 1; }
echo "roll-proxies: all checks passed"
