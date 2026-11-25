#!/usr/bin/env bash
# Guard bypass proof on a live zone. First a guarded call that succeeds end to end (the
# zone's public Participant route: Participant -> guard -> resource), then direct calls to the
# protected resource that skip the guard, each refused by the resource's own sidecar, with the
# receiver-side evidence read from that sidecar (its RBAC and listener counters before and after,
# and its access log), not inferred from a client-side failure. The guarded call is recorded whole:
# the Participant's bootstrap after a reset (it presents, acquires its token and is ready), the
# answer's status and body, the guard's allowed decision event, the resource's record of the request,
# and the RBAC allowed counters of the guard's and the resource's sidecars, which admit one SPIFFE
# identity each. A third probe calls the guard itself without a token and must be refused by it.
#
# The direct callers are two short-lived probe Jobs, never Service endpoints (their readiness never
# passes). Both carry the guard's pod label, which is the only opening: the resource's network policy
# admits the guard's label on the resource port, so the packet reaches the receiver and the mesh
# decides. One is meshed under the Participant's service account (a valid mesh identity that is not
# the guard's: the resource's AuthorizationPolicy refuses it); the other has no sidecar (plaintext to a
# STRICT receiver). The tokenless caller is a meshed probe with the Participant's labels and service
# account, the one caller the guard's policies admit, so that the guard and not the mesh answers it.
# Nothing else is created or changed; the Jobs are deleted on exit and their absence is verified.
#
#   ZTD_CONFIRM_CONTEXT=<context> scripts/verify-guard-bypass/verify.sh --namespace NS --url URL --ca CA
#       --probe-image IMAGE --out DIR [--node NODE]
#
# IMAGE is an admitted image with bash (the probe speaks HTTP over /dev/tcp). STORE_CLIENT_ID is the
# token store's OAuth client as the zone seeds it (default ztd-store): the resource must record the
# guarded request for exactly that client. Exit status: the number of failed checks; 125 refused.
set -euo pipefail

ns="" url="" ca="" image="" out="" node=""
while [ $# -gt 0 ]; do
  case "$1" in
    --namespace) ns=$2; shift 2 ;;
    --url) url=$2; shift 2 ;;
    --ca) ca=$2; shift 2 ;;
    --probe-image) image=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    --node) node=$2; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 125 ;;
  esac
done
context=$(kubectl config current-context)
if [ -z "$ns" ] || [ -z "$url" ] || [ ! -f "$ca" ] || [ -z "$image" ] || [ -z "$out" ] || [ "${ZTD_CONFIRM_CONTEXT:-}" != "$context" ]; then
  echo "refused: namespace, url, ca, probe image, out and ZTD_CONFIRM_CONTEXT=$context are required" >&2; exit 125
fi
[ ! -e "$out" ] || { echo "refused: $out exists" >&2; exit 125; }
mkdir -p "$out/before" "$out/after"
run=$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')
k() { kubectl -n "$ns" "$@"; }
failures=0
pass() { echo "PASS  $*" | tee -a "$out/verdict.txt"; }
fail() { echo "FAIL  $*" | tee -a "$out/verdict.txt"; failures=$((failures + 1)); }
cleanup() {
  k delete job -l "ztd.facis.io/probe-run=$run" --wait=true --timeout=120s >/dev/null 2>&1 || true
  k wait --for=delete pod -l "ztd.facis.io/probe-run=$run" --timeout=120s >/dev/null 2>&1 || true
  if [ -z "$(k get job,pod -l "ztd.facis.io/probe-run=$run" -o name 2>/dev/null)" ]; then
    pass "cleanup: no probe Job or Pod of run $run remains"
  else
    fail "cleanup: probe objects of run $run remain"
  fi
}
# On an early exit the cleanup still runs and its failure is the exit status.
trap 'cleanup; exit $(( failures > 0 ? failures : 1 ))' EXIT

# The state the proof must leave as it found: every policy object and workload of the namespace.
snapshot() {
  k get authorizationpolicy,peerauthentication,networkpolicy,deployment,service -o json \
    | jq '[.items[] | {kind, name: .metadata.name, resourceVersion: .metadata.resourceVersion, generation: .metadata.generation}]' > "$1/objects.json"
  helm list -n "$ns" -o json | jq '[.[] | {name, revision, status, chart}]' > "$1/releases.json"
}
resource_pod=$(k get pod -l app.kubernetes.io/name=ztd-protected-resource -o jsonpath='{.items[0].metadata.name}')
guard_pod=$(k get pod -l app.kubernetes.io/name=ztd-guard -o jsonpath='{.items[0].metadata.name}')
participant_instance=$(k get pod -l app.kubernetes.io/name=ztd-participant -o jsonpath='{.items[0].metadata.labels.app\.kubernetes\.io/instance}')
stats() { # stats FILE [POD]: the sidecar's RBAC and inbound listener counters, the resource's by default
  k exec "${2:-$resource_pod}" -c istio-proxy -- pilot-agent request GET stats 2>/dev/null \
    | grep -E '^(http\.inbound_0\.0\.0\.0_8080;\.rbac\.|listener\.0\.0\.0\.0_15006\.(no_filter_chain_match|downstream_cx_total|server_ssl_socket_factory)|listener\.0\.0\.0\.0_15006\.ssl\.connection_error)' \
    | sort > "$1" || true
}
snapshot "$out/before"
k get authorizationpolicy ztd-protected-resource-caller -o json | jq '{spec}' > "$out/before/resource-authorizationpolicy.json"
k get networkpolicy -o json | jq '[.items[] | select(.spec.podSelector.matchLabels["app.kubernetes.io/name"] == "ztd-protected-resource") | {name: .metadata.name, spec}]' > "$out/before/resource-networkpolicies.json"
{ echo "context: $context"; echo "namespace: $ns"; echo "uid: $(k get ns "$ns" -o jsonpath='{.metadata.uid}' 2>/dev/null || kubectl get ns "$ns" -o jsonpath='{.metadata.uid}')"; echo "resource pod: $resource_pod"; echo "probe run: $run"; echo "started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"; } > "$out/run.txt"

echo "== 1. The guarded path succeeds"
pub() { curl -sS -m 30 --cacert "$ca" -H 'Content-Type: application/json' "$@"; }
pub -X POST --data '{}' "$url/reset" > "$out/reset.json" || true
for _ in $(seq 1 60); do
  state=$(pub "$url/state" | jq -r '.state // empty' 2>/dev/null || true)
  [ "$state" = ready ] && break
  sleep 2
done
pub "$url/state" > "$out/state.json" || true
if jq -e '.state == "ready" and ([.history[].state] | index("presenting") < index("acquiring_token") and index("acquiring_token") < index("ready"))' "$out/state.json" >/dev/null 2>&1; then
  pass "authorized: after the reset the Participant presented, acquired its token and is ready"
else
  fail "authorized: the Participant is not ready after the reset: $(head -c 300 "$out/state.json")"
fi
stats "$out/guarded-stats-guard-before.txt" "$guard_pod"
stats "$out/guarded-stats-resource-before.txt"
pub -o "$out/guarded-response.json" -w '%{http_code}\n' -X POST --data '{"resource":"sample-report","action":"read"}' "$url/demo" > "$out/guarded-status.txt" || true
jq '{outcome, reasonCode, requestId, correlationId}' "$out/guarded-response.json" > "$out/guarded.json" || true
guarded_id=$(jq -r '.requestId // empty' "$out/guarded.json")
if [ "$(jq -r .outcome "$out/guarded.json")" = success ] && [ -n "$guarded_id" ]; then
  pass "guarded: $url/demo succeeds through the guard (request $guarded_id)"
else
  fail "guarded: $(cat "$out/guarded.json")"
fi
sleep 3
k logs "$resource_pod" -c ztd-protected-resource --since=10m 2>/dev/null | grep -F "$guarded_id" > "$out/guarded-resource-record.jsonl" || true
# The guard names its decision by its own correlation id, not the Participant's request id, so its
# allowed event is the one in the five seconds up to the resource's record of the request.
k logs "$guard_pod" -c guard --since=10m 2>/dev/null \
  | jq -cR --arg t "$(jq -r .time "$out/guarded-resource-record.jsonl" 2>/dev/null | head -1)" \
      'def sec: sub("\\.[0-9]+Z$"; "Z") | fromdate;
       fromjson? | select(.kind == "decision" and .payload.state == "allowed" and (.ts | sec) <= ($t | sec) and (.ts | sec) >= ($t | sec) - 5)' \
      > "$out/guarded-guard-record.jsonl" 2>/dev/null || true
stats "$out/guarded-stats-guard-after.txt" "$guard_pod"
stats "$out/guarded-stats-resource-after.txt"
allowed() { grep 'http.inbound_0.0.0.0_8080;.rbac.allowed' "$1" 2>/dev/null | awk -F': ' '{print $2}'; }
if [ "$(cat "$out/guarded-status.txt")" = 200 ] && jq -e '.safeData.report.id // .safeData.summary.id' "$out/guarded-response.json" >/dev/null 2>&1; then
  pass "guarded: the answer is 200 with the resource's data ($(jq -r .reasonCode "$out/guarded-response.json"))"
else
  fail "guarded: status $(cat "$out/guarded-status.txt"), no resource data in the answer"
fi
if [ -s "$out/guarded-guard-record.jsonl" ]; then
  pass "guarded: the guard recorded the allowed decision (rule $(jq -r .payload.rule_id "$out/guarded-guard-record.jsonl" | head -1), event $(jq -r .correlation_id "$out/guarded-guard-record.jsonl" | head -1))"
else
  fail "guarded: the guard has no allowed decision event at the time of request $guarded_id"
fi
gb=$(allowed "$out/guarded-stats-guard-before.txt"); ga=$(allowed "$out/guarded-stats-guard-after.txt")
rb=$(allowed "$out/guarded-stats-resource-before.txt"); ra=$(allowed "$out/guarded-stats-resource-after.txt")
if [ -n "$ga" ] && [ -n "$ra" ] && [ "$ga" -gt "${gb:-0}" ] && [ "$ra" -gt "${rb:-0}" ]; then
  pass "guarded: both hops were admitted by identity under mutual TLS (rbac.allowed: guard's sidecar $gb -> $ga, resource's sidecar $rb -> $ra)"
else
  fail "guarded: rbac.allowed did not rise at both sidecars (guard ${gb:-?} -> ${ga:-?}, resource ${rb:-?} -> ${ra:-?})"
fi
# The token store's client, as the zone seeds it (STORE_CLIENT_ID); the resource must have served it.
store_client=${STORE_CLIENT_ID:-ztd-store}
echo "$store_client" > "$out/expected-store-client.txt"
served_client=$(jq -r .client_id "$out/guarded-resource-record.jsonl" 2>/dev/null | head -1)
if [ -s "$out/guarded-resource-record.jsonl" ] && [ "$served_client" = "$store_client" ]; then
  pass "guarded: the resource recorded request $guarded_id with the token store's client $store_client (the substituted token, which only the guard obtains)"
else
  fail "guarded: the resource's record of $guarded_id names client '${served_client:-none}', not the token store's $store_client"
fi

echo "== 2. Direct calls to the resource, skipping the guard"
probe_job() { # probe_job NAME MESHED [POD LABELS]
  local labels=${3:-app.kubernetes.io/name: ztd-guard}
  local inject='"sidecar.istio.io/nativeSidecar": "true"'
  # Not ${node:+...} in the manifest: its first closing brace would end the expansion.
  local selector=""
  [ -z "$node" ] || selector="nodeSelector: {kubernetes.io/hostname: $node}"
  [ "$2" = yes ] || inject='"sidecar.istio.io/inject": "false"'
  k apply -f - <<EOF >/dev/null
apiVersion: batch/v1
kind: Job
metadata:
  name: $1
  labels: {ztd.facis.io/probe-run: "$run"}
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 600
  ttlSecondsAfterFinished: 60
  template:
    metadata:
      labels: {$labels, spiffe.io/spire-managed-identity: "true", ztd.facis.io/probe: "true", ztd.facis.io/probe-run: "$run"}
      annotations: {$inject}
    spec:
      serviceAccountName: ztd-participant
      automountServiceAccountToken: false
      restartPolicy: Never
      $selector
      securityContext: {runAsNonRoot: true, runAsUser: 70, runAsGroup: 70, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: probe
          image: "$image"
          command: [/bin/bash, -c, "trap 'exit 0' TERM; while :; do sleep 10 & wait \$!; done"]
          readinessProbe: {exec: {command: [/bin/sh, -c, "exit 1"]}}
          resources: {requests: {cpu: 10m, memory: 32Mi}, limits: {memory: 128Mi}}
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
EOF
}
attempt() { # attempt JOB OUT HOST: POST /demo to the Service HOST from the probe, raw HTTP, no token
  local raw="POST /demo HTTP/1.1\r\nHost: $3:8080\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}"
  k exec "job/$1" -c probe -- timeout 15 /bin/bash -c "exec 3<>/dev/tcp/$3/8080 && printf '$raw' >&3 && cat <&3" > "$2" 2>&1 || true
}
started() { [ "$(k get pod -l "job-name=$1" -o jsonpath='{.items[0].status.containerStatuses[?(@.name=="probe")].started}' 2>/dev/null)" = true ]; }
wait_started() { for _ in $(seq 1 90); do started "$1" && return 0; sleep 2; done; return 1; }
probes_from=$(date -u +%Y-%m-%dT%H:%M:%SZ)
unmeshed_refused=no
for probe in meshed unmeshed tokenless; do
  name="ztd-bypass-$probe-$run"
  meshed=yes; [ "$probe" = unmeshed ] && meshed=no
  host=ztd-protected-resource labels=""
  if [ "$probe" = tokenless ]; then
    host=ztd-guard labels="app.kubernetes.io/name: ztd-participant, app.kubernetes.io/instance: $participant_instance"
  fi
  # A cold admission cache answers ADM-PROVIDER-DOWN once; the same request is sent again.
  created=no
  for _ in 1 2 3 4 5; do
    if probe_job "$name" "$meshed" "$labels" 2> "$out/$probe-apply.txt"; then created=yes; break; fi
    grep -q ADM-PROVIDER-DOWN "$out/$probe-apply.txt" || break
    sleep 10
  done
  if [ "$created" = no ]; then fail "$probe probe: not created: $(tr '\n' ' ' < "$out/$probe-apply.txt")"; continue; fi
  if ! wait_started "$name"; then
    k get events --field-selector "involvedObject.kind=Job,involvedObject.name=$name" -o json | jq '[.items[] | {reason, message}]' > "$out/$probe-events.json"
    # A pod without a sidecar cannot exist in a plane namespace: the zone's admission rule refuses it.
    if [ "$probe" = unmeshed ] && grep -q "proxy-takes-spire-socket" "$out/$probe-events.json"; then
      pass "unmeshed direct caller: refused at admission (ValidatingAdmissionPolicy proxy-takes-spire-socket), so no workload without the mesh can call the resource from $ns"
      unmeshed_refused=yes
    else
      fail "$probe probe: never started (events in $probe-events.json)"
    fi
    continue
  fi
  stats "$out/$probe-stats-before.txt"
  attempt "$name" "$out/$probe-response.txt" "$host"
  sleep 3
  stats "$out/$probe-stats-after.txt"
  k logs "$resource_pod" -c istio-proxy --since=2m 2>/dev/null | grep -E '"response_code":"?403|rbac_access_denied|filter_chain_not_found|NR ' > "$out/$probe-receiver-log.txt" || true
  diff "$out/$probe-stats-before.txt" "$out/$probe-stats-after.txt" > "$out/$probe-stats-diff.txt" || true
done
b=$(grep 'http.inbound_0.0.0.0_8080;.rbac.denied' "$out/meshed-stats-before.txt" 2>/dev/null | awk -F': ' '{print $2}' || true)
a=$(grep 'http.inbound_0.0.0.0_8080;.rbac.denied' "$out/meshed-stats-after.txt" 2>/dev/null | awk -F': ' '{print $2}' || true)
if grep -q 'RBAC: access denied' "$out/meshed-response.txt" 2>/dev/null && [ -n "$a" ] && [ "$a" -gt "${b:-0}" ]; then
  pass "meshed direct call (Participant identity): 403 RBAC: access denied; the resource's sidecar counted it (rbac.denied $b -> $a)"
else
  fail "meshed direct call: response $(head -c 200 "$out/meshed-response.txt" 2>/dev/null | tr '\r\n' '  '), rbac.denied ${b:-?} -> ${a:-?}"
fi
if [ "$unmeshed_refused" = no ] && [ -f "$out/unmeshed-stats-diff.txt" ]; then
  nb=$(grep 'no_filter_chain_match' "$out/unmeshed-stats-before.txt" | awk -F': ' '{print $2}' || true)
  na=$(grep 'no_filter_chain_match' "$out/unmeshed-stats-after.txt" | awk -F': ' '{print $2}' || true)
  # The receiver must have counted the refusal: a plaintext connection to a STRICT inbound matches
  # no filter chain, or fails its TLS handshake. A changed byte count alone is not a denial.
  eb=$(grep 'ssl.connection_error' "$out/unmeshed-stats-before.txt" | awk -F': ' '{print $2}' || true)
  ea=$(grep 'ssl.connection_error' "$out/unmeshed-stats-after.txt" | awk -F': ' '{print $2}' || true)
  if ! grep -q '^HTTP/1.1 200' "$out/unmeshed-response.txt" && { [ "${na:-0}" -gt "${nb:-0}" ] || [ "${ea:-0}" -gt "${eb:-0}" ]; }; then
    pass "unmeshed direct call (plaintext): no answer from the resource; its sidecar counted the refusal (no_filter_chain_match ${nb:-0} -> ${na:-0}, ssl.connection_error ${eb:-0} -> ${ea:-0})"
  else
    fail "unmeshed direct call: $(head -c 200 "$out/unmeshed-response.txt" | tr '\r\n' '  '); no receiver-side denial counter increased"
  fi
fi
# The guard itself refuses the Participant's identity when the request carries no token, and records
# why under the correlation id it gave the caller. The code is TOK-MISSING; a guard older than the
# reason-code registry writes its runtime code, token_absent.
tokenless_id=$(tr -d '\r' < "$out/tokenless-response.txt" 2>/dev/null | awk -F': ' 'tolower($1) == "x-request-id" {print $2}' | head -1)
tokenless_code=$(grep -oE '"reason_code":"(TOK-MISSING|token_absent)"' "$out/tokenless-response.txt" 2>/dev/null | cut -d'"' -f4 | head -1)
k logs "$guard_pod" -c guard --since=10m 2>/dev/null \
  | jq -cR --arg id "$tokenless_id" --arg code "$tokenless_code" 'fromjson? | select(.kind == "decision" and .correlation_id == $id and .payload.state == "denied" and .payload.reason_code == $code)' \
  > "$out/tokenless-guard-record.jsonl" 2>/dev/null || true
if grep -q '^HTTP/1.1 401' "$out/tokenless-response.txt" 2>/dev/null && [ -n "$tokenless_id" ] && [ -n "$tokenless_code" ] \
  && ! grep -q 'safeData' "$out/tokenless-response.txt" && [ -s "$out/tokenless-guard-record.jsonl" ]; then
  pass "tokenless call through the guard (Participant identity, no token): 401 $tokenless_code, no resource data; the guard recorded the denial under the caller's correlation id $tokenless_id"
else
  fail "tokenless call through the guard: response $(head -c 200 "$out/tokenless-response.txt" 2>/dev/null | tr '\r\n' '  '); no denied event of the guard under ${tokenless_id:-no correlation id}"
fi
k logs "$resource_pod" -c ztd-protected-resource --since-time="$probes_from" > "$out/resource-app-log-during-probes.txt" 2>/dev/null || true
if [ ! -s "$out/resource-app-log-during-probes.txt" ]; then
  pass "the resource application logged nothing while the probes called it: no direct request reached it"
else
  fail "the resource application logged $(wc -l < "$out/resource-app-log-during-probes.txt") line(s) during the probes"
fi

echo "== 3. The namespace as found"
trap - EXIT
cleanup
snapshot "$out/after"
if diff "$out/before/objects.json" "$out/after/objects.json" > "$out/objects.diff" && diff "$out/before/releases.json" "$out/after/releases.json" >> "$out/objects.diff"; then
  pass "no policy, workload, Service or release of $ns changed (resourceVersions equal)"
else
  fail "the namespace changed: see objects.diff"
fi
echo "finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$out/run.txt"
echo "verdict: $([ "$failures" = 0 ] && echo PASS || echo "FAIL ($failures)")" | tee -a "$out/verdict.txt"
exit "$failures"
