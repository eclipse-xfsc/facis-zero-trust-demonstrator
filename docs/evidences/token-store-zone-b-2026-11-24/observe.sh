#!/usr/bin/env bash
# The token store on a live zone, without changing a release: its health and mesh identity read back,
# then the replay check of its internal API called by a probe that holds the guard's identity.
#
#   ZTD_CONFIRM_CONTEXT=<context> observe.sh --namespace NS --probe-image IMAGE --out DIR
#
# Read only: the pod's status, the application's /healthz and /readyz on its ops port (port-forward), the proxy's
# certificate (public part, verified against the SPIRE server's bundle) and the shape of the request records.
# The probe: one Job under the guard's service account with the guard's pod label (the store's network
# policy and its AuthorizationPolicy admit nothing else), meshed, never a Service endpoint (its
# readiness never passes), deleted on exit. It calls POST /internal/replay-check only, with made-up
# proof values for the route's target: no token is requested, read or substituted. Each admitted call
# leaves one row in the replay record, which the store sweeps after its 90 s window.
# Exit status: the number of failed checks; 125 refused.
set -euo pipefail
ns="" image="" out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --namespace) ns=$2; shift 2 ;;
    --probe-image) image=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 125 ;;
  esac
done
context=$(kubectl config current-context)
if [ -z "$ns" ] || [ -z "$image" ] || [ -z "$out" ] || [ "${ZTD_CONFIRM_CONTEXT:-}" != "$context" ]; then
  echo "refused: namespace, probe image, out and ZTD_CONFIRM_CONTEXT=$context are required" >&2; exit 125
fi
mkdir -p "$out/before" "$out/after"
run=$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')
job="ztd-replay-probe-$run"
k() { kubectl -n "$ns" "$@"; }
failures=0
pass() { echo "PASS  $*" | tee -a "$out/verdict.txt"; }
fail() { echo "FAIL  $*" | tee -a "$out/verdict.txt"; failures=$((failures + 1)); }
: > "$out/verdict.txt"
cleanup() {
  k delete job -l "ztd.facis.io/probe-run=$run" --wait=true --timeout=120s >/dev/null 2>&1 || true
  k wait --for=delete pod -l "ztd.facis.io/probe-run=$run" --timeout=120s >/dev/null 2>&1 || true
  [ -z "${pf:-}" ] || kill "$pf" 2>/dev/null || true
  local left
  if left=$(k get job,pod -l "ztd.facis.io/probe-run=$run" -o name 2>/dev/null) && [ -z "$left" ]; then
    pass "cleanup: no probe Job or Pod of run $run remains"
  else
    fail "cleanup: probe objects of run $run remain"
  fi
}
trap 'cleanup; exit $(( failures > 0 ? failures : 1 ))' EXIT
snapshot() {
  k get authorizationpolicy,peerauthentication,networkpolicy,deployment,service -o json \
    | jq '[.items[] | {kind, name: .metadata.name, resourceVersion: .metadata.resourceVersion, generation: .metadata.generation}]' > "$1/objects.json"
  helm list -n "$ns" -o json | jq '[.[] | {name, revision, status, chart}]' > "$1/releases.json"
}
snapshot "$out/before"
store=$(k get pod -l app.kubernetes.io/name=ztd-token-store,app.kubernetes.io/component=server -o jsonpath='{.items[0].metadata.name}')
td=$(k get deploy ztd-token-store -o json | jq -r '.spec.template.spec.containers[0].env[] | select(.name == "TOKEN_STORE_REPLAY_CALLERS") | .value' | sed -E 's|^spiffe://([^/]+)/.*|\1|')
{ echo "context: $context"; echo "namespace: $ns"; echo "store pod: $store"; echo "probe run: $run"; echo "probe image: $image"; echo "commit: $(git -C "$(dirname "$0")" rev-parse HEAD 2>/dev/null)"; echo "started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"; } > "$out/run.txt"

echo "== 1. Health and mesh identity (read only)"
k get pod "$store" -o json | jq '{name: .metadata.name, node: .spec.nodeName, started: .status.startTime, serviceAccount: .spec.serviceAccountName,
  ready: ([.status.conditions[] | select(.type == "Ready") | .status] | first),
  openbaoAuth: ([.spec.containers[0].env[] | select(.name | test("^TOKEN_STORE_OPENBAO_AUTH_(ROLE|MOUNT)$")) | {(.name): .value}] | add),
  containers: [(.status.initContainerStatuses // [])[], .status.containerStatuses[] | {name, ready, restartCount, image: .imageID}],
  readiness: .spec.containers[0].readinessProbe.httpGet, liveness: .spec.containers[0].livenessProbe.httpGet}' > "$out/pod.json"
if jq -e '.ready == "True" and (.containers | length > 0) and ([.containers[] | .ready and .restartCount == 0] | all)' "$out/pod.json" >/dev/null; then
  pass "the store's pod is Ready, no container restarted since $(jq -r .started "$out/pod.json")"
else
  fail "the store's pod is not Ready or a container restarted: $(jq -c .containers "$out/pod.json")"
fi
# A free local port, and the forward must be alive before it is asked: another listener must not answer.
port=$((20000 + RANDOM % 20000))
kubectl -n "$ns" port-forward "pod/$store" "$port:9090" > "$out/port-forward.txt" 2>&1 & pf=$!
for _ in $(seq 1 20); do grep -q "Forwarding from 127.0.0.1:$port" "$out/port-forward.txt" && break; sleep 0.5; done
if ! kill -0 "$pf" 2>/dev/null || ! grep -q "Forwarding from 127.0.0.1:$port" "$out/port-forward.txt"; then fail "the port-forward to $store did not start"; exit 1; fi
curl -s -m 5 -o "$out/readyz.json" -w '%{http_code}\n' http://127.0.0.1:$port/readyz > "$out/readyz-status.txt" || true
curl -s -m 5 -o /dev/null -w '%{http_code}\n' http://127.0.0.1:$port/healthz > "$out/healthz-status.txt" || true
kill "$pf" 2>/dev/null || true; pf=""; rm -f "$out/port-forward.txt"
if [ "$(cat "$out/readyz-status.txt")" = 200 ] && jq -e '.ready and .checks.postgres == "ok" and .checks.openbao == "ok"' "$out/readyz.json" >/dev/null; then
  pass "readiness is green with PostgreSQL and OpenBao reachable: $(jq -c .checks "$out/readyz.json")"
else
  fail "readiness: status $(cat "$out/readyz-status.txt"), $(head -c 200 "$out/readyz.json")"
fi
[ "$(cat "$out/healthz-status.txt")" = 200 ] && pass "liveness answers 200" || fail "liveness: $(cat "$out/healthz-status.txt")"
# The certificate the store's proxy serves: only the public chain is read from the proxy.
k exec "$store" -c istio-proxy -- pilot-agent request GET 'config_dump?resource=dynamic_active_secrets' 2>/dev/null \
  | jq -r '[.. | objects | select(.name? == "default") | .secret.tls_certificate.certificate_chain.inline_bytes] | first' | base64 -d > "$out/identity-chain.pem" 2>/dev/null || true
openssl x509 -in "$out/identity-chain.pem" -noout -issuer -ext subjectAltName -dates > "$out/identity.txt" 2>/dev/null || true
# The SPIRE server's published X.509 authorities (the bundle the agents and the mesh trust).
kubectl -n spire-system get configmap spire-bundle -o jsonpath='{.data.bundle\.spiffe}' \
  | jq -r '.keys[] | select(.use == "x509-svid") | "-----BEGIN CERTIFICATE-----\n" + .x5c[0] + "\n-----END CERTIFICATE-----"' > "$out/spire-bundle.pem" 2>/dev/null || true
want="URI:spiffe://$td/ns/$ns/sa/ztd-token-store"
if grep -q "$want" "$out/identity.txt" && openssl verify -CAfile "$out/spire-bundle.pem" -untrusted "$out/identity-chain.pem" "$out/identity-chain.pem" > "$out/identity-verify.txt" 2>&1; then
  pass "the store's proxy holds ${want#URI:} in a certificate that verifies against the SPIRE server's bundle ($(grep '^issuer' "$out/identity.txt"))"
else
  fail "the store's proxy certificate: $(tr '\n' ' ' < "$out/identity.txt") $(tail -1 "$out/identity-verify.txt" 2>/dev/null)"
fi
rm -f "$out/identity-chain.pem" "$out/spire-bundle.pem"
k logs "$store" -c server --tail=5000 2>/dev/null \
  | jq -cR 'fromjson? | select(.msg == "request") | {path, status, has_id: ((.correlation_id // "") != "")}' | sort | uniq -c > "$out/request-records.txt" || true
if [ -s "$out/request-records.txt" ] && ! grep -q '"has_id":false' "$out/request-records.txt"; then
  pass "every request record of the store's last 5000 log lines carries a correlation id ($(awk '{n += $1} END {print n}' "$out/request-records.txt") records)"
else
  fail "request records without a correlation id, or none: see request-records.txt"
fi

echo "== 2. The replay check, called as the guard"
for _ in 1 2 3 4 5; do
  if k apply -f - <<YAML >/dev/null 2> "$out/probe-apply.txt"
apiVersion: batch/v1
kind: Job
metadata:
  name: $job
  labels: {ztd.facis.io/probe-run: "$run"}
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 600
  ttlSecondsAfterFinished: 60
  template:
    metadata:
      labels: {app.kubernetes.io/name: ztd-guard, spiffe.io/spire-managed-identity: "true", ztd.facis.io/probe: "true", ztd.facis.io/probe-run: "$run"}
      annotations: {"sidecar.istio.io/nativeSidecar": "true"}
    spec:
      serviceAccountName: ztd-guard
      automountServiceAccountToken: false
      restartPolicy: Never
      securityContext: {runAsNonRoot: true, runAsUser: 70, runAsGroup: 70, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: probe
          image: "$image"
          command: [/bin/bash, -c, "trap 'exit 0' TERM; while :; do sleep 10 & wait \$!; done"]
          readinessProbe: {exec: {command: [/bin/sh, -c, "exit 1"]}}
          resources: {requests: {cpu: 10m, memory: 32Mi}, limits: {memory: 128Mi}}
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
YAML
  then break; fi
  # A cold admission cache answers ADM-PROVIDER-DOWN once; the same request is sent again.
  grep -q ADM-PROVIDER-DOWN "$out/probe-apply.txt" || break
  sleep 10
done
started() { [ "$(k get pod -l "job-name=$job" -o jsonpath='{.items[0].status.containerStatuses[?(@.name=="probe")].started}' 2>/dev/null)" = true ]; }
for _ in $(seq 1 90); do started && break; sleep 2; done
if ! started; then fail "the probe never started: $(tr '\n' ' ' < "$out/probe-apply.txt")"; exit 1; fi
# The probe must not be an endpoint of the guard's Service, whose label it carries.
probe_ip=$(k get pod -l "job-name=$job" -o jsonpath='{.items[0].status.podIP}')
k get endpointslices -l kubernetes.io/service-name=ztd-guard -o json > "$out/guard-endpoints.raw" || true
jq --arg ip "$probe_ip" '{slices: (.items | length), probeEntries: [.items[].endpoints[]? | select(.addresses | index($ip)) | .conditions], readyEndpoints: ([.items[].endpoints[]? | select(.conditions.ready)] | length)}' "$out/guard-endpoints.raw" > "$out/guard-endpoints.json" 2>/dev/null || true
rm -f "$out/guard-endpoints.raw"
if [ -n "$probe_ip" ] && jq -e '.slices > 0 and .readyEndpoints > 0 and ([.probeEntries[] | .ready] | all(. == false))' "$out/guard-endpoints.json" >/dev/null 2>&1; then
  pass "the probe is not a ready endpoint of the guard's Service ($(jq -c . "$out/guard-endpoints.json"))"
else
  fail "the probe is a ready endpoint of the guard's Service"; exit 1
fi
from=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# Inside the probe: one line per call, "<case> <status> <body>". The proof values are made up; the
# target is the guard's route (the store refuses a guard any other).
k exec "job/$job" -c probe -- timeout 60 /bin/bash -c '
call() { # call CASE JTI IAT HTU
  local body="{\"jkt\":\"$JKT\",\"htm\":\"POST\",\"htu\":\"$4\",\"jti\":\"$2\",\"iat\":$3}" answer
  answer=$( { exec 3<>/dev/tcp/ztd-token-store/8080 && printf "POST /internal/replay-check HTTP/1.1\r\nHost: ztd-token-store:8080\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s" ${#body} "$body" >&3 && cat <&3; } 2>&1 | tr -d "\r")
  printf "%s %s %s\n" "$1" "$(printf "%s" "$answer" | head -1 | cut -d" " -f2)" "$(printf "%s" "$answer" | grep -o "{.*}" | head -1)"
}
JKT=$(head -c 32 /dev/urandom | base64 | tr "+/" "-_" | tr -d "=\n")
now=$(date +%s); target=http://ztd-guard:8080/demo; id=zone-proof-'"$run"'
call first "$id-a" "$now" "$target"
call second "$id-a" "$now" "$target"
for i in $(seq 1 20); do call concurrent "$id-b" "$now" "$target" & done; wait
call stale "$id-c" "$((now - 120))" "$target"
call early "$id-d" "$((now + 120))" "$target"
call off-route "$id-e" "$now" http://elsewhere.invalid/demo
' > "$out/replay-calls.txt" 2> "$out/replay-exec.txt" || true
sleep 3
k logs "$store" -c server --since-time="$from" 2>/dev/null \
  | jq -cR 'fromjson? | select(.msg == "request" and .path == "/internal/replay-check") | {time, status, correlation_id}' > "$out/replay-store-records.jsonl" || true
got() { grep -c "^$1 $2 " "$out/replay-calls.txt" || true; }
[ "$(got first 200)" = 1 ] && grep -q '^first 200 {"fresh":true}' "$out/replay-calls.txt" && pass "a proof not seen before is admitted (200, fresh)" || fail "first use: $(grep '^first' "$out/replay-calls.txt")"
grep -q '^second 409 .*"reason_code":"TOK-REPLAY"' "$out/replay-calls.txt" && pass "the same proof again is refused: 409 TOK-REPLAY" || fail "second use: $(grep '^second' "$out/replay-calls.txt")"
if [ "$(grep -c '^concurrent ' "$out/replay-calls.txt")" = 20 ] && [ "$(grep -c '^concurrent 200 {"fresh":true}$' "$out/replay-calls.txt")" = 1 ] \
  && [ "$(grep -c '^concurrent 409 .*"reason_code":"TOK-REPLAY"' "$out/replay-calls.txt")" = 19 ]; then
  pass "of 20 concurrent identical proofs exactly one is admitted, 19 refused TOK-REPLAY"
else
  fail "concurrent: $(got concurrent 200) admitted, $(got concurrent 409) refused of 20"
fi
grep -q '^stale 422 .*TOK-PROOF-INVALID' "$out/replay-calls.txt" && grep -q '^early 422 .*TOK-PROOF-INVALID' "$out/replay-calls.txt" \
  && pass "a proof issued 120 s ago and one dated 120 s ahead are refused: 422 TOK-PROOF-INVALID (the window is 60 s back, 30 s ahead)" \
  || fail "window: $(grep -E '^(stale|early)' "$out/replay-calls.txt" | tr '\n' ' ')"
grep -q '^off-route 403 .*TOK-ROUTE-DENIED' "$out/replay-calls.txt" && pass "a target outside the guard's routes is refused: 403 TOK-ROUTE-DENIED" || fail "off-route: $(grep '^off-route' "$out/replay-calls.txt")"
# Every refusal's correlation id is in the store's own record of the request, with the same status.
missing=0
while read -r _ status body; do
  [ "$status" = 200 ] && continue
  cid=$(printf '%s' "$body" | jq -r '.correlation_id // empty' 2>/dev/null)
  if [ -z "$cid" ] || [ "$(jq -c --arg id "$cid" --arg s "$status" 'select(.correlation_id == $id and (.status | tostring) == $s)' "$out/replay-store-records.jsonl" | wc -l | tr -d ' ')" != 1 ]; then missing=$((missing + 1)); fi
done < "$out/replay-calls.txt"
records=$(wc -l < "$out/replay-store-records.jsonl" | tr -d ' ')
if [ "$missing" = 0 ] && [ "$records" = 25 ] && [ "$(wc -l < "$out/replay-calls.txt" | tr -d ' ')" = 25 ]; then
  pass "the store recorded the 25 calls, each of the 23 refusals once under the correlation id its answer carried, with the same status"
else
  fail "store records: $records of 25, $missing refusal(s) without a matching record"
fi

echo "== 3. The namespace as found"
trap - EXIT
cleanup
snapshot "$out/after"
if diff "$out/before/objects.json" "$out/after/objects.json" > "$out/objects.diff" && diff "$out/before/releases.json" "$out/after/releases.json" >> "$out/objects.diff"; then
  pass "no AuthorizationPolicy, PeerAuthentication, NetworkPolicy, Deployment, Service or Helm release of $ns changed (resourceVersions and revisions equal)"
else
  fail "the namespace changed: see objects.diff"
fi
echo "finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$out/run.txt"
echo "verdict: $([ "$failures" = 0 ] && echo PASS || echo "FAIL ($failures)")" | tee -a "$out/verdict.txt"
exit "$failures"
