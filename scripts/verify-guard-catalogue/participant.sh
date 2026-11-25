# shellcheck shell=bash disable=SC2154 # the variables and helpers are verify.sh's
# The participant-backend mock proof of verify.sh --participant, sourced by it once the chain is up:
# the Participant service (services/participant, the working tree's image) installed from the
# application-service chart in token mode, in the mesh, configured with the Connector's and the
# guard's addresses and nothing else (its network policy opens no other destination). It bootstraps
# by itself (registration check, presentation, token), is asked for one report through the guard and
# for one more while the policy engine is away, and its IF-01 v2 lines are read back from the feed
# bridge. Records:
#   run.json            the two request ids, the Participant's run id, identity and client, the endpoints
#   config.json         the PARTICIPANT_* environment of the running Deployment
#   state.json          GET /state once ready
#   served.http, refused.http   the Participant's answers
#   feed.jsonl          every event the UI's identity read from the bridge's /v2/events
#   hops.jsonl          the receivers' sidecar request counters by caller and receiver identity
#   resource.log        the Protected Resource's log
step "The participant-backend mock in token mode, from its chart"
participant_url=http://ztd-participant:8085
participant_id=spiffe://$td/ns/$ns/sa/ztd-participant
# The client the Connector registered for the guard's audience in this run, as mounted credentials;
# the outcome signer is the run's fixture verifier, as for the store's route.
jq -n --arg id "$viewer_id" --arg secret "$viewer_secret" '{client_id: $id, client_secret: $secret}' > "$work/credentials.json"
kubectl -n "$ns" create secret generic participant-mock --from-file=credentials.json="$work/credentials.json" \
  --from-file=outcome-key.pem="$work/issuer-private.pem" >/dev/null
cat > "$work/participant-values.yaml" <<EOF
name: ztd-participant
image: {repository: $reg/participant, digest: "${digest[participant]}"}
port: 8085
eventSource: participant-b
serviceAccount: {create: false, name: ztd-participant}
trustDomain: $td
callers: [{namespace: $ns, name: operator}]
podAnnotations: {sidecar.istio.io/nativeSidecar: "true"}
env:
  PARTICIPANT_ADAPTER_MODE: token
  PARTICIPANT_CONNECTOR_URL: $connector_url
  PARTICIPANT_RESOURCE_URL: $published
  PARTICIPANT_AUDIENCE: $inbound
  PARTICIPANT_CREDENTIALS_FILE: /var/run/participant/credentials.json
  PARTICIPANT_OUTCOME_ISSUER: $vp_issuer
  PARTICIPANT_OUTCOME_KID: $vp_kid
  PARTICIPANT_OUTCOME_KEY_FILE: /var/run/participant/outcome-key.pem
  PARTICIPANT_OUTCOME_ROLE: viewer
secretMounts: [{name: participant, secretName: participant-mock, mountPath: /var/run/participant}]
networkPolicy:
  ingressFrom: [{podSelector: {matchLabels: {app.kubernetes.io/name: operator}}}]
  egress:
    - to:
        - podSelector: {matchLabels: {app.kubernetes.io/name: ztd-connector}}
        - podSelector: {matchLabels: {app.kubernetes.io/name: ztd-guard}}
      ports: [{port: 8080, protocol: TCP}]
    - to: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: istio-system}}, podSelector: {matchLabels: {app: istiod}}}]
      ports: [{port: 15012, protocol: TCP}]
EOF
if helm install ztd-participant deployment/helm/application-service -n "$ns" -f "$work/participant-values.yaml" --wait --timeout 5m \
  > "$out/participant-install.txt" 2>&1; then
  pass "the Participant is running in the mesh from the application-service chart"
else
  fail "participant install: $(tail -3 "$out/participant-install.txt")"
fi
kubectl -n "$ns" get deploy ztd-participant -o json \
  | jq '[.spec.template.spec.containers[0].env[] | select(.name | startswith("PARTICIPANT_")) | {(.name): .value}] | add' > "$out/config.json"
kubectl -n "$ns" get networkpolicy ztd-participant -o json | jq '{spec}' > "$out/participant-networkpolicy.json"
if [ "$(jq -r '.PARTICIPANT_ADAPTER_MODE + " " + .PARTICIPANT_CONNECTOR_URL + " " + .PARTICIPANT_RESOURCE_URL' "$out/config.json")" = "token $connector_url $published" ]; then
  pass "configured in token mode with the Connector ($connector_url) and its guard ($published); its network policy opens those two and istiod"
else
  fail "participant configuration: $(jq -c . "$out/config.json")"
fi

step "The scenario: bootstrap, a served request, a request refused while the policy engine is away"
state() { kubectl -n "$ns" exec operator -c curl -- curl -sS -m 10 "$participant_url/state" 2>/dev/null > "$out/state.json" && [ "$(jq -r .state "$out/state.json")" = ready ]; }
if wait_until 90 state; then
  pass "the Participant bootstrapped by itself: $(jq -r '[.history[].state] | join(" > ")' "$out/state.json")"
else
  fail "the Participant is not ready: $(jq -c '{state, lastErrorCode}' "$out/state.json" 2>/dev/null)"
fi
# ask NAME ID: one report through the Participant, under an id the run chose; prints the status.
ask() {
  ccurl operator "$out/$1.http" -X POST -H 'Content-Type: application/json' \
    --data "$(jq -nc --arg id "$2" '{requestId: $id, correlationId: $id, resource: "sample-report", action: "read"}')" "$participant_url/demo"
}
resource_log() { kubectl -n "$ns" logs deploy/ztd-protected-resource -c ztd-protected-resource 2>/dev/null || true; }
served_id=$(hex 16)
code=$(ask served "$served_id")
if [ "$code" = 200 ] && [ "$(body_of "$out/served.http" | jq -r '.mode + " " + .outcome + " " + .correlationId')" = "token success $served_id" ] &&
  [ -n "$(body_of "$out/served.http" | jq -r '.safeData.summary.id // .safeData.report.id // empty')" ]; then
  pass "served: 200 with the resource's data ($(body_of "$out/served.http" | jq -r .reasonCode)) under $served_id"
else
  fail "served: $code $(body_of "$out/served.http" | head -c 300)"
fi
# Fail closed: without the policy engine the guard refuses, and the Participant reports it. The
# evaluator's lines so far are kept first: its pod is replaced, and a new pod is a new run.
sleep 2
logs policy-evaluator > "$out/policy-events.jsonl" || true
kubectl -n "$ns" scale deploy/ztd-policy-evaluator --replicas=0 >/dev/null
kubectl -n "$ns" wait --for=delete pod -l app.kubernetes.io/name=ztd-policy-evaluator --timeout=120s >/dev/null 2>&1 || true
refused_id=$(hex 16)
code=$(ask refused "$refused_id")
kubectl -n "$ns" scale deploy/ztd-policy-evaluator --replicas=1 >/dev/null
kubectl -n "$ns" rollout status deploy/ztd-policy-evaluator --timeout=180s >/dev/null
sleep 2
resource_log > "$out/resource.log"
if [ "$code" = 503 ] && [ "$(body_of "$out/refused.http" | jq -r '.outcome + " " + .reasonCode + " " + (.safeData | length | tostring)')" = "unavailable TOKEN_RESOURCE_UNAVAILABLE 0" ] &&
  ! grep -Fq "$refused_id" "$out/resource.log"; then
  pass "refused: 503 TOKEN_RESOURCE_UNAVAILABLE without data under $refused_id, nothing at the resource"
else
  fail "refused: $code $(body_of "$out/refused.http" | head -c 300)"
fi
if grep -Fq "$served_id" "$out/resource.log"; then pass "the resource's record holds $served_id"; else fail "the resource has no record of $served_id"; fi

step "The hops ran under mutual TLS between the workloads' identities"
# Each receiver's sidecar counts the requests it served by the caller's and its own certificate identity.
for receiver in ztd-connector ztd-guard ztd-protected-resource; do
  kubectl -n "$ns" exec "deploy/$receiver" -c istio-proxy -- pilot-agent request GET stats/prometheus 2>/dev/null \
    | grep '^istio_requests_total{.*reporter="destination"' || true
done | jq -cR '. as $line | ([scan("([a-z_]+)=\"([^\"]*)\"") | {(.[0]): .[1]}] | add) as $l
  | {source_workload: $l.source_workload, source: $l.source_principal, destination_workload: $l.destination_workload, destination: $l.destination_principal,
     security: $l.connection_security_policy, response_code: $l.response_code, requests: ($line | split(" ") | last | tonumber)}' > "$out/hops.jsonl"
kubectl -n "$ns" get peerauthentication,authorizationpolicy -o json | jq '[.items[] | {kind, name: .metadata.name, spec}]' > "$out/mesh-policies.json"
# hop FROM TO: requests answered 200 between those service accounts over mutual TLS.
hop() {
  jq -s --arg s "spiffe://$td/ns/$ns/sa/$1" --arg d "spiffe://$td/ns/$ns/sa/$2" \
    '[.[] | select(.source == $s and .destination == $d and .security == "mutual_tls" and .response_code == "200") | .requests] | add // 0' "$out/hops.jsonl"
}
for pair in "ztd-participant ztd-connector" "ztd-participant ztd-guard" "ztd-guard ztd-protected-resource"; do
  # shellcheck disable=SC2086 # two words
  n=$(hop $pair)
  if [ "$n" -ge 1 ]; then pass "${pair% *} -> ${pair#* }: $n request(s) served over mutual_tls between the two SPIFFE identities"; else fail "${pair% *} -> ${pair#* }: no request over mutual TLS recorded"; fi
done

step "The Participant's events on the feed bridge, read by the UI's identity"
events_of() { kubectl -n "$ns" logs "deploy/$1" -c "$1" 2>/dev/null | jq -cR 'fromjson? | select(.version? == 2 and .run_id? != null)'; }
events_of ztd-participant > "$out/participant-events.jsonl"
events_of ztd-protected-resource > "$out/resource-events.jsonl"
logs guard > "$out/guard-events.jsonl"
feed_bridge_up
# The operator's sidecar can learn of the new bridge a moment after its rollout ("no healthy upstream"):
# the post is repeated until the bridge answers it.
ingest() {
  cat "$out/participant-events.jsonl" "$out/resource-events.jsonl" "$out/guard-events.jsonl" "$out/policy-events.jsonl" | kubectl -n "$ns" exec -i operator -c curl -- \
    curl -sS -m 30 -X POST -H 'Content-Type: application/x-ndjson' --data-binary @- "$bridge/ingest" > "$out/feed-ingest.json" 2>&1 || true
  jq -e '.accepted' "$out/feed-ingest.json" >/dev/null 2>&1
}
wait_until 60 ingest || true
if [ "$(jq -r '.accepted // 0' "$out/feed-ingest.json" 2>/dev/null)" -gt 0 ]; then pass "ingest by the producer identity: $(cat "$out/feed-ingest.json")"; else fail "ingest: $(head -c 200 "$out/feed-ingest.json")"; fi
: > "$out/feed.jsonl"
for run in $(jq -rR 'fromjson? | .run_id? // empty' "$out/participant-events.jsonl" "$out/resource-events.jsonl" "$out/guard-events.jsonl" "$out/policy-events.jsonl" | sort -u); do
  kubectl -n "$ns" exec ui -c curl -- curl -s -m 3 "$bridge/v2/events?run_id=$run&from_seq=0" 2>/dev/null | sed -n 's/^data: //p' >> "$out/feed.jsonl" || true
done
participant_run=$(jq -r .run_id "$out/participant-events.jsonl" | sort -u)
jq -n --arg served "$served_id" --arg refused "$refused_id" --arg run "$participant_run" --arg id "$participant_id" \
  --arg connector "$connector_url" --arg guard "$published" --arg client "$viewer_id" \
  '{served_id: $served, refused_id: $refused, participant_run_id: $run, participant_identity: $id, connector_url: $connector, guard_url: $guard, client_id: $client}' > "$out/run.json"
# in_feed FILTER: the number of events of the feed that match.
in_feed() { jq -s --arg run "$participant_run" --arg served "$served_id" --arg refused "$refused_id" --arg id "$participant_id" --arg client "$viewer_id" "[.[] | select($1)] | length" "$out/feed.jsonl"; }
# shellcheck disable=SC2016 # jq's variables, here and in by_guard
mine='.run_id == $run and .version == 2 and .kind == "step" and .source == "participant-b"'
if [ "$(in_feed "$mine and .payload.detail == \"registration\" and .payload.state == \"registered\" and .correlation_id == \$run")" -ge 1 ]; then
  pass "feed: the registration event (registered) of run $participant_run"
else
  fail "feed: no registration event of the Participant's run"
fi
if [ "$(in_feed "$mine and .payload.detail == \"status\" and .payload.state == \"ready\" and .correlation_id == \$run")" -ge 1 ] &&
  [ "$(in_feed "$mine and .payload.detail == \"status\" and (.payload.state == \"presenting\" or .payload.state == \"acquiring_token\")")" -ge 2 ]; then
  pass "feed: the status events presenting, acquiring_token and ready of the same run"
else
  fail "feed: the Participant's status events are incomplete"
fi
# The guard's Envoy names each request itself, so its decision does not carry the Participant's id:
# it is the one decision for the Participant's identity and its registered client (the token's subject).
# shellcheck disable=SC2016
by_guard='.source == "guard-b" and .kind == "decision" and .payload.caller_spiffe_id == $id and .payload.token_subject == $client'
if [ "$(in_feed "$mine and .payload.detail == \"request\" and .payload.state == \"success\" and .correlation_id == \$served")" = 1 ] &&
  [ "$(in_feed ".source == \"protected-resource-b\" and .payload.state == \"success\" and .correlation_id == \$served")" = 1 ] &&
  [ "$(in_feed "$by_guard and .payload.state == \"allowed\"")" = 1 ]; then
  pass "feed: the request event (success) and the resource's access event under $served_id, and the guard's one allowed decision for the caller $participant_id with its client's token"
else
  fail "feed: the served request is not on the feed with the resource's access and the guard's decision"
fi
if [ "$(in_feed "$mine and .payload.detail == \"request\" and .payload.state == \"unavailable\" and .payload.reason_code == \"APP-TOKEN-RESOURCE-UNAVAILABLE\" and .correlation_id == \$refused")" = 1 ] &&
  [ "$(in_feed ".correlation_id == \$refused")" = 1 ] &&
  [ "$(in_feed "$by_guard and .payload.state == \"denied\" and .payload.reason_code == \"POL-PDP-UNAVAILABLE\"")" = 1 ] && [ "$(in_feed "$by_guard")" = 2 ]; then
  pass "feed: the refused request (unavailable, APP-TOKEN-RESOURCE-UNAVAILABLE) under $refused_id, no other event under that id, and the guard's one denial POL-PDP-UNAVAILABLE for the same caller and client"
else
  fail "feed: the refused request is not on the feed with the guard's denial"
fi
