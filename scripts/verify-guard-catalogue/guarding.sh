# shellcheck shell=bash disable=SC2154 # the variables and helpers are verify.sh's
# The guarding proof of verify.sh --tsa, sourced by it once the chain is up and the participants hold
# their tokens: the same three requests over the REST route and over the gRPC method, decided by the
# Rego bundle in the TSA. One line per case in cases.jsonl:
#   {case, protocol, http_status, grpc_status, reason_code, correlation_id, oid4vp_link,
#    resource_reached, guard_event, policy_event, verdict}
# The decision events are the IF-01 v2 lines of the guard and of the policy evaluator under the
# correlation id; resource_reached is whether the resource's log holds that id.
step "Guarding through the TSA's Rego bundle: REST and gRPC"
: > "$out/cases.jsonl"
grpc_url=$published$grpc_method
# One empty HealthCheckRequest in gRPC framing, in the caller's pod: curl cannot take NUL on its command line.
printf '\0\0\0\0\0' | kubectl -n "$ns" exec -i participant -c curl -- sh -c 'cat > /tmp/grpc-request.bin'
# call PROTOCOL NAME TOKEN KEY: one guarded request from the Participant's pod; writes NAME.http.
call() {
  local protocol=$1 name=$2 token=$3 key=$4
  if [ "$protocol" = rest ]; then guarded participant "$name" "$token" "$key" >/dev/null; return; fi
  ccurl participant "$out/$name.http" --http2-prior-knowledge -X POST -H 'Content-Type: application/grpc' -H 'TE: trailers' \
    -H "Authorization: DPoP $token" -H "DPoP: $(dpop_proof "$key" POST "$grpc_url" "$(ath_of "$token")" "")" \
    --data-binary @/tmp/grpc-request.bin "$grpc_url" >/dev/null
}
# decision COMPONENT ID: that component's decision event (not its other log lines) under the id.
decision() { { logs "$1" || true; } | jq -c --arg id "$2" 'select(.correlation_id? == $id and .payload? != null)' 2>/dev/null | head -1 || true; }
# grpc_status_of FILE: the gRPC status of the answer: a header of a headers-only answer, else the trailer,
# which curl prints straight after the binary message.
grpc_status_of() { LC_ALL=C grep -ao 'grpc-status: [0-9]*' "$1" | tail -1 | sed 's/.*: //' || true; }
resource_log() { kubectl -n "$ns" logs deploy/ztd-protected-resource -c ztd-protected-resource 2>/dev/null || true; }
# record NAME PROTOCOL ID OK: the case's line, from NAME.http and the events under ID.
record() {
  local name=$1 protocol=$2 id=$3 ok=$4 file="$out/$1.http" ge pe reached=false
  ge=$(decision guard "$id"); pe=$(decision policy-evaluator "$id")
  if [ -n "$id" ] && resource_log | grep -Fq "$id"; then reached=true; fi
  jq -nc --arg case "$name" --arg protocol "$protocol" --arg id "$id" --arg verdict "$ok" --argjson reached "$reached" \
    --arg http "$(sed -n '1s/^HTTP\/[0-9.]* \([0-9]*\).*/\1/p' "$file" | tr -d '\r')" --arg grpc "$(grpc_status_of "$file")" \
    --arg reason "$(header_of "$file" x-facis-reason-code)" --arg link "$(header_of "$file" x-facis-oid4vp-link)" \
    --argjson ge "${ge:-null}" --argjson pe "${pe:-null}" \
    '{case: $case, protocol: $protocol, http_status: $http, grpc_status: $grpc, reason_code: $reason, correlation_id: $id, oid4vp_link: $link,
      resource_reached: $reached, guard_event: $ge, policy_event: $pe, verdict: $verdict}' >> "$out/cases.jsonl"
}
# passes PROTOCOL NAME: the entitled request reaches the resource; the guard's and the policy's allowed
# events and the resource's record share one id, the policy's under the bundle's revision.
passes() {
  local protocol=$1 name=$2 id ge pe ok=no line
  call "$protocol" "$name" "$viewer_token" "$work/viewer.pem"
  sleep 2
  if [ "$protocol" = rest ]; then
    id=$(body_of "$out/$name.http" | jq -r '.requestId // empty' 2>/dev/null || true)
  else
    # A gRPC answer carries no id of the guard's: the resource's record of the call names it.
    id=$(resource_log | jq -r --arg m "$grpc_method" 'select(.grpcMethod? == $m) | .requestId' 2>/dev/null | tail -1)
    [ "$(grpc_status_of "$out/$name.http")" = 0 ] && LC_ALL=C grep -aq "$(printf '\010\001')" "$out/$name.http" || id=""   # 0 and SERVING
  fi
  ge=$(decision guard "$id"); pe=$(decision policy-evaluator "$id")
  line=$(resource_log | grep -F "${id:-no-id}" | head -1 || true)
  if [ "$(sed -n '1s/^HTTP\/[0-9.]* \([0-9]*\).*/\1/p' "$out/$name.http" | tr -d '\r')" = 200 ] && [ -n "$id" ] && [ -n "$line" ] &&
    [ "$(jq -r .payload.state <<<"${ge:-null}")" = allowed ] &&
    [ "$(jq -r '.payload | .state + " " + .rule_id + " " + .bundle_revision' <<<"${pe:-null}")" = "allowed m3-report-summary $revision" ]; then ok=yes; fi
  record "$name" "$protocol" "$id" "$ok"
  if [ "$ok" = yes ]; then pass "$name: passed the guard and the policy (m3-report-summary, bundle $revision) and reached the resource, one id $id"; else fail "$name: guard ${ge:-none}, policy ${pe:-none}, resource ${line:-none}: $(head -c 300 "$out/$name.http" | tr -d '\0' | tr '\r\n' '  ')"; fi
}
# denied PROTOCOL NAME TOKEN KEY HTTP GRPC CODE RULE [LINK]: refused with the code (REST: the status; gRPC:
# the gRPC status in a headers-only answer), the guard's and the policy's denied events under the id the
# caller received, the policy's naming RULE and the bundle's revision, nothing in the resource's record
# and, with LINK, the OID4VP link in the answer (REST: body and header; gRPC: header).
denied() {
  local protocol=$1 name=$2 http=$5 grpc=$6 code=$7 rule=$8 link=${9:-} file="$out/$2.http" id ge pe ok=yes
  call "$protocol" "$name" "$3" "$4"
  sleep 1
  id=$(header_of "$file" x-request-id)
  ge=$(decision guard "$id"); pe=$(decision policy-evaluator "$id")
  [ "$(sed -n '1s/^HTTP\/[0-9.]* \([0-9]*\).*/\1/p' "$file" | tr -d '\r')" = "$http" ] && [ "$(header_of "$file" x-facis-reason-code)" = "$code" ] && [ -n "$id" ] || ok=no
  if [ "$protocol" = grpc ]; then [ "$(grpc_status_of "$file")" = "$grpc" ] || ok=no; else [ "$(body_of "$file" | jq -r '.reason_code + " " + .rule_id' 2>/dev/null)" = "$code $rule" ] || ok=no; fi
  [ "$(jq -r '.payload | .state + " " + .reason_code + " " + .rule_id' <<<"${ge:-null}")" = "denied $code $rule" ] || ok=no
  [ "$(jq -r '.payload | .state + " " + .reason_code + " " + .rule_id + " " + .bundle_revision' <<<"${pe:-null}")" = "denied $code $rule $revision" ] || ok=no
  if [ -n "$id" ] && resource_log | grep -Fq "$id"; then ok=no; fi
  if [ -n "$link" ]; then
    [ "$(header_of "$file" x-facis-oid4vp-link)" = "$link" ] || ok=no
    if [ "$protocol" = rest ]; then [ "$(body_of "$file" | jq -r '.oid4vp_link // empty')" = "$link" ] || ok=no; fi
  fi
  record "$name" "$protocol" "$id" "$ok"
  if [ "$ok" = yes ]; then pass "$name: $http${grpc:+ grpc-status $grpc} $code ($rule, bundle $revision)${link:+ with the OID4VP link}, guard and policy events under $id, nothing at the resource"; else fail "$name: guard ${ge:-none}, policy ${pe:-none}: $(head -c 400 "$file" | tr -d '\0' | tr '\r\n' '  ')"; fi
}

passes rest rest-authorized
denied rest rest-unauthorized "$unrelated_token" "$work/unrelated.pem" 403 "" POL-RULE-DENY m3-default-deny
denied rest rest-presentation-required "$full_token" "$work/full.pem" 401 "" POL-PRESENTATION-REQUIRED m3-presentation-required "$oid4vp"
passes grpc grpc-authorized
denied grpc grpc-unauthorized "$unrelated_token" "$work/unrelated.pem" 200 7 POL-RULE-DENY m3-default-deny
denied grpc grpc-presentation-required "$full_token" "$work/full.pem" 200 16 POL-PRESENTATION-REQUIRED m3-presentation-required "$oid4vp"

# The decisions were the TSA's: the evaluator logged each as engine tsa, and the bundle sidecar's log names the active revision.
logs guard > "$out/guard-events.jsonl"
logs policy-evaluator > "$out/policy-events.jsonl"
resource_log > "$out/resource.log"
kubectl -n "$tsa_ns" logs deploy/tsa-policy-engine -c bundle > "$out/bundle-sidecar.log" 2>&1 || true
kubectl -n "$ns" get deploy,svc,authorizationpolicy,networkpolicy -o yaml > "$out/guard-namespace.yaml" 2>/dev/null || true
by_tsa=$(jq -c 'select(.engine? == "tsa" and .msg == "policy decision" and .rule_id != null)' "$out/policy-events.jsonl" | wc -l | tr -d ' ')
if [ "$by_tsa" -ge 6 ] && grep -q "bundle activated" "$out/bundle-sidecar.log" && grep -q "$revision" "$out/bundle-sidecar.log"; then
  pass "the evaluator took $by_tsa decisions from the TSA; the bundle sidecar activated revision $revision"
else
  fail "decisions by the TSA: $by_tsa; bundle sidecar: $(grep -c 'bundle activated' "$out/bundle-sidecar.log" || true) activation(s)"
fi
