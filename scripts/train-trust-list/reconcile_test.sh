#!/usr/bin/env bash
# Cases for reconcile.sh against fake_tspa.py (scripts/train-publish), the stand-in that copies the
# trust-list API's write semantics. Each case is one thing the reconciler must get right before a
# trust list is governed by it: a file the contract refuses, the change in words, no list, the
# first apply as PUTs with the marker and stable UUIDs, a second apply that writes nothing, a
# changed issuer as a PATCH of the same entry, a removed issuer as a DELETE with the pipeline's
# measurement entry untouched, verify finding drift and apply repairing it, a lookup key already
# held by another entry (nothing written), a duplicated entry, a wrong secret, a token without the
# role, a token the TSPA ignores, an unreachable TSPA, a broken TSPA, a writer racing the
# reconciler, the zones with a stubbed dig, and no secret in any output. Needs bash, curl, jq,
# python3 and sha256sum; no network beyond localhost.
#
#   scripts/train-trust-list/reconcile_test.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pub="$here/../train-publish"
for tool in curl jq python3 sha256sum; do
  command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 2; }
done
work="$(mktemp -d)"
fake=""
cleanup() { [ -n "$fake" ] && kill "$fake" 2>/dev/null; wait "$fake" 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT

port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
secret="test-secret-$RANDOM$RANDOM"
FAKE_TSPA_SECRET=$secret python3 "$pub/fake_tspa.py" --port "$port" --log "$work/requests.jsonl" 2>"$work/fake.err" &
fake=$!
base="http://127.0.0.1:$port"
for _ in $(seq 50); do curl -sf --max-time 1 -o /dev/null "$base/tspa-service/actuator/health" && break; sleep 0.1; done
curl -sf --max-time 1 -o /dev/null "$base/tspa-service/actuator/health" || { echo "fake TSPA did not start: $(cat "$work/fake.err")" >&2; exit 2; }

export TSPA_URL="$base/tspa-service"
export OIDC_TOKEN_URL="$base/realms/test/protocol/openid-connect/token" OIDC_CLIENT_ID=publisher OIDC_CLIENT_SECRET=$secret
fw=test.local
api="$TSPA_URL/tspa/v1"

fails=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; echo "$1" >> "$work/fails.txt"; fails=$((fails + 1)); }
check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi; }
rc=0
run() {  # run <name> <action> <file> [args...]: reconcile.sh with its own --out; rc, stdout and stderr kept
  local name=$1 action=$2 f=$3; shift 3
  set +e
  "$here/reconcile.sh" "$action" --file "$f" --out "$work/out-$name" "$@" >"$work/$name.out" 2>"$work/$name.err"
  rc=$?
  set -e
}
event() { sed -n 's/^EVENT_JSON=//p' "$work/$1.out" | tail -1; }
field() { event "$1" | jq -r "$2"; }
fieldc() { event "$1" | jq -c "$2"; }
writes_in_log() { jq -r 'select((.method == "PUT" or .method == "PATCH" or .method == "DELETE") and (.path | test("/trust-list/tsp"))) | .method' "$work/requests.jsonl" 2>/dev/null | wc -l | tr -d ' '; }
list() { curl -sS "$api/$fw/trust-list"; }
entries() { list | jq '[.TrustServiceStatusList.TrustServiceProviderList.TrustServiceProvider // [] | .[]] | length'; }
entry() { list | jq -c --arg u "$1" '[.TrustServiceStatusList.TrustServiceProviderList.TrustServiceProvider // [] | .[] | select(.UUID == $u)]'; }
by_sti() { list | jq -c --arg s "$1" '[.TrustServiceStatusList.TrustServiceProviderList.TrustServiceProvider // [] | .[] | select(.TSPServices.TSPService[0].ServiceTypeIdentifier == $s)]'; }
uuid_of() { python3 "$here/desired_state.py" render "$1" | jq -r --arg id "$2" '.issuers[] | select(.id == $id) | .uuid'; }
is_hex64() { [[ "$1" =~ ^[0-9a-f]{64}$ ]]; }
is_number() { [[ "$1" =~ ^[0-9]+(\.[0-9]+)?$ ]]; }
is_time() { [[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; }
count() { tr -d ' '; }
export api fw work
export -f list entries entry by_sti is_hex64 is_number is_time writes_in_log count

# The files: v1 two issuers, v2 one renamed, v3 one removed, v4 a lookup key another entry holds, v5 a third issuer.
desired() {  # desired <file> <issuers-json> [zones-json]
  jq -n --arg fw "$fw" --argjson issuers "$2" --argjson zones "${3:-[]}" \
    '{schemaVersion: 1, framework: $fw, operator: "test", zones: $zones, issuers: $issuers}' > "$1"
}
ia='{id: "issuer-a", name: "Issuer A", serviceTypeIdentifier: "did:example:issuer-a", credentialTypes: ["ParticipantCredential"], supplyPoint: "https://issuer-a.test", zone: "a"}'
ib='{id: "issuer-b", name: "Issuer B", serviceTypeIdentifier: "did:example:issuer-b", zone: "b"}'
ic='{id: "issuer-c", name: "Issuer C", serviceTypeIdentifier: "did:example:issuer-c", status: "suspended"}'
ir='{id: "rogue", name: "Rogue", serviceTypeIdentifier: "did:example:b-connector"}'
idd='{id: "issuer-d", name: "Issuer D", serviceTypeIdentifier: "did:example:issuer-d"}'
za='{name: "a", domain: "zone-a.test.local"}'; zb='{name: "b", domain: "zone-b.test.local"}'; zn='{name: "a", domain: "nozone-a.test.local"}'
zones=$(jq -n "[$za, $zb]")
desired "$work/v1.json" "$(jq -n "[$ia, $ib]")" "$zones"
desired "$work/v2.json" "$(jq -n "[$ia, ($ib | .name = \"Issuer B, renamed\")]")" "$zones"
desired "$work/v3.json" "$(jq -n "[$ia]")" "$zones"
desired "$work/v4.json" "$(jq -n "[$ia, $ir]")" "$zones"
desired "$work/v5.json" "$(jq -n "[$ia, $ic]")" "$zones"
desired "$work/vz.json" "$(jq -n "[$ia]")" "$(jq -n "[$zn]")"
ua=$(uuid_of "$work/v1.json" issuer-a); ub=$(uuid_of "$work/v1.json" issuer-b); uc=$(uuid_of "$work/v5.json" issuer-c)

echo "## the contract"
run good validate "$work/v1.json"
check "validate: a file that satisfies the contract exits 0" [ "$rc" = 0 ]
check "validate: the UUIDs are stable across renders" [ "$(uuid_of "$work/v2.json" issuer-b)" = "$ub" ]
bad() {  # bad <description> <jq filter over v1>
  jq "$2" "$work/v1.json" > "$work/bad.json"
  run bad validate "$work/bad.json"
  check "validate refuses $1 (exit 2)" [ "$rc" = 2 ]
  check "validate refuses $1: nothing called" bash -c "! grep -q -E 'token|trust-list' '$work/requests.jsonl'"
}
bad "an unknown property" '.issuers[0].colour = "blue"'
bad "a duplicate issuer id" '.issuers[1].id = "issuer-a"'
bad "two issuers with one lookup key" '.issuers[1].serviceTypeIdentifier = "did:example:issuer-a"'
bad "a zone the file does not declare" '.issuers[0].zone = "c"'
bad "another schema version" '.schemaVersion = 2'
bad "an id with capitals" '.issuers[0].id = "IssuerA"'
bad "a lookup key with spaces" '.issuers[0].serviceTypeIdentifier = "did:example:a b"'
bad "a supply point that is not a URI" '.issuers[0].supplyPoint = "issuer-a.test"'
bad "a status outside the two" '.issuers[0].status = "revoked"'
bad "a boolean where the schema version goes (const is typed)" '.schemaVersion = true'
bad "an id with a trailing newline (anchored patterns match the whole string)" '.issuers[0].id = "issuer-a\n"'
set +e; "$here/reconcile.sh" diff --from "$work/v1.json" --to "$work/v5.json" > "$work/diff.out" 2>&1; rc=$?; set -e
check "diff: exits 0" [ "$rc" = 0 ]
check "diff: names the issuer added" grep -q '^+ issuer issuer-c (did:example:issuer-c)' "$work/diff.out"
check "diff: names the issuer removed and the window" grep -q '^- issuer issuer-b (did:example:issuer-b).*cached the list keeps trusting it' "$work/diff.out"
set +e; "$here/reconcile.sh" diff --from "$work/v1.json" --to "$work/v2.json" > "$work/diff2.out" 2>&1; set -e
check "diff: names the field changed" grep -q '^~ issuer issuer-b: name changed' "$work/diff2.out"
set +e; "$here/reconcile.sh" diff --from "$work/v1.json" --to "$work/v1.json" > "$work/diff3.out" 2>&1; set -e
check "diff: says when nothing changes" grep -q '^= no change' "$work/diff3.out"
run noconf plan "$work/v1.json"
gets_before=$(grep -c 'trust-list' "$work/requests.jsonl" 2>/dev/null || echo 0)
check "apply without a token configuration is refused (exit 2) before the list is read" bash -c "OIDC_TOKEN_URL= TSPA_TOKEN_FILE= '$here/reconcile.sh' apply --file '$work/v1.json' --out '$work/out-notok' >/dev/null 2>&1; [ \$? = 2 ] && [ \"\$(grep -c 'trust-list' '$work/requests.jsonl' 2>/dev/null || echo 0)\" = '$gets_before' ]"
check "plan without TSPA_URL is refused (exit 2)" bash -c "TSPA_URL= '$here/reconcile.sh' plan --file '$work/v1.json' --out '$work/out-noconf' >/dev/null 2>&1; [ \$? = 2 ]"
check "--with-zones without TRAIN_DNS_SERVER is refused (exit 2)" bash -c "TRAIN_DNS_SERVER= '$here/reconcile.sh' apply --file '$work/v1.json' --out '$work/out-nodns' --with-zones >/dev/null 2>&1; [ \$? = 2 ]"
check "--with-zones goes with apply only (exit 2)" bash -c "TRAIN_DNS_SERVER=127.0.0.1 '$here/reconcile.sh' plan --file '$work/v1.json' --out '$work/out-zp' --with-zones >/dev/null 2>&1; [ \$? = 2 ]"

echo "## no list yet"
run nolist plan "$work/v1.json"
check "no trust list: plan exits 1" [ "$rc" = 1 ]
check "no trust list: outcome list-missing" [ "$(field nolist .outcome)" = list-missing ]
run nolist2 apply "$work/v1.json"
check "no trust list: apply exits 1 with list-missing" bash -c "[ '$rc' = 1 ] && [ '$(field nolist2 .outcome)' = list-missing ]"
check "no trust list: no write attempted" [ "$(writes_in_log)" = 0 ]

echo "## the list exists (federation setup, not the reconciler's job)"
code=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT -H 'Authorization: Bearer enrolltf-token' -H 'Content-Type: application/json' \
  --data-binary '{"TrustServiceStatusList":{"FrameworkInformation":{"FrameworkName":{"Name":"test.local"}}}}' "$api/init/json/$fw/trust-list")
check "trust list created (201)" [ "$code" = 201 ]

echo "## plan, then the first apply"
run plan1 plan "$work/v1.json"
check "plan: exits 0, outcome planned" bash -c "[ '$rc' = 0 ] && [ '$(field plan1 .outcome)' = planned ]"
check "plan: two creates, nothing else" [ "$(fieldc plan1 '[.plan.create, .plan.replace, .plan.delete, .plan.converged]')" = '[["issuer-a","issuer-b"],[],[],false]' ]
check "plan: says it in words on stderr" grep -q '^train-trust-list: + create issuer-a (did:example:issuer-a)' "$work/plan1.err"
check "plan: wrote nothing" [ "$(writes_in_log)" = 0 ]
check "plan: fetched no token" bash -c "! grep -q 'openid-connect/token' '$work/requests.jsonl'"
run a1 apply "$work/v1.json"
check "first apply: exit 0" [ "$rc" = 0 ]
check "first apply: outcome applied" [ "$(field a1 .outcome)" = applied ]
check "first apply: two PUTs answered 201" [ "$(fieldc a1 '[.writes[] | [.method, .status]]')" = '[["PUT",201],["PUT",201]]' ]
check "first apply: two entries in the list" [ "$(entries)" = 2 ]
check "first apply: the entries carry the UUIDs the file derives" [ "$(entry "$ua" | jq length)$(entry "$ub" | jq length)" = 11 ]
check "first apply: the entry carries the managed-by marker" [ "$(entry "$ua" | jq -r '.[0].TSPInformation.TSPEntityIdentifierList.TSPEntityIdendifier[] | select(.Type == "managed-by") | .Value')" = "train-trust-list/$fw" ]
check "first apply: the lookup key is the issuer's" [ "$(entry "$ua" | jq -r '.[0].TSPServices.TSPService[0].ServiceTypeIdentifier')" = did:example:issuer-a ]
check "first apply: the DID defaults to the lookup key" [ "$(entry "$ua" | jq -r '.[0].TSPServices.TSPService[0].ServiceDigitalIdentity.DigitalId.DID')" = did:example:issuer-a ]
check "first apply: the credential type, supply point and zone travel" [ "$(entry "$ua" | jq -c '.[0] | [.TSPServices.TSPService[0].AdditionalServiceInformation.ServiceIssuedCredentialTypes.CredentialType[0].Type, .TSPServices.TSPService[0].AdditionalServiceInformation.ServiceSupplyPoint, (.TSPInformation.TSPEntityIdentifierList.TSPEntityIdendifier[] | select(.Type == "zone") | .Value)]')" = '["ParticipantCredential","https://issuer-a.test","a"]' ]
check "first apply: no measurement pair in an issuer's entry" [ "$(entry "$ua" | jq '.[0].TSPInformation.TSPCertificationList.TSPCertification | length')" = 0 ]
start_b=$(entry "$ub" | jq -r '.[0].TSPServices.TSPService[0].StatusStartingTime')
check "first apply: StatusStartingTime is set at the first write" is_time "$start_b"
check "first apply: stdout is the one EVENT_JSON line" bash -c "[ \"\$(grep -c . '$work/a1.out')\" = 1 ] && grep -q '^EVENT_JSON=' '$work/a1.out'"
check "first apply: one evidence line in reconciliations.jsonl" [ "$(wc -l < "$work/out-a1/reconciliations.jsonl" | count)" = 1 ]
check "first apply: the source names the file and its sha256" bash -c "[ \"\$(sed -n 's/^EVENT_JSON=//p' '$work/a1.out' | jq -r .source.file)\" = '$work/v1.json' ] && is_hex64 \"\$(sed -n 's/^EVENT_JSON=//p' '$work/a1.out' | jq -r .source.sha256)\""
check "first apply: a file outside a repository has no commit" [ "$(field a1 .source.commit)" = null ]
check "first apply: readBack.listSha256 is a sha256" is_hex64 "$(field a1 .readBack.listSha256)"
check "first apply: readBack.vcHash is the VC's hash" is_hex64 "$(field a1 .readBack.vcHash)"
check "first apply: readBack.elapsedSeconds is a number" is_number "$(field a1 .readBack.elapsedSeconds)"
check "first apply: the requests are kept, without a token" bash -c "ls '$work/out-a1/last/' | grep -q '^request-1-PUT-' && ! grep -rq 'enrolltf-token' '$work/out-a1/'"
vc1=$(field a1 .readBack.vcHash)

echo "## apply again: nothing to write"
before=$(writes_in_log)
run a1b apply "$work/v1.json"
check "second apply: exit 0, outcome converged" bash -c "[ '$rc' = 0 ] && [ '$(field a1b .outcome)' = converged ]"
check "second apply: no writes" bash -c "[ '$(fieldc a1b .writes)' = '[]' ] && [ '$(writes_in_log)' = '$before' ]"
check "second apply: the plan says unchanged" [ "$(fieldc a1b .plan.unchanged)" = '["issuer-a","issuer-b"]' ]
check "second apply: the VC hash did not move" [ "$(field a1b .readBack.vcHash)" = "$vc1" ]

echo "## the pipeline publishes a measurement entry into the same list"
jq -n --arg v "$(printf teem | sha256sum | cut -c1-64)" --arg cfg "$(printf cfg | sha256sum | cut -c1-64)" --arg rfs "$(printf rootfs | sha256sum | cut -c1-64)" '
  {component: "connector", zone: "b", serviceTypeIdentifier: "did:example:b-connector",
   image: ("registry/b/connector@sha256:" + $cfg),
   measurement: {type: "TEEM-sha256", value: $v, configSha256: $cfg, rootfsSha256: $rfs},
   source: {commit: "0123456789abcdef", tool: "test"}}' > "$work/record.json"
TSPA_FRAMEWORK=$fw "$pub/publish.sh" publish --record "$work/record.json" --out "$work/out-pub" >"$work/pub.out" 2>"$work/pub.err" || true
pub_uuid=$(sed -n 's/^EVENT_JSON=//p' "$work/pub.out" | tail -1 | jq -r .uuid)
check "the publisher's entry is in the list (three entries)" [ "$(entries)" = 3 ]
pub_before=$(entry "$pub_uuid")

echo "## a renamed issuer: a PATCH of the same entry"
run a2 apply "$work/v2.json"
check "renamed issuer: exit 0, applied" bash -c "[ '$rc' = 0 ] && [ '$(field a2 .outcome)' = applied ]"
check "renamed issuer: one PATCH of issuer-b's entry" [ "$(fieldc a2 '[.writes[] | [.method, .uuid, .status]]')" = "[[\"PATCH\",\"$ub\",200]]" ]
check "renamed issuer: the name changed, the UUID and the start time did not" [ "$(entry "$ub" | jq -c '.[0] | [.TSPName, .TSPServices.TSPService[0].StatusStartingTime]')" = "[\"Issuer B, renamed\",\"$start_b\"]" ]
check "renamed issuer: still three entries" [ "$(entries)" = 3 ]
check "renamed issuer: the publisher's entry is byte for byte what it was" [ "$(entry "$pub_uuid")" = "$pub_before" ]
vc2=$(field a2 .readBack.vcHash)
check "renamed issuer: the VC hash moved" [ "$vc2" != "$vc1" ]

echo "## a removed issuer: a DELETE, the measurement entry untouched"
run a3 apply "$work/v3.json"
check "removed issuer: exit 0, applied" bash -c "[ '$rc' = 0 ] && [ '$(field a3 .outcome)' = applied ]"
check "removed issuer: one DELETE of issuer-b's entry" [ "$(fieldc a3 '[.writes[] | [.method, .uuid, .status]]')" = "[[\"DELETE\",\"$ub\",200]]" ]
check "removed issuer: the plan names what was deleted" [ "$(fieldc a3 .plan.delete)" = "[\"$ub\"]" ]
check "removed issuer: two entries remain" [ "$(entries)" = 2 ]
check "removed issuer: nothing answers to its lookup key any more" [ "$(by_sti did:example:issuer-b)" = '[]' ]
check "removed issuer: the publisher's entry is byte for byte what it was" [ "$(entry "$pub_uuid")" = "$pub_before" ]
check "removed issuer: the VC hash moved again" bash -c "[ '$(field a3 .readBack.vcHash)' != '$vc2' ]"
check "removed issuer: elapsedSeconds is a number (the window starts here)" is_number "$(field a3 .readBack.elapsedSeconds)"

echo "## verify: the list follows the file, or does not"
run v3 verify "$work/v3.json"
check "verify after apply: exit 0, verified" bash -c "[ '$rc' = 0 ] && [ '$(field v3 .outcome)' = verified ]"
check "verify: fetched no token and wrote nothing" bash -c "[ '$(fieldc v3 .writes)' = '[]' ]"
run v2 verify "$work/v2.json"
check "verify against another file: exit 1, drift" bash -c "[ '$rc' = 1 ] && [ '$(field v2 .outcome)' = drift ]"
check "verify drift: the plan says what apply would create" [ "$(fieldc v2 .plan.create)" = '["issuer-b"]' ]
# Someone edits the entry by hand (a token with the role): verify sees it, apply repairs it.
entry "$ua" | jq '.[0] | .TSPName = "Edited by hand" | {TrustServiceProvider: .}' > "$work/tamper.json"
code=$(curl -sS -o /dev/null -w '%{http_code}' -X PATCH -H 'Authorization: Bearer enrolltf-token' -H 'Content-Type: application/json' --data-binary @"$work/tamper.json" "$api/$fw/trust-list/tsp/$ua")
check "an entry edited by hand (PATCH 200)" [ "$code" = 200 ]
run v3b verify "$work/v3.json"
check "verify after the edit: exit 1, drift, replace issuer-a" bash -c "[ '$rc' = 1 ] && [ '$(field v3b .outcome)' = drift ] && [ '$(fieldc v3b .plan.replace)' = '[\"issuer-a\"]' ]"
run a3b apply "$work/v3.json"
check "apply after the edit: one PATCH repairs it" bash -c "[ '$rc' = 0 ] && [ '$(fieldc a3b '[.writes[] | .method]')' = '[\"PATCH\"]' ] && [ '$(entry "$ua" | jq -r '.[0].TSPName')' = 'Issuer A' ]"

echo "## a lookup key another entry holds: nothing written"
sha_before=$(list | sha256sum | cut -c1-64); before=$(writes_in_log)
run a4 apply "$work/v4.json"
check "conflict: exit 1, outcome conflict" bash -c "[ '$rc' = 1 ] && [ '$(field a4 .outcome)' = conflict ]"
check "conflict: the plan names the issuer, the key and the entry that holds it" [ "$(fieldc a4 '.plan.conflict')" = "[{\"id\":\"rogue\",\"serviceTypeIdentifier\":\"did:example:b-connector\",\"uuids\":[\"$pub_uuid\"]}]" ]
check "conflict: said in words on stderr" grep -q '^train-trust-list: ! conflict: rogue names the lookup key did:example:b-connector' "$work/a4.err"
check "conflict: nothing was written, the list is unchanged" bash -c "[ '$(writes_in_log)' = '$before' ] && [ '$(list | sha256sum | cut -c1-64)' = '$sha_before' ]"
run p4 plan "$work/v4.json"
check "plan with a conflict: exit 1 as well" bash -c "[ '$rc' = 1 ] && [ '$(field p4 .outcome)' = conflict ]"

echo "## a duplicated entry: the list needs repair"
curl -sS -o /dev/null -X POST --data-binary "{\"framework\":\"$fw\",\"uuid\":\"$ua\"}" "$base/__fake/duplicate"
run dup apply "$work/v3.json"
check "duplicate: exit 1, outcome duplicate-entry, nothing written" bash -c "[ '$rc' = 1 ] && [ '$(field dup .outcome)' = duplicate-entry ] && [ '$(fieldc dup .writes)' = '[]' ]"
curl -sS -o /dev/null -X POST --data-binary "{\"framework\":\"$fw\",\"remove\":\"$ua\"}" "$base/__fake/after-next-get"
list >/dev/null   # the hook fires: both copies gone
run dup2 apply "$work/v3.json"
check "after the repair: apply recreates the entry with a PUT" bash -c "[ '$rc' = 0 ] && [ '$(fieldc dup2 '[.writes[] | .method]')' = '[\"PUT\"]' ] && [ '$(entries)' = 2 ]"

echo "## an issuer renamed in the file (new id, same lookup key): a removal and a creation"
desired "$work/v3b.json" "$(jq -n "[($ia | .id = \"issuer-a2\")]")" "$zones"
ua2=$(uuid_of "$work/v3b.json" issuer-a2)
run ren apply "$work/v3b.json"
check "rename of the id: exit 0, applied, the old entry deleted before the new one is created" bash -c "[ '$rc' = 0 ] && [ '$(field ren .outcome)' = applied ] && [ '$(fieldc ren '[.writes[] | [.method, .uuid]]')' = '[[\"DELETE\",\"$ua\"],[\"PUT\",\"$ua2\"]]' ]"
check "rename of the id: one entry answers to the lookup key, under the new UUID" [ "$(by_sti did:example:issuer-a | jq -c '[.[].UUID]')" = "[\"$ua2\"]" ]
check "rename of the id: no conflict was reported" [ "$(fieldc ren .plan.conflict)" = '[]' ]
run ren2 apply "$work/v3.json"
check "renaming back: the same two writes the other way" bash -c "[ '$rc' = 0 ] && [ '$(fieldc ren2 '[.writes[] | [.method, .uuid]]')' = '[[\"DELETE\",\"$ua2\"],[\"PUT\",\"$ua\"]]' ]"

echo "## an entry under the file's UUID without the marker: not the file's to replace"
entry "$ua" | jq '.[0] | .TSPInformation.TSPEntityIdentifierList.TSPEntityIdendifier |= map(select(.Type != "managed-by")) | {TrustServiceProvider: .}' > "$work/unowned.json"
code=$(curl -sS -o /dev/null -w '%{http_code}' -X PATCH -H 'Authorization: Bearer enrolltf-token' -H 'Content-Type: application/json' --data-binary @"$work/unowned.json" "$api/$fw/trust-list/tsp/$ua")
check "the marker is stripped from issuer-a's entry by hand (PATCH $code)" [ "$code" = 200 ]
before=$(writes_in_log)
run unowned apply "$work/v3.json"
check "unowned entry: exit 1, outcome unowned-entry, nothing written" bash -c "[ '$rc' = 1 ] && [ '$(field unowned .outcome)' = unowned-entry ] && [ '$(fieldc unowned .writes)' = '[]' ] && [ '$(writes_in_log)' = '$before' ]"
check "unowned entry: the plan names the entry and the issuer" [ "$(fieldc unowned '.plan.unowned')" = "[{\"id\":\"issuer-a\",\"uuid\":\"$ua\"}]" ]
check "unowned entry: said in words on stderr" grep -q '^train-trust-list: ! unowned: the entry' "$work/unowned.err"
run unowned_v verify "$work/v3.json"
check "unowned entry: verify reports it too (exit 1)" bash -c "[ '$rc' = 1 ] && [ '$(field unowned_v .outcome)' = unowned-entry ]"
curl -sS -o /dev/null -X DELETE -H 'Authorization: Bearer enrolltf-token' "$api/$fw/trust-list/tsp/$ua"
run unowned_fix apply "$work/v3.json"
check "once the entry is removed by hand, apply recreates it with a PUT" bash -c "[ '$rc' = 0 ] && [ '$(fieldc unowned_fix '[.writes[] | .method]')' = '[\"PUT\"]' ]"

echo "## the token"
before=$(writes_in_log)
OIDC_CLIENT_SECRET=wrong run ws apply "$work/v5.json"
check "wrong secret: exit 1, token-failed, nothing written" bash -c "[ '$rc' = 1 ] && [ '$(field ws .outcome)' = token-failed ] && [ '$(writes_in_log)' = '$before' ]"
OIDC_CLIENT_ID=weak run weak apply "$work/v5.json"
check "token without enrolltf: exit 1, write-rejected (403), the entry not created" bash -c "[ '$rc' = 1 ] && [ '$(field weak .outcome)' = write-rejected ] && [ '$(fieldc weak '[.writes[] | .status]')' = '[403]' ] && [ '$(entries)' = 2 ]"
OIDC_CLIENT_ID=ghost run ghost apply "$work/v5.json"
check "token the TSPA ignores: exit 1, write-unconfirmed (200, empty body), the entry not created" bash -c "[ '$rc' = 1 ] && [ '$(field ghost .outcome)' = write-unconfirmed ] && [ '$(fieldc ghost '[.writes[] | .status]')' = '[200]' ] && [ '$(entries)' = 2 ]"
printf 'enrolltf-token\n' > "$work/token.txt"
OIDC_TOKEN_URL= TSPA_TOKEN_FILE="$work/token.txt" run tf apply "$work/v5.json"
check "a token already obtained: exit 0, applied" bash -c "[ '$rc' = 0 ] && [ '$(field tf .outcome)' = applied ] && [ '$(entries)' = 3 ]"
check "a suspended issuer is in the list, marked suspended" [ "$(entry "$uc" | jq -r '.[0].TSPServices.TSPService[0].ServiceCurrentStatus')" = suspended ]

echo "## the TSPA cannot be reached, or is broken"
closed=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
TSPA_URL="http://127.0.0.1:$closed/tspa-service" TRAIN_TRUST_LIST_TIMEOUT=3 run down apply "$work/v5.json"
check "unreachable TSPA: exit 1, transport-failure" bash -c "[ '$rc' = 1 ] && [ '$(field down .outcome)' = transport-failure ]"
jq '.framework = "error-500.local"' "$work/v5.json" > "$work/v500.json"
run broken apply "$work/v500.json"
check "broken TSPA (500 on the read): exit 1, tspa-error" bash -c "[ '$rc' = 1 ] && [ '$(field broken .outcome)' = tspa-error ]"

echo "## a writer racing the reconciler"
desired "$work/v6.json" "$(jq -n "[$ia, $ic, $idd]")" "$zones"
ud=$(uuid_of "$work/v6.json" issuer-d)
python3 "$here/desired_state.py" render "$work/v6.json" | jq --arg u "$ud" '.issuers[] | select(.uuid == $u) | .entry.TrustServiceProvider | .TSPServices.TSPService[0].StatusStartingTime = "2026-01-01T00:00:00Z" | .TSPName = "Issuer D, written by someone else"' > "$work/raced.json"
jq -n --arg fw "$fw" --slurpfile e "$work/raced.json" '{framework: $fw, add: $e[0]}' | curl -sS -o /dev/null -X POST --data-binary @- "$base/__fake/after-next-get"
run race apply "$work/v6.json"
check "race: exit 0, applied" bash -c "[ '$rc' = 0 ] && [ '$(field race .outcome)' = applied ]"
check "race: the PUT was answered 400, then the entry was PATCHed" [ "$(fieldc race '[.writes[] | [.method, .status]]')" = '[["PUT",400],["PATCH",200]]' ]
check "race: one entry for issuer-d, as the file says, with the other writer's start time kept" [ "$(entry "$ud" | jq -c '[length, .[0].TSPName, .[0].TSPServices.TSPService[0].StatusStartingTime]')" = '[1,"Issuer D","2026-01-01T00:00:00Z"]' ]
check "race: said on stderr" grep -q 'the list changed since it was read' "$work/race.err"

echo "## the zones, with a stubbed dig"
mkdir -p "$work/bin"
cat > "$work/bin/dig" <<'EOF'
#!/usr/bin/env bash
# dig [+opts] -p PORT PTR <name> @<server>: answers what DIG_ANSWER says, and records the question
echo "$*" >> "${DIG_LOG:?}"
[ -n "${DIG_ANSWER:-}" ] && echo "$DIG_ANSWER"
exit 0
EOF
chmod +x "$work/bin/dig"
: > "$work/dig.log"
PATH="$work/bin:$PATH" DIG_LOG="$work/dig.log" DIG_ANSWER="_scheme._trust.$fw." TRAIN_DNS_SERVER=127.0.0.53 run z1 apply "$work/v6.json" --with-zones
check "zones: exit 0, applied" bash -c "[ '$rc' = 0 ] && [ '$(field z1 .outcome)' = applied ]"
check "zones: one PUT /trustframework per zone domain, each answered 201, both proven" [ "$(fieldc z1 '.zones')" = '{"requested":["zone-a.test.local","zone-b.test.local"],"calls":[{"zone":"zone-a.test.local","status":201,"emptyBody":false},{"zone":"zone-b.test.local","status":201,"emptyBody":false}],"proven":["zone-a.test.local","zone-b.test.local"]}' ]
check "zones: the body names the framework as the target of the claim" [ "$(jq -c .schemes "$work/out-z1/last/request-trustframework.json")" = "[\"$fw\"]" ]
check "zones: the stand-in recorded the claim under each zone's name" bash -c "grep -q 'PUT.*trustframework/zone-a.test.local' '$work/requests.jsonl' && grep -q 'PUT.*trustframework/zone-b.test.local' '$work/requests.jsonl'"
check "zones: dig asked the configured server for each PTR, on port 53 over UDP" bash -c "grep -q -- '-p 53 PTR _scheme._trust.zone-a.test.local @127.0.0.53' '$work/dig.log' && grep -q '_scheme._trust.zone-b.test.local' '$work/dig.log' && ! grep -q '+tcp' '$work/dig.log'"
: > "$work/dig.log"
PATH="$work/bin:$PATH" DIG_LOG="$work/dig.log" DIG_ANSWER="_scheme._trust.$fw." TRAIN_DNS_SERVER=127.0.0.1 TRAIN_DNS_PORT=5353 TRAIN_DNS_TCP=1 run z1b apply "$work/v6.json" --with-zones
check "zones: TRAIN_DNS_PORT and TRAIN_DNS_TCP reach dig (a port-forward carries TCP only)" bash -c "[ '$rc' = 0 ] && grep -q -- '+tcp -p 5353 PTR _scheme._trust.zone-a.test.local @127.0.0.1' '$work/dig.log'"
PATH="$work/bin:$PATH" DIG_LOG="$work/dig.log" DIG_ANSWER="" TRAIN_DNS_SERVER=127.0.0.53 run z2 apply "$work/v6.json" --with-zones
check "zones: a PTR that does not answer is zones-not-published, exit 1, the calls still recorded" bash -c "[ '$rc' = 1 ] && [ '$(field z2 .outcome)' = zones-not-published ] && [ '$(fieldc z2 .zones.proven)' = '[]' ] && [ '$(fieldc z2 '[.zones.calls[].status]')' = '[201,201]' ]"
PATH="$work/bin:$PATH" DIG_LOG="$work/dig.log" DIG_ANSWER="_scheme._trust.$fw." TRAIN_DNS_SERVER=127.0.0.53 run z3 apply "$work/vz.json" --with-zones
check "zones: a zone the manager refuses (TSPA 500) is zones-not-published, exit 1" bash -c "[ '$rc' = 1 ] && [ '$(field z3 .outcome)' = zones-not-published ] && [ '$(fieldc z3 '[.zones.calls[] | [.zone, .status]]')' = '[[\"nozone-a.test.local\",500]]' ]"
check "zones: the issuers were reconciled and read back before the zones failed (issuer-a and the publisher's entry remain)" bash -c "[ '$(entries)' = 2 ] && [[ '$(field z3 .readBack.listSha256)' =~ ^[0-9a-f]{64}$ ]]"

echo "## no secret anywhere"
check "the secret appears in no output, record or request log" bash -c "! grep -rq -- '$secret' '$work'/*.out '$work'/*.err '$work'/out-* '$work/requests.jsonl'"
check "no token appears in any output, record or request log" bash -c "! grep -rq -- 'enrolltf-token' '$work'/*.out '$work'/*.err '$work'/out-* '$work/requests.jsonl'"
check "no Authorization header is kept" bash -c "! grep -rqi 'authorization' '$work'/out-*"

echo
if [ "$fails" = 0 ]; then echo "all checks passed"; else echo "$fails check(s) failed:"; sed 's/^/  /' "$work/fails.txt"; exit 1; fi
