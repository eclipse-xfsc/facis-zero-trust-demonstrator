#!/usr/bin/env bash
# Cases for publish.sh against fake_tspa.py, the stand-in that copies the trust-list API's write
# semantics (create-only PUT, PATCH with matching UUID, 404 without a list, 200 with an empty body
# when the token is unusable, 401 malformed, 403 without enrolltf). Each case is one thing the
# publisher must get right before a rollout is gated on it: no list, first publication as PUT,
# second as PATCH with the union, verify, prune, a wrong secret, a token without the role, a token
# the TSPA ignores, stable UUIDs, an unreachable TSPA, bad records, missing configuration, and no
# secret in any output. Needs bash 5, curl, jq, python3 and sha256sum; no network beyond localhost.
#
#   scripts/train-publish/publish_test.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for tool in curl jq python3 sha256sum; do
  command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 2; }
done
work="$(mktemp -d)"
fake=""
cleanup() { [ -n "$fake" ] && kill "$fake" 2>/dev/null; wait "$fake" 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT

port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
secret="test-secret-$RANDOM$RANDOM"
FAKE_TSPA_SECRET=$secret python3 "$here/fake_tspa.py" --port "$port" --log "$work/requests.jsonl" 2>"$work/fake.err" &
fake=$!
base="http://127.0.0.1:$port"
for _ in $(seq 50); do curl -sf --max-time 1 -o /dev/null "$base/tspa-service/actuator/health" && break; sleep 0.1; done
curl -sf --max-time 1 -o /dev/null "$base/tspa-service/actuator/health" || { echo "fake TSPA did not start: $(cat "$work/fake.err")" >&2; exit 2; }

export TSPA_URL="$base/tspa-service" TSPA_FRAMEWORK=test.local
export OIDC_TOKEN_URL="$base/realms/test/protocol/openid-connect/token" OIDC_CLIENT_ID=publisher OIDC_CLIENT_SECRET=$secret
fw=$TSPA_FRAMEWORK

fails=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; fails=$((fails + 1)); }
check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi; }
hex() { printf '%s' "$1" | sha256sum | cut -c1-64; }
record() {  # record <file> <zone> <component> <seed> [image-override] [value-override]
  local v; v=${6:-$(hex "teem-$4")}
  jq -n --arg z "$2" --arg c "$3" --arg v "$v" --arg cfg "$(hex "cfg-$4")" --arg rfs "$(hex rootfs)" \
    --arg img "${5:-registry/$2/$3@sha256:$(hex "image-$2-$3")}" --arg sti "did:example:$2-$3" '
    {component: $c, zone: $z, serviceTypeIdentifier: $sti, image: $img,
     measurement: {type: "TEEM-sha256", value: $v, configSha256: $cfg, rootfsSha256: $rfs},
     source: {commit: "0123456789abcdef", tool: "cmc 6754d3c measure"}}' > "$1"
}
rc=0
run() {  # run <name> <action> <record>: publish.sh with its own --out; rc, stdout and stderr kept
  local name=$1 action=$2 rec=$3
  set +e
  "$here/publish.sh" "$action" --record "$rec" --out "$work/out-$name" >"$work/$name.out" 2>"$work/$name.err"
  rc=$?
  set -e
}
event() { sed -n 's/^EVENT_JSON=//p' "$work/$1.out" | tail -1; }
field() { event "$1" | jq -r "$2"; }
fieldc() { event "$1" | jq -c "$2"; }
writes() { jq -r 'select((.method == "PUT" or .method == "PATCH") and (.path | test("/trust-list/tsp"))) | .method' "$work/requests.jsonl" 2>/dev/null | wc -l; }
list() { curl -sS "$TSPA_URL/tspa/v1/$TSPA_FRAMEWORK/trust-list"; }   # the framework of the moment, so the race cases read theirs
entries() { list | jq '[.TrustServiceStatusList.TrustServiceProviderList.TrustServiceProvider // [] | .[]] | length'; }
teems() {  # teems <uuid>: the TEEM values of that entry, sorted
  list | jq -c --arg u "$1" '[.TrustServiceStatusList.TrustServiceProviderList.TrustServiceProvider // [] | .[] | select(.UUID == $u) | .TSPInformation.TSPCertificationList.TSPCertification[] | select(.Type == "TEEM-sha256") | .Value] | unique'
}
digests() { list | jq -c --arg u "$1" '[.TrustServiceStatusList.TrustServiceProviderList.TrustServiceProvider // [] | .[] | select(.UUID == $u) | .TSPInformation.TSPCertificationList.TSPCertification[] | select(.Type == "image-digest") | .Value] | unique'; }
digest_of_record() { jq -r '.image | sub("^[^@]*@"; "")' "$1"; }

record "$work/r1.json" b connector one
record "$work/r2.json" b connector two
record "$work/r3.json" b connector three
record "$work/ra.json" a connector one
v1=$(jq -r .measurement.value "$work/r1.json"); v2=$(jq -r .measurement.value "$work/r2.json")

echo "## no list yet"
run nolist publish "$work/r1.json"
check "no trust list: exit 1" [ "$rc" = 1 ]
check "no trust list: outcome list-missing" [ "$(field nolist .outcome)" = list-missing ]
check "no trust list: no write attempted" [ "$(writes)" = 0 ]

echo "## the list exists (federation setup, not the publisher's job)"
code=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT -H 'Authorization: Bearer enrolltf-token' -H 'Content-Type: application/json' \
  --data-binary '{"TrustServiceStatusList":{"FrameworkInformation":{"FrameworkName":{"Name":"test.local"}}}}' \
  "$TSPA_URL/tspa/v1/init/json/$fw/trust-list")
check "trust list created (201)" [ "$code" = 201 ]

echo "## first publication"
run p1 publish "$work/r1.json"
check "first publication: exit 0" [ "$rc" = 0 ]
check "first publication: outcome published" [ "$(field p1 .outcome)" = published ]
check "first publication: method PUT" [ "$(field p1 .tspa.method)" = PUT ]
check "first publication: after is [v1]" [ "$(fieldc p1 .after)" = "[\"$v1\"]" ]
uuid=$(field p1 .uuid)
check "first publication: one entry in the list" [ "$(entries)" = 1 ]
check "first publication: the list carries v1" [ "$(teems "$uuid")" = "[\"$v1\"]" ]
check "first publication: the list carries the image digest" [ "$(digests "$uuid")" = "[\"$(digest_of_record "$work/r1.json")\"]" ]
check "first publication: one evidence line" [ "$(wc -l < "$work/out-p1/publications.jsonl")" = 1 ]
check "first publication: stdout is the one EVENT_JSON line" [ "$(grep -c . "$work/p1.out")" = 1 ] 
check "first publication: stdout starts with EVENT_JSON=" grep -q '^EVENT_JSON=' "$work/p1.out"
check "first publication: readBack.listSha256 is a sha256" bash -c "[[ \"\$(sed -n 's/^EVENT_JSON=//p' '$work/p1.out' | jq -r .readBack.listSha256)\" =~ ^[0-9a-f]{64}\$ ]]"
check "first publication: readBack.vcHash is the VC's hash" bash -c "[[ \"\$(sed -n 's/^EVENT_JSON=//p' '$work/p1.out' | jq -r .readBack.vcHash)\" =~ ^[0-9a-f]{64}\$ ]]"
check "first publication: the request kept has the lookup key" [ "$(jq -r '.TrustServiceProvider.TSPServices.TSPService[0].ServiceTypeIdentifier' "$work/out-p1/last/request.json")" = "did:example:b-connector" ]

echo "## a new measurement for the same endpoint"
run p2 publish "$work/r2.json"
check "second publication: exit 0" [ "$rc" = 0 ]
check "second publication: method PATCH" [ "$(field p2 .tspa.method)" = PATCH ]
check "second publication: same UUID" [ "$(field p2 .uuid)" = "$uuid" ]
check "second publication: before is [v1]" [ "$(fieldc p2 .before)" = "[\"$v1\"]" ]
check "second publication: after is the union" [ "$(fieldc p2 .after)" = "$(jq -cn --arg a "$v1" --arg b "$v2" '[$a,$b] | unique')" ]
check "second publication: still one entry" [ "$(entries)" = 1 ]
check "second publication: the list carries both" [ "$(teems "$uuid")" = "$(jq -cn --arg a "$v1" --arg b "$v2" '[$a,$b] | unique')" ]
run v1b verify "$work/r1.json"
check "during the rollout the old version still verifies: exit 0" [ "$rc" = 0 ]
check "during the rollout the old version still verifies: outcome verified" [ "$(field v1b .outcome)" = verified ]

echo "## verify"
w=$(writes)
run v2 verify "$work/r2.json"
check "verify of a published value: exit 0" [ "$rc" = 0 ]
check "verify: outcome verified" [ "$(field v2 .outcome)" = verified ]
check "verify: no write" [ "$(writes)" = "$w" ]
run v3 verify "$work/r3.json"
check "verify of an unpublished value: exit 1" [ "$rc" = 1 ]
check "verify of an unpublished value: outcome not-published" [ "$(field v3 .outcome)" = not-published ]

echo "## prune"
run pr prune "$work/r2.json"
check "prune: exit 0" [ "$rc" = 0 ]
check "prune: outcome pruned" [ "$(field pr .outcome)" = pruned ]
check "prune: after is [v2]" [ "$(fieldc pr .after)" = "[\"$v2\"]" ]
check "prune: the list carries v2 alone" [ "$(teems "$uuid")" = "[\"$v2\"]" ]
check "prune: the image digest stays" [ "$(digests "$uuid")" = "[\"$(digest_of_record "$work/r2.json")\"]" ]

echo "## a new image for the same endpoint (both run during the rollout)"
record "$work/r4.json" b connector four "registry/b/connector@sha256:$(hex image-four)"
run p4 publish "$work/r4.json"
check "new image: exit 0" [ "$rc" = 0 ]
check "new image: the list carries both digests" [ "$(digests "$uuid")" = "$(jq -cn --arg a "$(digest_of_record "$work/r2.json")" --arg b "$(digest_of_record "$work/r4.json")" '[$a,$b] | unique')" ]
check "new image: the list carries both measurements" [ "$(teems "$uuid")" = "$(jq -cn --arg a "$v2" --arg b "$(jq -r .measurement.value "$work/r4.json")" '[$a,$b] | unique')" ]
run pr4 prune "$work/r4.json"
check "prune after the new image: exit 0" [ "$rc" = 0 ]
check "prune after the new image: one digest, the new one" [ "$(digests "$uuid")" = "[\"$(digest_of_record "$work/r4.json")\"]" ]
check "prune after the new image: one measurement, the new one" [ "$(teems "$uuid")" = "[\"$(jq -r .measurement.value "$work/r4.json")\"]" ]
w=$(writes)
run again publish "$work/r4.json"
check "publishing the same record again: exit 0" [ "$rc" = 0 ]
check "publishing the same record again: a PATCH, values unchanged" [ "$(fieldc again .after)" = "[\"$(jq -r .measurement.value "$work/r4.json")\"]" ]
check "publishing the same record again: one write" [ "$(writes)" = "$((w + 1))" ]
run pr prune "$work/r2.json"
check "back to r2 for the credential cases: exit 0" [ "$rc" = 0 ]

echo "## credentials that must not publish"
w=$(writes)
OIDC_CLIENT_SECRET=wrong run badsecret publish "$work/r3.json"
check "wrong secret: exit 1" [ "$rc" = 1 ]
check "wrong secret: outcome token-failed" [ "$(field badsecret .outcome)" = token-failed ]
check "wrong secret: no write attempted" [ "$(writes)" = "$w" ]
OIDC_CLIENT_ID=weak run weak publish "$work/r3.json"
check "token without enrolltf: exit 1" [ "$rc" = 1 ]
check "token without enrolltf: outcome write-rejected" [ "$(field weak .outcome)" = write-rejected ]
check "token without enrolltf: status 403 recorded" [ "$(field weak .tspa.status)" = 403 ]
check "token without enrolltf: list unchanged" [ "$(teems "$uuid")" = "[\"$v2\"]" ]
OIDC_CLIENT_ID=ghost run ghost publish "$work/r3.json"
check "token the TSPA ignores: exit 1" [ "$rc" = 1 ]
check "token the TSPA ignores: TSPA answered 200" [ "$(field ghost .tspa.status)" = 200 ]
check "token the TSPA ignores: outcome write-unconfirmed (the empty body)" [ "$(field ghost .outcome)" = write-unconfirmed ]
check "token the TSPA ignores: list unchanged" [ "$(teems "$uuid")" = "[\"$v2\"]" ]

printf 'enrolltf-token\n' > "$work/token.txt"
set +e; (unset OIDC_TOKEN_URL OIDC_CLIENT_ID OIDC_CLIENT_SECRET; TSPA_TOKEN_FILE="$work/token.txt" "$here/publish.sh" verify --record "$work/r2.json" --out "$work/out-tokfile") >"$work/tokfile.out" 2>"$work/tokfile.err"; rc=$?; set -e
check "a token already obtained (TSPA_TOKEN_FILE): exit 0" [ "$rc" = 0 ]
check "a token already obtained: outcome verified" [ "$(field tokfile .outcome)" = verified ]
printf 'not.a.jwt\n' > "$work/bad-token.txt"
set +e; (unset OIDC_TOKEN_URL OIDC_CLIENT_ID OIDC_CLIENT_SECRET; TSPA_TOKEN_FILE="$work/bad-token.txt" "$here/publish.sh" publish --record "$work/r3.json" --out "$work/out-badtok") >"$work/badtok.out" 2>"$work/badtok.err"; rc=$?; set -e
check "a malformed token: exit 1" [ "$rc" = 1 ]
check "a malformed token: outcome write-rejected, status 401" [ "$(field badtok .outcome)" = write-rejected ] 
check "a malformed token: status 401 recorded" [ "$(field badtok .tspa.status)" = 401 ]
check "a malformed token: list unchanged" [ "$(teems "$uuid")" = "[\"$v2\"]" ]
OIDC_CLIENT_ID=ghost run ghost2 publish "$work/r2.json"
check "re-publishing a value already there with an ignored token: exit 1 (not a false success)" [ "$rc" = 1 ]
check "re-publishing a value already there with an ignored token: outcome write-unconfirmed" [ "$(field ghost2 .outcome)" = write-unconfirmed ]

echo "## UUIDs"
run pa publish "$work/ra.json"
check "another zone: exit 0" [ "$rc" = 0 ]
check "another zone: a different UUID" [ "$(field pa .uuid)" != "$uuid" ]
check "another zone: two entries now" [ "$(entries)" = 2 ]
check "UUID is a v5" [ "$(cut -c15 <<<"$uuid")" = 5 ]

echo "## the TSPA cannot be reached"
TSPA_URL="http://127.0.0.1:1/tspa-service" run down publish "$work/r3.json"
check "unreachable TSPA: exit 1" [ "$rc" = 1 ]
check "unreachable TSPA: outcome transport-failure" [ "$(field down .outcome)" = transport-failure ]

echo "## a writer racing the publisher between its read and its write"
rc_fw=race-a
curl -sS -o /dev/null -X PUT -H 'Authorization: Bearer enrolltf-token' -H 'Content-Type: application/json' \
  --data-binary '{"TrustServiceStatusList":{"FrameworkInformation":{"FrameworkName":{"Name":"race-a"}}}}' "$TSPA_URL/tspa/v1/init/json/$rc_fw/trust-list"
TSPA_FRAMEWORK=$rc_fw run race0 publish "$work/r1.json"
check "race setup: first publication in the race framework" [ "$rc" = 0 ]
curl -sS -o /dev/null -X POST --data-binary "$(jq -cn --arg f "$rc_fw" --arg u "$uuid" '{framework:$f, remove:$u}')" "$base/__fake/after-next-get"
TSPA_FRAMEWORK=$rc_fw run race1 publish "$work/r2.json"
check "entry removed after the read: exit 0 through the PATCH -> PUT fallback" [ "$rc" = 0 ]
check "entry removed after the read: the final write was a PUT" [ "$(field race1 .tspa.method)" = PUT ]
check "entry removed after the read: v2 published" [ "$(TSPA_FRAMEWORK=$rc_fw teems "$uuid")" = "[\"$v2\"]" ]
curl -sS -o /dev/null -X DELETE -H 'Authorization: Bearer enrolltf-token' "$TSPA_URL/tspa/v1/$rc_fw/trust-list/tsp/$uuid"
curl -sS -o /dev/null -X POST --data-binary "$(jq -cn --arg f "$rc_fw" --argjson e "$(jq .TrustServiceProvider "$work/out-race0/last/request.json")" '{framework:$f, add:$e}')" "$base/__fake/after-next-get"
TSPA_FRAMEWORK=$rc_fw run race2 publish "$work/r2.json"
check "entry created after the read: exit 0 through the PUT -> PATCH fallback" [ "$rc" = 0 ]
check "entry created after the read: the final write was a PATCH" [ "$(field race2 .tspa.method)" = PATCH ]
check "entry created after the read: the union is published" [ "$(TSPA_FRAMEWORK=$rc_fw teems "$uuid")" = "$(jq -cn --arg a "$v1" --arg b "$v2" '[$a,$b] | unique')" ]

echo "## a list that needs repair, and a broken TSPA"
curl -sS -o /dev/null -X POST --data-binary "$(jq -cn --arg f "$rc_fw" --arg u "$uuid" '{framework:$f, uuid:$u}')" "$base/__fake/duplicate"
TSPA_FRAMEWORK=$rc_fw run dup publish "$work/r2.json"
check "two entries with the UUID: exit 1" [ "$rc" = 1 ]
check "two entries with the UUID: outcome duplicate-entry, nothing written" [ "$(field dup .outcome)" = duplicate-entry ]
check "two entries with the UUID: no write attempted" [ "$(field dup .tspa.method)" = null ]
TSPA_FRAMEWORK=error-500 run boom publish "$work/r1.json"
check "a TSPA answering 500: exit 1" [ "$rc" = 1 ]
check "a TSPA answering 500: outcome tspa-error" [ "$(field boom .outcome)" = tspa-error ]

echo "## records and configuration the publisher refuses before any call"
w=$(writes)
record "$work/bad-prefixed.json" b connector x "" "sha256:$(hex x)"
run badval publish "$work/bad-prefixed.json"
check "prefixed measurement value: exit 2" [ "$rc" = 2 ]
record "$work/bad-image.json" b connector x "registry/b/connector:latest"
run badimg publish "$work/bad-image.json"
check "image by tag instead of digest: exit 2" [ "$rc" = 2 ]
jq '. + {extra: 1}' "$work/r1.json" > "$work/bad-extra.json"
run badextra publish "$work/bad-extra.json"
check "a record with an unknown key: exit 2" [ "$rc" = 2 ]
run badact frobnicate "$work/r1.json"
check "unknown action: exit 2" [ "$rc" = 2 ]
set +e; "$here/publish.sh" publish --out "$work/out-x" --record >/dev/null 2>&1; rc=$?; set -e
check "--record without a value: exit 2" [ "$rc" = 2 ]
set +e; "$here/publish.sh" publish --record "$work/r1.json" --out '' >/dev/null 2>&1; rc=$?; set -e
check "--out with an empty value: exit 2" [ "$rc" = 2 ]
set +e; (unset OIDC_TOKEN_URL OIDC_CLIENT_ID OIDC_CLIENT_SECRET; TSPA_TOKEN_FILE="$work/does-not-exist" "$here/publish.sh" publish --record "$work/r1.json" --out "$work/out-notok") >/dev/null 2>&1; rc=$?; set -e
check "TSPA_TOKEN_FILE that does not exist: exit 2" [ "$rc" = 2 ]
set +e; (unset TSPA_FRAMEWORK; "$here/publish.sh" publish --record "$work/r1.json" --out "$work/out-nofw") >/dev/null 2>&1; rc=$?; set -e
check "missing TSPA_FRAMEWORK: exit 2" [ "$rc" = 2 ]
set +e; (unset OIDC_TOKEN_URL OIDC_CLIENT_ID OIDC_CLIENT_SECRET; "$here/publish.sh" publish --record "$work/r1.json" --out "$work/out-nocred") >/dev/null 2>&1; rc=$?; set -e
check "no credentials: exit 2" [ "$rc" = 2 ]
check "refused records and configuration: no request reached the TSPA" [ "$(writes)" = "$w" ]

echo "## the entry must satisfy the real entry schema"
jq 'del(.TrustServiceProvider.TSPInformation.TSPInformationURI)' "$here/entry.tmpl.json" > "$work/broken.tmpl.json"
TRAIN_PUBLISH_TEMPLATE="$work/broken.tmpl.json" run badtmpl publish "$work/r4.json"
check "a template missing a required field: exit 1" [ "$rc" = 1 ]
check "a template missing a required field: outcome write-rejected (400 from the schema)" [ "$(field badtmpl .outcome)" = write-rejected ]
check "a template missing a required field: list unchanged" [ "$(teems "$uuid")" = "[\"$v2\"]" ]

echo "## nothing secret in any output"
leaks=$(grep -rl -e "$secret" -e enrolltf-token -e plain-token -e ghost-token "$work"/out-* "$work"/*.out "$work"/*.err "$work/requests.jsonl" 2>/dev/null | grep -v -E '/(fake\.err|token\.txt)$' || true)
check "no secret or token in records, stdout or stderr" [ -z "$leaks" ]
[ -n "$leaks" ] && echo "leaked in: $leaks"

echo
if [ "$fails" = 0 ]; then echo "publish_test: all checks passed"; else echo "publish_test: $fails check(s) failed"; exit 1; fi
