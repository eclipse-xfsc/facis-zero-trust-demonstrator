#!/usr/bin/env bash
# The fast cases of the TRAIN resolution, in seconds and without a cluster: the publisher writes
# real entries into the TSPA stand-in (scripts/train-publish/fake_tspa.py), the resolver stand-in
# (fake_tcr.py) answers the TCR's resolve API over that list, and the probe
# (cmd/train-resolve-probe) verifies peers against it with the gateway's own code
# (internal/trainresolve). Each case is one outcome the gateway must produce: accepted, served from
# the cache, mismatch, no measurement, unknown zone, not published, zero values, a rolling update
# accepted on both versions and pruned, a removal that bites within the TTL, an unverified
# credential, a resolver down or failing. No secret in any output.
#
#   scripts/train-resolve/resolve_test.sh
#
# Needs bash, curl, jq, python3, sha256sum and go; no network beyond localhost.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pub="$here/../train-publish"
root="$here/../.."
for tool in curl jq python3 sha256sum go; do
  command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 2; }
done
work="$(mktemp -d)"
pids=()
cleanup() { for p in ${pids[@]+"${pids[@]}"}; do kill "$p" 2>/dev/null || true; done; for p in ${pids[@]+"${pids[@]}"}; do wait "$p" 2>/dev/null || true; done; rm -rf "$work"; }   # empty-array-safe under set -u on bash 3.2
trap cleanup EXIT

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
wait_up() { for _ in $(seq 50); do curl -sf --max-time 1 -o /dev/null "$1" && return 0; sleep 0.1; done; echo "did not start: $1" >&2; exit 2; }
now_ms() { python3 -c 'import time; print(int(time.time()*1000))'; }
iso_ms() { python3 -c "import datetime,sys; print(int(datetime.datetime.fromisoformat(sys.argv[1].replace('Z','+00:00')).timestamp()*1000))" "$1"; }

echo "## build the probe"
( cd "$root" && go build -o "$work/probe" ./cmd/train-resolve-probe )

echo "## the TSPA stand-in, its list, the publisher's environment"
tspa_port=$(free_port)
secret="test-secret-$RANDOM$RANDOM"
FAKE_TSPA_SECRET=$secret python3 "$pub/fake_tspa.py" --port "$tspa_port" --log "$work/tspa.jsonl" 2>"$work/tspa.err" &
pids+=($!)
wait_up "http://127.0.0.1:$tspa_port/tspa-service/actuator/health"
export TSPA_URL="http://127.0.0.1:$tspa_port/tspa-service" TSPA_FRAMEWORK=test.local
export OIDC_TOKEN_URL="http://127.0.0.1:$tspa_port/realms/test/protocol/openid-connect/token" OIDC_CLIENT_ID=publisher OIDC_CLIENT_SECRET=$secret
fw=$TSPA_FRAMEWORK
api="$TSPA_URL/tspa/v1"
curl -sS -o /dev/null -X PUT -H 'Authorization: Bearer enrolltf-token' -H 'Content-Type: application/json' \
  --data-binary '{"TrustServiceStatusList":{"FrameworkInformation":{"FrameworkName":{"Name":"test.local"}}}}' "$api/init/json/$fw/trust-list"

echo "## the resolver stand-in over that list"
tcr_port=$(free_port)
python3 "$here/fake_tcr.py" --port "$tcr_port" --tspa "$TSPA_URL" --pointer "zone-b.$fw=$fw" --log "$work/tcr.jsonl" 2>"$work/tcr.err" &
pids+=($!)
wait_up "http://127.0.0.1:$tcr_port/actuator/health"
tcr="http://127.0.0.1:$tcr_port"

fails=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; fails=$((fails + 1)); }
check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi; }
hex() { printf '%s' "$1" | sha256sum | cut -c1-64; }
identity="spiffe://zone-b.$fw/gateway"
v1=$(hex teem-v1); v2=$(hex teem-v2); other=$(hex teem-other)
record() {  # record <file> <value>: a measurement record for zone b's gateway with that value
  jq -n --arg v "$2" --arg cfg "$(hex cfg)" --arg rfs "$(hex rootfs)" --arg img "registry/b/gateway@sha256:$(hex image)" --arg sti "$identity" '
    {component: "gateway", zone: "b", serviceTypeIdentifier: $sti, image: $img,
     measurement: {type: "TEEM-sha256", value: $v, configSha256: $cfg, rootfsSha256: $rfs},
     source: {commit: "0123456789abcdef", tool: "cmc 6754d3c measure"}}' > "$1"
}
rc=0
probe() {  # probe <args...>: the probe; rc and the records kept
  set +e
  "$work/probe" "$@" >"$work/probe.out" 2>"$work/probe.err"
  rc=$?
  set -e
}
last() { tail -1 "$work/probe.out" | jq -r "$1"; }
nth() { sed -n "${1}p" "$work/probe.out" | jq -r "$2"; }
resolves() { jq -r 'select(.path == "/tcr/v1/resolve") | .path' "$work/tcr.jsonl" 2>/dev/null | wc -l | tr -d ' '; }
publish() {  # publish <action> <record>
  set +e
  "$pub/publish.sh" "$1" --record "$2" --out "$work/pub" >"$work/pub.out" 2>"$work/pub.err"
  rc=$?
  set -e
}
has() { grep -q -- "$1" <<<"$2"; }

echo "## 1. before any publication: the list exists, the peer has no entry"
probe -tcr "$tcr" -identity "$identity" -digest "$v1"
check "not published: exit 2" [ "$rc" = 2 ]
check "not published: CHAN-MEASUREMENT-UNPUBLISHED" [ "$(last .code)" = CHAN-MEASUREMENT-UNPUBLISHED ]
check "not published: no values" [ "$(last .expectedCount)" = 0 ]
check "not published: no entry UUID" [ "$(last '.entryUUID // empty')" = "" ]
check "the resolver was asked with the identity as the issuer" [ "$(jq -r 'select(.path == "/tcr/v1/resolve") | .body.issuer' "$work/tcr.jsonl" | tail -1)" = "$identity" ]
check "the resolver was asked with the zone domain as the pointer" [ "$(jq -c 'select(.path == "/tcr/v1/resolve") | .body.trustSchemePointers' "$work/tcr.jsonl" | tail -1)" = "[\"zone-b.$fw\"]" ]

echo "## 2. the publisher writes v1; the peer presenting v1 is accepted"
record "$work/r1.json" "$v1"
publish publish "$work/r1.json"
check "publish v1: exit 0" [ "$rc" = 0 ]
uuid=$(sed -n 's/^EVENT_JSON=//p' "$work/pub.out" | tail -1 | jq -r .uuid)
probe -tcr "$tcr" -identity "$identity" -digest "$v1"
check "v1 accepted: exit 0" [ "$rc" = 0 ]
check "v1 accepted: outcome accepted" [ "$(last .outcome)" = accepted ]
check "v1 accepted: the first resolution is not from the cache" [ "$(last .fromCache)" = false ]
check "v1 accepted: one expected value" [ "$(last .expectedCount)" = 1 ]
check "v1 accepted: the entry is the publisher's" [ "$(last .entryUUID)" = "$uuid" ]
check "v1 accepted: the trust list URI recorded" [ "$(last .trustList)" = "$api/$fw/trust-list" ]

echo "## 3. two verifications in one process: the second is served from the cache"
before=$(resolves)
probe -tcr "$tcr" -identity "$identity" -digest "$v1" -repeat 2 -interval 0
check "repeat 2: exit 0" [ "$rc" = 0 ]
check "second verification from the cache" [ "$(nth 2 .fromCache)" = true ]
check "stats: one hit" [ "$(nth 2 .stats.Hits)" = 1 ]
check "stats: one miss" [ "$(nth 2 .stats.Misses)" = 1 ]
check "the resolver was asked once for the two" [ "$(( $(resolves) - before ))" = 1 ]

echo "## 4. a peer presenting another value is refused"
probe -tcr "$tcr" -identity "$identity" -digest "$other"
check "mismatch: exit 2" [ "$rc" = 2 ]
check "mismatch: CHAN-MEASUREMENT-MISMATCH" [ "$(last .code)" = CHAN-MEASUREMENT-MISMATCH ]
check "mismatch: the expected value was there" [ "$(last .expectedCount)" = 1 ]
check "mismatch: the reason names the presented side" has "${other:0:12}" "$(last .reason)"
check "mismatch: the reason names the expected side" has "${v1:0:12}" "$(last .reason)"
check "mismatch: no full value in the reason" bash -c "! grep -q -- '$v1' <<<'$(last .reason)'"

echo "## 5. a peer without a SHA-256 measurement is refused before TRAIN is asked"
before=$(resolves)
probe -tcr "$tcr" -identity "$identity"
check "no digest: exit 2" [ "$rc" = 2 ]
check "no digest: CHAN-MEASUREMENT-MISMATCH" [ "$(last .code)" = CHAN-MEASUREMENT-MISMATCH ]
check "no digest: the resolver was not asked" [ "$(resolves)" = "$before" ]
probe -tcr "$tcr" -identity "$identity" -digest "$(tr a-f A-F <<<"$v1")"
check "uppercase digest: refused" [ "$rc" = 2 ]
check "uppercase digest: not normalised, the resolver was not asked" [ "$(resolves)" = "$before" ]

echo "## 6. a peer from a zone without a PTR record: unknown zone"
probe -tcr "$tcr" -identity "spiffe://zone-c.$fw/gateway" -digest "$v1"
check "unknown zone: exit 2" [ "$rc" = 2 ]
check "unknown zone: CHAN-ZONE-UNKNOWN" [ "$(last .code)" = CHAN-ZONE-UNKNOWN ]
before=$(resolves)
probe -tcr "$tcr" -identity "gateway.zone-b.$fw" -digest "$v1"
check "a DNS SAN without a configured pointer: CHAN-ZONE-UNKNOWN" [ "$(last .code)" = CHAN-ZONE-UNKNOWN ]
check "a DNS SAN without a configured pointer: no network" [ "$(resolves)" = "$before" ]
probe -tcr "$tcr" -identity "gateway.zone-b.$fw" -digest "$v1" -pointer "zone-b.$fw"
check "a DNS SAN with the pointer configured: looked up under the identity" [ "$(last .key)" = "gateway.zone-b.$fw" ]
check "a DNS SAN with the pointer configured: nothing published under it" [ "$(last .code)" = CHAN-MEASUREMENT-UNPUBLISHED ]

echo "## 7. a rolling update: v2 published beside v1, both accepted; pruned to v2, v1 refused"
record "$work/r2.json" "$v2"
publish publish "$work/r2.json"
check "publish v2: exit 0" [ "$rc" = 0 ]
probe -tcr "$tcr" -identity "$identity" -digest "$v1"
check "during the rollout v1 is accepted" [ "$rc" = 0 ]
check "during the rollout two values are expected" [ "$(last .expectedCount)" = 2 ]
probe -tcr "$tcr" -identity "$identity" -digest "$v2"
check "during the rollout v2 is accepted" [ "$rc" = 0 ]
publish prune "$work/r2.json"
check "prune to v2: exit 0" [ "$rc" = 0 ]
probe -tcr "$tcr" -identity "$identity" -digest "$v1"
check "after the prune v1 is refused" [ "$(last .code)" = CHAN-MEASUREMENT-MISMATCH ]
check "after the prune one value is expected" [ "$(last .expectedCount)" = 1 ]
probe -tcr "$tcr" -identity "$identity" -digest "$v2"
check "after the prune v2 is accepted" [ "$rc" = 0 ]

echo "## 8. a removal bites within the TTL: the probe keeps verifying, the entry is deleted, the refusal arrives"
rm -f "$work/window.jsonl"
set +e
"$work/probe" -tcr "$tcr" -identity "$identity" -digest "$v2" -until-code CHAN-MEASUREMENT-UNPUBLISHED -ttl 3s -interval 0.25s -deadline 20s -record "$work/window.jsonl" >"$work/window.out" 2>"$work/window.err" &
wpid=$!
set -e
for _ in $(seq 100); do grep -q '"outcome":"accepted"' "$work/window.jsonl" 2>/dev/null && break; sleep 0.1; done
check "the probe accepted v2 before the removal" grep -q '"outcome":"accepted"' "$work/window.jsonl"
deleted_at=$(now_ms)
code=$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE -H 'Authorization: Bearer enrolltf-token' "$api/$fw/trust-list/tsp/$uuid")
check "the entry was deleted from the list ($code)" bash -c "[ '$code' = 200 ] || [ '$code' = 204 ]"
set +e; wait "$wpid"; wrc=$?; set -e
check "the refusal arrived before the deadline: exit 0" [ "$wrc" = 0 ]
transition=$(tail -1 "$work/window.out")
check "transition observed" [ "$(jq -r .observed <<<"$transition")" = true ]
after_ms=$(jq -r .transitionAfterMs <<<"$transition")
check "the refusal came within the TTL of 3 s plus one interval ($after_ms ms after the first acceptance)" [ "$after_ms" -le 3500 ]
first_ms=$(iso_ms "$(jq -r .firstAcceptedAt <<<"$transition")")
transition_ms=$(iso_ms "$(jq -r .transitionAt <<<"$transition")")
check "the first acceptance came before the deletion" [ "$first_ms" -le "$deleted_at" ]
check "the refusal never came before the deletion" [ "$transition_ms" -ge "$deleted_at" ]
early=$(jq -r --argjson d "$deleted_at" 'select(.outcome == "refused") | .ts' "$work/window.jsonl" | while read -r ts; do [ "$(iso_ms "$ts")" -lt "$deleted_at" ] && echo early; done || true)
check "no refusal was recorded before the deletion" [ -z "$early" ]

echo "## 9. an entry without a TEEM-sha256 value: not published"
record "$work/r3.json" "$v1"
publish publish "$work/r3.json"
check "republish v1 after the removal: exit 0" [ "$rc" = 0 ]
curl -sS "$api/$fw/trust-list" | jq --arg u "$uuid" '.TrustServiceStatusList.TrustServiceProviderList.TrustServiceProvider[] | select(.UUID == $u)
  | .TSPInformation.TSPCertificationList.TSPCertification |= map(select(.Type != "TEEM-sha256")) | {TrustServiceProvider: .}' > "$work/stripped.json"
code=$(curl -sS -o /dev/null -w '%{http_code}' -X PATCH -H 'Authorization: Bearer enrolltf-token' -H 'Content-Type: application/json' --data-binary @"$work/stripped.json" "$api/$fw/trust-list/tsp/$uuid")
check "the entry was patched to zero TEEM values ($code)" [ "$code" = 200 ]
probe -tcr "$tcr" -identity "$identity" -digest "$v1"
check "zero values: CHAN-MEASUREMENT-UNPUBLISHED" [ "$(last .code)" = CHAN-MEASUREMENT-UNPUBLISHED ]
check "zero values: the entry is named" [ "$(last .entryUUID)" = "$uuid" ]
publish publish "$work/r3.json"
check "republish v1 restores the value" [ "$rc" = 0 ]

echo "## 10. a resolver that did not verify the credential: unreachable, deny"
unv_port=$(free_port)
python3 "$here/fake_tcr.py" --port "$unv_port" --tspa "$TSPA_URL" --pointer "zone-b.$fw=$fw" --vc-unverified 2>"$work/unv.err" &
pids+=($!)
wait_up "http://127.0.0.1:$unv_port/actuator/health"
probe -tcr "http://127.0.0.1:$unv_port" -identity "$identity" -digest "$v1"
check "unverified credential: exit 2" [ "$rc" = 2 ]
check "unverified credential: CHAN-TRUST-UNREACHABLE" [ "$(last .code)" = CHAN-TRUST-UNREACHABLE ]
check "unverified credential: the reason says so" has 'did not verify the trust-list credential' "$(last .reason)"

echo "## 11. a resolver failing or down: unreachable, deny, within the handshake budget"
fail_port=$(free_port)
python3 "$here/fake_tcr.py" --port "$fail_port" --tspa "$TSPA_URL" --fail 502 2>"$work/fail.err" &
pids+=($!)
wait_up "http://127.0.0.1:$fail_port/actuator/health"
probe -tcr "http://127.0.0.1:$fail_port" -identity "$identity" -digest "$v1"
check "resolver answering 502: CHAN-TRUST-UNREACHABLE" [ "$(last .code)" = CHAN-TRUST-UNREACHABLE ]
check "resolver answering 502: the status in the reason" has 'answered 502' "$(last .reason)"
down_port=$(free_port)
probe -tcr "http://127.0.0.1:$down_port" -identity "$identity" -digest "$v1" -resolve-timeout 2s
check "resolver down: CHAN-TRUST-UNREACHABLE" [ "$(last .code)" = CHAN-TRUST-UNREACHABLE ]
check "resolver down: refused within the budget" [ "$(last .elapsedMs)" -lt 5000 ]
dead_port=$(free_port)
python3 "$here/fake_tcr.py" --port "$dead_port" --tspa "http://127.0.0.1:$down_port/tspa-service" --pointer "zone-b.$fw=$fw" 2>"$work/dead.err" &
pids+=($!)
wait_up "http://127.0.0.1:$dead_port/actuator/health"
probe -tcr "http://127.0.0.1:$dead_port" -identity "$identity" -digest "$v1"
check "resolver whose TSPA is down: CHAN-TRUST-UNREACHABLE" [ "$(last .code)" = CHAN-TRUST-UNREACHABLE ]

echo "## 12. no secret in any output"
check "no client secret in the records or logs" bash -c "! grep -q -- '$secret' '$work/probe.out' '$work/window.jsonl' '$work/tcr.jsonl' '$work/probe.err'"
check "no bearer token in the resolver log" bash -c "! grep -q 'enrolltf-token' '$work/tcr.jsonl'"

if [ "$fails" = 0 ]; then echo "resolve_test: all checks passed"; else echo "resolve_test: $fails check(s) failed"; exit 1; fi
