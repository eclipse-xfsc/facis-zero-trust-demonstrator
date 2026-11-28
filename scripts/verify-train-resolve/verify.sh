#!/usr/bin/env bash
# Proof of the TRAIN resolution (internal/trainresolve, through cmd/train-resolve-probe) against the
# real TSPA and the real zone manager: upstream's TSPA image built from its Dockerfile at the pinned
# commit, installed with upstream's chart and test realm on a disposable kind cluster (the kit under
# scripts/verify-tspa-api, with TSPA_ZONE_MANAGER=1). The reconciler publishes the zones' claims, so
# the PTR records exist in a real name server; the publisher writes the gateway's measurement entry
# into the real list; the resolver stand-in (scripts/train-resolve/fake_tcr.py) answers the TCR's
# resolve API by walking that DNS and reading that list; the probe verifies peers against it with
# the gateway's own code. The cases are the task's done-when: accepted only when TRAIN vouches,
# refused with the reason code when the measurement is absent or differs, a removal that bites
# within the documented window (measured against the real 300 s cache), a resolver that is down,
# failing or cannot verify the credential denies. Every check appends to the evidence file; the exit
# status is non-zero when any failed.
#
#   TSPA_REPO=<clone of eclipse-xfsc/train-trust-framework-manager, with train-shared in shared/> \
#     scripts/verify-train-resolve/verify.sh [--out DIR]
#
#   --out DIR   raw records of the run (default: .dev/train-resolve-proof, which git ignores): the
#               probe's records per case, the publisher's and reconciler's outputs, the stand-in's
#               request log, and the kind-up log
#
# Environment:
#   TSPA_REPO               required by the kit's kind-up.sh (the first image build takes about 15 minutes)
#   TRAIN_PROOF_EVIDENCE    where the evidence goes (default: evidence.md next to this script)
#   TRAIN_RESOLVE_WINDOW    the cache window the removal case measures against (default 300, the
#                           staleness matrix; a shorter value only to rehearse the script)
#
# Needs kind, kubectl, helm, docker, curl, jq, python3, sha256sum, dig and go. ZONE_MANAGER_REPO may
# name a checkout of the zone manager at the DNS kit's pinned commit; without it the kit fetches one.
# shellcheck disable=SC2016  # jq programs quote $names on purpose
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
kit="$root/scripts/verify-tspa-api"
reconciler="$root/scripts/train-trust-list/reconcile.sh"
publisher="$root/scripts/train-publish/publish.sh"
fake_tcr="$root/scripts/train-resolve/fake_tcr.py"
desired_src="$root/deployment/train/trust-lists/facis-ztd.local.json"
out="$root/.dev/train-resolve-proof"
evidence="${TRAIN_PROOF_EVIDENCE:-$here/evidence.md}"
kubeconfig="$root/.dev/tspa/kubeconfig"

fw=facis-ztd.local
window=${TRAIN_RESOLVE_WINDOW:-300}   # seconds: the trust-list cache, docs/architecture.md staleness matrix
zone_b=zone-b.$fw
identity="spiffe://$zone_b/gateway"   # the peer's identity as the channel reports it: key and pointer

die() { echo "verify.sh: $*" >&2; exit 2; }
while [ $# -gt 0 ]; do
  case $1 in
    --out) { [ $# -ge 2 ] && [ -n "$2" ]; } || die "--out needs a directory"; out=$2; shift 2 ;;
    -h|--help) sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done
for tool in kind kubectl helm docker curl jq python3 sha256sum dig go; do
  command -v "$tool" >/dev/null || die "$tool is required"
done
[ -n "${TSPA_REPO:-}" ] || die "set TSPA_REPO to a clone of train-trust-framework-manager (see scripts/verify-tspa-api/README.md)"
[ -x "$reconciler" ] || die "reconciler not found: $reconciler"
[ -x "$publisher" ] || die "publisher not found: $publisher"
[ -f "$fake_tcr" ] || die "resolver stand-in not found: $fake_tcr"
[ "$(jq -r .framework "$desired_src")" = "$fw" ] || die "$desired_src does not govern $fw"
[[ "$window" =~ ^[0-9]+$ ]] || die "TRAIN_RESOLVE_WINDOW must be a number of seconds"

mkdir -p "$out"; out="$(cd "$out" && pwd)"
steps="$out/steps"; files="$out/files"
rm -rf "$steps" "$files"; mkdir -p "$steps" "$files"
umask 077
work="$(mktemp -d)"
pids=()
cleanup() {
  local s=$?
  # "${pids[@]+"${pids[@]}"}": an empty array under set -u is an error in bash before 4.4 (macOS).
  for p in ${pids[@]+"${pids[@]}"}; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$work"
  exit "$s"
}
trap cleanup EXIT

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
now_ms() { python3 -c 'import time; print(int(time.time()*1000))'; }
iso_ms() { python3 -c "import datetime,sys; print(int(datetime.datetime.fromisoformat(sys.argv[1].replace('Z','+00:00')).timestamp()*1000))" "$1"; }
body="$work/body.md"; : > "$body"; : > "$work/checks"; : > "$work/summary.tsv"
say() { printf '%s\n' "$@" >> "$body"; }
code() { say '' '```'; say "$@"; say '```' ''; }
note() { say "  $*"; }
check() {  # check <title> <command...>: PASS when the command succeeds; counted either way
  local title=$1; shift
  echo x >> "$work/checks"
  if "$@" >/dev/null 2>&1; then say "- PASS: $title"; echo "PASS  $title"
  else say "- **FAIL**: $title"; echo "FAIL  $title"; echo "$title" >> "$work/fails"; fi
}
fails() { if [ -f "$work/fails" ]; then wc -l < "$work/fails" | tr -d ' '; else echo 0; fi; }
has() { grep -q -- "$1" <<<"$2"; }
k() { kubectl --kubeconfig "$kubeconfig" "$@"; }
row() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$work/summary.tsv"; }   # case, expected, code, exit

# ---- 0. the probe, built from this checkout ------------------------------------------------------
echo "== the probe"
( cd "$root" && go build -o "$work/probe" ./cmd/train-resolve-probe ) || die "the probe does not build"

# ---- the TSPA, Keycloak, the zone manager and the lanes to them ----------------------------------
echo "== TSPA, Keycloak and the zone manager on kind (the kit's kind-up.sh)"
TSPA_REPO=$TSPA_REPO TSPA_ZONE_MANAGER=1 TSPA_ZONE=$fw "$kit/kind-up.sh" > "$out/kind-up.log" 2>&1 || die "kind-up.sh failed; see $out/kind-up.log"
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
forward() {  # forward <service> <remote-port> <local-port> <ready-url>: a port-forward that answers
  k -n tspa port-forward "svc/$1" "$3:$2" >/dev/null 2>"$work/pf-$1.log" &
  pids+=("$!")
  for _ in $(seq 60); do curl -s --max-time 2 -o /dev/null "$4" && return 0; sleep 1; done
  die "no answer from $1 through the port-forward: $(cat "$work/pf-$1.log")"
}
tspa_port=$(free_port); kc_port=$(free_port); dns_port=$(free_port)
forward tspa-service 16003 "$tspa_port" "http://127.0.0.1:$tspa_port/tspa-service/api/docs"
forward keycloak 8080 "$kc_port" "http://127.0.0.1:$kc_port/realms/gxfs-dev-test"
# A port-forward carries TCP only, so every DNS question here asks over TCP.
k -n tspa port-forward svc/nsd-service-dns "$dns_port:53" >/dev/null 2>"$work/pf-dns.log" &
pids+=("$!")
for _ in $(seq 60); do dig +short +tcp +time=2 +tries=1 -p "$dns_port" SOA "$fw" @127.0.0.1 >/dev/null 2>&1 && break; sleep 1; done
export TRAIN_DNS_SERVER=127.0.0.1 TRAIN_DNS_PORT=$dns_port TRAIN_DNS_TCP=1
export TSPA_URL="http://127.0.0.1:$tspa_port/tspa-service" TSPA_FRAMEWORK=$fw
export OIDC_TOKEN_URL="http://127.0.0.1:$kc_port/realms/gxfs-dev-test/protocol/openid-connect/token" OIDC_CLIENT_ID=xfsctest
api="$TSPA_URL/tspa/v1"
# The test client's secret, from upstream's realm export; it reaches the scripts through their
# environment and the proof's own token requests through a body file, never an argument.
OIDC_CLIENT_SECRET=$(python3 -c "import json,sys;print([c for c in json.load(open(sys.argv[1]))['clients'] if c['clientId']=='xfsctest'][0]['secret'])" "$TSPA_REPO/keycloak/realm-export.json")
[ -n "$OIDC_CLIENT_SECRET" ] || die "no secret for xfsctest in $TSPA_REPO/keycloak/realm-export.json"
export OIDC_CLIENT_SECRET

say "## 1. The TSPA, Keycloak, the zone manager and the lanes to them" ""
docs=$(curl -s --max-time 30 -o /dev/null -w '%{http_code}' "$TSPA_URL/api/docs") || docs=000
check "the TSPA answers through the port-forward (GET /api/docs $docs)" [ "$docs" = 200 ]
soa=$(dig +short +tcp +time=3 +tries=1 -p "$dns_port" SOA "$fw" @127.0.0.1 2>/dev/null || true)
check "the zone manager's name server answers authoritatively for $fw over the forwarded TCP port" bash -c "[[ '$soa' == ns1.* ]]"
note "SOA of \`$fw\`: \`$soa\`"
fetch_token() {  # fetch_token <out-file>
  jq -rnj 'env.OIDC_CLIENT_SECRET as $s | "client_id=xfsctest&client_secret=\($s|@uri)&grant_type=client_credentials"' > "$work/form"
  curl -sS --max-time 30 -o "$work/tok.json" -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @"$work/form" "$OIDC_TOKEN_URL" \
    || die "token endpoint unreachable"
  rm -f "$work/form"
  jq -rj '.access_token // empty' "$work/tok.json" > "$1"
  [ -s "$1" ] || die "no token obtained: $(jq -c 'del(.access_token)' "$work/tok.json")"
}
fetch_token "$work/operator.tok"   # dies when no token comes back; nothing below runs without one
tspa() {  # tspa <method> <path> [body-file] [token-file]: the proof's own calls; prints the status, body in $work/resp
  local method=$1 path=$2 bodyfile=${3:-} tokfile=${4:-}
  local args=(-sS --max-time 120 -o "$work/resp" -w '%{http_code}' -X "$method" "$api$path")
  [ -n "$bodyfile" ] && args+=(-H 'Content-Type: application/json' --data-binary @"$bodyfile")
  if [ -n "$tokfile" ]; then printf 'Authorization: Bearer %s\n' "$(cat "$tokfile")" > "$work/auth.h"; args+=(-H @"$work/auth.h"); fi
  curl "${args[@]}" 2>"$work/curl.err" || echo 000
  rm -f "$work/auth.h"
}
list() { curl -sS --max-time 60 "$api/$fw/trust-list" || echo '{"unreachable": true}'; }
all_entries() { list | jq '[.TrustServiceStatusList.TrustServiceProviderList.TrustServiceProvider // [] | .[]] | length'; }
entry() { list | jq -c --arg u "$1" '[.TrustServiceStatusList.TrustServiceProviderList.TrustServiceProvider // [] | .[] | select(.UUID == $u)]'; }
hex() { printf '%s' "$1" | sha256sum | cut -c1-64; }

# ---- 2. the list, the zones' claims, the publisher's entry ---------------------------------------
echo "== the list, the zones, the publisher's entry"
say "## 2. The trust list, the zones' claims in DNS, the gateway's measurement entry" ""
say "The operator creates the list once; the reconciler applies the repository's file with \`--with-zones\`, so each zone's claim becomes a real PTR record in the zone manager's name server; the publisher writes the gateway's entry under its own UUID with the lookup key the gateway will present: its identity, \`$identity\`. The record is synthetic (the measuring step is not part of this proof); what matters is a real entry in a real list reached through a real PTR." ""
tspa DELETE "/$fw/trust-list" "" "$work/operator.tok" >/dev/null || true
st=$(tspa PUT "/init/json/$fw/trust-list" "$kit/payloads/trustlist-init.json" "$work/operator.tok")
check "the trust list of $fw is created by the operator (PUT init, $st)" [ "$st" = 201 ]
set +e
"$reconciler" apply --file "$desired_src" --out "$steps/zones" --with-zones >"$steps/zones.out" 2>"$steps/zones.err"; zrc=$?
set -e
zevent=$(sed -n 's/^EVENT_JSON=//p' "$steps/zones.out" | tail -1)
check "the repository's trust-list file is applied with the zones' claims (exit $zrc, $(jq -r .outcome <<<"$zevent"))" bash -c "[ '$zrc' = 0 ] && [ '$(jq -r .outcome <<<"$zevent")' = applied ]"
ptr=$(dig +short +tcp +time=3 +tries=1 -p "$dns_port" PTR "_scheme._trust.$zone_b" @127.0.0.1 2>/dev/null | tr -d '[:space:]' || true)
check "dig PTR _scheme._trust.$zone_b answers _scheme._trust.$fw. (the pointer the gateway derives from the peer's identity is anchored)" [ "$ptr" = "_scheme._trust.$fw." ]
none=$(dig +short +tcp +time=3 +tries=1 -p "$dns_port" PTR "_scheme._trust.zone-c.other.test" @127.0.0.1 2>/dev/null | tr -d '[:space:]' || true)
check "no PTR record for a zone outside the framework (zone-c.other.test)" [ -z "$none" ]
issuer_b_uuid=$(list | jq -r '.TrustServiceStatusList.TrustServiceProviderList.TrustServiceProvider[] | select(.TSPServices.TSPService[0].ServiceTypeIdentifier == "did:web:issuer-b.facis-ztd.local") | .UUID')
check "the reconciler's issuer entries are in the list (issuer-b: $issuer_b_uuid)" [ -n "$issuer_b_uuid" ]
v1=$(hex "teem-v1-$(now)"); v2=$(hex "teem-v2-$(now)"); other=$(hex teem-other)
record() {  # record <file> <value>: a measurement record for zone b's gateway with that value
  jq -n --arg v "$2" --arg cfg "$(hex cfg)" --arg rfs "$(hex rootfs)" --arg img "docker.io/curlimages/curl@sha256:$(hex image)" --arg sti "$identity" \
    --arg commit "$(git -C "$root" rev-parse HEAD)" --arg at "$(now)" '
    {component: "gateway", zone: "b", serviceTypeIdentifier: $sti, image: $img,
     measurement: {type: "TEEM-sha256", value: $v, configSha256: $cfg, rootfsSha256: $rfs},
     source: {commit: $commit, tool: "verify-train-resolve (synthetic record)", producedAt: $at}}' > "$1"
}
prc=0
publish() {  # publish <name> <action> <record>
  set +e
  "$publisher" "$2" --record "$3" --out "$steps/pub-$1" >"$steps/pub-$1.out" 2>"$steps/pub-$1.err"; prc=$?
  set -e
}
pevent() { sed -n 's/^EVENT_JSON=//p' "$steps/pub-$1.out" | tail -1; }
record "$files/record-v1.json" "$v1"
publish v1 publish "$files/record-v1.json"
uuid=$(pevent v1 | jq -r .uuid)
check "the publisher writes the gateway's entry with v1 (exit $prc, $(pevent v1 | jq -r .outcome))" bash -c "[ '$prc' = 0 ] && [ '$(pevent v1 | jq -r .outcome)' = published ]"
check "the entry's lookup key is the gateway's identity" [ "$(entry "$uuid" | jq -r '.[0].TSPServices.TSPService[0].ServiceTypeIdentifier')" = "$identity" ]
note "the gateway's entry: UUID \`$uuid\`, lookup key \`$identity\`, value \`${v1:0:12}...\`; the list holds $(all_entries) entries"

# ---- 3. the resolver stand-in over the real DNS and the real list --------------------------------
echo "== the resolver stand-in"
say "## 3. The resolver stand-in over the real name server and the real list" ""
say "\`scripts/train-resolve/fake_tcr.py\` answers \`POST /tcr/v1/resolve\` the way upstream's resolver does: the pointer is asked of the zone manager's name server (\`dig PTR _scheme._trust.<pointer>\`, over the forwarded TCP port), the framework it names gives the DID and the trust-list URIs at the TSPA, the list is read and the entry whose \`ServiceTypeIdentifier\` equals the issuer is returned. What it leaves out is the real resolver's (signature, hash, DID document, DNSSEC); see its README." ""
tcr_origin=""
start_tcr() {  # start_tcr <name> <args...>: a stand-in on a free port, its origin in $tcr_origin
  # Not a command substitution on purpose: a background process started inside $(...) keeps the
  # captured pipe open and the substitution never returns.
  local name=$1; shift
  local port; port=$(free_port)
  python3 "$fake_tcr" --port "$port" "$@" --log "$steps/tcr-$name.jsonl" >/dev/null 2>"$steps/tcr-$name.err" &
  pids+=("$!")
  for _ in $(seq 50); do curl -sf --max-time 1 -o /dev/null "http://127.0.0.1:$port/actuator/health" && break; sleep 0.1; done
  tcr_origin="http://127.0.0.1:$port"
}
start_tcr main --tspa "$TSPA_URL" --dns-server 127.0.0.1 --dns-port "$dns_port" --dns-tcp; tcr=$tcr_origin
check "the stand-in answers its health" curl -sf --max-time 2 -o /dev/null "$tcr/actuator/health"
jq -n --arg i "$identity" --arg p "$zone_b" '{issuer: $i, trustSchemePointers: [$p]}' > "$work/resolve.json"
curl -sS --max-time 30 -H 'Content-Type: application/json' --data-binary @"$work/resolve.json" "$tcr/tcr/v1/resolve" > "$files/resolve-answer.json" || true
check "asked directly, the stand-in walks the PTR to the framework's DID" [ "$(jq -c '.trustSchemePointers[0].dids' "$files/resolve-answer.json")" = "[\"did:web:$fw\"]" ]
check "asked directly, the stand-in returns the gateway's entry from the real list, credential read" bash -c "[ '$(jq -r '.resolvedResults[0].resolvedDoc.endpoints[0].trustList.UUID' "$files/resolve-answer.json")' = '$uuid' ] && [ '$(jq -r '.resolvedResults[0].resolvedDoc.endpoints[0].vcVerified' "$files/resolve-answer.json")' = true ]"
code "$(jq -c '{pointers: .trustSchemePointers, endpoint: (.resolvedResults[0].resolvedDoc.endpoints[0] | {tlUri, vcVerified, entry: .trustList.UUID})}' "$files/resolve-answer.json")"

# ---- 4. the cases ---------------------------------------------------------------------------------
rc=0
probe() {  # probe <name> <args...>: the probe with its records kept per case; rc kept
  local name=$1; shift
  set +e
  "$work/probe" "$@" -record "$steps/probe-$name.jsonl" >"$steps/probe-$name.out" 2>"$steps/probe-$name.err"; rc=$?
  set -e
}
last() { tail -1 "$steps/probe-$1.out" | jq -r "$2"; }
nth() { sed -n "${2}p" "$steps/probe-$1.out" | jq -r "$3"; }
case_row() { row "$1" "$2" "$(last "$3" '.code // .outcome')" "$rc"; }

echo "== the cases"
say "## 4. The peer presenting the published measurement is accepted" ""
probe match -tcr "$tcr" -identity "$identity" -digest "$v1"
case_row "match" "accepted" match
check "accepted: exit 0, outcome accepted" bash -c "[ '$rc' = 0 ] && [ '$(last match .outcome)' = accepted ]"
ptrs=$(last match '.pointers | join(",")')
check "accepted: the key is the identity, the pointer is the zone domain" bash -c "[ '$(last match .key)' = '$identity' ] && [ '$ptrs' = '$zone_b' ]"
check "accepted: one expected value, the publisher's entry, the real list's URI" bash -c "[ '$(last match .expectedCount)' = 1 ] && [ '$(last match .entryUUID)' = '$uuid' ] && [ '$(last match .trustList)' = '$api/$fw/trust-list' ]"
check "accepted: not from the cache, within the handshake budget ($(last match .elapsedMs) ms)" bash -c "[ '$(last match .fromCache)' = false ] && [ '$(last match .elapsedMs)' -lt 10000 ]"
code "$(tail -1 "$steps/probe-match.out" | jq -c 'del(.ts)')"

say "## 5. Two verifications in one process: the second is served from the cache" ""
probe cache -tcr "$tcr" -identity "$identity" -digest "$v1" -repeat 2 -interval 0
case_row "cache" "accepted, second from the cache" cache
check "cache: both accepted, the second from the cache, one resolution" bash -c "[ '$rc' = 0 ] && [ '$(nth cache 2 .fromCache)' = true ] && [ '$(nth cache 2 .stats.Flights)' = 1 ]"

say "## 6. A peer presenting another measurement is refused" ""
probe mismatch -tcr "$tcr" -identity "$identity" -digest "$other"
case_row "mismatch" "CHAN-MEASUREMENT-MISMATCH" mismatch
check "mismatch: exit 2, CHAN-MEASUREMENT-MISMATCH, the expected value was there" bash -c "[ '$rc' = 2 ] && [ '$(last mismatch .code)' = CHAN-MEASUREMENT-MISMATCH ] && [ '$(last mismatch .expectedCount)' = 1 ]"
note "reason: \`$(last mismatch .reason)\`"

say "## 7. A peer nobody published, in a known zone" ""
probe unpublished -tcr "$tcr" -identity "spiffe://$zone_b/other" -digest "$v1"
case_row "unpublished" "CHAN-MEASUREMENT-UNPUBLISHED" unpublished
check "unpublished: exit 2, CHAN-MEASUREMENT-UNPUBLISHED, no entry" bash -c "[ '$rc' = 2 ] && [ '$(last unpublished .code)' = CHAN-MEASUREMENT-UNPUBLISHED ] && [ '$(last unpublished '.entryUUID // empty')' = '' ]"

say "## 8. An issuer's entry is not a measurement" ""
say "The reconciler's issuer entries share the list. Looked up under an issuer's key, the entry is found, but it carries no TEEM-sha256 value: not published, with the entry named, never accepted." ""
probe issuer -tcr "$tcr" -identity "did:web:issuer-b.$fw" -digest "$v1" -pointer "$zone_b"
case_row "issuer entry" "CHAN-MEASUREMENT-UNPUBLISHED (entry named)" issuer
check "issuer entry: CHAN-MEASUREMENT-UNPUBLISHED with the issuer's entry named" bash -c "[ '$rc' = 2 ] && [ '$(last issuer .code)' = CHAN-MEASUREMENT-UNPUBLISHED ] && [ '$(last issuer .entryUUID)' = '$issuer_b_uuid' ]"

say "## 9. A peer from a zone without a claim: unknown zone" ""
probe zone -tcr "$tcr" -identity "spiffe://zone-c.other.test/gateway" -digest "$v1"
case_row "unknown zone" "CHAN-ZONE-UNKNOWN" zone
check "unknown zone: exit 2, CHAN-ZONE-UNKNOWN (no PTR record in the name server)" bash -c "[ '$rc' = 2 ] && [ '$(last zone .code)' = CHAN-ZONE-UNKNOWN ]"
check "unknown zone: the stand-in reported the pointer's DNS error" [ "$(jq -r 'select(.path == "/tcr/v1/resolve") | .body.trustSchemePointers[0]' "$steps/tcr-main.jsonl" | tail -1)" = "zone-c.other.test" ]

say "## 10. A rolling update: v2 published beside v1, both accepted; pruned to v2, v1 refused" ""
record "$files/record-v2.json" "$v2"
publish v2 publish "$files/record-v2.json"
check "the publisher adds v2 beside v1 (exit $prc)" [ "$prc" = 0 ]
probe roll-v1 -tcr "$tcr" -identity "$identity" -digest "$v1"
check "during the rollout v1 is accepted, two values expected" bash -c "[ '$rc' = 0 ] && [ '$(last roll-v1 .expectedCount)' = 2 ]"
probe roll-v2 -tcr "$tcr" -identity "$identity" -digest "$v2"
check "during the rollout v2 is accepted" [ "$rc" = 0 ]
case_row "rolling update, both versions" "accepted" roll-v2
publish prune prune "$files/record-v2.json"
check "the publisher prunes to v2 (exit $prc)" [ "$prc" = 0 ]
probe pruned-v1 -tcr "$tcr" -identity "$identity" -digest "$v1"
case_row "after the prune, v1" "CHAN-MEASUREMENT-MISMATCH" pruned-v1
check "after the prune v1 is refused, one value expected" bash -c "[ '$rc' = 2 ] && [ '$(last pruned-v1 .code)' = CHAN-MEASUREMENT-MISMATCH ] && [ '$(last pruned-v1 .expectedCount)' = 1 ]"
probe pruned-v2 -tcr "$tcr" -identity "$identity" -digest "$v2"
check "after the prune v2 is accepted" [ "$rc" = 0 ]

say "## 11. A removal bites within the window: the real cache of $window s" ""
say "One probe process keeps verifying v2 every 5 s with the documented TTL. Once it has accepted, the operator deletes the gateway's entry. The refusal must arrive no earlier than the deletion and no later than the first acceptance plus the window plus one interval: that is the window the staleness matrix documents, measured." ""
rm -f "$steps/probe-window.jsonl"
set +e
"$work/probe" -tcr "$tcr" -identity "$identity" -digest "$v2" -until-code CHAN-MEASUREMENT-UNPUBLISHED -ttl "${window}s" -interval 5s -deadline "$((window + 120))s" -record "$steps/probe-window.jsonl" >"$steps/probe-window.out" 2>"$steps/probe-window.err" &
wpid=$!
pids+=("$wpid")   # so that an aborted run does not leave it verifying until its deadline
set -e
for _ in $(seq 300); do grep -q '"outcome":"accepted"' "$steps/probe-window.jsonl" 2>/dev/null && break; sleep 0.1; done
check "the probe accepted v2 before the removal" grep -q '"outcome":"accepted"' "$steps/probe-window.jsonl"
sleep 7   # one more verification from the cache before the removal, so the window is measured from a warm cache
deleted_at=$(now_ms)
st=$(tspa DELETE "/$fw/trust-list/tsp/$uuid" "" "$work/operator.tok")
check "the operator deletes the gateway's entry (DELETE $st)" [ "$st" = 200 ]
check "the list no longer holds the entry" [ "$(entry "$uuid")" = '[]' ]
set +e; wait "$wpid"; wrc=$?; set -e
transition=$(tail -1 "$steps/probe-window.out")
row "removal within the window" "CHAN-MEASUREMENT-UNPUBLISHED within ${window} s" "$(jq -r 'if .observed then .untilCode else "not observed" end' <<<"$transition")" "$wrc"
check "the refusal arrived before the deadline (exit $wrc)" [ "$wrc" = 0 ]
after_ms=$(jq -r '.transitionAfterMs // 0' <<<"$transition")
first_ms=$(iso_ms "$(jq -r .firstAcceptedAt <<<"$transition")")
transition_ms=$(iso_ms "$(jq -r .transitionAt <<<"$transition")")
check "the refusal came within the window plus one interval: $after_ms ms after the first acceptance, window $window s" [ "$after_ms" -le $((window * 1000 + 5000)) ]
check "the refusal never came before the deletion ($((transition_ms - deleted_at)) ms after it)" [ "$transition_ms" -ge "$deleted_at" ]
early=$(jq -r 'select(.outcome == "refused") | .ts' "$steps/probe-window.jsonl" | while read -r ts; do [ "$(iso_ms "$ts")" -lt "$deleted_at" ] && echo early; done || true)
check "no refusal was recorded before the deletion; every verification until then was accepted from the cache" bash -c "[ -z '$early' ] && [ '$(jq -r 'select(.outcome == "accepted") | .fromCache' "$steps/probe-window.jsonl" | tail -1)' = true ]"
note "first acceptance $(jq -r .firstAcceptedAt <<<"$transition"); deletion $(python3 -c "import datetime,sys; print(datetime.datetime.fromtimestamp(int(sys.argv[1])/1000, datetime.timezone.utc).isoformat(timespec='milliseconds'))" "$deleted_at"); refusal $(jq -r .transitionAt <<<"$transition"); verifications: $(jq -r .attempts <<<"$transition")"
code "$(jq -c 'del(.schema)' <<<"$transition")"

say "## 12. An entry without a TEEM-sha256 value: not published" ""
record "$files/record-v3.json" "$v1"
publish v3 publish "$files/record-v3.json"
check "the publisher writes the entry again (exit $prc)" [ "$prc" = 0 ]
entry "$uuid" | jq '.[0] | .TSPInformation.TSPCertificationList.TSPCertification |= map(select(.Type != "TEEM-sha256")) | {TrustServiceProvider: .}' > "$files/stripped.json"
st=$(tspa PATCH "/$fw/trust-list/tsp/$uuid" "$files/stripped.json" "$work/operator.tok")
check "the entry is patched to zero TEEM-sha256 values (PATCH $st)" [ "$st" = 200 ]
probe zero -tcr "$tcr" -identity "$identity" -digest "$v1"
case_row "zero values" "CHAN-MEASUREMENT-UNPUBLISHED (entry named)" zero
check "zero values: CHAN-MEASUREMENT-UNPUBLISHED with the entry named" bash -c "[ '$rc' = 2 ] && [ '$(last zero .code)' = CHAN-MEASUREMENT-UNPUBLISHED ] && [ '$(last zero .entryUUID)' = '$uuid' ]"

say "## 13. A resolver that cannot verify the credential, a resolver failing, a resolver down" ""
start_tcr unverified --tspa "$TSPA_URL" --dns-server 127.0.0.1 --dns-port "$dns_port" --dns-tcp --vc-unverified; unv=$tcr_origin
probe unverified -tcr "$unv" -identity "$identity" -digest "$v1"
case_row "credential not verified" "CHAN-TRUST-UNREACHABLE" unverified
check "credential not verified by the resolver: CHAN-TRUST-UNREACHABLE" bash -c "[ '$rc' = 2 ] && [ '$(last unverified .code)' = CHAN-TRUST-UNREACHABLE ]"
check "credential not verified: the reason says so" has 'did not verify the trust-list credential' "$(last unverified .reason)"
start_tcr failing --tspa "$TSPA_URL" --fail 502; failing=$tcr_origin
probe failing -tcr "$failing" -identity "$identity" -digest "$v1"
case_row "resolver answering 502" "CHAN-TRUST-UNREACHABLE" failing
check "resolver answering 502: CHAN-TRUST-UNREACHABLE naming the status" bash -c "[ '$rc' = 2 ] && [ '$(last failing .code)' = CHAN-TRUST-UNREACHABLE ] && grep -q 'answered 502' <<<'$(last failing .reason)'"
down_port=$(free_port)
probe down -tcr "http://127.0.0.1:$down_port" -identity "$identity" -digest "$v1" -resolve-timeout 5s
case_row "resolver down" "CHAN-TRUST-UNREACHABLE" down
check "resolver down: CHAN-TRUST-UNREACHABLE within the handshake budget ($(last down .elapsedMs) ms)" bash -c "[ '$rc' = 2 ] && [ '$(last down .code)' = CHAN-TRUST-UNREACHABLE ] && [ '$(last down .elapsedMs)' -lt 10000 ]"
start_tcr dead-tspa --tspa "http://127.0.0.1:$down_port/tspa-service" --dns-server 127.0.0.1 --dns-port "$dns_port" --dns-tcp; dead=$tcr_origin
probe dead -tcr "$dead" -identity "$identity" -digest "$v1"
case_row "resolver whose TSPA is down" "CHAN-TRUST-UNREACHABLE" dead
check "resolver whose TSPA is down: CHAN-TRUST-UNREACHABLE" bash -c "[ '$rc' = 2 ] && [ '$(last dead .code)' = CHAN-TRUST-UNREACHABLE ]"

say "## 14. No secret in any record" ""
check "the client secret appears in no record, output or log kept" bash -c "! grep -rq -- \"\$OIDC_CLIENT_SECRET\" '$steps' '$files'"
check "no bearer token appears in any record, output or log kept" bash -c "! grep -rqi -- 'authorization' '$steps' '$files' && ! grep -rq -- \"\$(cat '$work/operator.tok')\" '$steps' '$files'"

# ---- the evidence --------------------------------------------------------------------------------
n=$(wc -l < "$work/checks" | tr -d ' '); f=$(fails)
tspa_commit=$(git -C "$TSPA_REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)
{
  echo "# TRAIN resolution against the real TSPA and name server: evidence"
  echo
  echo "Run of \`scripts/verify-train-resolve/verify.sh\` on $(now) against upstream's TSPA \`$tspa_commit\` built from its Dockerfile and upstream's zone manager, on kind. The code the run used: \`internal/trainresolve\` and \`cmd/train-resolve-probe\` of this checkout (probe built from it), the resolver stand-in \`fake_tcr.py\` sha256 \`$(sha256sum "$fake_tcr" | cut -c1-64)\`. Window measured against: $window s. Raw records: the \`--out\` directory (per case: the probe's records, stdout and stderr; the publisher's and reconciler's outputs; the stand-ins' request logs; the kind-up log)."
  echo
  echo "## Summary of the cases"
  echo
  echo "| Case | Expected | Code or outcome | Exit |"
  echo "|---|---|---|---|"
  awk -F'\t' '{printf "| %s | %s | `%s` | %s |\n", $1, $2, $3, $4}' "$work/summary.tsv"
  echo
  if [ "$f" = 0 ]; then echo "**Verdict: all $n checks passed.**"; else echo "**Verdict: $f of $n checks FAILED.**"; sed 's/^/- /' "$work/fails"; fi
  echo
  cat "$body"
} > "$evidence"
echo
echo "evidence: $evidence ($n checks, $f failed); records: $out"
[ "$f" = 0 ]
