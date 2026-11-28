#!/usr/bin/env bash
# Publishes one attested component's reference measurement into TRAIN through the TSPA trust-list
# API before the component rolls out, and prunes the entry back to the current value after it.
# The measurement is read from a record (docs/contracts/measurement-record.v1.schema.json), never
# computed here: the pipeline measures, this script publishes and proves. One entry per endpoint,
# under a UUID derived from the zone and the component, so the first publication is a PUT and every
# later one a PATCH of the same entry; the measurement rides in the entry's TSPCertification list as
# {Type: TEEM-sha256, Value: <64 hex>} (docs/adr/0011, 4.2), next to {Type: image-digest} pairs that
# this script adds for traceability and the verifier ignores; both lists follow the same set rule.
# `publish` writes the union of the values already there and the new one, so a rolling update is
# accepted on both versions; `prune` writes the new one alone once the rollout has converged;
# `verify` reads back without writing. The HTTP status is not the proof: after every write the
# trust list is read again and the entry, its lookup key and its values are asserted
# (docs/tspa-publish-api.md, 2 and 7.1). Any doubt is a failure, and a failure before a rollout
# is meant to stop it.
#
#   scripts/train-publish/publish.sh publish --record FILE [--out DIR]
#   scripts/train-publish/publish.sh prune   --record FILE [--out DIR]
#   scripts/train-publish/publish.sh verify  --record FILE [--out DIR]
#
# Environment:
#   TSPA_URL             base URL of the TSPA up to its context path, e.g. http://host:16003/tspa-service
#   TSPA_FRAMEWORK       the trust framework whose list carries the entries
#   OIDC_TOKEN_URL       token endpoint for client_credentials; with OIDC_CLIENT_ID and OIDC_CLIENT_SECRET
#   TSPA_TOKEN_FILE      instead of the three above: a file holding a bearer token already obtained
#   TRAIN_PUBLISH_TIMEOUT   seconds per HTTP call (default 30)
#   TRAIN_PUBLISH_TEMPLATE  the entry template (default entry.tmpl.json next to this script)
#
# Output: one JSON line per run appended to <out>/publications.jsonl and printed to stdout as
# EVENT_JSON=<json>, the line form scripts/lifecycle.sh relays as progress; the request and the
# lists read are kept under <out>/last/. No token or secret reaches any output or command line.
# Exit 0 when the read-back proves the action, 1 when it does not or the TSPA could not be reached,
# 2 for a bad record or configuration (nothing is called in that case).
# Needs curl, jq, python3 and sha256sum.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
timeout_s=${TRAIN_PUBLISH_TIMEOUT:-30}
template=${TRAIN_PUBLISH_TEMPLATE:-$here/entry.tmpl.json}

usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; }
say() { echo "train-publish: $*" >&2; }
die() { local code=$1; shift; say "$*"; exit "$code"; }

action=${1:-}
[ $# -gt 0 ] && shift
record=""; out=.dev/train-publish
while [ $# -gt 0 ]; do
  case "$1" in
    --record|--out) if [ $# -lt 2 ] || [ -z "$2" ]; then die 2 "$1 needs a value"; fi ;;
  esac
  case "$1" in
    --record) record=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die 2 "unknown argument: $1" ;;
  esac
done
case "$action" in
  publish|prune|verify) ;;
  ""|-h|--help) usage; exit 0 ;;
  *) die 2 "unknown action '$action': publish, prune or verify" ;;
esac
for tool in curl jq python3 sha256sum; do
  command -v "$tool" >/dev/null || die 2 "$tool is required"
done
if [ -z "$record" ] || [ ! -f "$record" ]; then die 2 "--record FILE is required and must exist"; fi
[ -f "$template" ] || die 2 "entry template not found: $template"
for v in TSPA_URL TSPA_FRAMEWORK; do
  [ -n "${!v:-}" ] || die 2 "$v must be set"
done
mkdir -p "$out/last"
out="$(cd "$out" && pwd)"
rm -f "$out"/last/*
umask 077
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# ---- the record -------------------------------------------------------------------------------
jq -e '
  (.component | type == "string" and test("^[a-z][a-z0-9-]{0,62}$")) and
  (.zone | type == "string" and test("^[a-z][a-z0-9-]{0,62}$")) and
  (.serviceTypeIdentifier | type == "string" and length > 0) and
  (.image | type == "string" and test("^[^@[:space:]]+@sha256:[0-9a-f]{64}$")) and
  (.measurement.type == "TEEM-sha256") and
  (.measurement.value | type == "string" and test("^[0-9a-f]{64}$")) and
  (.measurement.configSha256 | type == "string" and test("^[0-9a-f]{64}$")) and
  (.measurement.rootfsSha256 | type == "string" and test("^[0-9a-f]{64}$")) and
  (.source.commit | type == "string" and test("^[0-9a-f]{7,40}$")) and
  (.source.tool | type == "string" and length > 0) and
  ((.source.producedAt // "1970-01-01T00:00:00Z") | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$")) and
  ((keys - ["component", "zone", "serviceTypeIdentifier", "image", "measurement", "source"]) == []) and
  ((.measurement | keys) - ["type", "value", "configSha256", "rootfsSha256"] == []) and
  ((.source | keys) - ["commit", "tool", "producedAt"] == [])
' "$record" >/dev/null 2>&1 \
  || die 2 "record does not match docs/contracts/measurement-record.v1.schema.json: $record"
component=$(jq -r .component "$record")
zone=$(jq -r .zone "$record")
sti=$(jq -r .serviceTypeIdentifier "$record")
image=$(jq -r .image "$record")
digest=${image#*@}
value=$(jq -r .measurement.value "$record")
# One UUID per endpoint, the same on every run: a PUT creates it once, every later write is a PATCH.
uuid=$(python3 - "$zone" "$component" <<'PY'
import sys, uuid
ns = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/eclipse-xfsc/facis-zero-trust-demonstrator/train-publish")
print(uuid.uuid5(ns, f"{sys.argv[1]}/{sys.argv[2]}"))
PY
)
fw=$TSPA_FRAMEWORK
api="${TSPA_URL%/}/tspa/v1"
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# ---- the evidence line ------------------------------------------------------------------------
before='[]'; after='null'; method=null; status=null; bodysha=null; listsha=null; vchash=null
digests_before='[]'; digests_after='[]'; count=0; m=""
emit() {  # emit <outcome>: one JSON line to publications.jsonl and to stdout
  local line
  line=$(jq -cn --arg ts "$(now)" --arg action "$action" --arg fw "$fw" --arg uuid "$uuid" \
    --arg sti "$sti" --arg image "$image" --argjson before "$before" --argjson after "$after" \
    --argjson method "$method" --argjson status "$status" --argjson bodysha "$bodysha" \
    --argjson listsha "$listsha" --argjson vchash "$vchash" --arg outcome "$1" \
    '{ts:$ts, action:$action, framework:$fw, uuid:$uuid, serviceTypeIdentifier:$sti, image:$image,
      before:$before, after:$after, tspa:{method:$method, status:$status, bodySha256:$bodysha},
      readBack:{listSha256:$listsha, vcHash:$vchash}, outcome:$outcome}')
  echo "$line" >> "$out/publications.jsonl"
  echo "EVENT_JSON=$line"
}
fail() {  # fail <outcome> <message>: record the failure and exit 1
  emit "$1"; say "$2"; say "outcome: $1 (nothing proven; a rollout gated on this must not proceed)"
  exit 1
}
jstr() { jq -cn --arg v "$1" '$v'; }
sha() { sha256sum "$1" | cut -c1-64; }

# ---- the token (never printed, never on a command line) ---------------------------------------
auth="$work/auth.h"
if [ -n "${OIDC_TOKEN_URL:-}" ]; then
  for v in OIDC_CLIENT_ID OIDC_CLIENT_SECRET; do [ -n "${!v:-}" ] || die 2 "$v must be set with OIDC_TOKEN_URL"; done
  # jq reads both from the environment: neither value becomes an argument of any process.
  jq -rnj 'env.OIDC_CLIENT_ID as $i | env.OIDC_CLIENT_SECRET as $s
          | "grant_type=client_credentials&client_id=\($i|@uri)&client_secret=\($s|@uri)"' > "$work/form"
  code=$(curl -sS --max-time "$timeout_s" -o "$work/token.json" -w '%{http_code}' \
    -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @"$work/form" "$OIDC_TOKEN_URL" 2>"$work/curl.err") \
    || fail token-failed "token endpoint unreachable: $(head -c 200 "$work/curl.err")"
  [ "$code" = 200 ] || fail token-failed "token endpoint answered $code"
  tok=$(jq -r '.access_token // empty' "$work/token.json" 2>/dev/null || true)
  [ -n "$tok" ] || fail token-failed "token endpoint answered 200 without an access_token"
elif [ -n "${TSPA_TOKEN_FILE:-}" ]; then
  [ -r "$TSPA_TOKEN_FILE" ] || die 2 "TSPA_TOKEN_FILE is not a readable file: $TSPA_TOKEN_FILE"
  tok=$(tr -d '\r\n' < "$TSPA_TOKEN_FILE")
  [ -n "$tok" ] || die 2 "TSPA_TOKEN_FILE is empty"
else
  die 2 "set OIDC_TOKEN_URL with OIDC_CLIENT_ID and OIDC_CLIENT_SECRET, or TSPA_TOKEN_FILE"
fi
printf 'Authorization: Bearer %s\n' "$tok" > "$auth"
unset tok

# ---- the trust list as it is ------------------------------------------------------------------
read_list() {  # read_list <file>: GET the trust list into <file>; sets code, returns 1 when unreachable
  code=$(curl -sS --max-time "$timeout_s" -o "$1" -w '%{http_code}' "$api/$fw/trust-list" 2>"$work/curl.err") || return 1
}
entry_of() {  # entry_of <list> <file>: the entries with our UUID, as a JSON array
  jq -c --arg u "$uuid" \
    '[.TrustServiceStatusList.TrustServiceProviderList.TrustServiceProvider // [] | .[] | select(.UUID == $u)]' "$1" > "$2" 2>/dev/null \
    || { echo '[]' > "$2"; }
}
teems_of() { jq -c '[.[0].TSPInformation.TSPCertificationList.TSPCertification // [] | .[] | select(.Type == "TEEM-sha256") | .Value] | unique' "$1"; }
digests_of() { jq -c '[.[0].TSPInformation.TSPCertificationList.TSPCertification // [] | .[] | select(.Type == "image-digest") | .Value] | unique' "$1"; }

prepare() {  # read the list, find the entry, decide the values and the method, build the request
  read_list "$out/last/list-before.json" || fail transport-failure "TSPA unreachable reading the trust list: $(head -c 200 "$work/curl.err")"
  case "$code" in
    200) ;;
    404) fail list-missing "the trust list of $fw does not exist: creating it is a federation setup step, not this script's" ;;
    *) fail tspa-error "reading the trust list answered $code" ;;
  esac
  entry_of "$out/last/list-before.json" "$work/entry-before.json"
  count=$(jq length "$work/entry-before.json")
  [ "$count" -le 1 ] || fail duplicate-entry "$count entries carry the UUID $uuid; the list needs repair before any publication"
  before=$(teems_of "$work/entry-before.json")
  digests_before=$(digests_of "$work/entry-before.json")
  # The image digests beside the measurements follow the same set rule: during a rolling update both
  # images run, so both digests are listed; prune leaves the record's alone.
  case "$action" in
    publish) after=$(jq -cn --argjson b "$before" --arg v "$value" '($b + [$v]) | unique')
             digests_after=$(jq -cn --argjson b "$digests_before" --arg d "$digest" '($b + [$d]) | unique') ;;
    prune)   after=$(jq -cn --arg v "$value" '[$v]'); digests_after=$(jq -cn --arg d "$digest" '[$d]') ;;
    verify)  after=$before; digests_after=$digests_before ;;
  esac
  if [ "$count" = 1 ]; then m=PATCH; else m=PUT; fi
  [ "$action" = verify ] && return 0
  local start
  start=$(jq -r '.[0].TSPServices.TSPService[0].StatusStartingTime // empty' "$work/entry-before.json")
  [ -n "$start" ] || start=$(now)
  jq --arg uuid "$uuid" --arg name "$component ($zone)" --arg trade "$zone-$component" --arg sti "$sti" \
     --arg zone "$zone" --arg comp "$component" --argjson digests "$digests_after" --arg start "$start" --argjson teems "$after" '
    .TrustServiceProvider
    | .UUID = $uuid | .TSPName = $name | .TSPTradeName = $trade
    | .TSPInformation.TSPCertificationList.TSPCertification =
        ([$teems[] | {Type: "TEEM-sha256", Value: .}] + [$digests[] | {Type: "image-digest", Value: .}])
    | .TSPInformation.TSPEntityIdentifierList.TSPEntityIdendifier =
        [{Type: "zone", Value: $zone}, {Type: "component", Value: $comp}]
    | .TSPServices.TSPService[0].ServiceTypeIdentifier = $sti
    | .TSPServices.TSPService[0].ServiceDigitalIdentity.DigitalId.DID = $sti
    | .TSPServices.TSPService[0].StatusStartingTime = $start
    | {TrustServiceProvider: .}' "$template" > "$out/last/request.json"
}
write() {  # write PUT|PATCH: sets code and method; the body lands in last/response.txt
  local m=$1 url
  if [ "$m" = PATCH ]; then url="$api/$fw/trust-list/tsp/$uuid"; else url="$api/$fw/trust-list/tsp"; fi
  method=$(jstr "$m")
  code=$(curl -sS --max-time "$timeout_s" -o "$out/last/response.txt" -w '%{http_code}' -X "$m" \
      -H 'Content-Type: application/json' -H @"$auth" --data-binary @"$out/last/request.json" "$url" 2>"$work/curl.err") \
    || fail transport-failure "TSPA unreachable on $m: $(head -c 200 "$work/curl.err")"
  status=$code
  bodysha=$(jstr "$(sha "$out/last/response.txt")")
}

prepare
if [ "$action" != verify ]; then
  write "$m"
  # The read decided between PUT and PATCH a moment ago; a writer racing us can make it stale (the
  # entry appeared, or vanished). Once, as docs/tspa-publish-api.md 7.1 asks, start again from the
  # read, so the union is computed over what the other writer left, and write with the other method.
  if { [ "$m" = PUT ] && [ "$code" = 400 ] && grep -qi 'already exists' "$out/last/response.txt"; } \
     || { [ "$m" = PATCH ] && [ "$code" = 404 ]; }; then
    failed=$m
    say "$failed found the entry's state changed since the read; reading again"
    prepare
    [ "$m" != "$failed" ] || fail tspa-error "the trust list contradicts the TSPA's $failed answer ($code); not retrying"
    write "$m"
  fi
  case "$code" in
    200|201)
      # Section 5 of the page: a write the TSPA does not run (no usable token) is answered 200 with
      # an empty body and stores nothing. The read-back cannot tell that apart when the values were
      # already there, so an empty body is a failure in its own right.
      [ -s "$out/last/response.txt" ] || fail write-unconfirmed "TSPA answered $code with an empty body on $m: the write did not run (the token was not usable), nothing was stored" ;;
    401|403) fail write-rejected "TSPA refused the $m with $code: the token lacks the enrolltf realm role, or is invalid" ;;
    400) fail write-rejected "TSPA rejected the $m with 400: $(head -c 300 "$out/last/response.txt" | tr '\n' ' ')" ;;
    404) fail target-missing "TSPA answered 404 on $m: the trust list of $fw, or the entry $uuid, does not exist" ;;
    *) fail tspa-error "TSPA answered $code on $m" ;;
  esac
fi

# ---- the read-back: the only proof -----------------------------------------------------------
read_list "$out/last/list-after.json" || fail transport-failure "TSPA unreachable reading the trust list back: $(head -c 200 "$work/curl.err")"
[ "$code" = 200 ] || fail not-published "reading the trust list back answered $code"
listsha=$(jstr "$(sha "$out/last/list-after.json")")
entry_of "$out/last/list-after.json" "$work/entry-after.json"
count=$(jq length "$work/entry-after.json")
[ "$count" = 1 ] || fail not-published "read-back: $count entries with UUID $uuid (expected exactly one)"
got_sti=$(jq -r '.[0].TSPServices.TSPService[0].ServiceTypeIdentifier // empty' "$work/entry-after.json")
[ "$got_sti" = "$sti" ] || fail not-published "read-back: ServiceTypeIdentifier is '$got_sti', not '$sti'; the TCR would never find this entry"
got=$(teems_of "$work/entry-after.json")
case "$action" in
  verify) jq -e --arg v "$value" 'index($v) != null' <<<"$got" >/dev/null \
            || fail not-published "read-back: the measurement $value is not published for $uuid" ;;
  *) [ "$got" = "$after" ] || fail not-published "read-back: TEEM values are $got, expected $after" ;;
esac
got_digests=$(digests_of "$work/entry-after.json")
case "$action" in
  verify) jq -e --arg d "$digest" 'index($d) != null' <<<"$got_digests" >/dev/null \
            || fail not-published "read-back: the image digest $digest is not listed for $uuid (found $got_digests)" ;;
  *) [ "$got_digests" = "$digests_after" ] || fail not-published "read-back: image digests are $got_digests, expected $digests_after" ;;
esac
# The signed VC the TCR consumes; recorded, not judged (its hash is the list's).
if vc=$(curl -sS --max-time "$timeout_s" -o "$out/last/vc.json" -w '%{http_code}' "$api/$fw/vc/trust-list" 2>/dev/null) && [ "$vc" = 200 ]; then
  h=$(jq -r '.credentialSubject.hash // empty' "$out/last/vc.json" 2>/dev/null || true)
  [ -n "$h" ] && vchash=$(jstr "$h")
fi
case "$action" in
  publish) emit published; say "published $value for $zone/$component ($uuid): values $after" ;;
  prune)   emit pruned;    say "pruned $zone/$component ($uuid) to $after" ;;
  verify)  emit verified;  say "verified $value for $zone/$component ($uuid): values $got" ;;
esac
