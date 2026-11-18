#!/usr/bin/env bash
# Reconciles one trust framework's TRAIN trust list with the file that declares it, through the TSPA
# trust-list API. The file (docs/contracts/train-trust-list.v1.schema.json, one per framework under
# deployment/train/trust-lists/) names the zones that claim the framework and the issuers it trusts;
# it changes by pull request, and this script makes the list follow it: an issuer that appears is a
# PUT, one whose entry differs is a PATCH of the same entry, one that left the file is a DELETE.
# Every entry it writes carries {Type: managed-by, Value: train-trust-list/<framework>} in its
# identifier list, and it removes nothing without that marker, so the pipeline's measurement
# entries (scripts/train-publish) and the client's own are never touched. An issuer whose lookup
# key already belongs to another live entry is a conflict: nothing is written, the file is wrong.
# The HTTP status is not the proof: after the writes the list is read again and must match the
# file (docs/tspa-publish-api.md, 2 and 7.1); the time from the first write to that read-back is
# recorded, since what a verifier still trusts after a removal is bounded by its own cache on top
# of it (docs/train-trust-lists.md).
#
#   scripts/train-trust-list/reconcile.sh validate --file FILE
#   scripts/train-trust-list/reconcile.sh plan     --file FILE [--out DIR]
#   scripts/train-trust-list/reconcile.sh apply    --file FILE [--out DIR] [--with-zones]
#   scripts/train-trust-list/reconcile.sh verify   --file FILE [--out DIR]
#   scripts/train-trust-list/reconcile.sh diff     --from OLD --to NEW
#
#   --with-zones   also PUT /trustframework/{fw} with the file's zone domains (the TSPA writes the
#                  PTR records through its zone manager) and prove each PTR with dig against
#                  TRAIN_DNS_SERVER
#
# Environment:
#   TSPA_URL             base URL of the TSPA up to its context path, e.g. http://host:16003/tspa-service
#   OIDC_TOKEN_URL       token endpoint for client_credentials; with OIDC_CLIENT_ID and OIDC_CLIENT_SECRET
#   TSPA_TOKEN_FILE      instead of the three above: a file holding a bearer token already obtained
#   TRAIN_DNS_SERVER     with --with-zones: the name server dig asks for the PTR records
#   TRAIN_TRUST_LIST_TIMEOUT   seconds per HTTP call (default 30)
#   TRAIN_TRUST_LIST_TEMPLATE  the entry template (default entry.tmpl.json next to this script)
#
# The framework is the file's; TSPA_FRAMEWORK is not read. Output: one JSON line per run appended
# to <out>/reconciliations.jsonl and printed to stdout as EVENT_JSON=<json>; plan and apply also
# say what changes, in words, on stderr; the requests and the lists read are kept under <out>/last/.
# No token or secret reaches any output or command line. Exit 0 when the read-back proves the
# action (verify: the list matches the file), 1 when it does not, a conflict stops it, or the TSPA
# could not be reached, 2 for a file or configuration refused before anything is called.
# Needs bash, curl, jq, python3 and sha256sum; dig with --with-zones.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
timeout_s=${TRAIN_TRUST_LIST_TIMEOUT:-30}
template=${TRAIN_TRUST_LIST_TEMPLATE:-$here/entry.tmpl.json}
ds="$here/desired_state.py"

usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; }
say() { echo "train-trust-list: $*" >&2; }
die() { local code=$1; shift; say "$*"; exit "$code"; }

action=${1:-}
[ $# -gt 0 ] && shift
file=""; from=""; to=""; out=.dev/train-trust-list; with_zones=0
while [ $# -gt 0 ]; do
  case "$1" in
    --file|--out|--from|--to) if [ $# -lt 2 ] || [ -z "$2" ]; then die 2 "$1 needs a value"; fi ;;
  esac
  case "$1" in
    --file) file=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    --from) from=$2; shift 2 ;;
    --to) to=$2; shift 2 ;;
    --with-zones) with_zones=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die 2 "unknown argument: $1" ;;
  esac
done
case "$action" in
  validate|plan|apply|verify|diff) ;;
  ""|-h|--help) usage; exit 0 ;;
  *) die 2 "unknown action '$action': validate, plan, apply, verify or diff" ;;
esac
for tool in curl jq python3 sha256sum; do
  command -v "$tool" >/dev/null || die 2 "$tool is required"
done
[ -f "$ds" ] || die 2 "desired_state.py not found beside this script"

# ---- the actions that call nothing -----------------------------------------------------------
if [ "$action" = diff ]; then
  { [ -n "$from" ] && [ -n "$to" ]; } || die 2 "diff needs --from OLD --to NEW"
  { [ -f "$from" ] && [ -f "$to" ]; } || die 2 "--from and --to must be files"
  python3 "$ds" diff "$from" "$to"
  exit 0
fi
if [ -z "$file" ] || [ ! -f "$file" ]; then die 2 "--file FILE is required and must exist"; fi
python3 "$ds" validate "$file" >/dev/null || exit 2
[ -f "$template" ] || die 2 "entry template not found: $template"
if [ "$action" = validate ]; then say "$file satisfies the contract"; exit 0; fi
[ "$with_zones" = 1 ] && [ "$action" != apply ] && die 2 "--with-zones goes with apply"
if [ "$with_zones" = 1 ]; then
  command -v dig >/dev/null || die 2 "dig is required with --with-zones"
  [ -n "${TRAIN_DNS_SERVER:-}" ] || die 2 "TRAIN_DNS_SERVER must be set with --with-zones"
fi
[ -n "${TSPA_URL:-}" ] || die 2 "TSPA_URL must be set"
if [ "$action" = apply ]; then   # refused before anything is called, as exit 2 promises
  if [ -n "${OIDC_TOKEN_URL:-}" ]; then
    for v in OIDC_CLIENT_ID OIDC_CLIENT_SECRET; do [ -n "${!v:-}" ] || die 2 "$v must be set with OIDC_TOKEN_URL"; done
  elif [ -n "${TSPA_TOKEN_FILE:-}" ]; then
    [ -r "$TSPA_TOKEN_FILE" ] || die 2 "TSPA_TOKEN_FILE is not a readable file: $TSPA_TOKEN_FILE"
    [ -s "$TSPA_TOKEN_FILE" ] || die 2 "TSPA_TOKEN_FILE is empty"
  else
    die 2 "set OIDC_TOKEN_URL with OIDC_CLIENT_ID and OIDC_CLIENT_SECRET, or TSPA_TOKEN_FILE"
  fi
fi

mkdir -p "$out/last"
out="$(cd "$out" && pwd)"
rm -f "$out"/last/*
umask 077
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fw=$(jq -r .framework "$file")
api="${TSPA_URL%/}/tspa/v1"
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
clock() { python3 -c 'import time; print(f"{time.time():.3f}")'; }
sha() { sha256sum "$1" | cut -c1-64; }
jstr() { jq -cn --arg v "$1" '$v'; }

# ---- where the file comes from: the audit trail starts here ----------------------------------
file_abs="$(cd "$(dirname "$file")" && pwd)/$(basename "$file")"
commit=null; dirty=null
if git -C "$(dirname "$file_abs")" rev-parse --show-toplevel >/dev/null 2>&1; then
  c=$(git -C "$(dirname "$file_abs")" log -1 --format=%H -- "$file_abs" 2>/dev/null || true)
  [ -n "$c" ] && commit=$(jstr "$c")
  if [ -n "$(git -C "$(dirname "$file_abs")" status --porcelain -- "$file_abs" 2>/dev/null)" ]; then dirty=true; else dirty=false; fi
fi
source=$(jq -cn --arg f "$file_abs" --arg s "$(sha "$file")" --argjson c "$commit" --argjson d "$dirty" \
  '{file: $f, sha256: $s, commit: $c, uncommittedChanges: $d}')

# ---- the evidence line -----------------------------------------------------------------------
plan_json='null'; writes='[]'; zones_json='null'; listsha=null; vchash=null; elapsed=null; started=""
emit() {  # emit <outcome>
  local summary line
  summary=$(jq -c '
    if . == null then null else
    {create: [.create[].id], replace: [.replace[].id], delete: [.delete[].uuid], unchanged: [.unchanged[].id],
     conflict: [.conflict[] | {id, serviceTypeIdentifier, uuids}], duplicate: .duplicate, unowned: [.unowned[] | {id, uuid}],
     converged: .converged} end' <<<"$plan_json")
  line=$(jq -cn --arg ts "$(now)" --arg action "$action" --arg fw "$fw" --argjson source "$source" \
    --argjson plan "$summary" --argjson writes "$writes" --argjson zones "$zones_json" \
    --argjson listsha "$listsha" --argjson vchash "$vchash" --argjson elapsed "$elapsed" --arg outcome "$1" '
    {ts: $ts, action: $action, framework: $fw, source: $source, plan: $plan, writes: $writes, zones: $zones,
     readBack: {listSha256: $listsha, vcHash: $vchash, elapsedSeconds: $elapsed}, outcome: $outcome}')
  echo "$line" >> "$out/reconciliations.jsonl"
  echo "EVENT_JSON=$line"
}
fail() {  # fail <outcome> <message>: record the failure and exit 1
  emit "$1"; say "$2"; say "outcome: $1 (the list does not follow $file; nothing is proven)"
  exit 1
}

# ---- the token (apply only; never printed, never on a command line) --------------------------
auth="$work/auth.h"
token() {
  local tok code
  if [ -n "${OIDC_TOKEN_URL:-}" ]; then
    jq -rnj 'env.OIDC_CLIENT_ID as $i | env.OIDC_CLIENT_SECRET as $s
            | "grant_type=client_credentials&client_id=\($i|@uri)&client_secret=\($s|@uri)"' > "$work/form"
    code=$(curl -sS --max-time "$timeout_s" -o "$work/token.json" -w '%{http_code}' \
      -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @"$work/form" "$OIDC_TOKEN_URL" 2>"$work/curl.err") \
      || fail token-failed "token endpoint unreachable: $(head -c 200 "$work/curl.err")"
    [ "$code" = 200 ] || fail token-failed "token endpoint answered $code"
    tok=$(jq -r '.access_token // empty' "$work/token.json" 2>/dev/null || true)
    [ -n "$tok" ] || fail token-failed "token endpoint answered 200 without an access_token"
  else
    tok=$(tr -d '\r\n' < "$TSPA_TOKEN_FILE")
    [ -n "$tok" ] || die 2 "TSPA_TOKEN_FILE is empty"
  fi
  printf 'Authorization: Bearer %s\n' "$tok" > "$auth"
}

# ---- the list and the plan -------------------------------------------------------------------
read_list() {  # read_list <file>: GET the trust list; sets code, returns 1 when unreachable
  code=$(curl -sS --max-time "$timeout_s" -o "$1" -w '%{http_code}' "$api/$fw/trust-list" 2>"$work/curl.err") || return 1
}
plan_against() {  # plan_against <list-file>: the plan for that list, into plan_json
  read_list "$1" || fail transport-failure "TSPA unreachable reading the trust list: $(head -c 200 "$work/curl.err")"
  case "$code" in
    200) ;;
    404) fail list-missing "the trust list of $fw does not exist: creating it is a federation setup step, not this script's" ;;
    *) fail tspa-error "reading the trust list answered $code" ;;
  esac
  plan_json=$(python3 "$ds" plan "$file" "$1" "$template") || fail tspa-error "the list read from the TSPA could not be planned against"
}
describe() {  # the plan in words, on stderr
  jq -r '
    (.create[] | "+ create \(.id) (\(.serviceTypeIdentifier)) as \(.uuid)"),
    (.replace[] | "~ replace \(.id) (\(.serviceTypeIdentifier)), entry \(.uuid)"),
    (.delete[] | "- delete \(.uuid) (\(.serviceTypeIdentifier // "no lookup key")), \(.name // "unnamed"): its issuer left the file"),
    (.unchanged[] | "= \(.id) is as the file says"),
    (.conflict[] | "! conflict: \(.id) names the lookup key \(.serviceTypeIdentifier), already held by \(.uuids | join(", ")) which the file does not own"),
    (.duplicate[] | "! duplicate: \(.count) entries carry the UUID \(.uuid); the list needs repair"),
    (.unowned[] | "! unowned: the entry \(.uuid) (\(.name // "unnamed")) is where \(.id) would be written but carries no managed-by marker; the file may not replace it"),
    (if .converged then "the list follows the file" else empty end)' <<<"$plan_json" | while IFS= read -r l; do say "$l"; done
}

plan_against "$out/last/list-before.json"
describe
jq -e '.duplicate == []' <<<"$plan_json" >/dev/null || fail duplicate-entry "the list carries the same UUID more than once; repair it before any reconciliation"
jq -e '.conflict == []' <<<"$plan_json" >/dev/null || fail conflict "an issuer in the file names a lookup key another entry already holds; nothing was written"
jq -e '.unowned == []' <<<"$plan_json" >/dev/null || fail unowned-entry "an entry without the managed-by marker sits under a UUID this file derives; nothing was written"
case "$action" in
  plan) emit planned; exit 0 ;;
  verify) listsha=$(jstr "$(sha "$out/last/list-before.json")")
          if jq -e .converged <<<"$plan_json" >/dev/null; then emit verified; say "verified: the list of $fw follows $file"; exit 0
          else fail drift "the list of $fw does not follow $file"; fi ;;
esac

# ---- apply: the writes, in order -------------------------------------------------------------
token
started=$(clock)
write() {  # write <method> <uuid> <body-file|-> : sets code; records the write
  local m=$1 uid=$2 bodyfile=$3 url
  case "$m" in
    PUT) url="$api/$fw/trust-list/tsp" ;;
    *) url="$api/$fw/trust-list/tsp/$uid" ;;
  esac
  local args=(-sS --max-time "$timeout_s" -o "$work/response.txt" -w '%{http_code}' -X "$m" -H @"$auth" "$url")
  [ "$bodyfile" != - ] && args+=(-H 'Content-Type: application/json' --data-binary @"$bodyfile")
  code=$(curl "${args[@]}" 2>"$work/curl.err") || { writes=$(jq -c --arg m "$m" --arg u "$uid" '. + [{method: $m, uuid: $u, status: null}]' <<<"$writes"); fail transport-failure "TSPA unreachable on $m $uid: $(head -c 200 "$work/curl.err")"; }
  writes=$(jq -c --arg m "$m" --arg u "$uid" --argjson s "$code" --arg b "$(sha "$work/response.txt")" '. + [{method: $m, uuid: $u, status: $s, bodySha256: $b}]' <<<"$writes")
  cp "$work/response.txt" "$out/last/response-$m-$uid.txt"
}
judge() {  # judge <method> <uuid>: the answer to a write, as docs/tspa-publish-api.md reads it
  case "$code" in
    200|201) [ -s "$work/response.txt" ] || fail write-unconfirmed "TSPA answered $code with an empty body on $1 $2: the write did not run (the token was not usable), nothing was stored" ;;
    401|403) fail write-rejected "TSPA refused $1 $2 with $code: the token lacks the enrolltf realm role, or is invalid" ;;
    400) fail write-rejected "TSPA rejected $1 $2 with 400: $(head -c 300 "$work/response.txt" | tr '\n' ' ')" ;;
    404) fail target-missing "TSPA answered 404 on $1 $2: the trust list of $fw, or the entry, does not exist" ;;
    *) fail tspa-error "TSPA answered $code on $1 $2" ;;
  esac
}
n=0
run_writes() {
  local i uid
  # Deletes first: an issuer that took over a lookup key under a new id must not share it, even briefly.
  for i in $(jq -r '.delete | keys[]' <<<"$plan_json"); do
    uid=$(jq -r ".delete[$i].uuid" <<<"$plan_json"); n=$((n + 1))
    write DELETE "$uid" -
    [ "$code" = 404 ] && return 1   # already gone: someone else removed it since the read
    judge DELETE "$uid"
  done
  for i in $(jq -r '.create | keys[]' <<<"$plan_json"); do
    uid=$(jq -r ".create[$i].uuid" <<<"$plan_json"); n=$((n + 1))
    jq ".create[$i].body" <<<"$plan_json" > "$out/last/request-$n-PUT-$uid.json"
    write PUT "$uid" "$out/last/request-$n-PUT-$uid.json"
    if [ "$code" = 400 ] && grep -qi 'already exists' "$work/response.txt"; then return 1; fi   # a writer raced us
    judge PUT "$uid"
  done
  for i in $(jq -r '.replace | keys[]' <<<"$plan_json"); do
    uid=$(jq -r ".replace[$i].uuid" <<<"$plan_json"); n=$((n + 1))
    jq ".replace[$i].body" <<<"$plan_json" > "$out/last/request-$n-PATCH-$uid.json"
    write PATCH "$uid" "$out/last/request-$n-PATCH-$uid.json"
    [ "$code" = 404 ] && return 1
    judge PATCH "$uid"
  done
  return 0
}
applied_plan=$plan_json
if ! jq -e .converged <<<"$plan_json" >/dev/null; then
  if ! run_writes; then
    # The plan was computed over a list that changed under us (an entry appeared or vanished between
    # the read and the write). Once, as docs/tspa-publish-api.md 7.1 asks: read again, plan again,
    # write what is left.
    say "the list changed since it was read; reading and planning again"
    plan_against "$out/last/list-raced.json"
    describe
    jq -e '.conflict == [] and .duplicate == [] and .unowned == []' <<<"$plan_json" >/dev/null || fail conflict "after the race the plan has a conflict, a duplicate or an unowned entry; nothing more was written"
    applied_plan=$plan_json
    run_writes || fail tspa-error "the list contradicts the TSPA's answers twice; not retrying"
  fi
fi

# ---- the read-back: the only proof -----------------------------------------------------------
# The evidence line carries the plan that was executed; the read-back's own plan only has to be
# empty, which is what proves the list now follows the file.
plan_against "$out/last/list-after.json"
readback=$plan_json; plan_json=$applied_plan
elapsed=$(python3 -c 'import sys; print(f"{float(sys.argv[1]) - float(sys.argv[2]):.3f}")' "$(clock)" "$started")
listsha=$(jstr "$(sha "$out/last/list-after.json")")
if vc=$(curl -sS --max-time "$timeout_s" -o "$out/last/vc.json" -w '%{http_code}' "$api/$fw/vc/trust-list" 2>/dev/null) && [ "$vc" = 200 ]; then
  h=$(jq -r '.credentialSubject.hash // empty' "$out/last/vc.json" 2>/dev/null || true)
  [ -n "$h" ] && vchash=$(jstr "$h")
fi
jq -e .converged <<<"$readback" >/dev/null || { plan_json=$readback; describe; fail not-converged "read-back: the list of $fw still differs from $file after the writes"; }
# ---- the zones, once the entries are proven: the PTR records, through the TSPA's zone manager -
if [ "$with_zones" = 1 ]; then
  jq -c '{schemes: .zones}' <<<"$plan_json" > "$out/last/request-trustframework.json"
  zcode=$(curl -sS --max-time "$timeout_s" -o "$out/last/response-trustframework.txt" -w '%{http_code}' -X PUT \
      -H 'Content-Type: application/json' -H @"$auth" --data-binary @"$out/last/request-trustframework.json" "$api/trustframework/$fw" 2>"$work/curl.err") \
    || { zones_json=$(jq -cn --argjson z "$(jq -c .zones <<<"$plan_json")" '{requested: $z, status: null, proven: []}'); fail transport-failure "TSPA unreachable on PUT /trustframework/$fw: $(head -c 200 "$work/curl.err")"; }
  proven='[]'
  for d in $(jq -r '.zones[]' <<<"$plan_json"); do
    # dig's own failure (no server, a timeout) is an unproven zone, not an abort: pipefail is on.
    target=$(dig +short +time=3 +tries=1 PTR "_scheme._trust.$d" "@$TRAIN_DNS_SERVER" 2>/dev/null | tr -d '[:space:]' | sed 's/\.$//' || true)
    [ "$target" = "_scheme._trust.$fw" ] && proven=$(jq -c --arg d "$d" '. + [$d]' <<<"$proven")
  done
  zones_json=$(jq -cn --argjson z "$(jq -c .zones <<<"$plan_json")" --argjson s "$zcode" --argjson p "$proven" '{requested: $z, status: $s, proven: $p}')
  case "$zcode" in
    200|201) [ -s "$out/last/response-trustframework.txt" ] || fail zones-not-published "TSPA answered $zcode with an empty body on PUT /trustframework/$fw: the write did not run" ;;
    *) fail zones-not-published "TSPA answered $zcode on PUT /trustframework/$fw (its zone manager could not be reached, or refused)" ;;
  esac
  [ "$(jq -c 'sort' <<<"$proven")" = "$(jq -c '.zones | sort' <<<"$plan_json")" ] \
    || fail zones-not-published "the PTR records read from $TRAIN_DNS_SERVER do not name the framework for every zone: proven $proven"
fi

if [ "$writes" = '[]' ] && [ "$with_zones" = 0 ]; then emit converged; say "nothing to write: the list of $fw follows $file"
else emit applied; say "applied $file to $fw: $(jq -r 'length' <<<"$writes") write(s), read back after ${elapsed}s"; fi
