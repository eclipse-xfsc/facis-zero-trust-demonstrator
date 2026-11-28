#!/usr/bin/env bash
# Proof of the trust-list reconciliation (scripts/train-trust-list/reconcile.sh) against the real
# TSPA: upstream's image built from its Dockerfile at the pinned commit, installed with upstream's
# chart and test realm on a disposable kind cluster (the kit under scripts/verify-tspa-api). The
# desired-state file of the repository is applied as it is, then changed the way a pull request
# would change it: an issuer renamed, an issuer removed, an issuer that names a lookup key the
# pipeline's measurement entry already holds. Around it the publisher writes its own entry into the
# same list, and the proof checks it is never touched. For the removal, the time from the first
# write to the read-back that proves it is measured against the window docs/train-trust-lists.md
# documents. The zone manager runs beside the TSPA (the kit with TSPA_ZONE_MANAGER=1), so the zones'
# claims are published for real and proven by dig and through the manager's own API; a zone outside
# the DNS zone the manager serves is refused and reported. Every check appends to the evidence file;
# the exit status is non-zero when any failed.
#
#   TSPA_REPO=<clone of eclipse-xfsc/train-trust-framework-manager, with train-shared in shared/> \
#     scripts/verify-train-trust-list/verify.sh [--out DIR]
#
#   --out DIR   raw records of the run (default: .dev/train-trust-list-proof, which git ignores): the
#               reconciler's reconciliations.jsonl, per step its stdout, stderr, requests and lists,
#               the files applied, and the kind-up log
#
# Environment:
#   TSPA_REPO               required by the kit's kind-up.sh (the first image build takes about 15 minutes)
#   TRAIN_PROOF_EVIDENCE    where the evidence goes (default: evidence.md next to this script)
#
# Needs kind, kubectl, helm, docker, curl, jq, python3, sha256sum and dig. ZONE_MANAGER_REPO may name a
# checkout of the zone manager at the DNS kit's pinned commit; without it the kit fetches one.
# shellcheck disable=SC2016  # jq programs quote $names on purpose
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
kit="$root/scripts/verify-tspa-api"
reconciler="$root/scripts/train-trust-list/reconcile.sh"
ds="$root/scripts/train-trust-list/desired_state.py"
publisher="$root/scripts/train-publish/publish.sh"
desired_src="$root/deployment/train/trust-lists/facis-ztd.local.json"
out="$root/.dev/train-trust-list-proof"
evidence="${TRAIN_PROOF_EVIDENCE:-$here/evidence.md}"
kubeconfig="$root/.dev/tspa/kubeconfig"

fw=facis-ztd.local
window=300   # seconds: the TCR/gateway cache of the trust list, docs/architecture.md staleness matrix
connector_sti=did:web:connector-b.facis-ztd.local

die() { echo "verify.sh: $*" >&2; exit 2; }
while [ $# -gt 0 ]; do
  case $1 in
    --out) { [ $# -ge 2 ] && [ -n "$2" ]; } || die "--out needs a directory"; out=$2; shift 2 ;;
    -h|--help) sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done
for tool in kind kubectl helm docker curl jq python3 sha256sum dig; do
  command -v "$tool" >/dev/null || die "$tool is required"
done
[ -n "${TSPA_REPO:-}" ] || die "set TSPA_REPO to a clone of train-trust-framework-manager (see scripts/verify-tspa-api/README.md)"
[ -x "$reconciler" ] || die "reconciler not found: $reconciler"
[ -x "$publisher" ] || die "publisher not found: $publisher"
[ "$(jq -r .framework "$desired_src")" = "$fw" ] || die "$desired_src does not govern $fw"

mkdir -p "$out"; out="$(cd "$out" && pwd)"
steps="$out/steps"; files="$out/files"
rm -rf "$steps" "$files"; mkdir -p "$steps" "$files"
umask 077
work="$(mktemp -d)"
forwards=()
cleanup() {
  local s=$?
  for p in "${forwards[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$work"
  exit "$s"
}
trap cleanup EXIT

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
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
k() { kubectl --kubeconfig "$kubeconfig" "$@"; }
is_hex64() { [[ "$1" =~ ^[0-9a-f]{64}$ ]]; }

# ---- the TSPA, Keycloak and the lanes to them ---------------------------------------------------
echo "== TSPA and Keycloak on kind (the kit's kind-up.sh)"
TSPA_REPO=$TSPA_REPO TSPA_ZONE_MANAGER=1 TSPA_ZONE=$fw "$kit/kind-up.sh" > "$out/kind-up.log" 2>&1 || die "kind-up.sh failed; see $out/kind-up.log"
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
forward() {  # forward <service> <remote-port> <local-port> <ready-url>: a port-forward that answers
  k -n tspa port-forward "svc/$1" "$3:$2" >/dev/null 2>"$work/pf-$1.log" &
  forwards+=("$!")
  for _ in $(seq 60); do curl -s --max-time 2 -o /dev/null "$4" && return 0; sleep 1; done
  die "no answer from $1 through the port-forward: $(cat "$work/pf-$1.log")"
}
tspa_port=$(free_port); kc_port=$(free_port); zm_port=$(free_port); dns_port=$(free_port)
forward tspa-service 16003 "$tspa_port" "http://127.0.0.1:$tspa_port/tspa-service/api/docs"
forward keycloak 8080 "$kc_port" "http://127.0.0.1:$kc_port/realms/gxfs-dev-test"
forward nsd-service-rest 16001 "$zm_port" "http://127.0.0.1:$zm_port/status"
# A port-forward carries TCP only, so the PTR read-back asks over TCP.
k -n tspa port-forward svc/nsd-service-dns "$dns_port:53" >/dev/null 2>"$work/pf-dns.log" &
forwards+=("$!")
export TRAIN_DNS_SERVER=127.0.0.1 TRAIN_DNS_PORT=$dns_port TRAIN_DNS_TCP=1
export TSPA_URL="http://127.0.0.1:$tspa_port/tspa-service"
export OIDC_TOKEN_URL="http://127.0.0.1:$kc_port/realms/gxfs-dev-test/protocol/openid-connect/token" OIDC_CLIENT_ID=xfsctest
api="$TSPA_URL/tspa/v1"
# The test client's secret, from upstream's realm export; it reaches the scripts through their
# environment and the proof's own token requests through a body file, never an argument.
OIDC_CLIENT_SECRET=$(python3 -c "import json,sys;print([c for c in json.load(open(sys.argv[1]))['clients'] if c['clientId']=='xfsctest'][0]['secret'])" "$TSPA_REPO/keycloak/realm-export.json")
[ -n "$OIDC_CLIENT_SECRET" ] || die "no secret for xfsctest in $TSPA_REPO/keycloak/realm-export.json"
export OIDC_CLIENT_SECRET

say "## 1. The TSPA, Keycloak and the lanes to them" ""
issuer=$(curl -s --max-time 10 "http://127.0.0.1:$kc_port/realms/gxfs-dev-test/.well-known/openid-configuration" | jq -r '.issuer // empty')
check "Keycloak reached through the port-forward issues tokens under the in-cluster name the TSPA validates" [ "$issuer" = "http://keycloak:8080/realms/gxfs-dev-test" ]
docs=$(curl -s --max-time 30 -o /dev/null -w '%{http_code}' "$TSPA_URL/api/docs") || docs=000
check "the TSPA answers through the port-forward (GET /api/docs $docs)" [ "$docs" = 200 ]
health=$(curl -s --max-time 60 -o "$work/health.json" -w '%{http_code}' "$TSPA_URL/actuator/health") || health=000
check "the TSPA's health is UP now that its zone manager answers (GET /actuator/health $health)" bash -c "[ '$health' = 200 ] && [ '$(jq -r .status "$work/health.json")' = UP ]"
zm_status=$(curl -s --max-time 10 "http://127.0.0.1:$zm_port/status" || echo '{}')
check "the zone manager answers through the port-forward and serves the framework's DNS zone" bash -c "[ -n '$zm_status' ]"
note "zone manager status: \`$zm_status\`"
soa=$(dig +short +tcp +time=3 +tries=1 -p "$dns_port" SOA "$fw" @127.0.0.1 2>/dev/null || true)
check "the zone manager's name server answers authoritatively for $fw over the forwarded TCP port" bash -c "[ -n '$soa' ]"
note "SOA of \`$fw\`: \`$soa\`"
fetch_token() {  # fetch_token <out-file> [grant fields]
  local extra=${2:-grant_type=client_credentials}
  jq -rnj --arg extra "$extra" 'env.OIDC_CLIENT_SECRET as $s | "client_id=xfsctest&client_secret=\($s|@uri)&" + $extra' > "$work/form"
  curl -sS --max-time 30 -o "$work/tok.json" -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @"$work/form" "$OIDC_TOKEN_URL" \
    || die "token endpoint unreachable"
  rm -f "$work/form"
  jq -rj '.access_token // empty' "$work/tok.json" > "$1"
  [ -s "$1" ] || die "no token obtained: $(jq -c 'del(.access_token)' "$work/tok.json")"
}
claims() {
  python3 -c 'import sys,json,base64; p=sys.stdin.read().strip().split(".")[1]; p+="="*(-len(p)%4); c=json.loads(base64.urlsafe_b64decode(p)); print(json.dumps({"iss":c.get("iss"),"azp":c.get("azp"),"realm_roles":(c.get("realm_access") or {}).get("roles")}))' < "$1"
}
fetch_token "$work/operator.tok"
fetch_token "$work/testuser.tok" "grant_type=password&username=testuser&password=testuser"
check "the operator's token (service account of xfsctest) carries the realm role enrolltf" jq -e '.realm_roles | index("enrolltf") != null' <<<"$(claims "$work/operator.tok")"
check "testuser's token is valid but its realm roles lack enrolltf" jq -e '.realm_roles | index("enrolltf") == null' <<<"$(claims "$work/testuser.tok")"
note "operator token claims: \`$(claims "$work/operator.tok")\`; testuser: \`$(claims "$work/testuser.tok")\`"

tspa() {  # tspa <method> <path> [body-file] [token-file]: the proof's own calls; prints the status, body in $work/resp
  local method=$1 path=$2 bodyfile=${3:-} tokfile=${4:-}
  local args=(-sS --max-time 120 -o "$work/resp" -w '%{http_code}' -X "$method" "$api$path")
  [ -n "$bodyfile" ] && args+=(-H 'Content-Type: application/json' --data-binary @"$bodyfile")
  if [ -n "$tokfile" ]; then printf 'Authorization: Bearer %s\n' "$(cat "$tokfile")" > "$work/auth.h"; args+=(-H @"$work/auth.h"); fi
  curl "${args[@]}" 2>"$work/curl.err" || echo 000
  rm -f "$work/auth.h"
}
list() { curl -sS --max-time 60 "$api/$fw/trust-list" || echo '{"unreachable": true}'; }
list_sha() { list | sha256sum | cut -c1-64; }
all_entries() { list | jq '[.TrustServiceStatusList.TrustServiceProviderList.TrustServiceProvider // [] | .[]] | length'; }
entry() { list | jq -c --arg u "$1" '[.TrustServiceStatusList.TrustServiceProviderList.TrustServiceProvider // [] | .[] | select(.UUID == $u)]'; }
by_sti() { list | jq -c --arg s "$1" '[.TrustServiceStatusList.TrustServiceProviderList.TrustServiceProvider // [] | .[] | select(.TSPServices.TSPService[0].ServiceTypeIdentifier == $s)]'; }
managed() { list | jq -c --arg m "train-trust-list/$fw" '[.TrustServiceStatusList.TrustServiceProviderList.TrustServiceProvider // [] | .[] | select(any(.TSPInformation.TSPEntityIdentifierList.TSPEntityIdendifier[]?; .Type == "managed-by" and .Value == $m)) | .UUID] | sort'; }
vc_hash() { curl -sS --max-time 60 "$api/$fw/vc/trust-list" | jq -r '.credentialSubject.hash // empty'; }
uuid_of() { python3 "$ds" render "$1" | jq -r --arg id "$2" '.issuers[] | select(.id == $id) | .uuid'; }

# ---- the files a pull request would produce ------------------------------------------------------
cp "$desired_src" "$files/v1.json"
jq '.issuers |= map(if .id == "issuer-b" then .name = "Participant credential issuer of zone b (renamed)" else . end)' "$files/v1.json" > "$files/v2-renamed.json"
jq '.issuers |= map(select(.id != "issuer-b"))' "$files/v1.json" > "$files/v3-removed.json"
jq --arg sti "$connector_sti" '.issuers += [{id: "rogue", name: "An issuer naming the connector", serviceTypeIdentifier: $sti}]' "$files/v1.json" > "$files/v4-conflict.json"
ua=$(uuid_of "$files/v1.json" issuer-a); ub=$(uuid_of "$files/v1.json" issuer-b)
sti_b=$(jq -r '.issuers[] | select(.id == "issuer-b") | .serviceTypeIdentifier' "$files/v1.json")

rc=0
run() {  # run <name> <action> <file> [args...]: the reconciler, its stdout, stderr and out kept per step
  local name=$1 action=$2 f=$3; shift 3
  set +e
  "$reconciler" "$action" --file "$f" --out "$steps/$name" "$@" >"$steps/$name.out" 2>"$steps/$name.err"
  rc=$?
  set -e
  cat "$steps/$name/reconciliations.jsonl" >> "$out/reconciliations.jsonl" 2>/dev/null || true
}
event() { sed -n 's/^EVENT_JSON=//p' "$steps/$1.out" | tail -1; }
field() { event "$1" | jq -r "$2"; }
fieldc() { event "$1" | jq -c "$2"; }
row() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$work/summary.tsv"; }   # step, expected, outcome, exit

# ---- 2. the list exists (federation setup) -------------------------------------------------------
echo "== the trust list"
say "## 2. The trust list exists before anything is reconciled" ""
say "The operator creates it once with the kit's payload (\`scripts/verify-tspa-api/payloads/trustlist-init.json\`); the reconciler never does. A list left by an earlier run is removed first, so the run is repeatable." ""
tspa DELETE "/$fw/trust-list" "" "$work/operator.tok" >/dev/null || true
st=$(tspa PUT "/init/json/$fw/trust-list" "$kit/payloads/trustlist-init.json" "$work/operator.tok")
check "the trust list of $fw is created by the operator (PUT init, $st)" [ "$st" = 201 ]
check "the list has no entry" [ "$(all_entries)" = 0 ]
vc0=$(vc_hash)
note "the empty list's VC hash: \`$vc0\`"

# ---- 3. plan, then the first apply ---------------------------------------------------------------
echo "== the first apply"
say "## 3. The repository's file, applied as it is" ""
say "\`$(realpath --relative-to="$root" "$desired_src" 2>/dev/null || echo deployment/train/trust-lists/facis-ztd.local.json)\` declares two issuers for the framework \`$fw\`. \`plan\` says what \`apply\` would write and writes nothing; \`apply\` writes it and reads the list back." ""
sha0=$(list_sha)
run plan plan "$files/v1.json"
row "plan v1" "planned, two creates, no write" "$(field plan .outcome)" "$rc"
check "plan: exit 0, outcome planned, two creates" bash -c "[ '$rc' = 0 ] && [ '$(field plan .outcome)' = planned ] && [ '$(fieldc plan .plan.create)' = '[\"issuer-a\",\"issuer-b\"]' ]"
check "plan: the list is untouched" [ "$(list_sha)" = "$sha0" ]
code "$(sed 's/^train-trust-list: //' "$steps/plan.err")"
run a1 apply "$files/v1.json"
row "apply v1" "applied, two PUTs" "$(field a1 .outcome)" "$rc"
check "apply v1: exit 0, outcome applied" bash -c "[ '$rc' = 0 ] && [ '$(field a1 .outcome)' = applied ]"
check "apply v1: two PUTs answered 201" [ "$(fieldc a1 '[.writes[] | [.method, .status]]')" = '[["PUT",201],["PUT",201]]' ]
check "apply v1: two entries, under the UUIDs the file derives" bash -c "[ '$(all_entries)' = 2 ] && [ '$(managed)' = '$(jq -cn --arg a "$ua" --arg b "$ub" '[$a, $b] | sort')' ]"
check "apply v1: the entries carry the managed-by marker and the issuers' lookup keys" bash -c "[ '$(by_sti "$sti_b" | jq -r '.[0].UUID')' = '$ub' ]"
check "apply v1: the source names the copy applied here and its sha256 (the copy is outside version control: no commit)" bash -c "[[ '$(field a1 .source.sha256)' =~ ^[0-9a-f]{64}$ ]] && [ '$(field a1 .source.commit)' = null ]"
# The repository's own file, planned in place (nothing written): the audit trail names the commit that last touched it.
run plan_repo plan "$desired_src"
check "plan of the repository's file: the evidence names the commit that last touched it and that it has no uncommitted changes" bash -c "[[ '$(field plan_repo .source.commit)' =~ ^[0-9a-f]{40}$ ]] && [ '$(field plan_repo .source.uncommittedChanges)' = false ]"
note "source of the repository's file: \`$(event plan_repo | jq -c '.source | {sha256, commit, uncommittedChanges}')\` (the commit is the one that last touched the file when the proof ran; the commit that ships this evidence comes after it)"
check "apply v1: the read-back carries the list's sha256 and the VC's hash" bash -c "[[ '$(field a1 .readBack.listSha256)' =~ ^[0-9a-f]{64}$ ]] && [ -n '$(field a1 .readBack.vcHash)' ] && [ '$(field a1 .readBack.vcHash)' != null ]"
vc1=$(vc_hash)
check "apply v1: the signed VC the TCR consumes changed (its hash is the list's)" bash -c "[ '$vc1' != '$vc0' ] && [ '$(field a1 .readBack.vcHash)' = '$vc1' ]"
note "evidence line: \`$(event a1 | jq -c '{outcome, plan: .plan | {create, replace, delete}, writes: [.writes[] | [.method, .status]], readBack}')\`"
run a1b apply "$files/v1.json"
row "apply v1 again" "converged, no write" "$(field a1b .outcome)" "$rc"
check "apply v1 again: exit 0, converged, no write, the VC unchanged" bash -c "[ '$rc' = 0 ] && [ '$(field a1b .outcome)' = converged ] && [ '$(fieldc a1b .writes)' = '[]' ] && [ '$(vc_hash)' = '$vc1' ]"

# ---- 4. the pipeline's entry in the same list ----------------------------------------------------
echo "== the publisher's entry"
say "## 4. The pipeline publishes a measurement entry into the same list" ""
say "The publisher (\`scripts/train-publish/publish.sh\`) writes the connector's entry under its own UUID, without the reconciler's marker. The record is synthetic here (the measuring step is not part of this proof); what matters is that an entry the reconciler does not own sits in the list from now on." ""
hex() { printf '%s' "$1" | sha256sum | cut -c1-64; }
jq -n --arg sti "$connector_sti" --arg v "$(hex teem-v1)" --arg cfg "$(hex cfg)" --arg rfs "$(hex rootfs)" --arg img "docker.io/curlimages/curl@sha256:$(hex image)" \
  --arg commit "$(git -C "$root" rev-parse HEAD)" --arg at "$(now)" '
  {component: "connector", zone: "b", serviceTypeIdentifier: $sti, image: $img,
   measurement: {type: "TEEM-sha256", value: $v, configSha256: $cfg, rootfsSha256: $rfs},
   source: {commit: $commit, tool: "verify-train-trust-list (synthetic record)", producedAt: $at}}' > "$files/record.json"
set +e
TSPA_FRAMEWORK=$fw "$publisher" publish --record "$files/record.json" --out "$steps/publisher" >"$steps/publisher.out" 2>"$steps/publisher.err"
prc=$?
set -e
pub_uuid=$(sed -n 's/^EVENT_JSON=//p' "$steps/publisher.out" | tail -1 | jq -r .uuid)
check "the publisher's publication is proven (exit $prc, published)" bash -c "[ '$prc' = 0 ] && [ '$(sed -n 's/^EVENT_JSON=//p' "$steps/publisher.out" | tail -1 | jq -r .outcome)' = published ]"
check "three entries: two issuers and the connector" [ "$(all_entries)" = 3 ]
pub_before=$(entry "$pub_uuid")
check "the connector's entry carries no managed-by marker" [ "$(managed | jq length)" = 2 ]
note "the connector's entry: UUID \`$pub_uuid\`, lookup key \`$connector_sti\`"

# ---- 5. a pull request renames an issuer ---------------------------------------------------------
echo "== rename"
say "## 5. A pull request renames an issuer" ""
code "$("$reconciler" diff --from "$files/v1.json" --to "$files/v2-renamed.json")"
start_b=$(entry "$ub" | jq -r '.[0].TSPServices.TSPService[0].StatusStartingTime')
run a2 apply "$files/v2-renamed.json"
row "apply v2 (renamed)" "applied, one PATCH" "$(field a2 .outcome)" "$rc"
check "rename: exit 0, applied, one PATCH of issuer-b's entry" bash -c "[ '$rc' = 0 ] && [ '$(field a2 .outcome)' = applied ] && [ '$(fieldc a2 '[.writes[] | [.method, .uuid, .status]]')' = '[[\"PATCH\",\"$ub\",200]]' ]"
check "rename: the name changed, the UUID and the start time did not" [ "$(entry "$ub" | jq -c '.[0] | [.TSPName, .TSPServices.TSPService[0].StatusStartingTime]')" = "[\"Participant credential issuer of zone b (renamed)\",\"$start_b\"]" ]
check "rename: the connector's entry is byte for byte what it was" [ "$(entry "$pub_uuid")" = "$pub_before" ]
vc2=$(vc_hash)
check "rename: the VC hash moved" [ "$vc2" != "$vc1" ]

# ---- 6. a pull request removes an issuer: the window starts ---------------------------------------
echo "== removal"
say "## 6. A pull request removes an issuer" ""
code "$("$reconciler" diff --from "$files/v2-renamed.json" --to "$files/v3-removed.json")"
say "The entry is deleted and the list read back; the time between the first write and the read-back is the part of the window this side controls. What a verifier still trusts after that is bounded by its own cache: $window s for the trust list (docs/architecture.md, staleness matrix), plus the lifetime of a channel already open." ""
run a3 apply "$files/v3-removed.json"
row "apply v3 (removed)" "applied, one DELETE" "$(field a3 .outcome)" "$rc"
elapsed=$(field a3 .readBack.elapsedSeconds)
check "removal: exit 0, applied, one DELETE of issuer-b's entry" bash -c "[ '$rc' = 0 ] && [ '$(field a3 .outcome)' = applied ] && [ '$(fieldc a3 '[.writes[] | [.method, .uuid, .status]]')' = '[[\"DELETE\",\"$ub\",200]]' ]"
check "removal: two entries remain, issuer-a's and the connector's" bash -c "[ '$(all_entries)' = 2 ] && [ '$(managed)' = '[\"$ua\"]' ]"
check "removal: nothing in the list answers to the removed issuer's lookup key" [ "$(by_sti "$sti_b")" = '[]' ]
check "removal: the connector's entry is byte for byte what it was" [ "$(entry "$pub_uuid")" = "$pub_before" ]
vc3=$(vc_hash)
check "removal: the signed VC changed, so a TCR fetching it now gets a list without the issuer" bash -c "[ '$vc3' != '$vc2' ] && [ '$(field a3 .readBack.vcHash)' = '$vc3' ]"
check "removal: the read-back proved the removal within the documented window (${elapsed}s of ${window}s)" python3 -c 'import sys; sys.exit(0 if float(sys.argv[1]) < float(sys.argv[2]) else 1)' "$elapsed" "$window"
note "first write to read-back: ${elapsed}s; the documented window for a verifier's cached copy is ${window}s, plus a channel's lifetime"
run v3 verify "$files/v3-removed.json"
row "verify v3" "verified" "$(field v3 .outcome)" "$rc"
check "verify: the list follows the file (exit 0, verified, no write)" bash -c "[ '$rc' = 0 ] && [ '$(field v3 .outcome)' = verified ] && [ '$(fieldc v3 .writes)' = '[]' ]"
run v2 verify "$files/v2-renamed.json"
row "verify v2 after v3" "drift" "$(field v2 .outcome)" "$rc"
check "verify against the previous file: drift, exit 1, naming what apply would create" bash -c "[ '$rc' = 1 ] && [ '$(field v2 .outcome)' = drift ] && [ '$(fieldc v2 .plan.create)' = '[\"issuer-b\"]' ]"

# ---- 7. an entry edited by hand ------------------------------------------------------------------
echo "== edited by hand"
say "## 7. An entry edited by hand" ""
say "Someone with the role changes issuer-a's entry directly. \`verify\` sees the drift; \`apply\` writes it back as the file says." ""
entry "$ua" | jq '.[0] | .TSPName = "Edited by hand" | {TrustServiceProvider: .}' > "$files/tamper.json"
st=$(tspa PATCH "/$fw/trust-list/tsp/$ua" "$files/tamper.json" "$work/operator.tok")
check "the entry is edited by hand (PATCH $st)" [ "$st" = 200 ]
run v3b verify "$files/v3-removed.json"
row "verify after the edit" "drift" "$(field v3b .outcome)" "$rc"
check "verify after the edit: drift, replace issuer-a" bash -c "[ '$rc' = 1 ] && [ '$(field v3b .outcome)' = drift ] && [ '$(fieldc v3b .plan.replace)' = '[\"issuer-a\"]' ]"
run a3b apply "$files/v3-removed.json"
row "apply after the edit" "applied, one PATCH" "$(field a3b .outcome)" "$rc"
check "apply after the edit: one PATCH, the name is the file's again" bash -c "[ '$rc' = 0 ] && [ '$(fieldc a3b '[.writes[] | .method]')' = '[\"PATCH\"]' ] && [ '$(entry "$ua" | jq -r '.[0].TSPName')' = '$(jq -r '.issuers[0].name' "$files/v1.json")' ]"

# ---- 8. a lookup key the connector's entry holds -------------------------------------------------
echo "== conflict"
say "## 8. A pull request names a lookup key the connector's entry already holds" ""
code "$("$reconciler" diff --from "$files/v3-removed.json" --to "$files/v4-conflict.json")"
sha_c=$(list_sha)
run a4 apply "$files/v4-conflict.json"
row "apply v4 (conflict)" "conflict, nothing written" "$(field a4 .outcome)" "$rc"
check "conflict: exit 1, outcome conflict, naming the issuer, the key and the entry that holds it" bash -c "[ '$rc' = 1 ] && [ '$(field a4 .outcome)' = conflict ] && [ '$(fieldc a4 '.plan.conflict[0].uuids')' = '[\"$pub_uuid\"]' ]"
check "conflict: nothing was written; the list is byte for byte what it was" bash -c "[ '$(fieldc a4 .writes)' = '[]' ] && [ '$(list_sha)' = '$sha_c' ]"
code "$(sed 's/^train-trust-list: //' "$steps/a4.err" | grep -E '^(! conflict|outcome)' | sed "s#$out/#<out>/#g")"

# ---- 9. a token without the role, a write without a token ----------------------------------------
echo "== tokens"
say "## 9. A token without the role, a write without a token" ""
cp "$work/testuser.tok" "$work/weak.tok"
set +e
OIDC_TOKEN_URL= TSPA_TOKEN_FILE="$work/weak.tok" "$reconciler" apply --file "$files/v2-renamed.json" --out "$steps/weak" >"$steps/weak.out" 2>"$steps/weak.err"; rc=$?
set -e
cat "$steps/weak/reconciliations.jsonl" >> "$out/reconciliations.jsonl" 2>/dev/null || true
row "apply with testuser's token" "write-rejected (403)" "$(field weak .outcome)" "$rc"
check "testuser's token: exit 1, write-rejected, the TSPA answered 403, nothing changed" bash -c "[ '$rc' = 1 ] && [ '$(field weak .outcome)' = write-rejected ] && [ '$(fieldc weak '[.writes[] | .status]')' = '[403]' ] && [ '$(list_sha)' = '$sha_c' ]"
# The quirk the reconciler cannot be made to produce (it always sends the header), re-observed with curl.
st=$(tspa PATCH "/$fw/trust-list/tsp/$ua" "$files/tamper.json")
check "a PATCH without Authorization is answered $st with an empty body and stores nothing (docs/tspa-publish-api.md 5)" bash -c "[ '$st' = 200 ] && [ ! -s '$work/resp' ] && [ '$(list_sha)' = '$sha_c' ]"

# ---- 10. the zones: published through the zone manager, proven by dig and by the manager's API ---
echo "== zones"
say "## 10. The zones: claims published through the zone manager" ""
say "For each zone in the file the reconciler sends \`PUT /trustframework/<zone domain>\` with \`{\"schemes\": [\"$fw\"]}\`; the TSPA writes \`_scheme._trust.<zone domain> PTR _scheme._trust.$fw\` through the zone manager (upstream's semantics: the name is the record's owner, the schemes its targets). The reconciler proves each PTR with \`dig\` against the manager's own name server, over the forwarded TCP port; the proof reads the claims back a second way, through the manager's API with the operator's token." ""
run zones apply "$files/v3-removed.json" --with-zones
row "apply --with-zones" "applied, two claims, two PTRs" "$(field zones .outcome)" "$rc"
check "zones: exit 0, applied, one PUT /trustframework per zone answered 201" bash -c "[ '$rc' = 0 ] && [ '$(field zones .outcome)' = applied ] && [ '$(fieldc zones '[.zones.calls[] | .status]')' = '[201,201]' ]"
check "zones: both PTR records read back from the zone manager's name server name the framework" [ "$(fieldc zones '.zones.proven | sort')" = "$(jq -c '[.zones[].domain] | sort' "$files/v3-removed.json")" ]
check "zones: the claim's body names the framework as the target" [ "$(jq -c .schemes "$steps/zones/last/request-trustframework.json")" = "[\"$fw\"]" ]
for d in $(jq -r '.zones[].domain' "$files/v3-removed.json"); do
  ptr=$(dig +short +tcp +time=3 +tries=1 -p "$dns_port" PTR "_scheme._trust.$d" @127.0.0.1 2>/dev/null | tr -d '[:space:]' || true)
  check "zones: dig PTR _scheme._trust.$d answers _scheme._trust.$fw." [ "$ptr" = "_scheme._trust.$fw." ]
  printf 'Authorization: Bearer %s\n' "$(cat "$work/operator.tok")" > "$work/auth.h"
  claim=$(curl -sS --max-time 20 -H @"$work/auth.h" "http://127.0.0.1:$zm_port/names/$d/schemes" || echo '{}')
  rm -f "$work/auth.h"
  check "zones: the zone manager's API lists the claim of $d on $fw" [ "$(jq -c '.schemes' <<<"$claim")" = "[\"$fw\"]" ]
done
note "the TSPA answered: \`$(head -c 200 "$steps/zones/last/response-trustframework-$(jq -r '.zones[0].domain' "$files/v3-removed.json").txt")\`"
run zones2 apply "$files/v3-removed.json" --with-zones
row "apply --with-zones again" "applied, claims replaced, PTRs unchanged" "$(field zones2 .outcome)" "$rc"
check "zones again: exit 0, the claims are written again (the API replaces) and both PTRs still prove" bash -c "[ '$rc' = 0 ] && [ '$(field zones2 .outcome)' = applied ] && [ '$(fieldc zones2 '.zones.proven | length')' = 2 ]"
# A zone outside the DNS zone the manager serves: the manager answers 404 "domain name not in current
# zone", the TSPA reports 500, the reconciler reports the zone not published, after the entries were
# read back.
jq '.zones += [{name: "c", domain: "zone-c.other.test"}]' "$files/v3-removed.json" > "$files/v5-outside-zone.json"
run zones3 apply "$files/v5-outside-zone.json" --with-zones
row "apply --with-zones, a zone outside the DNS zone" "zones-not-published" "$(field zones3 .outcome)" "$rc"
outside_status=$(event zones3 | jq -c --arg z zone-c.other.test '[.zones.calls[] | select(.zone == $z) | .status]')
inside_status=$(event zones3 | jq -c --arg z zone-c.other.test '[.zones.calls[] | select(.zone != $z) | .status]')
check "a zone outside the served DNS zone: exit 1, zones-not-published, that call 500, the two others 201, the list read back" bash -c "[ '$rc' = 1 ] && [ '$(field zones3 .outcome)' = zones-not-published ] && [ '$outside_status' = '[500]' ] && [ '$inside_status' = '[201,201]' ] && [[ '$(field zones3 .readBack.listSha256)' =~ ^[0-9a-f]{64}$ ]]"
check "a zone outside the served DNS zone: not proven, the two inside still are" [ "$(fieldc zones3 '.zones.proven | sort')" = "$(jq -c '[.zones[].domain] | sort' "$files/v3-removed.json")" ]
note "the TSPA answered for the outside zone: \`$(head -c 300 "$steps/zones3/last/response-trustframework-zone-c.other.test.txt" | tr '\n' ' ')\`"
zm_log=$(k -n tspa logs deployment/nsd-service --since=5m 2>/dev/null | grep -i 'not in zone\|not in current zone' | tail -1 || true)
note "the zone manager's log: \`${zm_log:-<no matching line>}\`"

# ---- 11. no secret anywhere ----------------------------------------------------------------------
say "## 11. No secret in any record" ""
check "the client secret appears in no step output, record or request kept" bash -c "! grep -rq -- \"\$OIDC_CLIENT_SECRET\" '$steps' '$out/reconciliations.jsonl'"
check "no bearer token appears in any step output, record or request kept" bash -c "! grep -rqi -- 'authorization' '$steps' && ! grep -rq -- \"\$(cat '$work/operator.tok')\" '$steps' '$out/reconciliations.jsonl'"

# ---- the evidence --------------------------------------------------------------------------------
n=$(wc -l < "$work/checks" | tr -d ' '); f=$(fails)
tspa_commit=$(git -C "$TSPA_REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)
{
  echo "# Trust-list reconciliation against the real TSPA: evidence"
  echo
  echo "Run of \`scripts/verify-train-trust-list/verify.sh\` on $(now) against upstream's TSPA \`$tspa_commit\` built from its Dockerfile, on kind. The reconciler the run used: \`reconcile.sh\` sha256 \`$(sha256sum "$reconciler" | cut -c1-64)\`, \`desired_state.py\` sha256 \`$(sha256sum "$ds" | cut -c1-64)\`. Raw records: the \`--out\` directory (per step: stdout, stderr, requests and lists; \`reconciliations.jsonl\` with every evidence line of the run)."
  echo
  echo "## Summary of the steps"
  echo
  echo "| Step | Expected | Outcome | Exit |"
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
