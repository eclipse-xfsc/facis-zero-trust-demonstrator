#!/usr/bin/env bash
# Proof of the TRAIN publication step against the real TSPA. Upstream's TSPA image is built from
# its Dockerfile at the pinned commit and installed with upstream's chart and test realm on a
# disposable kind cluster (the kit under scripts/verify-tspa-api); a stand-in component runs with
# the configuration that was measured; the two measurement records come from the attestation
# component's own measurement code over the fixture bundle of tools/measurement-determinism, the
# second after one line of config.json changed. For every row of matrix.tsv the proof then drives
# the two steps the lifecycle wrapper will call around a rollout: publish before, prune after. A
# publication that is not proven leaves the rollout unstarted and the old pods running; a proven
# one is followed by the rollout, and the pods that come up carry the image digest and the
# configuration the record names. Every check appends to the evidence file; the exit status is
# non-zero when any check failed.
#
#   TSPA_REPO=<clone of eclipse-xfsc/train-trust-framework-manager, with train-shared in shared/> \
#     scripts/verify-train-publish/verify.sh [--out DIR]
#
#   --out DIR   raw records of the run (default: .dev/train-publish-proof, which git ignores): the
#               publisher's publications.jsonl, per row its stdout, stderr, request and lists, the
#               pods seen, environment.json and the kind-up log
#
# Environment:
#   TSPA_REPO               required by the kit's kind-up.sh (the first image build takes about 15 minutes)
#   TRAIN_PROOF_EVIDENCE    where the evidence goes (default: evidence.md next to this script)
#   TRAIN_PROOF_CMC_WORK    where measure-with-cmc.sh keeps its checkout (default: .dev/cmc)
#
# Needs kind, kubectl, helm, docker, curl, jq, python3, sha256sum, git and go (for the measurement).
# shellcheck disable=SC2016  # jq programs quote $names on purpose
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
kit="$root/scripts/verify-tspa-api"
publisher="$root/scripts/train-publish/publish.sh"
measure="$root/tools/measurement-determinism/measure-with-cmc.sh"
bundle_src="$root/tools/measurement-determinism/bundle"
out="$root/.dev/train-publish-proof"
evidence="${TRAIN_PROOF_EVIDENCE:-$here/evidence.md}"
cmc_work="${TRAIN_PROOF_CMC_WORK:-$root/.dev/cmc}"
kubeconfig="$root/.dev/tspa/kubeconfig"

fw=facis-ztd.local
zone=b
component=connector
sti=did:web:connector-b.facis-ztd.local
ns=train-publish-proof
# The stand-in's image, pinned by its manifest digest: the imageID the pods report is compared
# with the digest the record names, which is this one.
image=docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b
digest=${image#*@}

die() { echo "verify.sh: $*" >&2; exit 2; }
while [ $# -gt 0 ]; do
  case $1 in
    --out) { [ $# -ge 2 ] && [ -n "$2" ]; } || die "--out needs a directory"; out=$2; shift 2 ;;
    -h|--help) sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done
for tool in kind kubectl helm docker curl jq python3 sha256sum git go; do
  command -v "$tool" >/dev/null || die "$tool is required"
done
[ -n "${TSPA_REPO:-}" ] || die "set TSPA_REPO to a clone of train-trust-framework-manager (see scripts/verify-tspa-api/README.md)"
[ -x "$publisher" ] || die "publisher not found: $publisher"

mkdir -p "$out"; out="$(cd "$out" && pwd)"
rows="$out/rows"; pubout="$out/publisher"
rm -rf "$rows" "$pubout"; mkdir -p "$rows" "$pubout" "$out/records"
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
fails() { if [ -f "$work/fails" ]; then wc -l < "$work/fails"; else echo 0; fi; }
le() { [ "$1" = "$2" ] || [ "$1" \< "$2" ]; }   # le <a> <b>: a <= b as ISO-8601 strings in UTC
eq2() { [ "$1" = "$2" ] && [ "$3" = "$4" ]; }    # eq2 <a> <b> <c> <d>: a = b and c = d
in_set() { local v=$1 x; shift; for x in "$@"; do [ "$v" = "$x" ] && return 0; done; return 1; }
k() { kubectl --kubeconfig "$kubeconfig" "$@"; }

# ---- the TSPA, Keycloak and the lanes to them ---------------------------------------------------
echo "== TSPA and Keycloak on kind (the kit's kind-up.sh)"
TSPA_REPO=$TSPA_REPO "$kit/kind-up.sh" > "$out/kind-up.log" 2>&1 || die "kind-up.sh failed; see $out/kind-up.log"
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
forward() {  # forward <service> <remote-port> <local-port> <ready-url>: a port-forward that answers
  k -n tspa port-forward "svc/$1" "$3:$2" >/dev/null 2>"$work/pf-$1.log" &
  forwards+=("$!")
  for _ in $(seq 60); do curl -s --max-time 2 -o /dev/null "$4" && return 0; sleep 1; done
  die "no answer from $1 through the port-forward: $(cat "$work/pf-$1.log")"
}
tspa_port=$(free_port); kc_port=$(free_port)
forward tspa-service 16003 "$tspa_port" "http://127.0.0.1:$tspa_port/tspa-service/api/docs"
forward keycloak 8080 "$kc_port" "http://127.0.0.1:$kc_port/realms/gxfs-dev-test"
export TSPA_URL="http://127.0.0.1:$tspa_port/tspa-service" TSPA_FRAMEWORK=$fw
export OIDC_TOKEN_URL="http://127.0.0.1:$kc_port/realms/gxfs-dev-test/protocol/openid-connect/token" OIDC_CLIENT_ID=xfsctest
api="$TSPA_URL/tspa/v1"
# The test client's secret, from upstream's realm export; it reaches the publisher through its
# environment and the proof's own token requests through a body file, never an argument.
OIDC_CLIENT_SECRET=$(python3 -c "import json,sys;print([c for c in json.load(open(sys.argv[1]))['clients'] if c['clientId']=='xfsctest'][0]['secret'])" "$TSPA_REPO/keycloak/realm-export.json")
[ -n "$OIDC_CLIENT_SECRET" ] || die "no secret for xfsctest in $TSPA_REPO/keycloak/realm-export.json"
export OIDC_CLIENT_SECRET

say "## 1. The TSPA, Keycloak and the lanes to them" ""
issuer=$(curl -s --max-time 10 "http://127.0.0.1:$kc_port/realms/gxfs-dev-test/.well-known/openid-configuration" | jq -r '.issuer // empty')
check "Keycloak reached through the port-forward issues tokens under the in-cluster name the TSPA validates" [ "$issuer" = "http://keycloak:8080/realms/gxfs-dev-test" ]
note "issuer: \`$issuer\`; the TSPA's \`issuer-uri\` is \`http://keycloak:8080/realms/gxfs-dev-test\` (values-kind.yaml)"
docs=$(curl -s --max-time 30 -o /dev/null -w '%{http_code}' "$TSPA_URL/api/docs") || docs=000
check "the TSPA answers through the port-forward (GET /api/docs $docs)" [ "$docs" = 200 ]
# /actuator/health probes the Zone Manager first (unreachable here) and can take long or time out:
# recorded, not judged (docs/tspa-publish-api.md 8).
t0=$(date +%s); health=$(curl -s --max-time 60 -o "$work/health.json" -w '%{http_code}' "$TSPA_URL/actuator/health") || health=000
note "\`GET /actuator/health\` answered $health after $(( $(date +%s) - t0 ))s: \`$(jq -c '{status, zonemanager: .components.zonemanagerHealthCheck.status}' "$work/health.json" 2>/dev/null || echo "no body")\`"

fetch_token() {  # fetch_token <out-file> [grant fields]: an access token for xfsctest; client_credentials by default
  local extra=${2:-grant_type=client_credentials}
  jq -rnj --arg extra "$extra" 'env.OIDC_CLIENT_SECRET as $s | "client_id=xfsctest&client_secret=\($s|@uri)&" + $extra' > "$work/form"
  curl -sS --max-time 30 -o "$work/tok.json" -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @"$work/form" "$OIDC_TOKEN_URL" \
    || die "token endpoint unreachable"
  rm -f "$work/form"
  jq -rj '.access_token // empty' "$work/tok.json" > "$1"
  [ -s "$1" ] || die "no token obtained: $(jq -c 'del(.access_token)' "$work/tok.json")"
}
claims() {  # claims <token-file>: the claims the TSPA reads, from the token on stdin (never an argument)
  python3 -c 'import sys,json,base64; p=sys.stdin.read().strip().split(".")[1]; p+="="*(-len(p)%4); c=json.loads(base64.urlsafe_b64decode(p)); print(json.dumps({"iss":c.get("iss"),"azp":c.get("azp"),"realm_roles":(c.get("realm_access") or {}).get("roles")}))' < "$1"
}
fetch_token "$work/operator.tok"
fetch_token "$work/testuser.tok" "grant_type=password&username=testuser&password=testuser"
check "the operator's token (service account of xfsctest) carries the realm role enrolltf" jq -e '.realm_roles | index("enrolltf") != null' <<<"$(claims "$work/operator.tok")"
note "operator token claims: \`$(claims "$work/operator.tok")\`"
check "testuser's token is valid but its realm roles lack enrolltf" jq -e '.realm_roles | index("enrolltf") == null' <<<"$(claims "$work/testuser.tok")"
note "testuser token claims: \`$(claims "$work/testuser.tok")\`"

tspa() {  # tspa <method> <path> [body-file] [token-file]: the operator's own calls; prints the status, body in $work/resp
  local method=$1 path=$2 bodyfile=${3:-} tokfile=${4:-}
  local args=(-sS --max-time 120 -o "$work/resp" -w '%{http_code}' -X "$method" "$api$path")
  [ -n "$bodyfile" ] && args+=(-H 'Content-Type: application/json' --data-binary @"$bodyfile")
  if [ -n "$tokfile" ]; then printf 'Authorization: Bearer %s\n' "$(cat "$tokfile")" > "$work/auth.h"; args+=(-H @"$work/auth.h"); fi
  curl "${args[@]}" 2>"$work/curl.err" || echo 000
  rm -f "$work/auth.h"
}
# A lane that drops mid-run (a port-forward dying) turns into failed checks, not an abort before
# the evidence is written: list() and pods_json() answer something on failure.
list() { curl -sS --max-time 60 "$api/$fw/trust-list" || echo '{"unreachable": true}'; }
list_sha() { list | sha256sum | cut -c1-64; }
entries() { list | jq -c --arg u "$uuid" '[.TrustServiceStatusList.TrustServiceProviderList.TrustServiceProvider // [] | .[] | select(.UUID == $u)]'; }
entry_count() { entries | jq length; }
all_entries() { list | jq '[.TrustServiceStatusList.TrustServiceProviderList.TrustServiceProvider // [] | .[]] | length'; }
teems() { entries | jq -c '[.[].TSPInformation.TSPCertificationList.TSPCertification[] | select(.Type == "TEEM-sha256") | .Value] | unique'; }
digests() { entries | jq -c '[.[].TSPInformation.TSPCertificationList.TSPCertification[] | select(.Type == "image-digest") | .Value] | unique'; }
entry_sti() { entries | jq -r '.[0].TSPServices.TSPService[0].ServiceTypeIdentifier // empty'; }

# ---- the two measurement records ----------------------------------------------------------------
echo "== measuring the fixture bundle twice with the attestation component's code"
say "## 2. The measurement records" ""
mkdir -p "$work/bundles"
cp -R "$bundle_src" "$work/bundles/v1"; cp -R "$bundle_src" "$work/bundles/v2"
# The second version: the same files, one value of config.json changed (an environment variable),
# the change docs/tspa-publish-api.md's story has: the measurement moves, the image digest does not.
jq '.process.env |= map(if startswith("APP_MODE=") then "APP_MODE=serving" else . end)' "$bundle_src/config.json" > "$work/bundles/v2/config.json"
measure_bundle() { "$measure" "$1" "$cmc_work" 2>"$work/measure.err" || die "measurement failed: $(tail -5 "$work/measure.err")"; }
m1=$(measure_bundle "$work/bundles/v1"); m2=$(measure_bundle "$work/bundles/v2")
{ [ -n "$m1" ] && [ -n "$m2" ]; } || die "measurement failed: $(tail -5 "$work/measure.err")"
commit=$(git -C "$root" rev-parse HEAD)
cmc_commit=$(sed -n 's/^readonly CMC_COMMIT="\([0-9a-f]*\)".*/\1/p' "$measure")
mkrecord() {  # mkrecord <measurement-json> <out-file>
  jq -n --arg c "$component" --arg z "$zone" --arg sti "$sti" --arg img "$image" --argjson m "$1" \
    --arg commit "$commit" --arg tool "cmc ${cmc_commit:0:7} measure-with-cmc.sh" --arg at "$(now)" '
    {component: $c, zone: $z, serviceTypeIdentifier: $sti, image: $img,
     measurement: {type: "TEEM-sha256", value: $m.templateHash, configSha256: $m.configSha256, rootfsSha256: $m.rootfsSha256},
     source: {commit: $commit, tool: $tool, producedAt: $at}}' > "$2"
}
mkrecord "$m1" "$out/records/v1.json"; mkrecord "$m2" "$out/records/v2.json"
v1=$(jq -r .measurement.value "$out/records/v1.json"); v2=$(jq -r .measurement.value "$out/records/v2.json")
cfg_sha() { sha256sum "$work/bundles/$1/config.json" | cut -c1-64; }
# The publisher derives the entry's UUID from the zone and the component; the proof derives it the
# same way and later checks the publisher's events agree, so the derivation is shown, not trusted.
uuid=$(python3 - "$zone" "$component" <<'PY'
import sys, uuid
ns = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/eclipse-xfsc/facis-zero-trust-demonstrator/train-publish")
print(uuid.uuid5(ns, f"{sys.argv[1]}/{sys.argv[2]}"))
PY
)
say "Both records were produced by \`tools/measurement-determinism/measure-with-cmc.sh\` (the attestation component at \`$cmc_commit\`) over the fixture bundle; the second after \`APP_MODE=maintenance\` became \`APP_MODE=serving\` in \`config.json\`. The image is the stand-in's, pinned by digest. The rootfs did not change, so its hash is the same in both; the configuration did, so its hash and the template hash (the TEEM value) differ. The rootfs hash is this machine's (the bundle was not normalised; see tools/measurement-determinism/README.md): what is published is a measurement, which is all the publisher needs." ""
say "Record v1 (\`records/v1.json\`):"; code "$(jq . "$out/records/v1.json")"
say "Record v2 (\`records/v2.json\`):"; code "$(jq . "$out/records/v2.json")"
check "the two records differ in their TEEM value" [ "$v1" != "$v2" ]
check "the two records differ in configSha256" [ "$(jq -r .measurement.configSha256 "$out/records/v1.json")" != "$(jq -r .measurement.configSha256 "$out/records/v2.json")" ]
check "the two records share rootfsSha256 (only the configuration changed)" [ "$(jq -r .measurement.rootfsSha256 "$out/records/v1.json")" = "$(jq -r .measurement.rootfsSha256 "$out/records/v2.json")" ]
check "the two records name the same image digest" [ "$(jq -r .image "$out/records/v1.json")" = "$(jq -r .image "$out/records/v2.json")" ]
note "entry UUID derived from zone \`$zone\` and component \`$component\`: \`$uuid\`"

# ---- the trust list and the stand-in component ----------------------------------------------------
echo "== the trust list of $fw (federation setup, not the publisher's) and the stand-in component"
say "" "## 3. The trust list and the stand-in component" ""
tspa DELETE "/$fw/trust-list" "" "$work/operator.tok" > /dev/null   # whatever an earlier run left
code=$(tspa PUT "/init/json/$fw/trust-list" "$kit/payloads/trustlist-init.json" "$work/operator.tok")
check "the trust list of $fw is created once, by the operator (201)" [ "$code" = 201 ]
note "\`PUT /init/json/$fw/trust-list\` answered $code: \`$(head -c 200 "$work/resp")\`"
check "no entry for the endpoint before the first publication" [ "$(entry_count)" = 0 ]

k create namespace "$ns" --dry-run=client -o yaml | k apply -f - > /dev/null
k -n "$ns" delete deploy connector --ignore-not-found --wait=true > /dev/null
k -n "$ns" wait --for=delete pod -l app=connector --timeout=120s > /dev/null 2>&1 || true   # an earlier run's pods, still terminating
for v in v1 v2; do
  k -n "$ns" create configmap "connector-config-$v" --from-file=config.json="$work/bundles/$v/config.json" --dry-run=client -o yaml | k apply -f - > /dev/null
done
render() { sed -e "s|\${IMAGE}|$image|g" -e "s|\${VERSION}|$1|g" -e "s|\${CONFIG_SHA}|$2|g" -e "s|\${NAMESPACE}|$ns|g" "$here/stand-in.yaml"; }
pods_json() { k -n "$ns" get pods -l app=connector -o json || echo '{"items": []}'; }
pod_uids() { pods_json | jq -r '.items[].metadata.uid' | sort; }
ready_pods() {  # the Running, Ready pods not being deleted: name, uid, version annotation, imageID, creation time
  pods_json | jq -c '[.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running" and ([.status.conditions[]? | select(.type == "Ready" and .status == "True")] | length) > 0)
    | {name: .metadata.name, uid: .metadata.uid, version: .metadata.annotations["config-version"], imageID: (.status.containerStatuses[0].imageID // ""), created: .metadata.creationTimestamp}]'
}
say "Namespace \`$ns\`: ConfigMaps \`connector-config-v1\` and \`connector-config-v2\` hold the two \`config.json\` files measured (sha256 \`$(cfg_sha v1)\` and \`$(cfg_sha v2)\`); the Deployment \`connector\` (\`stand-in.yaml\`) mounts one of them and runs \`$image\`. The rollout from v1 to v2 is the configuration-only change the records describe." ""

# ---- the publisher around a rollout ---------------------------------------------------------------
run_publisher() {  # run_publisher <row> <action> <record> <induction>: sets rc, outcome, event, elapsed
  local row=$1 action=$2 rec=$3 induce=$4 t0 closed
  t0=$(date +%s)
  set +e
  case $induce in
    none)          "$publisher" "$action" --record "$rec" --out "$pubout" ;;
    wrong-secret)  OIDC_CLIENT_SECRET="not-the-secret-$RANDOM" "$publisher" "$action" --record "$rec" --out "$pubout" ;;
    token-file:*)  env -u OIDC_TOKEN_URL -u OIDC_CLIENT_ID -u OIDC_CLIENT_SECRET TSPA_TOKEN_FILE="${induce#token-file:}" \
                     "$publisher" "$action" --record "$rec" --out "$pubout" ;;
    refused)       closed=$(free_port); TSPA_URL="http://127.0.0.1:$closed/tspa-service" "$publisher" "$action" --record "$rec" --out "$pubout" ;;
    blackhole)     TSPA_URL=http://10.255.255.1:16003/tspa-service TRAIN_PUBLISH_TIMEOUT=5 "$publisher" "$action" --record "$rec" --out "$pubout" ;;
    *)             echo "unknown induction $induce" >&2; false ;;
  esac > "$rows/$row.$action.out" 2> "$rows/$row.$action.err"
  rc=$?
  set -e
  elapsed=$(( $(date +%s) - t0 ))
  event=$(sed -n 's/^EVENT_JSON=//p' "$rows/$row.$action.out" | tail -1); [ -n "$event" ] || event='{}'
  outcome=$(jq -r '.outcome // "none"' <<<"$event")
  mkdir -p "$rows/$row/$action"; cp "$pubout"/last/* "$rows/$row/$action/" 2>/dev/null || true
  echo "   $action: exit $rc, outcome $outcome, ${elapsed}s"
}
observe_rollout() {  # observe_rollout <row>: while an old pod still runs and the new one runs but is not ready, read the list
  local row=$1 pods old new
  during_teems=""; during_digests=""; during_old=0; during_new=0; during_imageids="[]"
  [ -n "$pods_before" ] || return 0
  for _ in $(seq 120); do
    pods=$(pods_json)
    old=$(jq -r --arg b "$pods_before" '[.items[] | select((.metadata.uid | IN($b | split("\n")[])) and .status.phase == "Running" and .metadata.deletionTimestamp == null)] | length' <<<"$pods")
    new=$(jq -r --arg b "$pods_before" '[.items[] | select((.metadata.uid | IN($b | split("\n")[]) | not) and .metadata.deletionTimestamp == null and .status.phase == "Running")
      | select(([.status.conditions[]? | select(.type == "Ready" and .status == "True")] | length) == 0)] | length' <<<"$pods")
    if [ "$old" -ge 1 ] && [ "$new" -ge 1 ]; then
      during_old=$old; during_new=$new
      during_teems=$(teems); during_digests=$(digests)
      during_imageids=$(jq -c '[.items[] | .status.containerStatuses[]? | .imageID | select(. != null and . != "") | sub("^[^@]*@"; "")] | unique' <<<"$pods")
      echo "$pods" > "$rows/$row.pods-during.json"
      return 0
    fi
    sleep 1
  done
}
gated_rollout() {  # gated_rollout <row> <record> <version> <induction>: publish; roll out only when proven; prune
  local row=$1 rec=$2 ver=$3 induce=$4
  pods_before=$(pod_uids); list_before=$(list_sha)
  rollout=not-started; prune_rc=""; prune_outcome=""; prune_event='{}'
  run_publisher "$row" publish "$rec" "$induce"
  pub_rc=$rc; pub_outcome=$outcome; pub_event=$event; pub_elapsed=$elapsed
  [ "$pub_rc" = 0 ] || return 0
  rollout=started
  render "$ver" "$(cfg_sha "$ver")" | k apply -f - > "$rows/$row.apply.txt"
  observe_rollout "$row"
  if k -n "$ns" rollout status deploy/connector --timeout=240s > "$rows/$row.rollout.txt" 2>&1; then rollout=converged; else rollout=failed; fi
  pods_json > "$rows/$row.pods-after.json"
  run_publisher "$row" prune "$rec" none
  prune_rc=$rc; prune_outcome=$outcome; prune_event=$event
}

echo "== the matrix"
say "" "## 4. The rows of matrix.tsv" ""
say "Each row runs the gate the lifecycle wrapper will run: \`publish.sh publish\` with the record, then, only when it exits 0, the stand-in's rollout to the record's version and \`publish.sh prune\` once it has converged. The induction changes the publisher's environment for the publish step alone." ""
while IFS=$'\t' read -r id day induce_text expect_outcome expect_exit expect_rollout <&3; do
  [ "$id" = id ] && continue
  echo "## $id ($day): $induce_text"
  say "### $id — $day" "" "Induction: $induce_text. Expected: outcome \`$expect_outcome\`, exit $expect_exit, rollout $expect_rollout." ""
  before_fails=$(fails)
  case $id in
    first-publication)     rec=$out/records/v1.json; ver=v1; induce=none ;;
    wrong-secret)          rec=$out/records/v2.json; ver=v2; induce=wrong-secret ;;
    token-without-role)    rec=$out/records/v2.json; ver=v2; induce="token-file:$work/testuser.tok" ;;
    malformed-token)       rec=$out/records/v2.json; ver=v2; printf 'not.a.jwt\n' > "$work/bad.tok"; induce="token-file:$work/bad.tok" ;;
    lane-closed-refused)   rec=$out/records/v2.json; ver=v2; induce=refused ;;
    lane-closed-blackhole) rec=$out/records/v2.json; ver=v2; induce=blackhole ;;
    new-version)           rec=$out/records/v2.json; ver=v2; induce=none ;;
    republish-same)        rec=$out/records/v2.json; ver=v2; induce=none ;;
    *) die "matrix.tsv names a row this script does not know: $id" ;;
  esac
  val=$(jq -r .measurement.value "$rec")
  gated_rollout "$id" "$rec" "$ver" "$induce"
  check "$id: the publisher exits $expect_exit" [ "$pub_rc" = "$expect_exit" ]
  check "$id: outcome $expect_outcome" [ "$pub_outcome" = "$expect_outcome" ]
  check "$id: rollout $expect_rollout" [ "$rollout" = "$expect_rollout" ]
  check "$id: the event names the derived UUID" [ "$(jq -r '.uuid // empty' <<<"$pub_event")" = "$uuid" ]
  if [ "$expect_rollout" = not-started ]; then
    check "$id: the pods are the ones from before (no rollout began)" [ "$(pod_uids)" = "$pods_before" ]
    check "$id: the trust list is byte for byte what it was" [ "$(list_sha)" = "$list_before" ]
    check "$id: the pods still run v1" jq -e 'length >= 1 and all(.version == "v1")' <<<"$(ready_pods)"
  else
    check "$id: prune proven (exit 0, outcome pruned)" eq2 "$prune_rc" 0 "$prune_outcome" pruned
    check "$id: exactly one entry for the endpoint, whatever the number of publications" [ "$(entry_count)" = 1 ]
    check "$id: the entry's ServiceTypeIdentifier is the record's (the TCR's lookup key)" [ "$(entry_sti)" = "$sti" ]
    check "$id: after prune the TEEM set is the record's value alone" [ "$(teems)" = "[\"$val\"]" ]
    check "$id: after prune the image-digest set is the record's digest alone" [ "$(digests)" = "[\"$digest\"]" ]
    ready=$(ready_pods)
    check "$id: the ready pods all run version $ver" jq -e --arg v "$ver" 'length >= 1 and all(.version == $v)' <<<"$ready"
    check "$id: every ready pod's imageID is the published digest" jq -e --arg d "$digest" 'all(.imageID | sub("^[^@]*@"; "") == $d)' <<<"$ready"
    note "ready pods: \`$ready\`"
    pod=$(jq -r '.[0].name // empty' <<<"$ready")
    running_cfg=$(k -n "$ns" exec "$pod" -- sha256sum /app/config.json 2>/dev/null | cut -c1-64 || true)
    check "$id: the config.json in the running pod is the one measured for the record (sha256)" [ "$running_cfg" = "$(cfg_sha "$ver")" ]
    first_created=$(jq -r 'map(.created) | min // empty' <<<"$ready")
    if [ "$id" != republish-same ]; then
      check "$id: the trust list carried the value before the first pod of this version existed" le "$(jq -r .ts <<<"$pub_event")" "$first_created"
      note "published at \`$(jq -r .ts <<<"$pub_event")\`, first pod of $ver created at \`$first_created\`, pruned at \`$(jq -r .ts <<<"$prune_event")\`"
    fi
  fi
  case $id in
    first-publication)
      check "$id: the first publication is a PUT" [ "$(jq -r .tspa.method <<<"$pub_event")" = PUT ]
      check "$id: nothing was there before, the record's value after" eq2 "$(jq -c .before <<<"$pub_event")" '[]' "$(jq -c .after <<<"$pub_event")" "[\"$v1\"]"
      check "$id: the list holds one entry in all" [ "$(all_entries)" = 1 ] ;;
    wrong-secret)
      check "$id: no write was attempted" [ "$(jq -r .tspa.method <<<"$pub_event")" = null ] ;;
    token-without-role)
      check "$id: the TSPA refused the write with 403" [ "$(jq -r .tspa.status <<<"$pub_event")" = 403 ] ;;
    malformed-token)
      check "$id: the TSPA refused the write with 401" [ "$(jq -r .tspa.status <<<"$pub_event")" = 401 ] ;;
    lane-closed-refused)
      check "$id: the publisher gave up within the timeout (${pub_elapsed}s, limit 40)" [ "$pub_elapsed" -le 40 ] ;;
    lane-closed-blackhole)
      check "$id: the publisher gave up within the timeout (${pub_elapsed}s, limit 5 plus 10 of margin)" [ "$pub_elapsed" -le 15 ] ;;
    new-version)
      check "$id: the second publication is a PATCH of the same entry" [ "$(jq -r .tspa.method <<<"$pub_event")" = PATCH ]
      check "$id: the publication wrote the union of old and new" [ "$(jq -c .after <<<"$pub_event")" = "$(jq -cn --arg a "$v1" --arg b "$v2" '[$a, $b] | sort')" ]
      check "$id: both generations ran at once during the rollout (old running: $during_old, new not ready: $during_new)" [ "$(( during_old >= 1 && during_new >= 1 ))" = 1 ]
      check "$id: while they did, the entry carried both measurements" [ "$during_teems" = "$(jq -cn --arg a "$v1" --arg b "$v2" '[$a, $b] | sort')" ]
      check "$id: and both pods ran the published digest" [ "$during_imageids" = "[\"$digest\"]" ]
      note "during the rollout: TEEM \`$during_teems\`, digests \`$during_digests\`, pod imageIDs \`$during_imageids\`"
      check "$id: the list still holds one entry in all" [ "$(all_entries)" = 1 ] ;;
    republish-same)
      check "$id: the repeated publication is a PATCH, never a second PUT" [ "$(jq -r .tspa.method <<<"$pub_event")" = PATCH ]
      check "$id: the value was there before and is there after, once" eq2 "$(jq -c .before <<<"$pub_event")" "[\"$v2\"]" "$(jq -c .after <<<"$pub_event")" "[\"$v2\"]"
      check "$id: the list still holds one entry in all" [ "$(all_entries)" = 1 ] ;;
  esac
  say "" "Publish event:"; code "$pub_event"
  if [ -n "$prune_rc" ]; then say "Prune event:"; code "$prune_event"; fi
  say "stderr of the publish step:"; code "$(sed 's/^/  /' "$rows/$id.publish.err" | head -20)"
  row_fails=$(( $(fails) - before_fails )); result=PASS; [ "$row_fails" = 0 ] || result="FAIL ($row_fails)"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$day" "$expect_outcome" "$expect_exit" "$expect_rollout" \
    "$pub_outcome" "$pub_rc" "$rollout" "${pub_elapsed}s" "$result" >> "$work/summary.tsv"
done 3< "$here/matrix.tsv"

# ---- the read side ------------------------------------------------------------------------------
echo "== verify, and the quirk of section 5"
say "" "## 5. Reading back without writing, and the missing-token quirk" ""
run_publisher verify-v2 verify "$out/records/v2.json" none
check "verify of the current record: exit 0, outcome verified" eq2 "$rc" 0 "$outcome" verified
code "$event"
run_publisher verify-v1 verify "$out/records/v1.json" none
check "verify of the pruned record: exit 1, outcome not-published (the old value is gone)" eq2 "$rc" 1 "$outcome" not-published
code "$event"
# Section 5 of docs/tspa-publish-api.md: a write without Authorization is answered 200 with an empty
# body and stores nothing. The publisher cannot be made to send none (it always has a token or a
# file), so this is re-observed with the operator's curl; the publisher's handling of it
# (write-unconfirmed) is covered by publish_test.sh against the stand-in.
before=$(list_sha)
if [ -f "$rows/republish-same/prune/request.json" ]; then
  jq '.TrustServiceProvider.TSPInformation.TSPCertificationList.TSPCertification |= map(if .Type == "TEEM-sha256" then .Value = ("f" * 64) else . end)' \
    "$rows/republish-same/prune/request.json" > "$work/quirk.json"
else   # the row before did not get to prune: the quirk is still observed, with a request built from the template
  jq --arg u "$uuid" --arg sti "$sti" '.TrustServiceProvider | .UUID = $u | .TSPServices.TSPService[0].ServiceTypeIdentifier = $sti
    | .TSPServices.TSPService[0].ServiceDigitalIdentity.DigitalId.DID = $sti | .TSPServices.TSPService[0].StatusStartingTime = "2026-01-01T00:00:00Z"
    | .TSPInformation.TSPCertificationList.TSPCertification = [{Type: "TEEM-sha256", Value: ("f" * 64)}] | {TrustServiceProvider: .}' \
    "$root/scripts/train-publish/entry.tmpl.json" > "$work/quirk.json"
fi
code_q=$(tspa PATCH "/$fw/trust-list/tsp/$uuid" "$work/quirk.json" "")
check "a PATCH without Authorization is answered 200 (the upstream quirk still holds on this build)" [ "$code_q" = 200 ]
check "with an empty body" [ ! -s "$work/resp" ]
check "and the list is byte for byte unchanged: the write never ran" [ "$(list_sha)" = "$before" ]
note "a publisher trusting that 200 would have declared a value published that is not there; publish.sh treats an empty 2xx body as \`write-unconfirmed\`"

# ---- nothing secret anywhere ------------------------------------------------------------------
echo "== nothing secret in any record"
say "" "## 6. Nothing secret in the records" ""
cp "$pubout/publications.jsonl" "$out/publications.jsonl"
leaks=$(grep -rlF -e "$OIDC_CLIENT_SECRET" -e "$(cat "$work/operator.tok")" -e "$(cat "$work/testuser.tok")" "$out" "$body" 2>/dev/null || true)
jwts=$(grep -rlE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' "$out" "$body" 2>/dev/null || true)
check "neither the client secret nor a token of this run appears in the records, the logs or the evidence" [ -z "$leaks" ]
[ -z "$leaks" ] || note "found in: $leaks"
check "no JWT at all appears in the records, the logs or the evidence" [ -z "$jwts" ]
[ -z "$jwts" ] || note "found in: $jwts"

# ---- the evidence ---------------------------------------------------------------------------------
jq -n --arg date "$(now)" --arg commit "$commit" --arg tspa "$(git -C "$TSPA_REPO" rev-parse --short HEAD)" \
  --arg shared "$(git -C "$TSPA_REPO/shared" rev-parse --short HEAD 2>/dev/null || echo unknown)" --arg cmc "$cmc_commit" \
  --arg kind "$(kind version 2>/dev/null | head -1)" --arg node "$(sed -n 's/^node_image="\([^"]*\)".*/\1/p' "$kit/kind-up.sh")" \
  --arg keycloak "$(sed -n 's/.*image: \(quay.io[^ ]*\).*/\1/p' "$kit/keycloak.yaml")" \
  --arg tspa_image "$(docker image inspect -f '{{.Id}}' tspa-service:local 2>/dev/null || echo unknown)" --arg standin "$image" \
  --arg go "$(go version)" --arg kubectl "$(kubectl version --client -o json 2>/dev/null | jq -r .clientVersion.gitVersion)" --arg helm "$(helm version --short 2>/dev/null)" \
  '{date: $date, repository: $commit, tspa_commit: $tspa, train_shared_commit: $shared, cmc_commit: $cmc, kind: $kind, node_image: $node,
    keycloak_image: $keycloak, tspa_image_id: $tspa_image, stand_in_image: $standin, go: $go, kubectl: $kubectl, helm: $helm}' > "$out/environment.json"
total=$(wc -l < "$work/checks"); failed=$(fails)
{
  echo "# TRAIN publication proof against the real TSPA ($(now))"
  echo
  echo "Written by \`scripts/verify-train-publish/verify.sh\`: upstream's TSPA built from its Dockerfile and installed with its chart and test realm on the kind cluster of \`scripts/verify-tspa-api/kind-up.sh\`, reached through port-forwards from the host, the publisher \`scripts/train-publish/publish.sh\` run around the rollouts of a stand-in component. Checks: **$total**, failed: **$failed**."
  echo
  echo "| | |"; echo "|---|---|"
  jq -r 'to_entries[] | "| \(.key) | `\(.value)` |"' "$out/environment.json"
  echo
  echo "## Summary of the matrix"
  echo
  echo "| row | day | expected outcome | exit | rollout | observed outcome | exit | rollout | publish took | result |"
  echo "|---|---|---|---|---|---|---|---|---|---|"
  awk -F'\t' '{printf "| %s | %s | `%s` | %s | %s | `%s` | %s | %s | %s | %s |\n", $1, $2, $3, $4, $5, $6, $7, $8, $9, $10}' "$work/summary.tsv"
  echo
  cat "$body"
  echo
  echo "## 7. The publication records (publications.jsonl)"
  echo
  echo "One line per publisher run, in order; the evidence the lifecycle wrapper will relay as \`EVENT_JSON\`."
  echo; echo '```'; cat "$out/publications.jsonl"; echo '```'
  echo
  if [ "$failed" = 0 ]; then echo "**Verdict: all $total checks passed.**"; else echo "**Verdict: $failed of $total checks failed.**"; fi
} > "$evidence"
chmod 644 "$evidence"   # the umask above protects the run's records; the evidence is meant to be read
echo
echo "evidence: $evidence; records: $out"
if [ "$failed" = 0 ]; then echo "verify: all $total checks passed"; else echo "verify: $failed of $total checks failed"; exit 1; fi
