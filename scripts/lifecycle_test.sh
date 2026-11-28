#!/usr/bin/env bash
# Cases for the TRAIN publication step of lifecycle.sh (LIFECYCLE_PUBLISH_RECORD): kubectl and helm
# are replaced by stubs that record their calls, the TSPA by scripts/train-publish/fake_tspa.py.
# What they hold the script to: without a record nothing changes; with one, publish runs and is
# proven before the server dry-run, prune after the release is ready, the result carries both
# evidence lines and the entry ends with the new value alone; a publication that is not proven
# (wrong secret) or refused (bad record) stops the deployment before helm runs; a record that does
# not exist is publishRefused too, never a field of the command; a publisher missing beside the script
# is a systemError; a Helm failure after a proven publication says what TRAIN keeps, and the next
# proven deploy prunes it; a prune that is not proven is pruneNotProven with the release's inventory
# in the result; no secret reaches stdout or stderr. Needs bash 5, curl, jq, python3 and
# sha256sum; no cluster, no network beyond localhost.
#
#   scripts/lifecycle_test.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for tool in curl jq python3 sha256sum; do
  command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 2; }
done
work="$(mktemp -d)"
fake=""
cleanup() { [ -n "$fake" ] && kill "$fake" 2>/dev/null; wait "$fake" 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT

# ---- the stubs: every call recorded, answers enough for the script's happy path ---------------
mkdir -p "$work/bin"
cat > "$work/bin/kubectl" <<'STUB'
#!/usr/bin/env bash
echo "kubectl $*" >> "$STUB_CALLS"
case "$*" in
  "get namespace kube-system -o jsonpath="*) echo stub-cluster-uid ;;
  "get namespace "*" -o name") echo "namespace/$3" ;;
  *"--output json"*) echo '{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"stub","uid":"uid-1"}}]}' ;;
esac
STUB
cat > "$work/bin/helm" <<'STUB'
#!/usr/bin/env bash
echo "helm $*" >> "$STUB_CALLS"
case "$*" in
  "version --short") echo v4.3.0-stub ;;
  *"--dry-run=server"*) echo "dry run ok" ;;
  "upgrade "*)
    [ -z "${STUB_FAIL_UPGRADE:-}" ] || { echo "Error: context deadline exceeded; rolled back"; exit 1; }
    if [ -n "${STUB_KILL_PID:-}" ]; then   # the TSPA dies while helm deploys; wait until it has
      kill "$STUB_KILL_PID" 2>/dev/null
      for _ in $(seq 100); do curl -s --max-time 1 -o /dev/null "$TSPA_URL/actuator/health" || break; sleep 0.05; done
    fi
    echo "Release deployed" ;;
  "get manifest "*) printf -- '---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: stub\n' ;;
  "status "*"--output json") echo '{"version": 3}' ;;
esac
STUB
chmod +x "$work/bin/kubectl" "$work/bin/helm"
mkdir -p "$work/chart"; echo 'name: stub' > "$work/chart/Chart.yaml"; echo 'a: 1' > "$work/values.yaml"

# ---- the TSPA stand-in, with a list ------------------------------------------------------------
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
secret="test-secret-$RANDOM$RANDOM"
FAKE_TSPA_SECRET=$secret python3 "$here/train-publish/fake_tspa.py" --port "$port" --log "$work/requests.jsonl" 2>"$work/fake.err" &
fake=$!
base="http://127.0.0.1:$port"
for _ in $(seq 50); do curl -sf --max-time 1 -o /dev/null "$base/tspa-service/actuator/health" && break; sleep 0.1; done
curl -sf --max-time 1 -o /dev/null "$base/tspa-service/actuator/health" || { echo "fake TSPA did not start: $(cat "$work/fake.err")" >&2; exit 2; }
export TSPA_URL="$base/tspa-service" TSPA_FRAMEWORK=test.local
export OIDC_TOKEN_URL="$base/realms/test/protocol/openid-connect/token" OIDC_CLIENT_ID=publisher OIDC_CLIENT_SECRET=$secret
curl -sS -o /dev/null -X PUT -H 'Authorization: Bearer enrolltf-token' -H 'Content-Type: application/json' \
  --data-binary '{"TrustServiceStatusList":{"FrameworkInformation":{"FrameworkName":{"Name":"test.local"}}}}' \
  "$TSPA_URL/tspa/v1/init/json/$TSPA_FRAMEWORK/trust-list"
export LIFECYCLE_RELEASE=stub LIFECYCLE_NAMESPACE=stub-ns LIFECYCLE_CHART=$work/chart LIFECYCLE_VALUES_FILE=$work/values.yaml

fails=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; fails=$((fails + 1)); }
check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi; }
eq() { while [ $# -ge 2 ]; do [ "$1" = "$2" ] || return 1; shift 2; done; }   # eq a b [c d ...]: every pair equal
hex() { printf '%s' "$1" | sha256sum | cut -c1-64; }
record() {  # record <file> <seed> [image]
  jq -n --arg v "$(hex "teem-$2")" --arg cfg "$(hex "cfg-$2")" --arg rfs "$(hex rootfs)" \
    --arg img "${3:-registry/b/connector@sha256:$(hex image)}" '
    {component: "connector", zone: "b", serviceTypeIdentifier: "did:example:b-connector", image: $img,
     measurement: {type: "TEEM-sha256", value: $v, configSha256: $cfg, rootfsSha256: $rfs},
     source: {commit: "0123456789abcdef", tool: "cmc 6754d3c measure"}}' > "$1"
}
record "$work/r1.json" one; record "$work/r2.json" two; record "$work/bad.json" three registry/b/connector:latest
v1=$(jq -r .measurement.value "$work/r1.json"); v2=$(jq -r .measurement.value "$work/r2.json")
rc=0
run() {  # run <name> [VAR=value...]: lifecycle.sh deploy with the stubs on PATH; rc, stdout, stderr and calls kept
  local name=$1; shift
  : > "$work/$name.calls"
  set +e
  env STUB_CALLS="$work/$name.calls" PATH="$work/bin:$PATH" "$@" bash "$here/lifecycle.sh" deploy >"$work/$name.out" 2>"$work/$name.err"
  rc=$?
  set -e
}
result() { sed -n 's/^RESULT_JSON=//p' "$work/$1.out" | tail -1; }
field() { result "$1" | jq -r "$2"; }
events() { sed -n 's/^EVENT_JSON=//p' "$work/$1.out" | jq -r '"\(.step):\(.status)"' | paste -sd' ' -; }
upgrades() { grep -c '^helm upgrade' "$work/$1.calls" || true; }
teems() { curl -sS "$TSPA_URL/tspa/v1/$TSPA_FRAMEWORK/trust-list" | jq -c '[.TrustServiceStatusList.TrustServiceProviderList.TrustServiceProvider // [] | .[] | .TSPInformation.TSPCertificationList.TSPCertification[] | select(.Type == "TEEM-sha256") | .Value] | unique'; }

echo "## without a record: the step is absent"
run plain
check "no record: exit 0, ok true" eq "$rc" 0 "$(field plain .ok)" true
check "no record: the events are the usual four" [ "$(events plain)" = "validate:running dry-run:running deploy:running deploy:succeeded" ]
check "no record: no publication in the result" [ "$(field plain '.publication // "absent"')" = absent ]
check "no record: helm upgraded twice (dry-run, then for real)" [ "$(upgrades plain)" = 2 ]

echo "## the first publication, around a deploy"
run first LIFECYCLE_PUBLISH_RECORD="$work/r1.json"
check "first: exit 0, ok true, revision from helm" eq "$rc" 0 "$(field first .ok)" true "$(field first .revision)" 3
check "first: publish is proven before the dry-run, prune after the release is ready" \
  [ "$(events first)" = "validate:running publish:running publish:succeeded dry-run:running deploy:running prune:running prune:succeeded deploy:succeeded" ]
check "first: the result carries the publisher's evidence for both steps" \
  eq "$(field first .publication.publish.outcome)" published "$(field first .publication.prune.outcome)" pruned
check "first: the first publication is a PUT, the prune a PATCH" \
  eq "$(field first .publication.publish.tspa.method)" PUT "$(field first .publication.prune.tspa.method)" PATCH
check "first: the entry holds the value alone" [ "$(teems)" = "[\"$v1\"]" ]

echo "## a new version: the union during the rollout, the new value after"
run second LIFECYCLE_PUBLISH_RECORD="$work/r2.json"
check "second: exit 0, ok true" eq "$rc" 0 "$(field second .ok)" true
check "second: publish wrote the union of old and new" [ "$(field second '.publication.publish.after | sort | join(",")')" = "$(printf '%s\n%s' "$v1" "$v2" | sort | paste -sd, -)" ]
check "second: prune left the new value alone" eq "$(field second '.publication.prune.after | join(",")')" "$v2" "$(teems)" "[\"$v2\"]"

echo "## a publication that is not proven stops the deployment before helm"
run badsecret LIFECYCLE_PUBLISH_RECORD="$work/r1.json" OIDC_CLIENT_SECRET=not-the-secret
check "wrong secret: exit 1, ok false, code publishNotProven" eq "$rc" 1 "$(field badsecret .ok)" false "$(field badsecret .error.code)" publishNotProven
check "wrong secret: the publisher's outcome is in the result" [ "$(field badsecret .publication.publish.outcome)" = token-failed ]
check "wrong secret: helm never ran an upgrade, not even the dry-run" [ "$(upgrades badsecret)" = 0 ]
check "wrong secret: the events say publish failed, then deploy failed" [ "$(events badsecret)" = "validate:running publish:running publish:failed deploy:failed" ]
check "wrong secret: the entry is untouched" [ "$(teems)" = "[\"$v2\"]" ]

echo "## a record the publisher refuses, and one that does not exist"
run badrecord LIFECYCLE_PUBLISH_RECORD="$work/bad.json"
check "refused record: exit 1, code publishRefused, no field (the record is not a field of the command)" eq "$rc" 1 "$(field badrecord .error.code)" publishRefused "$(field badrecord '.error.field // "none"')" none
check "refused record: the publication evidence says outcome none (refused before any call)" [ "$(field badrecord .publication.publish.outcome)" = none ]
check "refused record: helm never ran" [ "$(upgrades badrecord)" = 0 ]
run norecord LIFECYCLE_PUBLISH_RECORD="$work/does-not-exist.json"
check "missing record: exit 1, publishRefused naming the path, no field" eq "$rc" 1 "$(field norecord .error.code)" publishRefused "$(field norecord '.error.field // "none"')" none
check "missing record: the message names the path" grep -q 'does-not-exist.json' "$work/norecord.out"
check "missing record: helm never ran" [ "$(upgrades norecord)" = 0 ]

echo "## helm fails after a proven publication: the union stays in TRAIN, and the message says so"
run helmfail LIFECYCLE_PUBLISH_RECORD="$work/r1.json" STUB_FAIL_UPGRADE=1
check "helm failure: exit 1, deployFailed" eq "$rc" 1 "$(field helmfail .error.code)" deployFailed
check "helm failure: the publication was proven before it" [ "$(field helmfail .publication.publish.outcome)" = published ]
check "helm failure: the message says what TRAIN keeps" grep -q 'TRAIN entry keeps the previous and the new measurement' "$work/helmfail.out"
check "helm failure: the entry carries both values" [ "$(teems)" = "$(printf '["%s","%s"]' "$(printf '%s\n%s' "$v1" "$v2" | sort | head -1)" "$(printf '%s\n%s' "$v1" "$v2" | sort | tail -1)")" ]
run again LIFECYCLE_PUBLISH_RECORD="$work/r2.json"
check "the next proven deploy prunes the leftover" eq "$rc" 0 "$(teems)" "[\"$v2\"]"

echo "## the publisher missing beside the script (an installation without scripts/train-publish/)"
mkdir -p "$work/alone"; cp "$here/lifecycle.sh" "$work/alone/lifecycle.sh"
: > "$work/alone.calls"
set +e
env STUB_CALLS="$work/alone.calls" PATH="$work/bin:$PATH" LIFECYCLE_PUBLISH_RECORD="$work/r2.json" bash "$work/alone/lifecycle.sh" deploy >"$work/alone.out" 2>"$work/alone.err"
rc=$?
set -e
check "publisher missing: exit 1, systemError, not publishNotProven" eq "$rc" 1 "$(field alone .error.code)" systemError
check "publisher missing: the message names the publisher's path" grep -q 'train-publish/publish.sh' "$work/alone.out"
check "publisher missing: helm never ran" [ "$(upgrades alone)" = 0 ]
check "publisher missing: the entry is untouched" [ "$(teems)" = "[\"$v2\"]" ]

echo "## a prune that is not proven: the release stays, the step fails"
run badprune LIFECYCLE_PUBLISH_RECORD="$work/r2.json" STUB_KILL_PID="$fake"   # the TSPA dies while helm deploys
check "lost TSPA after the deploy: exit 1, code pruneNotProven" eq "$rc" 1 "$(field badprune .error.code)" pruneNotProven
check "lost TSPA after the deploy: the deploy did happen (two helm upgrades)" [ "$(upgrades badprune)" = 2 ]
# The stand-in is the token endpoint as well as the TSPA, so the first call prune cannot make is the token's.
check "lost TSPA after the deploy: publish proven, prune failed at its first call, both in the result" \
  eq "$(field badprune .publication.publish.outcome)" published "$(field badprune .publication.prune.outcome)" token-failed
check "lost TSPA after the deploy: the events end with prune failed" [ "$(events badprune)" = "validate:running publish:running publish:succeeded dry-run:running deploy:running prune:running prune:failed" ]
check "lost TSPA after the deploy: the result keeps the release's inventory" eq "$(field badprune .revision)" 3 "$(field badprune '.expected | length')" 1 "$(field badprune .chartDigest | cut -c1-7)" sha256:
check "lost TSPA after the deploy: the message names the revision and asks for prune again" grep -q 'revision 3.*run prune again' "$work/badprune.out"
wait "$fake" 2>/dev/null || true; fake=""

echo "## nothing secret in any output"
leaks=$(grep -lF -e "$secret" -e enrolltf-token "$work"/*.out "$work"/*.err 2>/dev/null | grep -v '/fake\.err$' || true)
check "no secret or token in stdout or stderr of any case" [ -z "$leaks" ]
[ -n "$leaks" ] && echo "leaked in: $leaks"

echo
if [ "$fails" = 0 ]; then echo "lifecycle_test: all checks passed"; else echo "lifecycle_test: $fails check(s) failed"; exit 1; fi
