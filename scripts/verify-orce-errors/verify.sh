#!/usr/bin/env bash
# Proves, against a running ORCE container, that a malformed lifecycle command is refused in a
# machine-readable way: a JSON answer, the error object in the flow context, and a log that holds
# nothing but JSON records. The image is the first-party ORCE image (ORCE_IMAGE); this checkout's
# flow and settings are mounted over the ones it was built with, so the check is of the working tree.
set -euo pipefail

: "${ORCE_IMAGE:?set ORCE_IMAGE to the first-party ORCE image, built from deployment/docker/orce/Dockerfile}"
root=$(cd "$(dirname "$0")/../.." && pwd)
name="ztd-orce-errors-$$"
port="${ORCE_PORT:-18801}"
user=bdd
pass=$(openssl rand -hex 16)
token=$(openssl rand -hex 16)
# The image takes bcrypt hashes, never the passwords themselves.
hash=$(htpasswd -bnBC 8 "" "$pass" | tr -d ':\n')

trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

docker run -d --name "$name" --platform linux/amd64 -p "127.0.0.1:${port}:1880" \
  -e ORCE_READ_TOKEN="$token" -e ORCE_ADMIN_USER=admin -e ORCE_ADMIN_PASSWORD_HASH="$hash" \
  -e ORCE_HTTP_USER="$user" -e ORCE_HTTP_PASSWORD_HASH="$hash" \
  -v "$root/flows/lifecycle.json:/data/lifecycle.json:ro" \
  -v "$root/deployment/docker/orce/settings.js:/data/settings.js:ro" \
  "$ORCE_IMAGE" >/dev/null

post() { curl -s -o "$1" -w '%{http_code}' -u "$user:$pass" -X POST "http://127.0.0.1:${port}/lifecycle" -H 'content-type: application/json' -d '{not json'; }

work=$(mktemp -d)
status=000
for _ in $(seq 1 60); do
  status=$(post "$work/answer.json" || true)
  [ "$status" = 400 ] && break
  sleep 2
done

fail=0
check() { if "$@"; then echo "ok    $what"; else echo "FAIL  $what"; fail=1; fi; }

what="a malformed body is refused with 400 and a JSON result naming the field"
check test "$status" = 400 -a "$(jq -r '.ok, .errors.fields.command' "$work/answer.json" 2>/dev/null | tr '\n' ' ')" = "false must be a JSON object "

curl -s -H "authorization: Bearer $token" "http://127.0.0.1:${port}/context/flow/ztd-lifecycle-tab/lifecycleMalformed" >"$work/context.json"
what="the same error object and its time are in the flow context"
check test "$(jq -r '.msg | fromjson | [.result.errors.fields.command, (.time | test("^[0-9]{4}-.*Z$"))] | @tsv' "$work/context.json" 2>/dev/null)" = "$(printf 'must be a JSON object\ttrue')"

# The route as Express matches it, the size limit and a compressed body: none may fall back to the
# admin API's parser, and none may lose what the JSON parser did for a command before.
url="http://127.0.0.1:${port}"
what="a malformed body is refused the same way on /Lifecycle/"
check test "$(curl -s -u "$user:$pass" -X POST "$url/Lifecycle/" -H 'content-type: application/json' -d '{not json' | jq -r '.errors.fields.command' 2>/dev/null)" = "must be a JSON object"

head -c 6000000 /dev/zero | tr '\0' ' ' >"$work/large"
what="a body over the limit is refused with 413 and a JSON result"
check test "$(curl -s -w ' %{http_code}' -u "$user:$pass" -X POST "$url/lifecycle" -H 'content-type: application/json' --data-binary "@$work/large" | jq -Rr 'split(" ")[-1] as $code | (.[:-4] | fromjson | .errors.fields.command) + " " + $code' 2>/dev/null)" = "must not be larger than 5mb 413"

printf '{"type":"command","action":"nope"}' | gzip >"$work/command.gz"
what="a gzip-compressed command is decoded and validated by the lifecycle node"
check test "$(curl -s -u "$user:$pass" -X POST "$url/lifecycle" -H 'content-type: application/json' -H 'content-encoding: gzip' --data-binary "@$work/command.gz" | jq -r '.errors.fields.action' 2>/dev/null)" = "must be deploy or uninstall"

what="a command without credentials is refused before the flow"
check test "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$url/lifecycle" -H 'content-type: application/json' -d '{not json')" = 401

docker logs "$name" >"$work/orce.log" 2>&1
what="every log line is one JSON record with the documented fields"
check test "$(jq -R 'fromjson? // null | if type == "object" and keys_unsorted == ["time","level","type","name","id","msg"] then empty else 1 end' "$work/orce.log" | wc -l | tr -d ' ')" = 0 -a -s "$work/orce.log"

[ "$fail" = 0 ] || { echo "--- log"; cat "$work/orce.log"; }
rm -rf "$work"
exit "$fail"
