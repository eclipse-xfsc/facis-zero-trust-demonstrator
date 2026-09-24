#!/usr/bin/env bash
# Cases for enforced.sh against controlled status objects (plan: missing replica, stale generation,
# audit-only acknowledgement, error, wrong UID, all acknowledged).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

pods='{"items":[
  {"metadata":{"name":"gk-a"},"status":{"conditions":[{"type":"Ready","status":"True"}]}},
  {"metadata":{"name":"gk-b"},"status":{"conditions":[{"type":"Ready","status":"True"}]}},
  {"metadata":{"name":"gk-c"},"status":{"conditions":[{"type":"Ready","status":"False"}]}}]}'
echo "$pods" > "$work/pods.json"
echo '{"items":[]}' > "$work/none.json"
ack() { printf '{"id":"%s","operations":["%s"],"enforced":%s,"observedGeneration":%s,"constraintUID":"%s"%s}' "$1" "${2:-webhook}" "${3:-true}" "${4:-3}" "${5:-u1}" "${6:-}"; }
constraint() { printf '{"metadata":{"generation":3,"uid":"u1"},"status":{"byPod":[%s]}}' "$1"; }

failures=0
expect() { # name want(0|1) constraint-json [pods-file]
  echo "$3" > "$work/c.json"
  if "$here/enforced.sh" "$work/c.json" "${4:-$work/pods.json}"; then got=0; else got=1; fi
  if [ "$got" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1 (exit $got, want $2)"; failures=$((failures + 1)); fi
}
expect "every Ready replica acknowledged" 0 "$(constraint "$(ack gk-a),$(ack gk-b)")"
expect "a not-Ready replica need not acknowledge" 0 "$(constraint "$(ack gk-a),$(ack gk-b)")"
expect "one Ready replica missing" 1 "$(constraint "$(ack gk-a)")"
expect "stale generation" 1 "$(constraint "$(ack gk-a),$(ack gk-b webhook true 2)")"
expect "another constraint UID" 1 "$(constraint "$(ack gk-a),$(ack gk-b webhook true 3 u0)")"
expect "not enforced" 1 "$(constraint "$(ack gk-a),$(ack gk-b webhook false)")"
expect "acknowledged with errors" 1 "$(constraint "$(ack gk-a),$(ack gk-b webhook true 3 u1 ',"errors":[{"message":"x"}]')")"
expect "audit-only acknowledgement" 1 "$(constraint "$(ack gk-a),$(ack gk-b audit)")"
expect "no status yet" 1 '{"metadata":{"generation":3,"uid":"u1"}}'
expect "no Ready replica" 1 "$(constraint "$(ack gk-a),$(ack gk-b)")" "$work/none.json"
[ "$failures" -eq 0 ]
