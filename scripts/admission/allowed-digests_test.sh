#!/usr/bin/env bash
# Cases for admission_allowed_json (checks.sh), the digest allow-list install.sh writes to the provider
# and the constraint: entries separated by spaces, tabs or newlines give the same array of exactly the
# entries checked; an empty list gives []; an entry with a tag instead of a digest is refused and named.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/admission/checks.sh
. "$here/checks.sh"

a=docker.io/istio/proxyv2@sha256:d86cba0dd1eb15c00b6901c69ce5ae3d2d5f8427a47751098cf8c3ab2a4a62e9
b=registry.example:5000/team/tool@sha256:0000000000000000000000000000000000000000000000000000000000000001
want=$(jq -cn --arg a "$a" --arg b "$b" '[$a, $b]')
failures=0
check() { # name input want-output want-status
  local out status=0
  out=$(admission_allowed_json "$2" 2>/dev/null) || status=$?
  if [ "$status" = "$4" ] && [ "$out" = "$3" ]; then echo "ok    $1"; else echo "FAIL  $1: status $status, output '$out'"; failures=$((failures + 1)); fi
}
check "space-separated" "$a $b" "$want" 0
check "newline-separated" "$a"$'\n'"$b" "$want" 0
check "tab-separated" "$a"$'\t'"$b" "$want" 0
check "mixed separators, leading and trailing whitespace" $'\n\t '"$a"$'\t\n  '"$b"$' \n' "$want" 0
check "empty" "" "[]" 0
check "whitespace only" $' \n\t' "[]" 0
check "a tag instead of a digest is refused" "$a docker.io/istio/proxyv2:1.31.1" "" 1
if out=$(admission_allowed_json "$a nope" 2>&1); then echo "FAIL  the refusal: accepted"; failures=$((failures + 1));
elif grep -q "entry 'nope'" <<<"$out"; then echo "ok    the refusal names the entry"; else echo "FAIL  the refusal: $out"; failures=$((failures + 1)); fi
[ "$failures" -eq 0 ]
