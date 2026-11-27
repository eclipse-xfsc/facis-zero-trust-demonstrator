#!/usr/bin/env bash
# Cases for runner-labels.sh: unset gives the hosted default, a label array is passed through compact,
# and everything that is not a non-empty array of plain labels is refused.
#
#   scripts/supplychain/runner-labels_test.sh
set -euo pipefail
script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/runner-labels.sh"
failures=0
want() { # name input expected
  local got
  if got="$(SIGNING_RUNNER="$2" "$script" 2>/dev/null)" && [ "$got" = "$3" ]; then echo "ok    $1"
  else echo "FAIL  $1 (got '${got:-<refused>}', want '$3')"; failures=$((failures + 1)); fi
}
refused() { # name input
  if SIGNING_RUNNER="$2" "$script" >/dev/null 2>&1; then echo "FAIL  $1 (accepted, want refused)"; failures=$((failures + 1))
  else echo "ok    $1"; fi
}
want "unset is the hosted runner" "" '["ubuntu-latest"]'
want "a label array is passed through" '[ "self-hosted", "ztd-signing" ]' '["self-hosted","ztd-signing"]'
refused "not JSON" 'self-hosted'
refused "a string, not an array" '"self-hosted"'
refused "an empty array" '[]'
refused "a label that is not a string" '["self-hosted", 1]'
refused "an empty label" '["self-hosted", ""]'
# shellcheck disable=SC2016 # the expression is the input, literally
refused "a label with an expression" '["${{ secrets.X }}"]'
[ "$failures" -eq 0 ] || { echo "$failures case(s) failed"; exit 1; }
