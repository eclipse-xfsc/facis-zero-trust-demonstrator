#!/usr/bin/env bash
# The runner the signing jobs run on: the repository variable SIGNING_RUNNER, a JSON array of runner
# labels (for example ["self-hosted","ztd-signing"]), or ["ubuntu-latest"] while it is unset. Anything
# else - not JSON, not an array, empty, a label that is not a plain string - is refused, so a typo
# never sends a signing job to a runner nobody chose. Prints the compact array, for
# runs-on: ${{ fromJSON(needs.signing-runner.outputs.labels) }}.
#
#   [SIGNING_RUNNER='["self-hosted","ztd-signing"]'] scripts/supplychain/runner-labels.sh
set -euo pipefail

labels="${SIGNING_RUNNER:-}"
[ -n "$labels" ] || labels='["ubuntu-latest"]'
jq -ce 'if type == "array" and length > 0 and all(.[]; type == "string" and test("^[A-Za-z0-9._-]+$"))
        then . else error("not a label array") end' <<<"$labels" 2>/dev/null \
  || { echo "::error::SIGNING_RUNNER must be a JSON array of runner labels, for example [\"self-hosted\",\"ztd-signing\"]" >&2; exit 1; }
