#!/usr/bin/env bash
#
# Measures the fixture twice -- as the checkout left it, and after normalisation --
# and prints both results as key=value lines, so that a caller can compare them
# with the results of the same script on another machine.
#
#   raw_*         what this machine would publish with no normalisation
#   normalised_*  what the commit is supposed to determine
#
# Only the normalised values are expected to agree elsewhere. The raw values are
# printed because a check where they happen to agree everywhere has proved
# nothing: something has to establish that the normalisation is load-bearing.
#
# Usage: proof.sh [BUNDLE_DIR]

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bundle="${1:-$here/bundle}"

emit() { # emit PREFIX < json
  local prefix="$1" json
  json="$(cat)"
  for field in configSha256 rootfsSha256 templateHash; do
    local value
    value="$(printf '%s' "$json" | sed -n "s/.*\"$field\": \"\\([0-9a-f]*\\)\".*/\\1/p")"
    if [ -z "$value" ]; then
      echo "proof.sh: no $field in the measurement output" >&2
      exit 1
    fi
    printf '%s_%s=%s\n' "$prefix" "$field" "$value"
  done
}

"$here/measure-with-cmc.sh" "$bundle" | emit raw
"$here/normalise.sh" "$bundle"
"$here/measure-with-cmc.sh" "$bundle" | emit normalised
