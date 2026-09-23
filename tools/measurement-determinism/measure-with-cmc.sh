#!/usr/bin/env bash
#
# Measures an OCI bundle with the attestation component's own measurement code at
# the pinned revision, and prints the three hashes as JSON.
#
# The component is fetched here rather than required by the delivery module, so
# that this check does not add a dependency to go.mod. What is pinned is the
# revision: the measurement is a property of that code, so a comparison across
# machines is only meaningful while both sides run the same one.
#
# Usage: measure-with-cmc.sh BUNDLE_DIR [WORK_DIR]

set -euo pipefail

readonly CMC_REPO="https://github.com/Fraunhofer-AISEC/cmc"
readonly CMC_COMMIT="6754d3c8992133830a3fb0e4c56c860c28e38c1e" # v0.9.15

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bundle="${1:-}"
work="${2:-${RUNNER_TEMP:-/tmp}/measurement-determinism}"

if [ -z "$bundle" ] || [ ! -d "$bundle" ]; then
  echo "usage: $0 BUNDLE_DIR [WORK_DIR]" >&2
  exit 2
fi

checkout="$work/cmc"
if [ ! -d "$checkout/.git" ]; then
  mkdir -p "$work"
  git -c advice.detachedHead=false clone --quiet "$CMC_REPO" "$checkout"
fi
git -C "$checkout" -c advice.detachedHead=false checkout --quiet "$CMC_COMMIT"

# The program carries a build tag that keeps it out of this repository's module;
# inside the component's module it is an ordinary main package.
mkdir -p "$checkout/cmd/measurebundle"
sed '/^\/\/go:build ignore$/d' "$here/measure.go" > "$checkout/cmd/measurebundle/main.go"

binary="$work/measurebundle"
(cd "$checkout" && go build -o "$binary" ./cmd/measurebundle)

"$binary" -bundle "$bundle"
