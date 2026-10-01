#!/usr/bin/env bash
# Before anything is built or pushed: the interim signing key must be present and must be the private
# half of the committed public key, so a missing or wrong key never leaves unsigned images behind.
#
#   COSIGN_INTERIM_KEY=... COSIGN_PASSWORD=... [COSIGN=cosign] scripts/supplychain/check-key.sh
set -euo pipefail

public=docs/contracts/keys/interim-cosign.pub
if [ -z "${COSIGN_INTERIM_KEY:-}" ]; then
  echo "::error::COSIGN_INTERIM_KEY is not set in the release environment - nothing is built or signed"
  exit 1
fi
if [ ! -s "$public" ]; then
  echo "::error::$public is missing - nothing could verify the signatures"
  exit 1
fi
derived="$(mktemp)"
trap 'rm -f "$derived"' EXIT
"${COSIGN:-cosign}" public-key --key env://COSIGN_INTERIM_KEY > "$derived"
if ! diff -q "$derived" "$public" >/dev/null; then
  echo "::error::COSIGN_INTERIM_KEY does not match $public"
  exit 1
fi
