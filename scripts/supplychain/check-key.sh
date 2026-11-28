#!/usr/bin/env bash
# Before anything is built or pushed: the signing key key-source.sh selected must be reachable and must
# be the private half of the committed public key for that source, so a missing or wrong key never
# leaves unsigned images behind. Prints nothing of the key.
#
#   COSIGN_KEY=env://VAR|hashivault://NAME SIGNING_PUBLIC_KEY=docs/contracts/keys/<source>-cosign.pub \
#     [COSIGN_PASSWORD=...] [VAULT_ADDR=... VAULT_TOKEN=...] [COSIGN=cosign] scripts/supplychain/check-key.sh
#
# Without COSIGN_KEY and SIGNING_PUBLIC_KEY it checks the interim key, as before the key source existed.
set -euo pipefail

key="${COSIGN_KEY:-env://COSIGN_INTERIM_KEY}"
public="${SIGNING_PUBLIC_KEY:-docs/contracts/keys/interim-cosign.pub}"
case "$key" in
  env://*)
    var="${key#env://}"
    if [ -z "${!var:-}" ]; then
      echo "::error::$var is not set in the release environment - nothing is built or signed"
      exit 1
    fi ;;
  hashivault://*)
    if [ -z "${VAULT_ADDR:-}" ] || [ -z "${VAULT_TOKEN:-}" ]; then
      echo "::error::$key needs VAULT_ADDR and VAULT_TOKEN in the release environment - nothing is built or signed"
      exit 1
    fi ;;
  *)
    echo "::error::COSIGN_KEY must be env://<secret> or hashivault://<key>, not a file or another KMS"
    exit 1 ;;
esac
if [ ! -s "$public" ]; then
  echo "::error::$public is missing - commit the public key of this source before signing with it"
  exit 1
fi
derived="$(mktemp)"
trap 'rm -f "$derived"' EXIT
"${COSIGN:-cosign}" public-key --key "$key" > "$derived"
if ! diff -q "$derived" "$public" >/dev/null; then
  echo "::error::the signing key $key does not match $public"
  exit 1
fi
echo "check-key: $key matches $public"
