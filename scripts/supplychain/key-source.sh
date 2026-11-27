#!/usr/bin/env bash
# Where the signing key comes from, chosen by the repository variable SIGNING_KEY_SOURCE, and the one
# public key that verifies it. Prints NAME=value lines for $GITHUB_ENV - references and paths, never
# key material:
#
#   COSIGN_KEY          what cosign signs with
#   SIGNING_PUBLIC_KEY  the committed public key every check verifies against
#
#   interim          (default) env://COSIGN_INTERIM_KEY, docs/contracts/keys/interim-cosign.pub
#   client           env://COSIGN_CLIENT_KEY (a cosign key file held as a secret, with
#                    COSIGN_CLIENT_PASSWORD), docs/contracts/keys/client-cosign.pub
#   openbao-transit  hashivault://<SIGNING_TRANSIT_KEY>, the key held in OpenBao's transit engine and
#                    used through cosign's HashiCorp Vault KMS: VAULT_ADDR from SIGNING_VAULT_ADDR, the
#                    engine's mount from SIGNING_TRANSIT_PATH (default transit), VAULT_TOKEN a secret;
#                    docs/contracts/keys/openbao-transit-cosign.pub
#
#   [SIGNING_KEY_SOURCE=...] [SIGNING_TRANSIT_KEY=... SIGNING_VAULT_ADDR=... [SIGNING_TRANSIT_PATH=...]] \
#     scripts/supplychain/key-source.sh
set -euo pipefail

source="${SIGNING_KEY_SOURCE:-interim}"
case "$source" in
  interim)
    echo "COSIGN_KEY=env://COSIGN_INTERIM_KEY"
    echo "SIGNING_PUBLIC_KEY=docs/contracts/keys/interim-cosign.pub" ;;
  client)
    echo "COSIGN_KEY=env://COSIGN_CLIENT_KEY"
    echo "SIGNING_PUBLIC_KEY=docs/contracts/keys/client-cosign.pub" ;;
  openbao-transit)
    [[ "${SIGNING_TRANSIT_KEY:-}" =~ ^[A-Za-z0-9._-]+$ ]] \
      || { echo "::error::SIGNING_KEY_SOURCE=openbao-transit needs SIGNING_TRANSIT_KEY, the transit key's name" >&2; exit 1; }
    [[ "${SIGNING_VAULT_ADDR:-}" =~ ^https?://[^[:space:]]+$ ]] \
      || { echo "::error::SIGNING_KEY_SOURCE=openbao-transit needs SIGNING_VAULT_ADDR, the OpenBao address" >&2; exit 1; }
    echo "VAULT_ADDR=$SIGNING_VAULT_ADDR"
    echo "COSIGN_KEY=hashivault://$SIGNING_TRANSIT_KEY"
    echo "SIGNING_PUBLIC_KEY=docs/contracts/keys/openbao-transit-cosign.pub"
    [ -z "${SIGNING_TRANSIT_PATH:-}" ] || echo "TRANSIT_SECRET_ENGINE_PATH=$SIGNING_TRANSIT_PATH" ;;
  *)
    echo "::error::SIGNING_KEY_SOURCE is '$source'; it must be interim, client or openbao-transit" >&2
    exit 1 ;;
esac
echo "SIGNING_KEY_SOURCE=$source"
