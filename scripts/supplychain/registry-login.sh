#!/usr/bin/env bash
# Log in to the image registry with the credentials of its kind - never another kind's: the job token
# only for GHCR, a Harbor robot account only for Harbor. Missing credentials fail before anything is
# sent. The workflow selects the values by kind (vars.HARBOR_HOST == '' && <GHCR value> || <Harbor
# secret>), so an empty Harbor secret stays empty instead of falling through to the job token.
#
#   REGISTRY_KIND=ghcr|harbor REGISTRY_HOST=... REGISTRY_USER=... REGISTRY_PASSWORD=... \
#     scripts/supplychain/registry-login.sh [docker config dir]
set -euo pipefail

case "${REGISTRY_KIND:-}" in
  ghcr) [ "${REGISTRY_HOST:-}" = ghcr.io ] || { echo "::error::a GHCR login must go to ghcr.io" >&2; exit 1; } ;;
  harbor) ;;
  *) echo "::error::REGISTRY_KIND must be ghcr or harbor" >&2; exit 1 ;;
esac
if [ -z "${REGISTRY_HOST:-}" ] || [ -z "${REGISTRY_USER:-}" ] || [ -z "${REGISTRY_PASSWORD:-}" ]; then
  echo "::error::the $REGISTRY_KIND registry credentials are missing (for Harbor: the HARBOR_PUSH_* or HARBOR_READ_* secrets) - nothing is sent" >&2
  exit 1
fi
config=()
[ $# -eq 0 ] || config=(--config "$1")
printf '%s' "$REGISTRY_PASSWORD" | "${DOCKER:-docker}" "${config[@]}" login "$REGISTRY_HOST" -u "$REGISTRY_USER" --password-stdin
