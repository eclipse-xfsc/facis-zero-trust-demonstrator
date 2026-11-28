#!/usr/bin/env bash
# The registry the images are pushed to and verified from, for $GITHUB_OUTPUT: this repository's GHCR
# namespace by default, or a Harbor project once the repository variables HARBOR_HOST and HARBOR_PROJECT
# name one. Prints kind=ghcr|harbor, host=<registry host> and path=<registry/path> for the images.
#
#   [HARBOR_HOST=harbor.example.org HARBOR_PROJECT=facis-ztd] GITHUB_REPOSITORY=owner/repo \
#     scripts/supplychain/registry.sh
set -euo pipefail

if [ -z "${HARBOR_HOST:-}" ]; then
  : "${GITHUB_REPOSITORY:?set GITHUB_REPOSITORY}"
  # GHCR names are lower case; the repository owner may not be.
  printf 'kind=ghcr\nhost=ghcr.io\npath=ghcr.io/%s\n' "${GITHUB_REPOSITORY,,}"
  exit 0
fi
[[ "$HARBOR_HOST" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]+)?$ ]] \
  || { echo "::error::HARBOR_HOST '$HARBOR_HOST' is not a registry host (lower case, optional :port, no scheme)" >&2; exit 1; }
[[ "${HARBOR_PROJECT:-}" =~ ^[a-z0-9]([a-z0-9._/-]*[a-z0-9])?$ ]] \
  || { echo "::error::HARBOR_HOST is set, so HARBOR_PROJECT must name the Harbor project (lower case)" >&2; exit 1; }
printf 'kind=harbor\nhost=%s\npath=%s/%s\n' "$HARBOR_HOST" "$HARBOR_HOST" "$HARBOR_PROJECT"
