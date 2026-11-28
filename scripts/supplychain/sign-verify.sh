#!/usr/bin/env bash
# Sign and attest every image digest listed in <images.txt> - the Grype-enriched Syft SBOM and the mock
# attestation, with sign-attest.sh - then verify each digest against the committed public key, with the
# admission provider's own code (cmd/imageverify) and with cosign. Any failure fails the run; a missing
# key fails it before anything is signed.
#
#   COSIGN_KEY=<key or env://VAR> COSIGN_PASSWORD=... \
#     scripts/supplychain/sign-verify.sh <registry/path> <images.txt> <out-dir>
#
# The public key is the selected source's (SIGNING_PUBLIC_KEY, from key-source.sh), the interim key's
# by default; PUBLIC_KEY overrides both (tests only). IMAGEVERIFY_FLAGS and
# COSIGN_VERIFY_FLAGS pass registry options for a local test registry. VERIFY_DOCKER_CONFIG names a
# Docker config directory holding read-only credentials: the cosign checks then read the registry with
# those, not with the push credentials that signed.
set -euo pipefail

[ $# -eq 3 ] || { echo "usage: $0 <registry/path> <images.txt> <out-dir>" >&2; exit 2; }
repository="$1" list="$2" out="$3"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
public="${PUBLIC_KEY:-${SIGNING_PUBLIC_KEY:-docs/contracts/keys/interim-cosign.pub}}"
cosign="${COSIGN:-cosign}"
[ -n "${COSIGN_KEY:-}" ] || { echo "sign-verify: COSIGN_KEY is not set - refusing to publish unsigned images" >&2; exit 1; }
[ -s "$public" ] || { echo "sign-verify: public key $public is missing - nothing could verify the signatures" >&2; exit 1; }
mapfile -t images < "$list"
[ ${#images[@]} -gt 0 ] || { echo "sign-verify: no images in $list" >&2; exit 1; }

mkdir -p "$out"
go run ./cmd/mockattest -profile sw > "$out/mock.json"
for image in "${images[@]}"; do
  name="${image%@*}"; name="${name##*/}"
  "$here/sbom.sh" "$image" "$out/$name.cdx.json"
  "$here/sign-attest.sh" "$image" "$out/$name.cdx.json" "$out/mock.json"
done

verify=()
[ -z "${VERIFY_DOCKER_CONFIG:-}" ] || verify=(env "DOCKER_CONFIG=$VERIFY_DOCKER_CONFIG")
# shellcheck disable=SC2086 # the flags are word lists on purpose
go run ./cmd/imageverify -key "$public" -repository "$repository" ${IMAGEVERIFY_FLAGS:-} "${images[@]}"
for image in "${images[@]}"; do
  # shellcheck disable=SC2086
  "${verify[@]}" "$cosign" verify --key "$public" --insecure-ignore-tlog=true ${COSIGN_VERIFY_FLAGS:-} "$image" >/dev/null
  for type in https://cyclonedx.org/bom https://facis.eu/ztd/mock-attestation/v1; do
    # shellcheck disable=SC2086
    "${verify[@]}" "$cosign" verify-attestation --key "$public" --insecure-ignore-tlog=true --type "$type" ${COSIGN_VERIFY_FLAGS:-} "$image" >/dev/null
  done
  echo "cosign verified $image"
done
