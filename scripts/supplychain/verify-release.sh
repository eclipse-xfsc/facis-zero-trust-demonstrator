#!/usr/bin/env bash
# The last gate before a release is published: every signature the release carries must verify against
# the committed public key of the selected source, or nothing is published. Checks, in <release dir>
# as release-set.sh wrote it and the release job signed it:
#
#   - release-manifest.json names that public key, and release-manifest.json.sig verifies;
#   - the upload set is exactly the signed list: every asset of the manifest is in assets/ with the
#     SHA-256 the manifest gives, and assets/ holds nothing the manifest does not list;
#   - assets/sbom.json.sig verifies for assets/sbom.json;
#   - every image of the manifest, by digest: the cosign signature and both attestations (the SBOM and
#     the mock attestation), read with VERIFY_DOCKER_CONFIG's credentials when it is set.
#
#   SIGNING_PUBLIC_KEY=docs/contracts/keys/<source>-cosign.pub [VERIFY_DOCKER_CONFIG=...] [COSIGN=cosign] \
#     scripts/supplychain/verify-release.sh <release dir>
set -euo pipefail

[ $# -eq 1 ] || { echo "usage: $0 <release dir>" >&2; exit 2; }
dir="$1"
public="${SIGNING_PUBLIC_KEY:-docs/contracts/keys/interim-cosign.pub}"
cosign="${COSIGN:-cosign}"
refuse() { echo "::error::verify-release: $* - the release is not published" >&2; exit 1; }
verify=()
[ -z "${VERIFY_DOCKER_CONFIG:-}" ] || verify=(env "DOCKER_CONFIG=$VERIFY_DOCKER_CONFIG")

manifest="$dir/release-manifest.json"
[ -s "$public" ] || refuse "no public key $public"
[ -s "$manifest" ] && [ -s "$manifest.sig" ] || refuse "the manifest or its signature is missing"
[ "$(jq -r '.publicKey // empty' "$manifest")" = "$public" ] || refuse "the manifest names another key than $public"
"$cosign" verify-blob --key "$public" --insecure-ignore-tlog=true --signature "$manifest.sig" "$manifest" >/dev/null 2>&1 \
  || refuse "release-manifest.json.sig does not verify"
# The upload set is the signed list, byte for byte, and nothing else.
while read -r name sha; do
  [ -f "$dir/assets/$name" ] || refuse "the manifest lists $name, which is not in the upload set"
  [ "$(sha256sum "$dir/assets/$name" | cut -d' ' -f1)" = "$sha" ] || refuse "$name does not match its signed SHA-256"
done < <(jq -r '.assets[] | .name + " " + .sha256' "$manifest")
while read -r name; do
  jq -e --arg name "$name" 'any(.assets[]; .name == $name)' "$manifest" >/dev/null || refuse "$name is in the upload set but not in the signed manifest"
done < <(cd "$dir/assets" && find . -mindepth 1 -maxdepth 1 | sed 's|^\./||')
[ -s "$dir/assets/sbom.json" ] && [ -s "$dir/assets/sbom.json.sig" ] || refuse "the repository SBOM or its signature is missing"
"$cosign" verify-blob --key "$public" --insecure-ignore-tlog=true --signature "$dir/assets/sbom.json.sig" "$dir/assets/sbom.json" >/dev/null 2>&1 \
  || refuse "sbom.json.sig does not verify"

mapfile -t images < <(jq -r '.images[] | .repository + "@" + .digest' "$manifest")
[ ${#images[@]} -gt 0 ] || refuse "the manifest lists no image"
for image in "${images[@]}"; do
  "${verify[@]}" "$cosign" verify --key "$public" --insecure-ignore-tlog=true "$image" >/dev/null 2>&1 \
    || refuse "$image is not signed by $public"
  for type in https://cyclonedx.org/bom https://facis.eu/ztd/mock-attestation/v1; do
    "${verify[@]}" "$cosign" verify-attestation --key "$public" --insecure-ignore-tlog=true --type "$type" "$image" >/dev/null 2>&1 \
      || refuse "$image has no $type attestation signed by $public"
  done
done
echo "verify-release: the manifest, the repository SBOM and ${#images[@]} image(s) verify against $public"
