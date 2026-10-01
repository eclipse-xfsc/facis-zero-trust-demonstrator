#!/usr/bin/env bash
# Sign an image by digest and attach its two attestations - the one signing profile, used by the
# release workflow and by the CI interop test alike: cosign v2 classic layout, key-based, no
# transparency log, in-toto Statement v0.1.
#
#   COSIGN_KEY=<key file or env://VAR> [COSIGN_PASSWORD=...] [COSIGN=cosign] \
#     scripts/supplychain/sign-attest.sh <registry/repository@sha256:...> <sbom.cdx.json> <mock-attestation.json>
#
# COSIGN_ALLOW_HTTP_REGISTRY=true lets cosign reach a plain-http test registry by name (the kind
# admission job); the release never sets it.
set -euo pipefail

[ $# -eq 3 ] || { echo "usage: $0 <image@sha256:digest> <sbom.json> <mock-attestation.json>" >&2; exit 2; }
image="$1" sbom="$2" mock="$3"
case "$image" in
  *@sha256:*) ;;
  *) echo "sign-attest: $image is not a digest reference" >&2; exit 2 ;;
esac
: "${COSIGN_KEY:?set COSIGN_KEY}"
cosign="${COSIGN:-cosign}"
common=(--yes --key "$COSIGN_KEY" --tlog-upload=false --new-bundle-format=false)
[ "${COSIGN_ALLOW_HTTP_REGISTRY:-}" = true ] && common+=(--allow-http-registry)

"$cosign" sign "${common[@]}" "$image"
"$cosign" attest "${common[@]}" --type https://cyclonedx.org/bom --predicate "$sbom" "$image"
"$cosign" attest "${common[@]}" --type https://facis.eu/ztd/mock-attestation/v1 --predicate "$mock" "$image"
