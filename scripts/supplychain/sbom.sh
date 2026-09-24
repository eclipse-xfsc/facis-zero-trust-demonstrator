#!/usr/bin/env bash
# The SBOM that is signed with an image: the Syft inventory of the image, scanned by digest, enriched by
# Grype with the known vulnerabilities (CycloneDX JSON carrying a vulnerabilities array). Scanning by
# digest makes metadata.component the image's registry/repository at that digest, which admission
# checks. Used by the release workflow.
#
#   [SYFT=syft] [GRYPE=grype] scripts/supplychain/sbom.sh <registry/repository@sha256:...> <out.cdx.json>
set -euo pipefail

[ $# -eq 2 ] || { echo "usage: $0 <image@sha256:digest> <out.cdx.json>" >&2; exit 2; }
image="$1" out="$2"
case "$image" in
  *@sha256:*) ;;
  *) echo "sbom: $image is not a digest reference" >&2; exit 2 ;;
esac
syft="${SYFT:-syft}" grype="${GRYPE:-grype}"
inventory="$(mktemp)"
trap 'rm -f "$inventory"' EXIT

"$syft" "registry:$image" -q -o "cyclonedx-json=$inventory"
"$grype" "sbom:$inventory" -q -o cyclonedx-json --file "$out"
