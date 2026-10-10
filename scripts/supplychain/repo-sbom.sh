#!/usr/bin/env bash
# The repository SBOM a release carries: Syft's CycloneDX inventory of the Go module in <module dir>,
# checked by cmd/sbomcheck (valid CycloneDX, every module of the build and tests present at its selected
# version), signed with cosign in the signing profile of sign-attest.sh (key-based, no transparency log)
# and verified against the committed public key before it is handed back. Writes <out> and <out>.sig.
#
#   COSIGN_KEY=<key file or env://VAR> [COSIGN_PASSWORD=...] [SYFT=syft] [COSIGN=cosign] \
#     scripts/supplychain/repo-sbom.sh <module dir> <out.json>
set -euo pipefail

[ $# -eq 2 ] || { echo "usage: $0 <module dir> <out.json>" >&2; exit 2; }
# Absolute paths: the check runs from the repository root, wherever the caller stands.
dir="$(cd "$1" && pwd)"
out="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
: "${COSIGN_KEY:?set COSIGN_KEY}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
public="$root/docs/contracts/keys/interim-cosign.pub"
syft="${SYFT:-syft}" cosign="${COSIGN:-cosign}"

# Only the Go module: the repository SBOM describes what the Go build is made of. Images have their own.
"$syft" scan "dir:$dir" --override-default-catalogers go-module-file-cataloger -q -o "cyclonedx-json=$out"
(cd "$root" && go run ./cmd/sbomcheck -sbom "$out" -dir "$dir")

"$cosign" sign-blob --yes --key "$COSIGN_KEY" --tlog-upload=false --new-bundle-format=false \
  --output-signature "$out.sig" "$out" >/dev/null
"$cosign" verify-blob --key "$public" --insecure-ignore-tlog=true --signature "$out.sig" "$out" >/dev/null
echo "repo-sbom: $out signed and verified"
