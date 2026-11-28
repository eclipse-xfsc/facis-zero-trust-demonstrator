#!/usr/bin/env bash
# Publish a Rego policy bundle for the TSA policy service: pack the policy directory, sign it in the
# TSA's own format, push it as an OCI artefact and sign the artefact - both signatures with the one
# signing profile (cosign, key-based, no transparency log). Prints the digest reference, which a
# pull request then declares as the zone's active bundle (docs/tsa-policy.md).
#
#   COSIGN_KEY=<key file or env://VAR> [COSIGN_PASSWORD=...] [COSIGN=cosign] [TSA_BUNDLE=tsa-bundle] \
#     scripts/supplychain/publish-tsa-bundle.sh <policy-dir> <revision> <registry/repository> <public-key> [zone-data.json]
#
# OUT=<file> keeps a copy of the published bundle. COSIGN_ALLOW_HTTP_REGISTRY=true lets cosign reach a
# plain-http test registry (the kind proof only).
set -euo pipefail

[ $# -ge 4 ] && [ $# -le 5 ] || { echo "usage: $0 <policy-dir> <revision> <registry/repository> <public-key> [zone-data.json]" >&2; exit 2; }
dir="$1" revision="$2" repository="$3" public="$4" data="${5:-}"
case "$revision" in
  *[!A-Za-z0-9._-]* | "") echo "publish-tsa-bundle: revision must be [A-Za-z0-9._-]+ (it is also the OCI tag)" >&2; exit 2 ;;
esac
: "${COSIGN_KEY:?set COSIGN_KEY}"
cosign="${COSIGN:-cosign}"
tsa_bundle="${TSA_BUNDLE:-go run ./cmd/tsa-bundle}"
http=()
[ "${COSIGN_ALLOW_HTTP_REGISTRY:-}" = true ] && http=(--allow-http-registry)

# A revision names one bundle for good: decisions and audit records carry the revision, not the
# digest, so publishing another bundle under a revision that exists is refused.
if "$cosign" triangulate ${http[@]+"${http[@]}"} "$repository:$revision" >/dev/null 2>&1; then
  echo "publish-tsa-bundle: revision $revision is already published in $repository; use a new revision" >&2
  exit 1
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# shellcheck disable=SC2086 # TSA_BUNDLE may be a command with arguments
$tsa_bundle pack -src "$dir" ${data:+-data "$data"} -revision "$revision" -out "$work"
"$cosign" sign-blob --yes --key "$COSIGN_KEY" --tlog-upload=false --new-bundle-format=false \
  --output-signature "$work/signature.b64" "$work/signing-input.bin" >/dev/null
# shellcheck disable=SC2086
$tsa_bundle seal -in "$work" -signature "$work/signature.b64" -key "$public" -out "$work/bundle.zip"
ref="$("$cosign" upload blob ${http[@]+"${http[@]}"} -f "$work/bundle.zip" --ct application/vnd.facis.tsa.bundle.v1+zip \
  "$repository:$revision" 2>/dev/null | tail -1)"
case "$ref" in
  *@sha256:*) ;;
  *) echo "publish-tsa-bundle: upload printed no digest reference" >&2; exit 1 ;;
esac
[ -z "${OUT:-}" ] || cp "$work/bundle.zip" "$OUT"
"$cosign" sign --yes --key "$COSIGN_KEY" --tlog-upload=false --new-bundle-format=false ${http[@]+"${http[@]}"} "$ref" >/dev/null 2>&1
echo "$ref"
