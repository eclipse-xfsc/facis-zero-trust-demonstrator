# shellcheck shell=bash disable=SC2154,SC2034 # inputs are set and outputs read by the sourcing script
# The admission test images, shared by the kind job (kind-e2e.sh) and the fork's fixtures workflow
# (publish-fixtures.sh). Sourced, not run.
#
# fixtures_build <path> pushes, over the distribution API of a plain-http registry, one image per case
# and sets img_<case> to its digest reference:
#   app       the pinned runnable linux/amd64 base (TEST_BASE_IMAGE), to be signed and attested
#   unsigned  the same image, never signed
#   wrongkey  the same image, to be signed by an untrusted key
#   nosbom    the same image, signed with only the mock attestation
#   nomock    the same image, signed with only the SBOM attestation
#   windows   an image whose configuration declares os windows, signed and attested
#   index     an image index over the base, signed and attested
# Needs: host_reg (the registry from this machine, host:port), reg (the registry name the references
# use), work (a scratch directory), TEST_BASE_IMAGE.
#
# fixtures_sign_script writes the commands that sign and attest them, for a shell that defines
# sign_attest <image> <sbom> <mock> (the release script), app_sbom <image> <out> (the SBOM of the
# runnable image) and the array flags (extra cosign flags), and has TRUSTED_KEY and OTHER_KEY set.

fixtures_sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

fixtures_put_blob() { # repository file
  local location sep
  location=$(curl -fsS -X POST -D - -o /dev/null "http://$host_reg/v2/$1/blobs/uploads/" | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
  case "$location" in http*) ;; *) location="http://$host_reg$location" ;; esac
  sep='?'; case "$location" in *\?*) sep='&' ;; esac
  curl -fsS -X PUT -H 'Content-Type: application/octet-stream' --data-binary @"$2" "$location${sep}digest=sha256:$(fixtures_sha "$2")" >/dev/null
}

fixtures_put_manifest() { # repository file media-type -> digest reference
  curl -fsS -X PUT -H "Content-Type: $3" --data-binary @"$2" "http://$host_reg/v2/$1/manifests/sha256:$(fixtures_sha "$2")" >/dev/null
  echo "$reg/$1@sha256:$(fixtures_sha "$2")"
}

fixtures_build() { # path
  local path="$1" base_repo base_digest base_type hub_token d layer
  local docker_manifest=application/vnd.docker.distribution.manifest.v2+json oci_manifest=application/vnd.oci.image.manifest.v1+json
  # The runnable image: the pinned linux/amd64 base, copied by digest from Docker Hub (anonymous pull).
  base_repo="${TEST_BASE_IMAGE#docker.io/}"; base_repo="${base_repo%%:*}"
  base_digest="${TEST_BASE_IMAGE#*@}"
  hub_token=$(curl -fsS "https://auth.docker.io/token?service=registry.docker.io&scope=repository:$base_repo:pull" | jq -r .token)
  curl -fsSL -H "Authorization: Bearer $hub_token" -H "Accept: $docker_manifest, $oci_manifest" -o "$work/base.manifest" \
    "https://registry-1.docker.io/v2/$base_repo/manifests/$base_digest"
  [ "sha256:$(fixtures_sha "$work/base.manifest")" = "$base_digest" ] || { echo "base manifest digest mismatch" >&2; return 1; }
  base_type=$(jq -r .mediaType "$work/base.manifest")
  for d in $(jq -r '.config.digest, .layers[].digest' "$work/base.manifest"); do
    curl -fsSL -H "Authorization: Bearer $hub_token" -o "$work/${d#sha256:}" "https://registry-1.docker.io/v2/$base_repo/blobs/$d"
    [ "$(fixtures_sha "$work/${d#sha256:}")" = "${d#sha256:}" ] || { echo "blob $d digest mismatch" >&2; return 1; }
  done
  push_base() { # repository -> digest reference
    local b
    for b in $(jq -r '.config.digest, .layers[].digest' "$work/base.manifest"); do fixtures_put_blob "$1" "$work/${b#sha256:}"; done
    fixtures_put_manifest "$1" "$work/base.manifest" "$base_type"
  }
  img_app=$(push_base "$path/app")
  img_unsigned=$(push_base "$path/unsigned")
  img_wrongkey=$(push_base "$path/wrongkey")
  img_nosbom=$(push_base "$path/nosbom")
  img_nomock=$(push_base "$path/nomock")

  # A Windows image (never run; it must be refused before that) and an image index.
  printf '{"architecture":"amd64","os":"windows","rootfs":{"type":"layers","diff_ids":[]}}' > "$work/windows.config"
  layer=$(jq -r '.layers[0].digest' "$work/base.manifest")
  fixtures_put_blob "$path/windows" "$work/windows.config"
  fixtures_put_blob "$path/windows" "$work/${layer#sha256:}"
  jq -n --arg c "sha256:$(fixtures_sha "$work/windows.config")" --argjson cs "$(wc -c < "$work/windows.config")" --argjson l "$(jq '.layers[0]' "$work/base.manifest")" \
    '{schemaVersion: 2, mediaType: "application/vnd.oci.image.manifest.v1+json", config: {mediaType: "application/vnd.oci.image.config.v1+json", digest: $c, size: $cs}, layers: [$l]}' > "$work/windows.manifest"
  img_windows=$(fixtures_put_manifest "$path/windows" "$work/windows.manifest" "$oci_manifest")
  push_base "$path/index" >/dev/null
  jq -n --arg d "$base_digest" --argjson s "$(wc -c < "$work/base.manifest")" --arg t "$base_type" \
    '{schemaVersion: 2, mediaType: "application/vnd.oci.image.index.v1+json", manifests: [{mediaType: $t, digest: $d, size: $s, platform: {os: "linux", architecture: "amd64"}}]}' > "$work/index.manifest"
  img_index=$(fixtures_put_manifest "$path/index" "$work/index.manifest" application/vnd.oci.image.index.v1+json)
}

# The fixture names, in a stable order.
fixtures_names="app unsigned wrongkey nosbom nomock windows index"

fixtures_sign_script() {
  local k v
  # An SBOM naming the image, as Syft writes it for an image scanned by digest.
  # shellcheck disable=SC2016 # written for the signing shell, expanded there
  echo 'sbom() { printf '"'"'{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"container","name":"%s","version":"%s"}},"components":[]}'"'"' "${1%@*}" "${1#*@}" > "$2"; }'
  echo "app_sbom '${img_app}' app.cdx.json"
  echo "COSIGN_KEY=\"\$TRUSTED_KEY\" sign_attest '${img_app}' app.cdx.json mock.json"
  for k in wrongkey windows index nomock; do
    v="img_$k"; echo "sbom '${!v}' $k.cdx.json"
  done
  echo "COSIGN_KEY=\"\$OTHER_KEY\" sign_attest '${img_wrongkey}' wrongkey.cdx.json mock.json"
  echo "COSIGN_KEY=\"\$TRUSTED_KEY\" sign_attest '${img_windows}' windows.cdx.json mock.json"
  echo "COSIGN_KEY=\"\$TRUSTED_KEY\" sign_attest '${img_index}' index.cdx.json mock.json"
  echo "\"\$COSIGN\" sign \${flags[@]+\"\${flags[@]}\"} --yes --tlog-upload=false --new-bundle-format=false --key \"\$TRUSTED_KEY\" '${img_nosbom}'"
  echo "\"\$COSIGN\" attest \${flags[@]+\"\${flags[@]}\"} --yes --tlog-upload=false --new-bundle-format=false --key \"\$TRUSTED_KEY\" --type https://facis.eu/ztd/mock-attestation/v1 --predicate mock.json '${img_nosbom}'"
  echo "\"\$COSIGN\" sign \${flags[@]+\"\${flags[@]}\"} --yes --tlog-upload=false --new-bundle-format=false --key \"\$TRUSTED_KEY\" '${img_nomock}'"
  echo "\"\$COSIGN\" attest \${flags[@]+\"\${flags[@]}\"} --yes --tlog-upload=false --new-bundle-format=false --key \"\$TRUSTED_KEY\" --type https://cyclonedx.org/bom --predicate nomock.cdx.json '${img_nomock}'"
}
