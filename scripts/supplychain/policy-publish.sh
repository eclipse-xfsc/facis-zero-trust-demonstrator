#!/usr/bin/env bash
# Publish a policy package (policy-package.sh): push the tarball as one OCI artefact - a single layer of
# the media type Argo CD reads from an oci:// source, with the annotations that tie it to the commit it
# came from - then sign the manifest by digest with the release signing profile (cosign v2 classic
# layout, key-based, no transparency log: the profile of sign-attest.sh) and verify the signature
# against the committed public key. The last line printed is the digest reference, the one thing a
# consumer pins: the tag is where to look, the digest is what was signed.
#
#   COSIGN_KEY=<key file or env://VAR> [COSIGN_PASSWORD=...] [PUBLIC_KEY=docs/contracts/keys/interim-cosign.pub] \
#   [REGISTRY_USER=... REGISTRY_PASSWORD=...] [SOURCE_URL=<repository url>] [CREATED=<RFC 3339>] \
#   [ORAS=oras] [COSIGN=cosign] \
#     scripts/supplychain/policy-publish.sh <package.tar.gz> <registry/repository> <version> <revision>
#
# REGISTRY_USER and REGISTRY_PASSWORD are the registry credential (a robot account). They are written
# to a Docker config private to this run, which oras and cosign both read, rather than given to
# `docker login`: a login first asks the registry for a token with no scope, and a registry that grants
# a robot account its repositories by scope can refuse that request while refusing nothing the push
# needs. Without them the tools read the ambient Docker config.
#
# CREATED pins the created annotation (oras writes the time of the push otherwise), so a package
# published twice from the same files has the same manifest digest. PLAIN_HTTP=true lets oras and
# cosign reach a plain-http test registry by name (the CI cases); a release never sets it.
set -euo pipefail

[ $# -eq 4 ] || { echo "usage: $0 <package.tar.gz> <registry/repository> <version> <revision>" >&2; exit 2; }
package="$1" repository="$2" version="$3" revision="$4"
: "${COSIGN_KEY:?set COSIGN_KEY}"
public="${PUBLIC_KEY:-docs/contracts/keys/interim-cosign.pub}"
[ -s "$package" ] || { echo "policy-publish: $package is missing or empty" >&2; exit 1; }
[ -s "$public" ] || { echo "policy-publish: public key $public is missing - nothing could verify the signature" >&2; exit 1; }
oras="${ORAS:-oras}" cosign="${COSIGN:-cosign}"

if [ -n "${REGISTRY_USER:-}" ]; then
  : "${REGISTRY_PASSWORD:?set REGISTRY_PASSWORD with REGISTRY_USER}"
  config="$(mktemp -d)"
  trap 'rm -rf "$config"' EXIT
  (umask 077 && printf '{"auths":{"%s":{"auth":"%s"}}}\n' "${repository%%/*}" \
    "$(printf '%s:%s' "$REGISTRY_USER" "$REGISTRY_PASSWORD" | base64 -w0)" > "$config/config.json")
  export DOCKER_CONFIG="$config"
fi

layer_type=application/vnd.oci.image.layer.v1.tar+gzip
push=(--no-tty --format 'go-template={{.digest}}' --artifact-type application/vnd.facis.ztd.policy.v1
  -a "org.opencontainers.image.title=$(basename "$repository")"
  -a "org.opencontainers.image.version=$version"
  -a "org.opencontainers.image.revision=$revision"
  -a "org.opencontainers.image.source=${SOURCE_URL:-https://github.com/eclipse-xfsc/facis-zero-trust-demonstrator}"
  -a "org.opencontainers.image.description=Gatekeeper admission policy of the FACIS zero trust demonstrator, as one tar.gz layer")
[ -n "${CREATED:-}" ] && push+=(-a "org.opencontainers.image.created=$CREATED")
[ -n "${DOCKER_CONFIG:-}" ] && push+=(--registry-config "$DOCKER_CONFIG/config.json")
sign=(--yes --key "$COSIGN_KEY" --tlog-upload=false --new-bundle-format=false)
verify=(--key "$public" --insecure-ignore-tlog=true)
if [ "${PLAIN_HTTP:-}" = true ]; then
  push+=(--plain-http); sign+=(--allow-http-registry); verify+=(--allow-http-registry)
fi

# oras records the file's path as the layer's title and refuses one that leaves the working directory,
# so the push runs from the package's own directory.
digest="$(cd "$(dirname "$package")" && "$oras" push "${push[@]}" "$repository:$version" "$(basename "$package"):$layer_type")"
case "$digest" in
  sha256:*) ;;
  *) echo "policy-publish: oras did not return a digest: $digest" >&2; exit 1 ;;
esac
echo "pushed $repository:$version"
"$cosign" sign "${sign[@]}" "$repository@$digest"
"$cosign" verify "${verify[@]}" "$repository@$digest" >/dev/null
echo "signed and verified against $public"
echo "$repository@$digest"
