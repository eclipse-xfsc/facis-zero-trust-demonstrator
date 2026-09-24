#!/usr/bin/env bash
# Build every image under deployment/docker/ for linux/amd64, labelled as signed with the interim key,
# push it to <registry/path>/<name>:<tag>, and append its digest reference to <images.txt>. The release
# candidate job runs this, then sign-verify.sh on the digests.
#
#   scripts/supplychain/build-push.sh <registry/path> <tag> <images.txt>
set -euo pipefail

[ $# -eq 3 ] || { echo "usage: $0 <registry/path> <tag> <images.txt>" >&2; exit 2; }
repository="$1" tag="$2" list="$3"
revision="${GITHUB_SHA:-$(git rev-parse HEAD)}"
: > "$list"
for dockerfile in deployment/docker/*/Dockerfile; do
  name="$(basename "$(dirname "$dockerfile")")"
  ref="$repository/$name:$tag"
  docker build --platform linux/amd64 --provenance=false --sbom=false \
    --label eu.facis.ztd.signing-key=interim --label "org.opencontainers.image.revision=$revision" \
    -f "$dockerfile" -t "$ref" .
  docker push -q "$ref" >/dev/null
  digest="$(docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$ref" | grep -m1 "^$repository/$name@sha256:")"
  echo "$digest" >> "$list"
  echo "pushed $digest"
done
