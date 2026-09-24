#!/usr/bin/env bash
# Publish the admission test images (fixtures-lib.sh) under <registry/path>/fixtures/<case> for a real
# cluster to pull, signed as each case needs: the interim key (COSIGN_KEY), an ephemeral untrusted key,
# or not at all. Each is then checked with the admission provider's own code against the committed
# public key, and its expected verdict is required. Writes "<case> <digest reference>" lines to <list>.
# Run by the admission-fixtures workflow on the fork.
#
#   COSIGN_KEY=env://COSIGN_INTERIM_KEY COSIGN_PASSWORD=... [IMAGEVERIFY_FLAGS=...] \
#     scripts/admission/publish-fixtures.sh <registry/path> <list>
#
# PUBLIC_KEY overrides the committed interim public key (local tests with an ephemeral key only);
# FIXTURES_REGISTRY_PORT moves the scratch registry off port 5000.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env
# shellcheck source=scripts/admission/fixtures-lib.sh disable=SC1091
. scripts/admission/fixtures-lib.sh
[ $# -eq 2 ] || { echo "usage: $0 <registry/path> <list>" >&2; exit 2; }
prefix="$1" list="$2"
: "${COSIGN_KEY:?set COSIGN_KEY}"
COSIGN="${COSIGN:-cosign}"
export COSIGN

work="$(mktemp -d)"
registry=ztd-fixtures-registry
port="${FIXTURES_REGISTRY_PORT:-5000}"
trap 'docker rm -f "$registry" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
docker run -d --name "$registry" -p "127.0.0.1:$port:5000" "$REGISTRY_IMAGE" >/dev/null
for _ in $(seq 30); do curl -fs "http://127.0.0.1:$port/v2/" >/dev/null && break; sleep 1; done

# Build locally, then copy each image by digest into the published path.
host_reg="127.0.0.1:$port" reg="localhost:$port"
fixtures_build fixtures
for k in $fixtures_names; do
  v="img_$k"; src="${!v}"; dst="$prefix/fixtures/$k"
  "$COSIGN" copy --force --allow-http-registry "$src" "$dst:fixture" >/dev/null
  printf -v "img_$k" '%s' "$dst@${src#*@}"
done

# Sign and attest as each case needs.
go run ./cmd/mockattest -profile sw > "$work/mock.json"
(cd "$work" && mkdir -p other && cd other && "$COSIGN" generate-key-pair >/dev/null 2>&1)
TRUSTED_KEY="$COSIGN_KEY" OTHER_KEY="$work/other/cosign.key"
export TRUSTED_KEY OTHER_KEY
# shellcheck disable=SC2034 # read by the generated signing script
flags=()
sign_attest() { "$root/scripts/supplychain/sign-attest.sh" "$@"; }
app_sbom() { "$root/scripts/supplychain/sbom.sh" "$1" "$2"; }
fixtures_sign_script > "$work/sign.sh"
# shellcheck disable=SC1091 # generated above
(cd "$work" && . ./sign.sh)

# Every fixture must get its expected verdict from the provider's code.
failures=0
: > "$list"
for k in $fixtures_names; do
  v="img_$k"; image="${!v}"
  case "$k" in
    app) want=verified ;; unsigned|wrongkey) want=ADM-UNSIGNED ;; nosbom) want=ADM-SBOM-MISSING ;;
    nomock) want=ADM-NO-ATTESTATION ;; windows) want=ADM-NOT-LINUX ;; index) want=ADM-INDEX-UNSUPPORTED ;;
  esac
  # shellcheck disable=SC2086 # the flags are a word list on purpose
  out="$(go run ./cmd/imageverify -key "${PUBLIC_KEY:-docs/contracts/keys/interim-cosign.pub}" -repository "$prefix" ${IMAGEVERIFY_FLAGS:-} "$image" || true)"
  if grep -q -- "$want" <<<"$out"; then
    echo "ok    $k $want"
  else
    echo "FAIL  $k: expected $want, got: $out"; failures=$((failures + 1))
  fi
  echo "$k $image" >> "$list"
done
[ "$failures" -eq 0 ] || exit 1
