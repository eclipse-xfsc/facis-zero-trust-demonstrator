#!/usr/bin/env bash
# Cases for verify-release.sh: a release whose every signature verifies passes; an unsigned image, an
# image without an attestation, an SBOM or manifest whose signature fails, a manifest naming another
# key, an asset the manifest does not list, an asset changed after signing and a listed asset missing
# from the upload set are each refused. cosign is a stub that fails for anything named in $STUB_UNSIGNED.
#
#   scripts/supplychain/verify-release_test.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0
run() { (cd "$work/repo" && env COSIGN="$work/cosign" SIGNING_PUBLIC_KEY=keys/k.pub "$@" "$here/verify-release.sh" rel); }
check() { local name=$1; shift; if run "$@" >"$work/log" 2>&1; then echo "ok    $name"; else echo "FAIL  $name"; sed 's/^/        /' "$work/log"; failures=$((failures + 1)); fi; }
refused() { # name reason env...
  local name=$1 reason=$2; shift 2
  if run "$@" >"$work/log" 2>&1; then echo "FAIL  $name (accepted)"; failures=$((failures + 1))
  elif grep -q -- "$reason" "$work/log"; then echo "ok    $name"
  else echo "FAIL  $name (refused, not with '$reason')"; sed 's/^/        /' "$work/log"; failures=$((failures + 1)); fi
}

cat > "$work/cosign" <<'STUB'
#!/usr/bin/env bash
# Fails when any argument, or the --type value, is listed in $STUB_UNSIGNED (space separated).
for arg in "$@"; do for bad in ${STUB_UNSIGNED:-}; do [ "$arg" = "$bad" ] && exit 1; [ "$arg" = "$(basename "$bad")" ] && exit 1; done; done
exit 0
STUB
chmod +x "$work/cosign"
mkdir -p "$work/repo/keys" "$work/repo/rel/assets"
echo key > "$work/repo/keys/k.pub"
echo other > "$work/repo/keys/other.pub"
a="ghcr.io/example/ztd/a@sha256:$(printf 'a%.0s' {1..64})"
for f in release-manifest.json.sig assets/sbom.json assets/sbom.json.sig; do echo "$f" > "$work/repo/rel/$f"; done
sha() { sha256sum "$1" | cut -d' ' -f1; }
jq -n --arg key keys/k.pub --arg digest "${a#*@}" \
  --arg s1 "$(sha "$work/repo/rel/assets/sbom.json")" --arg s2 "$(sha "$work/repo/rel/assets/sbom.json.sig")" \
  '{publicKey: $key, images: [{repository: "ghcr.io/example/ztd/a", digest: $digest}],
    assets: [{name: "sbom.json", sha256: $s1}, {name: "sbom.json.sig", sha256: $s2}]}' > "$work/repo/rel/release-manifest.json"

check "a release whose every signature verifies passes"
refused "an unsigned image is refused" "is not signed by" STUB_UNSIGNED="$a"
refused "an image without its SBOM attestation is refused" "https://cyclonedx.org/bom attestation" STUB_UNSIGNED=https://cyclonedx.org/bom
refused "an SBOM whose signature fails is refused" "sbom.json.sig does not verify" STUB_UNSIGNED=rel/assets/sbom.json.sig
refused "a manifest whose signature fails is refused" "release-manifest.json.sig does not verify" STUB_UNSIGNED=rel/release-manifest.json.sig
refused "a manifest naming another key is refused" "names another key" SIGNING_PUBLIC_KEY=keys/other.pub
echo extra > "$work/repo/rel/assets/unlisted.tgz"
refused "an asset the signed manifest does not list is refused" "unlisted.tgz is in the upload set but not in the signed manifest"
rm "$work/repo/rel/assets/unlisted.tgz"
cp "$work/repo/rel/assets/sbom.json" "$work/sbom.json"
echo changed >> "$work/repo/rel/assets/sbom.json"
refused "an asset changed after signing is refused" "sbom.json does not match its signed SHA-256"
cp "$work/sbom.json" "$work/repo/rel/assets/sbom.json"
rm "$work/repo/rel/assets/sbom.json.sig"
refused "a listed asset missing from the upload set is refused" "lists sbom.json.sig, which is not in the upload set"
[ "$failures" -eq 0 ] || { echo "$failures case(s) failed"; exit 1; }
