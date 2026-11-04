#!/usr/bin/env bash
# Cases for release-set.sh (plan: a complete set at the release version gives a manifest and notes that
# list every artefact with its digest, the same bytes for the same set; then each way a set can be short
# of the release - a chart at another version, a package missing from or not matching SHA256SUMS, an
# image without a digest, an image without its SBOM, an SBOM of another digest, no mock attestation, an
# repository SBOM without its signature file, no cucumber-JSON, a version that is not a release version - is refused).
# Nothing here needs a registry, a key or helm: the packages are tarballs of a Chart.yaml.
#
#   scripts/supplychain/release-set_test.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

failures=0
fail() { # name detail
  echo "FAIL  $1 ($2)"
  [ -s "$work/log" ] && sed 's/^/        /' "$work/log"
  failures=$((failures + 1))
}
check() { # name command...
  local name=$1
  shift
  if "$@" >"$work/log" 2>&1; then echo "ok    $name"; else fail "$name" "the check did not hold"; fi
}
refused() { # name reason command...   (refused, and for this reason: a failure for another is a failure)
  local name=$1 reason=$2
  shift 2
  if "$@" >"$work/log" 2>&1; then fail "$name" "accepted, want refused"
  elif grep -q -- "$reason" "$work/log"; then echo "ok    $name"
  else fail "$name" "refused, but not with '$reason'"; fi
}
sha() { sha256sum "$1" | cut -d' ' -f1; }

version=0.2.0
revision=0123456789abcdef0123456789abcdef01234567
digest_a="sha256:$(printf 'a%.0s' {1..64})"
digest_b="sha256:$(printf 'b%.0s' {1..64})"

package() { # dir name version   -> a package as helm would write it, name/Chart.yaml at that version
  local chart="$work/src/$2"
  mkdir -p "$chart"
  printf 'apiVersion: v2\nname: %s\nversion: %s\nappVersion: "%s"\n' "$2" "$3" "$3" > "$chart/Chart.yaml"
  tar -czf "$1/$2-$3.tgz" -C "$work/src" "$2/Chart.yaml"
}
sums() { (cd "$1" && sha256sum ./*.tgz | sed 's| \./| |' > SHA256SUMS); }
image_sbom() { # path repository digest   -> as Syft writes it for an image scanned by digest
  printf '{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"container","name":"%s","version":"%s"}},"components":[]}\n' "$2" "$3" > "$1"
}
repo_sbom() { # path   -> as Syft writes it for a directory
  printf '{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"file","name":"."}},"components":[]}\n' > "$1"
}
layout() { # dir   -> a complete set at the release version
  rm -rf "$1"
  mkdir -p "$1/images" "$1/charts" "$1/bdd"
  printf 'ghcr.io/example/ztd/admission-provider@%s\nghcr.io/example/ztd/orce@%s\n' "$digest_a" "$digest_b" > "$1/images.txt"
  image_sbom "$1/images/admission-provider.cdx.json" ghcr.io/example/ztd/admission-provider "$digest_a"
  image_sbom "$1/images/orce.cdx.json" ghcr.io/example/ztd/orce "$digest_b"
  echo '{"profile":"sw","mock":true}' > "$1/images/mock.json"
  package "$1/charts" ztd "$version"
  package "$1/charts" admission "$version"
  sums "$1/charts"
  repo_sbom "$1/sbom.json"
  echo "not-a-real-signature" > "$1/sbom.json.sig"
  echo '[{"name":"Supply chain","elements":[]}]' > "$1/bdd/go-report.json"
  echo '[]' > "$1/bdd/js-report.json"
  echo '| Row | Result |' > "$1/bdd/traceability.md"
  echo 'row,result' > "$1/bdd/traceability.csv"
}
run() { # set-dir out-dir [version]
  CREATED=2020-02-02T02:02:02Z "$here/release-set.sh" "${3:-$version}" "$revision" "$1" "$2"
}

echo "== A complete set"
layout "$work/set"
check "a complete set is accepted" run "$work/set" "$work/out"
manifest="$work/out/release-manifest.json"
notes="$work/out/RELEASE_NOTES.md"
check "the manifest is JSON at the release version and revision" \
  [ "$(jq -r '.version + " " + .tag + " " + .revision' "$manifest")" = "$version v$version $revision" ]
check "every image is listed by digest, tagged with the version" \
  [ "$(jq -r '.images[] | .reference' "$manifest" | sort | tr '\n' ' ')" = "ghcr.io/example/ztd/admission-provider:$version@$digest_a ghcr.io/example/ztd/orce:$version@$digest_b " ]
check "every chart is listed with the digest of its package" \
  [ "$(jq -r '.charts[] | select(.name == "ztd") | .sha256' "$manifest")" = "$(sha "$work/set/charts/ztd-$version.tgz")" ]
check "a chart not pushed to a registry says so" [ "$(jq -r '.charts[0].registry' "$manifest")" = null ]
# Every file under assets/ is in the manifest with its digest, and every digest in the manifest is right.
(cd "$work/out/assets" && sha256sum ./* | sed 's| \./| |' | sort -k2) > "$work/have"
jq -r '.assets[] | .sha256 + "  " + .name' "$manifest" | sort -k2 > "$work/want"
check "every asset is in the manifest with its digest" diff "$work/want" "$work/have"
for asset in ztd-$version.tgz admission-$version.tgz SHA256SUMS sbom.json sbom.json.sig mock-attestation.json \
  admission-provider.cdx.json orce.cdx.json bdd-go-report.json bdd-js-report.json bdd-traceability.md bdd-traceability.csv; do
  check "the set carries $asset" [ -s "$work/out/assets/$asset" ]
done
names_every() { # notes sums   -> every digest and every name of the sums file appears in the notes
  local sum name
  while read -r sum name; do
    grep -q -- "$sum" "$1" && grep -q -- "$name" "$1" || return 1
  done < "$2"
}
check "the notes name every asset and its digest" names_every "$notes" "$work/have"
check "the notes name the admission-provider image by digest" grep -q -- "$digest_a" "$notes"
check "the notes name the orce image by digest" grep -q -- "$digest_b" "$notes"

run "$work/set" "$work/out2" >/dev/null
check "the same set gives the same manifest bytes" [ "$(sha "$manifest")" = "$(sha "$work/out2/release-manifest.json")" ]

echo "== A chart pushed to a registry"
layout "$work/set"
echo "ztd-$version.tgz oci://registry.example/charts/ztd@$digest_a" > "$work/set/charts/pushed.txt"
run "$work/set" "$work/out" >/dev/null
check "a pushed chart is listed with its registry reference" \
  [ "$(jq -r '.charts[] | select(.name == "ztd") | .registry' "$manifest")" = "oci://registry.example/charts/ztd@$digest_a" ]
check "the notes name the registry reference" grep -q "oci://registry.example/charts/ztd@$digest_a" "$notes"
echo "ztd-$version.tgz oci://registry.example/charts/ztd:$version" > "$work/set/charts/pushed.txt"
refused "a registry reference without a digest is refused" "not an oci:// reference pinned by digest" run "$work/set" "$work/out"
echo "other-$version.tgz oci://registry.example/charts/other@$digest_a" > "$work/set/charts/pushed.txt"
refused "a pushed chart that is not in the set is refused" "not a package of this set" run "$work/set" "$work/out"

echo "== A prerelease"
layout "$work/pre"
rm "$work/pre"/charts/*
package "$work/pre/charts" ztd 0.2.0-rc.1
sums "$work/pre/charts"
check "a prerelease version is accepted" run "$work/pre" "$work/out" 0.2.0-rc.1
check "the prerelease tag carries the version" [ "$(jq -r .tag "$manifest")" = v0.2.0-rc.1 ]

echo "== What is refused"
layout "$work/set"
refused "a version with the leading v is refused" "not semantic versioning" run "$work/set" "$work/out" "v$version"
refused "a version that is not X.Y.Z is refused" "not semantic versioning" run "$work/set" "$work/out" 0.2
refused "a revision that is not a commit is refused" "not a commit SHA" \
  env CREATED=2020-02-02T02:02:02Z "$here/release-set.sh" "$version" main "$work/set" "$work/out"

layout "$work/set"
rm "$work/set/charts/admission-$version.tgz"
package "$work/set/charts" admission 0.1.0
sums "$work/set/charts"
refused "a chart packaged at another version is refused" "is not packaged at version $version" run "$work/set" "$work/out"

layout "$work/set"
rm "$work/set/charts/admission-$version.tgz"
mkdir -p "$work/src2/admission"
printf 'apiVersion: v2\nname: admission\nversion: 0.1.0\nappVersion: 0.1.0\n' > "$work/src2/admission/Chart.yaml"
tar -czf "$work/set/charts/admission-$version.tgz" -C "$work/src2" admission/Chart.yaml
sums "$work/set/charts"
refused "a package named at the version but holding another is refused" "chart version '0.1.0', want $version" run "$work/set" "$work/out"

layout "$work/set"
package "$work/set/charts" extra "$version"
refused "a package missing from SHA256SUMS is refused" "does not match charts/SHA256SUMS\|is not in charts/SHA256SUMS" run "$work/set" "$work/out"

layout "$work/set"
echo "tampered" >> "$work/set/charts/ztd-$version.tgz"
refused "a package that does not match SHA256SUMS is refused" "does not match charts/SHA256SUMS" run "$work/set" "$work/out"

layout "$work/set"
rm "$work/set/charts/SHA256SUMS"
refused "charts without SHA256SUMS are refused" "SHA256SUMS is missing" run "$work/set" "$work/out"

layout "$work/set"
echo "ghcr.io/example/ztd/admission-provider:$version" > "$work/set/images.txt"
refused "an image reference without a digest is refused" "not a digest reference" run "$work/set" "$work/out"

layout "$work/set"
: > "$work/set/images.txt"
refused "an empty image list is refused" "no image to release" run "$work/set" "$work/out"

layout "$work/set"
rm "$work/set/images/orce.cdx.json"
refused "an image without its SBOM is refused" "no SBOM for image orce" run "$work/set" "$work/out"

layout "$work/set"
image_sbom "$work/set/images/orce.cdx.json" ghcr.io/example/ztd/orce "$digest_a"
refused "an SBOM of the image at another digest is refused" "metadata.component does not name" run "$work/set" "$work/out"

layout "$work/set"
image_sbom "$work/set/images/orce.cdx.json" ghcr.io/example/ztd/other "$digest_b"
refused "an SBOM of another image is refused" "metadata.component does not name" run "$work/set" "$work/out"

layout "$work/set"
printf '{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"container","name":"ghcr.io/example/ztd/orce","version":"%s"}}}\n' "$digest_b" > "$work/set/images/orce.cdx.json"
refused "an image SBOM without a components array is refused" "lists no components" run "$work/set" "$work/out"

layout "$work/set"
echo '{"notCycloneDX":true}' > "$work/set/images/orce.cdx.json"
refused "an image SBOM that is not CycloneDX is refused" "is not CycloneDX" run "$work/set" "$work/out"

layout "$work/set"
rm "$work/set/images/mock.json"
refused "a set without the mock attestation is refused" "no mock attestation" run "$work/set" "$work/out"

layout "$work/set"
rm "$work/set/sbom.json.sig"
refused "a repository SBOM without its signature file is refused" "is not signed" run "$work/set" "$work/out"

layout "$work/set"
rm "$work/set/sbom.json"
refused "a set without the repository SBOM is refused" "no repository SBOM" run "$work/set" "$work/out"

layout "$work/set"
rm "$work/set"/bdd/*.json
refused "a set without cucumber-JSON is refused" "no cucumber-JSON" run "$work/set" "$work/out"

layout "$work/set"
echo '{"not":"an array"}' > "$work/set/bdd/go-report.json"
refused "a report that is not cucumber-JSON is refused" "is not cucumber-JSON" run "$work/set" "$work/out"

layout "$work/set"
rm "$work/set/bdd/traceability.md"
refused "reports without the traceability sheet are refused" "traceability.md is missing" run "$work/set" "$work/out"

[ "$failures" -eq 0 ] || { echo "$failures case(s) failed"; exit 1; }
echo "every case passed"
