#!/usr/bin/env bash
# The release artefact set: the manifest and the release notes that list every artefact of one release
# with its digest - the images signed by digest, the charts packaged at the release version, the
# repository SBOM and its signature, the SBOM of each image, the mock attestation and the cucumber-JSON
# of the BDD runs - once each of them is present and carries the release version. The release job
# assembles the set from what the run produced, runs this, and creates the GitHub release from the
# output; a set with a piece missing or at another version is refused, so a release that does not
# carry everything is never created.
#
#   [CREATED=<RFC 3339>] scripts/supplychain/release-set.sh <version> <revision> <set dir> <out dir>
#
# <set dir>, laid out by the caller:
#   images.txt                   one <repository>/<name>@sha256:<digest> per line (build-push.sh)
#   images/<name>.cdx.json       the SBOM each image was attested with (sbom.sh)
#   images/mock.json             the mock attestation each image was attested with (cmd/mockattest)
#   charts/<name>-<version>.tgz  the release charts with their SHA256SUMS (check-charts.sh --package)
#   charts/pushed.txt            optional: one "<file> <oci://...@sha256:...>" per chart pushed to a registry
#   sbom.json, sbom.json.sig     the repository SBOM and its signature (repo-sbom.sh)
#   bdd/*.json                   the cucumber-JSON of every BDD run, with traceability.md and traceability.csv
#
# <out dir> receives release-manifest.json, RELEASE_NOTES.md and assets/: every file the release
# carries, flat, as GitHub release assets are. The same set and CREATED give the same manifest bytes,
# so a manifest can be checked by rebuilding it.
set -euo pipefail

[ $# -eq 4 ] || { echo "usage: $0 <version> <revision> <set dir> <out dir>" >&2; exit 2; }
version="$1" revision="$2" dir="$3" out="$4"
created="${CREATED:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
public_key=docs/contracts/keys/interim-cosign.pub

refuse() { echo "release-set: $*" >&2; exit 1; }
sha() { sha256sum "$1" | cut -d' ' -f1; }
cyclonedx() { # path   -> refuses a file that is not a CycloneDX document
  jq -e . "$1" >/dev/null 2>&1 || refuse "$1 is not JSON"
  [ "$(jq -r '.bomFormat // empty' "$1")" = CycloneDX ] || refuse "$1 is not CycloneDX"
}

# The SemVer 2.0.0 grammar without build metadata, the one check-charts.sh holds the chart version to.
identifier='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
semver="^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-$identifier(\.$identifier)*)?$"
[[ "$version" =~ $semver ]] || refuse "version '$version' is not semantic versioning (X.Y.Z[-prerelease], without the leading v)"
[[ "$revision" =~ ^[0-9a-f]{40}$ ]] || refuse "revision '$revision' is not a commit SHA"
[ -d "$dir" ] || refuse "no set directory $dir"

assets="$out/assets"
rm -rf "$assets"
mkdir -p "$assets"

# The images: every reference is a digest, and every image has the SBOM that was attested to it,
# bound to the image the way admission binds it (internal/cosignverify, validateSBOM): its
# metadata.component is the container "registry/repository" at this digest, and it lists components.
[ -s "$dir/images.txt" ] || refuse "images.txt is missing or empty: no image to release"
images=()
while read -r ref; do
  [ -n "$ref" ] || continue
  [[ "$ref" =~ ^([^@[:space:]]+)@(sha256:[0-9a-f]{64})$ ]] || refuse "image '$ref' is not a digest reference"
  repository="${BASH_REMATCH[1]}" digest="${BASH_REMATCH[2]}"
  name="${repository##*/}"
  sbom="$dir/images/$name.cdx.json"
  [ -s "$sbom" ] || refuse "no SBOM for image $name (images/$name.cdx.json)"
  cyclonedx "$sbom"
  jq -e --arg name "$repository" --arg digest "$digest" \
    '.metadata.component | .type == "container" and .name == $name and .version == $digest' "$sbom" >/dev/null 2>&1 \
    || refuse "images/$name.cdx.json: metadata.component does not name $ref"
  jq -e '.components | type == "array"' "$sbom" >/dev/null 2>&1 || refuse "images/$name.cdx.json lists no components"
  cp "$sbom" "$assets/$name.cdx.json"
  images+=("$(jq -cn --arg name "$name" --arg repository "$repository" --arg tag "$version" --arg digest "$digest" \
    --arg sbom "$name.cdx.json" --arg sha "$(sha "$sbom")" \
    '{name: $name, repository: $repository, tag: $tag, digest: $digest,
      reference: ($repository + ":" + $tag + "@" + $digest), sbom: $sbom, sbomSha256: $sha}')")
done < "$dir/images.txt"
[ ${#images[@]} -gt 0 ] || refuse "images.txt names no image"

mock="$dir/images/mock.json"
[ -s "$mock" ] || refuse "no mock attestation (images/mock.json)"
jq -e 'type == "object"' "$mock" >/dev/null 2>&1 || refuse "images/mock.json is not a JSON document"
cp "$mock" "$assets/mock-attestation.json"

# The charts: packaged by check-charts.sh at the release version, every package in SHA256SUMS and
# matching it, and every package's Chart.yaml at that version and appVersion.
charts_dir="$dir/charts"
[ -s "$charts_dir/SHA256SUMS" ] || refuse "charts/SHA256SUMS is missing: the charts were not packaged by check-charts.sh"
shopt -s nullglob
packages=("$charts_dir"/*.tgz)
shopt -u nullglob
[ ${#packages[@]} -gt 0 ] || refuse "no chart package under charts/"
(cd "$charts_dir" && sha256sum -c --quiet SHA256SUMS) >/dev/null 2>&1 || refuse "a chart package does not match charts/SHA256SUMS"
declare -A pushed=()
if [ -f "$charts_dir/pushed.txt" ]; then
  while read -r file ref; do
    [ -n "$file" ] || continue
    [ -f "$charts_dir/$file" ] || refuse "pushed.txt names $file, which is not a package of this set"
    [[ "$ref" =~ ^oci://[^@[:space:]]+@sha256:[0-9a-f]{64}$ ]] || refuse "pushed.txt: '$ref' is not an oci:// reference pinned by digest"
    pushed["$file"]="$ref"
  done < "$charts_dir/pushed.txt"
fi
chart_field() { # chart.yaml field   -> the value, unquoted
  printf '%s\n' "$1" | sed -n "s/^$2: *//p" | head -1 | sed -e "s/^[\"']//" -e "s/[\"']\$//"
}
charts=()
for package in "${packages[@]}"; do
  file="$(basename "$package")"
  grep -q "[[:space:]]$file\$" "$charts_dir/SHA256SUMS" || refuse "$file is not in charts/SHA256SUMS"
  name="${file%-"$version".tgz}"
  [ "$name" != "$file" ] || refuse "$file is not packaged at version $version"
  chart="$(tar -xzOf "$package" "$name/Chart.yaml" 2>/dev/null)" || refuse "$file holds no $name/Chart.yaml"
  have="$(chart_field "$chart" version)"
  [ "$have" = "$version" ] || refuse "$file: chart version '$have', want $version"
  have="$(chart_field "$chart" appVersion)"
  [ "$have" = "$version" ] || refuse "$file: appVersion '$have', want $version"
  cp "$package" "$assets/$file"
  charts+=("$(jq -cn --arg name "$name" --arg version "$version" --arg asset "$file" --arg sha "$(sha "$package")" \
    --arg registry "${pushed[$file]:-}" \
    '{name: $name, version: $version, asset: $asset, sha256: $sha,
      registry: (if $registry == "" then null else $registry end)}')")
done
cp "$charts_dir/SHA256SUMS" "$assets/SHA256SUMS"

# The repository SBOM and its signature, as repo-sbom.sh wrote them: it verified the signature against
# the public key when it signed; here the pair must be present and the SBOM must be CycloneDX.
[ -s "$dir/sbom.json" ] || refuse "no repository SBOM (sbom.json)"
[ -s "$dir/sbom.json.sig" ] || refuse "the repository SBOM is not signed (sbom.json.sig)"
cyclonedx "$dir/sbom.json"
cp "$dir/sbom.json" "$dir/sbom.json.sig" "$assets/"

# The BDD evidence: the cucumber-JSON of every run and the sheet bddreport merged from them.
shopt -s nullglob
reports=("$dir"/bdd/*.json)
shopt -u nullglob
[ ${#reports[@]} -gt 0 ] || refuse "no cucumber-JSON under bdd/"
for report in "${reports[@]}"; do
  jq -e 'type == "array"' "$report" >/dev/null 2>&1 || refuse "bdd/$(basename "$report") is not cucumber-JSON (an array of features)"
  cp "$report" "$assets/bdd-$(basename "$report")"
done
for sheet in traceability.md traceability.csv; do
  [ -s "$dir/bdd/$sheet" ] || refuse "bdd/$sheet is missing: the reports were not merged by bddreport"
  cp "$dir/bdd/$sheet" "$assets/bdd-$sheet"
done

# The manifest: every asset with its digest, and the images and charts with what the digests belong to.
kind_of() {
  case "$1" in
    *.tgz) echo chart ;;
    SHA256SUMS) echo chart-checksums ;;
    sbom.json) echo repository-sbom ;;
    sbom.json.sig) echo signature ;;
    mock-attestation.json) echo mock-attestation ;;
    *.cdx.json) echo image-sbom ;;
    bdd-traceability.*) echo traceability ;;
    bdd-*.json) echo cucumber-json ;;
    *) echo file ;;
  esac
}
asset_list=()
while read -r file; do
  asset_list+=("$(jq -cn --arg name "$file" --arg sha "$(sha "$assets/$file")" --arg kind "$(kind_of "$file")" \
    '{name: $name, sha256: $sha, kind: $kind}')")
done < <(find "$assets" -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort)
jq -n --arg version "$version" --arg tag "v$version" --arg revision "$revision" --arg created "$created" \
  --arg key "$public_key" \
  --argjson images "$(printf '%s\n' "${images[@]}" | jq -s .)" \
  --argjson charts "$(printf '%s\n' "${charts[@]}" | jq -s .)" \
  --argjson assets "$(printf '%s\n' "${asset_list[@]}" | jq -s .)" \
  '{version: $version, tag: $tag, revision: $revision, created: $created, publicKey: $key,
    images: $images, charts: $charts, assets: $assets}' > "$out/release-manifest.json"

# The release notes: the same list, for the release page.
asset_sha() { jq -r --arg name "$1" '.assets[] | select(.name == $name) | .sha256' "$out/release-manifest.json"; }
{
  echo "# v$version"
  echo
  echo "The FACIS Zero Trust Demonstrator at version $version, built from commit \`$revision\` on $created."
  echo "Everything the release ships is listed here with its digest; the same list is \`release-manifest.json\`,"
  echo "signed as \`release-manifest.json.sig\`. The images, the SBOMs and the manifest are signed with the"
  echo "interim key, \`$public_key\` - not the client trust chain."
  echo
  echo "## Images"
  echo
  echo "Signed by digest, each with its SBOM and the mock attestation attached as cosign attestations."
  echo
  echo "| Image | Reference | SBOM asset | SBOM sha256 |"
  echo "|---|---|---|---|"
  jq -r '.images[] | "| \(.name) | `\(.reference)` | `\(.sbom)` | `\(.sbomSha256)` |"' "$out/release-manifest.json"
  echo
  echo "## Charts"
  echo
  echo "Packaged at version $version; \`SHA256SUMS\` (sha256 \`$(asset_sha SHA256SUMS)\`) checks them."
  echo
  echo "| Chart | Asset | sha256 | Registry |"
  echo "|---|---|---|---|"
  jq -r '.charts[] | "| \(.name) | `\(.asset)` | `\(.sha256)` | \(if .registry then "`" + .registry + "`" else "not pushed" end) |"' "$out/release-manifest.json"
  echo
  echo "## Repository SBOM and mock attestation"
  echo
  echo "| Asset | sha256 |"
  echo "|---|---|"
  for file in sbom.json sbom.json.sig mock-attestation.json; do echo "| \`$file\` | \`$(asset_sha "$file")\` |"; done
  echo
  echo "## BDD reports"
  echo
  echo "The cucumber-JSON of this release's BDD runs and the traceability sheet merged from them."
  echo
  echo "| Asset | sha256 |"
  echo "|---|---|"
  jq -r '.assets[] | select(.kind == "cucumber-json" or .kind == "traceability") | "| `\(.name)` | `\(.sha256)` |"' "$out/release-manifest.json"
  echo
  echo "## Consuming the release"
  echo
  echo '```bash'
  echo "gh release download v$version                      # every asset"
  echo "sha256sum -c SHA256SUMS                              # the charts"
  echo "cosign verify-blob --key $public_key --insecure-ignore-tlog=true \\"
  echo "  --signature release-manifest.json.sig release-manifest.json"
  echo "cosign verify-blob --key $public_key --insecure-ignore-tlog=true \\"
  echo "  --signature sbom.json.sig sbom.json"
  echo "cosign verify --key $public_key --insecure-ignore-tlog=true <image reference>"
  echo "helm install <release> <chart>-$version.tgz -f <zone file>   # see docs/deployment.md"
  echo '```'
} > "$out/RELEASE_NOTES.md"

echo "release-set: ${#images[@]} image(s), ${#charts[@]} chart(s), ${#asset_list[@]} asset(s) at version $version in $out"
