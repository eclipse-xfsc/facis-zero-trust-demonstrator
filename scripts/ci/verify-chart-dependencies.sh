#!/usr/bin/env bash
# Checks the dependency archives of a chart against the sha256 digests committed with it.
#
#   scripts/ci/verify-chart-dependencies.sh <chart-dir> [<archives-dir>]
#
# A chart with dependencies commits, next to its Chart.lock, a file dependencies.sha256 with one
# line per archive Helm builds into charts/ ("<sha256>  <archive>.tgz", the sha256sum format). The
# digest in Chart.lock covers the list of dependencies, not the archives' contents, so a repository
# that serves different bytes for the same version would pass `helm dependency build`; this check
# refuses it, as the zone installer refuses a SPIRE or Istio download that does not match its pinned
# digest. <archives-dir> is where the archives were built (default <chart-dir>/charts). Passes only
# when it holds exactly the archives listed, each a regular file with its committed digest, and
# nothing else: Helm also loads an unpacked chart directory (or a symbolic link) found in charts/,
# so any other entry, hidden ones included, is refused as unpinned. Used by
# scripts/ci/check-charts.sh, scripts/install-zone/install.sh and scripts/secrets/baseline.sh after
# every `helm dependency build`, before the chart is rendered or installed.
set -euo pipefail

chart=${1:?usage: verify-chart-dependencies.sh <chart-dir> [<archives-dir>]}
archives=${2:-$chart/charts}
pins=$chart/dependencies.sha256

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
fail() { echo "verify-chart-dependencies: $chart: $*" >&2; exit 1; }

[ -f "$pins" ] || fail "no dependencies.sha256: the dependency archives have no committed digest"
listed=0
while read -r want name; do
  case "$want" in ''|'#'*) continue ;; esac
  [[ "$want" =~ ^[0-9a-f]{64}$ ]] || fail "dependencies.sha256: '$want' is not a sha256 digest"
  [[ "$name" =~ ^[A-Za-z0-9._-]+\.tgz$ ]] || fail "dependencies.sha256: '$name' is not an archive name"
  if [ ! -f "$archives/$name" ] || [ -L "$archives/$name" ]; then fail "$name was not built into $archives as a regular file"; fi
  have=$(sha256 "$archives/$name")
  [ "$have" = "$want" ] || fail "$name has digest $have, not the committed $want"
  listed=$((listed + 1))
done <"$pins"
[ "$listed" -gt 0 ] || fail "dependencies.sha256 lists no archive"
shopt -s nullglob dotglob
for built in "$archives"/*; do
  awk -v n="${built##*/}" '$2 == n { found = 1 } END { exit !found }' "$pins" \
    || fail "${built##*/} is in $archives but is not an archive with a committed digest (Helm would load it as a dependency)"
done
echo "dependency archives match dependencies.sha256 ($listed)"
