#!/usr/bin/env bash
#
# Fails when the cryptographic register and the repository disagree: a register row that names a
# mechanism the baseline does not accept for its use, a row whose file no longer holds the text it
# quotes, or one of the scanned patterns in the Go code or the deployment configuration. It cannot
# tell that a row is missing or that a setting is in effect, and it inspects no running zone; see
# docs/crypto-baseline.md.
# Usage: scripts/check-crypto-baseline.sh [document]   (default: docs/crypto-baseline.md)

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
doc="${1:-$root/docs/crypto-baseline.md}"
status=0

fail() {
  printf 'FAIL  %s\n' "$1" >&2
  status=1
}

[ -f "$doc" ] || { fail "$doc: document not found"; exit "$status"; }

# The data rows of the first table under the heading $1, one per line, cells separated by tabs
# and stripped of their backticks. Found by heading, never by line number.
rows_under() {
  awk -v title="$1" '
    /^#+[[:space:]]/ { if (inside) exit; text = $0; sub(/^#+[[:space:]]+/, "", text); if (text == title) inside = 1; next }
    inside && /^\|/ {
      n++
      if (n <= 2) next
      line = $0; sub(/^\|[[:space:]]*/, "", line); sub(/[[:space:]]*\|$/, "", line)
      gsub(/[[:space:]]*\|[[:space:]]*/, "\t", line); gsub(/`/, "", line)
      print line; next
    }
    inside && n { exit }
  ' "$doc"
}

accepted="$(rows_under 'Accepted mechanisms')"
[ -n "$accepted" ] || fail "no table under 'Accepted mechanisms'"

rows=0
while IFS=$'\t' read -r component purpose use mechanism file setting; do
  [ -n "$component" ] || continue
  rows=$((rows + 1))
  what="$component, $purpose"
  allowed="$(printf '%s\n' "$accepted" | awk -F'\t' -v use="$use" '$1 == use { print $2 }')"
  if [ -z "$allowed" ]; then
    fail "$what: unknown use '$use'"
  elif ! printf '%s\n' "$allowed" | tr ',' '\n' | sed 's/^ *//; s/ *$//' | grep -qxF "$mechanism"; then
    fail "$what: '$mechanism' is not accepted for $use ($allowed)"
  fi
  if [ ! -f "$root/$file" ]; then
    fail "$what: $file does not exist"
  elif ! grep -qF -- "$setting" "$root/$file"; then
    fail "$what: $file no longer holds: $setting"
  fi
done <<<"$(rows_under 'Register')"
[ "$rows" -gt 0 ] || fail "no rows under 'Register'"

# scan <message> <grep arguments...>: fails with the matching lines. A grep that fails to run is a
# failure of the check, not "nothing found".
scan() {
  local message="$1" hits code=0
  shift
  hits="$(grep -rnE "$@")" || code=$?
  if [ "$code" -gt 1 ]; then
    fail "$message: grep failed"
  elif [ -n "$hits" ]; then
    fail "$message:
$hits"
  fi
}

# The Go code signs and verifies with ECDSA only, so any of these imports is a new mechanism.
# Tests are included: a fixture key is a key the code accepts.
scan "deprecated or unregistered algorithm imported in Go code" \
  '"crypto/(md5|sha1|des|rc4|dsa|rsa)"' --include='*.go' "$root/cmd" "$root/internal" "$root/services" "$root/scripts"

# Sprig's genCA, genSignedCert and genSelfSignedCert make RSA-2048 keys; the *WithKey forms take one.
scan "chart helper that generates an RSA-2048 key" \
  '(^|[^$[:alnum:]])gen(CA|SignedCert|SelfSignedCert)[[:space:]]' "$root/deployment"

scan "deprecated algorithm or short RSA key in the deployment configuration" -i \
  'rsa-?(1024|2048|3072)|key_?(size|bits)[^0-9a-z]{1,40}([1-9][0-9]{2}|[1-3][0-9]{3}|40[0-8][0-9]|409[0-5])\b|RSA-OAEP([^-[:alnum:]]|$)|RSA1_5|\b(md5|sha-?1)\b' \
  --include='*.yaml' --include='*.yml' --include='*.tpl' --include='*.json' "$root/deployment"

[ "$status" -ne 0 ] || printf 'ok    %s register rows agree with the repository; none of the scanned patterns found\n' "$rows"
exit "$status"
