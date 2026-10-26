#!/usr/bin/env bash
# Cases for policy-package.sh and policy-publish.sh (plan: the package holds exactly the cluster objects
# of the catalogue, at their Git paths; the same files give the same bytes whatever the modification
# times and modes of the checkout; a catalogue missing a member is refused; then, against a registry:
# the artefact is one layer of the media type Argo CD reads, pulling the signed digest back gives the
# bytes that were packaged, a signature by another key is refused, and a tampered package pushed to the
# same tag is a digest the signature does not cover while the signed digest still verifies).
#
#   REGISTRY=localhost:5000 [ORAS=oras] [COSIGN=cosign] scripts/supplychain/policy-package_test.sh
#
# The registry is plain http (a registry:2 on the runner). Without REGISTRY the registry cases are skipped.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
oras="${ORAS:-oras}" cosign="${COSIGN:-cosign}"
catalogue="$root/deployment/admission"

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
refused() { # name command...
  local name=$1
  shift
  if "$@" >"$work/log" 2>&1; then fail "$name" "accepted, want refused"; else echo "ok    $name"; fi
}
sha() { sha256sum "$1" | cut -d' ' -f1; }

echo "== The package"
"$here/policy-package.sh" "$catalogue" "$work/a.tar.gz" >/dev/null
# Exactly the cluster objects of the catalogue: templates/, constraints/ and exemptions.yaml, and nothing
# else (not the suite, the test objects, the chart values or the README).
(cd "$catalogue" && find templates constraints exemptions.yaml | sort) > "$work/want"
tar -tzf "$work/a.tar.gz" | sed 's|/$||' | sort > "$work/have"
check "the package holds the cluster objects of the catalogue and nothing else" diff "$work/want" "$work/have"

# The same files, with the modification times and modes of another checkout.
cp -r "$catalogue" "$work/other"
find "$work/other" -type f -exec touch -d '2020-02-02 02:02:02' {} + -exec chmod 600 {} +
find "$work/other" -type d -exec chmod 700 {} +
"$here/policy-package.sh" "$work/other" "$work/b.tar.gz" >/dev/null
check "the same files give the same bytes whatever the checkout's times and modes" [ "$(sha "$work/a.tar.gz")" = "$(sha "$work/b.tar.gz")" ]

rm "$work/other/exemptions.yaml"
refused "a catalogue missing a member is refused" "$here/policy-package.sh" "$work/other" "$work/c.tar.gz"

if [ -z "${REGISTRY:-}" ]; then
  echo "REGISTRY is not set: the registry cases are skipped"
  [ "$failures" -eq 0 ] || { echo "$failures case(s) failed"; exit 1; }
  echo "every case passed"
  exit 0
fi

echo "== The published artefact ($REGISTRY)"
repository="$REGISTRY/policy-package-test/admission"
export COSIGN_PASSWORD= PLAIN_HTTP=true ORAS="$oras" COSIGN="$cosign"
mkdir -p "$work/key" "$work/other-key"
(cd "$work/key" && "$cosign" generate-key-pair >/dev/null 2>&1)
(cd "$work/other-key" && "$cosign" generate-key-pair >/dev/null 2>&1)
export COSIGN_KEY="$work/key/cosign.key" PUBLIC_KEY="$work/key/cosign.pub"

ref="$("$here/policy-publish.sh" "$work/a.tar.gz" "$repository" 0.0.0-test deadbeef 2>"$work/log" | tail -n1)"
check "the package is published, signed and verified" [ "$ref" = "$repository@sha256:$(echo "$ref" | sed 's/.*@sha256://' | grep -E '^[0-9a-f]{64}$')" ]
digest="${ref#*@}"

"$oras" manifest fetch --plain-http "$ref" > "$work/manifest.json"
layers="$(jq -r '[.layers[].mediaType] | join(",")' "$work/manifest.json")"
check "the artefact is one layer of the media type Argo CD reads" [ "$layers" = application/vnd.oci.image.layer.v1.tar+gzip ]
check "the manifest names the version and the revision" \
  [ "$(jq -r '.annotations["org.opencontainers.image.version"] + " " + .annotations["org.opencontainers.image.revision"]' "$work/manifest.json")" = "0.0.0-test deadbeef" ]

mkdir -p "$work/pull"
(cd "$work/pull" && "$oras" pull --plain-http --no-tty "$ref" >/dev/null 2>&1)
check "pulling the signed digest gives the bytes that were packaged" [ "$(sha "$work/pull/a.tar.gz")" = "$(sha "$work/a.tar.gz")" ]

refused "a signature by another key is refused" \
  "$cosign" verify --key "$work/other-key/cosign.pub" --insecure-ignore-tlog=true --allow-http-registry "$ref"

# Tampered: one constraint changed, packaged and pushed to the same tag without the key. The tag now
# names a digest the signature does not cover; the signed digest is untouched.
cp -r "$catalogue" "$work/tampered"
sed -i 's/\^ztd-/^any-/' "$work/tampered/constraints/naming.yaml"
"$here/policy-package.sh" "$work/tampered" "$work/t.tar.gz" >/dev/null
tampered="$(cd "$work" && "$oras" push --plain-http --no-tty --format 'go-template={{.digest}}' \
  "$repository:0.0.0-test" t.tar.gz:application/vnd.oci.image.layer.v1.tar+gzip)"
check "the tampered push moved the tag to another digest" [ "$tampered" != "$digest" ]
refused "the tag's new digest has no valid signature" \
  "$cosign" verify --key "$PUBLIC_KEY" --insecure-ignore-tlog=true --allow-http-registry "$repository@$tampered"
check "the signed digest still verifies" \
  "$cosign" verify --key "$PUBLIC_KEY" --insecure-ignore-tlog=true --allow-http-registry "$ref"

[ "$failures" -eq 0 ] || { echo "$failures case(s) failed"; exit 1; }
echo "every case passed"
