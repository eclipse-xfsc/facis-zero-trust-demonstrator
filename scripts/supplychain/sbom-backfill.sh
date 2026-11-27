#!/usr/bin/env bash
# Every published release must carry sbom.json and sbom.json.sig, verifying. For each release:
#
#   - a pair that verifies against any key of the set (every docs/contracts/keys/*.pub) is done, and
#     left as it is - an old release stays signed with the key it was signed with;
#   - a release that carries neither file gets both, generated from its tag by repo-sbom.sh and signed
#     with the current key (SIGNING_PUBLIC_KEY's private half, COSIGN_KEY);
#   - a release that carries one of the two, or a pair that verifies against no key of the set, is
#     regenerated only when the release was signed with the current key - the key its
#     release-manifest.json names, or the interim key for a release without a manifest. Otherwise it is
#     reported and the run fails: an existing asset of an old release is never replaced under a new key.
#
# Which assets a release carries comes from the release's asset list; a listing or a download that
# fails fails that release (and the run) - an unreadable asset is never taken for a missing one.
#
#   COSIGN_KEY=... SIGNING_PUBLIC_KEY=... GH_TOKEN=... GITHUB_REPOSITORY=... scripts/supplychain/sbom-backfill.sh
#
# The functions are sourced by sbom-backfill_test.sh; COSIGN and KEYS_DIR are overridable there.
set -euo pipefail

SBOM_NAME=sbom.json
KEYS_DIR="${KEYS_DIR:-docs/contracts/keys}"
INTERIM_KEY=docs/contracts/keys/interim-cosign.pub

# verify_any <blob> <sig>  -> the key of the set the pair verifies against; fails if none does
verify_any() {
  local key
  for key in "$KEYS_DIR"/*.pub; do
    [ -s "$key" ] || continue
    if "${COSIGN:-cosign}" verify-blob --key "$key" --insecure-ignore-tlog=true --signature "$2" "$1" >/dev/null 2>&1; then
      echo "$KEYS_DIR/$(basename "$key")"
      return 0
    fi
  done
  return 1
}

# sbom_action <pair: none|partial|complete> <verified key or ""> <recorded key> <current key>  -> done|sign|refuse
sbom_action() {
  if [ "$1" = complete ] && [ -n "$2" ]; then echo "done"
  elif [ "$1" = none ] || [ "$3" = "$4" ]; then echo sign
  else echo refuse
  fi
}

# fetch_assets <tag> <dir>  -> the pair state (none|partial|complete), with the present assets of
# sbom.json, sbom.json.sig and release-manifest.json downloaded into <dir>; fails if the asset list or
# a download fails
fetch_assets() {
  local tag=$1 dir=$2 names name present=0 patterns=()
  names="$(gh release view "$tag" --json assets --jq '.assets[].name')" || return 1
  for name in "$SBOM_NAME" "$SBOM_NAME.sig" release-manifest.json; do
    grep -qxF "$name" <<<"$names" || continue
    patterns+=(--pattern "$name")
    [ "$name" = release-manifest.json ] || present=$((present + 1))
  done
  if [ ${#patterns[@]} -gt 0 ]; then
    gh release download "$tag" --dir "$dir" "${patterns[@]}" || return 1
    for name in "${patterns[@]}"; do
      [ "$name" = --pattern ] || [ -s "$dir/$name" ] || return 1
    done
  fi
  case "$present" in 0) echo none ;; 1) echo partial ;; *) echo complete ;; esac
}

main() {
  : "${COSIGN_KEY:?set COSIGN_KEY}"
  local current="${SIGNING_PUBLIC_KEY:-$INTERIM_KEY}" failed=0 tags tag check pair verified recorded workdir out
  # Every published release, all pages; a failed listing fails the run instead of looking empty.
  tags="$(gh api --paginate "repos/$GITHUB_REPOSITORY/releases" --jq '.[] | select(.draft | not) | .tag_name')"

  while read -r tag; do
    [ -n "$tag" ] || continue
    check="$(mktemp -d)"
    if ! pair="$(fetch_assets "$tag" "$check")"; then
      echo "::error::could not read the assets of $tag - left as it is"
      failed=1
      rm -rf "$check"
      continue
    fi
    verified="" recorded="$INTERIM_KEY"
    if [ "$pair" = complete ]; then
      verified="$(verify_any "$check/$SBOM_NAME" "$check/$SBOM_NAME.sig")" || verified=""
    fi
    [ -s "$check/release-manifest.json" ] && recorded="$(jq -r '.publicKey // empty' "$check/release-manifest.json")"
    rm -rf "$check"

    case "$(sbom_action "$pair" "$verified" "$recorded" "$current")" in
      done) echo "Signed SBOM already attached to $tag (verifies against $verified)"; continue ;;
      refuse)
        echo "::error::the SBOM of $tag is incomplete or verifies against no key of $KEYS_DIR, and $tag was signed with $recorded, not the current $current - not replaced under a new key"
        failed=1
        continue ;;
    esac

    if ! git cat-file -e "refs/tags/$tag:go.mod" 2>/dev/null; then
      echo "No go.mod at $tag - skipped"
      continue
    fi

    echo "Generating and signing the SBOM for $tag"
    workdir="$(mktemp -d)" out="$(mktemp -d)/$SBOM_NAME"
    git worktree add --quiet --detach "$workdir" "refs/tags/$tag"
    if scripts/supplychain/repo-sbom.sh "$workdir" "$out"; then
      gh release upload "$tag" "$out" "$out.sig" --clobber
    else
      echo "::error::could not produce a signed SBOM for $tag"
      failed=1
    fi
    git worktree remove --force "$workdir"
  done <<< "$tags"

  return "$failed"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi
