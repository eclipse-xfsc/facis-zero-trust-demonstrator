#!/usr/bin/env bash
#
# Fails when the plane-separation section of the architecture document breaks an invariant it
# states about its own tables: the management-plane role inventory, the allow matrix, the
# supporting-services table and the staleness matrix. It checks that the design is complete and
# consistent; it does not probe reachability, which only a test against a cluster can prove.
# Usage: scripts/check-plane-separation.sh [document]   (default: docs/architecture.md)

set -euo pipefail

doc="${1:-docs/architecture.md}"
rows_file="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/features/annex-rows.txt"
status=0

fail() {
  printf 'FAIL  %s\n' "$1" >&2
  status=1
}

if [ ! -f "$doc" ]; then
  fail "$doc: document not found"
  exit $status
fi

# shellcheck source=scripts/lib/doc-table.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/doc-table.sh"

# The L7 owner a permitted row must name: the mesh's L7 proxy, stated neutrally as both proxies,
# since the zone's mesh.mode selects which one it is (the sidecar proxy under sidecar mode, the
# waypoint under ambient). A row naming one proxy alone takes a side the design does not take.
l7_owner='L7 owner \(mesh proxy: sidecar or waypoint, per `mesh\.mode`\)'

# Reports each tag in a test cell that the acceptance row list does not hold, and an empty cell.
check_tags() {
  local table="$1" row="$2" cell="$3" tag id found=0
  for tag in $(grep -oE '@[A-Za-z0-9_-]+' <<<"$cell" || true); do
    found=1
    id="${tag#@}"
    if [[ "$id" =~ ^BDD-ZT-([0-9]+)$ ]]; then
      id=$(printf 'ZT-%02d' "$((10#${BASH_REMATCH[1]}))")
    elif [[ ! "$id" =~ ^(ZT-[0-9]+|TDR-BDD-[0-9]+)$ ]]; then
      continue
    fi
    if ! grep -qxF "$id" <<<"$annex_rows"; then
      fail "$table row '$row': tag $tag names no row in features/annex-rows.txt"
    fi
  done
  if [ $found -eq 0 ]; then
    fail "$table row '$row': test column names no scenario tag"
  fi
}

if [ -f "$rows_file" ]; then
  annex_rows="$(grep -vE '^[[:space:]]*(#|$)' "$rows_file")"
else
  fail "$rows_file: acceptance row list not found"
  annex_rows=""
fi

# --- Role inventory ---------------------------------------------------------------------------

roles=()
services=""
inventory=0
if load "role inventory" "Management-plane roles" &&
  column "role inventory" "ZT-55 role" && c_role=$col &&
  column "role inventory" "Implementing service" && c_svc=$col; then
  for line in "${lines[@]}"; do
    split_row "$line"
    roles+=("${cells[$c_role]}")
    services+="${cells[$c_role]}"$'\n'"${cells[$c_svc]}"$'\n'
  done
  inventory=1
fi

# --- Allow matrix -----------------------------------------------------------------------------

allow_destinations=""
allow_named=()
allow_roles=""
if load "allow matrix" "Allow matrix" &&
  column "allow matrix" "From" && c_from=$col &&
  column "allow matrix" "ZT-55 role" && c_role=$col &&
  column "allow matrix" "Allowed" && c_verdict=$col &&
  column "allow matrix" "Enforcement" && c_enf=$col &&
  column "allow matrix" "Test" && c_test=$col; then
  catch_all=0
  for line in "${lines[@]}"; do
    split_row "$line"
    row="${cells[$c_from]}"
    role="${cells[$c_role]}"
    verdict="${cells[$c_verdict]//\*/}"
    verdict="${verdict%% *}"
    dispositions "${cells[$c_enf]}"
    allow_destinations+="$(destination_of "$row")"$'\n'

    if [ "$verdict" != ALLOW ] && [ "$verdict" != DENY ]; then
      fail "allow matrix row '$row': verdict is neither ALLOW nor DENY"
    fi
    [ -n "$np" ] || fail "allow matrix row '$row': states no NetworkPolicy disposition"
    [ -n "$mesh" ] || fail "allow matrix row '$row': states no mesh disposition"

    if [ "$verdict" = ALLOW ]; then
      if [ "$np" = DENY ]; then
        fail "allow matrix row '$row': verdict ALLOW but NetworkPolicy: DENY"
      fi
      if [ "$mesh" = DENY ]; then
        fail "allow matrix row '$row': verdict ALLOW but mesh: DENY"
      fi
      # Every permitted row of the allow matrix is a path the mesh governs: its mesh's L7 proxy
      # is the path's single L7 owner, so NetworkPolicy is held to L3/L4 only and the cell names
      # no second L7 decision point. A path the mesh cannot govern has no place in this matrix;
      # it belongs in the supporting-services table.
      if [ "$np" = ALLOW ] && [[ ! "${cells[$c_enf]}" =~ NetworkPolicy:[[:space:]]*ALLOW,[[:space:]]*L3/L4\ only ]]; then
        fail "allow matrix row '$row': permitted path does not hold NetworkPolicy to L3/L4 only"
      fi
      if [ "$mesh" = ALLOW ]; then
        if [[ ! "$mesh_text" =~ $l7_owner ]]; then
          fail "allow matrix row '$row': permitted path does not name the mesh proxy (sidecar or waypoint, per mesh.mode) as L7 owner"
        fi
        l7_count=$(grep -ow 'L7' <<<"${cells[$c_enf]}" | wc -l)
        if [ "$l7_count" -ne 1 ]; then
          fail "allow matrix row '$row': permitted path names $l7_count L7 decision points, not a single L7 owner"
        fi
      fi
    elif [ "$verdict" = DENY ]; then
      if [ -n "$np" ] && [ "$np" != DENY ]; then
        fail "allow matrix row '$row': verdict DENY but NetworkPolicy: $np"
      fi
      if [ -n "$mesh" ] && [ "$mesh" != DENY ]; then
        fail "allow matrix row '$row': verdict DENY but mesh: $mesh"
      fi
    fi

    if [[ "$role" == "any management-plane destination"* ]]; then
      catch_all=1
      # The management components the catch-all names by example are management-plane
      # destinations as much as the bound roles are.
      allow_destinations+="$row"$'\n'
      if [ "$verdict" != DENY ] || [ "$np" != DENY ] || [ "$mesh" != DENY ]; then
        fail "allow matrix row '$row': catch-all row is not denied at both layers"
      fi
    else
      allow_named+=("$(destination_of "$row")")
      base="$(strip_qualifier "$role")"
      allow_roles+="$base"$'\n'
      known=0
      for r in "${roles[@]}"; do
        [ "$r" = "$base" ] && known=1
      done
      if [ $inventory -eq 1 ] && [ $known -eq 0 ]; then
        fail "allow matrix row '$row': role '$role' is not bound by the role inventory"
      fi
    fi

    check_tags "allow matrix" "$row" "${cells[$c_test]}"
  done

  if [ $catch_all -eq 0 ]; then
    fail "allow matrix: no catch-all row denying management-plane destinations without a row of their own"
  fi
  for r in "${roles[@]}"; do
    if ! grep -qxF "$r" <<<"$allow_roles"; then
      fail "role inventory role '$r': appears in no allow-matrix row"
    fi
  done
fi

# --- Supporting services ----------------------------------------------------------------------

if load "supporting-services table" "Supporting services"; then
  for h in "${header[@]}"; do
    if [[ "${h,,}" =~ (^|[^a-z])(tests?|tags?|scenarios?)([^a-z]|$) ]]; then
      fail "supporting-services table: has a test column '$h'; its rows are proved by their own requirements' families"
    fi
  done
  if column "supporting-services table" "From" && c_from=$col &&
    column "supporting-services table" "Enforcement" && c_enf=$col; then
    for line in "${lines[@]}"; do
      split_row "$line"
      row="${cells[$c_from]}"
      dest="$(destination_of "$row")"
      if [ -n "$dest" ] && grep -qiwF -- "$dest" <<<"$services$allow_destinations"; then
        fail "supporting-services row '$row': destination '$dest' is a management-plane destination"
      else
        for named in "${allow_named[@]}"; do
          if [ -n "$named" ] && grep -qiwF -- "$named" <<<"$dest"; then
            fail "supporting-services row '$row': destination '$dest' is covered by the allow matrix"
          fi
        done
      fi
      dispositions "${cells[$c_enf]}"
      [ -n "$np" ] || fail "supporting-services row '$row': states no NetworkPolicy disposition"
      if [ -z "$mesh" ] && [[ ! "${cells[$c_enf]}" =~ mesh\ cannot\ govern ]]; then
        fail "supporting-services row '$row': states no mesh disposition and does not record that the mesh cannot govern its traffic"
      fi
    done
  fi
fi

# --- Staleness matrix -------------------------------------------------------------------------

if load "staleness matrix" "Staleness matrix" &&
  column "staleness matrix" "Artefact" && c_art=$col &&
  column "staleness matrix" "Enforced by" && c_by=$col &&
  column "staleness matrix" "Test" && c_test=$col; then
  for line in "${lines[@]}"; do
    split_row "$line"
    row="${cells[$c_art]}"
    by="${cells[$c_by]:-}"
    if [ -z "$by" ] || [ "$by" = "—" ] || [ "$by" = "-" ]; then
      fail "staleness matrix row '$row': names no enforcing component"
    elif [[ "${by,,}" =~ networkpolic|network\ polic|authori[sz]ationpolic|authori[sz]ation\ polic ]]; then
      fail "staleness matrix row '$row': enforcing component '$by' is a network layer, which cannot express a lifetime"
    fi
    check_tags "staleness matrix" "$row" "${cells[$c_test]:-}"
  done
fi

exit $status
