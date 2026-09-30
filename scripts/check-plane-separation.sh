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

# Prints the header and data lines of the first pipe-delimited table under the heading whose text
# starts with $1, stopping at the next heading. The separator line is dropped. Tables are found by
# heading, never by line number, so edits to the surrounding prose do not move them.
table_under() {
  awk -v title="$1" '
    /^#+[[:space:]]/ {
      if (inside) exit
      text = $0
      sub(/^#+[[:space:]]+/, "", text)
      if (index(text, title) == 1) inside = 1
      next
    }
    inside && /^\|/ { started = 1; if ($0 !~ /^\|[[:space:]:|-]*$/) print; next }
    inside && started { exit }
  ' "$doc"
}

# Splits one table line into the global array `cells`, trimmed.
split_row() {
  local line="$1" cell
  line="${line#|}"
  line="${line%|}"
  cells=()
  IFS='|' read -ra parts <<<"$line"
  for cell in "${parts[@]}"; do
    cell="${cell#"${cell%%[![:space:]]*}"}"
    cell="${cell%"${cell##*[![:space:]]}"}"
    cells+=("$cell")
  done
}

# Sets the global `col` to the index of the header cell starting with $2 in table $1, or fails.
column() {
  local table="$1" name="$2" i
  col=-1
  for i in "${!header[@]}"; do
    if [[ "${header[$i]}" == "$name"* ]]; then
      col=$i
      return 0
    fi
  done
  fail "$table: no '$name' column"
  return 1
}

# Loads table $2 (heading prefix) into the global arrays `header` and `lines`. Returns non-zero,
# after reporting it, when the table cannot be located.
load() {
  local table="$1" heading="$2"
  mapfile -t lines < <(table_under "$heading")
  if [ ${#lines[@]} -lt 1 ]; then
    fail "$table: no table found under a heading starting '$heading'"
    return 1
  fi
  split_row "${lines[0]}"
  header=("${cells[@]}")
  lines=("${lines[@]:1}")
  return 0
}

strip_qualifier() {
  local s="$1"
  s="${s%% (*}"
  printf '%s' "$s"
}

destination_of() {
  local s="${1#*→}"
  s="${s#"${s%%[![:space:]]*}"}"
  strip_qualifier "$s"
}

# Sets `np` and `mesh` to the dispositions an enforcement cell states, and `mesh_text` to the
# text of its mesh part. A disposition the cell does not state is left empty.
dispositions() {
  local cell="$1"
  np=""
  mesh=""
  mesh_text=""
  if [[ "$cell" =~ NetworkPolicy:[[:space:]]*(ALLOW|DENY) ]]; then
    np="${BASH_REMATCH[1]}"
  fi
  if [[ "$cell" =~ mesh:[[:space:]]*(.*)$ ]]; then
    mesh_text="${BASH_REMATCH[1]}"
    if [[ "$mesh_text" =~ ^(ALLOW|DENY) ]]; then
      mesh="${BASH_REMATCH[1]}"
    elif [[ "$mesh_text" == "not applicable"* ]]; then
      mesh="not applicable"
    fi
  fi
}

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
      # A path the mesh cannot govern has no L7 owner; the network layer imposes the
      # restriction, and its disposition is still required above.
      if [ "$mesh" = ALLOW ] && [[ ! "$mesh_text" =~ L7\ owner.*waypoint ]]; then
        fail "allow matrix row '$row': permitted path names no mesh waypoint as L7 owner"
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
