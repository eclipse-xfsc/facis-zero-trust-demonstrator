# The heading-based reader of the plane-separation section's tables, shared by
# scripts/check-plane-separation.sh and scripts/verify-plane-separation/verify.sh. Sourced, never run;
# defines functions only. The caller sets `doc` (the document read) and defines `fail <message>`.
# shellcheck shell=bash disable=SC2034,SC2154

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
