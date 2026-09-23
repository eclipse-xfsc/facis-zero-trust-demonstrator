#!/usr/bin/env bash
#
# Normalises an OCI bundle so that its measurement depends on the commit and not
# on the machine that checked it out.
#
# The rootfs measurement hashes a tar stream whose headers carry the owner and the
# permission bits of every file as found on disk. Git records neither: it stores
# content, paths and one executable bit, so ownership follows whoever ran the
# checkout and the remaining mode bits follow their umask. Two honest checkouts of
# the same commit therefore measure differently.
#
# Ownership is flattened to 0:0 and the permission bits are taken from the Git
# index rather than from the working tree, so the mode that reaches the hash is
# the mode the commit records.
#
# The same argument applies to the security.capability xattr, which the rootfs
# measurement folds into the tar header when a file carries one. Git does not
# record it either, so a binary given file capabilities on one machine and not on
# another measures differently. It is removed here.
#
# Usage: normalise.sh BUNDLE_DIR

set -euo pipefail

bundle="${1:-}"
if [ -z "$bundle" ] || [ ! -d "$bundle" ]; then
  echo "usage: $0 BUNDLE_DIR" >&2
  exit 2
fi

# Setting an owner we do not own needs privilege. Say so plainly rather than
# measure an incompletely normalised tree and report it as reproducible.
as_root=()
if [ "$(id -u)" -ne 0 ]; then
  if sudo -n true 2>/dev/null; then
    as_root=(sudo)
  else
    echo "$0: ownership cannot be normalised without root or passwordless sudo." >&2
    echo "$0: run as root, or the measurement will carry this machine's uid and gid." >&2
    exit 3
  fi
fi

# Refuse for the same reason: a tree whose xattrs were left alone is not
# normalised, and reporting it as reproducible would be the error this whole
# check exists to catch. setfattr is in the 'attr' package.
if ! command -v setfattr >/dev/null 2>&1; then
  echo "$0: setfattr is not installed, so xattrs cannot be normalised." >&2
  echo "$0: install the 'attr' package." >&2
  exit 4
fi

# Every change runs with the same privilege: a checkout that already belongs to
# another user cannot be chmod'ed by this one either.

# Directories are not in the Git index; only their contents are.
"${as_root[@]}" find "$bundle" -type d -exec chmod 0755 {} +

while read -r mode _ _ path; do
  case "$mode" in
    100755) "${as_root[@]}" chmod 0755 "$path" ;;
    100644) "${as_root[@]}" chmod 0644 "$path" ;;
    120000) ;; # a symlink's own mode is not measured
    *) echo "$0: unexpected index mode $mode for $path" >&2; exit 1 ;;
  esac
done < <(git ls-files --stage -- "$bundle")

# ENODATA -- the usual case, a file with no such xattr -- is not an error here.
while IFS= read -r -d '' path; do
  "${as_root[@]}" setfattr -h -x security.capability "$path" 2>/dev/null || true
done < <(find "$bundle" -print0)

"${as_root[@]}" chown -R 0:0 "$bundle"
