#!/usr/bin/env bash
# Cases for registry.sh: GHCR by default, lower-cased; Harbor once HARBOR_HOST and HARBOR_PROJECT are
# set; a host with a scheme, or a host without a project, is refused.
#
#   scripts/supplychain/registry_test.sh
set -euo pipefail
script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/registry.sh"
failures=0
want() { # name expected env...
  local name=$1 expected=$2 got; shift 2
  if got="$(env -i PATH="$PATH" "$@" "$script" 2>/dev/null)" && [ "$got" = "$expected" ]; then echo "ok    $name"
  else echo "FAIL  $name (got '${got:-<refused>}')"; failures=$((failures + 1)); fi
}
refused() { # name env...
  local name=$1; shift
  if env -i PATH="$PATH" "$@" "$script" >/dev/null 2>&1; then echo "FAIL  $name (accepted)"; failures=$((failures + 1))
  else echo "ok    $name"; fi
}
want "GHCR by default, lower case" $'kind=ghcr\nhost=ghcr.io\npath=ghcr.io/owner/repo' GITHUB_REPOSITORY=Owner/Repo
want "Harbor when host and project are set" $'kind=harbor\nhost=harbor.example.org\npath=harbor.example.org/facis-ztd' \
  GITHUB_REPOSITORY=Owner/Repo HARBOR_HOST=harbor.example.org HARBOR_PROJECT=facis-ztd
refused "a host with a scheme is refused" HARBOR_HOST=https://harbor.example.org HARBOR_PROJECT=p
refused "a host without a project is refused" HARBOR_HOST=harbor.example.org
# registry-login.sh, with a docker stub that records where it would log in.
login="$(dirname "$script")/registry-login.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
printf '#!/usr/bin/env bash\necho "$*" > "%s/called"\n' "$work" > "$work/docker"
chmod +x "$work/docker"
logs_in() { # name env...
  local name=$1; shift
  rm -f "$work/called"
  if env -i PATH="$PATH" DOCKER="$work/docker" "$@" "$login" >/dev/null 2>&1 && [ -s "$work/called" ]; then echo "ok    $name"
  else echo "FAIL  $name"; failures=$((failures + 1)); fi
}
sends_nothing() { # name env...
  local name=$1; shift
  rm -f "$work/called"
  if env -i PATH="$PATH" DOCKER="$work/docker" "$@" "$login" >/dev/null 2>&1 || [ -e "$work/called" ]; then
    echo "FAIL  $name (logged in)"; failures=$((failures + 1))
  else echo "ok    $name"; fi
}
logs_in "GHCR with the job token" REGISTRY_KIND=ghcr REGISTRY_HOST=ghcr.io REGISTRY_USER=actor REGISTRY_PASSWORD=t
logs_in "Harbor with its robot account" REGISTRY_KIND=harbor REGISTRY_HOST=harbor.example.org REGISTRY_USER=robot-r REGISTRY_PASSWORD=p
sends_nothing "Harbor without its password sends nothing" REGISTRY_KIND=harbor REGISTRY_HOST=harbor.example.org REGISTRY_USER=robot-r REGISTRY_PASSWORD=
sends_nothing "Harbor without its user sends nothing" REGISTRY_KIND=harbor REGISTRY_HOST=harbor.example.org REGISTRY_PASSWORD=p
sends_nothing "a GHCR login to another host sends nothing" REGISTRY_KIND=ghcr REGISTRY_HOST=harbor.example.org REGISTRY_USER=a REGISTRY_PASSWORD=t
[ "$failures" -eq 0 ] || { echo "$failures case(s) failed"; exit 1; }
