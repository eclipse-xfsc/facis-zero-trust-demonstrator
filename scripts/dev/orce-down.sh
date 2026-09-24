#!/usr/bin/env bash
# Stop the local ORCE container and remove the credentials orce-up.sh wrote.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
docker rm -f orce-bdd >/dev/null 2>&1 || true
rm -f "$root/.dev/kind/orce.env" "$root/.dev/kind/kubeconfig-deployer-internal"
