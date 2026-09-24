#!/usr/bin/env bash
# Remove the local developer cluster and the identity kubeconfigs kind-up.sh wrote.
set -euo pipefail

cluster="${KIND_CLUSTER:-ztd-bdd}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if kind get clusters | grep -qx "$cluster"; then
  kind delete cluster --name "$cluster"
fi
rm -rf "$root/.dev/kind"
