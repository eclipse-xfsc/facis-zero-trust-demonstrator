#!/usr/bin/env bash
# Remove the local TSPA cluster and the kubeconfig kind-up.sh wrote.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="$root/.dev/tspa"

# Fails here, keeping the kubeconfig, if the clusters cannot be listed (for example Docker is down).
clusters="$(kind get clusters)"
if grep -qx ztd-tspa <<<"$clusters"; then
  KUBECONFIG="$out/kubeconfig" kind delete cluster --name ztd-tspa
fi
rm -rf "$out"
