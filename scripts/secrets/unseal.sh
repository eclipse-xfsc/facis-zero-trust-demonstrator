#!/usr/bin/env bash
# Unseal the bundled OpenBao after a restart (docs/secrets.md). OpenBao seals itself whenever its pod
# restarts and stays not ready until unsealed; this is the documented manual step, not an automatic one.
#
#   scripts/secrets/unseal.sh [namespace] [pod]      defaults: ztd-mgmt ztd-openbao-0
#
# The key is read from the Secret ztd-openbao-bootstrap and handed to `bao write sys/unseal key=-` on stdin:
# it never appears on a command line (which the API server's audit log would record) or in the output.
set -euo pipefail

ns=${1:-ztd-mgmt}
pod=${2:-ztd-openbao-0}

if kubectl -n "$ns" exec "$pod" -- bao status >/dev/null 2>&1; then
  echo "$pod is already unsealed"
  exit 0
fi
kubectl -n "$ns" get secret ztd-openbao-bootstrap -o jsonpath='{.data.unseal-key}' | base64 -d |
  kubectl -n "$ns" exec -i "$pod" -- bao write sys/unseal key=- >/dev/null
kubectl -n "$ns" exec "$pod" -- bao status >/dev/null || { echo "$pod is still sealed" >&2; exit 1; }
echo "$pod unsealed"
