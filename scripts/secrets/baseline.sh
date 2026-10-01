#!/usr/bin/env bash
# The secret-handling baseline on a disposable cluster (FZTD-72, TDR-BDD-08; docs/secrets.md):
#   1. install the umbrella with the kind zone file (OpenBao on), the API lane read off the cluster and
#      kind's own CNI, and wait for the bootstrap Job and the verification hooks;
#   2. scan every log and ConfigMap (scripts/secrets/canary_scan.py) before anything is replaced, as the
#      restart deletes the first OpenBao pod and the upgrade replaces the verification hook;
#   3. restart OpenBao: it must come back sealed and not ready, be unsealed by hand
#      (scripts/secrets/unseal.sh) and still hold the same fixture KV value and transit key;
#   4. scan again; scan.json holds both stages and is clean only if both were.
#
#   ZTD_CANARY=<synthetic value> scripts/secrets/baseline.sh EVIDENCE-DIR TARGET RUN
#
# The cluster is the current kube context and is assumed disposable: the install creates plane
# namespaces and cluster-scoped objects. Evidence: restart.json, scan-install.json, scan-final.json and
# scan.json (both stages), counts and hashes only.
set -euo pipefail

evidence=$1 target=$2 run=$3
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
chart="$root/deployment/helm/ztd"
mkdir -p "$evidence"
lane=$(mktemp)
trap 'rm -f "$lane"' EXIT
"$root/scripts/secrets/kind-api-lane.sh" > "$lane"

helm repo add openbao https://openbao.github.io/openbao-helm >/dev/null 2>&1 || true
helm dependency build "$chart" >/dev/null
up() {
  helm upgrade --install ztd "$chart" -n ztd-system --create-namespace -f "$chart/ci/values.yaml" -f "$lane" \
    --set cni.cilium.enabled=false --wait --wait-for-jobs --timeout 8m >/dev/null
}
fixture_hash() {
  kubectl -n ztd-mgmt logs job/ztd-verify-openbao | sed -n 's/.*fixture KV value readable (sha256 \([0-9a-f]*\)).*/\1/p'
}

echo "== install"
up
kubectl -n ztd-mgmt logs job/ztd-verify-openbao
before=$(fixture_hash)
[ -n "$before" ] || { echo "the verification did not report the fixture value" >&2; exit 1; }

echo "== canary scan after the install"
python3 "$root/scripts/secrets/canary_scan.py" --evidence "$evidence" --target "$target" --run "$run" --stage install

echo "== restart: OpenBao must come back sealed and not ready"
kubectl -n ztd-mgmt delete pod ztd-openbao-0 --wait=true >/dev/null
sealed=false
for _ in $(seq 1 60); do
  rc=0; kubectl -n ztd-mgmt exec ztd-openbao-0 -- bao status >/dev/null 2>&1 || rc=$?
  [ "$rc" = 2 ] && { sealed=true; break; }   # bao status exits 2 when sealed
  sleep 3
done
ready=$(kubectl -n ztd-mgmt get pod ztd-openbao-0 -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
[ "$sealed" = true ] && [ "$ready" != True ] || { echo "after a restart OpenBao is not sealed and not ready (sealed=$sealed ready=$ready)" >&2; exit 1; }
"$root/scripts/secrets/unseal.sh"
kubectl -n ztd-mgmt wait --for=condition=Ready pod/ztd-openbao-0 --timeout=120s >/dev/null
up
after=$(fixture_hash)
[ "$before" = "$after" ] || { echo "the fixture KV value changed across the restart" >&2; exit 1; }
server=$(kubectl -n ztd-mgmt exec ztd-openbao-0 -- bao version | awk '{print $2}')
printf '{"target":"%s","run":"%s","openbao":{"chart":"0.28.3","server":"%s"},"sealedAfterRestart":true,"notReadyWhileSealed":true,"unsealedByHand":true,"fixtureHashBefore":"%s","fixtureHashAfter":"%s","persisted":true}\n' \
  "$target" "$run" "$server" "$before" "$after" > "$evidence/restart.json"
echo "restart: sealed and not ready, unsealed by hand, fixture value unchanged ($after)"

echo "== canary scan at the end"
python3 "$root/scripts/secrets/canary_scan.py" --evidence "$evidence" --target "$target" --run "$run" --stage final
