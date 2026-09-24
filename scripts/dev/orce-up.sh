#!/usr/bin/env bash
# Run the first-party ORCE image next to the local kind cluster, deploying with the pool's
# least-privilege deployer identity, and write the acceptance runner's inputs to .dev/kind/orce.env.
# Developer loop only, never evidence. Needs scripts/dev/kind-up.sh first.
#
#   scripts/dev/orce-up.sh && set -a && . .dev/kind/orce.env && set +a && npm run bdd:cluster
set -euo pipefail

cluster="${KIND_CLUSTER:-ztd-bdd}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="$root/.dev/kind"
image="${ORCE_IMAGE:-ci/orce:local}"
name=orce-bdd
port="${ORCE_PORT:-18800}"

[ -f "$out/kubeconfig-ztd-lifecycle-deployer" ] || { echo "run scripts/dev/kind-up.sh first" >&2; exit 1; }
if ! docker image inspect "$image" >/dev/null 2>&1; then
  docker build --platform linux/amd64 -f "$root/deployment/docker/orce/Dockerfile" -t "$image" "$root"
fi

# Inside the kind network the API server is the control-plane container, not the host port.
umask 077
sed -E "s#server: https://[^[:space:]]+#server: https://${cluster}-control-plane:6443#" \
  "$out/kubeconfig-ztd-lifecycle-deployer" >"$out/kubeconfig-deployer-internal"
chmod 0644 "$out/kubeconfig-deployer-internal"   # read by the container user; $out itself stays 0700

hash() {
  docker run --rm --platform linux/amd64 --entrypoint node "$image" \
    -e "console.log(require('/opt/maestro/MBE/node_modules/bcryptjs').hashSync(process.argv[1], 10))" "$1"
}
admin_pass="$(openssl rand -hex 16)"
http_pass="$(openssl rand -hex 16)"
read_token="$(openssl rand -hex 32)"

docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" --platform linux/amd64 --network kind -p "127.0.0.1:$port:1880" \
  -e ORCE_ADMIN_USER=admin -e ORCE_ADMIN_PASSWORD_HASH="$(hash "$admin_pass")" \
  -e ORCE_HTTP_USER=bdd -e ORCE_HTTP_PASSWORD_HASH="$(hash "$http_pass")" \
  -e ORCE_READ_TOKEN="$read_token" \
  -e KUBECONFIG=/run/ztd/kubeconfig -e LIFECYCLE_TIMEOUT="${LIFECYCLE_TIMEOUT:-5m}" \
  -v "$out/kubeconfig-deployer-internal:/run/ztd/kubeconfig:ro" \
  "$image" >/dev/null

for _ in $(seq 1 90); do
  curl -s -o /dev/null "http://127.0.0.1:$port/" && break
  sleep 2
done

cat >"$out/orce.env" <<ENV
KUBECONFIG=$out/kubeconfig-ztd-bdd-observer
BDD_ORCE_URL=http://127.0.0.1:$port
BDD_ORCE_ADMIN_TOKEN=$read_token
BDD_ORCE_HTTP_USER=bdd
BDD_ORCE_HTTP_PASS=$http_pass
BDD_ORCE_LOGS_CMD='docker logs $name'
BDD_TARGET=local
ENV
chmod 0600 "$out/orce.env"
echo "ORCE ready on http://127.0.0.1:$port; runner inputs in ${out#"$root"/}/orce.env (admin password: not stored)"
