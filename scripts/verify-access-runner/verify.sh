#!/usr/bin/env bash
# Proves the privileged-operations runner (services/accessrunner) against a throwaway kind cluster
# and a Keycloak container: the realm applied by the Keycloak chart's own import job with the
# runner's clients, the access chart installed for its ServiceAccount and roles, then
# TestRunnerAgainstKindAndKeycloak, which logs callers in through the PKCE flow, performs every
# operation and every refusal, and checks their effect, or its absence, on the cluster and in Keycloak.
# Needs docker, kind, kubectl, helm, openssl, python3 with PyYAML and go. KEEP=1 leaves everything.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env

cluster=ztd-access
net="ztd-access-$$"
kc="ztd-access-kc-$$"
work="$(mktemp -d)"
export KUBECONFIG="$work/kubeconfig"
cleanup() {
  [ -n "${KEEP:-}" ] && return
  kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
  docker rm -f "$kc" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
kind create cluster --name "$cluster" --image "$KIND_NODE_IMAGE" --wait 180s >/dev/null 2>&1
for ns in ztd-access ztd-data ztd-other; do kubectl create namespace "$ns" >/dev/null; done
for ns in ztd-data ztd-other; do
  kubectl -n "$ns" create deployment app --image "$WHOAMI_IMAGE" >/dev/null
done
for ns in ztd-data ztd-other; do kubectl -n "$ns" rollout status deployment/app --timeout=180s >/dev/null; done

# Keycloak, and its realm applied by the chart's import job, as verify-crypto-baseline does.
kc_image=$(sed -n 's/^  image: \(quay.io\/keycloak\/.*\)/\1/p' deployment/helm/facis-ztd-keycloak/values.yaml)
cli_image=$(sed -n 's/^  image: \(docker.io\/adorsys\/.*\)/\1/p' deployment/helm/facis-ztd-keycloak/values.yaml)
admin_pass=$(openssl rand -hex 16)
runner_secret=$(openssl rand -hex 24)
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
redirect="https://127.0.0.1:$port/it-callback"
# The realm requires TLS for every connection: Keycloak serves HTTPS with a throwaway CA's certificate
# for 127.0.0.1, and plain HTTP only inside the Docker network for the import job.
mkdir -p "$work/tls"
openssl req -x509 -sha256 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve -nodes -days 1 -subj "/CN=ztd-access test CA" \
  -keyout "$work/tls/ca.key" -out "$work/tls/ca.crt" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve -nodes -subj "/CN=127.0.0.1" \
  -keyout "$work/tls/tls.key" -out "$work/tls/tls.csr" 2>/dev/null
printf 'subjectAltName=IP:127.0.0.1\n' >"$work/tls/ext"
openssl x509 -req -sha256 -in "$work/tls/tls.csr" -CA "$work/tls/ca.crt" -CAkey "$work/tls/ca.key" -CAcreateserial -days 1 \
  -extfile "$work/tls/ext" -out "$work/tls/tls.crt" 2>/dev/null
chmod 0644 "$work/tls/tls.key"
# The runner's own certificate, from the same CA.
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve -nodes -subj "/CN=127.0.0.1" \
  -keyout "$work/tls/runner.key" -out "$work/tls/runner.csr" 2>/dev/null
openssl x509 -req -sha256 -in "$work/tls/runner.csr" -CA "$work/tls/ca.crt" -CAkey "$work/tls/ca.key" -CAcreateserial -days 1 \
  -extfile "$work/tls/ext" -out "$work/tls/runner.crt" 2>/dev/null
docker network create "$net" >/dev/null
docker run -d --name "$kc" --network "$net" -p "127.0.0.1:$port:8443" -v "$work/tls:/certs:ro" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="$admin_pass" "$kc_image" start-dev \
  --https-certificate-file=/certs/tls.crt --https-certificate-key-file=/certs/tls.key >/dev/null
helm template kc deployment/helm/facis-ztd-keycloak --set accessRunner.enabled=true --set accessRunner.secretRef.name=runner \
  --set "accessRunner.redirectUris={$redirect}" >"$work/keycloak.yaml"
python3 - "$work/keycloak.yaml" "$work/realm.json" <<'PY'
import sys, yaml
for d in yaml.safe_load_all(open(sys.argv[1])):
    if d and d["kind"] == "ConfigMap" and "facis-ztd.json" in d.get("data", {}):
        open(sys.argv[2], "w").write(d["data"]["facis-ztd.json"])
PY
docker run --rm --network "$net" -v "$work/realm.json:/config/facis-ztd.json:ro" \
  -e KEYCLOAK_URL="http://$kc:8080" -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD="$admin_pass" \
  -e KEYCLOAK_AVAILABILITYCHECK_ENABLED=true -e KEYCLOAK_AVAILABILITYCHECK_TIMEOUT=300s \
  -e IMPORT_FILES_LOCATIONS=/config/facis-ztd.json -e IMPORT_CACHE_ENABLED=false \
  -e IMPORT_REMOTESTATE_ENABLED=true -e IMPORT_REMOTESTATE_ENCRYPTIONKEY="$admin_pass" \
  -e IMPORT_VARSUBSTITUTION_ENABLED=true -e IMPORT_VARSUBSTITUTION_NESTED=false \
  -e IMPORT_USERS_MERGEROLES=false -e IMPORT_USERS_MERGEGROUPS=false -e LOGGING_LEVEL_ROOT=WARN \
  -e DEMO_OPERATOR_PASSWORD_JSON="\"$admin_pass-1\"" -e DEMO_OBSERVER_PASSWORD_JSON="\"$admin_pass-2\"" \
  -e BDD_OPERATOR_PASSWORD_JSON="\"$admin_pass-3\"" -e BDD_OBSERVER_PASSWORD_JSON="\"$admin_pass-4\"" \
  -e ACCESS_RUNNER_SECRET="$runner_secret" \
  "$cli_image" --import.managed.client=no-delete --import.managed.role=no-delete \
  --import.managed.client-scope=no-delete --import.managed.required-action=no-delete >"$work/import.log" 2>&1 \
  || { cat "$work/import.log"; exit 1; }

kubectl -n ztd-access create secret generic access-runner-client --from-literal=client-secret="$runner_secret" >/dev/null

ACCESS_IT_KUBECONFIG="$KUBECONFIG" ACCESS_IT_KEYCLOAK="https://127.0.0.1:$port" ACCESS_IT_KEYCLOAK_CA="$work/tls/ca.crt" ACCESS_IT_ADMIN_PASSWORD="$admin_pass" \
  ACCESS_IT_RUNNER_CERT="$work/tls/runner.crt" ACCESS_IT_RUNNER_KEY="$work/tls/runner.key" \
  ACCESS_IT_REDIRECT="$redirect" ACCESS_IT_RUNNER_SECRET="$runner_secret" \
  go test ./services/accessrunner -count=1 -run TestRunnerAgainstKindAndKeycloak -v -timeout 15m
