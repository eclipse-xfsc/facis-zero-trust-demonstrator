#!/usr/bin/env bash
# The verification-service chart on a throwaway kind cluster: the image built from the working tree
# and deployed by digest, PostgreSQL and OpenBao (dev mode) from the pinned images inside the
# cluster, an issuer key generated for the run and the pinned FIXTURE trust list in the trust
# ConfigMap. It checks that the release comes up ready (database reachable, outcome key created in
# transit, trust set loaded), that `verification-service trust-set` in the pod prints the outcome
# key for the consumers, that the service refuses a caller without a forwarded mesh identity, with
# another one and with two, serves the declared caller, refuses a challenge offered twice, and stops
# being ready while PostgreSQL is gone. There is no mesh here: the Istio CRDs are installed inert so
# the chart's PeerAuthentication and DestinationRule are accepted, and the script plays the sidecar
# by setting X-Forwarded-Client-Cert through the API server's pod proxy. The presentation path
# itself (presentation, outcome, grant, token, protected call, renewal) is the Go end-to-end test
# services/token-store/internal/renew/verification_e2e_test.go.
#
#   scripts/verify-verification-service/verify.sh [--out DIR]   default .dev/verification-service (git-ignored)
#   BIN=<dir with kind and kubectl> ...                          default .tools/bin
#
# Needs docker, helm, kind, kubectl, curl, jq, openssl. KEEP=1 leaves the cluster and registry.
# pass and fail always succeed, so `check && pass || fail` is an if-then-else here.
# shellcheck disable=SC2015
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env
if [ -d "${BIN:-.tools/bin}" ]; then PATH="$(cd "${BIN:-.tools/bin}" && pwd):$PATH"; export PATH; fi

out=.dev/verification-service
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
for tool in docker helm kind kubectl curl jq openssl; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 2; }
done
mkdir -p "$out"
out="$(cd "$out" && pwd)"
rm -f "$out"/*.txt "$out"/*.json

cluster=${VS_KIND_CLUSTER:-ztd-verification-service}
reg_name=${VS_KIND_REGISTRY:-kind-registry-verification-service}
reg="$reg_name:5000"
host_reg=${VS_KIND_HOST_REGISTRY:-127.0.0.1:5003}
ns=ztd-mgmt
td=zone-a.trust.invalid
store_id="spiffe://$td/ns/$ns/sa/ztd-token-store"
sel=app.kubernetes.io/name=verification-service
work="$(mktemp -d)"
export KUBECONFIG="$work/kubeconfig"
cluster_owned=false
registry_owned=false
proxy_pid=""
proxy_port=""
failures=0
pass() { echo "PASS  $*" | tee -a "$out/run.txt"; }
fail() { echo "FAIL  $*" | tee -a "$out/run.txt"; failures=$((failures + 1)); }
step() { echo; echo "== $*"; }
cleanup() {
  if [ -n "$proxy_pid" ]; then kill "$proxy_pid" >/dev/null 2>&1 || true; fi
  if [ -n "${KEEP:-}" ]; then echo "kept: cluster $cluster, registry $reg_name, KUBECONFIG=$KUBECONFIG"; return; fi
  if [ "$cluster_owned" = true ]; then kind delete cluster --name "$cluster" >/dev/null 2>&1 || true; fi
  if [ "$registry_owned" = true ]; then docker rm -f "$reg_name" >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT
b64url() { base64 | tr -d '\n=' | tr '+/' '-_'; }
pod() { kubectl -n "$ns" get pod -l "$sel" -o json | jq -r '[.items[] | select(.metadata.deletionTimestamp == null)][0].metadata.name // empty'; }
# call METHOD PORT PATH XFCC... [curl args]: the pod through the API server's pod proxy; prints the
# HTTP code and leaves the body in $work/body. Each XFCC argument is one header field ("" for none).
call() {
  local method=$1 port=$2 path=$3 xfcc=$4
  shift 4
  local args=()
  if [ -n "$xfcc" ]; then IFS='|' read -r -a fields <<<"$xfcc"; for f in "${fields[@]}"; do args+=(-H "X-Forwarded-Client-Cert: $f"); done; fi
  curl -sS -m 10 -o "$work/body" -w '%{http_code}' -X "$method" ${args[@]+"${args[@]}"} "$@" \
    "http://127.0.0.1:$proxy_port/api/v1/namespaces/$ns/pods/$(pod):$port/proxy$path" 2>/dev/null || true
}
xfcc() { printf 'By=spiffe://%s/ns/%s/sa/verification-service;Hash=00;Subject="";URI=%s' "$td" "$ns" "$1"; }

step "Image from the working tree"
docker build -q -f deployment/docker/verification-service/Dockerfile -t "$host_reg/verification-service:verify" . >/dev/null

step "Cluster, registry, inert Istio CRDs"
if kind get clusters | grep -Fxq "$cluster" || docker inspect "$reg_name" >/dev/null 2>&1; then
  echo "refusing to replace an existing local cluster or registry" >&2; exit 1
fi
cluster_owned=true
kind create cluster --name "$cluster" --image "$KIND_NODE_IMAGE" --wait 120s --config - <<'EOF' >/dev/null
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry]
      config_path = "/etc/containerd/certs.d"
EOF
curl -fsSL "https://raw.githubusercontent.com/istio/istio/${ISTIO_CRDS_VERSION}/manifests/charts/base/files/crd-all.gen.yaml" -o "$work/istio-crds.yaml"
printf '%s  %s\n' "$ISTIO_CRDS_SHA256" "$work/istio-crds.yaml" | sha256sum -c - >/dev/null
kubectl apply --server-side -f "$work/istio-crds.yaml" >/dev/null
registry_owned=true
docker run -d --name "$reg_name" --network kind -p "$host_reg:5000" "$REGISTRY_IMAGE" >/dev/null
for node in $(kind get nodes --name "$cluster"); do
  docker exec "$node" mkdir -p "/etc/containerd/certs.d/$reg"
  printf '[host."http://%s"]\n' "$reg" | docker exec -i "$node" cp /dev/stdin "/etc/containerd/certs.d/$reg/hosts.toml"
done
docker push -q "$host_reg/verification-service:verify" >/dev/null
digest=$(docker image inspect --format '{{index .RepoDigests 0}}' "$host_reg/verification-service:verify" | sed 's/.*@//')
echo "image $reg/verification-service@$digest" | tee "$out/image.txt"

step "PostgreSQL, OpenBao, credentials and trust for this run"
kubectl create namespace "$ns" >/dev/null
bao_root=$(openssl rand -hex 16)
kubectl -n "$ns" apply -f - <<EOF >/dev/null
apiVersion: apps/v1
kind: Deployment
metadata: {name: postgres}
spec:
  selector: {matchLabels: {app: postgres}}
  template:
    metadata: {labels: {app: postgres}}
    spec:
      containers:
        - name: postgres
          image: "$POSTGRES_IMAGE"
          env: [{name: POSTGRES_PASSWORD, value: verify}, {name: POSTGRES_DB, value: verification}]
          readinessProbe: {exec: {command: [pg_isready, -h, 127.0.0.1, -U, postgres]}, periodSeconds: 2}
---
apiVersion: v1
kind: Service
metadata: {name: postgres}
spec: {selector: {app: postgres}, ports: [{port: 5432}]}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: openbao}
spec:
  selector: {matchLabels: {app: openbao}}
  template:
    metadata: {labels: {app: openbao}}
    spec:
      containers:
        - name: openbao
          image: "$OPENBAO_IMAGE"
          args: [server, -dev]
          env: [{name: BAO_DEV_LISTEN_ADDRESS, value: "0.0.0.0:8200"}, {name: BAO_DEV_ROOT_TOKEN_ID, value: "$bao_root"}, {name: SKIP_SETCAP, value: "true"}]
          readinessProbe: {httpGet: {path: /v1/sys/health, port: 8200}, periodSeconds: 2}
---
apiVersion: v1
kind: Service
metadata: {name: openbao}
spec: {selector: {app: openbao}, ports: [{port: 8200}]}
EOF
kubectl -n "$ns" rollout status deploy/postgres deploy/openbao --timeout=180s >/dev/null
printf '%s\n' "$bao_root" | kubectl -n "$ns" exec -i deploy/openbao -- \
  sh -c 'IFS= read -r BAO_TOKEN; export BAO_TOKEN BAO_ADDR=http://127.0.0.1:8200; bao secrets enable transit' >/dev/null
kubectl -n "$ns" create secret generic verification-service-database \
  --from-literal=url='postgres://postgres:verify@postgres:5432/verification?sslmode=disable' >/dev/null
kubectl -n "$ns" create secret generic verification-service-credentials --from-literal=openbao-token="$bao_root" >/dev/null
# The run's credential issuer: a fresh P-256 key, its public JWK in the issuer keys, and the
# FIXTURE trust list listing it as an active service.
openssl ecparam -name prime256v1 -genkey -noout -out "$work/issuer.pem" 2>/dev/null
openssl pkey -in "$work/issuer.pem" -pubout -outform DER -out "$work/issuer.der"
x=$(tail -c 64 "$work/issuer.der" | head -c 32 | b64url)
y=$(tail -c 32 "$work/issuer.der" | b64url)
issuer=https://issuer.zone-a.trust.invalid
jq -n --arg iss "$issuer" --arg x "$x" --arg y "$y" \
  '{($iss): {keys: [{kty: "EC", crv: "P-256", x: $x, y: $y, kid: "issuer-1"}]}}' > "$work/issuer-keys.json"
jq -n --arg iss "$issuer" '{TrustServiceStatusList: {FrameworkInformation: {FrameworkName: {Name: "FIXTURE pinned trust list"}},
  TrustServiceProviderList: {TrustServiceProvider: [{TSPServices: {TSPService: [{ServiceTypeIdentifier: $iss, ServiceCurrentStatus: "active"}]}}]}}}' \
  > "$work/trust-list.fixture.json"
kubectl -n "$ns" create configmap verification-service-trust \
  --from-file=issuer-keys.json="$work/issuer-keys.json" --from-file=trust-list.fixture.json="$work/trust-list.fixture.json" >/dev/null

step "Install the chart"
helm install verification-service deployment/helm/verification-service -n "$ns" --wait --timeout 3m \
  --set image.repository="$reg/verification-service" --set image.digest="$digest" \
  --set issuer=https://verification.zone-a.trust.invalid --set "callers={$store_id}" \
  --set database.existingSecret=verification-service-database --set openbao.address=http://openbao:8200 \
  --set openbao.existingSecret=verification-service-credentials --set trust.existingConfigMap=verification-service-trust \
  --set trust.fixtureTrustListKey=trust-list.fixture.json \
  --set "acceptedVCT={https://facis.example/credentials/participant}" \
  --set "statusPrefixes={https://status.zone-a.trust.invalid/lists/}" --set mesh.trustDomain="$td" >/dev/null \
  && pass "helm install --wait: the release is ready (database, outcome key in transit, trust set)" \
  || fail "helm install --wait did not become ready"
kubectl -n "$ns" get peerauthentication,destinationrule verification-service -o json \
  | jq '[.items[] | {kind, mtls: .spec.mtls, tls: .spec.trafficPolicy.tls}]' > "$out/mesh-resources.json"
jq -e --arg san "spiffe://$td/ns/$ns/sa/verification-service" \
  'any(.[]; .mtls.mode == "STRICT") and any(.[]; .tls.mode == "ISTIO_MUTUAL" and .tls.subjectAltNames == [$san])' "$out/mesh-resources.json" >/dev/null \
  && pass "PeerAuthentication STRICT and DestinationRule ISTIO_MUTUAL pinned to the service's SPIFFE ID are applied" \
  || fail "mesh resources: $(cat "$out/mesh-resources.json")"

kubectl -n "$ns" exec deploy/verification-service -- /verification-service trust-set > "$out/trust-set.json"
jq -e '."https://verification.zone-a.trust.invalid".keys[0] | .kty == "EC" and .crv == "P-256" and (.kid | endswith("-v1")) and (has("d") | not)' \
  "$out/trust-set.json" >/dev/null && pass "trust-set prints the outcome key's public JWK (no private member)" || fail "trust-set: $(cat "$out/trust-set.json")"

step "Callers"
kubectl proxy --port=0 --address=127.0.0.1 >"$work/proxy.log" 2>&1 &
proxy_pid=$!
for _ in $(seq 1 50); do
  proxy_port=$(sed -n 's/.*127\.0\.0\.1:\([0-9]*\).*/\1/p' "$work/proxy.log" | head -1)
  [ -n "$proxy_port" ] && break
  sleep 0.2
done
challenge=$(openssl rand -hex 24)
body=$(jq -nc --arg ch "$challenge" --arg exp "$(date -u -v+90S +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '+90 seconds' +%Y-%m-%dT%H:%M:%SZ)" \
  '{challenge: $ch, client_id: "zone-a-token-store", audience: "https://api.zone-b.trust.invalid", expires_at: $exp}')
check() {
  local want=$1 label=$2 code
  shift 2
  code=$(call "$@")
  echo "$label -> $code $(cat "$work/body" 2>/dev/null)" >> "$out/calls.txt"
  if [ "$code" = "$want" ]; then pass "$label: $code"; else fail "$label: $code, want $want ($(cat "$work/body" 2>/dev/null))"; fi
}
json=(-H 'Content-Type: application/json' --data "$body")
check 403 "no forwarded mesh identity" POST 8080 /v1/requests "" "${json[@]}"
check 403 "another workload's identity" POST 8080 /v1/requests "$(xfcc "spiffe://$td/ns/ztd-data/sa/participant")" "${json[@]}"
check 403 "two forwarded certificates (a forged one next to the sidecar's)" POST 8080 /v1/requests "$(xfcc "spiffe://$td/ns/ztd-data/sa/participant")|$(xfcc "$store_id")" "${json[@]}"
check 201 "the declared caller opens a request" POST 8080 /v1/requests "$(xfcc "$store_id")" "${json[@]}"
id=$(jq -r .request_id "$work/body")
check 400 "the same challenge again" POST 8080 /v1/requests "$(xfcc "$store_id")" "${json[@]}"
check 200 "the declared caller answers with a non-credential: a signed failed outcome" POST 8080 "/v1/responses/$id" "$(xfcc "$store_id")" \
  -H 'Content-Type: application/x-www-form-urlencoded' --data 'vp_token=not-a-credential'
jq -e '.status == "failed" and .reason_code == "CRED-INVALID"' "$work/body" >/dev/null && pass "the outcome says failed/CRED-INVALID" || fail "outcome $(cat "$work/body")"
check 404 "the request answered again" POST 8080 "/v1/responses/$id" "$(xfcc "$store_id")" \
  -H 'Content-Type: application/x-www-form-urlencoded' --data 'vp_token=not-a-credential'
kubectl -n "$ns" exec deploy/postgres -- psql -U postgres -d verification -Atc \
  "SELECT request_id, consumed_at IS NOT NULL, status, reason_code, detail FROM verification_request" > "$out/requests.txt"
grep -q "^$id|t|failed|CRED-INVALID|malformed-presentation$" "$out/requests.txt" \
  && pass "the request is recorded consumed, with its outcome and detail" || fail "records: $(cat "$out/requests.txt")"

step "Readiness without PostgreSQL"
kubectl -n "$ns" scale deploy/postgres --replicas=0 >/dev/null
kubectl -n "$ns" wait --for=condition=Ready=false pod -l "$sel" --timeout=120s >/dev/null 2>&1 \
  && pass "with PostgreSQL gone the pod leaves Ready" || fail "with PostgreSQL gone the pod stayed Ready"
kubectl -n "$ns" scale deploy/postgres --replicas=1 >/dev/null
kubectl -n "$ns" wait --for=condition=Ready pod -l "$sel" --timeout=180s >/dev/null 2>&1 \
  && pass "with PostgreSQL back the pod is Ready again" || fail "the pod did not come back Ready"
kubectl -n "$ns" logs deploy/verification-service > "$out/service-log.json" 2>&1 || true
if grep -q "$bao_root" "$out/service-log.json" "$out"/*.txt; then fail "the OpenBao token reached a record"; else pass "no record carries the OpenBao token"; fi

{
  echo "Verification-service chart on kind ($(date -u +%Y-%m-%dT%H:%M:%SZ), commit $(git rev-parse HEAD))"
  echo
  cat "$out/run.txt"
  echo
  if [ "$failures" -eq 0 ]; then echo "verdict: PASS"; else echo "verdict: FAIL ($failures)"; fi
} > "$out/verdict.txt"
cat "$out/verdict.txt"
[ "$failures" -eq 0 ]
