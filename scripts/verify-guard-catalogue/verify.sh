#!/usr/bin/env bash
# The guard's negative-case catalogue through the deployed chain on a throwaway kind cluster
# (README.md next to this file). Everything on the path is the working tree's or pinned: the guard
# chart (Envoy with the ext_authz hook, the policy evaluator), the protected resource, the token
# store and the connector, on PostgreSQL and OpenBao, every pod in one namespace with an Istio
# sidecar (istiod with its own CA, trust domain cluster.local; the zone's SPIRE chain is proven by
# scripts/verify-mesh-identity, not here) and the zone's XFCC sanitization. The caller is a meshed
# pod with the Participant's service account; it obtains its token through the verified-presentation
# grant and signs every proof itself. Each case records the caller's status and reason code, the
# guard's and, when policy decided, the policy's IF-01 v2 decision event under the correlation id the
# caller received; the allowed request is followed to the resource's log and through the feed bridge.
#
#   scripts/verify-guard-catalogue/verify.sh [--out DIR]   default .dev/guard-catalogue (git-ignored)
#   BIN=<dir with kind and kubectl> ...                      default .tools/bin
#
# --tsa runs the guarding proof instead of the catalogue, on the same chain: the guard's decisions
# are taken by the Rego bundle in the XFSC TSA policy service (deployment/helm/tsa-policy, meshed, a
# bundle published and signed for the run), the policy rules of the guard chart are not set, and
# the guard serves a gRPC method of the resource beside the REST route. For each protocol: an
# entitled request passes, an unentitled one is denied and one that needs a presentation is
# answered with the OID4VP link, each with the guard's and the policy's decision event under the
# bundle's revision, and no denied request in the resource's record. Records: cases.jsonl.
# It needs a linux cosign in BIN (scripts/tools/install.sh <dir> cosign).
#
# --participant runs the participant-backend mock proof instead of the catalogue, on the same chain:
# the Participant service in token mode, installed in the mesh from its chart, bootstraps at the
# Connector and calls the resource through the guard; its registration, request and status events
# are read back from the feed bridge, and the receivers' sidecars name the identities of every hop
# (participant.sh).
#
# Needs docker, go, helm, kind, kubectl, curl, jq, openssl. KEEP=1 leaves the cluster running.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env
if [ -d "${BIN:-.tools/bin}" ]; then PATH="$(cd "${BIN:-.tools/bin}" && pwd):$PATH"; export PATH; fi

out=.dev/guard-catalogue
tsa=false
mock=false
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    --tsa) tsa=true; shift ;;
    --participant) mock=true; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
for tool in docker go helm kind kubectl curl jq openssl; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 2; }
done
if [ "$tsa" = true ] && [ "$mock" = true ]; then echo "--tsa and --participant are separate proofs" >&2; exit 2; fi
mkdir -p "$out"
out="$(cd "$out" && pwd)"
rm -rf "${out:?}"/*

cluster=${GUARD_CATALOGUE_KIND_CLUSTER:-ztd-guard-catalogue}
reg_name=${GUARD_CATALOGUE_REGISTRY_NAME:-kind-registry-guard-catalogue}
reg="$reg_name:5000"
host_reg=${GUARD_CATALOGUE_HOST_REGISTRY:-127.0.0.1:5004}
istio_version=1.31.1   # scripts/install-zone/install.sh: ISTIO_VERSION, ISTIO_ARCHIVE_SHA256
istio_sha256=cb4af2e8a099acfc51368c1d15d4deab8321ae628554d4ee5c74f62ebe775857
ns=ztd-m3
td=cluster.local
guard_id=spiffe://$td/ns/$ns/sa/ztd-guard
issuer=https://connector.verify.invalid
inbound=https://guard.facis.invalid
upstream=https://resource.facis.invalid
published=http://ztd-guard:8080
connector_url=http://ztd-connector:8080
register_url=$connector_url/oauth2/register
token_url=$connector_url/oauth2/token
vp_issuer=https://verifier.verify.invalid
vp_kid=verify
oid4vp='openid4vp://authorize?client_id=verifier.verify.invalid&request_uri=https%3A%2F%2Fverifier.verify.invalid%2Frequest'
lifespan=90          # seconds; the expired case waits it out plus the verifier's 30 s skew; the store's
                     # renewer (every 15 s, at 75 %) keeps the upstream token valid in between
samples=${GUARD_CATALOGUE_SAMPLES:-100}
# --tsa: the TSA's namespace, the bundle's revision, the guarded gRPC method and the resource's port for it.
tsa_ns=ztd-tsa
revision=kind-guarding-1
grpc_method=/grpc.health.v1.Health/Check
grpc_port=9090
toolbox=golang:1.27@sha256:f24164268fc1e741bbdc0066dbadcf1c8426c5a8489f0729c02c3905a53032fd   # as scripts/verify-tsa-policy
images=(connector token-store guard policy-evaluator protected-resource feed-bridge)
if [ "$tsa" = true ]; then
  images+=(tsa-bundle tsa-git)
  [ -x "${BIN:-.tools/bin}/cosign" ] || { echo "--tsa needs a linux cosign in BIN" >&2; exit 2; }
  bin="$(cd "${BIN:-.tools/bin}" && pwd)"
fi
if [ "$mock" = true ]; then images+=(participant); fi
work="$(mktemp -d)"
export KUBECONFIG="$work/kubeconfig"
cluster_owned=false
registry_owned=false

failures=0
pass() { echo "PASS  $*" | tee -a "$out/verdict.txt"; }
fail() { echo "FAIL  $*" | tee -a "$out/verdict.txt"; failures=$((failures + 1)); }
step() { echo; echo "== $*"; }
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  if [ -n "${KEEP:-}" ]; then echo "kept: cluster $cluster, KUBECONFIG=$KUBECONFIG"; return; fi
  if [ "$cluster_owned" = true ]; then kind delete cluster --name "$cluster" >/dev/null 2>&1 || true; fi
  if [ "$registry_owned" = true ]; then docker rm -f "$reg_name" >/dev/null 2>&1 || true; fi
  # The publishing container wrote its keys and bundle as root.
  if [ "$tsa" = true ]; then docker run --rm -v "$work:/w" "$toolbox" chown -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
b64url() { base64 | tr -d '\n=' | tr '+/' '-_'; }
ec_key() { openssl ecparam -name prime256v1 -genkey -noout -out "$1" 2>/dev/null; }
# ec_xy PEM: "x y", base64url, of the key's public point.
ec_xy() {
  openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | tail -c 64 > "$work/point"
  printf '%s %s\n' "$(head -c 32 "$work/point" | b64url)" "$(tail -c 32 "$work/point" | b64url)"
}
# es256 PEM: signs stdin, prints the raw r||s signature base64url.
es256() {
  local ints r s
  openssl dgst -sha256 -sign "$1" -out "$work/sig.der"
  ints=$(openssl asn1parse -inform DER -in "$work/sig.der" | sed -n 's/.*INTEGER *:\([0-9A-F]*\).*/\1/p')
  r=$(printf '%064s' "$(sed -n 1p <<<"$ints" | sed 's/^00//')" | tr ' ' 0)
  s=$(printf '%064s' "$(sed -n 2p <<<"$ints" | sed 's/^00//')" | tr ' ' 0)
  printf '%b' "$(sed 's/../\\x&/g' <<<"$r$s")" | b64url
}
jws() { # jws PEM HEADER-JSON PAYLOAD-JSON
  local input
  input="$(printf '%s' "$2" | b64url).$(printf '%s' "$3" | b64url)"
  printf '%s.%s' "$input" "$(printf '%s' "$input" | es256 "$1")"
}
# dpop_proof PEM HTM HTU ATH NONCE
dpop_proof() {
  local xy
  xy=$(ec_xy "$1")
  jws "$1" "$(jq -nc --arg x "${xy% *}" --arg y "${xy#* }" '{alg: "ES256", typ: "dpop+jwt", jwk: {kty: "EC", crv: "P-256", x: $x, y: $y}}')" \
    "$(jq -nc --arg j "$(hex 16)" --arg m "$2" --arg u "$3" --argjson i "$(date +%s)" --arg a "$4" --arg n "$5" \
      '{jti: $j, htm: $m, htu: $u, iat: $i} + (if $a != "" then {ath: $a} else {} end) + (if $n != "" then {nonce: $n} else {} end)')"
}
ath_of() { printf '%s' "$1" | openssl dgst -sha256 -binary | b64url; }
# ccurl POD OUT ARGS...: curl from POD's curl container, headers and body to OUT; prints the status.
ccurl() {
  local pod=$1 out_file=$2
  shift 2
  # A kubectl exec that never reached the pod (an API server hiccup on a loaded host) writes nothing
  # and is tried again; a request that reached the server always leaves a status line.
  for _ in 1 2 3; do
    kubectl -n "$ns" exec "$pod" -c curl -- curl -sS -m 20 -i "$@" > "$out_file" 2>/dev/null || true
    [ -s "$out_file" ] && break
    sleep 3
  done
  sed -n '1s/^HTTP\/[0-9.]* \([0-9]*\).*/\1/p' "$out_file" | tr -d '\r'
}
body_of() { sed -e '1,/^\r\{0,1\}$/d' "$1"; }
header_of() { grep -i "^$2:" "$1" | head -1 | sed 's/^[^:]*: *//' | tr -d '\r'; }
# dpop_call PEM METHOD URL ATH OUT ARGS...: from the operator pod, once more with the server's nonce.
dpop_call() {
  local pem=$1 method=$2 url=$3 ath=$4 out_file=$5 nonce="" code try
  shift 5
  for try in 1 2; do
    code=$(ccurl operator "$out_file" -X "$method" -H "DPoP: $(dpop_proof "$pem" "$method" "$url" "$ath" "$nonce")" "$@" "$url")
    nonce=$(header_of "$out_file" DPoP-Nonce)
    if [ "$code" -lt 300 ] 2>/dev/null || [ -z "$nonce" ] || [ "$try" = 2 ]; then break; fi
  done
  echo "$code"
}
bao() { # bao ARGS...: the OpenBao CLI in its pod with the root token from stdin's first line
  { printf '%s\n' "$bao_root"; cat; } | kubectl -n "$ns" exec -i deploy/openbao -c openbao -- \
    sh -c 'IFS= read -r BAO_TOKEN; export BAO_TOKEN BAO_ADDR=http://127.0.0.1:8200; exec bao "$@"' sh "$@"
}
pg() { kubectl -n "$ns" exec deploy/postgres -c postgres -- psql -U postgres -d postgres -Atc "$1"; }
wait_until() {
  local deadline=$(( $(date +%s) + $1 ))
  shift
  until "$@"; do
    if [ "$(date +%s)" -ge "$deadline" ]; then return 1; fi
    sleep 2
  done
}

step "Images from the working tree"
for image in "${images[@]}"; do
  docker build -q -f "deployment/docker/$image/Dockerfile" -t "$host_reg/$image:verify" . >/dev/null
done

step "Cluster, registry and the mesh"
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
registry_owned=true
docker run -d --name "$reg_name" --network kind -p "$host_reg:5000" "$REGISTRY_IMAGE" >/dev/null
for node in $(kind get nodes --name "$cluster"); do
  docker exec "$node" mkdir -p "/etc/containerd/certs.d/$reg"
  printf '[host."http://%s"]\n' "$reg" | docker exec -i "$node" cp /dev/stdin "/etc/containerd/certs.d/$reg/hosts.toml"
done
wait_until 20 curl -sf -o /dev/null "http://$host_reg/v2/"
declare -A digest
for image in "${images[@]}"; do
  docker push -q "$host_reg/$image:verify" >/dev/null
  digest[$image]=$(docker image inspect --format '{{index .RepoDigests 0}}' "$host_reg/$image:verify" | sed 's/.*@//')
done
cache=${XDG_CACHE_HOME:-$HOME/.cache}/ztd-install-zone
archive="$cache/istio-$istio_version-linux-amd64.tar.gz"
mkdir -p "$cache"
if [ ! -f "$archive" ] || [ "$(openssl dgst -sha256 -r "$archive" | cut -d' ' -f1)" != "$istio_sha256" ]; then
  curl -fsSL -o "$archive" "https://github.com/istio/istio/releases/download/$istio_version/istio-$istio_version-linux-amd64.tar.gz"
fi
[ "$(openssl dgst -sha256 -r "$archive" | cut -d' ' -f1)" = "$istio_sha256" ] || { echo "Istio archive digest mismatch" >&2; exit 1; }
tar -xzf "$archive" -C "$work" "istio-$istio_version/manifests/charts"
charts="$work/istio-$istio_version/manifests/charts"
helm install istio-base "$charts/base" -n istio-system --create-namespace --wait >/dev/null
helm install istiod "$charts/istio-control/istio-discovery" -n istio-system --set meshConfig.accessLogFile=/dev/stdout \
  --set meshConfig.accessLogEncoding=JSON --wait --timeout 5m >/dev/null
# The zone's caller-identity rule (zone-policy, EnvoyFilter xfcc-sanitize-set), as the zone renders it.
helm template zone-policy deployment/helm/zone-policy -n istio-system --set trustDomain=$td \
  --show-only templates/envoyfilter-xfcc-sanitize.yaml | kubectl apply -n istio-system -f - >/dev/null
kubectl create namespace "$ns" >/dev/null
kubectl label namespace "$ns" istio-injection=enabled >/dev/null
# kind's CNI enforces network policy: the charts' own policies apply. The resource's sidecar reaches
# istiod's xDS and CA port, as the zone's meshControlPlane opening allows (the guard chart opens it
# for its own pods); nothing else is opened here.
kubectl -n "$ns" apply -f - <<'YAML' >/dev/null
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata: {name: strict}
spec: {mtls: {mode: STRICT}}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: mesh-control}
spec:
  podSelector: {matchLabels: {app.kubernetes.io/name: ztd-protected-resource}}
  policyTypes: [Egress]
  egress:
    - to: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: istio-system}}, podSelector: {matchLabels: {app: istiod}}}]
      ports: [{port: 15012, protocol: TCP}]
YAML
pass "kind with Istio $istio_version (istiod CA, trust domain $td), XFCC sanitized mesh-wide, namespace $ns STRICT"

if [ "$tsa" = true ]; then
  step "The TSA policy service with the run's signed Rego bundle"
  # The zone's data for this cluster: the guard's audience and host, the Participant, the guarded gRPC
  # method and the scope that needs a presentation. Nothing of it is in the guard chart's values.
  jq --arg aud "$inbound" --arg host "${published#http://}" --arg p "spiffe://$td/ns/$ns/sa/ztd-participant" --arg m "$grpc_method" --arg link "$oid4vp" \
    '.config += {audience: $aud, host: $host, participant_callers: [$p], grpc_methods: [$m], presentation: {scopes: ["report:full"], oid4vp_link: $link}}' \
    policies/tsa/facis/guard/1.0/data.json > "$work/zone-data.json"
  cp "$work/zone-data.json" "$out/bundle-data.json"
  case "$(docker exec "$cluster-control-plane" uname -m)" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; *) echo "unsupported node" >&2; exit 1 ;; esac
  GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -o "$work/tsa-bundle" ./cmd/tsa-bundle
  # shellcheck disable=SC2016 # expanded in the toolbox
  cat > "$work/publish.sh" <<'EOF'
set -euo pipefail
cd /src
export COSIGN_PASSWORD= COSIGN=/tools/cosign TSA_BUNDLE=/w/tsa-bundle COSIGN_ALLOW_HTTP_REGISTRY=true
mkdir -p /w/trusted
(cd /w/trusted && /tools/cosign generate-key-pair >/dev/null 2>&1)
COSIGN_KEY=/w/trusted/cosign.key bash scripts/supplychain/publish-tsa-bundle.sh policies/tsa/facis/guard/1.0 "$REVISION" \
  "$REG/tsa-bundles" /w/trusted/cosign.pub /w/zone-data.json 2>/dev/null > /w/bundle-ref
EOF
  docker run --rm --network kind -e REG="$reg" -e REVISION="$revision" -v "$work:/w" -v "$bin:/tools:ro" -v "$root:/src:ro" "$toolbox" bash /w/publish.sh
  bundle_ref=$(cat "$work/bundle-ref")
  reg_ip=$(docker inspect -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}' "$reg_name")
  kubectl create namespace "$tsa_ns" >/dev/null
  kubectl label namespace "$tsa_ns" istio-injection=enabled >/dev/null
  if helm install tsa deployment/helm/tsa-policy -n "$tsa_ns" \
    --set images.tsa.repository="${TSA_POLICY_IMAGE%%:*}" --set images.nats.repository="${NATS_IMAGE%%:*}" \
    --set images.git.repository="$reg/tsa-git" --set images.git.digest="${digest[tsa-git]}" \
    --set images.bundle.repository="$reg/tsa-bundle" --set images.bundle.digest="${digest[tsa-bundle]}" \
    --set bundle.repository="$reg/tsa-bundles" --set-json "bundle.plainHTTPRegistries=[\"$reg\"]" --set bundle.pollSeconds=2 \
    --set bundle.ref="$bundle_ref" --set bundle.revision="$revision" --set-file trustRoot="$work/trusted/cosign.pub" \
    --set trustDomain=$td --set-json "callers=[{\"namespace\":\"$ns\",\"name\":\"ztd-policy-evaluator\"}]" \
    --set networkPolicy.istiod.enabled=true --set-json 'podAnnotations={"sidecar.istio.io/nativeSidecar":"true"}' \
    --set-json "networkPolicy.egress=[{\"to\":[{\"ipBlock\":{\"cidr\":\"$reg_ip/32\"}}],\"ports\":[{\"protocol\":\"TCP\",\"port\":5000}]}]" \
    --wait --timeout 8m > "$out/tsa-install.txt" 2>&1; then
    pass "the TSA policy service is ready in the mesh: bundle $revision ($bundle_ref) verified and active"
  else
    fail "tsa install: $(tail -3 "$out/tsa-install.txt")"
  fi
fi

step "PostgreSQL, OpenBao, the connector and the token store"
curl_image=$(sed -n 's/^ *image: *\(docker\.io\/curlimages\/curl:[^ ]*\).*/\1/p' deployment/helm/ztd/values.yaml | head -1)
bao_root=$(hex 16)
pod_spec() { # pod_spec NAME SA LABEL: a meshed curl pod
  cat <<EOF
apiVersion: v1
kind: ServiceAccount
metadata: {name: $2}
---
apiVersion: v1
kind: Pod
metadata:
  name: $1
  labels: {app.kubernetes.io/name: $3}
spec:
  serviceAccountName: $2
  containers:
    - name: curl
      image: "$curl_image"
      command: [sh, -c, 'while true; do sleep 3600; done']
---
EOF
}
{
  pod_spec operator operator operator
  pod_spec ui ztd-ui ztd-ui
  pod_spec participant ztd-participant ztd-participant
  pod_spec intruder intruder ztd-participant
  cat <<EOF
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
          env: [{name: POSTGRES_PASSWORD, value: verify}]
          readinessProbe: {exec: {command: [pg_isready, -h, 127.0.0.1, -U, postgres]}, periodSeconds: 2}
---
apiVersion: v1
kind: Service
metadata: {name: postgres}
spec: {selector: {app: postgres}, ports: [{name: tcp-postgres, port: 5432}]}
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
          env:
            - {name: BAO_DEV_LISTEN_ADDRESS, value: "0.0.0.0:8200"}
            - {name: BAO_DEV_ROOT_TOKEN_ID, value: "$bao_root"}
            - {name: SKIP_SETCAP, value: "true"}
          readinessProbe: {httpGet: {path: /v1/sys/health, port: 8200}, periodSeconds: 2}
---
apiVersion: v1
kind: Service
metadata: {name: openbao}
spec: {selector: {app: openbao}, ports: [{name: http, port: 8200}]}
EOF
} > "$work/base.yaml"
# The injector is istiod's webhook: on a loaded host it can answer late after the install returns.
kubectl -n istio-system rollout status deploy/istiod --timeout=300s >/dev/null
for try in 1 2 3 4 5; do
  if kubectl -n "$ns" apply -f "$work/base.yaml" >/dev/null 2>"$work/apply.err"; then break; fi
  [ "$try" = 5 ] && { cat "$work/apply.err" >&2; exit 1; }
  sleep 15
done
kubectl -n "$ns" rollout status deploy/postgres deploy/openbao --timeout=300s >/dev/null
kubectl -n "$ns" wait --for=condition=Ready pod/operator pod/participant pod/intruder pod/ui --timeout=300s >/dev/null
pg "CREATE DATABASE connector" >/dev/null
pg "CREATE DATABASE tokenstore" >/dev/null
bao secrets enable transit </dev/null >/dev/null
bao write -f transit/keys/connector type=ecdsa-p256 </dev/null >/dev/null
connector_token=$(bao token create -policy=root -ttl=2h -format=json </dev/null | jq -r .auth.client_token)

ec_key "$work/issuer-private.pem"
openssl ec -in "$work/issuer-private.pem" -pubout -out "$work/issuer.pem" 2>/dev/null
xy=$(ec_xy "$work/issuer-private.pem")
jq -n --arg iss "$vp_issuer" --arg kid "$vp_kid" --arg x "${xy% *}" --arg y "${xy#* }" \
  '{($iss): {keys: [{kty: "EC", crv: "P-256", x: $x, y: $y, kid: $kid}]}}' > "$work/issuers.json"
jq -n '[{role: "viewer", scopes: ["report:summary"]}, {role: "unrelated", scopes: ["other:read"]}, {role: "full", scopes: ["report:full"]}]' > "$work/scopes.json"
kubectl -n "$ns" create configmap connector-vp --from-file="$work/issuers.json" --from-file="$work/scopes.json" >/dev/null
registrar_secret=$(hex 24)
kubectl -n "$ns" create secret generic connector-credentials --from-literal=openbao-token="$connector_token" \
  --from-literal=token-secret="$(hex 32)" --from-literal=registration-secret="$(hex 32)" --from-literal=registrar-secret="$registrar_secret" \
  --from-literal=database-url="postgres://postgres:verify@postgres:5432/connector?sslmode=disable" \
  --from-literal=store-database-url="postgres://postgres:verify@postgres:5432/tokenstore?sslmode=disable" >/dev/null
# one_off NAME SECRET-KEY ARGS...: the store's image as a one-off meshed pod (native sidecar, so it
# completes) with that database URL, the store's credentials and acquisition config mounted as the
# store mounts them; prints its final phase, its output to NAME.txt.
one_off() {
  local name=$1 key=$2 phase=""
  shift 2
  kubectl -n "$ns" apply -f - <<EOF >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: $name
  annotations: {sidecar.istio.io/nativeSidecar: "true"}
spec:
  restartPolicy: Never
  containers:
    - name: tool
      image: "$reg/token-store@${digest[token-store]}"
      args: $(printf '%s\n' "$@" | jq -R . | jq -sc .)
      env:
        - {name: TOKEN_STORE_DATABASE_URL, valueFrom: {secretKeyRef: {name: connector-credentials, key: $key}}}
        - {name: TOKEN_STORE_OPENBAO_URL, value: http://openbao:8200}
        - {name: TOKEN_STORE_OPENBAO_TOKEN_FILE, value: /var/run/token-store/credentials/openbao-token}
        - {name: TOKEN_STORE_ACQUIRE_CONFIG, value: /etc/token-store/acquisition.json}
      volumeMounts:
        - {name: acquisition, mountPath: /etc/token-store}
        - {name: credentials, mountPath: /var/run/token-store/credentials}
  volumes:
    - {name: acquisition, configMap: {name: ztd-token-store-acquisition, optional: true}}
    - {name: credentials, secret: {secretName: ztd-token-store-credentials, optional: true}}
EOF
  for _ in $(seq 1 90); do
    phase=$(kubectl -n "$ns" get pod "$name" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    case "$phase" in Succeeded|Failed) break ;; esac
    sleep 2
  done
  kubectl -n "$ns" logs "$name" -c tool > "$out/$name.txt" 2>&1 || true
  kubectl -n "$ns" delete pod "$name" --wait=false >/dev/null 2>&1 || true
  echo "$phase"
}
if [ "$(one_off migrate-connector database-url migrate up)" = Succeeded ] && [ "$(one_off migrate-store store-database-url migrate up)" = Succeeded ]; then
  pass "the shared schema is applied to the connector's and the store's databases"
else
  fail "migrations: $(tail -3 "$out/migrate-connector.txt" "$out/migrate-store.txt" 2>/dev/null | tr '\n' ' ')"
fi
kubectl -n "$ns" apply -f - <<EOF >/dev/null
apiVersion: v1
kind: ServiceAccount
metadata: {name: ztd-connector}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: ztd-connector}
spec:
  selector: {matchLabels: {app.kubernetes.io/name: ztd-connector}}
  template:
    metadata:
      labels: {app.kubernetes.io/name: ztd-connector}
      annotations: {sidecar.istio.io/nativeSidecar: "true"}
    spec:
      serviceAccountName: ztd-connector
      containers:
        - name: connector
          image: "$reg/connector@${digest[connector]}"
          args: [serve, --issuer=$issuer, --signing-key=connector, --signing-key-version=1, --registration-endpoint=$register_url,
            --openbao-token-file=/run/c/openbao-token, --token-secret-file=/run/c/token-secret, --registration-secret-file=/run/c/registration-secret,
            --registrar-id=registrar, --registrar-secret-file=/run/c/registrar-secret, --registrar-scopes=connector:client_registration,
            "--registrar-audiences=$register_url,$inbound,$upstream", "--registrar-delegable-scopes=report:summary,other:read,report:full",
            --vp-trusted-issuers-file=/etc/connector/issuers.json, --vp-scope-map-file=/etc/connector/scopes.json,
            --access-token-lifespan=${lifespan}s, --drain-delay=0s, --zone=b]
          env:
            - {name: CONNECTOR_DATABASE_URL, valueFrom: {secretKeyRef: {name: connector-credentials, key: database-url}}}
            - {name: CONNECTOR_OPENBAO_URL, value: http://openbao:8200}
          readinessProbe: {httpGet: {path: /readyz, port: 9090}, periodSeconds: 2}
          volumeMounts: [{name: vp, mountPath: /etc/connector}, {name: c, mountPath: /run/c}]
      volumes:
        - {name: vp, configMap: {name: connector-vp}}
        - {name: c, secret: {secretName: connector-credentials}}
---
apiVersion: v1
kind: Service
metadata: {name: ztd-connector}
spec: {selector: {app.kubernetes.io/name: ztd-connector}, ports: [{name: http, port: 8080}]}
EOF
if kubectl -n "$ns" rollout status deploy/ztd-connector --timeout=180s >/dev/null 2>&1; then pass "the connector is ready"; else fail "connector: $(kubectl -n "$ns" logs deploy/ztd-connector -c connector --tail=5 2>&1 | tr '\n' ';')"; fi

# The registrar's DPoP-bound registration token, then one client per role (register NAME SCOPE AUD).
ec_key "$work/registrar.pem"
code=$(dpop_call "$work/registrar.pem" POST "$token_url" "" "$work/registrar.http" -u "registrar:$registrar_secret" \
  --data-urlencode grant_type=client_credentials --data-urlencode scope=connector:client_registration \
  --data-urlencode "audience=$register_url $inbound $upstream")
registration_token=$(body_of "$work/registrar.http" | jq -r '.access_token // empty')
[ "$code" = 200 ] && [ -n "$registration_token" ] || { fail "registrar token: $code"; exit 1; }
register() {
  local code
  code=$(dpop_call "$work/registrar.pem" POST "$register_url" "$(ath_of "$registration_token")" "$work/register-$1.http" \
    -H "Authorization: DPoP $registration_token" -H 'Content-Type: application/json' --data-binary \
    "$(jq -nc --arg n "$1" --arg s "$2" --arg a "$3" '{client_name: $n, grant_types: ["urn:facis:params:oauth:grant-type:verified-presentation"],
      token_endpoint_auth_method: "client_secret_basic", scope: $s, dpop_bound_access_tokens: true, audience: [$a]}')")
  [ "$code" = 201 ] || { fail "registration $1: $code"; exit 1; }
  body_of "$work/register-$1.http" | jq -r '.client_id + " " + .client_secret'
}
read -r route_id route_secret < <(register store-route report:summary "$upstream")
read -r viewer_id viewer_secret < <(register viewer report:summary "$inbound")
read -r blocked_id blocked_secret < <(register blocked report:summary "$inbound")
read -r unrelated_id unrelated_secret < <(register unrelated other:read "$inbound")
read -r full_id full_secret < <(register full report:full "$inbound")
pass "five clients registered: the store's route (upstream audience) and four participants (inbound audience)"

store_token=$(bao token create -policy=root -ttl=2h -format=json </dev/null | jq -r .auth.client_token)
kubectl -n "$ns" create secret generic ztd-token-store-credentials --from-literal=openbao-token="$store_token" \
  --from-literal=client-secret="$route_secret" --from-file=issuer-private.pem="$work/issuer-private.pem" >/dev/null
kubectl -n "$ns" create secret generic token-store-database \
  --from-literal=url="postgres://postgres:verify@postgres:5432/tokenstore?sslmode=disable" >/dev/null
jq -n --arg iss "$vp_issuer" --arg kid "$vp_kid" --arg aud "$upstream" --arg url "$connector_url" --arg cid "$route_id" \
  --arg guard "$guard_id" --arg prefix "$published/$([ "$tsa" = true ] || echo demo)" '{signing_key: "ztd-token-store", kv_prefix: "ztd/token-store/upstream",
  trusted_issuers: [{issuer: $iss, kid: $kid, public_key_file: "/etc/token-store/issuer.pem"}],
  routes: [{name: "report-summary", peer_zone: "zone-b", audience: $aud, tenant: "report-summary", connector_url: $url, client_id: $cid,
    client_secret_file: "/var/run/token-store/credentials/client-secret", callers: [$guard], methods: ["POST"], target_prefix: $prefix,
    fixture_outcomes: {issuer: $iss, kid: $kid, private_key_file: "/var/run/token-store/credentials/issuer-private.pem", role: "viewer", validity_seconds: 90}}]}' \
  > "$work/acquisition.json"
kubectl -n "$ns" create configmap ztd-token-store-acquisition --from-file="$work/acquisition.json" --from-file=issuer.pem="$work/issuer.pem" >/dev/null
if [ "$(one_off keys-ensure store-database-url keys ensure)" = Succeeded ]; then pass "keys ensure created and registered the store's signing key"; else fail "keys ensure: $(tail -3 "$out/keys-ensure.txt")"; fi
if helm install ztd-token-store deployment/helm/token-store -n "$ns" --set runtime.enabled=true \
  --set runtime.existingConfigMap=ztd-token-store-acquisition --set runtime.credentialsSecret=ztd-token-store-credentials \
  --set-json "runtime.replayCallers=[\"$guard_id\"]" --set networkPolicy.enabled=true \
  --set-json 'networkPolicy.ingressFrom=[{"podSelector":{}}]' --set-json 'networkPolicy.egress=[{}]' \
  --set-json 'networkPolicy.schemaEgress=[{"to":[{"podSelector":{"matchLabels":{"app":"postgres"}}}],"ports":[{"port":5432,"protocol":"TCP"}]},{}]' \
  --set "image.repository=$reg/token-store" --set "image.digest=${digest[token-store]}" --set database.existingSecret=token-store-database \
  --set openbao.address=http://openbao:8200 --wait --wait-for-jobs --timeout 5m > "$out/token-store-install.txt" 2>&1; then
  pass "the token store is ready in runtime mode, the guard its only replay and substitution caller"
else
  fail "token store install: $(tail -3 "$out/token-store-install.txt")"
fi

step "The guarded chain: resource, guard and policy evaluator from their charts"
cat > "$work/resource-values.yaml" <<EOF
name: ztd-protected-resource
image: {repository: $reg/protected-resource, digest: "${digest[protected-resource]}"}
serviceAccount: {create: true, name: ztd-protected-resource}
ingress: {enabled: false}
env:
  PROTECTED_RESOURCE_MODE: token
  PROTECTED_RESOURCE_ADDRESS: ":8080"
  PROTECTED_RESOURCE_TOKEN_ISSUER: $issuer
  PROTECTED_RESOURCE_JWKS_URL: $connector_url/.well-known/jwks.json
  PROTECTED_RESOURCE_AUDIENCE: $upstream
  PROTECTED_RESOURCE_PUBLIC_BASE_URL: $published
networkPolicy:
  ingressFrom: []
  egress: [{to: [{podSelector: {matchLabels: {app.kubernetes.io/name: ztd-connector}}}], ports: [{port: 8080, protocol: TCP}]}]
EOF
resource_grpc=()
if [ "$tsa" = true ]; then resource_grpc=(--set "grpcPort=$grpc_port" --set "env.PROTECTED_RESOURCE_GRPC_ADDRESS=:$grpc_port"); fi
if helm install ztd-resource deployment/helm/application-service -n "$ns" -f "$work/resource-values.yaml" ${resource_grpc[@]+"${resource_grpc[@]}"} --wait --timeout 5m \
  > "$out/resource-install.txt" 2>&1; then
  pass "the protected resource is ready in token mode"
else
  fail "resource install: $(tail -3 "$out/resource-install.txt")"
fi
resource_port=$(kubectl -n "$ns" get svc ztd-protected-resource -o jsonpath='{.spec.ports[0].port}')
envoy_repo=${ENVOY_IMAGE%%:*}
cat > "$work/guard-values.yaml" <<EOF
zone: b
trustDomain: $td
resourcePort: $resource_port
images:
  guard: {repository: $reg/guard, digest: "${digest[guard]}"}
  policy: {repository: $reg/policy-evaluator, digest: "${digest[policy-evaluator]}"}
  envoy: {repository: $envoy_repo, digest: "${ENVOY_IMAGE##*@}"}
config:
  issuer: $issuer
  jwks_url: $connector_url/.well-known/jwks.json
  inbound_audience: $inbound
  upstream_audience: $upstream
  published_base_url: $published
  peer_zone: zone-b
policyRevision: kind-catalogue-1
podAnnotations: {sidecar.istio.io/nativeSidecar: "true"}
EOF
if [ "$tsa" = true ]; then
  # No policy rules in the chart: every decision is the bundle's.
  cat >> "$work/guard-values.yaml" <<EOF
tsa: {evaluationURL: "http://tsa-policy-engine.$tsa_ns:8080/policy/policies/facis/guard/1.0/evaluation"}
grpc: {methods: ["$grpc_method"], resourcePort: $grpc_port}
networkPolicy:
  istiod: {enabled: true}
  egress:
    - to: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: $tsa_ns}}, podSelector: {matchLabels: {app.kubernetes.io/name: tsa-policy-engine}}}]
      ports: [{protocol: TCP, port: 8080}]
EOF
else
  cat >> "$work/guard-values.yaml" <<EOF
policyRules:
  blockedClients: ["$blocked_id"]
  presentation: {scopes: ["report:full"], oid4vpLink: "$oid4vp"}
networkPolicy: {istiod: {enabled: true}}
EOF
fi
if helm install ztd-guard deployment/helm/guard -n "$ns" -f "$work/guard-values.yaml" --wait --timeout 5m > "$out/guard-install.txt" 2>&1; then
  pass "the guard and the policy evaluator are ready from the chart with values only"
else
  fail "guard install: $(tail -3 "$out/guard-install.txt")"
fi
cp "$work/guard-values.yaml" "$out/guard-values.yaml"

step "The participants' tokens through the verified-presentation grant"
# login ID SECRET ROLE KEY: challenge, an IF-03 outcome from the fixture verifier, the grant; prints the token.
login() {
  local id=$1 secret=$2 role=$3 key=$4 challenge outcome now code
  code=$(ccurl operator "$work/challenge.http" -u "$id:$secret" --data-urlencode "audience=$inbound" "$connector_url/oauth2/challenge")
  challenge=$(body_of "$work/challenge.http" | jq -r '.challenge // empty')
  [ "$code" = 200 ] && [ -n "$challenge" ] || { echo "challenge $code" >&2; return 1; }
  now=$(date -u +%s)
  outcome=$(jws "$work/issuer-private.pem" "$(jq -nc --arg k "$vp_kid" '{alg: "ES256", typ: "facis-verification-outcome+jws", kid: $k}')" \
    "$(jq -nc --arg iss "$vp_issuer" --arg id "$(hex 16)" --arg c "$id" --arg ch "$challenge" --arg a "$inbound" --arg r "$role" \
      --arg at "$(date -u -r "$now" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$now" +%Y-%m-%dT%H:%M:%SZ)" \
      --arg exp "$(date -u -r "$((now + 90))" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$((now + 90))" +%Y-%m-%dT%H:%M:%SZ)" \
      '{iss: $iss, outcome_id: ($id[0:8] + "-" + $id[8:12] + "-4" + $id[13:16] + "-8" + $id[17:20] + "-" + $id[20:32]), client_id: $c,
        challenge: $ch, audience: $a, claims: {role: $r}, status: "verified", verified_at: $at, expires_at: $exp}')")
  code=$(dpop_call "$key" POST "$token_url" "" "$work/grant.http" -u "$id:$secret" \
    --data-urlencode grant_type=urn:facis:params:oauth:grant-type:verified-presentation --data-urlencode "outcome=$outcome" \
    --data-urlencode "challenge=$challenge" --data-urlencode "audience=$inbound")
  [ "$code" = 200 ] || { echo "grant $code $(body_of "$work/grant.http" | head -c 200)" >&2; return 1; }
  body_of "$work/grant.http" | jq -r .access_token
}
for who in viewer blocked unrelated full other; do ec_key "$work/$who.pem"; done
viewer_token=$(login "$viewer_id" "$viewer_secret" viewer "$work/viewer.pem")
blocked_token=$(login "$blocked_id" "$blocked_secret" viewer "$work/blocked.pem")
unrelated_token=$(login "$unrelated_id" "$unrelated_secret" unrelated "$work/unrelated.pem")
full_token=$(login "$full_id" "$full_secret" full "$work/full.pem")
pass "four participant tokens for the guard's audience, each bound to its own key"

# environment: the run's record of what it ran on.
environment() {
  {
    echo "{"
    echo "  \"commit\": \"$(git rev-parse HEAD)\","
    echo "  \"tree\": \"$(if [ -n "$(git status --porcelain)" ]; then echo dirty; else echo clean; fi)\","
    echo "  \"date\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo "  \"host\": \"$(uname -sm)\","
    echo "  \"kube_system_uid\": \"$(kubectl get namespace kube-system -o jsonpath='{.metadata.uid}')\","
    echo "  \"kind_node_image\": \"$KIND_NODE_IMAGE\","
    echo "  \"istio\": \"$istio_version (istiod CA, trust domain $td)\","
    echo "  \"envoy_image\": \"$ENVOY_IMAGE\","
    echo "  \"postgres_image\": \"$POSTGRES_IMAGE\","
    echo "  \"openbao_image\": \"$OPENBAO_IMAGE\","
    if [ "$tsa" = true ]; then
      echo "  \"tsa_policy_image\": \"$TSA_POLICY_IMAGE\","
      echo "  \"bundle_revision\": \"$revision\","
      echo "  \"bundle_ref\": \"$bundle_ref\","
      echo "  \"grpc_method\": \"$grpc_method\","
    fi
    echo "  \"access_token_lifespan_seconds\": $lifespan"
    echo "}"
  } > "$out/environment.json"
}

step "The catalogue"
printf 'case\tstatus\treason_code\trule_id\tcorrelation_id\tguard_event\tpolicy_event\texpected\tverdict\n' > "$out/catalogue.tsv"
# guarded POD NAME TOKEN KEY [PROOF-KEY] [HEADERS...]: one POST /demo through the guard; writes NAME.http.
guarded() {
  local pod=$1 name=$2 token=$3 key=$4 proof_key=${5:-$4} args=()
  shift 5 2>/dev/null || shift $#
  if [ -n "$token" ]; then args+=(-H "Authorization: DPoP $token"); fi
  if [ -n "$proof_key" ] && [ "$proof_key" != none ]; then args+=(-H "DPoP: $(dpop_proof "$proof_key" POST "$published/demo" "$(ath_of "$token")" "")"); fi
  ccurl "$pod" "$out/$name.http" -X POST -H 'Content-Type: application/json' "${args[@]}" "$@" \
    --data '{"resource":"sample-report","action":"read"}' "$published/demo"
}
logs() { kubectl -n "$ns" logs "deploy/ztd-$1" -c "$1" 2>/dev/null; }
event_of() { { logs "$1" || true; } | jq -c --arg id "$2" 'select(.correlation_id? == $id)' 2>/dev/null | head -1 || true; }
# expect NAME STATUS CODE RULE POLICY(yes|no): the caller's answer and the matching decision events.
expect() {
  local name=$1 status=$2 code=$3 rule=$4 policy=$5 got reason got_rule id ge pe ok=yes
  got=$(sed -n '1s/^HTTP\/[0-9.]* \([0-9]*\).*/\1/p' "$out/$name.http" | tr -d '\r')
  reason=$(body_of "$out/$name.http" | jq -r '.reason_code // empty' 2>/dev/null || true)
  got_rule=$(body_of "$out/$name.http" | jq -r '.rule_id // empty' 2>/dev/null || true)
  id=$(header_of "$out/$name.http" x-request-id)
  sleep 1
  ge=$(event_of guard "$id"); pe=$(event_of policy-evaluator "$id")
  [ "$got" = "$status" ] && [ "$reason" = "$code" ] && { [ -z "$rule" ] || [ "$got_rule" = "$rule" ]; } || ok=no
  [ "$(jq -r '.payload.reason_code' <<<"${ge:-null}")" = "$code" ] && [ "$(jq -r .version <<<"${ge:-null}")" = 2 ] || ok=no
  if [ "$policy" = yes ]; then [ "$(jq -r '.payload.rule_id' <<<"${pe:-null}")" = "$rule" ] || ok=no; else [ -z "$pe" ] || ok=no; fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$got" "${reason:--}" "${got_rule:--}" "${id:--}" "${ge:--}" "${pe:--}" \
    "$status $code ${rule:--}" "$ok" >> "$out/catalogue.tsv"
  if [ "$ok" = yes ]; then pass "$name: $got $code${rule:+ ($rule)}, guard event${pe:+ and policy event} under $id"; else fail "$name: got $got ${reason:-} ${got_rule:-}, events: ${ge:-none} / ${pe:-none}"; fi
}

bridge=http://ztd-feed-bridge:8090
# feed_bridge_up: the feed bridge from its chart, in the mesh; the operator's identity is its producer.
feed_bridge_up() {
  if helm install ztd-feed-bridge deployment/helm/feed-bridge -n "$ns" --set "image.repository=$reg/feed-bridge" \
    --set "image.digest=${digest[feed-bridge]}" --set trustDomain=$td --set "ui.namespace=$ns" --set ui.serviceAccount=ztd-ui \
    --set-json "producers=[{\"namespace\":\"$ns\",\"serviceAccount\":\"operator\"}]" --wait --timeout 5m > "$out/feed-bridge-install.txt" 2>&1; then
    pass "the feed bridge is ready from its chart: STRICT mTLS, the UI's identity alone admitted to the feed"
  else
    fail "feed bridge install: $(tail -3 "$out/feed-bridge-install.txt")"
  fi
}

if [ "$tsa" = true ] || [ "$mock" = true ]; then
  if [ "$tsa" = true ]; then
    # shellcheck source=scripts/verify-guard-catalogue/guarding.sh disable=SC1091
    . scripts/verify-guard-catalogue/guarding.sh
  else
    # shellcheck source=scripts/verify-guard-catalogue/participant.sh disable=SC1091
    . scripts/verify-guard-catalogue/participant.sh
  fi
  environment
  echo
  echo "verdict: $([ "$failures" = 0 ] && echo PASS || echo "FAIL ($failures)")" | tee -a "$out/verdict.txt"
  exit "$failures"
fi

# The allowed request first: one correlation id across the guard, the policy, the resource and the feed.
code=$(guarded participant allowed "$viewer_token" "$work/viewer.pem")
id=$(body_of "$out/allowed.http" | jq -r '.requestId // empty' 2>/dev/null || true)
sleep 2
ge=$(event_of guard "$id"); pe=$(event_of policy-evaluator "$id")
re=$(kubectl -n "$ns" logs deploy/ztd-protected-resource -c ztd-protected-resource 2>/dev/null | grep -F "$id" | head -1 || true)
printf 'allowed\t%s\t-\t%s\t%s\t%s\t%s\t200\t%s\n' "$code" "$(jq -r '.payload.rule_id' <<<"${pe:-null}")" "${id:--}" "${ge:--}" "${pe:--}" \
  "$([ "$code" = 200 ] && [ -n "$ge" ] && [ -n "$pe" ] && [ -n "$re" ] && echo yes || echo no)" >> "$out/catalogue.tsv"
printf '%s\n' "$re" > "$out/resource-record.json"
if [ "$code" = 200 ] && [ -n "$id" ] && [ "$(jq -r .payload.state <<<"${ge:-null}")" = allowed ] && [ "$(jq -r .payload.rule_id <<<"${pe:-null}")" = m3-report-summary ] && [ -n "$re" ]; then
  pass "allowed: 200 through the guard; correlation id $id in the guard's and the policy's decision events and the resource's record"
else
  fail "allowed: $code, id ${id:-none}, guard ${ge:-none}, policy ${pe:-none}, resource ${re:-none}"
fi
allowed_id=$id

guarded participant no-token "" none none >/dev/null; expect no-token 401 TOK-MISSING "" no
guarded participant missing-proof "$viewer_token" "$work/viewer.pem" none >/dev/null; expect missing-proof 401 TOK-PROOF-INVALID "" no
guarded participant wrong-proof-key "$viewer_token" "$work/viewer.pem" "$work/other.pem" >/dev/null; expect wrong-proof-key 401 TOK-JKT-MISMATCH "" no
guarded participant insufficient-scope "$unrelated_token" "$work/unrelated.pem" >/dev/null; expect insufficient-scope 403 POL-RULE-DENY m3-scope-required yes
guarded participant policy-only-denial "$blocked_token" "$work/blocked.pem" >/dev/null; expect policy-only-denial 403 POL-RULE-DENY m3-client-blocked yes
guarded participant presentation-required "$full_token" "$work/full.pem" >/dev/null; expect presentation-required 401 POL-PRESENTATION-REQUIRED m3-presentation-required yes
if [ "$(body_of "$out/presentation-required.http" | jq -r '.oid4vp_link // empty')" = "$oid4vp" ]; then pass "presentation-required: the body carries the OID4VP link from the deployed evaluator"; else fail "presentation-required: no OID4VP link"; fi
# The same proof twice: the second use is a replay.
proof=$(dpop_proof "$work/viewer.pem" POST "$published/demo" "$(ath_of "$viewer_token")" "")
for n in replay-first replayed-proof; do
  ccurl participant "$out/$n.http" -X POST -H "Authorization: DPoP $viewer_token" -H "DPoP: $proof" -H 'Content-Type: application/json' \
    --data '{"resource":"sample-report","action":"read"}' "$published/demo" >/dev/null
done
expect replayed-proof 401 TOK-REPLAY "" no
# The upstream audience at the guard: a token the participant can never use there.
code=$(ccurl operator "$work/up-challenge.http" -u "$viewer_id:$viewer_secret" --data-urlencode "audience=$upstream" "$connector_url/oauth2/challenge")
if [ "$code" != 200 ]; then pass "wrong-audience: the participant cannot even obtain a challenge for the resource's audience ($code)"; else fail "wrong-audience: a resource-audience challenge was issued"; fi
# A meshed caller under another service account: refused by the guard's own sidecar (RBAC).
code=$(guarded intruder wrong-mesh-caller "$viewer_token" "$work/viewer.pem")
if [ "$code" = 403 ] && grep -q 'RBAC: access denied' "$out/wrong-mesh-caller.http"; then
  pass "wrong mesh caller: 403 RBAC: access denied from the guard's sidecar, before the hook"
else
  fail "wrong mesh caller: $code"
fi
printf 'wrong-mesh-caller\t%s\tRBAC\t-\t-\t-\t-\t403 RBAC\t%s\n' "$code" "$([ "$code" = 403 ] && echo yes || echo no)" >> "$out/catalogue.tsv"
# The evaluator's lines so far: its pod is replaced below, and a new pod is a new run.
kubectl -n "$ns" logs deploy/ztd-policy-evaluator -c policy-evaluator > "$out/policy-events.jsonl" 2>/dev/null || true
kubectl -n "$ns" scale deploy/ztd-policy-evaluator --replicas=0 >/dev/null
kubectl -n "$ns" wait --for=delete pod -l app.kubernetes.io/name=ztd-policy-evaluator --timeout=120s >/dev/null 2>&1 || true
guarded participant pdp-down "$viewer_token" "$work/viewer.pem" >/dev/null; expect pdp-down 503 POL-PDP-UNAVAILABLE "" no
kubectl -n "$ns" scale deploy/ztd-policy-evaluator --replicas=1 >/dev/null
kubectl -n "$ns" rollout status deploy/ztd-policy-evaluator --timeout=180s >/dev/null
kubectl -n "$ns" scale deploy/ztd-token-store --replicas=0 >/dev/null
kubectl -n "$ns" wait --for=delete pod -l app.kubernetes.io/name=ztd-token-store --timeout=120s >/dev/null 2>&1 || true
guarded participant store-down "$viewer_token" "$work/viewer.pem" >/dev/null; expect store-down 503 TOK-STORE-UNAVAILABLE "" no
kubectl -n "$ns" scale deploy/ztd-token-store --replicas=1 >/dev/null
kubectl -n "$ns" rollout status deploy/ztd-token-store --timeout=180s >/dev/null

step "Latency: the presentation-required decision through the guard against a mesh round trip without it"
# Both from the participant's pod through its sidecar, sequentially, ${samples} each, with a token
# granted just before. The guarded request runs the whole chain (Envoy, ext_authz, the token and proof
# check, the replay record in PostgreSQL, the policy decision) and is denied there with 401; the
# baseline is a mesh round trip from the same pod to another service of the namespace (the
# connector's key set, 200), the same sidecar legs without the guard.
full_token=$(login "$full_id" "$full_secret" full "$work/full.pem")
: > "$out/latency-guarded.txt"; : > "$out/latency-baseline.txt"
for _ in $(seq 1 "$samples"); do
  kubectl -n "$ns" exec participant -c curl -- curl -s -o /dev/null -w '%{http_code} %{time_total}\n' -X POST -H "Authorization: DPoP $full_token" \
    -H "DPoP: $(dpop_proof "$work/full.pem" POST "$published/demo" "$(ath_of "$full_token")" "")" -H 'Content-Type: application/json' \
    --data '{}' "$published/demo" >> "$out/latency-guarded.txt" || true
  kubectl -n "$ns" exec participant -c curl -- curl -s -o /dev/null -w '%{http_code} %{time_total}\n' \
    "$connector_url/.well-known/jwks.json" >> "$out/latency-baseline.txt" || true
done
# p FILE STATUS Q: the Q quantile in ms of the samples answered STATUS (nearest rank).
p() { awk -v s="$2" '$1 == s {print $2}' "$1" | sort -n | awk -v q="$3" '{v[NR]=$1} END {i=int(NR*q+0.999999); if (i<1) i=1; printf "%.1f", v[i]*1000}'; }
n() { awk -v s="$2" '$1 == s' "$1" | wc -l | tr -d ' '; }
{
  printf 'guarded_401_samples\t%s\nguarded_p50_ms\t%s\nguarded_p99_ms\t%s\n' "$(n "$out/latency-guarded.txt" 401)" "$(p "$out/latency-guarded.txt" 401 0.5)" "$(p "$out/latency-guarded.txt" 401 0.99)"
  printf 'baseline_200_samples\t%s\nbaseline_p50_ms\t%s\nbaseline_p99_ms\t%s\n' "$(n "$out/latency-baseline.txt" 200)" "$(p "$out/latency-baseline.txt" 200 0.5)" "$(p "$out/latency-baseline.txt" 200 0.99)"
} > "$out/latency.tsv"
if [ "$(n "$out/latency-guarded.txt" 401)" = "$samples" ] && [ "$(n "$out/latency-baseline.txt" 200)" = "$samples" ]; then
  pass "latency recorded: $(tr '\t\n' '= ' < "$out/latency.tsv")"
else
  fail "latency: not every sample answered as expected: $(tr '\t\n' '= ' < "$out/latency.tsv")"
fi

step "The expired token"
sleep $((lifespan + 31))
guarded participant expired-token "$viewer_token" "$work/viewer.pem" >/dev/null; expect expired-token 401 TOK-EXPIRED "" no

step "The feed bridge in the mesh: the UI reads it, nobody else does"
logs guard > "$out/guard-events.jsonl"
kubectl -n "$ns" logs deploy/ztd-policy-evaluator -c policy-evaluator >> "$out/policy-events.jsonl" 2>/dev/null || true
feed_bridge_up
# The producers' lines, posted by the one identity the chart admits to /ingest.
cat "$out/guard-events.jsonl" "$out/policy-events.jsonl" | kubectl -n "$ns" exec -i operator -c curl -- \
  curl -sS -m 30 -X POST -H 'Content-Type: application/x-ndjson' --data-binary @- "$bridge/ingest" > "$out/feed-ingest.json" 2>&1 || true
if [ "$(jq -r '.accepted // 0' "$out/feed-ingest.json" 2>/dev/null)" -gt 0 ]; then pass "ingest by the producer identity: $(cat "$out/feed-ingest.json")"; else fail "ingest: $(head -c 200 "$out/feed-ingest.json")"; fi
found=0
for run in $(jq -r .run_id "$out/guard-events.jsonl" "$out/policy-events.jsonl" 2>/dev/null | sort -u); do
  for v in "" /v2; do
    tag=v1; [ -n "$v" ] && tag=v2
    kubectl -n "$ns" exec ui -c curl -- curl -sS -m 10 "$bridge$v/snapshot?run_id=$run" > "$out/snapshot-$tag-$run.json" 2>/dev/null || true
    kubectl -n "$ns" exec ui -c curl -- curl -s -m 3 "$bridge$v/events?run_id=$run&from_seq=0" > "$out/feed-$tag-$run.txt" 2>/dev/null || true
  done
  if grep -q "\"correlation_id\":\"$allowed_id\"" "$out/feed-v2-$run.txt"; then found=$((found + 1)); fi
done
if [ "$found" = 2 ]; then pass "the UI reads the allowed request's guard and policy events under $allowed_id from /v2/events"; else fail "the UI reads $found of 2 events of $allowed_id"; fi
code=$(ccurl participant "$out/feed-participant.http" "$bridge/v2/snapshot?run_id=$run")
if [ "$code" = 403 ] && grep -q 'RBAC: access denied' "$out/feed-participant.http"; then pass "another identity (the Participant's) is refused by the bridge's sidecar: 403 RBAC"; else fail "the Participant read the feed: $code"; fi
code=$(ccurl intruder "$out/feed-intruder-ingest.http" -X POST --data-binary '{}' "$bridge/ingest")
if [ "$code" = 403 ] && grep -q 'RBAC: access denied' "$out/feed-intruder-ingest.http"; then pass "an identity that is not a producer cannot ingest: 403 RBAC"; else fail "a non-producer ingested: $code"; fi

environment
echo
echo "verdict: $([ "$failures" = 0 ] && echo PASS || echo "FAIL ($failures)")" | tee -a "$out/verdict.txt"
exit "$failures"
