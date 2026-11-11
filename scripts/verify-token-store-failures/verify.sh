#!/usr/bin/env bash
# The token store's failure catalogue on a throwaway kind cluster (README.md next to this file has
# the matrix). The store runs from the chart in runtime mode on PostgreSQL and OpenBao from the
# pinned images inside the cluster, with the real connector from the working tree as the peer
# zone's issuer and one substitution route registered at it through dynamic client registration.
# The script plays the guard: it substitutes and replay-checks through the API server's pod proxy
# with the forwarded-client-certificate header the sidecar would set. Then, one failure at a time:
# a caller and a target the routes refuse, a replay storm, PostgreSQL unreachable and PostgreSQL
# crash-recovered, OpenBao unreachable, the issuer down through a renewal, every token expired and
# a renewer that died holding its claim. Each is recorded with the status, the reason code, the
# readiness words and the audit rows the token-store page documents for it, and recovery is the
# dependency coming back: no statement against the database repairs anything, and every statement
# the script does run is listed in statements.txt.
#
#   scripts/verify-token-store-failures/verify.sh [--out DIR]   default .dev/token-store-failures (git-ignored)
#   BIN=<dir with kind and kubectl> ...                         default .tools/bin (scripts/tools/install.sh kind kubectl)
#
# Needs docker, helm, kind, kubectl, curl, jq, openssl. KEEP=1 leaves the cluster and registry
# running for inspection.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env
if [ -d "${BIN:-.tools/bin}" ]; then PATH="$(cd "${BIN:-.tools/bin}" && pwd):$PATH"; export PATH; fi

out=.dev/token-store-failures
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
for tool in docker helm kind kubectl curl jq sha256sum openssl; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 2; }
done
mkdir -p "$out"
out="$(cd "$out" && pwd)"
rm -f "$out"/*.txt "$out"/*.json "$out"/*.tsv

cluster=${TOKEN_STORE_FAILURES_KIND_CLUSTER:-ztd-token-store-failures}
reg_name=${TOKEN_STORE_FAILURES_KIND_REGISTRY:-kind-registry-token-store-failures}
reg="$reg_name:5000"                                                   # the registry's name inside the kind network
host_reg=${TOKEN_STORE_FAILURES_KIND_HOST_REGISTRY:-127.0.0.1:5003}    # the same registry from this machine, for the push
ns=ztd-mgmt
release='token-store'
secret='token-store-database'
db_url='postgres://postgres:verify@postgres:5432/tokenstore?sslmode=disable'
connector_db_url='postgres://postgres:verify@postgres:5432/connector?sslmode=disable'
store_sel='app.kubernetes.io/name=ztd-token-store,app.kubernetes.io/component=server'
key=ztd-token-store                  # the store's transit key
connector_key=connector              # the connector's transit key
kv_prefix=ztd/token-store/upstream
# The route: the guard of the data plane substitutes GET requests under the peer resource's API.
guard_id=spiffe://verify.invalid/ns/ztd-data/sa/guard
other_id=spiffe://verify.invalid/ns/ztd-data/sa/someone-else
peer_zone=zone-b
audience=https://resource-b.verify.invalid
target_prefix=$audience/api
target=$target_prefix/readings
connector_url=http://connector:8080
register_url=$connector_url/oauth2/register
token_url=$connector_url/oauth2/token
vp_issuer=https://verifier.verify.invalid
vp_kid=verify
token_lifespan=120s                  # renew_after at 75 %: the issuer-down row completes within the run
work="$(mktemp -d)"
export KUBECONFIG="$work/kubeconfig"
cluster_owned=false
registry_owned=false
proxy_pid=""
proxy_port=""

failures=0
pass() { echo "PASS  $*" | tee -a "$out/catalogue.txt"; }
fail() { echo "FAIL  $*" | tee -a "$out/catalogue.txt"; failures=$((failures + 1)); }
step() { echo; echo "== $*"; }
cleanup() {
  if [ ! -f "$out/verdict.txt" ]; then
    {
      echo "Token-store failure catalogue on kind"
      echo
      if [ -f "$out/catalogue.txt" ]; then cat "$out/catalogue.txt"; fi
      echo
      echo "verdict: FAIL (the run stopped before its last check)"
    } > "$out/verdict.txt"
  fi
  if [ -n "$proxy_pid" ]; then kill "$proxy_pid" >/dev/null 2>&1 || true; fi
  if [ -n "${KEEP:-}" ]; then
    echo "kept: cluster $cluster, registry $reg_name, KUBECONFIG=$KUBECONFIG"
    return
  fi
  if [ "$cluster_owned" = true ]; then kind delete cluster --name "$cluster" >/dev/null 2>&1 || true; fi
  if [ "$registry_owned" = true ]; then docker rm -f "$reg_name" >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

# The store's database, as the cluster sees it. Every statement is listed in statements.txt, reads
# as "read" and the two inductions of the matrix as "induce"; nothing else ever runs.
pg() { kubectl -n "$ns" exec deploy/postgres -- psql -U postgres -d "$1" -Atc "$2"; }
query() { printf 'read    %s\n' "$1" >> "$out/statements.txt"; pg tokenstore "$1"; }
induce() { printf 'induce  %s\n' "$1" >> "$out/statements.txt"; pg tokenstore "$1"; }
last_audit() { query "SELECT coalesce(max(event_id), 0) FROM audit_event"; }
# audit_since ID OUT: the audit rows after ID, "id kind reason token_id" per line.
audit_since() {
  query "SELECT event_id || ' ' || kind || ' ' || coalesce(reason_code, '-') || ' ' || coalesce(token_id::text, '-') FROM audit_event WHERE event_id > $1 ORDER BY event_id" > "$2"
}
rows() { query "SELECT token_id || ' ' || state || ' ' || to_char(expires_at, 'HH24:MI:SS') || ' ' || to_char(renew_after, 'HH24:MI:SS') || ' ' || coalesce(claimed_by, '-') FROM upstream_token ORDER BY created_at" > "$1"; }
live_row() { query "SELECT token_id FROM upstream_token WHERE state IN ('active', 'renewing') AND expires_at > now() ORDER BY created_at DESC LIMIT 1"; }
row_state() { query "SELECT state FROM upstream_token WHERE token_id::text = '$1'"; }
renew_epoch() { query "SELECT extract(epoch FROM renew_after)::bigint FROM upstream_token WHERE token_id::text = '$1'"; }

store_pod() {
  kubectl -n "$ns" get pod -l "$store_sel" -o json | jq -r '[.items[] | select(.metadata.deletionTimestamp == null)][0].metadata.name // empty'
}
start_proxy() {
  kubectl proxy --port=0 --address=127.0.0.1 >"$work/proxy.log" 2>&1 &
  proxy_pid=$!
  for _ in $(seq 1 50); do
    proxy_port=$(sed -n 's/.*127\.0\.0\.1:\([0-9]*\).*/\1/p' "$work/proxy.log" | head -1)
    if [ -n "$proxy_port" ]; then return; fi
    sleep 0.2
  done
  echo "kubectl proxy did not start" >&2
  exit 1
}
pod_url() { echo "http://127.0.0.1:$proxy_port/api/v1/namespaces/$ns/pods/$(store_pod):$1/proxy$2"; }
# probe PORT PATH OUT [curl args...]: prints the HTTP code (000 when the call fails), body to OUT.
probe() {
  local port=$1 path=$2 out_file=$3
  shift 3
  curl -sS -m 15 -o "$out_file" -w '%{http_code}' "$@" "$(pod_url "$port" "$path")" 2>/dev/null || true
}
word() { jq -r ".checks.$2 // empty" "$1" 2>/dev/null || true; }
reason() { jq -r '.reason_code // empty' "$1" 2>/dev/null || true; }
hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
b64url() { base64 | tr -d '\n=' | tr '+/' '-_'; }
# b64url_decode: standard base64 with padding again, then decoded.
b64url_decode() {
  local s
  s=$(tr '_-' '/+')
  while [ $(( ${#s} % 4 )) -ne 0 ]; do s="$s="; done
  printf '%s' "$s" | base64 -d
}
xfcc() { printf 'By=spiffe://verify.invalid/ns/%s/sa/ztd-token-store;URI=%s' "$ns" "$1"; }

# substitute NAME [TARGET] [METHOD] [CALLER]: one substitution as the guard sends it; prints the
# code, writes NAME-substitute-request.json and NAME-substitute.json. A CALLER of "-" sends no
# forwarded certificate at all. An answer's credential never reaches the records: authorization and
# dpop are replaced by their lengths, and the proof's claims are kept as dpop_claims.
substitute() {
  local name=$1 t=${2:-$target} m=${3:-GET} c=${4:-$guard_id} args=() code claims
  jq -n --arg z "$peer_zone" --arg a "$audience" --arg m "$m" --arg t "$t" --arg c "catalogue-$name-$(hex 4)" \
    '{peer_zone: $z, audience: $a, method: $m, target_uri: $t, correlation_id: $c}' > "$out/$name-substitute-request.json"
  if [ "$c" != - ]; then args=(-H "X-Forwarded-Client-Cert: $(xfcc "$c")"); fi
  code=$(probe 8080 /internal/substitute "$work/substitute.json" -X POST -H 'Content-Type: application/json' \
    "${args[@]}" --data-binary "@$out/$name-substitute-request.json")
  claims=$(jq -r '.dpop // empty' "$work/substitute.json" 2>/dev/null | cut -d. -f2 | b64url_decode 2>/dev/null || true)
  if [ -n "$claims" ] && jq -e . <<<"$claims" >/dev/null 2>&1; then
    jq --argjson claims "$claims" '.authorization |= (if . then "DPoP <redacted: \(. | length - 5) characters>" else . end)
      | .dpop |= (if . then "<redacted: \(. | length) characters>" else . end) | .dpop_claims = $claims' "$work/substitute.json" > "$out/$name-substitute.json"
  else
    cp "$work/substitute.json" "$out/$name-substitute.json"
  fi
  echo "$code"
}
# replay_check NAME JTI [IAT]: one replay check of a proof with that jti; prints the code.
jkt=$(head -c 32 /dev/urandom | b64url)   # 32 random bytes: the 43 characters of an RFC 7638 thumbprint
replay_check() {
  local name=$1 jti=$2 iat=${3:-$(date +%s)}
  jq -n --arg k "$jkt" --arg t "$target" --arg j "$jti" --argjson i "$iat" \
    '{jkt: $k, htm: "GET", htu: $t, jti: $j, iat: $i}' > "$out/$name-replay-request.json"
  probe 8080 /internal/replay-check "$out/$name-replay.json" -X POST -H 'Content-Type: application/json' \
    -H "X-Forwarded-Client-Cert: $(xfcc "$guard_id")" --data-binary "@$out/$name-replay-request.json"
}
# expect ROW WHAT EXP_CODE EXP_REASON GOT_CODE GOT_REASON: one line of the matrix and its verdict.
expect() {
  local row=$1 what=$2 ec=$3 er=$4 gc=$5 gr=$6
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$row" "$what" "$ec" "${er:--}" "$gc" "${gr:--}" >> "$out/matrix.tsv"
  if [ "$gc" = "$ec" ] && [ "${gr:-}" = "${er:-}" ]; then
    pass "$row: $what answers $ec${er:+ $er}"
  else
    fail "$row: $what answers $gc${gr:+ $gr}, want $ec${er:+ $er}"
  fi
}
# wait_until SECONDS CMD...: polls CMD every two seconds until it succeeds; false after SECONDS.
wait_until() {
  local deadline=$(( $(date +%s) + $1 ))
  shift
  until "$@"; do
    if [ "$(date +%s)" -ge "$deadline" ]; then return 1; fi
    sleep 2
  done
}
audit_has() { grep -q " $2 $3 $4\$" "$1" 2>/dev/null; }
row_is() { [ "$(row_state "$2")" = "$1" ]; }
claim_released() { [ "$(query "SELECT coalesce(claimed_by, '-') FROM upstream_token WHERE token_id::text = '$1'")" = - ]; }
renewed_since() { [ -n "$(live_row)" ] && [ "$(live_row)" != "$1" ]; }
lost_logged() { [ "$(kubectl -n "$ns" logs "$(store_pod)" -c server 2>/dev/null | grep -c 'may have been lost' || true)" -gt "$1" ]; }
pod_ready() { [ "$(kubectl -n "$ns" get pod "$(store_pod)" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = "$1" ]; }
readyz_is() { local code; code=$(probe 9090 /readyz "$work/readyz.json"); [ "$code" = "$1" ]; }
ready_words() { local code; code=$(probe 9090 /readyz "$1"); [ "$code" = "$2" ] && [ "$(word "$1" postgres)" = "$3" ] && [ "$(word "$1" openbao)" = "$4" ] && [ "$(word "$1" signing_key)" = "$5" ]; }

# bao TOKEN ARGS...: the OpenBao CLI inside its pod; the token on the first line of stdin, never on
# a command line, the rest of stdin the command's own.
bao() {
  local token=$1
  shift
  { printf '%s\n' "$token"; cat; } | kubectl -n "$ns" exec -i deploy/openbao -- \
    sh -c 'IFS= read -r BAO_TOKEN; export BAO_TOKEN BAO_ADDR=http://127.0.0.1:8200; exec bao "$@"' sh "$@"
}

# A P-256 key as the DPoP key of the registrar's calls: its JWK coordinates and ES256 signatures
# with openssl alone, so the registration flow needs no Go on this machine.
ec_xy() {
  # ec_xy PEM: prints "x y", base64url, from the uncompressed point of the private key's public half.
  local der="$work/ec.der" point="$work/ec.point"
  openssl pkey -in "$1" -pubout -outform DER -out "$der"
  tail -c 65 "$der" > "$point"
  printf '%s %s\n' "$(tail -c 64 "$point" | head -c 32 | b64url)" "$(tail -c 32 "$point" | b64url)"
}
es256() {
  # es256 PEM: signs stdin, prints the raw r||s signature base64url.
  local der="$work/sig.der" ints r s
  openssl dgst -sha256 -sign "$1" -out "$der"
  ints=$(openssl asn1parse -inform DER -in "$der" | sed -n 's/.*INTEGER *:\([0-9A-F]*\).*/\1/p')
  r=$(printf '%064s' "$(sed -n 1p <<<"$ints" | sed 's/^00//')" | tr ' ' 0)
  s=$(printf '%064s' "$(sed -n 2p <<<"$ints" | sed 's/^00//')" | tr ' ' 0)
  printf '%b' "$(sed 's/../\\x&/g' <<<"$r$s")" | b64url
}
dpop_proof() {
  # dpop_proof PEM HTM HTU ATH NONCE: a proof for the request, signed by PEM.
  local pem=$1 htm=$2 htu=$3 ath=$4 nonce=$5 xy header payload input
  xy=$(ec_xy "$pem")
  header=$(jq -nc --arg x "${xy% *}" --arg y "${xy#* }" '{alg: "ES256", typ: "dpop+jwt", jwk: {kty: "EC", crv: "P-256", x: $x, y: $y}}' | b64url)
  payload=$(jq -nc --arg j "$(hex 16 | b64url)" --arg m "$htm" --arg u "$htu" --argjson i "$(date +%s)" --arg a "$ath" --arg n "$nonce" \
    '{jti: $j, htm: $m, htu: $u, iat: $i} + (if $a != "" then {ath: $a} else {} end) + (if $n != "" then {nonce: $n} else {} end)' | b64url)
  input="$header.$payload"
  printf '%s.%s' "$input" "$(printf '%s' "$input" | es256 "$pem")"
}
# ccurl OUT ARGS...: curl from the client pod inside the cluster, headers and body to OUT (-i), the
# status code printed. The connector sees the Service's own host, which its proof checks expect.
ccurl() {
  local out_file=$1
  shift
  kubectl -n "$ns" exec client -- curl -sS -m 15 -i "$@" > "$out_file" 2>/dev/null || true
  sed -n '1s/^HTTP\/[0-9.]* \([0-9]*\).*/\1/p' "$out_file" | tr -d '\r'
}
body_of() { sed -e '1,/^\r\?$/d' "$1"; }
header_of() { grep -i "^$2:" "$1" | head -1 | sed 's/^[^:]*: *//' | tr -d '\r'; }
# dpop_call PEM METHOD URL ATH OUT ARGS...: the call with a fresh proof, once more with the server's
# nonce when it asks for one (the connector challenges every client with a nonce). Prints the code.
dpop_call() {
  local pem=$1 method=$2 url=$3 ath=$4 out_file=$5 nonce="" code try
  shift 5
  for try in 1 2; do
    code=$(ccurl "$out_file" -X "$method" -H "DPoP: $(dpop_proof "$pem" "$method" "$url" "$ath" "$nonce")" "$@" "$url")
    nonce=$(header_of "$out_file" DPoP-Nonce)
    if [ "$code" -lt 300 ] 2>/dev/null || [ -z "$nonce" ] || [ "$try" = 2 ]; then break; fi
  done
  echo "$code"
}

# tooling_run NAME IMAGE SECRET OUT ARGS...: a one-off pod of the chart's name label (admitted by
# the dependencies' ingress policy) and the tooling egress policy, with the acquisition config and
# SECRET mounted as the store mounts them. Prints the pod's final phase; its output goes to OUT.
tooling_run() {
  local pod=$1 image=$2 credentials=$3 out_file=$4
  shift 4
  local args
  args=$(printf '%s\n' "$@" | jq -R . | jq -sc .)
  kubectl -n "$ns" apply -f - <<EOF >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: $pod
  labels: {app.kubernetes.io/name: ztd-token-store, app.kubernetes.io/component: tooling}
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  enableServiceLinks: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    fsGroup: 65532
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: tool
      image: "$image"
      args: $args
      env:
        - name: TOKEN_STORE_DATABASE_URL
          valueFrom: {secretKeyRef: {name: $credentials, key: url}}
        - {name: TOKEN_STORE_OPENBAO_URL, value: http://openbao:8200}
        - {name: TOKEN_STORE_OPENBAO_TOKEN_FILE, value: /var/run/token-store/credentials/openbao-token}
        - {name: TOKEN_STORE_ACQUIRE_CONFIG, value: /etc/token-store/acquisition.json}
      volumeMounts:
        - {name: acquisition, mountPath: /etc/token-store, readOnly: true}
        - {name: credentials, mountPath: /var/run/token-store/credentials, readOnly: true}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: [ALL]}
  volumes:
    - name: acquisition
      configMap: {name: ztd-token-store-acquisition, optional: true}
    - name: credentials
      secret: {secretName: $credentials, defaultMode: 0440}
EOF
  local phase=""
  for _ in $(seq 1 60); do
    phase=$(kubectl -n "$ns" get pod "$pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    case "$phase" in Succeeded|Failed) break ;; esac
    sleep 2
  done
  kubectl -n "$ns" logs "$pod" > "$out_file" 2>&1 || true
  kubectl -n "$ns" delete pod "$pod" --wait=true >/dev/null 2>&1 || true
  echo "$phase"
}

step "Images from the working tree"
docker build -q -f deployment/docker/token-store/Dockerfile -t "$host_reg/token-store:verify" . >/dev/null
docker build -q -f deployment/docker/connector/Dockerfile -t "$host_reg/connector:verify" . >/dev/null

step "Cluster and registry"
if kind get clusters | grep -Fxq "$cluster" || docker inspect "$reg_name" >/dev/null 2>&1; then
  echo "refusing to replace an existing local cluster or registry" >&2; exit 1
fi
cluster_owned=true
kind create cluster --name "$cluster" --image "$KIND_NODE_IMAGE" --wait 0s --config - <<'EOF' >/dev/null
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry]
      config_path = "/etc/containerd/certs.d"
EOF
curl -fsSL "https://helm.cilium.io/cilium-${CILIUM_CHART_VERSION}.tgz" -o "$work/cilium.tgz"
printf '%s  %s\n' "$CILIUM_CHART_SHA256" "$work/cilium.tgz" | sha256sum -c - >/dev/null
helm install cilium "$work/cilium.tgz" -n kube-system --set operator.replicas=1 \
  --set ipam.mode=kubernetes --set kubeProxyReplacement=false --set envoy.enabled=false \
  --set securityContext.privileged=true --set cgroup.autoMount.enabled=false \
  --set cgroup.hostRoot=/sys/fs/cgroup --wait --timeout 5m >/dev/null
kubectl wait --for=condition=Ready node --all --timeout=180s >/dev/null
pass "pinned Cilium enforces NetworkPolicy"
curl -fsSL "https://raw.githubusercontent.com/istio/istio/${ISTIO_CRDS_VERSION}/manifests/charts/base/files/crd-all.gen.yaml" -o "$work/istio-crds.yaml"
printf '%s  %s\n' "$ISTIO_CRDS_SHA256" "$work/istio-crds.yaml" | sha256sum -c - >/dev/null
kubectl apply --server-side -f "$work/istio-crds.yaml" >/dev/null
registry_owned=true
docker run -d --name "$reg_name" --network kind -p "$host_reg:5000" "$REGISTRY_IMAGE" >/dev/null
for node in $(kind get nodes --name "$cluster"); do
  docker exec "$node" mkdir -p "/etc/containerd/certs.d/$reg"
  printf '[host."http://%s"]\n' "$reg" | docker exec -i "$node" cp /dev/stdin "/etc/containerd/certs.d/$reg/hosts.toml"
done
for _ in $(seq 1 50); do
  if curl -sf -o /dev/null "http://$host_reg/v2/"; then break; fi
  sleep 0.2
done
docker push -q "$host_reg/token-store:verify" >/dev/null
docker push -q "$host_reg/connector:verify" >/dev/null
digest=$(docker image inspect --format '{{index .RepoDigests 0}}' "$host_reg/token-store:verify" | sed 's/.*@//')
connector_digest=$(docker image inspect --format '{{index .RepoDigests 0}}' "$host_reg/connector:verify" | sed 's/.*@//')
curl_image=$(sed -n 's/^ *image: *\(docker\.io\/curlimages\/curl:[^ ]*\).*/\1/p' deployment/helm/ztd/values.yaml | head -1)
echo "  token-store $reg/token-store@$digest"
echo "  connector   $reg/connector@$connector_digest"

# The lane into the connector's pods, applied at setup and again after row 8b removes it: without
# it the default deny drops every packet to the issuer, which is the silent face of a peer that is
# down.
connector_ingress_lane() {
  kubectl -n "$ns" apply -f - <<'YAML' >/dev/null
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: connector-ingress}
spec:
  podSelector: {matchLabels: {app: connector}}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector: {matchLabels: {app.kubernetes.io/name: ztd-token-store}}
        - podSelector: {matchLabels: {app: client}}
      ports: [{port: 8080, protocol: TCP}]
YAML
}

step "PostgreSQL, OpenBao and the policies of the namespace"
kubectl create namespace "$ns" >/dev/null
# Default-deny first; then each lane by name. The store's own lanes come with its chart.
kubectl -n "$ns" apply -f - <<'YAML' >/dev/null
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: default-deny}
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: dependency-ingress}
spec:
  podSelector:
    matchExpressions:
      - {key: app, operator: In, values: [postgres, openbao]}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector: {matchLabels: {app.kubernetes.io/name: ztd-token-store}}
        - podSelector: {matchLabels: {app: connector}}
      ports: [{port: 5432, protocol: TCP}, {port: 8200, protocol: TCP}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: dns-and-dependencies-egress}
spec:
  podSelector:
    matchExpressions:
      - {key: app, operator: In, values: [connector, client]}
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: kube-system}}
          podSelector: {matchLabels: {k8s-app: kube-dns}}
      ports: [{port: 53, protocol: UDP}, {port: 53, protocol: TCP}, {port: 8053, protocol: UDP}, {port: 8053, protocol: TCP}]
    - to:
        - podSelector: {matchLabels: {app: postgres}}
      ports: [{port: 5432, protocol: TCP}]
    - to:
        - podSelector: {matchLabels: {app: openbao}}
      ports: [{port: 8200, protocol: TCP}]
    - to:
        - podSelector: {matchLabels: {app: connector}}
      ports: [{port: 8080, protocol: TCP}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: tooling-egress}
spec:
  podSelector: {matchLabels: {app.kubernetes.io/component: tooling}}
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: kube-system}}
          podSelector: {matchLabels: {k8s-app: kube-dns}}
      ports: [{port: 53, protocol: UDP}, {port: 53, protocol: TCP}, {port: 8053, protocol: UDP}, {port: 8053, protocol: TCP}]
    - to:
        - podSelector: {matchLabels: {app: postgres}}
      ports: [{port: 5432, protocol: TCP}]
    - to:
        - podSelector: {matchLabels: {app: openbao}}
      ports: [{port: 8200, protocol: TCP}]
YAML
connector_ingress_lane
pass "the namespace denies ingress and egress by default; each lane is named"
kubectl -n "$ns" create secret generic "$secret" --from-literal=url="$db_url" >/dev/null
kubectl -n "$ns" create secret generic connector-database --from-literal=url="$connector_db_url" >/dev/null
# PostgreSQL keeps its data on a volume: it is taken down, brought back and crash-recovered, and the
# schema and the tokens must survive all of it. OpenBao runs in dev mode, in memory: it is never
# stopped, only partitioned, so its keys and values are the same before and after.
root=$(hex 16)
kubectl -n "$ns" apply -f - <<EOF >/dev/null
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-data
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 1Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
spec:
  replicas: 1
  strategy: {type: Recreate}
  selector:
    matchLabels: {app: postgres}
  template:
    metadata:
      labels: {app: postgres}
    spec:
      containers:
        - name: postgres
          image: "$POSTGRES_IMAGE"
          env:
            - {name: POSTGRES_PASSWORD, value: verify}
            - {name: POSTGRES_DB, value: tokenstore}
            - {name: PGDATA, value: /var/lib/postgresql/data/pgdata}
          ports:
            - containerPort: 5432
          volumeMounts:
            - {name: data, mountPath: /var/lib/postgresql/data}
          readinessProbe:
            exec:
              command: [pg_isready, -h, 127.0.0.1, -U, postgres, -d, tokenstore]
            periodSeconds: 2
      volumes:
        - name: data
          persistentVolumeClaim: {claimName: postgres-data}
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
spec:
  selector: {app: postgres}
  ports:
    - port: 5432
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: openbao
spec:
  replicas: 1
  selector:
    matchLabels: {app: openbao}
  template:
    metadata:
      labels: {app: openbao}
    spec:
      containers:
        - name: openbao
          image: "$OPENBAO_IMAGE"
          args: [server, -dev]
          env:
            - {name: BAO_DEV_LISTEN_ADDRESS, value: "0.0.0.0:8200"}
            - {name: BAO_DEV_ROOT_TOKEN_ID, value: "$root"}
            - {name: SKIP_SETCAP, value: "true"}
          ports:
            - containerPort: 8200
          readinessProbe:
            httpGet: {path: /v1/sys/health, port: 8200}
            periodSeconds: 2
---
apiVersion: v1
kind: Service
metadata:
  name: openbao
spec:
  selector: {app: openbao}
  ports:
    - port: 8200
---
apiVersion: v1
kind: Pod
metadata:
  name: client
  labels: {app: client}
spec:
  containers:
    - name: curl
      image: "$curl_image"
      command: [sh, -c, 'while true; do sleep 3600; done']
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: {drop: [ALL]}
EOF
kubectl -n "$ns" rollout status deploy/postgres --timeout=180s >/dev/null
kubectl -n "$ns" rollout status deploy/openbao --timeout=180s >/dev/null
kubectl -n "$ns" wait --for=condition=Ready pod/client --timeout=120s >/dev/null
pg postgres "CREATE DATABASE connector" >/dev/null
pass "PostgreSQL (two databases, one each for the store and the connector), OpenBao and the client pod are up"

# Transit and the policies: the store's service token reads its key, signs with it and owns its KV
# prefix; the operator's token may create and configure the store's key; the connector's token
# signs with its own key and reads nothing else.
bao "$root" secrets enable transit </dev/null >/dev/null
bao "$root" policy write token-store - <<EOF >/dev/null
path "transit/keys/$key"         { capabilities = ["read"] }
path "transit/sign/$key"         { capabilities = ["update"] }
path "secret/data/$kv_prefix/*"     { capabilities = ["create", "read"] }
path "secret/metadata/$kv_prefix"   { capabilities = ["list"] }
path "secret/metadata/$kv_prefix/*" { capabilities = ["read", "list", "delete"] }
EOF
bao "$root" policy write token-store-admin - <<EOF >/dev/null
path "transit/keys/$key"         { capabilities = ["create", "read", "update"] }
path "transit/keys/$key/rotate"  { capabilities = ["update"] }
path "transit/keys/$key/config"  { capabilities = ["update"] }
EOF
bao "$root" policy write connector - <<EOF >/dev/null
path "transit/keys/$connector_key"  { capabilities = ["read"] }
path "transit/sign/$connector_key"  { capabilities = ["update"] }
EOF
# The connector signs with a pinned key version it never creates: the operator provisions the key.
bao "$root" write -f "transit/keys/$connector_key" type=ecdsa-p256 exportable=false allow_plaintext_backup=false </dev/null >/dev/null
runtime_token=$(bao "$root" token create -policy=token-store -ttl=2h -format=json </dev/null | jq -r .auth.client_token)
admin_token=$(bao "$root" token create -policy=token-store-admin -ttl=2h -format=json </dev/null | jq -r .auth.client_token)
connector_token=$(bao "$root" token create -policy=connector -ttl=2h -format=json </dev/null | jq -r .auth.client_token)
if [ "${#runtime_token}" -gt 20 ] && [ "${#admin_token}" -gt 20 ] && [ "${#connector_token}" -gt 20 ]; then
  pass "three OpenBao tokens, one policy each: the store, its operator, the connector"
else
  fail "OpenBao token creation failed"
fi

step "The connector as the peer zone's issuer"
# The fixture signer stands in for the peer's verifier: the connector trusts its public key as the
# one IF-03 issuer, the store signs its outcomes with the private half, which it alone holds.
openssl ecparam -name prime256v1 -genkey -noout -out "$work/issuer-private.pem" 2>/dev/null
openssl ec -in "$work/issuer-private.pem" -pubout -out "$work/issuer.pem" 2>/dev/null
xy=$(ec_xy "$work/issuer-private.pem")
jq -n --arg iss "$vp_issuer" --arg kid "$vp_kid" --arg x "${xy% *}" --arg y "${xy#* }" \
  '{($iss): {keys: [{kty: "EC", crv: "P-256", x: $x, y: $y, kid: $kid}]}}' > "$work/issuers.json"
printf '[{"role":"participant","entitlement":"read","scopes":["read"]}]\n' > "$work/scopes.json"
kubectl -n "$ns" create configmap connector-vp --from-file=issuers.json="$work/issuers.json" --from-file=scopes.json="$work/scopes.json" >/dev/null
registrar_secret=$(hex 24)
kubectl -n "$ns" create secret generic connector-credentials \
  --from-literal=openbao-token="$connector_token" --from-literal=token-secret="$(hex 32)" \
  --from-literal=registration-secret="$(hex 32)" --from-literal=registrar-secret="$registrar_secret" >/dev/null
phase=$(tooling_run connector-migrate "$reg/token-store@$digest" connector-database "$out/connector-migrate.txt" migrate up)
if [ "$phase" = Succeeded ]; then pass "the connector's database carries the shared schema (migrate up from the store's image)"; else fail "connector migrate: $phase $(tail -3 "$out/connector-migrate.txt")"; fi
kubectl -n "$ns" apply -f - <<EOF >/dev/null
apiVersion: apps/v1
kind: Deployment
metadata:
  name: connector
spec:
  replicas: 1
  selector:
    matchLabels: {app: connector}
  template:
    metadata:
      labels: {app: connector}
    spec:
      automountServiceAccountToken: false
      enableServiceLinks: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: connector
          image: "$reg/connector@$connector_digest"
          args:
            - serve
            - --issuer=https://connector.zone-b.verify.invalid
            - --signing-key=$connector_key
            - --signing-key-version=1
            - --registration-endpoint=$register_url
            - --openbao-token-file=/var/run/connector/credentials/openbao-token
            - --token-secret-file=/var/run/connector/credentials/token-secret
            - --registration-secret-file=/var/run/connector/credentials/registration-secret
            - --registrar-id=registrar
            - --registrar-secret-file=/var/run/connector/credentials/registrar-secret
            - --registrar-scopes=connector:client_registration
            - --registrar-audiences=$register_url,$audience
            - --registrar-delegable-scopes=read
            - --vp-trusted-issuers-file=/etc/connector/issuers.json
            - --vp-scope-map-file=/etc/connector/scopes.json
            - --access-token-lifespan=$token_lifespan
            - --drain-delay=0s
          env:
            - name: CONNECTOR_DATABASE_URL
              valueFrom: {secretKeyRef: {name: connector-database, key: url}}
            - {name: CONNECTOR_OPENBAO_URL, value: http://openbao:8200}
          ports:
            - containerPort: 8080
            - containerPort: 9090
          readinessProbe:
            httpGet: {path: /readyz, port: 9090}
            periodSeconds: 2
          volumeMounts:
            - {name: vp, mountPath: /etc/connector, readOnly: true}
            - {name: credentials, mountPath: /var/run/connector/credentials, readOnly: true}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
      volumes:
        - name: vp
          configMap: {name: connector-vp}
        - name: credentials
          secret: {secretName: connector-credentials, defaultMode: 0440}
---
apiVersion: v1
kind: Service
metadata:
  name: connector
spec:
  selector: {app: connector}
  ports:
    - port: 8080
EOF
if kubectl -n "$ns" rollout status deploy/connector --timeout=180s >/dev/null 2>&1; then
  pass "the connector is ready: its key in transit, its schema current, the verified-presentation grant on"
else
  fail "the connector did not become ready: $(kubectl -n "$ns" logs deploy/connector --tail=5 2>/dev/null | tr '\n' ';')"
fi

step "Dynamic client registration of the store's route at the connector"
# Through the Service, as the store will reach it: its endpoints follow the pod's readiness.
jwks_served() { [ "$(ccurl "$work/jwks.http" "$connector_url/.well-known/jwks.json")" = 200 ]; }
if wait_until 60 jwks_served; then pass "the connector publishes its JWKS through its Service"; else fail "the connector's JWKS is not reachable through its Service"; fi
# The registrar's DPoP-bound registration token, then the client: confidential, DPoP-bound, the
# verified-presentation grant, scope read, the resource's audience. The secret is returned once.
openssl ecparam -name prime256v1 -genkey -noout -out "$work/registrar-key.pem" 2>/dev/null
code=$(dpop_call "$work/registrar-key.pem" POST "$token_url" "" "$work/registrar-token.http" \
  -u "registrar:$registrar_secret" --data-urlencode grant_type=client_credentials \
  --data-urlencode scope=connector:client_registration --data-urlencode "audience=$register_url $audience")
registration_token=$(body_of "$work/registrar-token.http" | jq -r '.access_token // empty' 2>/dev/null || true)
if [ "$code" = 200 ] && [ -n "$registration_token" ]; then
  pass "the registrar obtained a DPoP-bound registration token"
else
  fail "registrar token: $code $(body_of "$work/registrar-token.http" | head -c 300)"
fi
ath=$(printf '%s' "$registration_token" | openssl dgst -sha256 -binary | b64url)
jq -n --arg a "$audience" '{client_name: "token-store-route", grant_types: ["urn:facis:params:oauth:grant-type:verified-presentation"],
  token_endpoint_auth_method: "client_secret_basic", scope: "read", dpop_bound_access_tokens: true, audience: [$a]}' > "$work/registration.json"
code=$(dpop_call "$work/registrar-key.pem" POST "$register_url" "$ath" "$work/registration.http" \
  -H "Authorization: DPoP $registration_token" -H 'Content-Type: application/json' --data-binary "$(cat "$work/registration.json")")
client_id=$(body_of "$work/registration.http" | jq -r '.client_id // empty' 2>/dev/null || true)
client_secret=$(body_of "$work/registration.http" | jq -r '.client_secret // empty' 2>/dev/null || true)
if [ "$code" = 201 ] && [ -n "$client_id" ] && [ -n "$client_secret" ]; then
  pass "the route's client is registered: DPoP-bound, verified-presentation grant, scope read, the resource's audience"
else
  fail "registration: $code $(body_of "$work/registration.http" | head -c 300)"
fi

step "The store in runtime mode: its key, its route, its callers"
kubectl -n "$ns" create secret generic ztd-token-store-credentials --from-literal=openbao-token="$runtime_token" \
  --from-literal=client-secret="$client_secret" --from-file=issuer-private.pem="$work/issuer-private.pem" >/dev/null
# The operator's pod reads the whole acquisition config too, the fixture signer's key file included.
kubectl -n "$ns" create secret generic token-store-admin --from-literal=openbao-token="$admin_token" --from-literal=url="$db_url" \
  --from-literal=client-secret="$client_secret" --from-file=issuer-private.pem="$work/issuer-private.pem" >/dev/null
jq -n --arg key "$key" --arg kv "$kv_prefix" --arg iss "$vp_issuer" --arg kid "$vp_kid" --arg zone "$peer_zone" --arg aud "$audience" \
  --arg url "$connector_url" --arg cid "$client_id" --arg guard "$guard_id" --arg prefix "$target_prefix" '{
  signing_key: $key, kv_prefix: $kv,
  trusted_issuers: [{issuer: $iss, kid: $kid, public_key_file: "/etc/token-store/issuer.pem"}],
  routes: [{name: "resource-b", peer_zone: $zone, audience: $aud, connector_url: $url, client_id: $cid,
    client_secret_file: "/var/run/token-store/credentials/client-secret",
    callers: [$guard], methods: ["GET"], target_prefix: $prefix,
    fixture_outcomes: {issuer: $iss, kid: $kid, private_key_file: "/var/run/token-store/credentials/issuer-private.pem",
      role: "participant", entitlement: "read", validity_seconds: 90}}]}' > "$work/acquisition.json"
kubectl -n "$ns" create configmap ztd-token-store-acquisition --from-file=acquisition.json="$work/acquisition.json" --from-file=issuer.pem="$work/issuer.pem" >/dev/null
# The key is registered before the service exists, so the schema is applied here; the chart's
# migration hook then finds it current.
phase=$(tooling_run token-store-migrate "$reg/token-store@$digest" token-store-admin "$out/store-migrate.txt" migrate up)
if [ "$phase" = Succeeded ]; then pass "the store's database carries the schema"; else fail "store migrate: $phase $(tail -3 "$out/store-migrate.txt")"; fi
phase=$(tooling_run token-store-keys-ensure "$reg/token-store@$digest" token-store-admin "$out/key-ensure.txt" keys ensure)
ensured_ref=$(jq -rs 'map(select(has("key_ref"))) | last | .key_ref // empty' "$out/key-ensure.txt" 2>/dev/null || true)
if [ "$phase" = Succeeded ] && [ "$ensured_ref" = "transit:$key:v1" ]; then
  pass "keys ensure created the store's key in transit and registered $ensured_ref"
else
  fail "keys ensure: phase $phase, $(tail -3 "$out/key-ensure.txt" 2>/dev/null)"
fi
cat > "$work/runtime-values.yaml" <<YAML
runtime:
  enabled: true
  existingConfigMap: ztd-token-store-acquisition
  credentialsSecret: ztd-token-store-credentials
  replayCallers: ["$guard_id"]
networkPolicy:
  enabled: true
  schemaEgress:
    - to:
        - podSelector: {matchLabels: {app: postgres}}
      ports: [{port: 5432, protocol: TCP}]
  egress:
    - to:
        - podSelector: {matchLabels: {app: postgres}}
      ports: [{port: 5432, protocol: TCP}]
    - to:
        - podSelector: {matchLabels: {app: openbao}}
      ports: [{port: 8200, protocol: TCP}]
    - to:
        - podSelector: {matchLabels: {app: connector}}
      ports: [{port: 8080, protocol: TCP}]
YAML
helm install "$release" deployment/helm/token-store -n "$ns" -f "$work/runtime-values.yaml" \
  --set "image.repository=$reg/token-store" --set "image.digest=$digest" --set "database.existingSecret=$secret" \
  --set "openbao.address=http://openbao:8200" --set schema.dropOnUninstall=true --wait --wait-for-jobs --timeout 3m >/dev/null
start_proxy
kubectl -n "$ns" rollout status deploy/ztd-token-store --timeout=90s >/dev/null
if ready_words "$out/install-readyz.json" 200 ok ok ok; then
  pass "/readyz answers 200 with postgres ok, openbao ok and signing_key ok"
else
  fail "/readyz after the install: $(cat "$out/install-readyz.json" 2>/dev/null)"
fi

host_kind=local
if [ -n "${GITHUB_ACTIONS:-}" ]; then host_kind=ci; fi
{
  echo "{"
  echo "  \"commit\": \"$(git rev-parse HEAD)\","
  echo "  \"tree\": \"$(if [ -n "$(git status --porcelain)" ]; then echo dirty; else echo clean; fi)\","
  echo "  \"host_kind\": \"$host_kind\","
  echo "  \"date\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"helm\": \"$(helm version --short)\","
  echo "  \"kind\": \"$(kind version | cut -d' ' -f2)\","
  echo "  \"kind_node_image\": \"$KIND_NODE_IMAGE\","
  echo "  \"postgres_image\": \"$POSTGRES_IMAGE\","
  echo "  \"openbao_image\": \"$OPENBAO_IMAGE\","
  echo "  \"registry_image\": \"$REGISTRY_IMAGE\","
  echo "  \"token_store_image\": \"$reg/token-store@$digest\","
  echo "  \"connector_image\": \"$reg/connector@$connector_digest\","
  echo "  \"access_token_lifespan\": \"$token_lifespan\","
  echo "  \"renewal_defaults\": \"cycle 15s, stale claim after 5m, three attempts\","
  echo "  \"istio_crds_version\": \"$ISTIO_CRDS_VERSION\""
  echo "}"
} > "$out/environment.json"
printf 'row\twhat\texpected_status\texpected_reason\tobserved_status\tobserved_reason\n' > "$out/matrix.tsv"

step "Row 0: the baseline, a cold route acquires on demand"
since=$(last_audit)
code=$(substitute baseline)
expect "row 0" "substitution on a cold route" 200 "" "$code" "$(reason "$out/baseline-substitute.json")"
claims=$(jq -c '.dpop_claims // empty' "$out/baseline-substitute.json")
if jq -e '.authorization | startswith("DPoP ")' "$out/baseline-substitute.json" >/dev/null 2>&1 \
  && [ "$(jq -r .htm <<<"$claims")" = GET ] && [ "$(jq -r .htu <<<"$claims")" = "$target" ] && [ -n "$(jq -r '.ath // empty' <<<"$claims")" ]; then
  pass "row 0: the answer carries a DPoP authorization and a proof for exactly the upstream request (htm, htu, ath)"
else
  fail "row 0: answer or proof claims not as the contract says: $(head -c 200 "$out/baseline-substitute.json")"
fi
code=$(substitute baseline-again)
jti1=$(jq -r '.jti // empty' <<<"$claims")
jti2=$(jq -r '.dpop_claims.jti // empty' "$out/baseline-again-substitute.json")
if [ "$code" = 200 ] && [ -n "$jti1" ] && [ -n "$jti2" ] && [ "$jti1" != "$jti2" ]; then
  pass "row 0: two substitutions give two proofs with distinct jti"
else
  fail "row 0: second substitution $code, jti $jti1 and $jti2"
fi
audit_since "$since" "$out/baseline-audit.txt"
rows "$out/baseline-rows.txt"
if audit_has "$out/baseline-audit.txt" upstream.acquired - "$(live_row)" && [ "$(grep -c ' active ' "$out/baseline-rows.txt")" = 1 ]; then
  pass "row 0: audit upstream.acquired for the one active row"
else
  fail "row 0: audit $(tr '\n' ';' < "$out/baseline-audit.txt"); rows $(tr '\n' ';' < "$out/baseline-rows.txt")"
fi

step "Row 1: a caller the routes do not list"
code=$(substitute caller-denied "$target" GET "$other_id")
expect "row 1" "a forwarded certificate of another identity" 403 TOK-CALLER-DENIED "$code" "$(reason "$out/caller-denied-substitute.json")"
code=$(substitute caller-denied-none "$target" GET -)
expect "row 1" "no forwarded certificate" 403 TOK-CALLER-DENIED "$code" "$(reason "$out/caller-denied-none-substitute.json")"

step "Row 2: a target outside the route"
code=$(substitute route-denied "$audience/admin/users")
expect "row 2" "a target outside target_prefix" 403 TOK-ROUTE-DENIED "$code" "$(reason "$out/route-denied-substitute.json")"
code=$(substitute route-denied-method "$target" POST)
expect "row 2" "a method the route does not allow" 403 TOK-ROUTE-DENIED "$code" "$(reason "$out/route-denied-method-substitute.json")"

step "Row 3: a replay storm"
storm_jti=$(hex 16 | b64url)
jq -n --arg k "$jkt" --arg t "$target" --arg j "$storm_jti" --argjson i "$(date +%s)" \
  '{jkt: $k, htm: "GET", htu: $t, jti: $j, iat: $i}' > "$out/replay-storm-request.json"
url=$(pod_url 8080 /internal/replay-check)
: > "$out/replay-storm-codes.txt"
seq 1 100 | xargs -P 100 -I{} sh -c 'curl -sS -m 15 -o "$1/replay-storm-{}.json" -w "%{http_code}\n" -X POST -H "Content-Type: application/json" -H "X-Forwarded-Client-Cert: $2" --data-binary "@$1/replay-storm-request.json" "$3" 2>/dev/null || echo 000' \
  sh "$out" "$(xfcc "$guard_id")" "$url" >> "$out/replay-storm-codes.txt"
fresh=$(grep -c '^200$' "$out/replay-storm-codes.txt" || true)
replayed=$(grep -c '^409$' "$out/replay-storm-codes.txt" || true)
replay_codes=$(cat "$out"/replay-storm-[0-9]*.json | jq -r '.reason_code // empty' 2>/dev/null | sort -u | tr '\n' ' ' || true)
if [ "$fresh" = 1 ] && [ "$replayed" = 99 ] && [ "$replay_codes" = "TOK-REPLAY " ]; then
  pass "row 3: of 100 concurrent presentations of one proof exactly one is fresh and 99 are 409 TOK-REPLAY"
else
  fail "row 3: $fresh fresh, $replayed replayed, codes '$replay_codes' (see replay-storm-codes.txt)"
fi
printf 'row 3\t100 concurrent replay checks of one proof\t1x200 + 99x409\tTOK-REPLAY\t%sx200 + %sx409\t%s\n' "$fresh" "$replayed" "${replay_codes% }" >> "$out/matrix.tsv"
rm -f "$out"/replay-storm-[0-9]*.json
code=$(replay_check replay-storm-again "$storm_jti")
expect "row 3" "the same proof once more" 409 TOK-REPLAY "$code" "$(reason "$out/replay-storm-again-replay.json")"
code=$(replay_check replay-storm-stale "$(hex 16 | b64url)" "$(( $(date +%s) - 600 ))")
expect "row 3" "a proof whose iat is outside the window" 422 TOK-PROOF-INVALID "$code" "$(reason "$out/replay-storm-stale-replay.json")"

step "Row 4: PostgreSQL unreachable"
kubectl -n "$ns" scale deploy/postgres --replicas=0 >/dev/null
kubectl -n "$ns" wait --for=delete pod -l app=postgres --timeout=90s >/dev/null 2>&1 || true
if wait_until 120 pod_ready False; then pass "row 4: with PostgreSQL gone the pod leaves Ready"; else fail "row 4: the pod stayed Ready without PostgreSQL"; fi
code=$(substitute postgres-down)
expect "row 4" "substitution without the database" 503 TOK-STORE-UNAVAILABLE "$code" "$(reason "$out/postgres-down-substitute.json")"
code=$(replay_check postgres-down "$(hex 16 | b64url)")
expect "row 4" "replay check without the database" 503 TOK-STORE-UNAVAILABLE "$code" "$(reason "$out/postgres-down-replay.json")"
if ready_words "$out/postgres-down-readyz.json" 503 unreachable ok unreachable; then
  pass "row 4: /readyz answers 503 with postgres unreachable and signing_key unreachable (its rows are in the database), openbao ok"
else
  fail "row 4: /readyz without PostgreSQL: $(cat "$out/postgres-down-readyz.json" 2>/dev/null)"
fi
code=$(probe 9090 /healthz "$out/postgres-down-healthz.txt")
if [ "$code" = 200 ]; then pass "row 4: /healthz stays 200"; else fail "row 4: /healthz answered $code without PostgreSQL"; fi
kubectl -n "$ns" scale deploy/postgres --replicas=1 >/dev/null
kubectl -n "$ns" rollout status deploy/postgres --timeout=180s >/dev/null
if wait_until 120 pod_ready True && ready_words "$out/postgres-back-readyz.json" 200 ok ok ok; then
  pass "row 4: /readyz answers 200 again once PostgreSQL is back, with no step in between"
else
  fail "row 4: readiness after PostgreSQL came back: $(cat "$out/postgres-back-readyz.json" 2>/dev/null)"
fi
code=$(substitute postgres-back)
expect "row 4" "substitution with the database back" 200 "" "$code" "$(reason "$out/postgres-back-substitute.json")"

step "Row 5: PostgreSQL crash recovery empties the unlogged replay record"
crash_jti=$(hex 16 | b64url)
code=$(replay_check postgres-crash-before "$crash_jti")
expect "row 5" "a proof recorded before the crash" 200 "" "$code" "$(reason "$out/postgres-crash-before-replay.json")"
logs_before=$(kubectl -n "$ns" logs "$(store_pod)" -c server 2>/dev/null | grep -c 'may have been lost' || true)
# SIGQUIT is PostgreSQL's immediate shutdown: no checkpoint, so the restart is a crash recovery.
kubectl -n "$ns" exec deploy/postgres -- kill -QUIT 1 >/dev/null 2>&1 || true
sleep 5
kubectl -n "$ns" rollout status deploy/postgres --timeout=180s >/dev/null
wait_until 120 pod_ready True || true
crash_restarts=$(kubectl -n "$ns" get pod -l app=postgres -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}')
if [ "${crash_restarts:-0}" -ge 1 ]; then pass "row 5: the database container restarted ($crash_restarts) and recovered on its volume"; else fail "row 5: the database container did not restart"; fi
wait_until 60 lost_logged "$logs_before" || true
kubectl -n "$ns" logs "$(store_pod)" -c server > "$out/postgres-crash-store-logs.txt" 2>/dev/null || true
lost=$(grep -c 'may have been lost' "$out/postgres-crash-store-logs.txt" || true)
if [ "$lost" -gt "$logs_before" ]; then
  pass "row 5: the store stayed up and logged once that the replay record may have been lost, naming the window"
else
  fail "row 5: no record of the lost replay state after the crash recovery"
fi
code=$(replay_check postgres-crash-replay "$crash_jti")
expect "row 5" "the pre-crash proof once more, inside the window: the documented bounded exposure" 200 "" "$code" "$(reason "$out/postgres-crash-replay-replay.json")"
code=$(replay_check postgres-crash-replay-again "$crash_jti")
expect "row 5" "and a third time, recorded again" 409 TOK-REPLAY "$code" "$(reason "$out/postgres-crash-replay-again-replay.json")"

step "Row 6: OpenBao unreachable"
# A partition, not a stop: the dev-mode server keeps its keys and values, which an in-memory
# restart would not, so the store comes back to the same key.
kubectl -n "$ns" patch service openbao -p '{"spec":{"selector":{"app":"nobody"}}}' >/dev/null
if wait_until 90 ready_words "$out/openbao-down-readyz.json" 503 ok unreachable unreachable; then
  pass "row 6: /readyz answers 503 with openbao unreachable and signing_key unreachable, postgres ok"
else
  fail "row 6: /readyz with OpenBao partitioned: $(cat "$out/openbao-down-readyz.json" 2>/dev/null)"
fi
code=$(substitute openbao-down)
expect "row 6" "substitution without the key-value store" 503 TOK-STORE-UNAVAILABLE "$code" "$(reason "$out/openbao-down-substitute.json")"
if ! jq -e '.authorization // .dpop' "$out/openbao-down-substitute.json" >/dev/null 2>&1; then pass "row 6: no credential in the refusal"; else fail "row 6: a credential in the refusal"; fi
code=$(probe 9090 /healthz "$out/openbao-down-healthz.txt")
if [ "$code" = 200 ]; then pass "row 6: /healthz stays 200"; else fail "row 6: /healthz answered $code"; fi
kubectl -n "$ns" patch service openbao -p '{"spec":{"selector":{"app":"openbao"}}}' >/dev/null
if wait_until 90 ready_words "$out/openbao-back-readyz.json" 200 ok ok ok; then
  pass "row 6: /readyz answers 200 again once OpenBao is reachable, the same key resolved"
else
  fail "row 6: readiness after the partition: $(cat "$out/openbao-back-readyz.json" 2>/dev/null)"
fi
code=$(substitute openbao-back)
expect "row 6" "substitution with the key-value store back" 200 "" "$code" "$(reason "$out/openbao-back-substitute.json")"

# The issuer down has two faces, and the design page answers each differently: a peer that refuses
# the connection has "definitively answered without a token", 409 TOK-NO-UPSTREAM; a peer that
# never answers runs the caller out of its deadline, 503 TOK-STORE-UNAVAILABLE. A Service with no
# endpoints shows one face or the other depending on the datapath (refused at once on one kernel,
# dropped on another: the first CI run of this proof saw the silent face where every local run had
# seen the refusing one), so each face is induced on purpose. Refusing: the connector scaled to zero
# and, under its label, a pod that listens on nothing, so the Service resolves to it and its kernel
# answers every SYN with a reset. Silent: the lane into the connector's pods removed, so the default
# deny drops every packet.
issuer_refusing() {
  kubectl -n "$ns" scale deploy/connector --replicas=0 >/dev/null
  kubectl -n "$ns" wait --for=delete pod -l app=connector --timeout=90s >/dev/null 2>&1 || true
  kubectl -n "$ns" apply -f - <<EOF >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: issuer-standin
  labels: {app: connector}
spec:
  containers:
    - name: nothing
      image: "$curl_image"
      command: [sh, -c, 'while true; do sleep 3600; done']
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: {drop: [ALL]}
EOF
  kubectl -n "$ns" wait --for=condition=Ready pod/issuer-standin --timeout=120s >/dev/null
  wait_until 30 standin_is_the_endpoint || true
  connector_endpoints > "$out/$1-endpoints.txt"
}
connector_endpoints() {
  kubectl -n "$ns" get endpointslices -l kubernetes.io/service-name=connector \
    -o jsonpath='{range .items[*].endpoints[*]}{.targetRef.name}{" "}{end}' 2>/dev/null | tr -d ' \n' || true
  echo
}
standin_is_the_endpoint() { [ "$(connector_endpoints)" = issuer-standin ]; }
standin_check() {
  if [ "$(cat "$out/$2-endpoints.txt")" = issuer-standin ]; then
    pass "$1: the connector is gone and its Service resolves to a pod that listens on nothing: every connection is refused"
  else
    fail "$1: the Service's endpoints are '$(cat "$out/$2-endpoints.txt")', want the stand-in alone"
  fi
}
issuer_silent() { kubectl -n "$ns" delete networkpolicy connector-ingress >/dev/null; }
issuer_back() {
  kubectl -n "$ns" delete pod issuer-standin --wait=true >/dev/null 2>&1 || true
  kubectl -n "$ns" scale deploy/connector --replicas=1 >/dev/null
  kubectl -n "$ns" rollout status deploy/connector --timeout=180s >/dev/null
  wait_until 60 jwks_served || true   # the Service's endpoints follow the pod's readiness
}
audit_after() { [ "$(last_audit)" -gt "$1" ]; }

step "Row 7: the issuer down and refusing, through a renewal"
# The row the issuer will fail to renew is chosen before the issuer goes, with its renewal at least
# 30 s away: the induction and the substitution below then happen before the worker claims it.
# Read after the induction instead, the row could already have been claimed and given up, and
# there would be no live row to follow.
live=$(live_row)
if [ -n "$live" ] && [ $(( $(renew_epoch "$live") - $(date +%s) )) -lt 30 ]; then
  echo "  the live row's renewal is due within 30s; waiting for the worker to renew it before the issuer goes"
  wait_until 75 renewed_since "$live" || true
  live=$(live_row)
fi
if [ -z "$live" ]; then fail "row 7: no live row before the issuer goes down"; fi
renew_at=$(renew_epoch "$live")
since=$(last_audit)
issuer_refusing issuer-down
standin_check "row 7" issuer-down
code=$(substitute issuer-down-valid)
expect "row 7" "substitution while the token is still valid" 200 "" "$code" "$(reason "$out/issuer-down-valid-substitute.json")"
# Recorded, not judged: a passing issuer-separation check is cached for five minutes, so readiness
# may still say signing_key ok while the issuer is gone (docs/token-store.md, "Key material
# separation at readiness").
probe 9090 /readyz "$out/issuer-down-readyz.json" >/dev/null || true
budget=$(( renew_at - $(date +%s) + 90 ))
if [ "$budget" -lt 60 ]; then budget=60; fi
echo "  waiting up to ${budget}s for the worker to claim $live at renew_after and give up"
if wait_until "$budget" row_is failed "$live"; then
  pass "row 7: the worker's renewal failed and the row ended failed"
else
  fail "row 7: the row is $(row_state "$live") after ${budget}s, want failed"
fi
audit_since "$since" "$out/issuer-down-audit.txt"
attempts=$(grep -c " upstream.failed ACQ-CHALLENGE-FAILED " "$out/issuer-down-audit.txt" || true)
if [ "$attempts" -ge 3 ] && audit_has "$out/issuer-down-audit.txt" renewal.failed ACQ-CHALLENGE-FAILED "$live"; then
  pass "row 7: three audited attempts upstream.failed ACQ-CHALLENGE-FAILED, then renewal.failed ACQ-CHALLENGE-FAILED"
else
  fail "row 7: audit $(tr '\n' ';' < "$out/issuer-down-audit.txt")"
fi
since=$(last_audit)
code=$(substitute issuer-down)
expect "row 7" "substitution with the row failed and the issuer refusing" 409 TOK-NO-UPSTREAM "$code" "$(reason "$out/issuer-down-substitute.json")"
audit_since "$since" "$out/issuer-down-ondemand-audit.txt"
if grep -q " upstream.failed ACQ-CHALLENGE-FAILED " "$out/issuer-down-ondemand-audit.txt"; then
  pass "row 7: the on-demand attempt is audited upstream.failed ACQ-CHALLENGE-FAILED"
else
  fail "row 7: on-demand audit $(tr '\n' ';' < "$out/issuer-down-ondemand-audit.txt")"
fi
since=$(last_audit)
issuer_back
code=$(substitute issuer-back)
expect "row 7" "substitution with the issuer back" 200 "" "$code" "$(reason "$out/issuer-back-substitute.json")"
audit_since "$since" "$out/issuer-back-audit.txt"
rows "$out/issuer-back-rows.txt"
new_live=$(live_row)
if [ -n "$new_live" ] && [ "$new_live" != "$live" ] && audit_has "$out/issuer-back-audit.txt" upstream.acquired - "$new_live" && [ "$(row_state "$live")" = failed ]; then
  pass "row 7: a new token was acquired on demand ($new_live), audited upstream.acquired; the failed row stays as history"
else
  fail "row 7: live $new_live (was $live, now $(row_state "$live")); audit $(tr '\n' ';' < "$out/issuer-back-audit.txt")"
fi

step "Row 8: everything expired (induced), the issuer refusing; row 8b: the issuer silent"
live=$(live_row)
if [ -z "$live" ]; then fail "row 8: no live row to expire"; fi
issuer_refusing expired
standin_check "row 8" expired
induce "UPDATE upstream_token SET expires_at = now() - interval '1 second', renew_after = now() - interval '1 second' WHERE token_id::text = '$live'" >/dev/null
rows "$out/expired-rows.txt"
code=$(substitute expired)
expect "row 8" "substitution with every token expired and the issuer refusing" 409 TOK-NO-UPSTREAM "$code" "$(reason "$out/expired-substitute.json")"
if ! jq -e '.authorization // .dpop' "$out/expired-substitute.json" >/dev/null 2>&1; then pass "row 8: no credential in the refusal"; else fail "row 8: a credential in the refusal"; fi
# With the issuer refusing, the worker claims the expired row at its next cycle (renew_after is in
# the past) and fails it after three fast attempts. Row 8b starts from that settled state: a failed
# row is left alone by later cycles, so the one audit row written during the silent face is the
# on-demand attempt's.
if wait_until 60 row_is failed "$live"; then
  pass "row 8: the worker claimed the expired row and failed it against the refusing issuer"
else
  fail "row 8: the expired row is $(row_state "$live") after 60s, want failed"
fi
# Row 8b, the silent face: the lane into the issuer's pods removed, every packet to it dropped. The
# call is bounded by the caller's deadline (10 s), not answered by the peer: 503
# TOK-STORE-UNAVAILABLE, no credential, and the attempt's audit row still written, the cleanup the
# design page says survives the deadline.
since=$(last_audit)
issuer_silent
started=$(date +%s)
code=$(substitute expired-silent)
elapsed=$(( $(date +%s) - started ))
expect "row 8b" "substitution with every token expired and the issuer silent" 503 TOK-STORE-UNAVAILABLE "$code" "$(reason "$out/expired-silent-substitute.json")"
if [ "$elapsed" -ge 9 ]; then
  pass "row 8b: the refusal came at the caller's deadline (${elapsed}s), bounded by the store, not answered by the peer"
else
  fail "row 8b: the refusal came after ${elapsed}s; a silent peer should run the caller's 10s deadline out"
fi
if ! jq -e '.authorization // .dpop' "$out/expired-silent-substitute.json" >/dev/null 2>&1; then pass "row 8b: no credential in the refusal"; else fail "row 8b: a credential in the refusal"; fi
wait_until 10 audit_after "$since" || true
audit_since "$since" "$out/expired-silent-audit.txt"
if grep -q " upstream.failed ACQ-CHALLENGE-FAILED " "$out/expired-silent-audit.txt"; then
  pass "row 8b: the attempt is audited upstream.failed ACQ-CHALLENGE-FAILED although the deadline cut the call"
else
  fail "row 8b: audit $(tr '\n' ';' < "$out/expired-silent-audit.txt")"
fi
connector_ingress_lane
issuer_back
code=$(substitute expired-back)
expect "row 8" "substitution with the issuer back" 200 "" "$code" "$(reason "$out/expired-back-substitute.json")"
rows "$out/expired-back-rows.txt"
old_state=$(row_state "$live")
new_live=$(live_row)
if [ -n "$new_live" ] && [ "$new_live" != "$live" ] && { [ "$old_state" = retired ] || [ "$old_state" = failed ]; }; then
  pass "row 8: the expired row is $old_state, closed by the store itself, and a new row ($new_live) is live"
else
  fail "row 8: the expired row is '$old_state' and the live row is '$new_live'"
fi

step "Row 9: a renewer that died holding its claim (induced)"
live=$(live_row)
if [ -z "$live" ]; then fail "row 9: no live row to claim"; fi
since=$(last_audit)
induce "UPDATE upstream_token SET state = 'renewing', claimed_by = 'worker-that-died', claimed_at = now() - interval '6 minutes' WHERE token_id::text = '$live'" >/dev/null
code=$(substitute stale-claim)
expect "row 9" "substitution while the row is renewing under a dead claim" 200 "" "$code" "$(reason "$out/stale-claim-substitute.json")"
if wait_until 60 claim_released "$live"; then
  pass "row 9: the dead worker's claim was released within a cycle, with no step in between"
else
  fail "row 9: the claim is still held by worker-that-died after 60s"
fi
audit_since "$since" "$out/stale-claim-audit.txt"
rows "$out/stale-claim-rows.txt"
if audit_has "$out/stale-claim-audit.txt" renewal.released REN-CLAIM-STALE "$live"; then
  pass "row 9: audit renewal.released REN-CLAIM-STALE for the row"
else
  fail "row 9: audit $(tr '\n' ';' < "$out/stale-claim-audit.txt")"
fi

step "After every failure: the same process, ready, its records clean"
pod=$(store_pod)
restarts=$(kubectl -n "$ns" get pod "$pod" -o jsonpath='{.status.containerStatuses[?(@.name=="server")].restartCount}')
echo "restartCount: $restarts" > "$out/pod-status.txt"
if [ "$restarts" = 0 ]; then pass "the store's container never restarted: liveness held through every failure"; else fail "the store's container restarted $restarts times"; fi
if ready_words "$out/final-readyz.json" 200 ok ok ok; then pass "/readyz answers 200 with every check ok at the end"; else fail "/readyz at the end: $(cat "$out/final-readyz.json" 2>/dev/null)"; fi
kubectl -n "$ns" logs "$pod" -c server > "$out/store-logs.txt" 2>/dev/null || true
kubectl -n "$ns" logs deploy/connector > "$out/connector-logs.txt" 2>/dev/null || true
if jq -e . "$out/store-logs.txt" >/dev/null 2>&1; then pass "every record the store wrote is JSON"; else fail "a record the store wrote is not JSON"; fi
query "SELECT event_id || ' ' || kind || ' ' || coalesce(reason_code, '-') || ' ' || coalesce(token_id::text, '-') FROM audit_event ORDER BY event_id" > "$out/audit-all.txt"
if [ "$(grep -c '^induce' "$out/statements.txt")" = 2 ]; then
  pass "two statements induced a state (rows 8 and 9) and none repaired one: statements.txt lists them all"
else
  fail "$(grep -c '^induce' "$out/statements.txt") inducing statements, want 2"
fi
# No credential in any record: this run's OpenBao tokens, the route's client secret, the
# registrar's, the database credential and the fixture signer's private key.
pem_body=$(grep -v -- '-----' "$work/issuer-private.pem" | tr -d '\n')
pem_point=${pem_body:36:24}
: > "$out/credential-scan.txt"
leaks=0
for needle in "$root" "$admin_token" "$runtime_token" "$connector_token" "$client_secret" "$registrar_secret" "postgres:verify@" "$pem_point" "PRIVATE KEY"; do
  n=$( (grep -l -F -- "$needle" "$out"/*.txt "$out"/*.json "$out"/*.tsv 2>/dev/null || true) | grep -v -c credential-scan.txt || true)
  printf '%-14s %s\n' "$(case "$needle" in "$root") echo root-token;; "$admin_token") echo admin-token;; "$runtime_token") echo service-token;; "$connector_token") echo connector-token;; "$client_secret") echo client-secret;; "$registrar_secret") echo registrar-secret;; "$pem_point") echo signer-key;; *) echo "'$needle'";; esac)" "$n" >> "$out/credential-scan.txt"
  leaks=$((leaks + n))
done
if [ "$leaks" = 0 ]; then pass "no credential in any record (credential-scan.txt)"; else fail "a credential reached a record: $(tr '\n' ';' < "$out/credential-scan.txt")"; fi

step "Verdict"
if [ "$failures" = 0 ]; then verdict=PASS; else verdict=FAIL; fi
{
  echo "Token-store failure catalogue on kind"
  echo
  cat "$out/catalogue.txt"
  echo
  echo "verdict: $verdict"
} > "$out/verdict.txt"
echo "verdict: $verdict ($failures failed)"
[ "$failures" = 0 ]
