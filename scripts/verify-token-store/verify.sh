#!/usr/bin/env bash
# The token-store chart's lifecycle and the service's readiness on a throwaway kind cluster: an
# install applies the schema to an empty database and brings the service up ready; the service
# stops being ready, and stays alive, while PostgreSQL or the key-value store is unreachable, and
# is ready again when they are back; its records are JSON, every request's record carries a
# correlation id, and a caller's x-request-id and traceparent reach its records; it runs as its
# own ServiceAccount with the identity label; an upgrade of a current database changes nothing;
# an uninstall with schema.dropOnUninstall leaves the schema empty; an uninstall without it keeps
# the schema. Then, in runtime mode, the store's key custody: its signing key is created in OpenBao
# transit by `token-store keys ensure` with a least-privilege token, the database holds only the
# key's reference and RFC 7638 thumbprint (checked against one computed with openssl), transit
# refuses to export the key, `keys rotate` retires the previous version and transit no longer signs
# with it, and with OpenBao gone readiness fails closed while no key material or OpenBao token
# reaches the database or the records. Builds the image from the working tree, pushes it to a
# registry on the kind network, runs PostgreSQL and OpenBao from the pinned images inside the
# cluster with the connection URL in a Secret, as a real deployment has it, and writes its records
# and verdict to --out.
#
#   scripts/verify-token-store/verify.sh [--out DIR]       default .dev/token-store-evidence (git-ignored)
#   BIN=<dir with kind and kubectl> ...                    default .tools/bin (scripts/tools/install.sh kind kubectl)
#
# Needs docker, helm, kind, kubectl, curl, jq, openssl. KEEP=1 leaves the cluster and registry
# running for inspection.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env
if [ -d "${BIN:-.tools/bin}" ]; then PATH="$(cd "${BIN:-.tools/bin}" && pwd):$PATH"; export PATH; fi

out=.dev/token-store-evidence
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
rm -f "$out"/*.txt "$out"/*.json

cluster=${TOKEN_STORE_KIND_CLUSTER:-ztd-token-store}
reg_name=${TOKEN_STORE_KIND_REGISTRY:-kind-registry-token-store}
reg="$reg_name:5000"            # the registry's name inside the kind network
host_reg=${TOKEN_STORE_KIND_HOST_REGISTRY:-127.0.0.1:5002}         # the same registry from this machine, for the push
ns=ztd-mgmt
release=token-store
secret=token-store-database
db_url='postgres://postgres:verify@postgres:5432/tokenstore?sslmode=disable'
latest=$(find services/token-store/internal/schema/migrations -name '*.up.sql' | wc -l | tr -d ' ')
store_sel='app.kubernetes.io/name=ztd-token-store,app.kubernetes.io/component=server'
key=ztd-token-store                 # the store's transit key in the runtime-mode stage
kv_prefix=ztd/token-store/upstream  # the KV prefix its runtime policy is scoped to
work="$(mktemp -d)"
export KUBECONFIG="$work/kubeconfig"
cluster_owned=false
registry_owned=false
proxy_pid=""
proxy_port=""

failures=0
pass() { echo "PASS  $*" | tee -a "$out/lifecycle.txt"; }
fail() { echo "FAIL  $*" | tee -a "$out/lifecycle.txt"; failures=$((failures + 1)); }
step() { echo; echo "== $*"; }
cleanup() {
  # A run that stops before its last check still leaves a verdict for the job summary.
  if [ ! -f "$out/verdict.txt" ]; then
    {
      echo "Token-store chart lifecycle on kind"
      echo
      if [ -f "$out/lifecycle.txt" ]; then cat "$out/lifecycle.txt"; fi
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

# The database, as the cluster sees it.
psql() { kubectl -n "$ns" exec deploy/postgres -- psql -U postgres -d tokenstore -Atc "$1"; }
tables() { psql "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'"; }
record() { psql "SELECT version || ' ' || name || ' ' || checksum || ' ' || applied_at FROM schema_migrations ORDER BY version"; }

# The service, as the kubelet sees it: its pod, reached through the API server's pod proxy, which
# answers while the pod is not Ready, when the Service would not.
# The service's pod that is not on its way out: a pod of a previous release can linger Terminating
# for its grace period, and a probe sent to it would be refused.
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
# probe PORT PATH OUT [curl args...]: prints the HTTP code (000 when the call fails) and writes the
# body to OUT.
probe() {
  local port=$1 path=$2 out_file=$3
  shift 3
  curl -sS -m 10 -o "$out_file" -w '%{http_code}' "$@" \
    "http://127.0.0.1:$proxy_port/api/v1/namespaces/$ns/pods/$(store_pod):$port/proxy$path" 2>/dev/null || true
}
# word FILE CHECK: the word a /readyz body gives for one check.
word() { jq -r ".checks.$2 // empty" "$1" 2>/dev/null || true; }
hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
# dependency_down NAME LABEL: the service stops being ready and stays alive while NAME is gone,
# and is ready again once it is back.
dependency_down() {
  local name=$1 label=$2 other
  if [ "$name" = postgres ]; then other=openbao; else other=postgres; fi
  kubectl -n "$ns" scale "deploy/$name" --replicas=0 >/dev/null
  kubectl -n "$ns" wait --for=delete pod -l "$label" --timeout=90s >/dev/null 2>&1 || true
  if kubectl -n "$ns" wait --for=condition=Ready=false pod -l "$store_sel" --timeout=120s >/dev/null 2>&1; then
    pass "with $name gone the pod leaves Ready"
  else
    fail "with $name gone the pod stayed Ready"
  fi
  local code
  code=$(probe 9090 /readyz "$out/$name-down-readyz.json")
  if [ "$code" = 503 ] && [ "$(word "$out/$name-down-readyz.json" "$name")" = unreachable ] && [ "$(word "$out/$name-down-readyz.json" "$other")" = ok ]; then
    pass "/readyz answers 503 with $name unreachable and $other ok"
  else
    fail "/readyz with $name gone: $code $(cat "$out/$name-down-readyz.json" 2>/dev/null)"
  fi
  code=$(probe 9090 /healthz "$out/$name-down-healthz.txt")
  if [ "$code" = 200 ]; then pass "/healthz stays 200 while $name is gone"; else fail "/healthz answered $code while $name was gone"; fi
  kubectl -n "$ns" scale "deploy/$name" --replicas=1 >/dev/null
  kubectl -n "$ns" rollout status "deploy/$name" --timeout=180s >/dev/null
  if kubectl -n "$ns" wait --for=condition=Ready pod -l "$store_sel" --timeout=120s >/dev/null 2>&1; then
    pass "with $name back the pod is Ready again"
  else
    fail "with $name back the pod did not become Ready"
  fi
  code=$(probe 9090 /readyz "$out/$name-back-readyz.json")
  if [ "$code" = 200 ] && [ "$(word "$out/$name-back-readyz.json" postgres)" = ok ] && [ "$(word "$out/$name-back-readyz.json" openbao)" = ok ]; then
    pass "/readyz answers 200 with both checks ok once $name is back"
  else
    fail "/readyz with $name back: $code $(cat "$out/$name-back-readyz.json" 2>/dev/null)"
  fi
}

# bao TOKEN ARGS...: the OpenBao CLI inside its pod. The token goes on the first line of stdin,
# never on a command line, and the rest of stdin is the command's own (a policy body, or nothing).
bao() {
  local token=$1
  shift
  { printf '%s\n' "$token"; cat; } | kubectl -n "$ns" exec -i deploy/openbao -- \
    sh -c 'IFS= read -r BAO_TOKEN; export BAO_TOKEN BAO_ADDR=http://127.0.0.1:8200; exec bao "$@"' sh "$@"
}
# b64url: base64url without padding, as RFC 7638 and the store's jkt column use.
b64url() { base64 | tr -d '\n=' | tr '+/' '-_'; }
# jkt_of_pem FILE: the RFC 7638 thumbprint of a P-256 public key in PEM, computed with openssl
# alone, independently of the store: the point from the DER encoding, the canonical JWK, SHA-256.
jkt_of_pem() {
  local der point x y
  der="$work/pub.der"
  openssl pkey -pubin -in "$1" -outform DER -out "$der"
  if [ "$(wc -c < "$der" | tr -d ' ')" != 91 ]; then echo "not a P-256 SubjectPublicKeyInfo" >&2; return 1; fi
  point="$work/pub.point"
  tail -c 65 "$der" > "$point"                       # 0x04 || X || Y
  x=$(tail -c 64 "$point" | head -c 32 | b64url)
  y=$(tail -c 32 "$point" | b64url)
  printf '{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}' "$x" "$y" | openssl dgst -sha256 -binary | b64url
}
# keys_run ACTION OUT: `token-store keys ACTION` from the built image, as an operator runs it: a
# one-off pod with the admin token, the acquisition config and the database URL, its output to
# OUT. Prints the pod's final phase. The pod carries the chart's name label so the dependencies'
# ingress policy admits it, and a component of its own so it is never mistaken for the server.
keys_run() {
  local action=$1 out_file=$2 pod="token-store-keys-$1"
  kubectl -n "$ns" apply -f - <<EOF >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: $pod
  labels: {app.kubernetes.io/name: ztd-token-store, app.kubernetes.io/component: keys}
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
    - name: keys
      image: "$reg/token-store@$digest"
      args: [keys, $action]
      env:
        - name: TOKEN_STORE_DATABASE_URL
          valueFrom: {secretKeyRef: {name: $secret, key: url}}
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
      configMap: {name: ztd-token-store-acquisition}
    - name: credentials
      secret: {secretName: token-store-admin, defaultMode: 0440}
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
# dependency_gone NAME LABEL PREFIX: the down half of dependency_down for the runtime stage, whose
# OpenBao is in memory and cannot come back as it was; in runtime mode the signing-key check must
# read unreachable too. Records go to PREFIX-NAME-*.
dependency_gone() {
  local name=$1 label=$2 prefix=$3 other
  if [ "$name" = postgres ]; then other=openbao; else other=postgres; fi
  kubectl -n "$ns" scale "deploy/$name" --replicas=0 >/dev/null
  kubectl -n "$ns" wait --for=delete pod -l "$label" --timeout=90s >/dev/null 2>&1 || true
  if kubectl -n "$ns" wait --for=condition=Ready=false pod -l "$store_sel" --timeout=120s >/dev/null 2>&1; then
    pass "runtime mode: with $name gone the pod leaves Ready"
  else
    fail "runtime mode: with $name gone the pod stayed Ready"
  fi
  local code f="$out/$prefix-$name-down-readyz.json"
  code=$(probe 9090 /readyz "$f")
  if [ "$code" = 503 ] && [ "$(word "$f" "$name")" = unreachable ] && [ "$(word "$f" "$other")" = ok ] && [ "$(word "$f" signing_key)" = unreachable ]; then
    pass "runtime mode: /readyz answers 503 with $name unreachable, signing_key unreachable and $other ok"
  else
    fail "runtime mode: /readyz with $name gone: $code $(cat "$f" 2>/dev/null)"
  fi
  code=$(probe 9090 /healthz "$out/$prefix-$name-down-healthz.txt")
  if [ "$code" = 200 ]; then pass "runtime mode: /healthz stays 200 while $name is gone"; else fail "runtime mode: /healthz answered $code while $name was gone"; fi
}

step "Image from the working tree"
docker build -q -f deployment/docker/token-store/Dockerfile -t "$host_reg/token-store:verify" . >/dev/null

step "Cluster and registry"
# Never replace a pre-existing local cluster or registry.
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
step "Enforce NetworkPolicy with the pinned Cilium chart"
curl -fsSL "https://helm.cilium.io/cilium-${CILIUM_CHART_VERSION}.tgz" -o "$work/cilium.tgz"
printf '%s  %s\n' "$CILIUM_CHART_SHA256" "$work/cilium.tgz" | sha256sum -c - >/dev/null
helm install cilium "$work/cilium.tgz" -n kube-system --set operator.replicas=1 \
  --set ipam.mode=kubernetes --set kubeProxyReplacement=false --set envoy.enabled=false \
  --set securityContext.privileged=true --set cgroup.autoMount.enabled=false \
  --set cgroup.hostRoot=/sys/fs/cgroup --wait --timeout 5m >/dev/null
kubectl wait --for=condition=Ready node --all --timeout=180s >/dev/null
pass "pinned Cilium enforces NetworkPolicy"
# The chart's runtime mode renders a PeerAuthentication; the pinned Istio CRDs make the API server
# accept it. No controller, no mesh: the resource is inert here.
curl -fsSL "https://raw.githubusercontent.com/istio/istio/${ISTIO_CRDS_VERSION}/manifests/charts/base/files/crd-all.gen.yaml" -o "$work/istio-crds.yaml"
printf '%s  %s\n' "$ISTIO_CRDS_SHA256" "$work/istio-crds.yaml" | sha256sum -c - >/dev/null
kubectl apply --server-side -f "$work/istio-crds.yaml" >/dev/null
registry_owned=true
docker run -d --name "$reg_name" --network kind -p "$host_reg:5000" "$REGISTRY_IMAGE" >/dev/null
for node in $(kind get nodes --name "$cluster"); do
  docker exec "$node" mkdir -p "/etc/containerd/certs.d/$reg"
  printf '[host."http://%s"]\n' "$reg" | docker exec -i "$node" cp /dev/stdin "/etc/containerd/certs.d/$reg/hosts.toml"
done
docker push -q "$host_reg/token-store:verify" >/dev/null
digest=$(docker image inspect --format '{{index .RepoDigests 0}}' "$host_reg/token-store:verify" | sed 's/.*@//')
echo "  token-store image $reg/token-store@$digest"

step "PostgreSQL and OpenBao from the pinned images, inside the cluster"
kubectl create namespace "$ns" >/dev/null
# Default-deny is installed before dependencies or any Helm hook can run.
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
        - podSelector:
            matchLabels: {app.kubernetes.io/name: ztd-token-store}
      ports: [{port: 5432, protocol: TCP}, {port: 8200, protocol: TCP}]
YAML
pass "namespace denies ingress and egress by default"
kubectl -n "$ns" create secret generic "$secret" --from-literal=url="$db_url" >/dev/null
# PostgreSQL keeps its data on a volume: the readiness proof takes it down and brings it back, and
# the schema must survive that. OpenBao runs in dev mode: in memory, initialised and unsealed at
# start, which is all the readiness check asks of it; its root token is this run's, so the runtime
# stage can mount transit and mint the store's scoped tokens, and it is one of the canaries no
# record may carry.
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
              # Over TCP: during the image's init the temporary server listens on the socket only.
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
EOF
kubectl -n "$ns" rollout status deploy/postgres --timeout=180s >/dev/null
kubectl -n "$ns" rollout status deploy/openbao --timeout=180s >/dev/null

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
  echo "  \"istio_crds_version\": \"$ISTIO_CRDS_VERSION\","
  echo "  \"embedded_schema_version\": $latest"
  echo "}"
} > "$out/environment.json"

cat > "$work/network-values.yaml" <<'YAML'
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
YAML
values=(-f "$work/network-values.yaml" --set "image.repository=$reg/token-store" --set "image.digest=$digest" --set "database.existingSecret=$secret" --set "openbao.address=http://openbao:8200")

step "Before the install: an empty database"
if [ "$(tables)" = 0 ]; then pass "the database holds no table before the install"; else fail "the database is not empty before the install: $(tables) tables"; fi

step "Negative control: removing schema egress must block the hook"
cp -R deployment/helm/token-store "$work/no-schema-policy"
rm "$work/no-schema-policy/templates/schema-networkpolicy.yaml"
if helm install schema-negative "$work/no-schema-policy" -n "$ns" "${values[@]}" \
  --wait --wait-for-jobs --timeout 45s >"$work/negative.log" 2>&1; then
  fail "schema hook completed without its egress policy"
else
  if kubectl -n "$ns" get job ztd-token-store-migrate -o json | jq -e '(.status.succeeded // 0) == 0 and ((.status.active // 0) > 0 or (.status.failed // 0) > 0)' >/dev/null; then
    pass "schema hook blocked without its egress policy under enforced default-deny"
  else
    fail "negative hook did not reach the network-policy control"
  fi
fi
helm uninstall schema-negative -n "$ns" --no-hooks >/dev/null 2>&1 || true
kubectl -n "$ns" delete job -l app.kubernetes.io/instance=schema-negative --wait=true >/dev/null
kubectl -n "$ns" delete serviceaccount ztd-token-store-schema --ignore-not-found >/dev/null
if [ "$(tables)" != 0 ]; then fail "negative hook mutated the schema"; fi

step "Install: the schema is applied"
helm install "$release" deployment/helm/token-store -n "$ns" "${values[@]}" --set schema.dropOnUninstall=true \
  --wait --wait-for-jobs --timeout 3m >/dev/null
if kubectl -n "$ns" get networkpolicy ztd-token-store-schema -o json | jq -e '.spec.podSelector.matchLabels["app.kubernetes.io/component"] == "schema" and .spec.policyTypes == ["Egress"] and (.metadata.annotations["helm.sh/hook-weight"] | tonumber) < 41' >/dev/null; then
  pass "schema egress policy precedes migration and drop hooks"
else fail "schema egress policy missing or incorrectly scoped"; fi
version=$(psql "SELECT coalesce(max(version), 0) FROM schema_migrations")
record > "$out/install-schema_migrations.txt"
psql "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY 1" > "$out/install-tables.txt"
if [ "$version" = "$latest" ]; then pass "the install applied the schema up to version $version, the embedded latest"; else fail "the install left the schema at version $version, embedded latest $latest"; fi
if [ "$(tables)" -gt 1 ]; then pass "the schema's tables exist ($(tables) tables, schema_migrations included)"; else fail "no tables after the install"; fi
if [ "$(kubectl -n "$ns" get jobs -o name | grep -c migrate)" = 0 ]; then pass "the succeeded migration Job was removed by its hook policy"; else fail "the migration Job is still there after a successful install"; fi

step "The service: ready, alive, correlated"
start_proxy
kubectl -n "$ns" rollout status deploy/ztd-token-store --timeout=90s >/dev/null
rid="verify-$(hex 8)"
tid="$(hex 16)"
sid="$(hex 8)"
code=$(probe 9090 /readyz "$out/install-readyz.json" -D "$out/install-readyz-headers.txt" -H "x-request-id: $rid" -H "traceparent: 00-$tid-$sid-01")
if [ "$code" = 200 ] && [ "$(word "$out/install-readyz.json" postgres)" = ok ] && [ "$(word "$out/install-readyz.json" openbao)" = ok ]; then
  pass "/readyz answers 200 with postgres ok and openbao ok"
else
  fail "/readyz after the install: $code $(cat "$out/install-readyz.json" 2>/dev/null)"
fi
if grep -qi "^x-request-id: $rid" "$out/install-readyz-headers.txt"; then pass "the response echoes the caller's x-request-id"; else fail "the response does not echo the caller's x-request-id"; fi
code=$(probe 9090 /healthz "$out/install-healthz.txt")
if [ "$code" = 200 ]; then pass "/healthz answers 200"; else fail "/healthz answered $code"; fi
code=$(probe 8080 /readyz "$out/install-api-readyz.json")
if [ "$code" = 200 ]; then pass "the API listener serves the contract's /readyz too"; else fail "/readyz on the API listener answered $code"; fi

step "PostgreSQL unreachable: not ready, still alive, ready again when it is back"
dependency_down postgres app=postgres

step "OpenBao unreachable: not ready, still alive, ready again when it is back"
dependency_down openbao app=openbao

step "Identity, no restart, every record correlated"
pod=$(store_pod)
sa=$(kubectl -n "$ns" get pod "$pod" -o jsonpath='{.spec.serviceAccountName}')
label=$(kubectl -n "$ns" get pod "$pod" -o jsonpath='{.metadata.labels.spiffe\.io/spire-managed-identity}')
printf 'serviceAccountName: %s\nspiffe.io/spire-managed-identity: %s\n' "$sa" "$label" > "$out/identity.txt"
if [ "$sa" = ztd-token-store ] && [ "$label" = true ]; then pass "the pod runs as ServiceAccount ztd-token-store with the identity label"; else fail "identity: serviceAccountName=$sa label=$label"; fi
restarts=$(kubectl -n "$ns" get pod "$pod" -o jsonpath='{.status.containerStatuses[0].restartCount}')
echo "restartCount: $restarts" > "$out/pod-status.txt"
if [ "$restarts" = 0 ]; then pass "liveness stayed green while the dependencies were gone: no restart"; else fail "the container restarted $restarts times"; fi
kubectl -n "$ns" logs "$pod" > "$out/store-logs.txt"
if jq -e . "$out/store-logs.txt" >/dev/null 2>&1; then
  pass "every record the service wrote is JSON"
  requests=$(jq -c 'select(.msg == "request")' "$out/store-logs.txt" | wc -l | tr -d ' ')
  uncorrelated=$(jq -c 'select(.msg == "request" and ((.correlation_id // "") == ""))' "$out/store-logs.txt" | wc -l | tr -d ' ')
  matched=$(jq -c --arg id "$rid" --arg t "$tid" --arg s "$sid" \
    'select(.msg == "request" and .path == "/readyz" and .correlation_id == $id and .trace_id == $t and .span_id == $s)' \
    "$out/store-logs.txt" | tee "$out/logs-correlation.txt" | wc -l | tr -d ' ')
  if [ "$requests" -gt 0 ] && [ "$uncorrelated" = 0 ]; then pass "every one of the $requests request records carries a correlation_id"; else fail "$uncorrelated of $requests request records carry no correlation_id"; fi
  if [ "$matched" -ge 1 ]; then pass "the caller's x-request-id, trace_id and span_id are on the probe's record"; else fail "no record carries the caller's x-request-id and trace context"; fi
else
  fail "a record the service wrote is not JSON"
fi
if [ "$(grep -c 'postgres:verify@' "$out/store-logs.txt" || true)" = 0 ]; then pass "no credential in the records"; else fail "the database credential reached the records"; fi

step "Upgrade: a no-op on a current database"
helm upgrade "$release" deployment/helm/token-store -n "$ns" "${values[@]}" --set schema.dropOnUninstall=true \
  --wait --wait-for-jobs --timeout 3m >/dev/null
record > "$out/upgrade-schema_migrations.txt"
if cmp -s "$out/install-schema_migrations.txt" "$out/upgrade-schema_migrations.txt"; then
  pass "the upgrade changed nothing: schema_migrations is identical, applied_at included"
else
  fail "the upgrade changed schema_migrations"
fi
revision=$(helm -n "$ns" history "$release" --max 1 -o json | sed -n 's/.*"revision":\([0-9]*\).*/\1/p')
if [ "$revision" = 2 ]; then pass "the upgrade went through as revision 2, so its hook ran and succeeded"; else fail "the release is at revision ${revision:-?}, want 2"; fi

step "Uninstall with schema.dropOnUninstall: an empty schema"
helm uninstall "$release" -n "$ns" --wait --timeout 3m >/dev/null
if [ "$(tables)" = 0 ]; then pass "the uninstall left an empty schema, schema_migrations included"; else fail "$(tables) tables left after the uninstall"; fi

step "Install and uninstall without schema.dropOnUninstall: the schema stays"
helm install "$release" deployment/helm/token-store -n "$ns" "${values[@]}" --wait --wait-for-jobs --timeout 3m >/dev/null
before=$(tables)
helm uninstall "$release" -n "$ns" --wait --timeout 3m >/dev/null
if [ "$before" -gt 1 ] && [ "$(tables)" = "$before" ]; then pass "by default the uninstall keeps the schema ($before tables before and after)"; else fail "the default uninstall changed the schema: $before tables before, $(tables) after"; fi

step "Runtime mode: key custody against OpenBao"
# Transit and two policies: the service's token reads its key, signs with it and owns its KV
# prefix; the operator's token may create, rotate and configure the key, and nothing else.
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
runtime_token=$(bao "$root" token create -policy=token-store -ttl=2h -format=json </dev/null | jq -r .auth.client_token)
admin_token=$(bao "$root" token create -policy=token-store-admin -ttl=2h -format=json </dev/null | jq -r .auth.client_token)
if [ "${#runtime_token}" -gt 20 ] && [ "${#admin_token}" -gt 20 ]; then pass "runtime mode: a service token and an operator token, each with its own policy"; else fail "runtime mode: token creation failed"; fi
kubectl -n "$ns" create secret generic ztd-token-store-credentials --from-literal=openbao-token="$runtime_token" >/dev/null
kubectl -n "$ns" create secret generic token-store-admin --from-literal=openbao-token="$admin_token" >/dev/null
# The acquisition config: the key's name and one trusted IF-03 issuer (its public key only; the
# private half never leaves this run's temporary directory). No routes: nothing is acquired here.
openssl ecparam -name prime256v1 -genkey -noout -out "$work/issuer-private.pem" 2>/dev/null
openssl ec -in "$work/issuer-private.pem" -pubout -out "$work/issuer.pem" 2>/dev/null
printf '{"signing_key":"%s","kv_prefix":"%s","trusted_issuers":[{"issuer":"https://verifier.verify.invalid","kid":"verify","public_key_file":"/etc/token-store/issuer.pem"}],"routes":[]}\n' "$key" "$kv_prefix" > "$work/acquisition.json"
kubectl -n "$ns" create configmap ztd-token-store-acquisition --from-file=acquisition.json="$work/acquisition.json" --from-file=issuer.pem="$work/issuer.pem" >/dev/null
kubectl -n "$ns" apply -f - <<'YAML' >/dev/null
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: token-store-keys}
spec:
  podSelector:
    matchLabels: {app.kubernetes.io/component: keys}
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

# 1. The key exists only in OpenBao; the database holds its reference and thumbprint.
# The command's JSON is the pod's stdout; a record on stderr would share the log, so the output
# document is picked by its field rather than assumed to be alone.
phase=$(keys_run ensure "$out/key-ensure.txt")
ensured_ref=$(jq -rs 'map(select(has("key_ref"))) | last | .key_ref // empty' "$out/key-ensure.txt" 2>/dev/null || true)
ensured_jkt=$(jq -rs 'map(select(has("key_ref"))) | last | .jkt // empty' "$out/key-ensure.txt" 2>/dev/null || true)
if [ "$phase" = Succeeded ] && [ "$ensured_ref" = "transit:$key:v1" ] && [ "${#ensured_jkt}" = 43 ]; then
  pass "keys ensure created the key in transit and registered $ensured_ref with its thumbprint"
else
  fail "keys ensure: phase $phase, $(cat "$out/key-ensure.txt" 2>/dev/null)"
fi
psql "SELECT key_ref || ' ' || jkt || ' ' || alg || ' ' || state FROM signing_key ORDER BY created_at" > "$out/key-row.txt"
if [ "$(wc -l < "$out/key-row.txt" | tr -d ' ')" = 1 ] && grep -q "^transit:$key:v1 $ensured_jkt ES256 active$" "$out/key-row.txt"; then
  pass "signing_key holds one row: the reference, the thumbprint, the algorithm and the state"
else
  fail "signing_key rows: $(cat "$out/key-row.txt")"
fi
bao "$root" read -format=json "transit/keys/$key" </dev/null > "$work/key.json"
jq -r '{type: .data.type, exportable: .data.exportable, allow_plaintext_backup: .data.allow_plaintext_backup, latest_version: .data.latest_version, min_encryption_version: .data.min_encryption_version}' "$work/key.json" > "$out/key-public.txt"
jq -r '.data.keys["1"].public_key' "$work/key.json" > "$work/key-v1.pem"
cat "$work/key-v1.pem" >> "$out/key-public.txt"
if jq -e '.data.type == "ecdsa-p256" and .data.exportable == false and .data.allow_plaintext_backup == false' "$work/key.json" >/dev/null; then
  pass "the transit key is ecdsa-p256, not exportable, no plaintext backup"
else
  fail "the transit key's settings: $(head -6 "$out/key-public.txt")"
fi
computed=$(jkt_of_pem "$work/key-v1.pem")
printf 'recorded  %s\ncomputed  %s\n' "$ensured_jkt" "$computed" > "$out/key-thumbprint.txt"
if [ -n "$computed" ] && [ "$computed" = "$ensured_jkt" ]; then
  pass "the recorded thumbprint equals the RFC 7638 thumbprint computed with openssl from the public key"
else
  fail "thumbprints differ: $(cat "$out/key-thumbprint.txt")"
fi
{
  echo "# with the root token"
  bao "$root" read "transit/export/signing-key/$key" </dev/null 2>&1 || echo "exit $?"
  echo "# with the service token"
  bao "$runtime_token" read "transit/export/signing-key/$key" </dev/null 2>&1 || echo "exit $?"
} > "$out/key-export-refused.txt"
if grep -q "exit [1-9]" "$out/key-export-refused.txt" && ! grep -q "BEGIN" "$out/key-export-refused.txt" && grep -qi "not exportable\|Code: 400" "$out/key-export-refused.txt" && grep -qi "permission denied\|Code: 403" "$out/key-export-refused.txt"; then
  pass "transit refuses to export the key: 400 not exportable to the root token, 403 to the service token"
else
  # Never the file itself: the one way this fails is an export that succeeded, and that output is
  # the private key. The statuses and the count of PEM lines say what happened.
  fail "key export: exits $(grep -c '^exit' "$out/key-export-refused.txt" || true), statuses $(grep -o 'Code: [0-9]*' "$out/key-export-refused.txt" | tr '\n' ' '), PEM lines $(grep -c BEGIN "$out/key-export-refused.txt" || true); see key-export-refused.txt"
fi

# 2. The service in runtime mode, with the service token only, comes up ready with signing_key ok.
helm install "$release" deployment/helm/token-store -n "$ns" "${values[@]}" --set schema.dropOnUninstall=true \
  --set runtime.enabled=true --set runtime.existingConfigMap=ztd-token-store-acquisition \
  --set runtime.credentialsSecret=ztd-token-store-credentials --wait --wait-for-jobs --timeout 3m >/dev/null
kubectl -n "$ns" rollout status deploy/ztd-token-store --timeout=90s >/dev/null
code=$(probe 9090 /readyz "$out/runtime-install-readyz.json")
if [ "$code" = 200 ] && [ "$(word "$out/runtime-install-readyz.json" signing_key)" = ok ]; then
  pass "runtime mode: /readyz answers 200 with signing_key ok, through the service token alone"
else
  fail "runtime mode: /readyz after the install: $code $(cat "$out/runtime-install-readyz.json" 2>/dev/null)"
fi
pem_body=$(grep -v -- '-----' "$work/key-v1.pem" | tr -d '\n')
# The first 36 characters of every P-256 public key PEM are the same DER header; the canary is
# taken from the point itself, so it names this key and no other.
pem_point=${pem_body:36:24}
scan() {
  # scan FILE LABEL: counts of every canary in FILE, as "LABEL needle count" lines; prints the sum.
  local file=$1 label=$2 total=0 n
  for needle in "$root" "$admin_token" "$runtime_token" "$pem_point" "BEGIN " "PRIVATE KEY" "-----"; do
    n=$(grep -c -F -- "$needle" "$file" || true)
    printf '%s  %-14s %s\n' "$label" "$(case "$needle" in "$root") echo root-token;; "$admin_token") echo admin-token;; "$runtime_token") echo service-token;; "$pem_point") echo pem-point;; *) echo "'$needle'";; esac)" "$n" >> "$out/key-material-scan.txt"
    total=$((total + n))
  done
  echo "$total"
}
: > "$out/key-material-scan.txt"
# Positive control: a file that holds every canary once must count seven, so an empty or wrong
# needle cannot pass as "not found".
printf '%s\n%s\n%s\n%s\nBEGIN \nPRIVATE KEY\n-----\n' "$root" "$admin_token" "$runtime_token" "$pem_point" > "$work/canaries.txt"
if [ "${#pem_point}" = 24 ] && [ "$(scan "$work/canaries.txt" control)" = 7 ] && [ "$(grep -c -F -- "$pem_point" "$work/key-v1.pem")" = 1 ] && [ "$(grep -c -F -- "$pem_point" "$work/issuer.pem")" = 0 ]; then
  pass "the canary scan finds each of its seven needles where planted, and the PEM canary names this key alone"
else
  fail "the canary scan's positive control: $(grep control "$out/key-material-scan.txt" | tr '\n' ';')"
fi
kubectl -n "$ns" exec deploy/postgres -- pg_dump -U postgres tokenstore > "$work/dump.sql"
if [ "$(scan "$work/dump.sql" database)" = 0 ]; then
  pass "the database dump carries no key material and no OpenBao token"
else
  fail "key material or a token in the database dump: $(grep database "$out/key-material-scan.txt" | tr '\n' ';')"
fi

# 3. Rotation: the next version is active, the previous one retired, and transit no longer signs with it.
phase=$(keys_run rotate "$out/key-rotate.txt")
if [ "$phase" = Succeeded ] && jq -es --arg k "$key" 'map(select(has("active"))) | last | .active == ("transit:" + $k + ":v2") and .retired == ["transit:" + $k + ":v1"] and .min_signing_version == 2 and .adopted == false' "$out/key-rotate.txt" >/dev/null; then
  pass "keys rotate activated transit:$key:v2, retired v1 and set transit's signing floor to 2"
else
  fail "keys rotate: phase $phase, $(cat "$out/key-rotate.txt" 2>/dev/null)"
fi
psql "SELECT key_ref || ' ' || state || ' ' || coalesce(retired_at::text, '-') FROM signing_key ORDER BY created_at" > "$out/key-rows-after-rotate.txt"
if [ "$(psql "SELECT count(*) FROM signing_key WHERE state = 'active'")" = 1 ] && grep -q "^transit:$key:v1 retired 20" "$out/key-rows-after-rotate.txt" && grep -q "^transit:$key:v2 active -$" "$out/key-rows-after-rotate.txt"; then
  pass "signing_key: v1 retired with retired_at, v2 the one active version"
else
  fail "signing_key after the rotation: $(cat "$out/key-rows-after-rotate.txt" | tr '\n' ';')"
fi
code=$(probe 9090 /readyz "$out/runtime-rotate-readyz.json")
if [ "$code" = 200 ] && [ "$(word "$out/runtime-rotate-readyz.json" signing_key)" = ok ]; then
  pass "runtime mode: the running service resolves the rotated key: /readyz 200 with signing_key ok"
else
  fail "runtime mode: /readyz after the rotation: $code $(cat "$out/runtime-rotate-readyz.json" 2>/dev/null)"
fi
phase=$(keys_run status "$out/key-status.txt")
if [ "$phase" = Succeeded ] && jq -es 'map(select(has("versions"))) | last | .present == true and .latest_version == 2 and .min_signing_version == 2 and (.versions | length) == 2 and all(.versions[]; (.jkt | length) == 43)' "$out/key-status.txt" >/dev/null; then
  pass "keys status reports the two registered versions, transit's latest version and its signing floor"
else
  fail "keys status: phase $phase, $(cat "$out/key-status.txt" 2>/dev/null)"
fi
input=$(printf 'eyJhbGciOiJFUzI1NiJ9.e30' | base64 | tr -d '\n')
{
  echo "# key_version=1, retired"
  bao "$runtime_token" write "transit/sign/$key" key_version=1 input="$input" </dev/null 2>&1 | grep -v '^signature\|vault:v' || echo "exit $?"
  echo "# key_version=2, active"
  if bao "$runtime_token" write -format=json "transit/sign/$key" key_version=2 input="$input" </dev/null 2>/dev/null | jq -e '.data.signature | startswith("vault:v2:")' >/dev/null; then echo "signed with v2: ok"; else echo "signed with v2: FAILED"; fi
} > "$out/key-retired-sign-refused.txt"
if grep -q "exit [1-9]" "$out/key-retired-sign-refused.txt" && grep -qi "less than the minimum" "$out/key-retired-sign-refused.txt" && grep -q "signed with v2: ok" "$out/key-retired-sign-refused.txt"; then
  pass "transit refuses to sign with the retired version and signs with the active one"
else
  fail "signing after the rotation: $(cat "$out/key-retired-sign-refused.txt" | tr '\n' ';')"
fi

# 4. OpenBao gone: readiness fails closed, liveness holds, and the records carry no key material.
dependency_gone openbao app=openbao runtime
pod=$(store_pod)
restarts=$(kubectl -n "$ns" get pod "$pod" -o jsonpath='{.status.containerStatuses[?(@.name=="server")].restartCount}')
echo "restartCount: $restarts" > "$out/runtime-pod-status.txt"
if [ "$restarts" = 0 ]; then pass "runtime mode: no restart while OpenBao was gone"; else fail "runtime mode: the container restarted $restarts times"; fi
kubectl -n "$ns" logs "$pod" -c server > "$out/runtime-store-logs.txt"
if jq -e . "$out/runtime-store-logs.txt" >/dev/null 2>&1; then pass "runtime mode: every record is JSON"; else fail "runtime mode: a record is not JSON"; fi
resolved=$(jq -c 'select(.msg == "signing keys resolved")' "$out/runtime-store-logs.txt" | wc -l | tr -d ' ')
stopped=$(jq -c 'select(.msg == "signing key misconfigured; stopping")' "$out/runtime-store-logs.txt" | wc -l | tr -d ' ')
if [ "$resolved" = 1 ] && [ "$stopped" = 0 ]; then pass "startup resolved the signing keys once and found no misconfiguration"; else fail "startup records: resolved $resolved, misconfigured $stopped"; fi
if [ "$(scan "$out/runtime-store-logs.txt" records)" = 0 ] && [ "$(grep -c 'postgres:verify@' "$out/runtime-store-logs.txt" || true)" = 0 ]; then
  pass "no key material, OpenBao token or database credential in the records"
else
  fail "key material or a credential in the records: $(grep records "$out/key-material-scan.txt" | tr '\n' ';')"
fi
helm uninstall "$release" -n "$ns" --wait --timeout 3m >/dev/null
if [ "$(tables)" = 0 ]; then pass "runtime mode: the uninstall left an empty schema"; else fail "runtime mode: $(tables) tables left after the uninstall"; fi

step "Verdict"
if [ "$failures" = 0 ]; then verdict=PASS; else verdict=FAIL; fi
{
  echo "Token-store chart lifecycle on kind"
  echo
  cat "$out/lifecycle.txt"
  echo
  echo "verdict: $verdict"
} > "$out/verdict.txt"
echo "verdict: $verdict ($failures failed)"
[ "$failures" = 0 ]
