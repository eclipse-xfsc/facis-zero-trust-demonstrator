#!/usr/bin/env bash
# The token-store chart's lifecycle and the service's readiness on a throwaway kind cluster: an
# install applies the schema to an empty database and brings the service up ready; the service
# stops being ready, and stays alive, while PostgreSQL or the key-value store is unreachable, and
# is ready again when they are back; its records are JSON, every request's record carries a
# correlation id, and a caller's x-request-id and traceparent reach its records; it runs as its
# own ServiceAccount with the identity label; an upgrade of a current database changes nothing;
# an uninstall with schema.dropOnUninstall leaves the schema empty; an uninstall without it keeps
# the schema. Builds the image from the working tree, pushes it to a registry on the kind network,
# runs PostgreSQL and OpenBao from the pinned images inside the cluster with the connection URL in
# a Secret, as a real deployment has it, and writes its records and verdict to --out.
#
#   scripts/verify-token-store/verify.sh [--out DIR]       default .dev/token-store-evidence (git-ignored)
#   BIN=<dir with kind and kubectl> ...                    default .tools/bin (scripts/tools/install.sh kind kubectl)
#
# Needs docker, helm, kind, kubectl, curl, jq. KEEP=1 leaves the cluster and registry running for
# inspection.
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
for tool in docker helm kind kubectl curl jq; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 2; }
done
mkdir -p "$out"
out="$(cd "$out" && pwd)"
rm -f "$out"/*.txt "$out"/*.json

cluster=ztd-token-store
reg_name=kind-registry-token-store
reg="$reg_name:5000"            # the registry's name inside the kind network
host_reg=127.0.0.1:5002         # the same registry from this machine, for the push
ns=ztd-mgmt
release=token-store
secret=token-store-database
db_url='postgres://postgres:verify@postgres:5432/tokenstore?sslmode=disable'
latest=$(find services/token-store/internal/schema/migrations -name '*.up.sql' | wc -l | tr -d ' ')
store_sel='app.kubernetes.io/name=ztd-token-store,app.kubernetes.io/component=server'
work="$(mktemp -d)"
export KUBECONFIG="$work/kubeconfig"
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
  kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
  docker rm -f "$reg_name" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

# The database, as the cluster sees it.
psql() { kubectl -n "$ns" exec deploy/postgres -- psql -U postgres -d tokenstore -Atc "$1"; }
tables() { psql "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'"; }
record() { psql "SELECT version || ' ' || name || ' ' || checksum || ' ' || applied_at FROM schema_migrations ORDER BY version"; }

# The service, as the kubelet sees it: its pod, reached through the API server's pod proxy, which
# answers while the pod is not Ready, when the Service would not.
store_pod() { kubectl -n "$ns" get pod -l "$store_sel" -o jsonpath='{.items[0].metadata.name}'; }
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

step "Image from the working tree"
docker build -q -f deployment/docker/token-store/Dockerfile -t "$host_reg/token-store:verify" . >/dev/null

step "Cluster and registry"
# A cluster or registry kept by an earlier run (KEEP=1) is replaced.
kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
docker rm -f "$reg_name" >/dev/null 2>&1 || true
kind create cluster --name "$cluster" --image "$KIND_NODE_IMAGE" --wait 180s --config - <<'EOF' >/dev/null
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry]
      config_path = "/etc/containerd/certs.d"
EOF
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
kubectl -n "$ns" create secret generic "$secret" --from-literal=url="$db_url" >/dev/null
# PostgreSQL keeps its data on a volume: the readiness proof takes it down and brings it back, and
# the schema must survive that. OpenBao runs in dev mode: in memory, initialised and unsealed at
# start, which is all the readiness check asks of it.
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
  echo "  \"embedded_schema_version\": $latest"
  echo "}"
} > "$out/environment.json"

values=(--set "image.repository=$reg/token-store" --set "image.digest=$digest" --set "database.existingSecret=$secret" --set "openbao.address=http://openbao:8200")

step "Before the install: an empty database"
if [ "$(tables)" = 0 ]; then pass "the database holds no table before the install"; else fail "the database is not empty before the install: $(tables) tables"; fi

step "Install: the schema is applied"
helm install "$release" deployment/helm/token-store -n "$ns" "${values[@]}" --set schema.dropOnUninstall=true \
  --wait --wait-for-jobs --timeout 3m >/dev/null
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
