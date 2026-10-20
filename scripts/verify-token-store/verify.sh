#!/usr/bin/env bash
# The token-store chart's lifecycle on a throwaway kind cluster: an install applies the schema to
# an empty database, an upgrade of a current database changes nothing, an uninstall with
# schema.dropOnUninstall leaves the schema empty, and an uninstall without it keeps the schema.
# Builds the image from the working tree, pushes it to a registry on the kind network, runs
# PostgreSQL from the pinned image inside the cluster with its connection URL in a Secret, as a
# real deployment has it, and writes its records and verdict to --out.
#
#   scripts/verify-token-store/verify.sh [--out DIR]       default .dev/token-store-evidence (git-ignored)
#   BIN=<dir with kind and kubectl> ...                    default .tools/bin (scripts/tools/install.sh kind kubectl)
#
# Needs docker, helm, kind, kubectl. KEEP=1 leaves the cluster and registry running for inspection.
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
for tool in docker helm kind kubectl; do
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
work="$(mktemp -d)"
export KUBECONFIG="$work/kubeconfig"

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

step "PostgreSQL from the pinned image, inside the cluster"
kubectl create namespace "$ns" >/dev/null
kubectl -n "$ns" create secret generic "$secret" --from-literal=url="$db_url" >/dev/null
kubectl -n "$ns" apply -f - <<EOF >/dev/null
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
spec:
  replicas: 1
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
          ports:
            - containerPort: 5432
          readinessProbe:
            exec:
              # Over TCP: during the image's init the temporary server listens on the socket only.
              command: [pg_isready, -h, 127.0.0.1, -U, postgres, -d, tokenstore]
            periodSeconds: 2
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
spec:
  selector: {app: postgres}
  ports:
    - port: 5432
EOF
kubectl -n "$ns" rollout status deploy/postgres --timeout=180s >/dev/null

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
  echo "  \"registry_image\": \"$REGISTRY_IMAGE\","
  echo "  \"token_store_image\": \"$reg/token-store@$digest\","
  echo "  \"embedded_schema_version\": $latest"
  echo "}"
} > "$out/environment.json"

values=(--set "image.repository=$reg/token-store" --set "image.digest=$digest" --set "database.existingSecret=$secret")

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
