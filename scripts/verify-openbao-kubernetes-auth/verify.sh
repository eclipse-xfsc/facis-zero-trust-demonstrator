#!/usr/bin/env bash
# OpenBao Kubernetes auth on a throwaway kind cluster (docs/secrets.md#kubernetes-auth): the
# ztd-openbao release, installed with kubernetesAuth on, has its bootstrap enable auth/kubernetes/
# against the cluster's API server (the server's own CA and rotating service-account token review the
# logins through the auth-delegator binding) and write one narrow role; a pod with an audience-bound
# projected token logs in; then the Go client's token source (internal/transit, the one the connector
# and the token store use) is run against the real server and API server with a short token ttl:
# least privilege, renewal at half the lease with a rotated token, a fresh login after the token
# expired, a restarted client, and refusals of a wrong ServiceAccount, namespace and audience. Last,
# an upgrade that changes the roles of a store whose root token is revoked fails loudly instead of
# leaving the roles unapplied. Short ttls prove expiry and re-login; they are not a soak.
#
#   scripts/verify-openbao-kubernetes-auth/verify.sh [--out DIR]   default .dev/openbao-kubernetes-auth-evidence
#   BIN=<dir with kind and kubectl> ...                           default .tools/bin
#
# Needs docker, helm, kind, kubectl, go, jq, sha256sum. KEEP=1 leaves the cluster.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env
if [ -d "${BIN:-.tools/bin}" ]; then PATH="$(cd "${BIN:-.tools/bin}" && pwd):$PATH"; export PATH; fi

out=.dev/openbao-kubernetes-auth-evidence
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
for tool in docker helm kind kubectl go jq sha256sum; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 2; }
done
mkdir -p "$out"
out="$(cd "$out" && pwd)"
rm -f "$out"/*.txt "$out"/*.json

cluster=${KUBEAUTH_KIND_CLUSTER:-ztd-openbao-kubeauth}
ns=ztd-mgmt
app_ns=kubeauth-a
role=kubeauth-app
ttl=20s
work="$(mktemp -d)"
export KUBECONFIG="$work/kubeconfig"
cluster_owned=false
pf_pid=""
failures=0
pass() { echo "PASS  $*" | tee -a "$out/checks.txt"; }
fail() { echo "FAIL  $*" | tee -a "$out/checks.txt"; failures=$((failures + 1)); }
step() { echo; echo "== $*"; }
cleanup() {
  if [ ! -f "$out/verdict.txt" ]; then
    { cat "$out/checks.txt" 2>/dev/null; echo; echo "verdict: FAIL (the run stopped before its last check)"; } > "$out/verdict.txt"
  fi
  if [ -n "$pf_pid" ]; then kill "$pf_pid" >/dev/null 2>&1 || true; fi
  if [ -n "${KEEP:-}" ]; then echo "kept: cluster $cluster, KUBECONFIG=$KUBECONFIG"; return; fi
  if [ "$cluster_owned" = true ]; then kind delete cluster --name "$cluster" >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

step "Cluster"
if kind get clusters | grep -Fxq "$cluster"; then echo "refusing to replace an existing cluster" >&2; exit 1; fi
cluster_owned=true
kind create cluster --name "$cluster" --image "$KIND_NODE_IMAGE" --wait 120s >/dev/null
for n in "$ns" "$app_ns" kubeauth-b; do kubectl create namespace "$n" >/dev/null; done
kubectl -n "$app_ns" create serviceaccount "$role" >/dev/null
kubectl -n "$app_ns" create serviceaccount kubeauth-other >/dev/null
kubectl -n kubeauth-b create serviceaccount "$role" >/dev/null

step "ztd-openbao with kubernetesAuth"
cat > "$work/auth-values.yaml" <<EOF
cilium: {enabled: false}
openbao:
  server:
    authDelegator: {enabled: true}
kubernetesAuth:
  enabled: true
  roles:
    - name: $role
      namespace: $app_ns
      serviceAccount: $role
      audience: openbao
      ttl: $ttl
      policy: |
        path "transit/keys/kubeauth-test" { capabilities = ["read", "update"] }
EOF
helm dependency build deployment/helm/ztd-openbao >/dev/null
scripts/ci/verify-chart-dependencies.sh deployment/helm/ztd-openbao
helm install ztd-openbao deployment/helm/ztd-openbao -n "$ns" -f deployment/helm/ztd-openbao/ci/values.yaml \
  -f "$work/auth-values.yaml" --wait --wait-for-jobs --timeout 6m >/dev/null
kubectl -n "$ns" logs -l app.kubernetes.io/name=ztd-openbao-bootstrap -c bootstrap --tail=-1 > "$out/bootstrap.log"
if grep -q "Kubernetes auth role $role" "$out/bootstrap.log" && grep -q "root token revoked and removed" "$out/bootstrap.log"; then
  pass "the bootstrap enabled auth/kubernetes/, wrote role $role, then revoked the root token"
else
  fail "bootstrap log: $(tr '\n' ';' < "$out/bootstrap.log")"
fi
marker=$(kubectl -n "$ns" get secret ztd-openbao-bootstrap -o json | jq -r '.data["kubernetes-auth"] // empty' | base64 -d)
if [ -n "$marker" ] && [ -z "$(kubectl -n "$ns" get secret ztd-openbao-bootstrap -o json | jq -r '.data["root-token"] // empty')" ]; then
  pass "the bootstrap Secret records the applied configuration ($marker) and holds no root token"
else
  fail "bootstrap Secret marker '$marker'"
fi
kubectl get clusterrolebinding -o json | jq -r '.items[] | select(.roleRef.name == "system:auth-delegator") | .metadata.name + " -> " + (.subjects[0].namespace + "/" + .subjects[0].name)' > "$out/auth-delegator.txt"
if grep -q " -> $ns/ztd-openbao$" "$out/auth-delegator.txt"; then pass "system:auth-delegator is bound to $ns/ztd-openbao only"; else fail "auth-delegator: $(cat "$out/auth-delegator.txt")"; fi

step "A pod logs in with its projected, audience-bound token"
curl_image=$(sed -n 's|^  image: \(docker.io/curlimages/.*\)$|\1|p' deployment/helm/ztd-openbao/values.yaml)
kubectl -n "$app_ns" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: login}
spec:
  serviceAccountName: $role
  automountServiceAccountToken: false
  restartPolicy: Never
  containers:
    - name: login
      image: $curl_image
      command: [sh, -c]
      args:
        - 'printf "{\"role\":\"$role\",\"jwt\":\"%s\"}" "\$(cat /var/run/secrets/openbao/token)" > /tmp/b; curl -s -o /dev/null -w "%{http_code}" -X POST --data-binary @/tmp/b http://ztd-openbao.$ns.svc:8200/v1/auth/kubernetes/login; rm -f /tmp/b'
      volumeMounts: [{name: t, mountPath: /var/run/secrets/openbao, readOnly: true}]
  volumes:
    - name: t
      projected:
        sources: [{serviceAccountToken: {audience: openbao, expirationSeconds: 600, path: token}}]
EOF
kubectl -n "$app_ns" wait --for=jsonpath='{.status.phase}'=Succeeded pod/login --timeout=120s >/dev/null || true
code=$(kubectl -n "$app_ns" logs login)
if [ "$code" = 200 ]; then pass "a pod of $app_ns/$role logs in with its projected token (HTTP 200)"; else fail "pod login answered $code"; fi

step "The token source against the real server (ttl $ttl)"
jwts="$work/jwts"; mkdir -m 700 "$jwts"
kubectl -n "$app_ns" create token "$role" --audience openbao --duration 10m > "$jwts/good"
kubectl -n "$app_ns" create token "$role" --audience openbao --duration 10m > "$jwts/rotated"
kubectl -n "$app_ns" create token kubeauth-other --audience openbao --duration 10m > "$jwts/wrong-sa"
kubectl -n kubeauth-b create token "$role" --audience openbao --duration 10m > "$jwts/wrong-ns"
kubectl -n "$app_ns" create token "$role" --audience not-openbao --duration 10m > "$jwts/wrong-aud"
kubectl -n "$ns" port-forward svc/ztd-openbao 18200:8200 >/dev/null 2>&1 &
pf_pid=$!
for _ in $(seq 1 50); do curl -fsS -o /dev/null http://127.0.0.1:18200/v1/sys/health && break; sleep 0.2; done
if KUBEAUTH_TEST_ADDR=http://127.0.0.1:18200 KUBEAUTH_TEST_ROLE=$role KUBEAUTH_TEST_JWTS="$jwts" KUBEAUTH_TEST_KEY=kubeauth-test KUBEAUTH_TEST_TTL=$ttl \
  go test -count=1 -v -run TestOpenBaoKubernetesAuth ./internal/transit/ > "$out/go-test.txt" 2>&1 && grep -q -- "--- PASS: TestOpenBaoKubernetesAuth" "$out/go-test.txt"; then
  pass "token source: login, least privilege, renewal with a rotated token, re-login after expiry, restart, refused wrong SA/namespace/audience ($(grep -c -- '--- PASS' "$out/go-test.txt") passes)"
else
  fail "token source: $(grep -- '--- \(FAIL\|SKIP\)' "$out/go-test.txt" | tr '\n' ';')"
fi
if grep -q "eyJ" "$out/go-test.txt"; then fail "a JWT reached the test output"; fi

step "An upgrade that changes the roles of a configured store fails loudly"
sed -i.bak "s/ttl: $ttl/ttl: 30s/" "$work/auth-values.yaml"
if helm upgrade ztd-openbao deployment/helm/ztd-openbao -n "$ns" -f deployment/helm/ztd-openbao/ci/values.yaml \
  -f "$work/auth-values.yaml" --wait --wait-for-jobs --timeout 4m >/dev/null 2>&1; then
  fail "the upgrade succeeded although the store's root token is revoked"
else
  kubectl -n "$ns" logs -l app.kubernetes.io/name=ztd-openbao-bootstrap -c bootstrap --tail=-1 > "$out/bootstrap-upgrade.log" 2>&1 || true
  if grep -q "is not applied to this store" "$out/bootstrap-upgrade.log"; then
    pass "the upgrade failed: the bootstrap names the unapplied configuration and docs/secrets.md#kubernetes-auth"
  else
    fail "the upgrade failed for another reason: $(tail -3 "$out/bootstrap-upgrade.log" | tr '\n' ';')"
  fi
fi

{
  echo "{"
  echo "  \"commit\": \"$(git rev-parse HEAD)\","
  echo "  \"tree\": \"$(if [ -n "$(git status --porcelain)" ]; then echo dirty; else echo clean; fi)\","
  echo "  \"date\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"kind_node_image\": \"$KIND_NODE_IMAGE\","
  echo "  \"helm\": \"$(helm version --short)\","
  echo "  \"role_ttl\": \"$ttl\""
  echo "}"
} > "$out/environment.json"
if [ "$failures" = 0 ]; then verdict=PASS; else verdict=FAIL; fi
{ cat "$out/checks.txt"; echo; echo "verdict: $verdict"; } > "$out/verdict.txt"
echo "verdict: $verdict ($failures failed)"
[ "$failures" = 0 ]
