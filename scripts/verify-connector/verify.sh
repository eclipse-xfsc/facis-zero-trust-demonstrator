#!/usr/bin/env bash
# The connector chart and the registration path on a throwaway kind cluster: the token-store chart
# prepares the schema, the connector installs and comes up ready against PostgreSQL and OpenBao
# with its signing key; a client registers through the registrar with `connector register` from the
# connector's own image and gets its credentials file; a registration the policy refuses is refused
# with the specific error; both decisions are in the audit trail and on the security-state feed; the
# pod runs as its own ServiceAccount with the identity label and never restarts; no secret reaches
# any record; the service drains on SIGTERM. Builds both images from the working tree, pushes them
# to a registry on the kind network, and writes its records and verdict to --out.
#
#   scripts/verify-connector/verify.sh [--out DIR]       default .dev/connector-evidence (git-ignored)
#   BIN=<dir with kind and kubectl> ...                   default .tools/bin (scripts/tools/install.sh kind kubectl)
#
# Needs docker, helm, kind, kubectl, curl, jq. KEEP=1 leaves the cluster and registry running for
# inspection.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env
if [ -d "${BIN:-.tools/bin}" ]; then PATH="$(cd "${BIN:-.tools/bin}" && pwd):$PATH"; export PATH; fi

out=.dev/connector-evidence
while [ $# -gt 0 ]; do
  case "$1" in
    --out)
      if [ $# -lt 2 ] || [ -z "$2" ]; then echo "--out needs a directory" >&2; exit 2; fi
      out="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$out"
out="$(cd "$out" && pwd)"
# Only this proof's own records are replaced; nothing else in --out is touched.
for record in lifecycle.txt verdict.txt environment.json readyz.json readyz-headers.txt healthz.txt jwks.json \
  register-ok.txt register-refused.txt audit-events.txt connector-logs.txt if01-events.jsonl identity.txt drain.txt; do
  rm -f "$out/$record"
done

cluster=ztd-connector
reg_name=kind-registry-connector
reg="$reg_name:5000"            # the registry's name inside the kind network
host_reg=127.0.0.1:5003         # the same registry from this machine, for the push
ns=ztd-mgmt
issuer=https://connector-b.verify.invalid
resource=https://resource.verify.invalid
hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
# Throwaway credentials of this run's PostgreSQL and OpenBao, never the same twice.
bao_root="$(hex 16)"
db_password="$(hex 12)"
db_url="postgres://postgres:$db_password@postgres:5432/tokenstore?sslmode=disable"
connector_sel='app.kubernetes.io/name=ztd-connector,app.kubernetes.io/component=server'
work="$(mktemp -d)"
export KUBECONFIG="$work/kubeconfig"
proxy_pid=""
proxy_port=""

failures=0
current_step="the tool check"
pass() { echo "PASS  $*" | tee -a "$out/lifecycle.txt"; }
fail() { echo "FAIL  $*" | tee -a "$out/lifecycle.txt"; failures=$((failures + 1)); }
step() { current_step="$*"; echo; echo "== $*"; }
cleanup() {
  if [ ! -f "$out/verdict.txt" ]; then
    {
      echo "Connector chart and registration path on kind"
      echo
      if [ -f "$out/lifecycle.txt" ]; then cat "$out/lifecycle.txt"; fi
      echo
      echo "verdict: FAIL (the run stopped during: $current_step)"
    } > "$out/verdict.txt"
  fi
  if [ -n "$proxy_pid" ]; then kill "$proxy_pid" >/dev/null 2>&1 || true; fi
  if [ -n "${KEEP:-}" ]; then
    echo "kept: cluster $cluster, registry $reg_name, KUBECONFIG=$KUBECONFIG"
    return
  fi
  if command -v kind >/dev/null; then kind delete cluster --name "$cluster" >/dev/null 2>&1 || true; fi
  if command -v docker >/dev/null; then docker rm -f "$reg_name" >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT
for tool in docker helm kind kubectl curl jq; do
  if ! command -v "$tool" >/dev/null; then fail "$tool is required"; exit 2; fi
done
# leaks FILE VALUE...: true when FILE holds any of the non-empty values.
leaks() {
  local file=$1 value
  shift
  for value in "$@"; do
    if [ -n "$value" ] && grep -qF -- "$value" "$file"; then return 0; fi
  done
  return 1
}

psql() { kubectl -n "$ns" exec deploy/postgres -- psql -U postgres -d tokenstore -Atc "$1"; }
tables() { psql "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'"; }
connector_pod() { kubectl -n "$ns" get pod -l "$connector_sel" -o jsonpath='{.items[0].metadata.name}'; }
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
# probe PORT PATH OUT [curl args...]: prints the HTTP code (000 when the call fails), body to OUT.
probe() {
  local port=$1 path=$2 out_file=$3
  shift 3
  curl -sS -m 10 -o "$out_file" -w '%{http_code}' "$@" \
    "http://127.0.0.1:$proxy_port/api/v1/namespaces/$ns/pods/$(connector_pod):$port/proxy$path" 2>/dev/null || true
}
word() { jq -r ".checks.$2 // empty" "$1" 2>/dev/null || true; }
bao() { kubectl -n "$ns" exec deploy/openbao -- env BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN="$bao_root" bao "$@"; }

step "Images from the working tree"
docker build -q -f deployment/docker/token-store/Dockerfile -t "$host_reg/token-store:verify" . >/dev/null
docker build -q -f deployment/docker/connector/Dockerfile -t "$host_reg/connector:verify" . >/dev/null

step "Cluster and registry"
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
docker push -q "$host_reg/connector:verify" >/dev/null
store_digest=$(docker image inspect --format '{{index .RepoDigests 0}}' "$host_reg/token-store:verify" | sed 's/.*@//')
connector_digest=$(docker image inspect --format '{{index .RepoDigests 0}}' "$host_reg/connector:verify" | sed 's/.*@//')
echo "  connector image $reg/connector@$connector_digest"

step "PostgreSQL and OpenBao from the pinned images, the Secrets, the transit key"
kubectl create namespace "$ns" >/dev/null
registrar_secret=$(hex 24)
kubectl -n "$ns" create secret generic token-store-database --from-literal=url="$db_url" >/dev/null
kubectl -n "$ns" create secret generic connector-secrets --from-literal=token-secret="$(hex 24)" \
  --from-literal=registration-secret="$(hex 24)" --from-literal=registrar-secret="$registrar_secret" >/dev/null
kubectl -n "$ns" create secret generic connector-openbao --from-literal=token="$bao_root" >/dev/null
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
            - {name: POSTGRES_PASSWORD, value: "$db_password"}
            - {name: POSTGRES_DB, value: tokenstore}
          ports:
            - containerPort: 5432
          readinessProbe:
            exec:
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
            - {name: BAO_DEV_ROOT_TOKEN_ID, value: "$bao_root"}
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
bao secrets enable transit >/dev/null
bao write -f transit/keys/connector-at type=ecdsa-p256 exportable=false allow_plaintext_backup=false >/dev/null
if [ "$(bao read -field=latest_version transit/keys/connector-at)" = 1 ]; then pass "the transit key connector-at exists at version 1"; else fail "the transit key was not created"; fi

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
  echo "  \"token_store_image\": \"$reg/token-store@$store_digest\","
  echo "  \"connector_image\": \"$reg/connector@$connector_digest\""
  echo "}"
} > "$out/environment.json"

step "The schema, by the token-store chart"
helm install token-store deployment/helm/token-store -n "$ns" --set "image.repository=$reg/token-store" --set "image.digest=$store_digest" \
  --set database.existingSecret=token-store-database --set openbao.address=http://openbao:8200 --set schema.dropOnUninstall=true \
  --wait --wait-for-jobs --timeout 3m >/dev/null
version=$(psql "SELECT coalesce(max(version), 0) FROM schema_migrations")
if [ "$version" -ge 4 ]; then pass "the token-store chart applied the schema to version $version"; else fail "schema at version $version, the connector needs 4"; fi

step "The connector: installed and ready"
helm install connector deployment/helm/connector -n "$ns" --set "image.repository=$reg/connector" --set "image.digest=$connector_digest" \
  --set zone=b --set database.existingSecret=token-store-database --set openbao.address=http://openbao:8200 \
  --set openbao.existingTokenSecret=connector-openbao --set secrets.existingSecret=connector-secrets \
  --set "issuer=$issuer" --set signing.key=connector-at --set signing.version=1 \
  --set 'registrar.scopes={connector:client_registration,resource.read}' --set "registrar.audiences={$resource}" \
  --wait --timeout 3m >/dev/null
start_proxy
rid="verify-ready-$(hex 4)"
code=$(probe 9090 /readyz "$out/readyz.json" -D "$out/readyz-headers.txt" -H "x-request-id: $rid")
if [ "$code" = 200 ] && [ "$(word "$out/readyz.json" postgres)" = ok ] && [ "$(word "$out/readyz.json" openbao)" = ok ] &&
   [ "$(word "$out/readyz.json" signing_key)" = ok ] && [ "$(word "$out/readyz.json" registrar)" = ok ]; then
  pass "/readyz answers 200 with postgres, openbao, signing_key and registrar ok"
else
  fail "/readyz: $code $(cat "$out/readyz.json" 2>/dev/null)"
fi
if grep -qi "^x-request-id: $rid" "$out/readyz-headers.txt"; then pass "the response echoes the caller's x-request-id"; else fail "x-request-id not echoed"; fi
code=$(probe 9090 /healthz "$out/healthz.txt")
if [ "$code" = 200 ]; then pass "/healthz answers 200"; else fail "/healthz answered $code"; fi
code=$(probe 8080 /.well-known/jwks.json "$out/jwks.json")
if [ "$code" = 200 ] && grep -q '"alg":"ES256"' "$out/jwks.json"; then pass "the API port publishes the ES256 signing key"; else fail "jwks: $code"; fi

step "A participant registers through the registrar, with connector register from the connector image"
ok_rid="verify-ok-$(hex 4)"
refused_rid="verify-refused-$(hex 4)"
kubectl -n "$ns" create configmap register-refused --from-literal=metadata.json="{\"client_name\":\"verify-refused\",\"grant_types\":[\"client_credentials\"],\"token_endpoint_auth_method\":\"client_secret_basic\",\"scope\":\"resource.read\",\"dpop_bound_access_tokens\":false,\"audience\":[\"$resource\"]}" >/dev/null
register_pod() { # register_pod NAME REQUEST_ID ARGS...
  local name=$1 req=$2
  shift 2
  local args=""
  for a in "$@"; do args="$args, \"$a\""; done
  kubectl -n "$ns" apply -f - <<EOF >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: $name
spec:
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    fsGroup: 65532
    seccompProfile: {type: RuntimeDefault}
  initContainers:
    - name: register
      image: "$reg/connector@$connector_digest"
      args: ["register", "--connector", "http://ztd-connector.$ns.svc:8080", "--registrar-id", "ztd-registrar",
             "--registrar-secret-file", "/var/run/secrets/connector/registrar-secret", "--out", "/out/credentials.json",
             "--request-id", "$req"$args]
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
      volumeMounts:
        - {name: secrets, mountPath: /var/run/secrets/connector, readOnly: true}
        - {name: out, mountPath: /out}
        - {name: metadata, mountPath: /etc/reg, readOnly: true}
  containers:
    - name: holder
      image: "$TEST_BASE_IMAGE"
      command: [sleep, "600"]
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
      volumeMounts:
        - {name: out, mountPath: /out, readOnly: true}
  volumes:
    - name: secrets
      secret: {secretName: connector-secrets, defaultMode: 0400, items: [{key: registrar-secret, path: registrar-secret}]}
    - name: out
      emptyDir: {}
    - name: metadata
      configMap: {name: register-refused}
EOF
}
register_pod register-ok "$ok_rid" --client-name verify-participant --scope resource.read --audience "$resource"
if kubectl -n "$ns" wait --for=condition=Ready pod/register-ok --timeout=120s >/dev/null 2>&1; then
  pass "the registration pod registered and holds the credentials file"
else
  fail "the registration pod did not come up: $(kubectl -n "$ns" logs register-ok -c register 2>&1 | tail -3)"
fi
kubectl -n "$ns" logs register-ok -c register > "$out/register-ok.txt" 2>&1 || true
credentials=$(kubectl -n "$ns" exec register-ok -c holder -- cat /out/credentials.json 2>/dev/null || true)
client_id=$(printf '%s' "$credentials" | jq -r '.client_id // empty' 2>/dev/null || true)
client_secret=$(printf '%s' "$credentials" | jq -r '.client_secret // empty' 2>/dev/null || true)
if [ "$(printf '%s' "$credentials" | jq -c 'keys' 2>/dev/null)" = '["client_id","client_secret"]' ] && [ ${#client_id} = 64 ] && [ ${#client_secret} = 32 ]; then
  pass "the credentials file holds exactly client_id (64) and client_secret (32)"
else
  fail "credentials file: $(printf '%s' "$credentials" | jq -c 'keys' 2>/dev/null) id ${#client_id} secret ${#client_secret}"
fi
echo "client_id: $client_id" >> "$out/register-ok.txt"
if [ -n "$client_id" ] && grep -q "^registered client_id=$client_id " "$out/register-ok.txt" && ! leaks "$out/register-ok.txt" "$client_secret"; then
  pass "register printed the client id and never the secret"
else
  fail "register's output: $(grep -v "registered client_id" "$out/register-ok.txt" | head -2)"
fi

step "A registration the policy refuses"
register_pod register-refused "$refused_rid" --metadata-file /etc/reg/metadata.json
for _ in $(seq 1 60); do
  exit_code=$(kubectl -n "$ns" get pod register-refused -o jsonpath='{.status.initContainerStatuses[0].state.terminated.exitCode}' 2>/dev/null || true)
  if [ -n "$exit_code" ]; then break; fi
  sleep 2
done
kubectl -n "$ns" logs register-refused -c register > "$out/register-refused.txt" 2>&1 || true
if [ "${exit_code:-}" = 1 ] && grep -q "registration refused: registration_rejected (400): dpop_bound_access_tokens must be true" "$out/register-refused.txt"; then
  pass "the refused registration exited 1 with the specific error"
else
  fail "refused registration: exit ${exit_code:-none}: $(tail -2 "$out/register-refused.txt")"
fi

step "The audit trail and the security-state events"
psql "SELECT kind || ' | ' || coalesce(client_id, '-') || ' | ' || coalesce(reason_code, '-') || ' | ' || coalesce(correlation_id, '-') || ' | ' || detail::text FROM audit_event WHERE kind LIKE 'registration.%' ORDER BY event_id" > "$out/audit-events.txt"
rows=$(wc -l < "$out/audit-events.txt" | tr -d ' ')
if [ "$rows" = 2 ]; then pass "two registration decisions in the audit trail"; else fail "$rows registration rows: $(cat "$out/audit-events.txt")"; fi
if grep -q "^registration.accepted | $client_id | - | $ok_rid | .*\"registrar\": \"ztd-registrar\"" "$out/audit-events.txt"; then
  pass "the accepted row names the client, the registrar and the request"
else
  fail "accepted row: $(head -1 "$out/audit-events.txt")"
fi
if grep -q "^registration.refused | ztd-registrar | TOK-REGISTRATION-REJECTED | $refused_rid | .*\"rule\": \"dcr.dpop_bound\"" "$out/audit-events.txt"; then
  pass "the refused row names the registrar, the reason code and the rule"
else
  fail "refused row: $(tail -1 "$out/audit-events.txt")"
fi
if [ "$(psql "SELECT count(*) FROM oauth2_client")" = 2 ]; then pass "the refusal left no client: registrar and one registered"; else fail "$(psql "SELECT count(*) FROM oauth2_client") clients"; fi
if ! leaks "$out/audit-events.txt" "$client_secret" "$registrar_secret"; then pass "no secret in the audit trail"; else fail "a secret reached the audit trail"; fi

pod=$(connector_pod)
kubectl -n "$ns" logs "$pod" > "$out/connector-logs.txt"
if jq -e . "$out/connector-logs.txt" >/dev/null 2>&1; then
  pass "every record the connector wrote is JSON"
  jq -c 'select(.kind == "token_event")' "$out/connector-logs.txt" > "$out/if01-events.jsonl"
  events=$(wc -l < "$out/if01-events.jsonl" | tr -d ' ')
  first=$(sed -n '1p' "$out/if01-events.jsonl"); second=$(sed -n '2p' "$out/if01-events.jsonl")
  if [ "$events" = 2 ] &&
     [ "$(printf '%s' "$first" | jq -r '[.source, .seq, .payload.state, .correlation_id] | join(" ")')" = "connector-b 0 registered $ok_rid" ] &&
     [ "$(printf '%s' "$second" | jq -r '[.source, .seq, .payload.state, .payload.reason_code, .payload.rule_id, .correlation_id] | join(" ")')" = "connector-b 1 refused TOK-REGISTRATION-REJECTED dcr.dpop_bound $refused_rid" ] &&
     [ "$(printf '%s' "$first" | jq -r .run_id)" = "$(printf '%s' "$second" | jq -r .run_id)" ]; then
    pass "two security-state events: registered then refused, in sequence, with the requests' correlation ids"
  else
    fail "events: $(cat "$out/if01-events.jsonl")"
  fi
  uncorrelated=$(jq -c 'select(.msg == "request" and ((.correlation_id // "") == ""))' "$out/connector-logs.txt" | wc -l | tr -d ' ')
  if [ "$uncorrelated" = 0 ]; then pass "every request record carries a correlation_id"; else fail "$uncorrelated request records lack a correlation_id"; fi
else
  fail "a record the connector wrote is not JSON"
fi
# A credential header's value is a scheme and a token: "DPoP x.y", "Bearer x.y". The records never
# name a header, so "Authorization" itself must not appear either.
if ! leaks "$out/connector-logs.txt" "$client_secret" "$registrar_secret" "$bao_root" "$db_password" "postgres://" "Authorization" &&
   ! grep -qE '(DPoP|Bearer) [A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+' "$out/connector-logs.txt"; then
  pass "no secret, token, proof or credential header in the records"
else
  fail "a secret or a header reached the records"
fi

step "Identity and no restart"
sa=$(kubectl -n "$ns" get pod "$pod" -o jsonpath='{.spec.serviceAccountName}')
label=$(kubectl -n "$ns" get pod "$pod" -o jsonpath='{.metadata.labels.spiffe\.io/spire-managed-identity}')
restarts=$(kubectl -n "$ns" get pod "$pod" -o jsonpath='{.status.containerStatuses[0].restartCount}')
printf 'serviceAccountName: %s\nspiffe.io/spire-managed-identity: %s\nrestartCount: %s\n' "$sa" "$label" "$restarts" > "$out/identity.txt"
if [ "$sa" = ztd-connector ] && [ "$label" = true ]; then pass "the pod runs as ServiceAccount ztd-connector with the identity label"; else fail "identity: serviceAccountName=$sa label=$label"; fi
if [ "$restarts" = 0 ]; then pass "the container never restarted"; else fail "the container restarted $restarts times"; fi

step "Drain on scale to zero, then uninstall"
kubectl -n "$ns" logs -f "$pod" > "$out/drain.txt" 2>/dev/null &
logs_pid=$!
kubectl -n "$ns" scale deploy/ztd-connector --replicas=0 >/dev/null
kubectl -n "$ns" wait --for=delete "pod/$pod" --timeout=90s >/dev/null 2>&1 || true
wait "$logs_pid" 2>/dev/null || true
if grep -q '"msg":"draining"' "$out/drain.txt" && grep -q '"msg":"connector stopped"' "$out/drain.txt"; then pass "the connector drained and stopped on its own"; else fail "no drain records: $(tail -2 "$out/drain.txt")"; fi
helm uninstall connector -n "$ns" --wait --timeout 3m >/dev/null
helm uninstall token-store -n "$ns" --wait --timeout 3m >/dev/null
if [ "$(tables)" = 0 ]; then pass "the uninstalls left an empty schema"; else fail "$(tables) tables left"; fi

step "Verdict"
if [ "$failures" = 0 ]; then verdict=PASS; else verdict=FAIL; fi
{
  echo "Connector chart and registration path on kind"
  echo
  cat "$out/lifecycle.txt"
  echo
  echo "verdict: $verdict"
} > "$out/verdict.txt"
echo "verdict: $verdict ($failures failed)"
[ "$failures" = 0 ]
