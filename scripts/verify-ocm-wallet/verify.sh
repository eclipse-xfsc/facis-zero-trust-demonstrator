#!/usr/bin/env bash
# The OCM W-Stack wallet lane on a throwaway kind cluster laid out like a zone: Cilium as the CNI, the
# ztd umbrella with its default deny, its API lane and its OpenBao, whose bootstrap issues one service
# token per wallet; then ocm-backbone and two ocm-wallet releases, one per tenant, on one backbone.
# Seven case groups, each with its negative half where there is one; a FAIL fails the script:
#
#   1 tokens       the bootstrap issued a token per wallet into its own Secret and revoked the root
#                  token; a wallet's token signs with its own key, renews itself through its CronJob,
#                  and is refused (403) the KV store, the shared engine, the other wallet's key, key
#                  export, the identity key's configuration and rotation, and child tokens
#   2 backbone     Cassandra answers CQL with the ocm keyspace, NATS answers; the claim is bound
#   3 identity     each wallet's did:web document resolves over TLS by its host name, its id is the
#                  DID, it lists exactly its own key, and that key's RFC 7638 thumbprint equals the
#                  one computed from the transit public key with openssl; the JWKS answers; the edge
#                  serves nothing else; a management-plane pod resolves the other wallet's DID
#                  in-cluster and the two keys differ; a data-plane pod is refused by the stores; an
#                  upgrade leaves the document byte-identical
#   4 credential   a credential stored through the wallet's storage subject is in Cassandra
#   5 restarts     every wallet pod and the Cassandra pod restarted: same document, credential still
#                  stored; OpenBao restarted: the document carries no key while the store is sealed,
#                  and is identical again once scripts/secrets/unseal.sh has run
#   6 reinstall    helm uninstall of the wallets and the backbone keeps the Cassandra claim; a
#                  reinstall from the same values finds the credential and serves the same document
#   7 gates        the repository's chart gate passes both charts; the mesh variant renders
#
# Records go to --out (default .dev/ocm-wallet-evidence, git-ignored): the documents, the JWKS, the
# in-cluster resolution, the credential ids before the restarts, the test CA certificate, the case
# lines (cases.md), environment.json and verdict.txt, written by the exit trap whatever happens.
#
#   scripts/verify-ocm-wallet/verify.sh [--out DIR]
#   BIN=<dir with kind and kubectl>   default .tools/bin (scripts/tools/install.sh kind kubectl)
#   KEEP=1                            leave the cluster behind for inspection
#
# Needs docker, helm, kind, kubectl, curl, openssl 3, python3, jq, sha256sum; pulls the pinned images, Cilium's
# chart and the kind node image. Credentials (OpenBao tokens) reach the CLI on standard input only.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env
export PATH="${BIN:-$root/.tools/bin}:$PATH"
out=.dev/ocm-wallet-evidence
while [ $# -gt 0 ]; do
  case "$1" in
    --out) [ $# -ge 2 ] || { echo "usage: $0 [--out DIR]" >&2; exit 2; }; out=$2; shift 2 ;;
    *) echo "usage: $0 [--out DIR]" >&2; exit 2 ;;
  esac
done
for tool in docker helm kind kubectl curl openssl python3 jq sha256sum; do
  command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 2; }
done
case "$(openssl version 2>/dev/null)" in OpenSSL\ [3-9]*) ;; *) echo "needs OpenSSL 3 or newer (x509 -copy_extensions): $(openssl version)" >&2; exit 2 ;; esac
mkdir -p "$out"; out="$(cd "$out" && pwd)"
: > "$out/cases.md"

umbrella=deployment/helm/ztd
backbone_chart=deployment/helm/ocm-backbone
wallet_chart=deployment/helm/ocm-wallet
cluster=ztd-ocm-wallet
mgmt=ztd-mgmt
CILIUM_VERSION=${CILIUM_VERSION:-1.20.2}
work="$(mktemp -d)"
export KUBECONFIG="$work/kubeconfig"
failed=0; passed=0
pf_pid=""

say()  { printf '%s\n' "$*" | tee -a "$out/cases.md"; }
pass() { say "PASS  $*"; passed=$((passed + 1)); }
fail() { say "FAIL  $*"; failed=1; }
note() { say "      $*"; }
step() { say "== $*"; }
k() { kubectl "$@"; }

finish() {
  rc=$?
  stop_forwards
  if [ "$rc" != 0 ] && [ "$failed" = 0 ]; then say "FAIL  the proof stopped early (exit $rc) during: $(grep '^== ' "$out/cases.md" | tail -1 | sed 's/^== //')"; failed=1; fi
  { echo "ocm-wallet proof: $([ "$failed" = 0 ] && echo PASS || echo FAIL) ($passed case(s) passed) at $(date -u +%FT%TZ)"; grep -E '^(PASS|FAIL) ' "$out/cases.md"; } > "$out/verdict.txt"
  if [ -n "${KEEP:-}" ]; then echo "kept: cluster $cluster, KUBECONFIG=$KUBECONFIG"; else kind delete cluster --name "$cluster" >/dev/null 2>&1 || true; rm -rf "$work"; fi
  exit "$rc"
}
trap finish EXIT

image_repo() { printf '%s' "${1%%@*}" | sed 's/:[^:/]*$//'; }   # repo without tag
image_digest() { printf '%s' "${1##*@}"; }

# bao TOKEN ARGS...: the OpenBao CLI inside its pod, the token on the first line of stdin, never on a
# command line (copied from scripts/verify-token-store). Prints the CLI's output; the exit code is
# the CLI's.
bao() {
  token=$1; shift
  { printf '%s\n' "$token"; } | k -n "$mgmt" exec -i ztd-openbao-0 -- \
    sh -c 'IFS= read -r BAO_TOKEN; export BAO_TOKEN BAO_ADDR=http://127.0.0.1:8200; exec bao "$@"' sh "$@"
}
token_of() { k -n "$mgmt" get secret "ztd-openbao-$1" -o jsonpath='{.data.openbao-token}' | base64 -d; }
# jkt_jwk FILE: the RFC 7638 thumbprint of the EC JWK in FILE (object with crv, kty, x, y).
jkt_jwk() {
  python3 -I - "$1" <<'PY'
import json, sys, hashlib, base64
jwk = json.load(open(sys.argv[1]))
canon = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True).encode()
print(base64.urlsafe_b64encode(hashlib.sha256(canon).digest()).rstrip(b"=").decode())
PY
}
# jkt_pem FILE: the same thumbprint from a P-256 public key in PEM, through openssl alone.
jkt_pem() {
  hex=$(openssl pkey -pubin -in "$1" -text -noout | awk '/pub:/{f=1;next} /ASN1 OID|NIST CURVE/{f=0} f' | tr -d ' :\n')
  python3 -I - "$hex" <<'PY'
import sys, hashlib, base64, json
raw = bytes.fromhex(sys.argv[1])
assert raw[0] == 4 and len(raw) == 65, "not an uncompressed P-256 point"
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
canon = json.dumps({"crv": "P-256", "kty": "EC", "x": b64(raw[1:33]), "y": b64(raw[33:65])}, separators=(",", ":"), sort_keys=True).encode()
print(b64(hashlib.sha256(canon).digest()))
PY
}
# fetch TENANT PATH OUT: the document from the host through a port-forward to the edge Service,
# over TLS with the test CA and the tenant's host name. Prints the HTTP code.
fetch() {
  local host port
  host=$(tenant_host "$1"); port=$(tenant_port "$1")
  local code
  code=$(curl -sS --max-time 15 --cacert "$work/ca.crt" --resolve "$host:$port:127.0.0.1" -o "$3" -w '%{http_code}' "https://$host:$port$2" 2>/dev/null) || true
  printf '%s' "${code:-000}"
}
tenant_host() { case "$1" in a) echo wallet-a.ztd.test ;; b) echo wallet-b.ztd.test ;; esac; }
tenant_port() { case "$1" in a) echo 18443 ;; b) echo 18444 ;; esac; }
stop_forwards() { for p in $pf_pid; do kill "$p" 2>/dev/null || true; done; for p in $pf_pid; do wait "$p" 2>/dev/null || true; done; pf_pid=""; }
forward() { # the port-forwards to both edges, restarted after a restart of the pods; a FAIL when they never answer
  stop_forwards
  k -n "$mgmt" port-forward svc/ocm-wallet-a-edge 18443:443 >/dev/null 2>&1 & pf_pid=$!
  k -n "$mgmt" port-forward svc/ocm-wallet-b-edge 18444:443 >/dev/null 2>&1 & pf_pid="$pf_pid $!"
  # Ready when both edges answer through the forwards (any HTTP code; 000 is no connection).
  for _ in $(seq 1 60); do
    a=$(fetch a /healthz "$work/null"); b=$(fetch b /healthz "$work/null")
    [ "$a" != 000 ] && [ "$b" != 000 ] && return 0
    sleep 1
  done
  fail "port-forwards to the edges not answering after 60 s (a=$a b=$b); the document checks that follow cannot run"
  return 1
}
# credential_ids: tenant, account and the ids (the keys of the credentials map), never the stored
# values. Prints "cqlsh-failed" when the node does not answer, so a tool failure is never read as an
# absent row.
credential_ids() {
  k -n "$mgmt" exec ocm-cassandra-0 -- cqlsh 127.0.0.1 9042 -e "SELECT JSON tenant, account, credentials FROM ocm.credentials;" 2>/dev/null \
    | python3 -I -c '
import sys, json
for l in sys.stdin:
    l = l.strip()
    if l.startswith("{"):
        d = json.loads(l); print(d.get("tenant"), d.get("account"), *sorted((d.get("credentials") or {}).keys()))' 2>/dev/null || echo cqlsh-failed
}
# credential_present ID -> 0 present, 1 absent, 2 cqlsh did not answer
credential_present() { out_=$(credential_ids); case "$out_" in *cqlsh-failed*) return 2 ;; esac; printf '%s\n' "$out_" | grep -q "$1"; }

say "# OCM wallet lane: $(date -u +%FT%TZ)"

# ---------------------------------------------------------------- cluster
step "Cluster: kind with Cilium (cni.exclusive=false)"
kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
kind create cluster --name "$cluster" --image "$KIND_NODE_IMAGE" --config - >/dev/null <<KIND   # no --wait: without a CNI no node is Ready until Cilium is in
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
nodes:
  - role: control-plane
KIND
helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1 || true
helm repo update cilium >/dev/null
# One node, so one operator replica: the default two never schedule on one node and --wait would
# never return.
helm upgrade --install cilium cilium/cilium --version "$CILIUM_VERSION" -n kube-system \
  --set cni.exclusive=false --set ipam.mode=kubernetes --set image.pullPolicy=IfNotPresent --set operator.replicas=1 \
  --wait --timeout 10m >/dev/null
k -n kube-system rollout status ds/cilium --timeout=5m >/dev/null
k wait --for=condition=Ready nodes --all --timeout=5m >/dev/null
server=$(k version -o json | jq -r .serverVersion.gitVersion)
note "cluster $cluster: Kubernetes $server, Cilium $CILIUM_VERSION"

# ---------------------------------------------------------------- 1 umbrella and tokens
step "1 umbrella with OpenBao: one service token per wallet"
sed -n 's/^ *repository: *"\{0,1\}\(https:[^"]*\)"\{0,1\}$/\1/p' "$umbrella/Chart.yaml" | sort -u | while read -r url; do
  helm repo add "dep-$(printf '%s' "$url" | sha256sum | cut -c1-8)" "$url" >/dev/null 2>&1 || true
done
helm dependency build "$umbrella" >/dev/null
scripts/secrets/kind-api-lane.sh > "$work/api-lane.yaml"
cat > "$work/tokens.yaml" <<YAML
openbaoBootstrap:
  serviceTokens:
    - { name: ocm-wallet-a, transitMount: ocm/zone-a }
    - { name: ocm-wallet-b, transitMount: ocm/zone-b }
YAML
if helm upgrade --install ztd "$umbrella" -n ztd-system --create-namespace -f "$umbrella/ci/values.yaml" -f "$work/api-lane.yaml" -f "$work/tokens.yaml" \
     --wait --wait-for-jobs --timeout 10m >"$work/umbrella.log" 2>&1; then
  pass "1a the umbrella installed with OpenBao bootstrapped and verified"
else
  fail "1a umbrella install failed:"; tail -8 "$work/umbrella.log" | sed 's/^/      /'
  k -n "$mgmt" logs -l app.kubernetes.io/name=ztd-openbao-bootstrap --tail=20 2>/dev/null | sed 's/^/      /'
fi
secrets=$(k -n "$mgmt" get secret ztd-openbao-ocm-wallet-a ztd-openbao-ocm-wallet-b -o name 2>/dev/null | wc -l | tr -d ' ' || true)
root_present=$(k -n "$mgmt" get secret ztd-openbao-bootstrap -o jsonpath='{.data.root-token}' 2>/dev/null || true)
if [ "$secrets" = 2 ] && [ -z "$root_present" ]; then
  pass "1b both service-token Secrets exist and the bootstrap Secret holds no root token"
else
  fail "1b service-token Secrets: $secrets of 2; root token in the bootstrap Secret: $([ -n "$root_present" ] && echo present || echo absent)"
fi
tok_a=$(token_of ocm-wallet-a || true)

install_backbone() {
  helm upgrade --install ocm-backbone "$backbone_chart" -n "$mgmt" \
    --set images.cassandra.repository="$(image_repo "$OCM_CASSANDRA_IMAGE")" --set images.cassandra.digest="$(image_digest "$OCM_CASSANDRA_IMAGE")" \
    --set images.nats.repository="$(image_repo "$OCM_NATS_IMAGE")" --set images.nats.digest="$(image_digest "$OCM_NATS_IMAGE")" \
    --set cassandra.storage.className=standard --wait --wait-for-jobs --timeout 10m
}

# ---------------------------------------------------------------- 2 backbone
step "2 backbone: Cassandra and NATS"
if install_backbone >"$work/backbone.log" 2>&1; then
  pass "2a ocm-backbone installed: Cassandra and NATS ready, keyspace Job done"
else
  fail "2a ocm-backbone install failed:"; tail -8 "$work/backbone.log" | sed 's/^/      /'; k -n "$mgmt" get pods | sed 's/^/      /'
fi
ks=$(k -n "$mgmt" exec ocm-cassandra-0 -- cqlsh 127.0.0.1 9042 -e "DESCRIBE KEYSPACES" 2>/dev/null | tr -s ' \n' ' ' || true)
case " $ks " in *" ocm "*) pass "2b Cassandra answers CQL and holds the ocm keyspace" ;; *) fail "2b keyspaces: '$ks'" ;; esac
pvc=$(k -n "$mgmt" get pvc data-ocm-cassandra-0 -o jsonpath='{.status.phase}' 2>/dev/null || true)
pv_before=$(k -n "$mgmt" get pvc data-ocm-cassandra-0 -o jsonpath='{.spec.volumeName}' 2>/dev/null || true)
[ "$pvc" = Bound ] && pass "2c the Cassandra claim data-ocm-cassandra-0 is Bound to $pv_before" || fail "2c claim phase: '$pvc'"

# ---------------------------------------------------------------- TLS, DNS
step "Test CA, certificates and in-cluster names for the two hosts (test infrastructure, not chart)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=ztd-ocm-wallet test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -keyout "$work/ca.key" -out "$work/ca.crt" >/dev/null 2>&1
for t in a b; do
  host=$(tenant_host $t)
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$host" -addext "subjectAltName=DNS:$host" -keyout "$work/$t.key" -out "$work/$t.csr" >/dev/null 2>&1
  openssl x509 -req -in "$work/$t.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" -CAcreateserial -days 2 -copy_extensions copy -out "$work/$t.crt" >/dev/null 2>&1
  k -n "$mgmt" create secret tls "ocm-wallet-$t-tls" --cert="$work/$t.crt" --key="$work/$t.key" >/dev/null
done
k -n "$mgmt" create configmap ocm-test-ca --from-file=ca.crt="$work/ca.crt" >/dev/null
cp "$work/ca.crt" "$out/test-ca.crt"
# CoreDNS: the two host names resolve to the edges inside the cluster, as public DNS would outside.
k -n kube-system get configmap coredns -o json | python3 -I -c '
import json, sys
cm = json.load(sys.stdin)
c = cm["data"]["Corefile"]
rules = "".join("    rewrite name exact %s ocm-wallet-%s-edge.ztd-mgmt.svc.cluster.local\n" % (h, t) for t, h in (("a", "wallet-a.ztd.test"), ("b", "wallet-b.ztd.test")))
cm["data"]["Corefile"] = c.replace(".:53 {\n", ".:53 {\n" + rules, 1)
json.dump(cm, sys.stdout)' | k apply -f - >/dev/null
k -n kube-system rollout restart deployment/coredns >/dev/null; k -n kube-system rollout status deployment/coredns --timeout=2m >/dev/null
note "certificates for wallet-a.ztd.test and wallet-b.ztd.test from a test CA; CoreDNS rewrites both names to the edges"

# ---------------------------------------------------------------- 3 wallets and identity
step "3 wallets: two tenants on one backbone"
wallet_values=(
  --set images.signer.repository="$(image_repo "$OCM_SIGNER_IMAGE")" --set images.signer.digest="$(image_digest "$OCM_SIGNER_IMAGE")"
  --set images.vaultPlugin.repository="$(image_repo "$OCM_VAULT_PLUGIN_IMAGE")" --set images.vaultPlugin.digest="$(image_digest "$OCM_VAULT_PLUGIN_IMAGE")"
  --set images.storage.repository="$(image_repo "$OCM_STORAGE_IMAGE")" --set images.storage.digest="$(image_digest "$OCM_STORAGE_IMAGE")"
  --set images.retrieval.repository="$(image_repo "$OCM_RETRIEVAL_IMAGE")" --set images.retrieval.digest="$(image_digest "$OCM_RETRIEVAL_IMAGE")"
  --set images.edge.repository="$(image_repo "$OCM_EDGE_IMAGE")" --set images.edge.digest="$(image_digest "$OCM_EDGE_IMAGE")"
  --set images.hook.repository="$(image_repo "$OCM_HOOK_IMAGE")" --set images.hook.digest="$(image_digest "$OCM_HOOK_IMAGE")"
  --set retrieval.trustedCAConfigMap=ocm-test-ca --set networkPolicy.cilium=true
  --set 'networkPolicy.issuerEgress.peers[0].podSelector.matchLabels.app\.kubernetes\.io/component=edge'
)
install_wallet() { # a|b
  helm upgrade --install "ocm-wallet-$1" "$wallet_chart" -n "$mgmt" "${wallet_values[@]}" \
    --set tenant.id="zone-$1" --set tenant.host="$(tenant_host "$1")" \
    --set openbao.existingSecret="ztd-openbao-ocm-wallet-$1" --set edge.tls.existingSecret="ocm-wallet-$1-tls" \
    --wait --wait-for-jobs --timeout 8m
}
for t in a b; do
  if install_wallet $t >"$work/wallet-$t.log" 2>&1; then
    keylog=$(k -n "$mgmt" logs "job/ocm-wallet-$t-key" 2>/dev/null | tail -1 || true)
    pass "3a ocm-wallet-$t installed and ready; $keylog"
  else
    fail "3a ocm-wallet-$t install failed:"; tail -8 "$work/wallet-$t.log" | sed 's/^/      /'
    k -n "$mgmt" get pods -l "app.kubernetes.io/instance=ocm-wallet-$t" | sed 's/^/      /'
    for p in $(k -n "$mgmt" get pods -l "app.kubernetes.io/instance=ocm-wallet-$t" -o name); do k -n "$mgmt" logs "$p" --all-containers --tail=15 2>/dev/null | sed "s|^|      $p: |"; done
  fi
done
forward || true
for t in a b; do
  host=$(tenant_host $t); did="did:web:$host"
  code=$(fetch $t /.well-known/did.json "$out/did-$t.json")
  if [ "$code" = 200 ] && [ "$(jq -r .id "$out/did-$t.json" 2>/dev/null)" = "$did" ]; then
    pass "3b wallet $t: https://$host/.well-known/did.json answers 200 over TLS with id $did"
  else
    fail "3b wallet $t: did.json HTTP $code, id '$(jq -r .id "$out/did-$t.json" 2>/dev/null)' (want $did)"; head -c 400 "$out/did-$t.json" | sed 's/^/      /'; echo
  fi
  n=$(jq '.verificationMethod | length' "$out/did-$t.json" 2>/dev/null || echo 0)
  vm_id=$(jq -r '.verificationMethod[0].id // empty' "$out/did-$t.json" 2>/dev/null || true)
  jq '.verificationMethod[0].publicKeyJwk // empty' "$out/did-$t.json" > "$work/jwk-$t.json" 2>/dev/null || true
  pem_json=$(bao "$(token_of ocm-wallet-$t)" read -format=json "ocm/zone-$t/keys/wallet-zone-$t" 2>/dev/null || true)
  printf '%s' "$pem_json" | jq -r '.data.keys | to_entries | max_by(.key | tonumber) | .value.public_key' > "$work/pub-$t.pem" 2>/dev/null || true
  jkt_doc=$(jkt_jwk "$work/jwk-$t.json" 2>/dev/null || echo none); jkt_bao=$(jkt_pem "$work/pub-$t.pem" 2>/dev/null || echo unknown)
  if [ "$n" = 1 ] && [ "$jkt_doc" = "$jkt_bao" ] && [ "$jkt_doc" != none ]; then
    pass "3c wallet $t: the document lists exactly one key, $vm_id, whose RFC 7638 thumbprint $jkt_doc equals the transit key's (openssl)"
  else
    fail "3c wallet $t: $n verification method(s); thumbprint in the document '$jkt_doc', from transit '$jkt_bao'"
  fi
  eval "jkt_$t=\$jkt_doc"
  jw=$(fetch $t /.well-known/jwks.json "$out/jwks-$t.json")
  if [ "$jw" = 200 ] && [ "$(jq '.keys | length' "$out/jwks-$t.json" 2>/dev/null)" = 1 ]; then
    pass "3d wallet $t: jwks.json answers 200 with 1 key"
  else
    fail "3d wallet $t: jwks.json HTTP $jw ($(jq '.keys | length' "$out/jwks-$t.json" 2>/dev/null) keys)"
  fi
  other=$(fetch $t /v1/sign "$work/null"); [ "$other" = 404 ] && pass "3e wallet $t: the edge answers 404 for anything but the two documents (/v1/sign)" || fail "3e wallet $t: /v1/sign through the edge: HTTP $other"
done
# shellcheck disable=SC2154
if [ -n "${jkt_a:-}" ] && [ "$jkt_a" != "${jkt_b:-}" ]; then pass "3f the two wallets' keys differ ($jkt_a / $jkt_b)"; else fail "3f thumbprints: '$jkt_a' / '${jkt_b:-}'"; fi
# In-cluster: a pod in the management plane resolves wallet b's DID by name, with the test CA.
k -n "$mgmt" run did-resolver --image="$OCM_HOOK_IMAGE" --image-pull-policy=IfNotPresent --restart=Never \
  --labels="app.kubernetes.io/part-of=ocm" --overrides='{"spec":{"automountServiceAccountToken":false,"volumes":[{"name":"ca","configMap":{"name":"ocm-test-ca"}}],"containers":[{"name":"did-resolver","image":"'"$OCM_HOOK_IMAGE"'","command":["sh","-c","curl -sS --max-time 20 --cacert /ca/ca.crt https://wallet-b.ztd.test/.well-known/did.json"],"volumeMounts":[{"name":"ca","mountPath":"/ca"}]}]}}' >/dev/null
k -n "$mgmt" wait --for=jsonpath='{.status.phase}'=Succeeded pod/did-resolver --timeout=90s >/dev/null 2>&1 || true
k -n "$mgmt" logs did-resolver > "$out/did-b-resolved-in-cluster.json" 2>/dev/null || true
k -n "$mgmt" delete pod did-resolver --now >/dev/null 2>&1 || true
if [ "$(jq -r .id "$out/did-b-resolved-in-cluster.json" 2>/dev/null)" = "did:web:wallet-b.ztd.test" ]; then
  pass "3g a management-plane pod resolves did:web:wallet-b.ztd.test by name over TLS"
else
  fail "3g in-cluster resolution of wallet b: $(head -c 200 "$out/did-b-resolved-in-cluster.json")"
fi
# A data-plane pod is refused by the stores and the signer (the umbrella's default deny; the
# intra-plane lane admits management-plane pods only).
k -n ztd-data run lane-probe --image="$OCM_HOOK_IMAGE" --image-pull-policy=IfNotPresent --restart=Never --overrides='{"spec":{"automountServiceAccountToken":false}}' \
  --command -- sh -c 'for t in ocm-cassandra.ztd-mgmt.svc:9042 ocm-nats.ztd-mgmt.svc:4222 ocm-wallet-a-signer.ztd-mgmt.svc:50051 ocm-wallet-a-storage.ztd-mgmt.svc:8080; do if curl -sS --max-time 4 -o /dev/null "telnet://$t" 2>/dev/null; then echo "open $t"; else echo "refused $t"; fi; done' >/dev/null 2>&1 || true
k -n ztd-data wait --for=jsonpath='{.status.phase}'=Succeeded pod/lane-probe --timeout=90s >/dev/null 2>&1 || true
probe_out=$(k -n ztd-data logs lane-probe 2>/dev/null || true); k -n ztd-data delete pod lane-probe --now >/dev/null 2>&1 || true
if [ "$(printf '%s\n' "$probe_out" | grep -c '^refused ')" = 4 ]; then
  pass "3i a data-plane pod is refused by Cassandra, NATS, the signer's engine and the storage API"
else
  fail "3i data-plane probe: $(printf '%s' "$probe_out" | tr '\n' ' ')"
fi
before=$(sha256sum "$out/did-a.json" 2>/dev/null | cut -c1-16 || true)
if install_wallet a >"$work/wallet-a-upgrade.log" 2>&1; then
  forward || true; fetch a /.well-known/did.json "$work/did-a-after.json" >/dev/null
  after=$(sha256sum "$work/did-a-after.json" | cut -c1-16)
  [ "$before" = "$after" ] && pass "3h an upgrade with the same values leaves the document byte-identical ($after)" || fail "3h document changed across an upgrade: $before -> $after"
else
  fail "3h helm upgrade of ocm-wallet-a failed"; tail -5 "$work/wallet-a-upgrade.log" | sed 's/^/      /'
fi
# Token boundaries, with wallet a's token.
sign_own=$(bao "$tok_a" write -format=json ocm/zone-a/sign/wallet-zone-a input=aGVsbG8= 2>/dev/null | jq -r .data.signature 2>/dev/null || true)
case "$sign_own" in vault:v*) pass "1c wallet a's token signs with its own key ($(printf '%s' "$sign_own" | cut -c1-12)...)" ;; *) fail "1c wallet a's token could not sign with its own key" ;; esac
# The renewal CronJob renews the token: run it once now.
if k -n "$mgmt" create job --from=cronjob/ocm-wallet-a-renew renew-now >/dev/null 2>&1 && k -n "$mgmt" wait --for=condition=Complete job/renew-now --timeout=120s >/dev/null 2>&1; then
  pass "1e the wallet's renewal CronJob renews its own token ($(k -n "$mgmt" logs job/renew-now 2>/dev/null | tail -1 || true))"
else
  fail "1e the renewal Job did not complete: $(k -n "$mgmt" logs job/renew-now 2>/dev/null | tail -2 | tr '\n' ' ' || true)"
fi
k -n "$mgmt" delete job renew-now --now >/dev/null 2>&1 || true
# refused NAME ARGS...: the call must fail with OpenBao's "permission denied" (a 403); any other
# failure is a tool failure and counts against the case.
refused_n=0; allowed=""; broken=""
refused() { name=$1; shift; if err=$(bao "$tok_a" "$@" 2>&1 >/dev/null); then allowed="$allowed $name"; return 0; fi; case "$err" in *"permission denied"*) refused_n=$((refused_n+1)) ;; *) broken="$broken $name" ;; esac; }
refused kv-fixture read secret/data/ztd-fixture/canary
refused transit/ read transit/keys/ztd-fixture
refused sign-b write ocm/zone-b/sign/wallet-zone-b input=aGVsbG8=
refused read-key-b read ocm/zone-b/keys/wallet-zone-b
refused export read ocm/zone-a/export/signing-key/wallet-zone-a
refused key-config write ocm/zone-a/keys/wallet-zone-a/config exportable=true
refused storage-export read ocm/zone-a-storage/export/encryption-key/participant-reader
refused tune-b read sys/mounts/ocm/zone-b/tune
refused child-token token create
refused rotate write -f ocm/zone-a/keys/wallet-zone-a/rotate
[ "$refused_n" = 10 ] && pass "1d wallet a's token is refused, with 403, the KV store, the shared engine, wallet b's key (sign, read) and mount config, key export in both engines, the identity key's configuration and rotation, and child tokens" || fail "1d wallet a's token: allowed:[$allowed] tool failures:[$broken] refused: $refused_n of 10"

# ---------------------------------------------------------------- 4 credential
step "4 credential stored through the storage subject"
cred_id="urn:uuid:$(python3 -I -c 'import uuid; print(uuid.uuid4())')"
payload=$(jq -c --arg id "$cred_id" '.output.credential | .id = $id' features/fixtures/xfsc/issue/allow.json)
payload_sha=$(printf '%s' "$payload" | sha256sum | cut -c1-16)
event=$(python3 -I - "$payload" "$cred_id" <<'PY'
import json, sys, base64, uuid
payload, cid = sys.argv[1], sys.argv[2]
data = {"tenant_id": "zone-a", "request_id": str(uuid.uuid4()), "group_id": "group-a", "accountId": "participant-reader",
        "type": "storage.service.credential", "payload": base64.b64encode(payload.encode()).decode(),
        "contentType": "application/json", "region": "EU", "country": "DE", "id": cid}
print(json.dumps({"specversion": "1.0", "id": str(uuid.uuid4()), "source": "urn:ztd:ocm-wallet-proof", "type": "storage.service.credential",
                  "datacontenttype": "application/json", "data": data}))
PY
)
# publish: the store event through a one-shot nats-box pod; a pod that never ran (pull, scheduling)
# is a tool failure and is retried, up to three times.
pub_log=""
for attempt in 1 2 3; do
  k -n "$mgmt" delete pod nats-pub --now >/dev/null 2>&1 || true
  k -n "$mgmt" run nats-pub --image="$NATS_BOX_IMAGE" --image-pull-policy=IfNotPresent --restart=Never --labels="app.kubernetes.io/part-of=ocm" \
    --overrides='{"spec":{"automountServiceAccountToken":false}}' --command -- nats --server nats://ocm-nats:4222 pub zone-a.storage "$event" >/dev/null 2>&1 || true
  k -n "$mgmt" wait --for=jsonpath='{.status.phase}'=Succeeded pod/nats-pub --timeout=120s >/dev/null 2>&1 || true
  pub_log=$(k -n "$mgmt" logs nats-pub 2>/dev/null | tail -1 || true)
  case "$pub_log" in *Published*) break ;; esac
  pub_log="attempt $attempt: no publish; pod: $(k -n "$mgmt" get pod nats-pub -o jsonpath='{.status.phase} {.status.containerStatuses[0].state}' 2>/dev/null || echo absent)"
  note "$pub_log"
done
k -n "$mgmt" delete pod nats-pub --now >/dev/null 2>&1 || true
stored=no
for _ in $(seq 1 20); do if credential_present "$cred_id"; then stored=yes; break; fi; sleep 3; done
if [ "$stored" = yes ]; then
  pass "4a the credential $cred_id (payload sha256 $payload_sha) published on zone-a.storage is in ocm.credentials (tenant zone-a, account participant-reader)"
else
  fail "4a credential not found in Cassandra after the publish ($pub_log)"; k -n "$mgmt" logs deploy/ocm-wallet-a-storage --tail=15 2>/dev/null | sed 's/^/      /'
fi
credential_ids > "$out/credentials-before.txt" 2>/dev/null || true

# ---------------------------------------------------------------- 5 restarts
step "5 restarts"
k -n "$mgmt" rollout restart deployment -l app.kubernetes.io/part-of=ocm >/dev/null
k -n "$mgmt" delete pod ocm-cassandra-0 --wait=true >/dev/null
for d in $(k -n "$mgmt" get deployment -l app.kubernetes.io/part-of=ocm -o name); do k -n "$mgmt" rollout status "$d" --timeout=5m >/dev/null; done
k -n "$mgmt" rollout status statefulset/ocm-cassandra --timeout=8m >/dev/null
forward || true
fetch a /.well-known/did.json "$work/did-a-restart.json" >/dev/null
[ "$(sha256sum "$work/did-a-restart.json" | cut -c1-16)" = "$before" ] && pass "5a after every wallet pod and the Cassandra pod restarted, wallet a's document is byte-identical" || fail "5a document after the restarts differs: $(sha256sum "$work/did-a-restart.json" | cut -c1-16) (was $before)"
cp_=0; credential_present "$cred_id" || cp_=$?
case "$cp_" in 0) pass "5b the credential is still in Cassandra after the restarts" ;; 2) fail "5b cqlsh did not answer after the restarts (tool failure, not an absent row)" ;; *) fail "5b the credential is gone after the restarts" ;; esac
k -n "$mgmt" delete pod ztd-openbao-0 --wait=true >/dev/null
sealed=false
for _ in $(seq 1 60); do rc=0; k -n "$mgmt" exec ztd-openbao-0 -- bao status >/dev/null 2>&1 || rc=$?; [ "$rc" = 2 ] && { sealed=true; break; }; sleep 3; done
code=$(fetch a /.well-known/did.json "$work/did-a-sealed.json"); keys_sealed=$(jq '.verificationMethod | length' "$work/did-a-sealed.json" 2>/dev/null || echo "?")
if [ "$sealed" = true ] && [ "$keys_sealed" = 0 ]; then
  pass "5c with OpenBao sealed after its restart the document carries no key (HTTP $code, 0 verification methods): nothing can be verified against it"
else
  fail "5c OpenBao sealed=$sealed; document while sealed: HTTP $code, $keys_sealed verification method(s)"
fi
scripts/secrets/unseal.sh >/dev/null
k -n "$mgmt" wait --for=condition=Ready pod/ztd-openbao-0 --timeout=120s >/dev/null
recovered=no
for _ in $(seq 1 20); do fetch a /.well-known/did.json "$work/did-a-unsealed.json" >/dev/null; [ "$(sha256sum "$work/did-a-unsealed.json" | cut -c1-16)" = "$before" ] && { recovered=yes; break; }; sleep 3; done
[ "$recovered" = yes ] && pass "5d once unsealed, the document is byte-identical again without any other step" || fail "5d document after the unseal differs: $(sha256sum "$work/did-a-unsealed.json" | cut -c1-16) (was $before)"

# ---------------------------------------------------------------- 6 reinstall
step "6 uninstall and reinstall from the same values"
stop_forwards
helm uninstall ocm-wallet-a ocm-wallet-b -n "$mgmt" --wait --timeout 3m >/dev/null
helm uninstall ocm-backbone -n "$mgmt" --wait --timeout 3m >/dev/null
k -n "$mgmt" wait --for=delete pod/ocm-cassandra-0 --timeout=3m >/dev/null 2>&1 || true
pvc=$(k -n "$mgmt" get pvc data-ocm-cassandra-0 -o jsonpath='{.status.phase}' 2>/dev/null || true)
pv_after=$(k -n "$mgmt" get pvc data-ocm-cassandra-0 -o jsonpath='{.spec.volumeName}' 2>/dev/null || true)
[ "$pvc" = Bound ] && [ -n "$pv_before" ] && [ "$pv_after" = "$pv_before" ] && pass "6a helm uninstall of the wallets and the backbone left the Cassandra claim behind, still bound to $pv_after" || fail "6a claim after uninstall: phase '$pvc', volume '$pv_after' (was '$pv_before')"
if install_backbone >"$work/backbone2.log" 2>&1 \
   && install_wallet a >"$work/wallet-a2.log" 2>&1 && install_wallet b >"$work/wallet-b2.log" 2>&1; then
  cp_=0; credential_present "$cred_id" || cp_=$?
  case "$cp_" in 0) pass "6b reinstalled from the same values: the credential is in Cassandra" ;; 2) fail "6b cqlsh did not answer after the reinstall (tool failure, not an absent row)" ;; *) fail "6b the credential is gone after the reinstall" ;; esac
  forward || true; fetch a /.well-known/did.json "$work/did-a-reinstall.json" >/dev/null
  [ "$(sha256sum "$work/did-a-reinstall.json" | cut -c1-16)" = "$before" ] && pass "6c reinstalled: wallet a serves the same document (same key in OpenBao)" || fail "6c document after the reinstall differs"
else
  fail "6b/6c reinstall failed"; tail -5 "$work/backbone2.log" "$work/wallet-a2.log" "$work/wallet-b2.log" 2>/dev/null | sed 's/^/      /'
fi

# ---------------------------------------------------------------- 7 gates
step "7 gates"
if scripts/ci/check-charts.sh "$backbone_chart" "$wallet_chart" >"$work/gate.log" 2>&1; then pass "7a the chart gate (lint, render) passes both charts"; else fail "7a the chart gate failed:"; tail -5 "$work/gate.log" | sed 's/^/      /'; fi
# The mesh and LoadBalancer paths render (no Istio on this cluster, so a render, not an install).
if helm template mesh "$wallet_chart" -f "$wallet_chart/ci/values.yaml" --set mesh.enabled=true --set edge.service.type=LoadBalancer >"$work/mesh.yaml" 2>"$work/mesh.err" && [ "$(grep -c '^kind: PeerAuthentication' "$work/mesh.yaml")" = 4 ]; then
  pass "7b the mesh variant renders four PeerAuthentications and a LoadBalancer edge"
else
  fail "7b the mesh variant does not render: $(tail -2 "$work/mesh.err" | tr '\n' ' ')"
fi

cat > "$out/environment.json" <<JSON
{
  "kubernetes": "$server",
  "kind_node_image": "$KIND_NODE_IMAGE",
  "cilium": "$CILIUM_VERSION",
  "helm": "$(helm version --short 2>/dev/null)",
  "images": {
    "signer": "$OCM_SIGNER_IMAGE", "vaultPlugin": "$OCM_VAULT_PLUGIN_IMAGE", "storage": "$OCM_STORAGE_IMAGE", "retrieval": "$OCM_RETRIEVAL_IMAGE",
    "cassandra": "$OCM_CASSANDRA_IMAGE", "nats": "$OCM_NATS_IMAGE", "edge": "$OCM_EDGE_IMAGE", "hook": "$OCM_HOOK_IMAGE", "natsBox": "$NATS_BOX_IMAGE"
  },
  "tenants": {"a": {"did": "did:web:wallet-a.ztd.test", "jkt": "${jkt_a:-}"}, "b": {"did": "did:web:wallet-b.ztd.test", "jkt": "${jkt_b:-}"}},
  "credential": {"id": "$cred_id", "payloadSha256_16": "$payload_sha"}
}
JSON
say "# result: $([ $failed = 0 ] && echo 'all cases passed' || echo 'at least one case FAILED')"
exit $failed
