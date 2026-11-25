#!/usr/bin/env bash
# The TSA policy proof on a throwaway kind cluster: the real XFSC TSA policy service (pinned digest)
# from deployment/helm/tsa-policy, and the guard chart's IF-05 evaluator deciding through it.
#
#   1. bundle v1 active: an entitled summary request is allowed (rule and revision v1), and denied by
#      rule m3-tenant-membership when it names a target tenant the bundle has no members for;
#   2. bundle v2 declared (a policy change withdrawing the summary scope): the same request is
#      denied by rule m3-scope-withdrawn under v2, with no pod restarted;
#   3. an unsigned bundle, one signed by another key, one whose policy was altered after signing and
#      a correctly signed one whose Rego reports another revision than its data are each refused,
#      and v2 stays (or, for the last, is restored as) the active bundle;
#   4. v1 declared again (rollback): allowed under v1, still no restart;
#   5. every decision the evaluator logged names its rule and bundle revision.
#
# Requests are sent to the evaluator as the guard sends them (POST /decision, the guard's identity
# in the X-Forwarded-Client-Cert header its mesh sidecar would set); no mesh, token store or
# connector is installed, so the guard's own token path is not exercised here.
#
#   BIN=<dir with a linux cosign and istio-crds/> scripts/verify-tsa-policy/verify.sh [--out DIR]
#   (scripts/tools/install.sh <dir> kind kubectl cosign istio-crds fills it)
#
# Needs docker, kind, kubectl, helm, jq and python3. KEEP=1 leaves the cluster and registry running.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env
out="$root/.dev/tsa-policy-evidence"
[ "${1:-}" = --out ] && out="$2"
mkdir -p "$out"
bin="$(cd "${BIN:-.tools/bin}" && pwd)"
export PATH="$bin:$PATH"

cluster=ztd-tsa
reg_name=kind-registry-tsa
reg="$reg_name:5000"
host_reg=127.0.0.1:5002
toolbox=golang:1.27@sha256:f24164268fc1e741bbdc0066dbadcf1c8426c5a8489f0729c02c3905a53032fd
tsa_ns=ztd-tsa
guard_ns=ztd-guard
work="$(mktemp -d)"
export KUBECONFIG="$work/kubeconfig"

cleanup() {
  if [ -n "${KEEP:-}" ]; then
    echo "kept: cluster $cluster, registry $reg_name, KUBECONFIG=$KUBECONFIG"
    return
  fi
  kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
  docker rm -f "$reg_name" >/dev/null 2>&1 || true
  docker run --rm -v "$work:/w" "$toolbox" chown -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

failures=0
pass() { echo "PASS  $*" | tee -a "$out/verdict.txt"; }
fail() { echo "FAIL  $*" | tee -a "$out/verdict.txt"; failures=$((failures + 1)); }
step() { echo; echo "== $*"; }
: > "$out/verdict.txt"

step "Cluster and registry"
kind create cluster --name "$cluster" --image "$KIND_NODE_IMAGE" --wait 180s --config - <<'EOF'
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
reg_ip=$(docker inspect -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}' "$reg_name")
case "$(docker exec "$cluster-control-plane" uname -m)" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; *) echo "unsupported node" >&2; exit 1 ;; esac

step "Images (built for the node, pushed by digest)"
digest() {
  curl -fsSI -H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json" \
    "http://$host_reg/v2/ztd/$1/manifests/proof" | tr -d '\r' | awk 'tolower($1)=="docker-content-digest:"{print $2}'
}
declare -A digests
for image in tsa-bundle tsa-git policy-evaluator guard; do
  docker build -q --platform "linux/$arch" -f "deployment/docker/$image/Dockerfile" -t "$host_reg/ztd/$image:proof" . >/dev/null
  docker push -q "$host_reg/ztd/$image:proof" >/dev/null
  digests[$image]=$(digest "$image")
done
GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -o "$work/tsa-bundle" ./cmd/tsa-bundle

step "Keys and bundles (publish script, on the kind network)"
mkdir -p "$work/v2"
cp policies/tsa/facis/guard/1.0/policy.rego "$work/v2/"
# v2 is a policy change: the summary scope is withdrawn.
jq '.config.withdrawn_scopes = ["report:summary"]' policies/tsa/facis/guard/1.0/data.json > "$work/v2/data.json"
# lying: correctly signed, its data says v4 but its Rego answers with v2 - only the check after import
# can catch it, and the last verified bundle must be restored.
mkdir -p "$work/lying"
sed 's/"bundle_revision": revision/"bundle_revision": "v2"/' policies/tsa/facis/guard/1.0/policy.rego > "$work/lying/policy.rego"
grep -q '"bundle_revision": "v2"' "$work/lying/policy.rego"
cp policies/tsa/facis/guard/1.0/data.json "$work/lying/"
# shellcheck disable=SC2016 # expanded in the toolbox
cat > "$work/publish.sh" <<'EOF'
set -euo pipefail
cd /src
export COSIGN_PASSWORD= COSIGN=/tools/cosign TSA_BUNDLE=/w/tsa-bundle COSIGN_ALLOW_HTTP_REGISTRY=true
mkdir -p /w/trusted /w/other
(cd /w/trusted && /tools/cosign generate-key-pair >/dev/null 2>&1)
(cd /w/other && /tools/cosign generate-key-pair >/dev/null 2>&1)
pub() { COSIGN_KEY=/w/$1/cosign.key bash scripts/supplychain/publish-tsa-bundle.sh "$2" "$3" "$REG/tsa-bundles" "/w/$1/cosign.pub" "${4:-}" 2>/dev/null; }
pub trusted policies/tsa/facis/guard/1.0 v1 > /w/ref-v1
OUT=/w/v2.zip pub trusted policies/tsa/facis/guard/1.0 v2 /w/v2/data.json > /w/ref-v2
pub other policies/tsa/facis/guard/1.0 v3 > /w/ref-other
mkdir -p /w/lying-src/facis/guard && cp -R /w/lying /w/lying-src/facis/guard/1.0
pub trusted /w/lying-src/facis/guard/1.0 v4 > /w/ref-lying
# Unsigned: a valid TSA bundle signed by the trusted key, pushed without the artefact signature.
/w/tsa-bundle pack -src policies/tsa/facis/guard/1.0 -revision unsigned -out /w/u
/tools/cosign sign-blob --yes --key /w/trusted/cosign.key --tlog-upload=false --new-bundle-format=false \
  --output-signature /w/u/sig.b64 /w/u/signing-input.bin >/dev/null 2>&1
/w/tsa-bundle seal -in /w/u -signature /w/u/sig.b64 -key /w/trusted/cosign.pub -out /w/unsigned.zip
/tools/cosign upload blob --allow-http-registry -f /w/unsigned.zip --ct application/vnd.facis.tsa.bundle.v1+zip "$REG/tsa-bundles:unsigned" 2>/dev/null | tail -1 > /w/ref-unsigned
EOF
docker run --rm --network kind -e REG="$reg" -v "$work:/w" -v "$bin:/tools:ro" -v "$root:/src:ro" "$toolbox" bash /w/publish.sh
# Tampered: v2 with its policy replaced by an allow-all after signing, then pushed and given a valid
# artefact signature by the trusted key - only the bundle signature can catch it.
python3 -I - "$work/v2.zip" "$work/tampered.zip" <<'EOF'
import io, sys, zipfile
outer = zipfile.ZipFile(sys.argv[1])
inner = zipfile.ZipFile(io.BytesIO(outer.read("policy_bundle.zip")))
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    for n in inner.namelist():
        data = inner.read(n)
        if n == "policy.rego":
            data = data.replace(b'"m3-scope-withdrawn"', b'"tampered"')
            assert b"tampered" in data
        z.writestr(n, data)
with zipfile.ZipFile(sys.argv[2], "w") as z:
    z.writestr("policy_bundle.zip", buf.getvalue())
    z.writestr("signature.raw", outer.read("signature.raw"))
EOF
cat > "$work/tamper.sh" <<'EOF'
set -euo pipefail
ref=$(/tools/cosign upload blob --allow-http-registry -f /w/tampered.zip --ct application/vnd.facis.tsa.bundle.v1+zip "$REG/tsa-bundles:tampered" 2>/dev/null | tail -1)
COSIGN_PASSWORD= /tools/cosign sign --yes --key /w/trusted/cosign.key --tlog-upload=false --new-bundle-format=false --allow-http-registry "$ref" >/dev/null 2>&1
echo "$ref" > /w/ref-tampered
EOF
docker run --rm --network kind -e REG="$reg" -v "$work:/w" -v "$bin:/tools:ro" "$toolbox" bash /w/tamper.sh
for r in v1 v2 other unsigned tampered lying; do echo "  $r $(cat "$work/ref-$r")"; done | tee "$out/bundles.txt"

step "Install the TSA policy service and the guard chart"
# The charts' PeerAuthentication and AuthorizationPolicy need the Istio CRDs; no mesh is installed.
kubectl apply --server-side -f "$bin/istio-crds/istio.yaml" >/dev/null
kubectl create namespace "$tsa_ns" >/dev/null
kubectl create namespace "$guard_ns" >/dev/null
tsa_values=(-n "$tsa_ns"
  --set images.tsa.repository="${TSA_POLICY_IMAGE%%:*}" --set images.nats.repository="${NATS_IMAGE%%:*}"
  --set images.git.repository="$reg/ztd/tsa-git" --set images.git.digest="${digests[tsa-git]}"
  --set images.bundle.repository="$reg/ztd/tsa-bundle" --set images.bundle.digest="${digests[tsa-bundle]}"
  --set bundle.repository="$reg/tsa-bundles" --set-json "bundle.plainHTTPRegistries=[\"$reg\"]" --set bundle.pollSeconds=2
  --set-file trustRoot="$work/trusted/cosign.pub"
  --set-json "callers=[{\"namespace\":\"$guard_ns\",\"name\":\"ztd-policy-evaluator\"}]"
  --set-json "networkPolicy.egress=[{\"to\":[{\"ipBlock\":{\"cidr\":\"$reg_ip/32\"}}],\"ports\":[{\"protocol\":\"TCP\",\"port\":5000}]}]")
declare_bundle() { helm upgrade --install tsa deployment/helm/tsa-policy "${tsa_values[@]}" --set bundle.ref="$(cat "$work/ref-$1")" --set bundle.revision="$2" >/dev/null; }
declare_bundle v1 v1
helm install guard deployment/helm/guard -n "$guard_ns" -f deployment/helm/guard/ci/values.yaml \
  --set images.guard.repository="$reg/ztd/guard" --set images.guard.digest="${digests[guard]}" \
  --set images.policy.repository="$reg/ztd/policy-evaluator" --set images.policy.digest="${digests[policy-evaluator]}" \
  --set images.envoy.repository="${ENVOY_IMAGE%%:*}" --set networkPolicy.istiod.enabled=false \
  --set tsa.evaluationURL="http://tsa-policy-engine.$tsa_ns:8080/policy/policies/facis/guard/1.0/evaluation" \
  --set-json "networkPolicy.egress=[{\"to\":[{\"namespaceSelector\":{\"matchLabels\":{\"kubernetes.io/metadata.name\":\"$tsa_ns\"}},\"podSelector\":{\"matchLabels\":{\"app.kubernetes.io/name\":\"tsa-policy-engine\"}}}],\"ports\":[{\"protocol\":\"TCP\",\"port\":8080}]}]" >/dev/null
# The test client stands where the guard does: its label is what the evaluator's ingress admits.
kubectl -n "$guard_ns" run client --image="docker.io/curlimages/curl:8.10.1@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b" \
  --labels=app.kubernetes.io/name=ztd-guard --restart=Never --command -- sleep 3600 >/dev/null
kubectl -n "$tsa_ns" rollout status deploy/tsa-policy-engine --timeout=300s
kubectl -n "$guard_ns" rollout status deploy/ztd-policy-evaluator --timeout=180s
kubectl -n "$guard_ns" wait pod/client --for=condition=Ready --timeout=120s >/dev/null

pods() {
  for p in "$tsa_ns app.kubernetes.io/name=tsa-policy-engine" "$guard_ns app.kubernetes.io/name=ztd-policy-evaluator"; do
    read -r ns selector <<<"$p"
    kubectl -n "$ns" get pod -l "$selector" -o json | jq -c '[.items[] | {pod: .metadata.name, uid: .metadata.uid, restarts: ([.status.containerStatuses[]?, .status.initContainerStatuses[]?] | map({(.name): .restartCount}) | add)}]'
  done | jq -sc add
}
before=$(pods)
input='{"correlation_id":"CID","source":{"spiffe_id":"spiffe://zone-b.trust.invalid/ns/ztd-guard/sa/ztd-participant"},"request":{"method":"POST","path":"/demo","host":"ztd-guard:8080"},"token":{"present":true,"sub":"subject","client_id":"client","jkt":"thumbprint","scope":"report:summary","aud":"https://guard.facis.invalid","proof_valid":true},"tenant":"report-summary"}'
: > "$out/decisions.jsonl"
# decide [input]: one IF-05 request as the guard sends it (default $input); the answer is recorded
# with its correlation id.
decide() {
  local id d req=${1:-$input}
  id="proof-$(wc -l < "$out/decisions.jsonl" | tr -d ' ')"
  d=$(kubectl -n "$guard_ns" exec client -- curl -sS -m 5 -X POST http://ztd-policy-evaluator:8080/decision \
    -H 'Content-Type: application/json' -H "X-Forwarded-Client-Cert: URI=spiffe://zone-b.trust.invalid/ns/$guard_ns/sa/ztd-guard" \
    -d "${req/CID/$id}")
  jq -nc --arg id "$id" --arg d "$d" '{id: $id, answer: ($d | fromjson? // $d)}' >> "$out/decisions.jsonl"
  echo "$d"
}
# until_revision <revision>: decisions until one is taken under that revision (the kubelet refreshes
# the mounted bundle declaration within about a minute).
until_revision() {
  for _ in $(seq 1 90); do
    d=$(decide)
    [ "$(jq -r .bundle_revision <<<"$d" 2>/dev/null)" = "$1" ] && { echo "$d"; return 0; }
    sleep 2
  done
  echo "$d"
  return 1
}
# until_answered: a decision, asking again while the answer is the fail-closed 503 (a loaded node
# can make one evaluation miss the bound; that is a refusal, never a wrong decision, and stays in
# decisions.jsonl).
until_answered() { # until_answered [input]
  for _ in $(seq 1 10); do
    d=$(decide "${1:-}")
    jq -e '.bundle_revision' <<<"$d" >/dev/null 2>&1 && break
    sleep 3
  done
  echo "$d"
}
expect() { # expect <label> <decision> <allow> <rule> <revision>
  if [ "$(jq -c '[.allow, .rule_id, .bundle_revision]' <<<"$2")" = "[$3,\"$4\",\"$5\"]" ]; then pass "$1: $2"; else fail "$1: $2"; fi
}

step "1. v1 allows"
expect "v1 active, entitled summary request" "$(until_revision v1)" true m3-report-summary v1
# Tenant membership in the bundle's Rego: the same request on a route a guard names for tenant-a,
# while the bundle's data names no member of any tenant.
expect "v1 active, the same request for target tenant tenant-a, of which the bundle names no member" \
  "$(until_answered "$(jq -c '. + {target_tenant: "tenant-a"}' <<<"$input")")" false m3-tenant-membership v1

step "2. v2 denies, without a restart"
declare_bundle v2 v2
expect "v2 declared, same request" "$(until_revision v2)" false m3-scope-withdrawn v2
if [ "$(pods)" = "$before" ]; then pass "no pod replaced or restarted: $before"; else fail "pods changed: $before -> $(pods)"; fi

step "3. refused bundles leave v2 active"
for bad in "unsigned unsigned" "other v3" "tampered v2-tampered" "lying v4"; do
  read -r name revision <<<"$bad"
  set -- "$name" "$revision"
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  declare_bundle "$1" "$2"
  ref=$(cat "$work/ref-$1")
  reason=""
  for _ in $(seq 1 90); do
    reason=$(kubectl -n "$tsa_ns" logs deploy/tsa-policy-engine -c bundle --since-time="$since" | jq -r --arg ref "$ref" 'select(.msg=="bundle refused" and .bundle==$ref) | .reason' | head -1)
    [ -n "$reason" ] && break
    sleep 2
  done
  if [ -n "$reason" ]; then pass "$1 bundle refused: $reason"; else fail "$1 bundle not refused"; fi
  expect "after the $1 bundle" "$(until_answered)" false m3-scope-withdrawn v2
done

step "4. rollback to v1"
declare_bundle v1 v1
expect "v1 declared again" "$(until_revision v1)" true m3-report-summary v1
if [ "$(pods)" = "$before" ]; then pass "still no pod replaced or restarted"; else fail "pods changed: $before -> $(pods)"; fi

step "5. decision log"
{ kubectl -n "$guard_ns" logs deploy/ztd-policy-evaluator --previous 2>/dev/null || true
  kubectl -n "$guard_ns" logs deploy/ztd-policy-evaluator; } > "$out/evaluator.log"
kubectl -n "$tsa_ns" logs deploy/tsa-policy-engine -c bundle > "$out/bundle-sidecar.log"
kubectl -n "$tsa_ns" logs deploy/tsa-policy-engine -c tsa > "$out/tsa.log"
# Every decision answered must appear in the evaluator's log under its correlation id, with the
# same rule and revision.
n=$(jq -s 'map(select((.answer | type) == "object" and .answer.bundle_revision != null)) | length' "$out/decisions.jsonl")
matched=$(jq -s --slurpfile log <(jq -c 'select(.msg=="policy decision")' "$out/evaluator.log") '
  map(select((.answer | type) == "object" and .answer.bundle_revision != null)) | map(. as $d | $log | any(.correlation_id == $d.id and .rule_id == $d.answer.rule_id
    and .bundle_revision == $d.answer.bundle_revision and .rule_id != null and .bundle_revision != null)) | map(select(.)) | length' "$out/decisions.jsonl")
if [ "$n" -gt 0 ] && [ "$matched" -eq "$n" ]; then pass "$n decisions logged, each with its rule_id and bundle_revision"; else fail "$n decisions, $matched logged with rule and revision"; fi

jq -n --arg tsa "$TSA_POLICY_IMAGE" --arg nats "$NATS_IMAGE" --arg node "$KIND_NODE_IMAGE" --arg arch "$arch" \
  --arg commit "$(git rev-parse HEAD)" '{tsa: $tsa, nats: $nats, kind_node: $node, node_arch: $arch, commit: $commit}' > "$out/environment.json"
echo
if [ "$failures" -eq 0 ]; then echo "VERDICT PASS" | tee -a "$out/verdict.txt"; else echo "VERDICT FAIL ($failures)" | tee -a "$out/verdict.txt"; exit 1; fi
