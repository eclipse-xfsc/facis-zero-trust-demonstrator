#!/usr/bin/env bash
# Admission end to end in a throwaway kind cluster: Gatekeeper (pinned chart, gatekeeper-values.yaml),
# the image-verification provider (deployment/helm/admission), the constraints (deployment/admission)
# and a local registry holding test images signed and attested with the release script and an
# ephemeral key. Runs the admission catalogue and fails if any case does not behave as specified.
#
#   BIN=<dir with kind kubectl cosign syft and the Gatekeeper chart> scripts/admission/kind-e2e.sh
#
# Needs docker and helm. KEEP=1 leaves the cluster and registry running for inspection.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env
bin="$(cd "${BIN:-.tools/bin}" && pwd)"
export PATH="$bin:$PATH"

cluster=ztd-admission
reg_name="kind-registry"
reg="$reg_name:5000"            # the registry's name inside the kind network, used in every image reference
host_reg=127.0.0.1:5001         # the same registry from this machine, for uploads
toolbox=golang:1.27@sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244
ns=ztd-adm-001
work="$(mktemp -d)"
export KUBECONFIG="$work/kubeconfig"

cleanup() {
  if [ -n "${KEEP:-}" ]; then
    echo "kept: cluster $cluster, registry $reg_name, KUBECONFIG=$KUBECONFIG"
    return
  fi
  kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
  docker rm -f "$reg_name" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

failures=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; failures=$((failures + 1)); }
step() { echo; echo "== $*"; }

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
# The test images are linux/amd64 (the policy admits nothing else); they run on an amd64 node only.
case "$(docker exec "$cluster-control-plane" uname -m)" in x86_64) node_arch=amd64 ;; aarch64) node_arch=arm64 ;; *) node_arch=other ;; esac
for node in $(kind get nodes --name "$cluster"); do
  docker exec "$node" mkdir -p "/etc/containerd/certs.d/$reg"
  printf '[host."http://%s"]\n' "$reg" | docker exec -i "$node" cp /dev/stdin "/etc/containerd/certs.d/$reg/hosts.toml"
done

step "Test images"
# shellcheck source=scripts/admission/fixtures-lib.sh disable=SC1091
. scripts/admission/fixtures-lib.sh
fixtures_build ztd
for k in $fixtures_names; do v="img_$k"; echo "  $k ${!v}"; done
oci_manifest=application/vnd.oci.image.manifest.v1+json
docker_manifest=application/vnd.docker.distribution.manifest.v2+json

step "Sign and attest (release script, ephemeral keys, on the kind network)"
cp docs/attestation/samples/sw.mock.json "$work/mock.json"
# shellcheck disable=SC2016 # the signing container's preamble, expanded there
{
  echo 'set -euo pipefail; cd /w'
  echo 'export COSIGN_PASSWORD= COSIGN_ALLOW_HTTP_REGISTRY=true COSIGN=/tools/cosign SYFT_REGISTRY_INSECURE_USE_HTTP=true'
  echo 'export TRUSTED_KEY=cosign.key OTHER_KEY=other/cosign.key'
  echo 'flags=(--allow-http-registry)'
  echo '/tools/cosign generate-key-pair >/dev/null; mkdir -p other; (cd other && /tools/cosign generate-key-pair >/dev/null)'
  echo 'sign_attest() { bash /src/scripts/supplychain/sign-attest.sh "$@"; }'
  echo 'app_sbom() { /tools/syft "registry:$1" -q -o "cyclonedx-json=$2"; }'
  fixtures_sign_script
} > "$work/sign.sh"
docker run --rm --network kind -v "$work:/w" -v "$bin:/tools:ro" -v "$root:/src:ro" "$toolbox" bash /w/sign.sh

step "Provider image"
# Built for the node, so the job also runs on an arm64 workstation; gatekeeper-system is exempt.
docker build -q --platform "linux/$node_arch" -f deployment/docker/admission-provider/Dockerfile -t "$host_reg/ztd/admission-provider:e2e" . >/dev/null
docker push -q "$host_reg/ztd/admission-provider:e2e" >/dev/null
provider_digest=$(curl -fsSI -H "Accept: $oci_manifest, $docker_manifest, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json" \
  "http://$host_reg/v2/ztd/admission-provider/manifests/e2e" | tr -d '\r' | awk 'tolower($1)=="docker-content-digest:"{print $2}')

step "Install (scripts/admission/install.sh, as on a real cluster)"
BIN="$bin" PROVIDER_IMAGE="$reg/ztd/admission-provider@$provider_digest" TRUST_REPOSITORY="$reg/ztd" TRUST_KEY="$work/cosign.pub" \
  GATEKEEPER_REPLICAS=2 PROVIDER_REPLICAS=1 PLAIN_HTTP_REGISTRY="$reg" scripts/admission/install.sh
# The same values, for the trust-removal upgrade below.
provider_values=(--set replicas=1 --set image.repository="$reg/ztd/admission-provider" --set image.digest="$provider_digest"
  --set insecurePlainHTTPRegistry="$reg" --set-json "trust.repositories=[\"$reg/ztd\"]")
unscoped=$(kubectl get validatingwebhookconfiguration gatekeeper-validating-webhook-configuration -o json | jq -r '
  .webhooks[] | select(any(.namespaceSelector.matchExpressions[]?; .key == "facis.ztd/admission-proof" and .operator == "In" and .values == ["true"]) | not) | .name')
if [ -z "$unscoped" ]; then pass "both webhooks scoped to facis.ztd/admission-proof=true"; else fail "webhooks not scoped: $unscoped"; fi
ttl=$(kubectl -n gatekeeper-system get deploy gatekeeper-controller-manager -o jsonpath='{.spec.template.spec.containers[0].args}' | tr ',' '\n' | grep -o 'response-cache-ttl=[^"]*' || true)
if [ "$ttl" = "response-cache-ttl=0s" ]; then pass "Gatekeeper external-data response cache off ($ttl)"; else fail "Gatekeeper response cache: '$ttl'"; fi
# Scope follows the label, not the name: a labelled namespace with any name is enforced, an unlabelled
# ztd-adm-* namespace is not.
kubectl create namespace proof-labelled >/dev/null
kubectl label namespace proof-labelled facis.ztd/admission-proof=true >/dev/null
kubectl create namespace ztd-adm-unlabelled >/dev/null
# The ignore-label webhook guards the admission namespaces only.
if out=$(kubectl label namespace "$ns" admission.gatekeeper.sh/ignore=true --dry-run=server 2>&1); then
  fail "ignore label on an admission namespace: accepted"
else pass "ignore label on an admission namespace: denied"; fi
if kubectl label namespace ztd-adm-unlabelled admission.gatekeeper.sh/ignore=true --dry-run=server >/dev/null 2>&1; then
  pass "ignore label on an unrelated namespace: accepted"
else fail "ignore label on an unrelated namespace: denied"; fi

step "Admission catalogue"
# The admission namespaces enforce the restricted Pod Security Standard; every test workload meets it,
# so a denial is always the admission policy's.
pod_security=$'  securityContext:\n    runAsNonRoot: true\n    runAsUser: 65534\n    seccompProfile: {type: RuntimeDefault}\n'
container_security=$'      securityContext:\n        allowPrivilegeEscalation: false\n        capabilities: {drop: [ALL]}\n'
template_pod_security=$'      securityContext:\n        runAsNonRoot: true\n        runAsUser: 65534\n        seccompProfile: {type: RuntimeDefault}\n'
template_container_security=$'          securityContext:\n            allowPrivilegeEscalation: false\n            capabilities: {drop: [ALL]}\n'
pod() { # name image [namespace] [extra spec lines]
  printf 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: %s\n  namespace: %s\nspec:\n%s  containers:\n    - name: app\n      image: "%s"\n      command: [sleep, "3600"]\n%s%s\n' "$1" "${3:-$ns}" "$pod_security" "$2" "$container_security" "${4:-}"
}
deployment() { # name image
  printf 'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: %s\n  namespace: %s\nspec:\n  selector:\n    matchLabels: {app: %s}\n  template:\n    metadata:\n      labels: {app: %s}\n    spec:\n%s      containers:\n        - name: app\n          image: "%s"\n          command: [sleep, "3600"]\n%s' "$1" "$ns" "$1" "$1" "$template_pod_security" "$2" "$template_container_security"
}
# Server-side dry run: the request goes through admission, nothing is stored.
expect_denied() { # case code manifest
  local out
  if out=$(kubectl create --dry-run=server -f - <<<"$3" 2>&1); then fail "$1: admitted, expected $2"; return; fi
  if grep -q -- "$2" <<<"$out"; then pass "$1: denied $2"; else fail "$1: denied, but not with $2: $out"; fi
}
eventually_allowed() { # case manifest: admitted within a minute
  local out
  for _ in $(seq 30); do
    if out=$(kubectl create --dry-run=server -f - <<<"$2" 2>&1); then pass "$1: admitted"; return; fi
    sleep 2
  done
  fail "$1: still denied: $out"
}
expect_allowed() { # case manifest
  local out
  if out=$(kubectl create --dry-run=server -f - <<<"$2" 2>&1); then pass "$1: admitted"; else fail "$1: denied: $out"; fi
}

signed=${img_app}
if ! out=$(kubectl create -f - <<<"$(pod ztd-signed "$signed")" 2>&1); then
  fail "signed image: denied: $out"
elif [ "$node_arch" != amd64 ]; then
  pass "signed image: admitted"
  echo "SKIP  signed image Running: the node is $node_arch, the test image linux/amd64"
elif kubectl -n "$ns" wait --for=condition=Ready pod/ztd-signed --timeout=180s >/dev/null; then
  pass "signed image: admitted and Running"
else
  fail "signed image: admitted but not Running: $(kubectl -n "$ns" get pod ztd-signed 2>&1 | tail -1)"
fi
expect_denied "unsigned" ADM-UNSIGNED "$(pod ztd-unsigned "${img_unsigned}")"
expect_denied "signed by an untrusted key" ADM-UNSIGNED "$(pod ztd-wrongkey "${img_wrongkey}")"
expect_denied "mutable tag" ADM-NOT-DIGEST "$(pod ztd-tag "$reg/ztd/app:e2e")"
expect_denied "SBOM attestation missing" ADM-SBOM-MISSING "$(pod ztd-nosbom "${img_nosbom}")"
expect_denied "mock attestation missing" ADM-NO-ATTESTATION "$(pod ztd-nomock "${img_nomock}")"
expect_denied "non-Linux image" ADM-NOT-LINUX "$(pod ztd-windows "${img_windows}")"
expect_denied "image index" ADM-INDEX-UNSUPPORTED "$(pod ztd-index "${img_index}")"
expect_denied "registry not allowed" ADM-REGISTRY-DENIED "$(pod ztd-foreign "docker.io/library/busybox@${signed#*@}")"
expect_denied "name outside the convention" ADM-NAME-INVALID "$(pod busybox "$signed")"
expect_denied "unsigned init container" ADM-UNSIGNED "$(pod ztd-init "$signed" "$ns" "  initContainers:
    - name: init
      image: \"${img_unsigned}\"
      command: [\"true\"]
${container_security%$'\n'}")"
expect_denied "deployment with an unsigned template" ADM-UNSIGNED "$(deployment ztd-unsigned-deploy "${img_unsigned}")"
expect_allowed "deployment with a signed template" "$(deployment ztd-signed-deploy "$signed")"
expect_denied "labelled namespace of another name" ADM-UNSIGNED "$(pod ztd-unsigned "${img_unsigned}" proof-labelled)"
expect_allowed "unlabelled ztd-adm-* namespace" "$(pod ztd-unsigned "${img_unsigned}" ztd-adm-unlabelled)"
if out=$(kubectl -n "$ns" debug ztd-signed --profile=restricted --image="${img_unsigned}" --container=dbg-unsigned 2>&1); then
  fail "unsigned ephemeral container: added"
elif grep -q ADM-UNSIGNED <<<"$out"; then pass "unsigned ephemeral container: denied ADM-UNSIGNED"; else fail "unsigned ephemeral container: $out"; fi
if kubectl -n "$ns" debug ztd-signed --profile=restricted --image="$signed" --container=dbg-signed >/dev/null 2>&1; then
  pass "signed ephemeral container: added"
else fail "signed ephemeral container: denied"; fi

step "Provider down"
kubectl -n gatekeeper-system scale deploy/ztd-admission-provider --replicas=0 >/dev/null
kubectl -n gatekeeper-system wait --for=delete pod -l app.kubernetes.io/name=ztd-admission-provider --timeout=120s >/dev/null 2>&1 || true
expect_denied "signed image with the provider down" ADM-PROVIDER-DOWN "$(pod ztd-signed-2 "$signed")"
kubectl -n gatekeeper-system scale deploy/ztd-admission-provider --replicas=1 >/dev/null
kubectl -n gatekeeper-system rollout status deploy/ztd-admission-provider --timeout=180s >/dev/null
# The Service routes to the new pod a moment after it is Ready.
eventually_allowed "signed image with the provider back" "$(pod ztd-signed-2 "$signed")"

step "Trust removed while the provider cache is warm"
# The next admission after the provider has loaded the new policy must be denied, while the warmed
# verdict would still be valid (positive TTL 5 min): only the policy change can explain the denial.
revisions() { kubectl -n gatekeeper-system logs deploy/ztd-admission-provider 2>/dev/null | grep '"trust policy loaded"' | grep -o '"revision":"[^"]*"' || true; }
expect_allowed "signed image, warm cache" "$(pod ztd-signed-3 "$signed")"
warmed=$(date +%s)
before=$(revisions | tail -1)
helm upgrade admission deployment/helm/admission -n gatekeeper-system "${provider_values[@]}" \
  --set-file trust.publicKeys="$work/other/cosign.pub" --wait --timeout 3m >/dev/null
loaded=
for _ in $(seq 90); do
  now=$(revisions | tail -1)
  if [ -n "$now" ] && [ "$now" != "$before" ]; then loaded=$now; break; fi
  sleep 2
done
elapsed=$(( $(date +%s) - warmed ))
if [ -z "$loaded" ]; then
  fail "trusted key removed: the provider did not load a new trust policy"
elif [ "$elapsed" -ge 280 ]; then
  fail "trusted key removed: policy loaded only after ${elapsed}s, too close to the cache TTL to prove anything"
else
  expect_denied "trusted key removed ($loaded after ${elapsed}s): next admission" ADM-UNSIGNED "$(pod ztd-signed-3 "$signed")"
fi
helm upgrade admission deployment/helm/admission -n gatekeeper-system "${provider_values[@]}" \
  --set-file trust.publicKeys="$work/cosign.pub" --wait --timeout 3m >/dev/null

step "Gatekeeper down"
kubectl -n gatekeeper-system scale deploy/gatekeeper-controller-manager --replicas=0 >/dev/null
kubectl -n gatekeeper-system wait --for=delete pod -l control-plane=controller-manager --timeout=120s >/dev/null 2>&1 || true
expect_denied "admission namespace with Gatekeeper down" "failed calling webhook" "$(pod ztd-signed-4 "$signed")"
expect_denied "labelled namespace of another name with Gatekeeper down" "failed calling webhook" "$(pod ztd-signed-5 "$signed" proof-labelled)"
expect_allowed "unlabelled ztd-adm-* namespace with Gatekeeper down" "$(pod ztd-other "${img_unsigned}" ztd-adm-unlabelled)"
kubectl -n gatekeeper-system scale deploy/gatekeeper-controller-manager --replicas=1 >/dev/null
kubectl -n gatekeeper-system rollout status deploy/gatekeeper-controller-manager --timeout=180s >/dev/null

echo
if [ "$failures" -gt 0 ]; then echo "$failures case(s) failed"; exit 1; fi
echo "all admission cases passed"
