#!/usr/bin/env bash
# Admission end to end in a throwaway kind cluster: Gatekeeper (pinned chart, gatekeeper-values.yaml),
# the image-verification provider (deployment/helm/admission), the constraints (deployment/admission)
# and a local registry holding test images signed and attested with the release script and an
# ephemeral key. Runs the admission catalogue and fails if any case does not behave as specified.
#
#   BIN=<dir with kind kubectl cosign syft and the Gatekeeper chart> [LAYOUT=standalone] scripts/admission/kind-e2e.sh
#
# LAYOUT is how admission is installed before the catalogue runs:
#   standalone  scripts/admission/install.sh: releases gatekeeper, admission, admission-pool (default)
#   umbrella    a clean install of the umbrella's admission release (scripts/install-zone/install.sh
#               install gatekeeper, with the kind zone file and admission.install)
#   migrate     standalone, then the umbrella adopts it (ADMISSION_ADOPT=1); the Deployments, the
#               provider's TLS Secret and the constraints must be the same objects afterwards
#   rollback    migrate, then back to standalone (scripts/admission/install.sh FROM_UMBRELLA=1), with
#               the same objects again; the rollback is interrupted once after Gatekeeper and re-run
# The umbrella layout also upgrades the installed release: during a readiness blip (no Gatekeeper
# webhook replica) nothing may be removed; with a changed constraint and a new pool namespace the
# namespace comes only after the change is enforced; and (POLICY=helm) the handoff to Argo CD is
# refused without admission.policy.keep, and with it leaves every policy object in place.
# The trust-removal step changes the provider in whichever layout is installed. POLICY=argocd (umbrella
# layouts) sets admission.policy.managedBy: argocd and stands in for Argo CD: the policy objects are
# applied with kubectl, as install.sh applies them, once Gatekeeper's CRDs exist; the release must
# then neither render nor own them.
#
# Needs docker and helm; python3 with PyYAML for the umbrella layouts. KEEP=1 leaves the cluster and
# registry running for inspection.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env
# shellcheck source=scripts/admission/checks.sh
. scripts/admission/checks.sh
bin="$(cd "${BIN:-.tools/bin}" && pwd)"
export PATH="$bin:$PATH"
layout=${LAYOUT:-standalone}
policy=${POLICY:-helm}
case "$policy" in helm | argocd) ;; *) echo "POLICY must be helm or argocd" >&2; exit 2 ;; esac
case "$layout" in standalone | umbrella | migrate | rollback) ;; *) echo "LAYOUT must be standalone, umbrella, migrate or rollback" >&2; exit 2 ;; esac

cluster=ztd-admission
reg_name="kind-registry"
reg="$reg_name:5000"            # the registry's name inside the kind network, used in every image reference
host_reg=127.0.0.1:5001         # the same registry from this machine, for uploads
toolbox=golang:1.27@sha256:f24164268fc1e741bbdc0066dbadcf1c8426c5a8489f0729c02c3905a53032fd
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
  # The signing container writes $work as root; hand it back so the runner user can remove it.
  docker run --rm -v "$work:/w" "$toolbox" chown -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 || true
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
cp docs/contracts/samples/sw.mock.json "$work/mock.json"
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

step "Install ($layout layout, as on a real cluster)"
# A third-party image admitted by exact digest (the injected Istio proxy); only dry runs use it.
allow_listed=docker.io/istio/proxyv2@sha256:d86cba0dd1eb15c00b6901c69ce5ae3d2d5f8427a47751098cf8c3ab2a4a62e9
standalone() {
  ALLOWED_DIGESTS="$allow_listed" BIN="$bin" PROVIDER_IMAGE="$reg/ztd/admission-provider@$provider_digest" TRUST_REPOSITORY="$reg/ztd" TRUST_KEY="$work/cosign.pub" \
    GATEKEEPER_REPLICAS=2 PROVIDER_REPLICAS=1 PLAIN_HTTP_REGISTRY="$reg" env "$@" scripts/admission/install.sh
}
# The kind zone file with admission.install and the same settings as standalone() above.
umbrella() {
  python3 - deployment/helm/ztd/ci/values.yaml "$work/zone.yaml" "$reg" "$provider_digest" "$work/cosign.pub" "$allow_listed" "$policy" <<'PY'
import sys, yaml
source, target, reg, digest, key, allowed, policy = sys.argv[1:]
zone = yaml.safe_load(open(source))
zone["admission"] = {"install": True, "policy": {"managedBy": policy}}
zone["gatekeeper"] = {"replicas": 2}
zone["admissionProvider"] = {
    "replicas": 1,
    "image": {"repository": f"{reg}/ztd/admission-provider", "digest": digest},
    "insecurePlainHTTPRegistry": reg,
    "trust": {"repositories": [f"{reg}/ztd"], "publicKeys": open(key).read(), "allowedDigests": [allowed]},
}
yaml.safe_dump(zone, open(target, "w"), sort_keys=False)
PY
  [ "$policy" = helm ] || argocd_standin &
  KUBE_CONTEXT="kind-$cluster" ZONE_VALUES="$work/zone.yaml" ADMISSION_ADOPT=1 scripts/install-zone/install.sh install gatekeeper
  wait
}
# Argo CD's part with POLICY=argocd: the policy objects, applied from outside the release.
argocd_standin() {
  until kubectl get crd constrainttemplates.templates.gatekeeper.sh >/dev/null 2>&1; do sleep 2; done
  kubectl apply -f deployment/admission/templates/ -f deployment/admission/exemptions.yaml >/dev/null
  for c in $admission_constraints; do
    until kubectl wait --for=condition=established --timeout=5s "crd/${c%%/*}.constraints.gatekeeper.sh" >/dev/null 2>&1; do sleep 2; done
  done
  sed -e "s|ghcr.io/eclipse-xfsc/facis-zero-trust-demonstrator|$reg/ztd|" -e "s|^    allowedDigests: \[\]$|    allowedDigests: [\"$allow_listed\"]|" \
    deployment/admission/constraints/allowed-repositories.yaml | kubectl apply -f - >/dev/null
  for c in image-digest naming verified-images; do kubectl apply -f "deployment/admission/constraints/$c.yaml" >/dev/null; done
}
# With POLICY=argocd no policy object may carry a Helm owner.
policy_owners() {
  kubectl get constrainttemplates -o json | jq -r '.items[] | .metadata.annotations["meta.helm.sh/release-name"] // empty'
  for c in $admission_constraints; do kubectl get "$c" -o jsonpath='{.metadata.annotations.meta\.helm\.sh/release-name}'; done
  kubectl -n gatekeeper-system get config config -o jsonpath='{.metadata.annotations.meta\.helm\.sh/release-name}'
}
# The objects that must survive a change of layout unchanged: the Deployments (same UID - adopted in
# place, not recreated), the provider's TLS Secret (same CA) and the constraints.
identity() {
  {
    kubectl -n gatekeeper-system get deploy gatekeeper-controller-manager gatekeeper-audit ztd-admission-provider -o jsonpath='{range .items[*]}{.metadata.name} {.metadata.uid}{"\n"}{end}'
    kubectl -n gatekeeper-system get secret ztd-admission-provider-tls -o jsonpath='{.metadata.uid} {.data.ca\.crt}' | shasum -a 256
    for c in $admission_constraints; do kubectl get "$c" -o jsonpath='{.metadata.name} {.metadata.uid}{"\n"}'; done
  }
}
releases() { helm list -n gatekeeper-system -o json | jq -r 'map("\(.name)=\(.chart)") | sort | join(" ")'; }
expect_layout() { # layout releases
  if [ "$(admission_layout)" = "$1" ] && [ "$(releases)" = "$2" ]; then pass "layout $1: $2"; else fail "layout: $(admission_layout), releases $(releases), expected $1: $2"; fi
}
if [ "$layout" != standalone ]; then
  # The umbrella's dependencies, from its Chart.lock and the local admission charts.
  helm repo add ztd-openbao https://openbao.github.io/openbao-helm >/dev/null 2>&1 || true
  helm repo add ztd-gatekeeper https://open-policy-agent.github.io/gatekeeper/charts >/dev/null 2>&1 || true
  helm dependency build deployment/helm/ztd >/dev/null
fi
standalone_releases="admission-pool=admission-pool-0.1.0 admission=admission-0.1.0 gatekeeper=gatekeeper-$GATEKEEPER_CHART_VERSION"
umbrella_releases="gatekeeper=ztd-$(sed -n 's/^version: *//p' deployment/helm/ztd/Chart.yaml)"
case "$layout" in
  standalone) standalone ;;
  umbrella)
    umbrella
    expect_layout umbrella "$umbrella_releases" ;;
  migrate | rollback)
    standalone
    before=$(identity)
    umbrella
    expect_layout umbrella "$umbrella_releases"
    if [ "$(identity)" = "$before" ]; then pass "migrate: the same Deployments, provider CA and constraints"; else fail "migrate: objects replaced: $(diff <(echo "$before") <(identity) || true)"; fi
    if [ "$layout" = rollback ]; then
      # Interrupted once Gatekeeper is back as its own release, before the provider and the pool.
      standalone FROM_UMBRELLA=1 > "$work/rollback.log" 2>&1 &
      pid=$!
      until grep -q '^== Provider' "$work/rollback.log" || ! kill -0 "$pid" 2>/dev/null; do sleep 1; done
      kill "$pid" 2>/dev/null || true
      wait "$pid" || true
      echo "rollback interrupted; releases now: $(releases)"
      standalone FROM_UMBRELLA=1
      expect_layout standalone "$standalone_releases"
      if [ "$(identity)" = "$before" ]; then pass "rollback: the same Deployments, provider CA and constraints"; else fail "rollback: objects replaced: $(diff <(echo "$before") <(identity) || true)"; fi
    fi ;;
esac
# zone_set <python statement on zone>: change the kind zone file.
zone_set() {
  python3 - "$work/zone.yaml" "$1" <<'PY'
import sys, yaml
path, statement = sys.argv[1:]
zone = yaml.safe_load(open(path))
exec(statement)
yaml.safe_dump(zone, open(path, "w"), sort_keys=False)
PY
}
zone_install() { KUBE_CONTEXT="kind-$cluster" ZONE_VALUES="$work/zone.yaml" scripts/install-zone/install.sh install gatekeeper; }
inventory() { helm get manifest gatekeeper -n gatekeeper-system | grep -c '^kind:'; }
pool_uids() { kubectl get namespace ztd-adm-001 ztd-adm-002 -o jsonpath='{range .items[*]}{.metadata.uid} {end}'; }
if [ "$layout" = umbrella ]; then
  step "Upgrades of the umbrella's admission release"
  # A readiness blip: no Gatekeeper webhook replica, so no constraint is acknowledged.
  before=$(identity) objects=$(inventory) pools=$(pool_uids)
  kubectl -n gatekeeper-system scale deploy/gatekeeper-controller-manager --replicas=0 >/dev/null
  kubectl -n gatekeeper-system wait --for=delete pod -l control-plane=controller-manager --timeout=120s >/dev/null 2>&1 || true
  if zone_install > "$work/blip.log" 2>&1 && [ "$(identity)" = "$before" ] && [ "$(inventory)" -ge "$objects" ] && [ "$(pool_uids)" = "$pools" ]; then
    pass "upgrade during a readiness blip: nothing removed ($(inventory) objects, the same Deployments, constraints and pool)"
  else fail "upgrade during a readiness blip: $(tail -3 "$work/blip.log") inventory $objects -> $(inventory)"; fi
  # A changed constraint (one more allow-listed digest) and a new pool namespace together.
  extra=docker.io/library/busybox@sha256:0000000000000000000000000000000000000000000000000000000000000001
  zone_set "zone['admissionProvider']['trust']['allowedDigests'].append('$extra'); zone.setdefault('admissionPool', {})['namespaces'] = ['ztd-adm-001', 'ztd-adm-002', 'ztd-adm-003']"
  [ "$policy" = helm ] || kubectl patch k8sztdallowedrepositories ztd-allowed-repositories --type=json \
    -p "[{\"op\":\"add\",\"path\":\"/spec/parameters/allowedDigests/-\",\"value\":\"$extra\"}]" >/dev/null
  if zone_install > "$work/change.log" 2>&1; then
    order=$(grep -nE 'pool: ztd-adm-001 ztd-adm-002\)|adding the pool namespaces' "$work/change.log" | cut -d: -f1 | tr '\n' ' ')
    digests=$(kubectl get k8sztdallowedrepositories ztd-allowed-repositories -o json | jq -r '.spec.parameters.allowedDigests | join(" ")')
    if [ "$(wc -w <<<"$order")" -eq 2 ] && [[ "$digests" == *"$extra"* ]] && kubectl get namespace ztd-adm-003 >/dev/null 2>&1 &&
      admission_enforced k8sztdallowedrepositories/ztd-allowed-repositories; then
      pass "policy change with a new pool namespace: the change enforced first, then ztd-adm-003 added"
    else fail "policy change with a new pool namespace: order [$order], digests [$digests]: $(tail -3 "$work/change.log")"; fi
  else fail "policy change with a new pool namespace: $(tail -3 "$work/change.log")"; fi
  if [ "$policy" = helm ]; then
    # The handoff to Argo CD: refused while the policy objects lack keep; with it, they stay.
    revision=$(helm status gatekeeper -n gatekeeper-system -o json | jq .version)
    zone_set "zone['admission']['policy']['managedBy'] = 'argocd'"
    if ! zone_install > "$work/handoff.log" 2>&1 && grep -q 'admission.policy.keep' "$work/handoff.log" &&
      [ "$(helm status gatekeeper -n gatekeeper-system -o json | jq .version)" = "$revision" ]; then
      pass "handoff to Argo CD without keep: refused, nothing changed"
    else fail "handoff to Argo CD without keep: $(tail -3 "$work/handoff.log")"; fi
    before=$(identity)
    zone_set "zone['admission']['policy'].update(managedBy='helm', keep=True)"
    zone_install > "$work/handoff.log" 2>&1 || fail "handoff step 1 (keep): $(tail -3 "$work/handoff.log")"
    zone_set "zone['admission']['policy']['managedBy'] = 'argocd'"
    if zone_install > "$work/handoff.log" 2>&1 && [ "$(identity)" = "$before" ] &&
      ! helm get manifest gatekeeper -n gatekeeper-system | grep -qE '^kind: (ConstraintTemplate|Config$|K8sZtd)'; then
      pass "handoff to Argo CD with keep: the release holds no policy object, every one still in place"
    else fail "handoff to Argo CD with keep: $(tail -3 "$work/handoff.log")"; fi
  fi
fi
if [ "$policy" = argocd ]; then
  owners=$(policy_owners)
  if [ -z "$owners" ]; then pass "policy objects owned by no Helm release (Argo CD's)"; else fail "policy objects owned by Helm release(s): $owners"; fi
fi
# The webhook-scope post-renderer, for the provider upgrades below in the umbrella layout.
admission_helm_home "$work/helm-data"
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
expect_allowed "allow-listed third-party digest" "$(pod ztd-allow-listed "$allow_listed")"
expect_denied "other digest of an allow-listed repository" ADM-REGISTRY-DENIED "$(pod ztd-allow-other "${allow_listed%@*}@${signed#*@}")"
expect_denied "allow-listed digest with a tag" ADM-NOT-DIGEST "$(pod ztd-allow-tag "${allow_listed%@*}:1.31.1@${allow_listed#*@}")"
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
admission_provider_upgrade --set-file trust.publicKeys="$work/other/cosign.pub" --wait --timeout 3m >/dev/null
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
admission_provider_upgrade --set-file trust.publicKeys="$work/cosign.pub" --wait --timeout 3m >/dev/null

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
