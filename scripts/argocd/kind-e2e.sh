#!/usr/bin/env bash
# The admission reconciler end to end in a throwaway kind cluster: Gatekeeper (pinned chart,
# gatekeeper-values.yaml, the webhook-scope post-renderer, as scripts/admission/install.sh installs it;
# no provider, the policy is applied, not exercised), then Argo CD handed the admission policy of a Git
# revision by scripts/argocd/install.sh, which proves every Application Synced and Healthy, the zone's
# repository prefix in the allowed-repositories constraint and the sync status in the metrics. Then the
# catalogue in the cluster is compared with the checkout, a hand-edited constraint is put back
# (scripts/argocd/drift-check.sh), and a change on the parent is reverted too.
#
# Then the policy package (ZT-12): the catalogue is published to a registry on the kind network with
# the release scripts and an ephemeral key, the zone is re-installed to read the package through the
# puller (deployment/helm/policy-puller), and every child reads it by digest with the same content;
# a tampered package published to the channel tag with another key is refused and changes nothing, a
# release published with the trusted key reaches the cluster, the channel tag moved back to the older
# release is refused as a rollback, a registry that cannot be reached changes nothing, and the zone
# re-installed without the package reads Git again with nothing of the package left.
#
#   BIN=<dir with kind kubectl oras cosign and the Gatekeeper and Argo CD charts> REPO_URL=<git url> REVISION=<ref> \
#   scripts/argocd/kind-e2e.sh
#
# REPO_URL and REVISION are what the cluster's Argo CD fetches; the checkout must be that revision, or
# the comparison is meaningless. Needs docker and helm. KEEP=1 leaves the cluster for inspection.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env
: "${REPO_URL:?set REPO_URL}" "${REVISION:?set REVISION}"
bin="$(cd "${BIN:-.tools/bin}" && pwd)"
export PATH="$bin:$PATH"

cluster=ztd-gitops
trust_repository=registry.ztd.test/zone-e2e   # a prefix the files in Git do not name, so the patch is visible
reg_name=ztd-gitops-registry
reg="$reg_name:5000"            # the registry's name inside the kind network, in every reference the cluster sees
host_reg=127.0.0.1:5002         # the same registry from this machine, for uploads
policy_repo=ztd/policy/admission
# The publish runs in a container on the kind network, so the signature names the registry as the
# cluster does: the puller checks the signature's reference against the repository it verifies.
toolbox=golang:1.27@sha256:007a316059246276cb214df93950be77837545dc78007a73e0291a4963d5d3bf
work="$(mktemp -d)"
export KUBECONFIG="$work/kubeconfig"
# The webhook-scope post-renderer is a Helm plugin; it lives in this run's own Helm directory.
export HELM_DATA_HOME="$work/helm" HELM_PLUGINS="$work/helm/plugins"

cleanup() {
  if [ -n "${KEEP:-}" ]; then
    echo "kept: cluster $cluster, registry $reg_name, KUBECONFIG=$KUBECONFIG"
    return
  fi
  kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
  docker rm -f "$reg_name" >/dev/null 2>&1 || true
  # The publishing container writes $work as root; hand it back so the runner user can remove it.
  docker run --rm -v "$work:/w" "$toolbox" chown -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

failures=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; failures=$((failures + 1)); }
step() { echo; echo "== $*"; }

step "Cluster and registry"
# The nodes reach the registry by name over plain http, for the puller image.
kind create cluster --name "$cluster" --image "$KIND_NODE_IMAGE" --wait 180s --config - <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry]
      config_path = "/etc/containerd/certs.d"
EOF
docker rm -f "$reg_name" >/dev/null 2>&1 || true
docker run -d --name "$reg_name" --network kind -p "$host_reg:5000" "$REGISTRY_IMAGE" >/dev/null
for node in $(kind get nodes --name "$cluster"); do
  docker exec "$node" mkdir -p "/etc/containerd/certs.d/$reg"
  printf '[host."http://%s"]\n' "$reg" | docker exec -i "$node" cp /dev/stdin "/etc/containerd/certs.d/$reg/hosts.toml"
done

step "Gatekeeper"
helm plugin install deployment/admission/webhook-scope >/dev/null
helm upgrade --install gatekeeper "$bin/gatekeeper-$GATEKEEPER_CHART_VERSION.tgz" -n gatekeeper-system --create-namespace \
  -f deployment/admission/gatekeeper-values.yaml --set replicas=1 \
  --set image.release="${GATEKEEPER_IMAGE#*:}" \
  --set preInstall.crdRepository.image.repository="${GATEKEEPER_CRDS_IMAGE%%:*}" \
  --set preInstall.crdRepository.image.tag="${GATEKEEPER_CRDS_IMAGE#*:}" \
  --set postInstall.labelNamespace.image.tag="${GATEKEEPER_CRDS_IMAGE#*:}" \
  --set postUpgrade.labelNamespace.image.tag="${GATEKEEPER_CRDS_IMAGE#*:}" \
  --set postInstall.probeWebhook.enabled=false --post-renderer ztd-webhook-scope --wait --timeout 8m >/dev/null
echo "gatekeeper deployed"

step "Argo CD and the admission policy of $REVISION"
# kind's CNI enforces NetworkPolicy and selects the API server by address: the lane goes to the
# endpoint of the kubernetes Service (the node, port 6443) and to the Service address.
api_cidrs=$(kubectl get endpointslices -n default -l kubernetes.io/service-name=kubernetes -o jsonpath='{.items[*].endpoints[*].addresses[*]}' | tr ' ' '\n' | sed 's|$|/32|' | paste -sd,)
api_cidrs="$api_cidrs,$(kubectl get service kubernetes -o jsonpath='{.spec.clusterIP}')/32"
install_env=(BIN="$bin" TRUST_REPOSITORY="$trust_repository" REPO_URL="$REPO_URL" REVISION="$REVISION" KUBE_API_CIDRS="$api_cidrs")
env "${install_env[@]}" scripts/argocd/install.sh

# The spec of every object in a file, as the server would store it (a server dry-run applies the
# defaults the API fills in, legacySchema on a ConstraintTemplate among them), against the spec of the
# live object. What Argo CD adds to the metadata (its tracking annotation) is not a difference, so
# kubectl diff is not the comparison. jq -s takes both forms kubectl prints, one object or a List.
specs() { jq -S -s '[.[] | (if .kind == "List" then .items[] else . end) | {kind, namespace: .metadata.namespace, name: .metadata.name, spec}]'; }
same_spec() { # file [jq filter applied to both sides]
  local want have
  want=$(kubectl apply --dry-run=server -o json -f "$1" | specs | jq -S "${2:-.}")
  have=$(kubectl get -o json -f "$1" | specs | jq -S "${2:-.}")
  [ "$want" = "$have" ] || { diff <(echo "$want") <(echo "$have") || true; return 1; }
}
catalogue_is() { # dir: the catalogue in the cluster equals this directory, the zone's prefix aside
  local dir=$1 f
  for f in "$dir"/templates/ "$dir"/exemptions.yaml "$dir"/constraints/image-digest.yaml "$dir"/constraints/naming.yaml "$dir"/constraints/verified-images.yaml; do
    if same_spec "$f"; then pass "$f equal in the cluster"; else fail "$f differs in the cluster"; fi
  done
  # The one zone fact: equal once the prefix is taken out of both sides, and the live prefix is the zone's.
  if same_spec "$dir"/constraints/allowed-repositories.yaml 'del(.[].spec.parameters.repositories)' \
    && [ "$(kubectl get k8sztdallowedrepositories ztd-allowed-repositories -o jsonpath='{.spec.parameters.repositories}')" = "[\"$trust_repository\"]" ]; then
    pass "allowed-repositories carries the zone's prefix $trust_repository and nothing else differs"
  else
    fail "allowed-repositories does not carry the zone's prefix, or differs beyond it"
  fi
}

step "The catalogue in the cluster is the checkout"
catalogue_is deployment/admission

step "A hand-edited constraint is put back"
if scripts/argocd/drift-check.sh; then pass "drift check"; else fail "drift check"; fi

step "A hand-edited child Application is put back"
# The parent manages the children: a sync policy removed from one by hand comes back.
kubectl -n argocd patch application admission-templates --type json -p '[{"op":"remove","path":"/spec/syncPolicy/automated"}]' >/dev/null
restored=
for _ in $(seq 180); do
  if [ "$(kubectl -n argocd get application admission-templates -o jsonpath='{.spec.syncPolicy.automated.selfHeal}')" = "true" ]; then restored=1; break; fi
  sleep 1
done
if [ -n "$restored" ]; then pass "admission-templates sync policy put back by the parent"; else fail "admission-templates sync policy not put back within 180s"; fi

step "Policy package: publish the catalogue to the registry (release scripts, ephemeral keys, on the kind network)"
mkdir -p "$work/key" "$work/other-key" "$work/pkg"
(cd "$work/key" && COSIGN_PASSWORD= cosign generate-key-pair >/dev/null 2>&1)
(cd "$work/other-key" && COSIGN_PASSWORD= cosign generate-key-pair >/dev/null 2>&1)
scripts/supplychain/policy-package.sh deployment/admission "$work/pkg/a.tar.gz" >/dev/null
# A later release: the naming constraint admits one more prefix. Published with the trusted key.
cp -r deployment/admission "$work/release-b"
sed -i 's/\^ztd-/^(ztd|zone)-/' "$work/release-b/constraints/naming.yaml"
scripts/supplychain/policy-package.sh "$work/release-b" "$work/pkg/b.tar.gz" >/dev/null
# Tampered: the naming constraint opened to any name, published to the channel tag with another key.
cp -r deployment/admission "$work/tampered"
sed -i 's/\^ztd-/^any-/' "$work/tampered/constraints/naming.yaml"
scripts/supplychain/policy-package.sh "$work/tampered" "$work/pkg/t.tar.gz" >/dev/null
publish() { # package key-dir version created -> the digest on stdout, "failed" (and the log) otherwise
  if docker run --rm --network kind -v "$work:/w" -v "$bin:/tools:ro" -v "$root:/src:ro" \
    -e COSIGN_PASSWORD= -e PLAIN_HTTP=true -e CHANNEL=main -e ORAS=/tools/oras -e COSIGN=/tools/cosign \
    -e COSIGN_KEY="/w/$2/cosign.key" -e PUBLIC_KEY="/w/$2/cosign.pub" -e CREATED="$4" \
    "$toolbox" bash /src/scripts/supplychain/policy-publish.sh "/w/pkg/$1" "$reg/$policy_repo" "$3" e2e >"$work/publish.log" 2>&1; then
    tail -n1 "$work/publish.log" | sed 's/.*@//'
  else
    cat "$work/publish.log" >&2
    echo failed
  fi
}
digest_a=$(publish a.tar.gz key 0.0.0-a 2020-02-02T02:02:02Z)
case "$digest_a" in sha256:*) pass "release A published and signed: $digest_a" ;; *) fail "release A not published"; exit 1 ;; esac

step "Puller image"
docker build -q --platform linux/amd64 -f deployment/docker/policy-puller/Dockerfile -t "$host_reg/ztd/policy-puller:e2e" . >/dev/null
docker push -q "$host_reg/ztd/policy-puller:e2e" >/dev/null
puller_digest=$(curl -fsSI -H "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json" \
  "http://$host_reg/v2/ztd/policy-puller/manifests/e2e" | tr -d '\r' | awk 'tolower($1)=="docker-content-digest:"{print $2}')
echo "$reg/ztd/policy-puller@$puller_digest"

step "The zone re-installed to read the package (scripts/argocd/install.sh with POLICY_REPOSITORY)"
# The installer runs the puller once and proves every child reads oci://$reg/$policy_repo at the digest.
env "${install_env[@]}" POLICY_REPOSITORY="$reg/$policy_repo" PULLER_IMAGE="$reg/ztd/policy-puller@$puller_digest" \
  TRUST_KEY="$work/key/cosign.pub" PLAIN_HTTP_REGISTRY="$reg" scripts/argocd/install.sh
pinned() { kubectl -n argocd get application ztd-admission -o jsonpath='{.metadata.annotations.facis\.ztd/policy-digest}'; }
refused() { kubectl -n argocd get application ztd-admission -o jsonpath='{.metadata.annotations.facis\.ztd/policy-refused}'; }
if [ "$(pinned)" = "$digest_a" ]; then pass "the parent follows release A"; else fail "the parent follows '$(pinned)', not $digest_a"; fi
catalogue_is deployment/admission

# One run of the puller, now: 0 when it applied or confirmed a package, 1 when it refused or could not.
run_puller() {
  local job="ztd-policy-puller-e2e-$RANDOM" state
  kubectl -n argocd create job --from=cronjob/ztd-policy-puller "$job" >/dev/null
  for _ in $(seq 90); do
    state=$(kubectl -n argocd get job "$job" -o jsonpath='{.status.succeeded}/{.status.failed}')
    case "$state" in
      1/*) kubectl -n argocd logs "job/$job"; kubectl -n argocd delete job "$job" >/dev/null; return 0 ;;
      */1) kubectl -n argocd logs "job/$job"; kubectl -n argocd delete job "$job" >/dev/null; return 1 ;;
    esac
    sleep 2
  done
  echo "job $job did not finish"
  return 1
}
children_at() { # digest: every child reads the package at this digest, Synced and Healthy
  local app
  for app in admission-templates admission-exemptions admission-constraints; do
    for _ in $(seq 60); do
      [ "$(kubectl -n argocd get application "$app" -o jsonpath='{.spec.source.repoURL}@{.status.sync.revision} {.status.sync.status}/{.status.health.status}')" = "oci://$reg/$policy_repo@$1 Synced/Healthy" ] && break
      sleep 3
    done
    [ "$(kubectl -n argocd get application "$app" -o jsonpath='{.spec.source.repoURL}@{.status.sync.revision} {.status.sync.status}/{.status.health.status}')" = "oci://$reg/$policy_repo@$1 Synced/Healthy" ] || return 1
  done
}
naming_pattern() { kubectl get k8sztdnaming ztd-naming -o jsonpath='{.spec.parameters.pattern}'; }
pattern_a=$(naming_pattern)
pattern_b="${pattern_a/^ztd-/^(ztd|zone)-}"   # release B's, as the sed above made it

step "A tampered package at the channel tag is refused"
digest_t=$(publish t.tar.gz other-key 0.0.0-t 2020-04-04T04:04:04Z)
case "$digest_t" in sha256:*) ;; *) fail "the tampered package was not published"; exit 1 ;; esac
if run_puller; then fail "the puller accepted the tampered package"; else pass "the puller refused the tampered package"; fi
if [ "$(pinned)" = "$digest_a" ] && children_at "$digest_a"; then pass "the zone still reads release A"; else fail "the zone moved from release A: parent at '$(pinned)'"; fi
case "$(refused)" in *unsigned*) pass "the refusal is on the Application: $(refused)" ;; *) fail "no refusal recorded on the Application: '$(refused)'" ;; esac
if kubectl -n argocd get events --field-selector reason=PolicyPackageRefused -o name | grep -q .; then pass "a PolicyPackageRefused event was recorded"; else fail "no PolicyPackageRefused event"; fi
if [ "$(naming_pattern)" = "$pattern_a" ]; then pass "the naming constraint is unchanged"; else fail "the naming constraint changed to $(naming_pattern)"; fi

step "A release published with the trusted key reaches the cluster"
digest_b=$(publish b.tar.gz key 0.0.0-b 2020-03-03T03:03:03Z)
case "$digest_b" in sha256:*) ;; *) fail "release B was not published"; exit 1 ;; esac
if run_puller; then pass "the puller applied release B"; else fail "the puller did not apply release B"; fi
if [ "$(pinned)" = "$digest_b" ] && children_at "$digest_b"; then pass "every child reads release B"; else fail "the children do not read release B: parent at '$(pinned)'"; fi
if [ "$(naming_pattern)" = "$pattern_b" ]; then pass "the naming constraint in the cluster is release B's"; else fail "the naming constraint is $(naming_pattern), not release B's"; fi
[ -z "$(refused)" ] && pass "the refusal was cleared by the success" || fail "the refusal annotation is still '$(refused)'"
catalogue_is "$work/release-b"

step "The channel tag moved back to the older release is refused as a rollback"
oras tag --plain-http "$host_reg/$policy_repo@$digest_a" main >/dev/null
if run_puller; then fail "the puller accepted the rollback"; else pass "the puller refused the rollback"; fi
case "$(refused)" in *rollback*) pass "the refusal names the rollback" ;; *) fail "the refusal is '$(refused)', not a rollback" ;; esac
if [ "$(pinned)" = "$digest_b" ] && children_at "$digest_b"; then pass "the zone still reads release B"; else fail "the zone moved from release B"; fi

step "A registry that cannot be reached changes nothing"
docker stop "$reg_name" >/dev/null
if run_puller; then fail "the puller succeeded without a registry"; else pass "the puller reported the registry unavailable"; fi
docker start "$reg_name" >/dev/null
case "$(refused)" in *registry*) pass "the unavailability is on the Application: $(refused)" ;; *) fail "the unavailability is not recorded: '$(refused)'" ;; esac
if [ "$(pinned)" = "$digest_b" ] && [ "$(naming_pattern)" = "$pattern_b" ]; then pass "the zone still holds release B"; else fail "the zone changed without a registry"; fi

step "The zone sent back to Git (scripts/argocd/install.sh without POLICY_REPOSITORY)"
# The installer without the package: the puller, the repository and its lane go, the parent is
# re-applied without package values, and the run finishes only once every child reads Git again. The
# cluster then holds the checkout's catalogue: release B's naming pattern went with the package.
env "${install_env[@]}" scripts/argocd/install.sh
if helm status policy-puller -n argocd >/dev/null 2>&1; then fail "the puller release is still installed"; else pass "the puller release is gone"; fi
left=$(kubectl -n argocd get cronjob/ztd-policy-puller secret/ztd-policy-package networkpolicy/allow-policy-registry-egress --ignore-not-found -o name 2>/dev/null)
if [ -z "$left" ]; then pass "the CronJob, the repository Secret and the registry lane are gone"; else fail "left behind by the re-install: $(echo "$left" | paste -sd' ')"; fi
if [ -z "$(kubectl -n argocd get application ztd-admission -o jsonpath='{.spec.source.helm.valuesObject.package}')" ]; then pass "the parent carries no package values"; else fail "the parent still carries package values"; fi
# A child on Git: the repository URL the zone was installed with, synced at a commit, not a digest.
for app in admission-templates admission-exemptions admission-constraints; do
  source=$(kubectl -n argocd get application "$app" -o jsonpath='{.spec.source.repoURL}@{.status.sync.revision} {.status.sync.status}/{.status.health.status}')
  if [[ $source =~ ^"$REPO_URL"@[0-9a-f]{40}" Synced/Healthy"$ ]]; then pass "$app reads Git again: $source"; else fail "$app does not read Git: $source"; fi
done
if [ "$(naming_pattern)" = "$pattern_a" ]; then pass "the naming constraint is the checkout's again: release B went with the package"; else fail "the naming constraint is $(naming_pattern), not the checkout's"; fi
catalogue_is deployment/admission

echo
if [ "$failures" -ne 0 ]; then echo "$failures check(s) failed"; exit 1; fi
echo "every check passed"
