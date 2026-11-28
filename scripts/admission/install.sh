#!/usr/bin/env bash
# Install admission control on the current kube context, in the reviewed order: Gatekeeper (pinned
# chart, gatekeeper-values.yaml, the webhook-scope post-renderer, every image pinned by digest), the
# image-verification provider, the constraint templates, the exemptions, the constraints, then the
# admission pool (namespaces and tester identity). Re-running it upgrades in place. It stops at the
# first check that fails: an unpinned image, a webhook not scoped to the admission label, a Gatekeeper
# response cache that is on, or a constraint not enforced.
#
#   BIN=<dir holding the Gatekeeper chart archive> PROVIDER_IMAGE=<repository@sha256:...> \
#   TRUST_REPOSITORY=<host/path> TRUST_KEY=<cosign public key file> \
#   [GATEKEEPER_REPLICAS=2] [PROVIDER_REPLICAS=2] [PLAIN_HTTP_REGISTRY=host:port] \
#   [ALLOWED_DIGESTS="host/repository@sha256:<digest> ..."] [REGISTRY_AUTH_SECRET=<dockerconfigjson Secret>] \
#   scripts/admission/install.sh
#
#   BIN=... RESTORE=1 [RESTORE_FROM=<file>] [GATEKEEPER_REPLICAS=n] [PROVIDER_REPLICAS=n] [PREFLIGHT=1] scripts/admission/install.sh
#
# PREFLIGHT=1 checks that the install could run and changes nothing: the inputs, the Gatekeeper
# archive against GATEKEEPER_CHART_SHA256 (scripts/tools/pins.env, checked on every run), and a
# server-side dry run of the Gatekeeper release (with the webhook-scope post-renderer) and of the
# provider release; the fault cases run it before they inject anything.
#
# RESTORE_FROM is a snapshot that admission_installed_provider wrote earlier (the fault cases take one
# before they change anything); without it the settings are read when this runs.
# RESTORE=1 re-installs with the provider settings as installed (admission_installed_provider: image,
# replicas, trust keys, repositories, allowedDigests, registryAuth.secretName, plain-http registry),
# never with values given here: the fault cases' restore and the rollback below use it. PROVIDER_IMAGE,
# TRUST_REPOSITORY, TRUST_KEY, ALLOWED_DIGESTS, REGISTRY_AUTH_SECRET and PLAIN_HTTP_REGISTRY are then
# not read. REGISTRY_AUTH_SECRET names the provider's registry read credentials (registryAuth.secretName).
#
# ALLOWED_DIGESTS (space-separated, default none) are third-party images admitted by exact digest
# reference, such as the injected Istio proxy; the one list goes to both the provider's
# trust.allowedDigests and the ztd-allowed-repositories constraint's allowedDigests.
#
# The standalone layout. A zone whose zone file sets admission.install has the umbrella layout
# instead - one release gatekeeper of deployment/helm/ztd, installed by scripts/install-zone/install.sh -
# and this script refuses it, except as the rollback to this layout (docs/umbrella-chart.md, "Admission
# in the umbrella"): FROM_UMBRELLA=1 (which implies RESTORE=1) drops the umbrella release's records,
# leaving every object in place, and adopts the objects into the three releases here (helm
# --take-ownership) with the provider settings the umbrella release had installed.
#
# Break-glass: delete the ValidatingWebhookConfiguration gatekeeper-validating-webhook-configuration,
# then helm uninstall gatekeeper -n gatekeeper-system.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env
# shellcheck source=scripts/admission/checks.sh
. scripts/admission/checks.sh
: "${BIN:?set BIN}"
chart="$BIN/gatekeeper-$GATEKEEPER_CHART_VERSION.tgz"
[ -f "$chart" ] || { echo "Gatekeeper chart not found: $chart" >&2; exit 2; }
chart_sha=$(if command -v sha256sum >/dev/null; then sha256sum "$chart"; else shasum -a 256 "$chart"; fi | cut -d' ' -f1)
[ "$chart_sha" = "$GATEKEEPER_CHART_SHA256" ] ||
  { echo "Gatekeeper chart $chart: digest $chart_sha is not the pinned $GATEKEEPER_CHART_SHA256" >&2; exit 2; }
[ "${FROM_UMBRELLA:-}" != 1 ] || RESTORE=1
# The provider's values, as a values file: as installed (RESTORE=1), or from the inputs.
values_dir="$(mktemp -d)"
trap 'rm -rf "$values_dir"' EXIT
provider_file="$values_dir/provider.json"
if [ "${RESTORE:-}" = 1 ] && [ -n "${RESTORE_FROM:-}" ]; then
  jq -e '.image.digest and (.trust.repositories | length > 0)' "$RESTORE_FROM" >/dev/null 2>&1 ||
    { echo "RESTORE_FROM $RESTORE_FROM is not a provider snapshot" >&2; exit 2; }
  jq --argjson n "${PROVIDER_REPLICAS:-null}" 'if $n then .replicas = $n else . end' "$RESTORE_FROM" > "$provider_file"
elif [ "${RESTORE:-}" = 1 ]; then
  admission_installed_provider > "$provider_file" ||
    { echo "RESTORE: no installed provider to take the settings from (deployment and trust policy in gatekeeper-system)" >&2; exit 2; }
  [ -z "${PROVIDER_REPLICAS:-}" ] || jq --argjson n "$PROVIDER_REPLICAS" '.replicas = $n' "$provider_file" > "$provider_file.new"
  [ ! -f "$provider_file.new" ] || mv "$provider_file.new" "$provider_file"
else
  : "${PROVIDER_IMAGE:?set PROVIDER_IMAGE}" "${TRUST_REPOSITORY:?set TRUST_REPOSITORY}" "${TRUST_KEY:?set TRUST_KEY}"
  case "$PROVIDER_IMAGE" in *@sha256:*) ;; *) echo "PROVIDER_IMAGE must be a digest reference" >&2; exit 2 ;; esac
  grep -qs "BEGIN PUBLIC KEY" "$TRUST_KEY" || { echo "TRUST_KEY is not a PEM public key file: $TRUST_KEY" >&2; exit 2; }
  allowed_json=$(admission_allowed_json "${ALLOWED_DIGESTS:-}") || exit 2
  jq -n --arg image "$PROVIDER_IMAGE" --argjson replicas "${PROVIDER_REPLICAS:-2}" --arg repository "$TRUST_REPOSITORY" \
    --rawfile keys "$TRUST_KEY" --argjson allowed "$allowed_json" --arg plain "${PLAIN_HTTP_REGISTRY:-}" \
    --arg auth "${REGISTRY_AUTH_SECRET:-}" '
    {replicas: $replicas, image: {repository: ($image | split("@")[0]), digest: ($image | split("@")[1])},
     insecurePlainHTTPRegistry: $plain, registryAuth: {secretName: $auth},
     trust: {repositories: [$repository], publicKeys: $keys, allowedDigests: $allowed}}' > "$provider_file"
fi

# The webhook-scope post-renderer is a Helm plugin; it lives in this run's own Helm directory.
helm_home="$values_dir/helm"
admission_helm_home "$helm_home"
gatekeeper_values=(-f deployment/admission/gatekeeper-values.yaml --set replicas="${GATEKEEPER_REPLICAS:-2}"
  --set image.release="${GATEKEEPER_IMAGE#*:}"
  --set preInstall.crdRepository.image.repository="${GATEKEEPER_CRDS_IMAGE%%:*}"
  --set preInstall.crdRepository.image.tag="${GATEKEEPER_CRDS_IMAGE#*:}"
  --set postInstall.labelNamespace.image.tag="${GATEKEEPER_CRDS_IMAGE#*:}"
  --set postUpgrade.labelNamespace.image.tag="${GATEKEEPER_CRDS_IMAGE#*:}"
  --set postInstall.probeWebhook.enabled=false --post-renderer ztd-webhook-scope)

if [ "${PREFLIGHT:-}" = 1 ]; then
  helm upgrade --install gatekeeper "$chart" -n gatekeeper-system "${gatekeeper_values[@]}" --dry-run=server >/dev/null
  helm upgrade --install admission deployment/helm/admission -n gatekeeper-system -f "$provider_file" --dry-run=server >/dev/null
  echo "preflight: the Gatekeeper archive is the pinned one; Gatekeeper and the provider dry-run on the server"
  exit 0
fi

# The rollback is resumable: with FROM_UMBRELLA=1 every release here adopts (--take-ownership) on
# every run, so a run interrupted after Gatekeeper but before the provider or the pool is re-run as
# it is; the umbrella's records are dropped only while release gatekeeper is still the umbrella's,
# and only once the inputs are checked.
adopt=()
if [ "${FROM_UMBRELLA:-}" = 1 ]; then
  adopt=(--take-ownership)
  if [ "$(admission_layout)" = umbrella ]; then
    echo "== Rollback from the umbrella layout: dropping release gatekeeper's records, keeping its objects"
    admission_forget gatekeeper
  fi
elif [ "$(admission_layout)" = umbrella ]; then
  echo "the admission stack is release gatekeeper of the umbrella chart (scripts/install-zone/install.sh); FROM_UMBRELLA=1 rolls it back to this layout" >&2
  exit 1
fi

echo "== Gatekeeper"
unpinned=$(helm template gatekeeper "$chart" -n gatekeeper-system "${gatekeeper_values[@]}" | grep -E '^\s*image:' | grep -v '@sha256:' || true)
[ -z "$unpinned" ] || { echo "Gatekeeper images not pinned by digest:" >&2; echo "$unpinned" >&2; exit 1; }
helm upgrade --install gatekeeper "$chart" -n gatekeeper-system --create-namespace "${gatekeeper_values[@]}" ${adopt[@]+"${adopt[@]}"} --wait --timeout 8m >/dev/null
# Both webhooks must select only the admission namespaces.
unscoped=$(admission_unscoped)
[ -z "$unscoped" ] || { echo "webhooks not scoped to facis.ztd/admission-proof=true: $unscoped" >&2; exit 1; }
ttl=$(admission_cache_ttl)
[ "$ttl" = "response-cache-ttl=0s" ] || { echo "Gatekeeper response cache is not off: '$ttl'" >&2; exit 1; }
echo "webhooks scoped to facis.ztd/admission-proof=true; $ttl"

echo "== Provider"
helm upgrade --install admission deployment/helm/admission -n gatekeeper-system -f "$provider_file" ${adopt[@]+"${adopt[@]}"} --wait --timeout 5m >/dev/null

echo "== Policy"
kubectl apply -f deployment/admission/templates/ >/dev/null
for kind in k8sztdimagedigest k8sztdallowedrepositories k8sztdnaming k8sztdverifiedimages; do
  for _ in $(seq 60); do kubectl get crd "$kind.constraints.gatekeeper.sh" >/dev/null 2>&1 && break; sleep 2; done
  kubectl wait --for=condition=established --timeout=120s "crd/$kind.constraints.gatekeeper.sh" >/dev/null
done
kubectl apply -f deployment/admission/exemptions.yaml >/dev/null
# The provider's repositories and allow-list, so the two never disagree; the allow-list only when set,
# as in the umbrella (a constraint template that predates it has no allowedDigests in its schema).
kubectl create --dry-run=client -o json -f deployment/admission/constraints/allowed-repositories.yaml |
  jq --slurpfile p "$provider_file" '.spec.parameters.repositories = $p[0].trust.repositories
    | if ($p[0].trust.allowedDigests | length) > 0 then .spec.parameters.allowedDigests = $p[0].trust.allowedDigests
      else del(.spec.parameters.allowedDigests) end' | kubectl apply -f - >/dev/null
for c in image-digest naming verified-images; do kubectl apply -f "deployment/admission/constraints/$c.yaml" >/dev/null; done
# Each constraint must be acknowledged, current and error-free, by every Ready webhook replica.
admission_wait_enforced
echo "constraints enforced by every webhook replica"

echo "== Admission pool"
helm upgrade --install admission-pool deployment/helm/admission-pool -n gatekeeper-system ${adopt[@]+"${adopt[@]}"} --wait >/dev/null
kubectl get namespaces -l facis.ztd/admission-proof=true -o name
