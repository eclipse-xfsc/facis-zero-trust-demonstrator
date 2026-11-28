# shellcheck shell=bash
# Sourced, never run: the admission checks shared by scripts/admission/install.sh (the standalone
# layout: releases gatekeeper, admission and admission-pool) and scripts/install-zone/install.sh (the
# umbrella layout: one release gatekeeper of deployment/helm/ztd), and the layout helpers the fault
# and end-to-end scripts use to change the provider in whichever layout is installed. kubectl and
# helm talk to the current context.

admission_ns=gatekeeper-system
admission_constraints="k8sztdimagedigest/ztd-image-digest k8sztdallowedrepositories/ztd-allowed-repositories k8sztdnaming/ztd-naming k8sztdverifiedimages/ztd-verified-images"

# The webhooks not scoped to facis.ztd/admission-proof=true, one per line; empty when both are.
admission_unscoped() {
  kubectl get validatingwebhookconfiguration gatekeeper-validating-webhook-configuration -o json | jq -r '
    .webhooks[] | select(any(.namespaceSelector.matchExpressions[]?; .key == "facis.ztd/admission-proof" and .operator == "In" and .values == ["true"]) | not) | .name'
}

# Gatekeeper's external-data response cache setting, "response-cache-ttl=0s" when it is off.
admission_cache_ttl() {
  kubectl -n "$admission_ns" get deploy gatekeeper-controller-manager -o jsonpath='{.spec.template.spec.containers[0].args}' |
    tr ',' '\n' | grep -o 'response-cache-ttl=[^"]*' || true
}

# admission_enforced <kind/name>: the constraint is acknowledged, current and error-free by every
# Ready webhook replica (scripts/admission/enforced.sh), once - no waiting.
admission_enforced() {
  local dir status=0
  dir=$(mktemp -d)
  kubectl get "$1" -o json >"$dir/constraint.json" 2>/dev/null &&
    kubectl -n "$admission_ns" get pods -l control-plane=controller-manager -o json >"$dir/pods.json" &&
    "$(dirname "${BASH_SOURCE[0]}")/enforced.sh" "$dir/constraint.json" "$dir/pods.json" || status=1
  rm -rf "$dir"
  return "$status"
}

# admission_wait_enforced: every constraint enforced by every Ready webhook replica, within 3 minutes.
admission_wait_enforced() {
  local c ok
  for c in $admission_constraints; do
    ok=
    for _ in $(seq 90); do admission_enforced "$c" && { ok=1; break; }; sleep 2; done
    [ -n "$ok" ] || { echo "constraint $c is not enforced by every Ready webhook replica" >&2; return 1; }
  done
}

# The layout installed: umbrella (release gatekeeper is deployment/helm/ztd), standalone (release
# gatekeeper is the Gatekeeper chart, or release admission or admission-pool exists) or none.
admission_layout() {
  local chart
  chart=$(helm list -n "$admission_ns" -o json 2>/dev/null | jq -r '.[] | select(.name == "gatekeeper") | .chart')
  case "$chart" in
    ztd-*) echo umbrella ;;
    gatekeeper-*) echo standalone ;;
    *) if admission_standalone_releases | grep -q .; then echo standalone; else echo none; fi ;;
  esac
}

# The releases of the standalone layout that exist, one per line (gatekeeper only when it is the
# Gatekeeper chart).
admission_standalone_releases() {
  helm list -n "$admission_ns" -o json 2>/dev/null | jq -r '.[]
    | select(.name == "admission" or .name == "admission-pool" or (.name == "gatekeeper" and (.chart | startswith("gatekeeper-")))) | .name'
}

# admission_forget <release...>: drop the Helm records of releases whose objects another release has
# adopted (helm --take-ownership), leaving the objects; `helm uninstall` would delete them.
admission_forget() {
  local r
  for r in "$@"; do kubectl -n "$admission_ns" delete secret -l "owner=helm,name=$r" >/dev/null; done
}

# admission_helm_home: install the ztd-webhook-scope post-renderer plugin into a Helm data directory
# of this run (path in $1, removed by the caller) and point Helm at it.
admission_helm_home() {
  export HELM_DATA_HOME="$1" HELM_PLUGINS="$1/plugins"
  helm plugin install "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/deployment/admission/webhook-scope" >/dev/null
}

# admission_allowed_json <list>: the digest allow-list - entries separated by any whitespace (spaces,
# tabs, newlines) - as a JSON array, each entry checked to be host/repository@sha256:<digest>; the
# array printed is the one checked. Fails, naming the entry, on anything else.
admission_allowed_json() {
  local entries=() d
  read -r -d '' -a entries <<<"${1:-}" || true
  for d in ${entries[@]+"${entries[@]}"}; do
    [[ "$d" =~ ^[a-z0-9.:-]+/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$ ]] ||
      { echo "ALLOWED_DIGESTS entry '$d' is not host/repository@sha256:<digest>" >&2; return 1; }
  done
  printf '%s\n' ${entries[@]+"${entries[@]}"} | jq -Rsc 'split("\n") | map(select(. != ""))'
}

# admission_installed_provider: the provider's settings as installed, read from its live objects in
# either layout (and halfway through a rollback): image, replicas, request timeout, the plain-http
# registry, registryAuth.secretName and the whole trust policy (repositories, publicKeys,
# allowedDigests), as deployment/helm/admission values in JSON. Fails when the provider is not there.
admission_installed_provider() {
  local deploy policy
  deploy=$(kubectl -n "$admission_ns" get deploy ztd-admission-provider -o json) || return 1
  policy=$(kubectl -n "$admission_ns" get configmap ztd-admission-provider-trust -o jsonpath='{.data.policy\.json}') || return 1
  jq -en --argjson d "$deploy" --argjson p "$policy" '
    $d.spec.template.spec.containers[0] as $c
    | def arg($name): [$c.args[]? | select(startswith("--" + $name + "=")) | sub("^[^=]*="; "")][0];
    {replicas: $d.spec.replicas,
     image: {repository: ($c.image | split("@")[0]), digest: ($c.image | split("@")[1])},
     requestTimeout: (arg("request-timeout") // "1s"),
     insecurePlainHTTPRegistry: (arg("insecure-plain-http-registry") // ""),
     registryAuth: {secretName: ([$d.spec.template.spec.volumes[]? | select(.name == "registry-auth") | .secret.secretName][0] // "")},
     trust: {repositories: $p.repositories, publicKeys: $p.publicKeys, allowedDigests: ($p.allowedDigests // [])}}
    | select(.image.digest != null and (.trust.repositories | length) > 0)'
}

# admission_umbrella_upgrade <helm args...>: upgrade the umbrella layout's release in place, keeping
# every value it has (--reuse-values) apart from the ones given. Needs the webhook-scope plugin
# (admission_helm_home).
admission_umbrella_upgrade() {
  helm upgrade gatekeeper "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/deployment/helm/ztd" -n "$admission_ns" \
    --reuse-values --post-renderer ztd-webhook-scope "$@"
}

# admission_provider_upgrade <helm args...>: change the provider's values in place in either layout,
# keeping every other value (--reuse-values). The --set* args name the provider's own values
# (replicas, trust.publicKeys, ...); they are prefixed admissionProvider. for the umbrella, where
# Gatekeeper's live replica count is passed too, so that changing the provider never scales
# Gatekeeper (as in the standalone layout, where the provider is a release of its own).
admission_provider_upgrade() {
  local args=() replicas
  if [ "$(admission_layout)" = umbrella ]; then
    replicas=$(kubectl -n "$admission_ns" get deploy gatekeeper-controller-manager -o jsonpath='{.spec.replicas}')
    args+=(--set "gatekeeper.replicas=$replicas")
    while [ $# -gt 0 ]; do
      case "$1" in
        --set|--set-file|--set-json|--set-string) args+=("$1" "admissionProvider.$2"); shift 2 ;;
        *) args+=("$1"); shift ;;
      esac
    done
    admission_umbrella_upgrade ${args[@]+"${args[@]}"}
  else
    helm upgrade admission "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/deployment/helm/admission" -n "$admission_ns" \
      --reuse-values "$@"
  fi
}
