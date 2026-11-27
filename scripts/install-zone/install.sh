#!/usr/bin/env bash
# Install one zone of the demonstrator from an empty cluster (with its CNI) as seven Helm releases,
# in this order, each through the deployment lifecycle step (scripts/lifecycle.sh: server-side dry
# run, then helm upgrade --install --wait with rollback on failure), each waiting on the previous:
#
#   1 ztd          ztd-system    the umbrella: plane namespaces (with spire-system and istio-system),
#                                default deny, declared openings, allow matrix
#   2 spire-crds   spire-system  the SPIRE controller-manager's CRDs        (upstream, pinned)
#   3 spire        spire-system  server, agents, CSI driver, controller-manager (upstream, pinned)
#   4 istio-base   istio-system  Istio's CRDs                                (upstream, pinned)
#   5 istiod       istio-system  the mesh control plane, sidecar mode, SPIRE as certificate source
#   6 istio-cni    istio-system  the Istio CNI plugin, chained behind the cluster's CNI
#   7 zone-policy  istio-system  ClusterSPIFFEID, STRICT PeerAuthentication, identity-band checks
#   8 gatekeeper   gatekeeper-system  only when the zone file sets admission.install: the admission
#                                release of the umbrella chart - Gatekeeper, the image-verification
#                                provider, the admission policy and the admission pool
#
# The admission release is the umbrella chart installed a second time, into Gatekeeper's namespace,
# with Gatekeeper's values (deployment/admission/gatekeeper-values.yaml), its image pins
# (scripts/tools/pins.env) and the ztd-webhook-scope post-renderer, which limits both Gatekeeper
# webhooks to the namespaces labelled facis.ztd/admission-proof=true. On a first install it goes in
# four stages, each a deploy of the same release waiting on the one before: Gatekeeper; the provider,
# the constraint templates and the exemptions; the constraints, once Gatekeeper has generated their
# CRDs; the admission pool, once every Ready webhook replica enforces every constraint. A stage whose
# successor's condition already holds is skipped, so an upgrade is one deploy. Admission objects that
# scripts/admission/install.sh installed (releases gatekeeper, admission, admission-pool) are adopted
# only with ADMISSION_ADOPT=1 (helm --take-ownership, docs/umbrella-chart.md); the records of the old
# releases are dropped afterwards, their objects kept.
#
# Usage:
#   scripts/install-zone/install.sh install [release...]
#                                                    install or upgrade the zone, or only the named
#                                                    releases (idempotent)
#   scripts/install-zone/install.sh plan             list the steps; touches no cluster
#   scripts/install-zone/install.sh render [release...]
#                                                    render the releases from the pinned charts and
#                                                    the merged values; touches no cluster (CI);
#                                                    an unknown release name is an error
#   scripts/install-zone/install.sh uninstall        uninstall in reverse order
#   scripts/install-zone/install.sh help             this text (also -h, --help)
#
# Environment:
#   ZONE_VALUES   zone file             (default: deployment/helm/ztd/ci/values.yaml, the kind zone)
#   KUBE_CONTEXT  kubectl context       (default: kind-ztd)
#   STEP_TIMEOUT  timeout per release   (default: 10m)
#   RENDER_DIR    with `render`, write each release's manifest there as <release>.yaml, and the
#                 values it was rendered with as <release>.values.yaml
#   INSTALL_ZONE_CACHE  where the pinned charts are kept (default: ~/.cache/ztd-install-zone)
#   ADMISSION_ADOPT=1   let the admission release adopt the objects of scripts/admission/install.sh
#
# Mesh settings: the installer installs sidecar mode with the default, unrevisioned istiod (and the
# Istio CNI plugin with ambient off). It refuses, before it renders or installs anything, a zone
# file whose mesh.mode is anything but sidecar (absent counts as sidecar) or whose mesh.revision is
# set: the umbrella would label the plane namespaces for an injector this installer never installs.
# It also refuses, before it renders istiod or zone-policy, a zone-policy whose
# proxySocketPolicy.proxyImage or statusPort differs from istiod's global.proxy.image or statusPort:
# the admission policy would refuse every injected plane pod.
#
# The umbrella reads the whole zone file. The other releases read their upstream values file under
# deployment/helm/values/ (zone-policy: its chart defaults) merged with the zone facts they need;
# a missing zone fact stops the run before anything is rendered. Every namespace the releases
# install into is created by the umbrella; the one namespace this script creates is the umbrella's
# own release namespace, which holds only the release record and its verification job, and
# gatekeeper-system, the admission release's (Gatekeeper's own namespace). The umbrella's
# dependencies are taken from deployment/helm/ztd/charts: run `helm dependency build
# deployment/helm/ztd` after a change to deployment/helm/admission or admission-pool. Needs
# helm, kubectl, jq, curl, python3 with PyYAML, and sha256sum or shasum.
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ZONE_VALUES=${ZONE_VALUES:-$REPO/deployment/helm/ztd/ci/values.yaml}
KUBE_CONTEXT=${KUBE_CONTEXT:-kind-ztd}
STEP_TIMEOUT=${STEP_TIMEOUT:-10m}
CACHE=${INSTALL_ZONE_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/ztd-install-zone}
VALUES_DIR=$REPO/deployment/helm/values
# shellcheck source=scripts/tools/pins.env disable=SC1091
. "$REPO/scripts/tools/pins.env"
# shellcheck source=scripts/admission/checks.sh
. "$REPO/scripts/admission/checks.sh"

# ---- Pins (docs/dependencies.md). An upgrade changes a version and its digest here, then reruns
# ---- scripts/verify-mesh-identity/verify.sh; every Istio minor also reruns the ADR-0009 check.
SPIRE_REPO=https://spiffe.github.io/helm-charts-hardened/
SPIRE_CRDS_VERSION=0.6.1
SPIRE_CRDS_SHA256=ce982e63fc375e392b014fc99e621a55442ab886052413e9bb052f72d66580a8
SPIRE_VERSION=0.30.2   # SPIRE v1.15.3
SPIRE_SHA256=aadaeabe1dfecbcd803d541580ab41c229d99c0075ace3b6e050b0ceef36aa8d
# Istio 1.31 charts are not in Istio's Helm repository (its index stops at 1.31.0-rc.0, last
# modified 2026-09-21) nor in its OCI registry; they ship in the release archive, under
# manifests/charts, which is pinned by its published sha256.
ISTIO_VERSION=1.31.1
ISTIO_ARCHIVE_URL=https://github.com/istio/istio/releases/download/$ISTIO_VERSION/istio-$ISTIO_VERSION-linux-amd64.tar.gz
ISTIO_ARCHIVE_SHA256=cb4af2e8a099acfc51368c1d15d4deab8321ae628554d4ee5c74f62ebe775857

# ---- The steps: release, namespace, chart, values file, zone facts (<values key>=<zone key>,...),
# ---- extra lifecycle settings. "zone" as values file means the zone file itself.
STEPS=(
  "ztd|ztd-system|umbrella|zone||"
  "spire-crds|spire-system|spire-crds|$VALUES_DIR/spire-crds.yaml||"
  "spire|spire-system|spire|$VALUES_DIR/spire.yaml|global.spire.trustDomain=zone.trustDomain,global.spire.clusterName=zone.name,global.spire.persistence.storageClass=zone.storageClass,global.spire.caSubject.commonName=zone.trustDomain|"
  "istio-base|istio-system|istio-base|$VALUES_DIR/istio-base.yaml||"
  "istiod|istio-system|istiod|$VALUES_DIR/istiod.yaml|meshConfig.trustDomain=zone.trustDomain|"
  "istio-cni|istio-system|istio-cni|$VALUES_DIR/istio-cni.yaml||"
  "zone-policy|istio-system|zone-policy||trustDomain=zone.trustDomain|wait-for-jobs"
)
# The admission release, when the zone file opts in; "admission" as values file means the zone file
# with Gatekeeper's values and the stage settings (merged_values).
if [ -f "$ZONE_VALUES" ] && command -v python3 >/dev/null &&
  [ "$(python3 -c 'import sys, yaml; z = yaml.safe_load(open(sys.argv[1])) or {}; print((z.get("admission") or {}).get("install") is True)' "$ZONE_VALUES" 2>/dev/null)" = True ]; then
  STEPS+=("gatekeeper|$admission_ns|umbrella|admission||")
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

say() { printf '%s\n' "$*"; }
die() { printf 'install-zone: %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,/^# the admission policy would refuse every injected plane pod/p' "$0" | sed 's/^# \{0,1\}//'; }

# zone_file: the zone file must exist before anything reads it.
zone_file() { [ -f "$ZONE_VALUES" ] || die "zone file not found: $ZONE_VALUES"; }

# zone_mesh: the zone file's mesh settings must be the ones this installer installs, sidecar mode
# with the default, unrevisioned istiod; anything else is refused before anything is rendered or
# installed. Read with PyYAML, as merged_values reads the zone facts.
# With "admission-only" (the run installs or renders release gatekeeper alone, which labels no plane
# namespace) only the admission switches are checked, so a zone without a mesh, such as IONOS, can
# take the admission release.
zone_mesh() {
  python3 - "$ZONE_VALUES" "${1:-}" <<'PY' || exit 1
import sys, yaml
zone_file, scope_only = sys.argv[1], sys.argv[2] == "admission-only"
zone = yaml.safe_load(open(zone_file)) or {}
mesh = zone.get("mesh") if isinstance(zone, dict) else None
mesh = mesh if isinstance(mesh, dict) else {}
mode = mesh.get("mode")
revision = mesh.get("revision")
scope = "this installer installs the default, unrevisioned istiod in sidecar mode only"
if not scope_only and mode is not None and str(mode) != "sidecar":
    sys.exit(f'install-zone: the zone file sets mesh.mode "{mode}", but {scope}; '
             'another mesh mode needs its own installer support (a zone without a mesh installs '
             'the umbrella alone through scripts/lifecycle.sh)')
if not scope_only and revision is not None and str(revision).strip() != "":
    sys.exit(f'install-zone: the zone file sets mesh.revision "{revision}", but {scope}; '
             'a revisioned mesh needs its own installer support')
# The switches of the admission release are the installer's: a zone file that set them would render
# the admission stack into release ztd, or skip a stage.
owned = [f"{k}.{f}" for k, f in [("gatekeeper", "enabled"), ("admissionProvider", "enabled"),
         ("admissionPool", "enabled"), ("admissionPolicy", "templates"), ("admissionPolicy", "constraints")]
         if isinstance(zone, dict) and isinstance(zone.get(k), dict) and f in zone[k]]
if owned:
    sys.exit(f'install-zone: the zone file sets {", ".join(owned)}, which the installer sets for the '
             'admission release; set admission.install instead')
PY
}

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

# MESH_SCOPE: "admission-only" while a run renders or installs release gatekeeper alone (zone_mesh).
MESH_SCOPE=
plan() {
  zone_file
  zone_mesh "$MESH_SCOPE"
  say "Zone file: ${ZONE_VALUES#"$REPO"/}   context: $KUBE_CONTEXT"
  local i=0 step release ns chart values facts extra label
  for step in "${STEPS[@]}"; do
    IFS='|' read -r release ns chart values facts extra <<<"$step"
    i=$((i + 1))
    if [ "$values" = zone ]; then label="the zone file"
    elif [ "$values" = admission ]; then label="the zone file + deployment/admission/gatekeeper-values.yaml, staged"
    elif [ -n "$values" ]; then label=${values#"$REPO"/}
    else label="chart defaults"; fi
    printf '  %d/%d  %-12s into %-13s chart %-12s values %s%s%s\n' "$i" "${#STEPS[@]}" "$release" "$ns" \
      "$(chart_label "$chart")" "$label" "${facts:+ + zone facts ${facts//,/ }}" "${extra:+ ($extra)}"
  done
}

chart_label() {
  case $1 in
    umbrella) echo "deployment/helm/ztd" ;;
    zone-policy) echo "deployment/helm/zone-policy" ;;
    spire-crds) echo "spire-crds $SPIRE_CRDS_VERSION" ;;
    spire) echo "spire $SPIRE_VERSION" ;;
    istio-base) echo "base $ISTIO_VERSION" ;;
    istiod) echo "istiod $ISTIO_VERSION" ;;
    istio-cni) echo "cni $ISTIO_VERSION" ;;
  esac
}

# fetch <url-or-repo-chart> ...: the pinned charts into the cache, verified by digest.
fetch_spire_chart() { # fetch_spire_chart <chart> <version> <sha256>
  local file="$CACHE/$1-$2.tgz"
  if [ ! -f "$file" ] || [ "$(sha256 "$file")" != "$3" ]; then
    mkdir -p "$CACHE"
    helm pull "$1" --repo "$SPIRE_REPO" --version "$2" --destination "$work" >/dev/null \
      || die "could not fetch chart $1 $2 from $SPIRE_REPO"
    mv "$work/$1-$2.tgz" "$file"
  fi
  [ "$(sha256 "$file")" = "$3" ] || die "chart $1 $2: digest $(sha256 "$file") is not the pinned $3"
  echo "$file"
}

fetch_istio() {
  local dir="$CACHE/istio-$ISTIO_VERSION" archive="$CACHE/istio-$ISTIO_VERSION-linux-amd64.tar.gz"
  if [ ! -f "$dir/.verified" ]; then
    mkdir -p "$CACHE"
    if [ ! -f "$archive" ] || [ "$(sha256 "$archive")" != "$ISTIO_ARCHIVE_SHA256" ]; then
      curl -fsSL -o "$archive" "$ISTIO_ARCHIVE_URL" || die "could not fetch $ISTIO_ARCHIVE_URL"
    fi
    [ "$(sha256 "$archive")" = "$ISTIO_ARCHIVE_SHA256" ] \
      || die "Istio archive: digest $(sha256 "$archive") is not the pinned $ISTIO_ARCHIVE_SHA256"
    rm -rf "$dir"; mkdir -p "$dir"
    tar -xzf "$archive" -C "$dir" --strip-components=3 "istio-$ISTIO_VERSION/manifests/charts"
    touch "$dir/.verified"
  fi
  echo "$dir"
}

chart_path() {
  case $1 in
    umbrella) echo "$REPO/deployment/helm/ztd" ;;
    zone-policy) echo "$REPO/deployment/helm/zone-policy" ;;
    spire-crds) fetch_spire_chart spire-crds "$SPIRE_CRDS_VERSION" "$SPIRE_CRDS_SHA256" ;;
    spire) fetch_spire_chart spire "$SPIRE_VERSION" "$SPIRE_SHA256" ;;
    istio-base) echo "$(fetch_istio)/base" ;;
    istiod) echo "$(fetch_istio)/istio-control/istio-discovery" ;;
    istio-cni) echo "$(fetch_istio)/istio-cni" ;;
  esac
}

# merged_values <release> <values> <facts> <out>: the values file with the zone facts set; refuses
# when the zone file does not state a fact. Paths travel as arguments, never inside the source.
# "admission": the zone file over Gatekeeper's values and pins, with the switches of stage
# $ADMISSION_STAGE (default 4, everything).
merged_values() {
  if [ "$2" = zone ]; then cp "$ZONE_VALUES" "$4"; return; fi
  if [ "$2" = admission ]; then
    python3 - "$ZONE_VALUES" "$REPO/deployment/admission/gatekeeper-values.yaml" "${ADMISSION_STAGE:-4}" "$4" \
      "$GATEKEEPER_IMAGE" "$GATEKEEPER_CRDS_IMAGE" <<'PY'
import os, sys, yaml
zone_file, gatekeeper_file, stage, out, image, crds = sys.argv[1:]
stage = int(stage)
def merge(base, over):
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            merge(base[k], v)
        else:
            base[k] = v
    return base
crds_repository, crds_tag = crds.split(":", 1)
gatekeeper = merge(yaml.safe_load(open(gatekeeper_file)) or {}, {
    # As scripts/admission/install.sh sets them: every image by digest, no probe job.
    "replicas": 2,
    "image": {"release": image.split(":", 1)[1]},
    "preInstall": {"crdRepository": {"image": {"repository": crds_repository, "tag": crds_tag}}},
    "postInstall": {"labelNamespace": {"image": {"tag": crds_tag}}, "probeWebhook": {"enabled": False}},
    "postUpgrade": {"labelNamespace": {"image": {"tag": crds_tag}}},
})
values = merge({"gatekeeper": gatekeeper}, yaml.safe_load(open(zone_file)) or {})
# Where Argo CD owns the policy (admission.policy.managedBy: argocd), the release renders none of it.
helm_policy = ((values.get("admission") or {}).get("policy") or {}).get("managedBy", "helm") == "helm"
# ADMISSION_POOL (stage 4 only): the pool namespaces to render this time, a subset of the zone's.
pool = os.environ.get("ADMISSION_POOL")
if pool is not None and stage >= 4:
    values.setdefault("admissionPool", {})["namespaces"] = pool.split()
merge(values, {
    "openbao": {"enabled": False},
    "gatekeeper": {"enabled": True},
    "admissionProvider": {"enabled": stage >= 2},
    "admissionPolicy": {"templates": helm_policy and stage >= 2, "constraints": helm_policy and stage >= 3},
    "admissionPool": {"enabled": stage >= 4},
})
yaml.safe_dump(values, open(out, "w"), sort_keys=False)
PY
    return
  fi
  python3 - "$1" "$2" "$3" "$ZONE_VALUES" "$4" <<'PY'
import sys, yaml
release, values_file, facts, zone_file, out = sys.argv[1:]
values = (yaml.safe_load(open(values_file)) if values_file else None) or {}
zone = yaml.safe_load(open(zone_file)) or {}
missing = []
for pair in filter(None, facts.split(",")):
    target, source = pair.split("=")
    v = zone
    for k in source.split("."):
        v = v.get(k) if isinstance(v, dict) else None
    if v is None or str(v).strip() == "":
        missing.append(f"{source} (for {target})")
        continue
    node = values
    keys = target.split(".")
    for k in keys[:-1]:
        node = node.setdefault(k, {})
    node[keys[-1]] = v
if missing:
    sys.exit(f"install-zone: release {release}: the zone file {zone_file} does not state the zone fact "
             + ", ".join(missing))
yaml.safe_dump(values, open(out, "w"), sort_keys=False)
PY
}

# mesh_coupling: the zone-policy admission policy pins the injected proxy's image and status port
# (proxySocketPolicy.proxyImage, .statusPort); they must equal what the istiod release injects
# (global.proxy.image, and global.proxy.statusPort, from the pinned Istio chart's defaults when
# istiod.yaml leaves it unset), or the policy refuses every injected plane pod. Refused here, before
# anything is rendered or installed, so a mismatch never reaches a cluster; CI runs it with render.
mesh_coupling() {
  python3 - "$REPO/deployment/helm/zone-policy/values.yaml" "$VALUES_DIR/istiod.yaml" \
    "$(chart_path istiod)/values.yaml" <<'PY' || exit 1
import sys, yaml
policy_file, istiod_file, chart_file = sys.argv[1:]
def get(d, *keys):
    for k in keys:
        d = d.get(k) if isinstance(d, dict) else None
    return d
policy = get(yaml.safe_load(open(policy_file)) or {}, "proxySocketPolicy") or {}
istiod = yaml.safe_load(open(istiod_file)) or {}
chart = yaml.safe_load(open(chart_file)) or {}
chart = chart.get("_internal_defaults_do_not_set", chart)
pairs = [
    ("proxyImage", "global.proxy.image", get(istiod, "global", "proxy", "image")),
    ("statusPort", "global.proxy.statusPort",
     get(istiod, "global", "proxy", "statusPort") or get(chart, "global", "proxy", "statusPort")),
]
bad = [f"zone-policy proxySocketPolicy.{k} is {policy.get(k)!r}, istiod {ik} is {iv!r}"
       for k, ik, iv in pairs if iv is None or str(policy.get(k)) != str(iv)]
if bad:
    sys.exit("install-zone: the zone-policy admission policy would refuse every injected plane pod: "
             + "; ".join(bad) + " (they must be equal: deployment/helm/zone-policy/values.yaml and "
             "deployment/helm/values/istiod.yaml)")
PY
}

# admission_only <want...>: "admission-only" when the release gatekeeper alone is named.
admission_only() { [ "$*" != gatekeeper ] || echo admission-only; }

# wanted <release> <want...>: the release is among the wanted ones, or none are named.
wanted() { local r=$1; shift; [ $# -eq 0 ] || [[ " $* " == *" $r "* ]]; }

# known_releases <name...>: every name is a release of this zone.
known_releases() {
  local step name names=""
  for step in "${STEPS[@]}"; do names="$names ${step%%|*}"; done
  # ${...[@]+...}: an empty array under set -u is an unbound variable on bash before 4.4 (macOS's
  # bash 3.2), as in scripts/lifecycle.sh.
  for name in "$@"; do
    [[ "$names " == *" $name "* ]] || die "unknown release '$name'; the releases are $(sed 's/^ //; s/ /, /g' <<<"$names")"
  done
}

# admission_setup: the admission release's prerequisites, once per run - the Gatekeeper subchart is
# the pinned one, and the webhook-scope post-renderer is installed in this run's Helm directory.
admission_ready_to_render=
admission_setup() {
  [ -z "$admission_ready_to_render" ] || return 0
  local tgz="$REPO/deployment/helm/ztd/charts/gatekeeper-$GATEKEEPER_CHART_VERSION.tgz"
  [ -f "$tgz" ] || die "the umbrella's dependencies are not built: helm dependency build deployment/helm/ztd"
  [ "$(sha256 "$tgz")" = "$GATEKEEPER_CHART_SHA256" ] \
    || die "deployment/helm/ztd/charts: Gatekeeper chart digest $(sha256 "$tgz") is not the pinned $GATEKEEPER_CHART_SHA256"
  admission_helm_home "$work/helm-data"
  admission_ready_to_render=1
}

render() {
  local want=("$@") step release ns chart values facts extra path out flags
  zone_file
  MESH_SCOPE=$(admission_only ${want[@]+"${want[@]}"})
  zone_mesh "$MESH_SCOPE"
  known_releases ${want[@]+"${want[@]}"}
  # The coupling of zone-policy to istiod is checked whenever either of them is rendered.
  if [ ${#want[@]} -eq 0 ] || [[ " ${want[*]} " == *" istiod "* ]] || [[ " ${want[*]} " == *" zone-policy "* ]]; then
    mesh_coupling
  fi
  [ -n "${RENDER_DIR:-}" ] && mkdir -p "$RENDER_DIR"
  for step in "${STEPS[@]}"; do
    IFS='|' read -r release ns chart values facts extra <<<"$step"
    wanted "$release" ${want[@]+"${want[@]}"} || continue
    merged_values "$release" "$values" "$facts" "$work/$release.values.yaml" || exit 1
    path=$(chart_path "$chart")
    out=${RENDER_DIR:+$RENDER_DIR/$release.yaml}
    flags=()
    if [ "$values" = admission ]; then admission_setup; flags=(--post-renderer ztd-webhook-scope); fi
    if ! helm template "$release" "$path" --namespace "$ns" --values "$work/$release.values.yaml" \
        ${flags[@]+"${flags[@]}"} >"${out:-$work/$release.manifest.yaml}" 2>"$work/$release.err"; then
      cat "$work/$release.err" >&2
      die "release $release does not render"
    fi
    if [ "$values" = admission ] && grep -E '^\s*image:' "${out:-$work/$release.manifest.yaml}" | grep -qv '@sha256:'; then
      die "release $release: an image is not pinned by digest: $(grep -E '^\s*image:' "${out:-$work/$release.manifest.yaml}" | grep -v '@sha256:' | head -3)"
    fi
    # The merged values beside the manifest, for a dry run against a cluster (docs/umbrella-chart.md).
    [ -z "$out" ] || cp "$work/$release.values.yaml" "$RENDER_DIR/$release.values.yaml"
    say "rendered $release ($(chart_label "$chart")) into $ns: $(grep -c '^kind:' "${out:-$work/$release.manifest.yaml}") objects"
  done
}

kctx() { kubectl --context "$KUBE_CONTEXT" "$@"; }

# plane namespaces of the zone: the two fixed planes and planes.extra
zone_namespaces() {
  python3 - "$REPO/deployment/helm/ztd/values.yaml" "$ZONE_VALUES" <<'PY'
import sys, yaml
chart, zone = (yaml.safe_load(open(p)) or {} for p in sys.argv[1:])
planes = {**chart.get("planes", {}), **(zone.get("planes") or {})}
names = [planes["management"]["namespace"], planes["data"]["namespace"]]
names += [e["name"] for e in planes.get("extra") or []]
print(" ".join(names))
PY
}

# wait_ready <timeout-seconds> <namespace...>: every pod Ready (finished Job pods aside)
wait_ready() {
  local deadline=$(( $(date +%s) + $1 )); shift
  local pending
  while :; do
    pending=$(for ns in "$@"; do
      kctx -n "$ns" get pods -o json | jq -r --arg ns "$ns" '.items[]
        | select(.status.phase != "Succeeded")
        | select(([.status.conditions[]? | select(.type == "Ready" and .status == "True")] | length) == 0)
        | "\($ns)/\(.metadata.name)"'
    done)
    [ -z "$pending" ] && return 0
    [ "$(date +%s)" -ge "$deadline" ] && { say "pods not Ready:" "$pending"; return 1; }
    sleep 5
  done
}

preflight() {
  local tool
  for tool in helm kubectl jq curl python3; do
    command -v "$tool" >/dev/null || die "missing tool: $tool"
  done
  python3 -c 'import yaml' 2>/dev/null || die "python3 needs PyYAML"
  zone_file
  if ! kctx version --request-timeout=10s >/dev/null 2>&1; then
    plan
    die "the cluster of context $KUBE_CONTEXT cannot be reached; refusing to continue (nothing was changed)"
  fi
  # The lifecycle step uses the current context of its kubeconfig: give it one with only ours.
  kubectl config view --minify --flatten --context "$KUBE_CONTEXT" >"$work/kubeconfig"
  export KUBECONFIG="$work/kubeconfig"
}

# deploy <i> <release> <namespace> <chart path> <values file> <extra>: one release through the
# lifecycle step (LIFECYCLE_* settings in the environment pass through); stops the run on failure.
deploy() {
  local i=$1 release=$2 ns=$3 line ok
  line=$(LIFECYCLE_RELEASE=$release LIFECYCLE_NAMESPACE=$ns LIFECYCLE_CHART=$4 \
    LIFECYCLE_VALUES_FILE=$5 LIFECYCLE_TIMEOUT=$STEP_TIMEOUT \
    LIFECYCLE_WAIT_FOR_JOBS=$([ "$6" = wait-for-jobs ] && echo true || echo false) \
    "$REPO/scripts/lifecycle.sh" deploy 2>"$work/$release.stderr" | grep '^RESULT_JSON=' | cut -d= -f2-) || true
  [ -n "$line" ] || line='{}'
  ok=$(jq -r '.ok // false' <<<"$line" 2>/dev/null || echo false)
  if [ "$ok" != true ]; then
    say "step $i/${#STEPS[@]} FAILED: release $release in $ns: $(jq -r '.error.message // "no result"' <<<"$line" 2>/dev/null)"
    jq -r '.output // empty' <<<"$line" 2>/dev/null | tail -20 >&2 || true
    cat "$work/$release.stderr" >&2
    exit 1
  fi
  say "step $i/${#STEPS[@]}: $release deployed, revision $(jq -r '.revision' <<<"$line")"
}

# admission_stage_ready <stage>: what stage <stage> needs is in place - 2: Gatekeeper's CRDs; 3: the
# CRDs Gatekeeper generates from the constraint templates; 4: every constraint enforced by every
# Ready webhook replica.
admission_stage_ready() {
  local c
  case $1 in
    2) kubectl wait --for=condition=established --timeout=5s crd/providers.externaldata.gatekeeper.sh \
         crd/constrainttemplates.templates.gatekeeper.sh crd/configs.config.gatekeeper.sh >/dev/null 2>&1 ;;
    3) for c in $admission_constraints; do
         kubectl wait --for=condition=established --timeout=5s "crd/${c%%/*}.constraints.gatekeeper.sh" >/dev/null 2>&1 || return 1
       done ;;
    4) for c in $admission_constraints; do admission_enforced "$c" || return 1; done ;;
  esac
}

# data_plane_parity: with admission.enforceDataPlane and admission.policy.managedBy argocd, refuse to
# label the data plane until Argo CD's ztd-allowed-repositories constraint holds every digest of the
# zone's admissionProvider.trust.allowedDigests (the injected Istio proxy among them): otherwise the
# provider would admit what the constraint denies, and every meshed pod there would be refused.
data_plane_parity() {
  local want have missing d
  python3 -c 'import sys, yaml; z = yaml.safe_load(open(sys.argv[1])) or {}; sys.exit(0 if (z.get("admission") or {}).get("enforceDataPlane") is True else 1)' "$ZONE_VALUES" || return 0
  [ "$(policy_managed_by)" = argocd ] || return 0
  want=$(python3 -c 'import sys, yaml; z = yaml.safe_load(open(sys.argv[1])) or {}; print(" ".join(((z.get("admissionProvider") or {}).get("trust") or {}).get("allowedDigests") or []))' "$ZONE_VALUES")
  have=" $(kubectl get k8sztdallowedrepositories ztd-allowed-repositories -o json 2>/dev/null | jq -r '.spec.parameters.allowedDigests // [] | join(" ")') "
  missing=
  for d in $want; do [[ "$have" == *" $d "* ]] || missing="$missing $d"; done
  [ -z "$missing" ] || die "admission.enforceDataPlane with the policy kept by Argo CD: the live constraint ztd-allowed-repositories lacks the allow-listed digest(s)${missing}; sync them into Argo CD's policy source and run scripts/admission/preflight-data-plane.sh <namespace> first; nothing was changed"
}

# policy_managed_by: admission.policy.managedBy of the zone file, helm by default.
policy_managed_by() {
  python3 -c 'import sys, yaml; z = yaml.safe_load(open(sys.argv[1])) or {}; print(((z.get("admission") or {}).get("policy") or {}).get("managedBy", "helm"))' "$ZONE_VALUES"
}

# admission_installed_stage: the stage release gatekeeper of this chart already holds (its deployed
# switches), 0 when there is none. No deploy renders less than this: a manifest without a component
# the release holds would make Helm delete it.
admission_installed_stage() {
  [ "$(admission_layout)" = umbrella ] || { echo 0; return; }
  helm get values gatekeeper -n "$admission_ns" -o json | jq -r '
    if .admissionPool.enabled then 4 elif .admissionPolicy.constraints then 3
    elif .admissionProvider.enabled then 2 elif .gatekeeper.enabled then 1 else 0 end'
}

# admission_pool_desired: the zone's pool namespaces (admissionPool.namespaces, or the chart's).
admission_pool_desired() {
  python3 - "$ZONE_VALUES" "$REPO/deployment/helm/admission-pool/values.yaml" <<'PY'
import sys, yaml
zone, chart = (yaml.safe_load(open(p)) or {} for p in sys.argv[1:])
print(" ".join((zone.get("admissionPool") or {}).get("namespaces") or chart.get("namespaces") or []))
PY
}

# admission_policy_handoff: with admission.policy.managedBy argocd, release gatekeeper may hold no
# policy object that Helm would delete: each one it holds must carry helm.sh/resource-policy: keep
# (admission.policy.keep, the first step of the handoff in docs/umbrella-chart.md).
admission_policy_handoff() {
  [ "$(admission_layout)" = umbrella ] || return 0
  helm get manifest gatekeeper -n "$admission_ns" | python3 -c '
import sys, yaml
bad = [d["kind"] + "/" + d["metadata"]["name"] for d in yaml.safe_load_all(sys.stdin) if d
       and (d["kind"] == "ConstraintTemplate" or d["apiVersion"].startswith(("constraints.gatekeeper.sh/", "config.gatekeeper.sh/")))
       and (d["metadata"].get("annotations") or {}).get("helm.sh/resource-policy") != "keep"]
if bad:
    sys.exit("release gatekeeper holds policy objects that Helm would delete on the switch to Argo CD: "
             + ", ".join(bad) + "; first install with admission.policy.keep: true and managedBy helm "
             "(docs/umbrella-chart.md, handing the policy to Argo CD)")
' || die "admission.policy.managedBy argocd refused; nothing was changed"
}

# install_admission <i> <namespace>: the admission release, in stages (header), then the checks of
# scripts/admission/install.sh: webhooks scoped, response cache off, constraints enforced.
# - No deploy renders fewer components than the release holds (admission_installed_stage): on an
#   upgrade the stages below it are not deployed again, whatever a readiness check says.
# - Changed policy goes out with the pool namespaces that exist already; the installer waits until
#   every constraint's current generation is enforced by every Ready webhook replica, and only then
#   adds new pool namespaces.
# - Where Argo CD owns the policy (admission.policy.managedBy: argocd) the release never renders it,
#   so an adoption never takes ownership of it: stage 3 deploys nothing, and the installer waits for
#   Argo CD's constraint CRDs and constraints instead (ADMISSION_POLICY_TIMEOUT seconds per wait,
#   default 300). Switching a release that renders the policy to argocd needs the handoff first.
install_admission() {
  local i=$1 ns=$2 stage adopt=false old managed wait_s installed desired existing n
  old=$(admission_standalone_releases)
  [ -z "$old" ] || adopt=true
  managed=$(policy_managed_by)
  wait_s=${ADMISSION_POLICY_TIMEOUT:-300}
  [ "$managed" != argocd ] || admission_policy_handoff
  installed=$(admission_installed_stage)
  admission_setup
  for stage in 1 2 3; do
    { [ "$stage" -lt "$installed" ] || admission_stage_ready $((stage + 1)); } && continue
    if [ "$stage" -eq 3 ] && [ "$managed" = argocd ]; then
      say "step $i/${#STEPS[@]}: gatekeeper, stage 3/4: the constraints are Argo CD's; waiting for them to be enforced ..."
    else
      admission_deploy "$i" "$ns" "$stage" "$adopt" "$old"
    fi
    admission_wait "$((stage + 1))" "$wait_s" "$stage" "$managed"
  done
  # Stage 4: the policy with the pool namespaces that exist, enforced, then the new ones.
  desired=$(admission_pool_desired)
  existing=
  for n in $desired; do kubectl get namespace "$n" >/dev/null 2>&1 && existing="$existing $n"; done
  existing=${existing# }
  if [ -n "$existing" ] || [ "$installed" -ge 4 ]; then
    ADMISSION_POOL=${existing:-$desired} admission_deploy "$i" "$ns" 4 "$adopt" "$old"
  fi
  admission_wait 4 "$wait_s" 4 "$managed"
  if [ "$existing" != "$desired" ]; then
    say "step $i/${#STEPS[@]}: gatekeeper: every constraint enforced; adding the pool namespaces ${desired} ..."
    ADMISSION_POOL=$desired admission_deploy "$i" "$ns" 4 "$adopt" "$old"
  fi
  local unscoped ttl
  unscoped=$(admission_unscoped)
  [ -z "$unscoped" ] || die "webhooks not scoped to facis.ztd/admission-proof=true: $unscoped"
  ttl=$(admission_cache_ttl)
  [ "$ttl" = "response-cache-ttl=0s" ] || die "Gatekeeper response cache is not off: '$ttl'"
  admission_wait_enforced || die "the admission release is deployed, but not every constraint is enforced"
  # Adopted: the old releases' records go, their objects stay (helm uninstall would delete them).
  # Release gatekeeper is now this chart's, so only the other two are dropped.
  if [ "$adopt" = true ]; then
    admission_forget admission admission-pool
    say "adopted: the records of releases admission and admission-pool dropped, their objects kept"
  fi
  say "admission: webhooks scoped to facis.ztd/admission-proof=true; $ttl; every constraint enforced"
}

# admission_deploy <i> <namespace> <stage> <adopt> <old releases>: one deploy of the admission
# release with the switches of <stage> (ADMISSION_POOL in the environment narrows the pool).
admission_deploy() {
  ADMISSION_STAGE=$3 merged_values gatekeeper admission "" "$work/gatekeeper.values.yaml"
  say "step $1/${#STEPS[@]}: gatekeeper, stage $3/4${ADMISSION_POOL:+ (pool: $ADMISSION_POOL)}${5:+ (adopting the objects of ${5//$'\n'/ })} ..."
  LIFECYCLE_POST_RENDERER=ztd-webhook-scope LIFECYCLE_TAKE_OWNERSHIP=$4 \
    deploy "$1" gatekeeper "$2" "$(chart_path umbrella)" "$work/gatekeeper.values.yaml" ""
}

# admission_wait <stage> <seconds> <after stage> <managed by>: until admission_stage_ready <stage>,
# or stop with what is missing.
admission_wait() {
  local deadline=$(( $(date +%s) + $2 )) msg
  until admission_stage_ready "$1"; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
      msg="what stage $1 needs is not in place after ${2}s"
      if [ "$4" = argocd ] && [ "$3" -ge 2 ]; then
        msg="Argo CD has not provided the admission policy after ${2}s: $([ "$1" -eq 3 ] && echo "the constraint CRDs (from its constraint templates) are not Established" || echo "the constraints are not enforced by every Ready webhook replica"); check its Applications admission-templates, admission-constraints and admission-exemptions"
      fi
      die "admission stage $3: $msg"
    fi
    sleep 5
  done
}

install() {
  local want=("$@")
  zone_file
  MESH_SCOPE=$(admission_only ${want[@]+"${want[@]}"})
  zone_mesh "$MESH_SCOPE"
  preflight
  known_releases ${want[@]+"${want[@]}"}
  # Adopting the standalone admission objects is the operator's decision, refused before anything.
  if wanted gatekeeper ${want[@]+"${want[@]}"} && [[ " ${STEPS[*]} " == *" gatekeeper|"* ]]; then
    local old
    old=$(admission_standalone_releases)
    if [ -n "$old" ] && [ "${ADMISSION_ADOPT:-}" != 1 ]; then
      die "the admission stack is installed by scripts/admission/install.sh (releases ${old//$'\n'/ }); ADMISSION_ADOPT=1 lets release gatekeeper adopt it (docs/umbrella-chart.md, migration); nothing was changed"
    fi
  fi
  # An enforced data plane needs the allow-list in the constraint too: where Argo CD keeps the policy,
  # the zone file reaches only the provider, so the live constraint is checked before release ztd.
  if wanted ztd ${want[@]+"${want[@]}"}; then data_plane_parity; fi
  # Every release is checked to render, with its zone facts, before the first one is installed.
  render ${want[@]+"${want[@]}"} >/dev/null
  plan
  local umbrella_ns
  umbrella_ns=$(IFS='|' read -r _ ns _ <<<"${STEPS[0]}"; echo "$ns")
  if wanted ztd ${want[@]+"${want[@]}"}; then
    kctx get namespace "$umbrella_ns" >/dev/null 2>&1 || kctx create namespace "$umbrella_ns" >/dev/null
  fi
  local i=0 step release ns chart values facts extra
  for step in "${STEPS[@]}"; do
    IFS='|' read -r release ns chart values facts extra <<<"$step"
    i=$((i + 1))
    wanted "$release" ${want[@]+"${want[@]}"} || continue
    if [ "$values" = admission ]; then
      kctx get namespace "$ns" >/dev/null 2>&1 || kctx create namespace "$ns" >/dev/null
      install_admission "$i" "$ns"
      continue
    fi
    merged_values "$release" "$values" "$facts" "$work/$release.values.yaml"
    say "step $i/${#STEPS[@]}: $release into $ns ..."
    deploy "$i" "$release" "$ns" "$(chart_path "$chart")" "$work/$release.values.yaml" "$extra"
  done
  # The plane namespaces' pods, unless only the admission release was installed.
  [ ${#want[@]} -eq 0 ] || [ "${want[*]}" != gatekeeper ] || return 0
  local namespaces
  namespaces=$(zone_namespaces)
  # shellcheck disable=SC2086 # one word per namespace
  wait_ready 600 $namespaces || die "the releases are deployed, but not every pod in $namespaces is Ready"
  say "zone installed: every pod in $namespaces is Ready"
}

uninstall() {
  preflight
  local i step release ns rest line
  for (( i=${#STEPS[@]}-1; i>=0; i-- )); do
    IFS='|' read -r release ns rest <<<"${STEPS[$i]}"
    if ! helm --kube-context "$KUBE_CONTEXT" status "$release" -n "$ns" >/dev/null 2>&1; then
      say "uninstall $release: not installed"; continue
    fi
    line=$(LIFECYCLE_RELEASE=$release LIFECYCLE_NAMESPACE=$ns LIFECYCLE_TIMEOUT=$STEP_TIMEOUT \
      "$REPO/scripts/lifecycle.sh" uninstall 2>/dev/null | grep '^RESULT_JSON=' | cut -d= -f2-) || true
    [ -n "$line" ] || line='{}'
    [ "$(jq -r '.ok // false' <<<"$line")" = true ] \
      || die "uninstall of $release in $ns failed: $(jq -r '.error.message // "no result"' <<<"$line")"
    # Istio's base chart marks its CRDs helm.sh/resource-policy: keep in the chart's files, not in a
    # value, so Helm leaves them behind. The CRDs this release owned leave with it. Only istio-base:
    # spire-crds drops the annotation in its values, so its plain helm uninstall removes its CRDs.
    if [ "$release" = istio-base ]; then
      kctx get crd -o json | jq -r --arg r "$release" --arg n "$ns" '.items[]
        | select(.metadata.annotations["meta.helm.sh/release-name"] == $r
                 and .metadata.annotations["meta.helm.sh/release-namespace"] == $n) | .metadata.name' \
        | xargs -r kubectl --context "$KUBE_CONTEXT" delete crd >/dev/null
    fi
    say "uninstall $release: done"
  done
}

case "${1:-}" in
  install) shift; install "$@" ;;
  plan) plan ;;
  render) shift; render "$@" ;;
  uninstall) uninstall ;;
  help|-h|--help) usage ;;
  '') usage >&2; exit 2 ;;
  *) usage >&2; printf "install-zone: unknown command '%s'\n" "$1" >&2; exit 2 ;;
esac
