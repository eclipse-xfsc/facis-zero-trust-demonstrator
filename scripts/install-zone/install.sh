#!/usr/bin/env bash
# Install one zone of the demonstrator from an empty cluster (with its CNI) as Helm releases, in
# order, each through the deployment lifecycle step (scripts/lifecycle.sh: server-side dry run, then
# helm upgrade --install --wait with rollback on failure), each waiting on the previous. The zone
# file's mesh.mode selects one of two paths.
#
# The sidecar path (mesh.mode sidecar, or absent: the participant zones and the kind zone, ADR-0009),
# eight releases:
#   1 ztd          ztd-system    the umbrella: plane namespaces (with spire-system and istio-system),
#                                default deny, declared openings, allow matrix
#   2 spire-crds   spire-system  the SPIRE controller-manager's CRDs        (upstream, pinned)
#   3 spire        spire-system  server, agents, CSI driver, controller-manager (upstream, pinned)
#   4 istio-base   istio-system  Istio's CRDs                                (upstream, pinned)
#   5 istiod       istio-system  the mesh control plane, sidecar mode, SPIRE as certificate source
#   6 istio-cni    istio-system  the Istio CNI plugin, chained behind the cluster's CNI
#   7 zone-policy  istio-system  ClusterSPIFFEID, STRICT PeerAuthentication, identity-band checks
#   8 ztd-openbao  ztd-mgmt      OpenBao, its bootstrap Job and verification hook (project chart
#                                wrapping the upstream openbao chart, built from its Chart.lock,
#                                pinned by digest); last, so its pods are created with a sidecar
#                                and an SVID
#
# The ambient path (mesh.mode ambient: the demonstrator cluster on Calico, without SPIRE, ADR-0018),
# six releases, Istio from its own pin (ISTIO_AMBIENT_VERSION), no SPIRE and no OpenBao:
#   1 ztd          ztd-system    the umbrella, with the declared CNI derogation (cni.derogation)
#   2 istio-base   istio-system  Istio's CRDs
#   3 istiod       istio-system  the mesh control plane, ambient profile, istiod's own CA
#   4 istio-cni    istio-system  the Istio CNI agent, ambient on, chained behind the cluster's CNI
#   5 ztunnel      istio-system  the ambient data plane, one per node
#   6 zone-policy  istio-system  the STRICT PeerAuthentication, no injected proxy in the planes, and
#                                the allow-matrix lanes' ports enforced by ztunnel (spire.enabled
#                                false; the zone's allow matrix as lanePorts)
#
# Usage:
#   scripts/install-zone/install.sh install          install or upgrade the zone (idempotent)
#   scripts/install-zone/install.sh plan             list the steps; touches no cluster
#   scripts/install-zone/install.sh render [release...]
#                                                    render the releases from the pinned charts and
#                                                    the merged values; touches no cluster (CI);
#                                                    an unknown release name is an error
#   scripts/install-zone/install.sh uninstall        uninstall in reverse order (the last release first)
#   scripts/install-zone/install.sh help             this text (also -h, --help)
#
# Environment:
#   ZONE_VALUES   zone file             (default: deployment/helm/ztd/ci/values.yaml, the kind zone)
#   ZONE_OVERLAY  a second file deep-merged over the zone file (its lists replace the zone file's),
#                 for facts kept out of the repository: CI renders zones/ionos.yaml with
#                 deployment/helm/ztd/ci/ionos.overlay.yaml (documentation-range addresses); the
#                 operator installs the demonstrator cluster from a local, uncommitted copy of
#                 zones/ionos.yaml that holds the API endpoint addresses
#   KUBE_CONTEXT  kubectl context       (default: kind-ztd)
#   STEP_TIMEOUT  timeout per release   (default: 10m)
#   RENDER_DIR    with `render`, write each release's manifest there as <release>.yaml
#   INSTALL_ZONE_CACHE  where the pinned charts and the built OpenBao dependency are kept
#                       (default: ~/.cache/ztd-install-zone)
#
# Mesh settings: the installer installs the default, unrevisioned istiod, in sidecar mode (with the
# Istio CNI plugin with ambient off) or in ambient mode (with ztunnel). It refuses, before it renders
# or installs anything, a zone file whose mesh.mode is anything but sidecar (absent counts as
# sidecar) or ambient, or whose mesh.revision is set: the umbrella would label the plane namespaces
# for an injector this installer never installs. A zone without a mesh (none) installs the umbrella
# alone through scripts/lifecycle.sh. On the sidecar path it also refuses, before it renders istiod
# or zone-policy, a zone-policy whose proxySocketPolicy.proxyImage or statusPort differs from
# istiod's global.proxy.image or statusPort: the admission policy would refuse every injected plane
# pod. The ambient path injects no proxy and renders no such policy, so the check does not apply.
#
# The umbrella reads the whole zone file. The other releases read their upstream values file under
# deployment/helm/values/ (zone-policy and ztd-openbao: their chart defaults) merged with the zone
# facts they need. The zone facts are read from the umbrella's defaults
# (deployment/helm/ztd/values.yaml) with the zone file on top, so a fact the umbrella defaults (the
# management namespace, the Cilium switch) needs no repeating; a fact the umbrella leaves empty
# (zone.trustDomain, zone.name, zone.storageClass) and the zone file does not state stops the run
# before anything is rendered. ztd-openbao goes into the management namespace of the same merge.
# Every namespace the releases install into is created by the umbrella; the one namespace this
# script creates is the umbrella's own release namespace, which holds only the release record and
# its verification job. Needs helm, kubectl, jq, curl, python3 with PyYAML, and sha256sum or shasum.
# No release is placed on a node: the scheduler places every pod, ztd-openbao's included.
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ZONE_VALUES=${ZONE_VALUES:-$REPO/deployment/helm/ztd/ci/values.yaml}
KUBE_CONTEXT=${KUBE_CONTEXT:-kind-ztd}
STEP_TIMEOUT=${STEP_TIMEOUT:-10m}
CACHE=${INSTALL_ZONE_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/ztd-install-zone}
VALUES_DIR=$REPO/deployment/helm/values

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
# The ambient path's own Istio (the demonstrator cluster, ADR-0018): 1.31.4 or later, the release of
# the security advisory of 6 Nov 2026, from the release archive like the zones' pin above, which
# stays where it is until the zones' own upgrade (that upgrade reruns
# scripts/verify-mesh-identity/verify.sh on the zones). An upgrade of this pin changes the version,
# the sha256 and the image digests of deployment/helm/values/*-ambient.yaml and ztunnel.yaml, then
# reruns scripts/verify-ambient-mesh/verify.sh.
ISTIO_AMBIENT_VERSION=1.31.4
ISTIO_AMBIENT_ARCHIVE_URL=https://github.com/istio/istio/releases/download/$ISTIO_AMBIENT_VERSION/istio-$ISTIO_AMBIENT_VERSION-linux-amd64.tar.gz
ISTIO_AMBIENT_ARCHIVE_SHA256=956421eb4934c10029622b6cd96442c904548d12eadbe874fb1d1a38d5d58ccc
# The upstream openbao chart of ztd-openbao: its version in the project chart's Chart.lock, its
# archive's sha256 in deployment/helm/ztd-openbao/dependencies.sha256 (build_openbao_chart).

# ---- The steps: release, namespace, chart, values file, zone facts (<values key>=<zone key>,...),
# ---- extra lifecycle settings. "zone" as values file means the zone file itself; no values file
# ---- means the chart's defaults. A fact written <values key>=!<YAML> sets that literal value
# ---- instead of a zone fact (spire.enabled=!false is the boolean false).
# The sidecar path.
STEPS=(
  "ztd|ztd-system|umbrella|zone||"
  "spire-crds|spire-system|spire-crds|$VALUES_DIR/spire-crds.yaml||"
  "spire|spire-system|spire|$VALUES_DIR/spire.yaml|global.spire.trustDomain=zone.trustDomain,global.spire.clusterName=zone.name,global.spire.persistence.storageClass=zone.storageClass,global.spire.caSubject.commonName=zone.trustDomain|"
  "istio-base|istio-system|istio-base|$VALUES_DIR/istio-base.yaml||"
  "istiod|istio-system|istiod|$VALUES_DIR/istiod.yaml|meshConfig.trustDomain=zone.trustDomain|"
  "istio-cni|istio-system|istio-cni|$VALUES_DIR/istio-cni.yaml||"
  "zone-policy|istio-system|zone-policy||trustDomain=zone.trustDomain|wait-for-jobs"
  "ztd-openbao|=planes.management.namespace|ztd-openbao||managementNamespace=planes.management.namespace,openbao.global.namespace=planes.management.namespace,openbao.server.dataStorage.storageClass=zone.storageClass,cilium.enabled=cni.cilium.enabled|wait-for-jobs"
)
# The ambient path: no SPIRE, no OpenBao; Istio from the ambient pin, with ztunnel.
AMBIENT_STEPS=(
  "ztd|ztd-system|umbrella|zone||"
  "istio-base|istio-system|istio-base|$VALUES_DIR/istio-base.yaml||"
  "istiod|istio-system|istiod|$VALUES_DIR/istiod-ambient.yaml|meshConfig.trustDomain=zone.trustDomain|"
  "istio-cni|istio-system|istio-cni|$VALUES_DIR/istio-cni-ambient.yaml||"
  "ztunnel|istio-system|ztunnel|$VALUES_DIR/ztunnel.yaml||"
  "zone-policy|istio-system|zone-policy||trustDomain=zone.trustDomain,spire.enabled=!false,lanePorts.allowMatrix=allowMatrix,lanePorts.namespaces.management=planes.management.namespace,lanePorts.namespaces.data=planes.data.namespace|"
)
# A namespace written "=<zone key>" is that zone fact (the management namespace of ztd-openbao).

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

say() { printf '%s\n' "$*"; }
die() { printf 'install-zone: %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,/^set -euo pipefail$/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }

# zone_file: the zone file must exist before anything reads it. With ZONE_OVERLAY, the zone file
# from here on is the zone file with the overlay deep-merged on top (lists replaced), written once
# into the run's work directory; ZONE_LABEL keeps the names for the output.
ZONE_LABEL=
zone_file() {
  [ -n "$ZONE_LABEL" ] && return 0
  [ -f "$ZONE_VALUES" ] || die "zone file not found: $ZONE_VALUES"
  ZONE_LABEL=${ZONE_VALUES#"$REPO"/}
  if [ -n "${ZONE_OVERLAY:-}" ]; then
    [ -f "$ZONE_OVERLAY" ] || die "zone overlay not found: $ZONE_OVERLAY"
    python3 - "$ZONE_VALUES" "$ZONE_OVERLAY" "$work/zone.yaml" <<'PY' || exit 1
import sys, yaml
def merge(base, top):
    if isinstance(base, dict) and isinstance(top, dict):
        out = dict(base)
        for k, v in top.items():
            out[k] = merge(base[k], v) if k in base else v
        return out
    return top
base = yaml.safe_load(open(sys.argv[1])) or {}
top = yaml.safe_load(open(sys.argv[2])) or {}
yaml.safe_dump(merge(base, top), open(sys.argv[3], "w"), sort_keys=False)
PY
    ZONE_LABEL="$ZONE_LABEL + ${ZONE_OVERLAY#"$REPO"/}"
    ZONE_VALUES=$work/zone.yaml
  fi
}

# zone_mesh: the zone file's mesh settings must be ones this installer installs: sidecar mode
# (absent counts as sidecar) or ambient mode, with the default, unrevisioned istiod; anything else is
# refused before anything is rendered or installed. Read with PyYAML, as merged_values reads the zone
# facts. Selects the path: MESH_PATH, the steps (PATH_STEPS) and the Istio pin (ISTIO_SEL_*).
MESH_PATH=
mesh_mode() {
  python3 - "$ZONE_VALUES" <<'PY'
import sys, yaml
zone_file = sys.argv[1]
zone = yaml.safe_load(open(zone_file)) or {}
mesh = zone.get("mesh") if isinstance(zone, dict) else None
mesh = mesh if isinstance(mesh, dict) else {}
mode = mesh.get("mode")
revision = mesh.get("revision")
scope = ("this installer installs the default, unrevisioned istiod in sidecar mode (the zones) or "
         "in ambient mode (the demonstrator cluster, ADR-0018) only")
if mode is not None and str(mode) not in ("sidecar", "ambient"):
    sys.exit(f'install-zone: the zone file sets mesh.mode "{mode}", but {scope}; '
             'another mesh mode needs its own installer support (a zone without a mesh installs '
             'the umbrella alone through scripts/lifecycle.sh)')
if revision is not None and str(revision).strip() != "":
    sys.exit(f'install-zone: the zone file sets mesh.revision "{revision}" with mesh.mode '
             f'"{mode or "sidecar"}", but {scope}; a revisioned mesh needs its own installer support')
print("ambient" if str(mode) == "ambient" else "sidecar")
PY
}
zone_mesh() {
  [ -n "$MESH_PATH" ] && return 0
  MESH_PATH=$(mesh_mode) || exit 1
  if [ "$MESH_PATH" = ambient ]; then
    PATH_STEPS=("${AMBIENT_STEPS[@]}")
    ISTIO_SEL_VERSION=$ISTIO_AMBIENT_VERSION
    ISTIO_SEL_ARCHIVE_URL=$ISTIO_AMBIENT_ARCHIVE_URL
    ISTIO_SEL_ARCHIVE_SHA256=$ISTIO_AMBIENT_ARCHIVE_SHA256
  else
    PATH_STEPS=("${STEPS[@]}")
    ISTIO_SEL_VERSION=$ISTIO_VERSION
    ISTIO_SEL_ARCHIVE_URL=$ISTIO_ARCHIVE_URL
    ISTIO_SEL_ARCHIVE_SHA256=$ISTIO_ARCHIVE_SHA256
  fi
}

# path_label: the selected path, for the output.
path_label() {
  if [ "$MESH_PATH" = ambient ]; then
    echo "ambient (Istio $ISTIO_SEL_VERSION, istiod's CA, no SPIRE; ADR-0018)"
  else
    echo "sidecar (Istio $ISTIO_SEL_VERSION, SPIRE; ADR-0009)"
  fi
}

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

# The zone document: the umbrella's defaults with the zone file deep-merged on top (the zone file
# wins), the one source of every release's zone facts and of the plane namespaces. zone_py runs a
# Python program, read from stdin, after the definitions below; its arguments follow the umbrella's
# values file and the zone file, which the program finds as UMBRELLA and ZONE.
UMBRELLA_VALUES=$REPO/deployment/helm/ztd/values.yaml
zone_py() {
  { cat <<'PY'
import sys, yaml
UMBRELLA, ZONE = sys.argv[1], sys.argv[2]
ARGS = sys.argv[3:]
def merge(base, top):
    if isinstance(base, dict) and isinstance(top, dict):
        out = dict(base)
        for k, v in top.items():
            out[k] = merge(base[k], v) if k in base else v
        return out
    return top
def zone_doc():
    return merge(yaml.safe_load(open(UMBRELLA)) or {}, yaml.safe_load(open(ZONE)) or {})
def fact(doc, key):
    for k in key.split("."):
        doc = doc.get(k) if isinstance(doc, dict) else None
    return doc
PY
    cat; } | python3 - "$UMBRELLA_VALUES" "$ZONE_VALUES" "$@"
}

# zone_fact <key>: one fact of the zone document, empty when absent; booleans print as true/false.
zone_fact() {
  zone_py "$1" <<'PY'
v = fact(zone_doc(), ARGS[0])
print("" if v is None else (str(v).lower() if isinstance(v, bool) else v))
PY
}

# step_ns <namespace>: a step's namespace; "=<zone key>" is that zone fact, refused when empty.
step_ns() {
  case $1 in
    =*) local ns; ns=$(zone_fact "${1#=}") || exit 1
        [ -n "$ns" ] || die "the zone fact ${1#=} is empty: no namespace to install into"
        echo "$ns" ;;
    *) echo "$1" ;;
  esac
}

plan() {
  zone_file
  zone_mesh
  say "Zone file: $ZONE_LABEL   context: $KUBE_CONTEXT"
  say "Mesh path: $(path_label)"
  local i=0 step release ns chart values facts extra label
  for step in "${PATH_STEPS[@]}"; do
    IFS='|' read -r release ns chart values facts extra <<<"$step"
    ns=$(step_ns "$ns")
    i=$((i + 1))
    if [ "$values" = zone ]; then label="the zone file"
    elif [ -n "$values" ]; then label=${values#"$REPO"/}
    else label="chart defaults"; fi
    printf '  %d/%d  %-12s into %-13s chart %-12s values %s%s%s\n' "$i" "${#PATH_STEPS[@]}" "$release" "$ns" \
      "$(chart_label "$chart")" "$label" "${facts:+ + zone facts ${facts//,/ }}" "${extra:+ ($extra)}"
  done
}

chart_label() {
  case $1 in
    umbrella) echo "deployment/helm/ztd" ;;
    zone-policy) echo "deployment/helm/zone-policy" ;;
    ztd-openbao) echo "deployment/helm/ztd-openbao" ;;
    spire-crds) echo "spire-crds $SPIRE_CRDS_VERSION" ;;
    spire) echo "spire $SPIRE_VERSION" ;;
    istio-base) echo "base $ISTIO_SEL_VERSION" ;;
    istiod) echo "istiod $ISTIO_SEL_VERSION" ;;
    istio-cni) echo "cni $ISTIO_SEL_VERSION" ;;
    ztunnel) echo "ztunnel $ISTIO_SEL_VERSION" ;;
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

# fetch_istio: the charts of the selected path's Istio release (zone_mesh), from its archive,
# verified by its pinned sha256.
fetch_istio() {
  local v=$ISTIO_SEL_VERSION
  local dir="$CACHE/istio-$v" archive="$CACHE/istio-$v-linux-amd64.tar.gz"
  if [ ! -f "$dir/.verified" ]; then
    mkdir -p "$CACHE"
    if [ ! -f "$archive" ] || [ "$(sha256 "$archive")" != "$ISTIO_SEL_ARCHIVE_SHA256" ]; then
      curl -fsSL -o "$archive" "$ISTIO_SEL_ARCHIVE_URL" || die "could not fetch $ISTIO_SEL_ARCHIVE_URL"
    fi
    [ "$(sha256 "$archive")" = "$ISTIO_SEL_ARCHIVE_SHA256" ] \
      || die "Istio archive: digest $(sha256 "$archive") is not the pinned $ISTIO_SEL_ARCHIVE_SHA256"
    rm -rf "$dir"; mkdir -p "$dir"
    tar -xzf "$archive" -C "$dir" --strip-components=3 "istio-$v/manifests/charts"
    touch "$dir/.verified"
  fi
  echo "$dir"
}

# build_openbao_chart: deployment/helm/ztd-openbao with its upstream dependency built from the
# committed Chart.lock. `helm dependency build` refuses a lock whose digest does not match the
# chart's dependencies; that digest covers the list of dependencies, not the archive's bytes, so
# the built archive is checked against the sha256 committed in the chart's dependencies.sha256
# (scripts/ci/verify-chart-dependencies.sh) on every run, as the SPIRE and Istio downloads are
# checked against their pins above. The build runs once per Chart.yaml and Chart.lock, into the
# cache, with a repository configuration of the installer's own (the user's Helm repositories are
# neither read nor changed). Each run copies the chart from the checkout into its work directory,
# copies the cached archives into it (their bytes: -L copies the target of a symbolic link, not the
# link), and only then verifies them: what is checked is the copy in
# the run's own work directory that Helm installs, not the cache, which could change between a
# check and a later copy. Nothing but the pinned archives may be there (no unpacked chart
# directory either), so the chart's templates and values are always the checkout's.
build_openbao_chart() {
  local src=$REPO/deployment/helm/ztd-openbao out=$work/chart-ztd-openbao key dir url
  if [ -f "$out/.ready" ]; then echo "$out"; return; fi
  key=$(cat "$src/Chart.yaml" "$src/Chart.lock" >"$work/openbao-chart-key"; sha256 "$work/openbao-chart-key" | cut -c1-16)
  dir=$CACHE/ztd-openbao-deps-$key
  if [ ! -f "$dir/.built" ]; then
    rm -rf "$dir"; mkdir -p "$dir/chart"
    cp "$src/Chart.yaml" "$src/Chart.lock" "$dir/chart/"
    url=$(sed -n 's/^ *repository: *"\{0,1\}\(https:[^"]*\)"\{0,1\}$/\1/p' "$src/Chart.yaml" | head -1)
    if ! { HELM_REPOSITORY_CONFIG=$dir/repositories.yaml HELM_REPOSITORY_CACHE=$dir/repository \
             helm repo add ztd-openbao-dependency "$url" \
           && HELM_REPOSITORY_CONFIG=$dir/repositories.yaml HELM_REPOSITORY_CACHE=$dir/repository \
             helm dependency build "$dir/chart"; } >"$work/openbao-deps.log" 2>&1; then
      cat "$work/openbao-deps.log" >&2
      die "chart ztd-openbao: its dependency was not built from Chart.lock (a lock out of sync with Chart.yaml, or $url unreachable)"
    fi
    touch "$dir/.built"
  fi
  rm -rf "$out"; cp -R "$src" "$out"; rm -rf "$out/charts"; cp -RL "$dir/chart/charts" "$out/charts"
  "$REPO/scripts/ci/verify-chart-dependencies.sh" "$src" "$out/charts" >/dev/null \
    || die "chart ztd-openbao: the dependency built from Chart.lock into $dir does not match the committed deployment/helm/ztd-openbao/dependencies.sha256 (or $dir/chart/charts holds more than the pinned archives); remove $dir and rerun, and if it fails again, do not install (the repository serves other bytes for the pinned version)"
  touch "$out/.ready"
  echo "$out"
}

chart_path() {
  case $1 in
    umbrella) echo "$REPO/deployment/helm/ztd" ;;
    zone-policy) echo "$REPO/deployment/helm/zone-policy" ;;
    ztd-openbao) build_openbao_chart ;;
    spire-crds) fetch_spire_chart spire-crds "$SPIRE_CRDS_VERSION" "$SPIRE_CRDS_SHA256" ;;
    spire) fetch_spire_chart spire "$SPIRE_VERSION" "$SPIRE_SHA256" ;;
    istio-base) echo "$(fetch_istio)/base" ;;
    istiod) echo "$(fetch_istio)/istio-control/istio-discovery" ;;
    istio-cni) echo "$(fetch_istio)/istio-cni" ;;
    ztunnel) echo "$(fetch_istio)/ztunnel" ;;
  esac
}

# merged_values <release> <values> <facts> <out>: the values file with the zone facts set, each read
# from the zone document (the umbrella's defaults with the zone file on top); refuses when a fact is
# empty there, so a fact the umbrella leaves empty (zone.trustDomain, zone.name, zone.storageClass)
# must be stated by the zone file. A source written !<YAML> is that literal value, not a zone fact.
# Paths travel as arguments, never inside the source.
merged_values() {
  if [ "$2" = zone ]; then cp "$ZONE_VALUES" "$4"; return; fi
  zone_py "$@" <<'PY'
release, values_file, facts, out = ARGS
values = (yaml.safe_load(open(values_file)) if values_file else None) or {}
doc = zone_doc()
def put(target, v):
    node = values
    keys = target.split(".")
    for k in keys[:-1]:
        node = node.setdefault(k, {})
    node[keys[-1]] = v
missing = []
for pair in filter(None, facts.split(",")):
    target, source = pair.split("=", 1)
    if source.startswith("!"):
        put(target, yaml.safe_load(source[1:]))
        continue
    v = fact(doc, source)
    if v is None or str(v).strip() == "":
        missing.append(f"{source} (for {target})")
        continue
    put(target, v)
if missing:
    sys.exit(f"install-zone: release {release}: the zone file {ZONE} does not state the zone fact "
             + ", ".join(missing))
yaml.safe_dump(values, open(out, "w"), sort_keys=False)
PY
}

# mesh_coupling: the zone-policy admission policy pins the injected proxy's image and status port
# (proxySocketPolicy.proxyImage, .statusPort); they must equal what the istiod release injects
# (global.proxy.image, and global.proxy.statusPort, from the pinned Istio chart's defaults when
# istiod.yaml leaves it unset), or the policy refuses every injected plane pod. Refused here, before
# anything is rendered or installed, so a mismatch never reaches a cluster; CI runs it with render.
# Sidecar path only: the ambient path injects no proxy and renders no admission policy.
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

render() {
  local want=("$@") step release ns chart values facts extra path out name names=""
  zone_file
  zone_mesh
  say "Mesh path: $(path_label)"
  for step in "${PATH_STEPS[@]}"; do names="$names ${step%%|*}"; done
  # ${want[@]+...}: an empty array under set -u is an unbound variable on bash before 4.4 (macOS's
  # bash 3.2), as in scripts/lifecycle.sh.
  for name in ${want[@]+"${want[@]}"}; do
    [[ "$names " == *" $name "* ]] || die "render: unknown release '$name'; the releases are $(sed 's/^ //; s/ /, /g' <<<"$names")"
  done
  # The coupling of zone-policy to istiod is checked whenever either of them is rendered (sidecar).
  if [ "$MESH_PATH" = sidecar ] && { [ ${#want[@]} -eq 0 ] || [[ " ${want[*]} " == *" istiod "* ]] || [[ " ${want[*]} " == *" zone-policy "* ]]; }; then
    mesh_coupling
  fi
  [ -n "${RENDER_DIR:-}" ] && mkdir -p "$RENDER_DIR"
  for step in "${PATH_STEPS[@]}"; do
    IFS='|' read -r release ns chart values facts extra <<<"$step"
    if [ ${#want[@]} -gt 0 ] && [[ ! " ${want[*]+${want[*]}} " == *" $release "* ]]; then continue; fi
    ns=$(step_ns "$ns")
    merged_values "$release" "$values" "$facts" "$work/$release.values.yaml" || exit 1
    path=$(chart_path "$chart")
    out=${RENDER_DIR:+$RENDER_DIR/$release.yaml}
    if ! helm template "$release" "$path" --namespace "$ns" --values "$work/$release.values.yaml" \
        >"${out:-$work/$release.manifest.yaml}" 2>"$work/$release.err"; then
      cat "$work/$release.err" >&2
      die "release $release does not render"
    fi
    say "rendered $release ($(chart_label "$chart")) into $ns: $(grep -c '^kind:' "${out:-$work/$release.manifest.yaml}") objects"
  done
}

kctx() { kubectl --context "$KUBE_CONTEXT" "$@"; }

# plane namespaces of the zone: the two fixed planes and planes.extra, from the zone document
zone_namespaces() {
  zone_py <<'PY'
planes = zone_doc().get("planes") or {}
names = [planes["management"]["namespace"], planes["data"]["namespace"]]
names += [e["name"] for e in planes.get("extra") or []]
print(" ".join(names))
PY
}

# wait_ready <timeout-seconds> <namespace...>: every pod Ready (finished Job pods aside: Succeeded,
# or Failed attempts of a Job; a Job that failed has already failed its release's --wait-for-jobs)
wait_ready() {
  local deadline=$(( $(date +%s) + $1 )); shift
  local pending
  while :; do
    pending=$(for ns in "$@"; do
      kctx -n "$ns" get pods -o json | jq -r --arg ns "$ns" '.items[]
        | select(.status.phase != "Succeeded")
        | select((.status.phase == "Failed" and ([.metadata.ownerReferences[]? | select(.kind == "Job")] | length) > 0) | not)
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

install() {
  zone_file
  zone_mesh
  preflight
  # Every release is checked to render, with its zone facts, before the first one is installed.
  render >/dev/null
  plan
  local umbrella_ns
  umbrella_ns=$(IFS='|' read -r _ ns _ <<<"${PATH_STEPS[0]}"; echo "$ns")
  kctx get namespace "$umbrella_ns" >/dev/null 2>&1 || kctx create namespace "$umbrella_ns" >/dev/null
  local i=0 step release ns chart values facts extra line ok
  for step in "${PATH_STEPS[@]}"; do
    IFS='|' read -r release ns chart values facts extra <<<"$step"
    ns=$(step_ns "$ns")
    i=$((i + 1))
    merged_values "$release" "$values" "$facts" "$work/$release.values.yaml"
    say "step $i/${#PATH_STEPS[@]}: $release into $ns ..."
    line=$(LIFECYCLE_RELEASE=$release LIFECYCLE_NAMESPACE=$ns LIFECYCLE_CHART=$(chart_path "$chart") \
      LIFECYCLE_VALUES_FILE=$work/$release.values.yaml LIFECYCLE_TIMEOUT=$STEP_TIMEOUT \
      LIFECYCLE_WAIT_FOR_JOBS=$([ "$extra" = wait-for-jobs ] && echo true || echo false) \
      "$REPO/scripts/lifecycle.sh" deploy 2>"$work/$release.stderr" | grep '^RESULT_JSON=' | cut -d= -f2-) || true
    [ -n "$line" ] || line='{}'
    ok=$(jq -r '.ok // false' <<<"$line" 2>/dev/null || echo false)
    if [ "$ok" != true ]; then
      say "step $i/${#PATH_STEPS[@]} FAILED: release $release in $ns: $(jq -r '.error.message // "no result"' <<<"$line" 2>/dev/null)"
      jq -r '.output // empty' <<<"$line" 2>/dev/null | tail -20 >&2 || true
      cat "$work/$release.stderr" >&2
      exit 1
    fi
    say "step $i/${#PATH_STEPS[@]}: $release deployed, revision $(jq -r '.revision' <<<"$line")"
  done
  local namespaces
  namespaces=$(zone_namespaces)
  # shellcheck disable=SC2086 # one word per namespace
  wait_ready 600 $namespaces || die "the releases are deployed, but not every pod in $namespaces is Ready"
  say "zone installed: every pod in $namespaces is Ready"
}

uninstall() {
  zone_file
  zone_mesh
  preflight
  say "Mesh path: $(path_label)"
  local i step release ns rest line
  for (( i=${#PATH_STEPS[@]}-1; i>=0; i-- )); do
    IFS='|' read -r release ns rest <<<"${PATH_STEPS[$i]}"
    ns=$(step_ns "$ns")
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
  install) install ;;
  plan) plan ;;
  render) shift; render "$@" ;;
  uninstall) uninstall ;;
  help|-h|--help) usage ;;
  '') usage >&2; exit 2 ;;
  *) usage >&2; printf "install-zone: unknown command '%s'\n" "$1" >&2; exit 2 ;;
esac
