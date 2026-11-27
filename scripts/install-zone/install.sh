#!/usr/bin/env bash
# Install one cluster of the demonstrator from its zone file, as a sequence of Helm releases, each
# through the deployment lifecycle step (scripts/lifecycle.sh: server-side dry run, then helm upgrade
# --install --wait with rollback on failure), each waiting on the previous. The zone file's zone.role
# chooses the sequence.
#
# A participant zone (zone.role participant, the default: zone A, zone B, kind) is ten releases:
#
#   1 ztd          ztd-system    the umbrella: plane namespaces (with spire-system and istio-system),
#                                default deny, declared openings, allow matrix
#   2 spire-crds   spire-system  the SPIRE controller-manager's CRDs        (upstream, pinned)
#   3 spire        spire-system  server, agents, CSI driver, controller-manager (upstream, pinned)
#   4 istio-base   istio-system  Istio's CRDs                                (upstream, pinned)
#   5 istiod       istio-system  the mesh control plane, sidecar mode, SPIRE as certificate source
#   6 istio-cni    istio-system  the Istio CNI plugin, chained behind the cluster's CNI
#   7 zone-policy  istio-system  ClusterSPIFFEID, STRICT PeerAuthentication, the mesh default deny,
#                                one allow rule per allow-matrix row and intra-plane pair, the
#                                denial log, identity-band checks
#   8 ztd-openbao  ztd-mgmt      OpenBao, its bootstrap Job and verification hook, and the allow
#                                rules of its own pairs (project chart wrapping the upstream openbao
#                                chart, built from its Chart.lock, pinned by digest); after
#                                zone-policy, so its pods are created with a sidecar and an SVID
#   9 otel-node    ztd-otel-node the node collectors: a host-network DaemonSet that reads every pod's
#                                logs and scrapes its node's SPIRE agent on the loopback (upstream
#                                OpenTelemetry Collector chart, pinned)
#  10 otel-gateway ztd-mgmt      the zone gateway: OTLP from the workloads and the proxies, the SPIRE
#                                server and controller-manager scrapes, node readiness, the
#                                revocation probe (same chart); meshed, with an SVID
# Both telemetry releases export to the demonstrator cluster's entry (telemetryExport.entry) with the
# zone's client certificate, the Secret telemetryExport.clientSecret in ztd-otel-node and in the
# management namespace, which the demonstrator role's step telemetry-client-certs creates; `install`
# stops before otel-node when that Secret is missing (install the umbrella first, so the namespaces
# exist, then run telemetry-client-certs from the demonstrator side, then install again).
#
# The demonstrator cluster (zone.role demonstrator: IONOS; on kind ci/demonstrator-values.yaml, in
# the same cluster as the kind zone) is five releases and one step, all into the backends' namespace
# (observabilityBackends.namespace) except the umbrella:
#   1 ztd-demonstrator  ztd-system   the umbrella in its demonstrator role: the backends' namespace,
#                                    its default deny and the entry's listeners, nothing else
#   2 telemetry-issuers              the telemetry CA as cert-manager resources: root, server
#                                    certificate, one intermediate and one client certificate per zone
#                                    (project chart deployment/helm/telemetry-issuers; needs
#                                    cert-manager on the cluster)
#   3 otel-entry                     the receiving collector: one mutual-TLS listener per zone
#   4 prometheus                     metrics by remote write, the alert rules (upstream, pinned);
#                                    a rule in the firing state is the alert
#   5 jaeger                         traces, Badger on a persistent volume (upstream, pinned)
#     telemetry-client-certs         copies each zone's client certificate into that zone, when
#                                    TELEMETRY_ZONES names the zones (also a command of its own)
# The logs of every zone end in files on the entry's volume (otel-entry-logs, one file per zone,
# rotated by size); no log query service is installed.
#
# Usage:
#   scripts/install-zone/install.sh install [release...]
#                                                    install or upgrade the zone (idempotent); with
#                                                    release names, only those, in plan order
#   scripts/install-zone/install.sh plan             list the steps; touches no cluster
#   scripts/install-zone/install.sh render [release...]
#                                                    render the releases from the pinned charts and
#                                                    the merged values; touches no cluster (CI);
#                                                    an unknown release name is an error
#   scripts/install-zone/install.sh uninstall        uninstall in reverse order (the last release
#                                                    first)
#   scripts/install-zone/install.sh telemetry-client-certs
#                                                    demonstrator role: copy each zone's client
#                                                    certificate into that zone (TELEMETRY_ZONES)
#   scripts/install-zone/install.sh help             this text (also -h, --help)
#
# Environment:
#   ZONE_VALUES   zone file             (default: deployment/helm/ztd/ci/values.yaml, the kind zone)
#   KUBE_CONTEXT  kubectl context       (default: kind-ztd)
#   STEP_TIMEOUT  timeout per release   (default: 10m)
#   RENDER_DIR    with `render`, write each release's manifest there as <release>.yaml
#   INSTALL_ZONE_CACHE  where the pinned charts and the built OpenBao dependency are kept
#                       (default: ~/.cache/ztd-install-zone)
#   TELEMETRY_ZONES     demonstrator role: the zones whose client certificate telemetry-client-certs
#                       copies, as <zone>=<kubectl context>[,...] (kind: kind=kind-ztd); each
#                       certificate goes into ztd-otel-node and the management namespace
#                       (TELEMETRY_ZONE_MGMT_NAMESPACE, default ztd-mgmt) of that context; the key
#                       passes through a temporary directory that is removed, never the repository
#
# Mesh settings: the installer installs sidecar mode with the default, unrevisioned istiod (and the
# Istio CNI plugin with ambient off). It refuses, before it renders or installs anything, a zone
# file whose mesh.mode is anything but sidecar (absent counts as sidecar) or whose mesh.revision is
# set: the umbrella would label the plane namespaces for an injector this installer never installs.
# It also refuses, before it renders istiod or zone-policy, a zone-policy whose
# proxySocketPolicy.proxyImage or statusPort differs from istiod's global.proxy.image or statusPort:
# the admission policy would refuse every injected plane pod. And it refuses, once zone-policy is
# rendered, a zone whose allow rules are not exactly one per row of the umbrella's allowMatrix and
# intraPlanePairs, each with the row's namespaces, selector, principal (or source namespace for a
# whole-plane source) and ports (pairs_coupling): the mesh layer must render what the network layer
# declares, and nothing else.
#
# The umbrella reads the whole zone file. The other releases read their upstream values file under
# deployment/helm/values/ (zone-policy and ztd-openbao: their chart defaults) merged with the zone
# facts they need, a scalar or a structured value (zone-policy's `pairs`: the merged allowMatrix rows
# followed by the intraPlanePairs, in the pair shape of zone-policy), written into the generated
# values file of the release, never with --set. The zone facts are read from the umbrella's defaults
# (deployment/helm/ztd/values.yaml) with the zone file on top, so a fact the umbrella defaults (the
# management namespace, the Cilium switch) needs no repeating; a fact the umbrella leaves empty
# (zone.trustDomain, zone.name, zone.storageClass) and the zone file does not state stops the run
# before anything is rendered. ztd-openbao goes into the management namespace of the same merge.
# Every namespace the releases install into is created by the umbrella; the one namespace this
# script creates is the umbrella's own release namespace, which holds only the release record and
# its verification job. Needs helm, kubectl, jq, curl, python3 with PyYAML, and sha256sum or shasum.
# No release is placed on a node: the scheduler places every pod, ztd-openbao's included.
#
# The telemetry releases need two zone facts: the entry (telemetryExport.entry.address, or
# .inCluster on kind) and the revocation status-list URL (telemetryExport.revocationStatusListUrl).
# A participant zone file without either is refused before anything is rendered, whenever the run
# includes otel-node or otel-gateway. A demonstrator zone file on a cluster with a LoadBalancer is
# refused while observabilityBackends.entry.sourceRanges is empty.
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ZONE_VALUES=${ZONE_VALUES:-$REPO/deployment/helm/ztd/ci/values.yaml}
KUBE_CONTEXT=${KUBE_CONTEXT:-kind-ztd}
STEP_TIMEOUT=${STEP_TIMEOUT:-10m}
CACHE=${INSTALL_ZONE_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/ztd-install-zone}
VALUES_DIR=$REPO/deployment/helm/values

# ---- Pins (docs/dependencies.md). An upgrade changes a version and its digest here, then reruns
# ---- scripts/verify-mesh-identity/verify.sh; every Istio minor also reruns the ADR-0009 check.
# ---- The observability charts and images are pinned in scripts/tools/pins.env (exported for the
# ---- derived values below); an upgrade there reruns scripts/verify-observability/verify.sh.
set -a
# shellcheck source-path=SCRIPTDIR source=../tools/pins.env
. "$REPO/scripts/tools/pins.env"
set +a
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
# The upstream openbao chart of ztd-openbao: its version in the project chart's Chart.lock, its
# archive's sha256 in deployment/helm/ztd-openbao/dependencies.sha256 (build_openbao_chart).

# ---- The steps: release, namespace, chart, values file, zone facts (<values key>=<zone key>,...),
# ---- extra lifecycle settings. "zone" as values file means the zone file itself; no values file
# ---- means the chart's defaults. A zone key written "<key>+<key>" is the concatenation of those
# ---- lists in the pair shape of zone-policy (merged_values); an empty list is a fact, not a gap.
PARTICIPANT_STEPS=(
  "ztd|ztd-system|umbrella|zone||"
  "spire-crds|spire-system|spire-crds|$VALUES_DIR/spire-crds.yaml||"
  "spire|spire-system|spire|$VALUES_DIR/spire.yaml|global.spire.trustDomain=zone.trustDomain,global.spire.clusterName=zone.name,global.spire.persistence.storageClass=zone.storageClass,global.spire.caSubject.commonName=zone.trustDomain|"
  "istio-base|istio-system|istio-base|$VALUES_DIR/istio-base.yaml||"
  "istiod|istio-system|istiod|$VALUES_DIR/istiod.yaml|meshConfig.trustDomain=zone.trustDomain|"
  "istio-cni|istio-system|istio-cni|$VALUES_DIR/istio-cni.yaml||"
  "zone-policy|istio-system|zone-policy||trustDomain=zone.trustDomain,planes.management.namespace=planes.management.namespace,planes.data.namespace=planes.data.namespace,pairs=allowMatrix+intraPlanePairs|wait-for-jobs"
  "ztd-openbao|=planes.management.namespace|ztd-openbao||managementNamespace=planes.management.namespace,openbao.global.namespace=planes.management.namespace,openbao.server.dataStorage.storageClass=zone.storageClass,cilium.enabled=cni.cilium.enabled,trustDomain=zone.trustDomain,mesh.mode=mesh.mode|wait-for-jobs"
  "otel-node|ztd-otel-node|otel-collector|$VALUES_DIR/otel-node.yaml||"
  "otel-gateway|=planes.management.namespace|otel-collector|$VALUES_DIR/otel-gateway.yaml||"
)
DEMONSTRATOR_STEPS=(
  "ztd-demonstrator|ztd-system|umbrella|zone||"
  "telemetry-issuers|=observabilityBackends.namespace|telemetry-issuers||serverName=observabilityBackends.entry.serverName,zones=observabilityBackends.entry.zones|"
  "otel-entry|=observabilityBackends.namespace|otel-collector|$VALUES_DIR/otel-entry.yaml||"
  "prometheus|=observabilityBackends.namespace|prometheus|$VALUES_DIR/prometheus.yaml|server.retention=observabilityBackends.retention,server.retentionSize=observabilityBackends.retentionSize,server.persistentVolume.size=observabilityBackends.volumes.prometheus,server.persistentVolume.storageClass=zone.storageClass|"
  "jaeger|=observabilityBackends.namespace|jaeger|$VALUES_DIR/jaeger.yaml||"
)
# The releases of the zone file's role (load_steps, once the zone file is known).
STEPS=()
TELEMETRY_RELEASES=" otel-node otel-gateway "
# A namespace written "=<zone key>" is that zone fact (the management namespace of ztd-openbao and
# otel-gateway, the backends' namespace of the demonstrator releases).

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

say() { printf '%s\n' "$*"; }
die() { printf 'install-zone: %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,/^# refused while observabilityBackends.entry.sourceRanges is empty\.$/p' "$0" | sed 's/^# \{0,1\}//'; }

# zone_file: the zone file must exist before anything reads it.
zone_file() {
  [ -f "$ZONE_VALUES" ] || die "zone file not found: $ZONE_VALUES"
  load_steps
}

# load_steps: the releases of the zone file's role (zone.role; participant when absent).
ROLE=""
load_steps() {
  [ -n "$ROLE" ] && return 0
  ROLE=$(zone_fact zone.role) || exit 1
  case ${ROLE:-participant} in
    participant) ROLE=participant; STEPS=("${PARTICIPANT_STEPS[@]}") ;;
    demonstrator) STEPS=("${DEMONSTRATOR_STEPS[@]}") ;;
    *) die "the zone file sets zone.role \"$ROLE\"; it is participant or demonstrator" ;;
  esac
}

# telemetry_facts [release...]: the zone facts the telemetry releases need, refused before anything
# is rendered. Participant: when the run includes otel-node or otel-gateway (all releases when none
# is named), the entry (address or inCluster), the revocation status-list URL, the node collectors'
# namespace without the mesh, and the SPIRE metrics lane. Demonstrator: on a cluster with a
# LoadBalancer, the zones' egress addresses.
telemetry_facts() {
  local want=" $* " r include=false
  if [ "$ROLE" = participant ]; then
    if [ $# -eq 0 ]; then include=true; else
      for r in $TELEMETRY_RELEASES; do [[ "$want" == *" $r "* ]] && include=true; done
    fi
    [ "$include" = true ] || return 0
  fi
  zone_py "$ROLE" <<'PY' || exit 1
role = ARGS[0]
doc = zone_doc()
missing = []
if role == "participant":
    te = fact(doc, "telemetryExport") or {}
    entry = te.get("entry") or {}
    inc = entry.get("inCluster") or {}
    if not str(entry.get("address") or "").strip() and not inc.get("namespace"):
        missing.append("telemetryExport.entry.address (the demonstrator cluster's entry as a /32 CIDR; "
                       "telemetryExport.entry.inCluster on kind)")
    if not str(te.get("revocationStatusListUrl") or "").strip():
        missing.append("telemetryExport.revocationStatusListUrl (the revocation status list the zone gateway probes)")
    extra = (fact(doc, "planes") or {}).get("extra") or []
    if not any(e.get("name") == "ztd-otel-node" and str(e.get("mesh")).lower() == "false" for e in extra):
        missing.append("planes.extra entry ztd-otel-node with mesh: false (the node collectors' namespace)")
    if not (fact(doc, "networkPolicy.observabilityScrape") or {}).get("enabled"):
        missing.append("networkPolicy.observabilityScrape.enabled: true (the zone gateway's SPIRE metrics lane)")
else:
    lb = fact(doc, "zone.loadBalancer.type")
    if lb and lb != "none" and not (fact(doc, "observabilityBackends.entry.sourceRanges") or []):
        missing.append("observabilityBackends.entry.sourceRanges (the zones' egress addresses; the entry "
                       "is never published on a LoadBalancer without them)")
if missing:
    sys.exit(f"install-zone: the zone file {ZONE} does not state, for the telemetry releases: "
             + "; ".join(missing) + ". Nothing was rendered or installed.")
PY
}

# zone_mesh: the zone file's mesh settings must be the ones this installer installs, sidecar mode
# with the default, unrevisioned istiod; anything else is refused before anything is rendered or
# installed. Read with PyYAML, as merged_values reads the zone facts.
zone_mesh() {
  python3 - "$ZONE_VALUES" <<'PY' || exit 1
import sys, yaml
zone_file = sys.argv[1]
zone = yaml.safe_load(open(zone_file)) or {}
mesh = zone.get("mesh") if isinstance(zone, dict) else None
mesh = mesh if isinstance(mesh, dict) else {}
mode = mesh.get("mode")
revision = mesh.get("revision")
scope = "this installer installs the default, unrevisioned istiod in sidecar mode only"
if mode is not None and str(mode) != "sidecar":
    sys.exit(f'install-zone: the zone file sets mesh.mode "{mode}", but {scope}; '
             'another mesh mode needs its own installer support (a zone without a mesh installs '
             'the umbrella alone through scripts/lifecycle.sh)')
if revision is not None and str(revision).strip() != "":
    sys.exit(f'install-zone: the zone file sets mesh.revision "{revision}", but {scope}; '
             'a revisioned mesh needs its own installer support')
PY
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
  [ "$ROLE" = participant ] && zone_mesh
  say "Zone file: ${ZONE_VALUES#"$REPO"/}   role: $ROLE   context: $KUBE_CONTEXT"
  local i=0 step release ns chart values facts extra label
  for step in "${STEPS[@]}"; do
    IFS='|' read -r release ns chart values facts extra <<<"$step"
    ns=$(step_ns "$ns")
    i=$((i + 1))
    if [ "$values" = zone ]; then label="the zone file"
    elif [ -n "$values" ]; then label=${values#"$REPO"/}
    else label="chart defaults"; fi
    printf '  %d/%d  %-17s into %-17s chart %-12s values %s%s%s\n' "$i" "${#STEPS[@]}" "$release" "$ns" \
      "$(chart_label "$chart")" "$label" "${facts:+ + zone facts ${facts//,/ }}" "${extra:+ ($extra)}"
  done
  if [ "$ROLE" = demonstrator ]; then
    say "  then telemetry-client-certs: ${TELEMETRY_ZONES:-not run (TELEMETRY_ZONES is empty)}"
    say "  the logs of every zone are exported to files on the volume otel-entry-logs; no log query service is installed"
  fi
}

chart_label() {
  case $1 in
    umbrella) echo "deployment/helm/ztd" ;;
    zone-policy) echo "deployment/helm/zone-policy" ;;
    ztd-openbao) echo "deployment/helm/ztd-openbao" ;;
    spire-crds) echo "spire-crds $SPIRE_CRDS_VERSION" ;;
    spire) echo "spire $SPIRE_VERSION" ;;
    istio-base) echo "base $ISTIO_VERSION" ;;
    istiod) echo "istiod $ISTIO_VERSION" ;;
    istio-cni) echo "cni $ISTIO_VERSION" ;;
    telemetry-issuers) echo "deployment/helm/telemetry-issuers" ;;
    otel-collector) echo "opentelemetry-collector $OTEL_COLLECTOR_CHART_VERSION" ;;
    prometheus) echo "prometheus $PROMETHEUS_CHART_VERSION" ;;
    jaeger) echo "jaeger $JAEGER_CHART_VERSION" ;;
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

# fetch_chart <repo> <chart> <version> <sha256>: an upstream chart of pins.env into the cache,
# verified by the digest its repository's index publishes.
fetch_chart() {
  local file="$CACHE/$2-$3.tgz"
  if [ ! -f "$file" ] || [ "$(sha256 "$file")" != "$4" ]; then
    mkdir -p "$CACHE"
    helm pull "$2" --repo "$1" --version "$3" --destination "$work" >/dev/null \
      || die "could not fetch chart $2 $3 from $1"
    mv "$work/$2-$3.tgz" "$file"
  fi
  [ "$(sha256 "$file")" = "$4" ] || die "chart $2 $3: digest $(sha256 "$file") is not the pinned $4"
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
    telemetry-issuers) echo "$REPO/deployment/helm/telemetry-issuers" ;;
    otel-collector) fetch_chart "$OTEL_COLLECTOR_CHART_REPO" opentelemetry-collector "$OTEL_COLLECTOR_CHART_VERSION" "$OTEL_COLLECTOR_CHART_SHA256" ;;
    prometheus) fetch_chart "$PROMETHEUS_CHART_REPO" prometheus "$PROMETHEUS_CHART_VERSION" "$PROMETHEUS_CHART_SHA256" ;;
    jaeger) fetch_chart "$JAEGER_CHART_REPO" jaeger "$JAEGER_CHART_VERSION" "$JAEGER_CHART_SHA256" ;;
  esac
}

# merged_values <release> <values> <facts> <out>: the values file with the zone facts set, each read
# from the zone document (the umbrella's defaults with the zone file on top); refuses when a fact is
# empty there, so a fact the umbrella leaves empty (zone.trustDomain, zone.name, zone.storageClass)
# must be stated by the zone file. A fact "<key>+<key>" (zone-policy's pairs) is the concatenation of
# those lists of rows, each turned into zone-policy's pair shape: the caller's plane or namespace
# with its serviceAccount, or wholePlane when its podSelector is {} (the row's selector, enforcedBy
# and the destination's serviceAccount stay in the umbrella); the destination's plane or namespace,
# podSelector and ports; and the row's l7Owner when it has one (every allowMatrix row; an
# intraPlanePairs entry has none and zone-policy defaults it to sidecar). Then the derived values of
# the observability releases: the pinned images of scripts/tools/pins.env, and what follows from the
# zone file beyond a single fact (the collectors' exporter, the entry's listeners per zone, the
# silent-zone rules per zone, the volumes). Paths travel as arguments, never inside the source.
merged_values() {
  if [ "$2" = zone ]; then cp "$ZONE_VALUES" "$4"; return; fi
  zone_py "$@" <<'PY'
release, values_file, facts, out = ARGS
values = (yaml.safe_load(open(values_file)) if values_file else None) or {}
doc = zone_doc()
def as_pairs(rows, source):
    pairs = []
    for row in rows:
        f, t = row.get("from") or {}, row.get("to") or {}
        src = {k: f[k] for k in ("plane", "namespace") if f.get(k)}
        if f.get("podSelector"):
            if not f.get("serviceAccount"):
                sys.exit(f"install-zone: {source} row {row.get('name')}: from.podSelector names a workload "
                         "but from.serviceAccount is not set, so the mesh rule could not name its caller")
            src["serviceAccount"] = f["serviceAccount"]
        else:
            src["wholePlane"] = True
        dst = {k: t[k] for k in ("plane", "namespace", "podSelector") if t.get(k)}
        if t.get("ports"):
            dst["ports"] = [dict({"port": p["port"]}, **({"protocol": p["protocol"]} if p.get("protocol") else {}))
                            for p in t["ports"]]
        pair = {"name": row.get("name"), "from": src, "to": dst}
        if row.get("l7Owner"):
            pair["l7Owner"] = row["l7Owner"]
        pairs.append(pair)
    return pairs
def put(target, v):
    node = values
    keys = target.split(".")
    for k in keys[:-1]:
        node = node.setdefault(k, {})
    node[keys[-1]] = v
missing = []
for pair in filter(None, facts.split(",")):
    target, source = pair.split("=")
    if "+" in source:
        lists = [(key, fact(doc, key)) for key in source.split("+")]
        absent = [key for key, v in lists if not isinstance(v, list)]
        if absent:
            missing.append(" and ".join(absent) + f" (lists, for {target})")
            continue
        put(target, [p for key, v in lists for p in as_pairs(v, key)])
        continue
    v = fact(doc, source)
    if v is None or str(v).strip() == "":
        missing.append(f"{source} (for {target})")
        continue
    put(target, v)
if missing:
    sys.exit(f"install-zone: release {release}: the zone file {ZONE} does not state the zone fact "
             + ", ".join(missing))
import os

def image(var):
    ref = os.environ[var]
    name, digest = ref.split("@", 1)
    repo, tag = name.rsplit(":", 1)
    return repo, tag, digest

te = fact(doc, "telemetryExport") or {}
ob = fact(doc, "observabilityBackends") or {}
if release in ("otel-node", "otel-gateway", "otel-entry"):
    repo, tag, digest = image("OTEL_COLLECTOR_IMAGE")
    values.setdefault("image", {}).update(repository=repo, tag=tag, digest=digest)
if release in ("otel-node", "otel-gateway"):
    entry = te.get("entry") or {}
    inc = entry.get("inCluster") or {}
    host = inc.get("host") or str(entry.get("address") or "").split("/")[0]
    exporter = values["config"]["exporters"]["otlp/entry"]
    exporter["endpoint"] = f"{host}:{entry['port']}"
    exporter["tls"]["server_name_override"] = entry["serverName"]
    for vol in values.get("extraVolumes") or []:
        if vol["name"] == "telemetry-client":
            vol["secret"]["secretName"] = te["clientSecret"]
    if release == "otel-node" and inc.get("namespace"):
        # kind only: the demonstrator role shares the cluster; its pods are not the zone's.
        values["config"]["receivers"]["filelog"]["exclude"] = [f"/var/log/pods/{inc['namespace']}_*/*/*.log"]
    if release == "otel-gateway":
        values["config"]["receivers"]["http_check/revocation"]["targets"][0]["endpoint"] = te["revocationStatusListUrl"]
if release == "otel-entry":
    e = ob.get("entry") or {}
    cfg = values["config"]
    lb = fact(doc, "zone.loadBalancer.type") or "none"
    values["service"]["type"] = "ClusterIP" if lb == "none" else "LoadBalancer"
    values["service"]["loadBalancerSourceRanges"] = list(e.get("sourceRanges") or [])
    # The log export: one file per zone on the volume otel-entry-logs, rotated by size. The size at
    # which a file rotates is the volume shared out over every zone's current file and backups, with a
    # tenth kept free.
    lx = values.pop("logExport")
    size = str((ob.get("volumes") or {}).get("logs") or "")
    unit = {"Mi": 1, "Gi": 1024, "Ti": 1024 * 1024}.get(size[-2:])
    if not unit or not size[:-2].isdigit():
        sys.exit(f"install-zone: release otel-entry: observabilityBackends.volumes.logs ({size!r}) is not a size in Mi, Gi or Ti")
    files = len(e["zones"]) * (int(lx["maxBackups"]) + 1)
    rotate_mb = int(int(size[:-2]) * unit * 0.9 // files)
    if rotate_mb < 1:
        sys.exit(f"install-zone: release otel-entry: the logs volume ({size}) is too small for {files} files")
    for obj in values.get("extraManifests") or []:
        if obj.get("kind") == "PersistentVolumeClaim":
            obj["spec"]["storageClassName"] = fact(doc, "zone.storageClass")
            obj["spec"]["resources"]["requests"]["storage"] = size
    for z in e["zones"]:
        n, port = z["name"], int(z["port"])
        if len(f"tcp-{n}") > 15:
            sys.exit(f"install-zone: zone name {n} is too long for a port name (tcp-<zone>, 15 characters)")
        cfg["receivers"][f"otlp/{n}"] = {"protocols": {"grpc": {"endpoint": f"0.0.0.0:{port}", "tls": {
            "cert_file": "/etc/ztd-entry/server/tls.crt", "key_file": "/etc/ztd-entry/server/tls.key",
            "client_ca_file": f"/etc/ztd-entry/zones/{n}/ca.crt", "min_version": "1.3"}}}}
        # The zone is the listener's: set on the resource, removed wherever the client may have put one.
        cfg["processors"][f"transform/zone-{n}"] = {"error_mode": "ignore",
            "trace_statements": [f'set(resource.attributes["zone"], "{n}")', 'delete_key(span.attributes, "zone")'],
            "metric_statements": [f'set(resource.attributes["zone"], "{n}")', 'delete_key(datapoint.attributes, "zone")'],
            "log_statements": [f'set(resource.attributes["zone"], "{n}")', 'delete_key(log.attributes, "zone")']}
        cfg["exporters"][f"file/{n}"] = {"path": f"{lx['directory']}/{n}.jsonl", "format": "json",
            "flush_interval": "1s",
            "rotation": {"max_megabytes": rotate_mb, "max_backups": int(lx["maxBackups"]), "localtime": False}}
        for signal, exporter in (("traces", "otlp/jaeger"), ("metrics", "prometheus_remote_write"), ("logs", f"file/{n}")):
            cfg["service"]["pipelines"][f"{signal}/{n}"] = {"receivers": [f"otlp/{n}"],
                "processors": ["memory_limiter", f"transform/zone-{n}", "batch"], "exporters": [exporter]}
        values["ports"][f"tcp-{n}"] = {"enabled": True, "containerPort": port, "servicePort": port, "protocol": "TCP"}
        values["extraVolumes"].append({"name": f"ca-{n}", "secret": {"secretName": f"ztd-telemetry-{n}-ca",
            "defaultMode": 0o444, "items": [{"key": "tls.crt", "path": "ca.crt"}]}})
        values["extraVolumeMounts"].append({"name": f"ca-{n}", "mountPath": f"/etc/ztd-entry/zones/{n}", "readOnly": True})
if release == "prometheus":
    repo, tag, digest = image("PROMETHEUS_IMAGE")
    values["server"]["image"].update(repository=repo, digest=digest)
    repo, tag, digest = image("CONFIG_RELOADER_IMAGE")
    values["configmapReload"]["prometheus"]["image"].update(repository=repo, digest=digest)
    # A silent zone: no uptime sample of its gateway for 15 s (the window is the pending period;
    # for 5 s on top), one rule per zone of the entry, so a zone that never reported is caught too.
    rules = [{"alert": "ZoneSilent",
              "expr": f'absent_over_time({{__name__=~"otelcol_process_uptime.*",collector="otel-gateway",ztd_source="collector",zone="{z["name"]}"}}[15s])',
              "for": "5s",
              "labels": {"severity": "critical", "zone": z["name"], "target": "zone-gateway", "ztd_source": "collector"},
              "annotations": {"summary": f"No telemetry from {z['name']}: its zone gateway, its export path or the zone is down"}}
             for z in (ob.get("entry") or {}).get("zones") or []]
    values["serverFiles"]["alerting_rules.yml"]["groups"].append({"name": "ztd-silent-zones", "interval": "5s", "rules": rules})
if release == "jaeger":
    repo, tag, digest = image("JAEGER_IMAGE")
    values["jaeger"]["image"].update(repository=repo, tag=tag, digest=digest)
    for obj in values.get("extraObjects") or []:
        if obj.get("kind") == "PersistentVolumeClaim":
            obj["spec"]["storageClassName"] = fact(doc, "zone.storageClass")
            obj["spec"]["resources"]["requests"]["storage"] = (ob.get("volumes") or {}).get("jaeger")
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

# pairs_coupling <zone-policy manifest>: the allow rules zone-policy rendered must be exactly one per
# row of the umbrella's allowMatrix and intraPlanePairs (read from the zone document, not from the
# values the installer handed over, so a wrong copy is caught too): AuthorizationPolicy allow-<name>
# in the destination's namespace, selecting the row's to.podSelector, admitting the principal
# <trust domain>/ns/<source namespace>/sa/<from.serviceAccount> (or the source namespace when the
# row's from.podSelector is {}), on the row's ports, and nothing else in its rule. Refused otherwise,
# naming each row that differs; CI runs it with every render of zone-policy.
pairs_coupling() {
  zone_py "$1" <<'PY' || exit 1
manifest = ARGS[0]
doc = zone_doc()
td = fact(doc, "zone.trustDomain")
planes = doc.get("planes") or {}
def ns(e):
    return e.get("namespace") or (planes.get(e.get("plane")) or {}).get("namespace")
rows = [("allowMatrix", r) for r in (doc.get("allowMatrix") or [])] + \
       [("intraPlanePairs", r) for r in (doc.get("intraPlanePairs") or [])]
want = {}
for where, r in rows:
    f, t = r.get("from") or {}, r.get("to") or {}
    source = ({"namespaces": [ns(f)]} if not f.get("podSelector")
              else {"principals": [f"{td}/ns/{ns(f)}/sa/{f.get('serviceAccount')}"]})
    rule = {"from": [{"source": source}]}
    if t.get("ports"):
        rule["to"] = [{"operation": {"ports": [str(p["port"]) for p in t["ports"]]}}]
    want["allow-" + str(r.get("name"))] = (where, {"namespace": ns(t), "selector": {"matchLabels": t.get("podSelector") or {}},
                                                  "action": "ALLOW", "rules": [rule]})
got = {}
for d in yaml.safe_load_all(open(manifest)):
    if d and d.get("kind") == "AuthorizationPolicy" and d["metadata"]["name"].startswith("allow-"):
        spec = d.get("spec") or {}
        got[d["metadata"]["name"]] = {"namespace": d["metadata"].get("namespace"), "selector": spec.get("selector"),
                                      "action": spec.get("action", "ALLOW"), "rules": spec.get("rules")}
bad = []
for name, (where, w) in want.items():
    if name not in got:
        bad.append(f"{where} row {name[6:]}: no AuthorizationPolicy {name} rendered")
    elif got[name] != w:
        bad.append(f"{where} row {name[6:]}: {name} renders {got[name]}, the row asks for {w}")
bad += [f"{name}: rendered by zone-policy but no allowMatrix row or intraPlanePairs entry declares it"
        for name in sorted(set(got) - set(want))]
if bad:
    sys.exit("install-zone: the mesh allow rules of zone-policy do not match the umbrella's pairs: "
             + "; ".join(bad))
matrix = sum(1 for w, _ in rows if w == "allowMatrix")
print(f"pairs coupling: {len(got)} allow rules of zone-policy match the {len(want)} declared pairs "
      f"({matrix} allowMatrix rows, {len(want) - matrix} intraPlanePairs)")
PY
}

render() {
  local want=("$@") step release ns chart values facts extra path out name names=""
  zone_file
  [ "$ROLE" = participant ] && zone_mesh
  telemetry_facts ${want[@]+"${want[@]}"}
  for step in "${STEPS[@]}"; do names="$names ${step%%|*}"; done
  # ${want[@]+...}: an empty array under set -u is an unbound variable on bash before 4.4 (macOS's
  # bash 3.2), as in scripts/lifecycle.sh.
  for name in ${want[@]+"${want[@]}"}; do
    [[ "$names " == *" $name "* ]] || die "render: unknown release '$name'; the releases are $(sed 's/^ //; s/ /, /g' <<<"$names")"
  done
  # The coupling of zone-policy to istiod is checked whenever either of them is rendered.
  if [ "$ROLE" = participant ] && { [ ${#want[@]} -eq 0 ] || [[ " ${want[*]} " == *" istiod "* ]] || [[ " ${want[*]} " == *" zone-policy "* ]]; }; then
    mesh_coupling
  fi
  [ -n "${RENDER_DIR:-}" ] && mkdir -p "$RENDER_DIR"
  for step in "${STEPS[@]}"; do
    IFS='|' read -r release ns chart values facts extra <<<"$step"
    if [ ${#want[@]} -gt 0 ] && [[ ! " ${want[*]+${want[*]}} " == *" $release "* ]]; then continue; fi
    ns=$(step_ns "$ns")
    merged_values "$release" "$values" "$facts" "$work/$release.values.yaml" || exit 1
    path=$(chart_path "$chart") || exit 1
    out=${RENDER_DIR:+$RENDER_DIR/$release.yaml}
    if ! helm template "$release" "$path" --namespace "$ns" --values "$work/$release.values.yaml" \
        >"${out:-$work/$release.manifest.yaml}" 2>"$work/$release.err"; then
      cat "$work/$release.err" >&2
      die "release $release does not render"
    fi
    say "rendered $release ($(chart_label "$chart")) into $ns: $(grep -c '^kind:' "${out:-$work/$release.manifest.yaml}") objects"
    # The mesh layer's rows are checked against the network layer's whenever zone-policy is rendered.
    if [ "$release" = zone-policy ]; then pairs_coupling "${out:-$work/$release.manifest.yaml}"; fi
  done
}

kctx() { kubectl --context "$KUBE_CONTEXT" "$@"; }

# plane namespaces of the zone: the two fixed planes and planes.extra, from the zone document
zone_namespaces() {
  zone_py "$ROLE" <<'PY'
doc = zone_doc()
if ARGS[0] == "demonstrator":
    print(fact(doc, "observabilityBackends.namespace"))
else:
    planes = doc.get("planes") or {}
    names = [planes["management"]["namespace"], planes["data"]["namespace"]]
    names += [e["name"] for e in planes.get("extra") or []]
    print(" ".join(names))
PY
}

# client_secret_present: the zone's client-certificate Secret is in ztd-otel-node and in the
# management namespace (created by the demonstrator role's step telemetry-client-certs).
client_secret_present() {
  local secret mgmt ns missing=""
  secret=$(zone_fact telemetryExport.clientSecret); mgmt=$(zone_fact planes.management.namespace)
  for ns in ztd-otel-node "$mgmt"; do
    kctx -n "$ns" get secret "$secret" >/dev/null 2>&1 || missing="$missing $ns/$secret"
  done
  [ -z "$missing" ] && return 0
  say "the zone's telemetry client certificate is missing:$missing"
  say "  run, against the demonstrator cluster: ZONE_VALUES=<its zone file> KUBE_CONTEXT=<its context> \\"
  say "    TELEMETRY_ZONES=$(zone_fact zone.name)=$KUBE_CONTEXT scripts/install-zone/install.sh telemetry-client-certs"
  say "  then rerun this install (the releases already installed are left as they are)"
  return 1
}

# cert_manager_present: the demonstrator role's issuers need cert-manager on the cluster.
cert_manager_present() {
  kctx get crd certificates.cert-manager.io issuers.cert-manager.io >/dev/null 2>&1 \
    || die "cert-manager is not installed on $KUBE_CONTEXT (no certificates.cert-manager.io CRD); the telemetry issuers need it (on kind: scripts/dev/kind-cert-manager-up.sh)"
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
  local want=("$@") names="" name s
  zone_file
  [ "$ROLE" = participant ] && zone_mesh
  for s in "${STEPS[@]}"; do names="$names ${s%%|*}"; done
  for name in ${want[@]+"${want[@]}"}; do
    [[ "$names " == *" $name "* ]] || die "install: unknown release '$name'; the releases are $(sed 's/^ //; s/ /, /g' <<<"$names")"
  done
  telemetry_facts ${want[@]+"${want[@]}"}
  preflight
  # Every release is checked to render, with its zone facts, before the first one is installed; the
  # verdict of the pairs coupling is kept in the log.
  render ${want[@]+"${want[@]}"} >"$work/render.log"
  grep '^pairs coupling:' "$work/render.log" || true
  plan
  [ "$ROLE" = demonstrator ] && cert_manager_present
  local umbrella_ns
  umbrella_ns=$(IFS='|' read -r _ ns _ <<<"${STEPS[0]}"; echo "$ns")
  kctx get namespace "$umbrella_ns" >/dev/null 2>&1 || kctx create namespace "$umbrella_ns" >/dev/null
  local i=0 step release ns chart values facts extra line ok
  for step in "${STEPS[@]}"; do
    IFS='|' read -r release ns chart values facts extra <<<"$step"
    i=$((i + 1))
    if [ ${#want[@]} -gt 0 ] && [[ ! " ${want[*]} " == *" $release "* ]]; then continue; fi
    ns=$(step_ns "$ns")
    if [ "$ROLE" = participant ] && [ "$release" = otel-node ] && ! client_secret_present; then
      die "stopped before $release: the zone's telemetry client certificate is not in the zone yet"
    fi
    merged_values "$release" "$values" "$facts" "$work/$release.values.yaml" || exit 1
    say "step $i/${#STEPS[@]}: $release into $ns ..."
    line=$(LIFECYCLE_RELEASE=$release LIFECYCLE_NAMESPACE=$ns LIFECYCLE_CHART=$(chart_path "$chart") \
      LIFECYCLE_VALUES_FILE=$work/$release.values.yaml LIFECYCLE_TIMEOUT=$STEP_TIMEOUT \
      LIFECYCLE_WAIT_FOR_JOBS=$([ "$extra" = wait-for-jobs ] && echo true || echo false) \
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
  done
  if [ ${#want[@]} -gt 0 ]; then
    # A subset: each release waited for its own resources; the rest of the zone is not judged here.
    say "installed: ${want[*]}"
  else
    local namespaces
    namespaces=$(zone_namespaces)
    # shellcheck disable=SC2086 # one word per namespace
    wait_ready 600 $namespaces || die "the releases are deployed, but not every pod in $namespaces is Ready"
    say "$ROLE installed: every pod in $namespaces is Ready"
  fi
  if [ "$ROLE" = demonstrator ] && [ ${#want[@]} -eq 0 ]; then
    if [ -n "${TELEMETRY_ZONES:-}" ]; then telemetry_client_certs
    else say "telemetry-client-certs not run: TELEMETRY_ZONES is empty"; fi
  fi
}

# telemetry_client_certs: demonstrator role. For each <zone>=<context> of TELEMETRY_ZONES, wait for
# the zone's client certificate (release telemetry-issuers), and create or update the Secret
# telemetryExport.clientSecret (ztd-telemetry-client) in ztd-otel-node and the management namespace
# of that context: tls.crt and tls.key of the zone's certificate, ca.crt the telemetry root's
# certificate (never its key). The material passes through a temporary directory readable by the
# user alone, removed on exit; the Secret is applied server-side, so no copy of it lands in a
# last-applied annotation. A namespace that does not exist yet (the zone's umbrella not installed)
# stops the step: only the umbrella creates namespaces.
telemetry_client_certs() {
  zone_file
  [ "$ROLE" = demonstrator ] || die "telemetry-client-certs runs with the demonstrator cluster's zone file (zone.role demonstrator)"
  [ -n "${TELEMETRY_ZONES:-}" ] || die "telemetry-client-certs: TELEMETRY_ZONES is empty (<zone>=<context>[,...])"
  local backends known pair zone ctx dir ns mgmt=${TELEMETRY_ZONE_MGMT_NAMESPACE:-ztd-mgmt}
  backends=$(zone_fact observabilityBackends.namespace)
  known=$(zone_py <<'PY'
print(" ".join(z["name"] for z in (fact(zone_doc(), "observabilityBackends.entry.zones") or [])))
PY
)
  kctx version --request-timeout=10s >/dev/null 2>&1 || die "the demonstrator cluster of context $KUBE_CONTEXT cannot be reached"
  dir=$(umask 077; mktemp -d)
  # shellcheck disable=SC2064 # the directory is fixed now
  trap "rm -rf '$dir' '$work'" EXIT
  IFS=',' read -r -a pairs <<<"$TELEMETRY_ZONES"
  for pair in "${pairs[@]}"; do
    zone=${pair%%=*}; ctx=${pair#*=}
    [[ " $known " == *" $zone "* ]] || die "telemetry-client-certs: zone $zone has no listener on the entry (observabilityBackends.entry.zones: $known)"
    kctx -n "$backends" wait --for=condition=Ready "certificate/ztd-telemetry-client-$zone" --timeout=120s >/dev/null \
      || die "telemetry-client-certs: the certificate ztd-telemetry-client-$zone is not Ready in $backends"
    (umask 077
     kctx -n "$backends" get secret "ztd-telemetry-client-$zone" -o jsonpath='{.data.tls\.crt}' | base64 -d >"$dir/tls.crt"
     kctx -n "$backends" get secret "ztd-telemetry-client-$zone" -o jsonpath='{.data.tls\.key}' | base64 -d >"$dir/tls.key"
     kctx -n "$backends" get secret ztd-telemetry-root -o jsonpath='{.data.tls\.crt}' | base64 -d >"$dir/ca.crt")
    if [ ! -s "$dir/tls.crt" ] || [ ! -s "$dir/tls.key" ] || [ ! -s "$dir/ca.crt" ]; then
      die "telemetry-client-certs: the certificate of $zone could not be read"
    fi
    for ns in ztd-otel-node "$mgmt"; do
      kubectl --context "$ctx" get namespace "$ns" >/dev/null 2>&1 \
        || die "telemetry-client-certs: namespace $ns does not exist on $ctx; install the zone's umbrella first (install.sh install ztd)"
      kubectl --context "$ctx" -n "$ns" create secret generic ztd-telemetry-client \
          --from-file=tls.crt="$dir/tls.crt" --from-file=tls.key="$dir/tls.key" --from-file=ca.crt="$dir/ca.crt" \
          --dry-run=client -o yaml \
        | kubectl --context "$ctx" label --local -f - ztd.facis.io/telemetry-zone="$zone" -o yaml \
        | kubectl --context "$ctx" apply --server-side --force-conflicts --field-manager=install-zone -f - >/dev/null \
        || die "telemetry-client-certs: could not write the Secret into $ctx $ns"
      say "telemetry-client-certs: $zone -> $ctx $ns/ztd-telemetry-client"
    done
    rm -f "$dir"/*
  done
}

uninstall() {
  zone_file
  preflight
  local i step release ns rest line
  for (( i=${#STEPS[@]}-1; i>=0; i-- )); do
    IFS='|' read -r release ns rest <<<"${STEPS[$i]}"
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
  install) shift; install "$@" ;;
  telemetry-client-certs) telemetry_client_certs ;;
  plan) plan ;;
  render) shift; render "$@" ;;
  uninstall) uninstall ;;
  help|-h|--help) usage ;;
  '') usage >&2; exit 2 ;;
  *) usage >&2; printf "install-zone: unknown command '%s'\n" "$1" >&2; exit 2 ;;
esac
