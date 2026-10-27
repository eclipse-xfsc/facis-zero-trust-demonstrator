#!/usr/bin/env bash
# Evidence that the zone's mesh identities are SPIRE's, on the local kind cluster with Cilium
# chained (scripts/dev/kind-cilium-up.sh) or on one of the two participant clusters with the
# provider's Cilium. Installs the zone from an empty cluster with scripts/install-zone/install.sh,
# twice, then proves with stand-in pods: an SVID over the CSI socket, on every node with a SPIRE
# agent too (one unmeshed stand-in per node in spire-system, from fixtures/svid-on-node.yaml), the
# SPIRE server's and the controller-manager's metrics endpoints answering beside the agents'
# loopback ones, the proxy's certificate and root bundle issued by SPIRE, no proxy without the SPIRE
# socket and a certificate from istiod's CA refused by a meshed peer, the proxy's traffic capture
# held at the injector's defaults (the capture rule), the TLS 1.3 minimum of mesh mTLS, an
# unregistered workload cut off, traffic through the proxies, the default deny intact with the
# chained CNI and both control planes inside it, the native-sidecar version rule, the identity-band
# checks, the registration inventory (every entry on the SPIRE server against the certificates in use
# in the plane namespaces, by SPIFFE ID, both ways), the cluster's CNI left as found, and a teardown that leaves nothing behind (or, on a
# participant cluster with the keep opt-in and every check passed, the record of what stays).
# On every cluster, kind and participant, the proof places a meshed stand-in on every node with a
# SPIRE agent (fixtures/mesh-on-node.yaml, mesh-on-<node> in the data plane) and calls, from each, the
# stand-in of the next node in a ring, so that every node is a caller and a receiver across a node
# boundary; the cross-plane denial and the unregistered workload's refusal run with the caller on a
# node other than the peer's. No pod the proof creates is held to istiod's node (no pin): besides those
# placements on purpose (and the per-node SVID stand-ins), the scheduler places the pods. No release
# of the zone is held to a node either: section 5 checks that no pod of ztd-openbao carries a node
# affinity or a node selector. Among the
# preconditions, the routing check fails the run when the cluster's Cilium would masquerade pod traffic
# between nodes (native routing, masquerading on, a node's pod range outside ipv4-native-routing-cidr)
# and stops it there, before the clean slate: nothing is uninstalled or installed, and the record of the
# preconditions is written.
# Writes evidence.md and environment.json to a run directory outside the repository (see
# ZTD_EVIDENCE_DIR below) and prints that directory as its last line; it never writes under docs/ or
# anywhere else in the repository, which holds no record of a run. Never run by CI: the evidence is
# the record of a run on a cluster.
#
# Usage:
#   scripts/verify-mesh-identity/verify.sh           run the proof: DESTRUCTIVE, it uninstalls the zone
#                                                    from the cluster first and again at the end
#   scripts/verify-mesh-identity/verify.sh --help    this text; touches nothing
# Any other argument prints this text and exits 125 without touching the cluster.
#
# Exit status:
#   0        every check passed
#   1-124    the number of failed checks (capped at 124); the evidence is written
#   125      refused or not run (an argument, CI, the context guard, a run directory inside the
#            repository): nothing written
#   130/143  interrupted (INT/TERM); on a participant cluster the zone is torn down once the run has
#            reached the clean slate (section 1), and left as found before it; no evidence
#
# Environment:
#   KUBE_CONTEXT          kubectl context (default: kind-ztd). Accepted: a kind cluster (named
#                         kind-<name>, every node's provider ID kind://...), or the participant
#                         cluster zerotrust-a or zerotrust-b when all of these hold: ZTD_CONFIRM_CLUSTER
#                         equals the context name, the context's API server host begins with
#                         api.<context>., every node's provider ID begins with onmetal:// and every
#                         node name contains --<context>-. Anything else is refused (exit 125) before
#                         the cluster is read or written.
#   ZTD_CONFIRM_CLUSTER   on a participant cluster: the context name, typed for this run
#   ZTD_KEEP_ZONE         on a participant cluster: the context name to leave the zone installed when
#                         every check passed (the teardown is replaced by the record of what remains);
#                         unset, a failed check or an interrupted run tears the zone down once the run
#                         has reached section 1 (before it, the cluster is left as found). Refused on
#                         kind and with any other value.
#   ZONE_VALUES           zone file (default: deployment/helm/ztd/ci/values.yaml on kind,
#                         deployment/helm/ztd/zones/zone-<a|b>.yaml on zerotrust-<a|b>); on a
#                         participant cluster its zone.name must be zone-<a|b> of that context
#   ZTD_EVIDENCE_DIR      the run directory: created if missing, used as given, refused inside the
#                         repository (exit 125). Default: a new directory per run,
#                         ${XDG_STATE_HOME:-$HOME/.local/state}/ztd/verify-mesh-identity/<context>/<UTC start, YYYYMMDDTHHMMSSZ>/
#
# Placement: on every cluster the per-node stand-ins (svid-on-<node> in spire-system and mesh-on-<node>
# in the data plane, one each per node with a SPIRE agent) are placed by their own node affinity, and
# the management-plane caller and the unregistered stand-in by a node affinity to a node other than the
# peer's, preferring one that is not istiod's either (where no such node exists, it is istiod's, which is
# then the only node other than the peer's); every other pod is placed by the scheduler. All of them
# are removed with the other stand-ins.
#
# Every check is "<test>; check $? <title>": the status of the test is what the check records.
# shellcheck disable=SC2319,SC2016,SC2181,SC1091
set -uo pipefail
usage() { sed -n '2,/^# Every check/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }
case $# in
  0) ;;
  1) case $1 in -h|--help) usage; exit 0;; esac; usage >&2; echo "verify-mesh-identity: unknown argument: $1" >&2; exit 125;;
  *) usage >&2; echo "verify-mesh-identity: takes no arguments" >&2; exit 125;;
esac
if [ -n "${CI:-}" ]; then
  echo "verify-mesh-identity: refusing to run under CI; the evidence is written from a run on a cluster" >&2
  exit 125
fi
# A relative zone file or run directory is the caller's, read before the script moves into its own
# directory.
[ -n "${ZONE_VALUES:-}" ] && ZONE_VALUES=$(realpath -m -- "$ZONE_VALUES")
[ -n "${ZTD_EVIDENCE_DIR:-}" ] && ZTD_EVIDENCE_DIR=$(realpath -m -- "$ZTD_EVIDENCE_DIR")
cd "$(dirname "$0")" || exit 125
REPO=$(git rev-parse --show-toplevel)
CHART=$REPO/deployment/helm/ztd
CONTEXT=${KUBE_CONTEXT:-kind-ztd}
# yaml_get <file> <key>... : one value out of a YAML file; the path travels as an argument, never inside the source
yaml_get() { python3 -c 'import sys,yaml
v=yaml.safe_load(open(sys.argv[1]))
for k in sys.argv[2:]: v=v[k]
print(v)' "$@"; }
# A refusal exits 125, outside the range of the failure count (1-124), so a caller tells them apart.
refuse() { echo "verify-mesh-identity: refusing context '$CONTEXT': $*" >&2; exit 125; }
# The run uninstalls and reinstalls the zone: refuse any cluster that is neither a local kind cluster
# nor a confirmed participant cluster, before anything is read from it or written to it.
KEEP=0
case $CONTEXT in
  kind-?*)
    [ -z "${ZTD_KEEP_ZONE:-}" ] || refuse "ZTD_KEEP_ZONE is set ('$ZTD_KEEP_ZONE'), expected unset: the keep opt-in applies to a participant cluster only (kind-cilium-up.sh recreates a kind zone)"
    CLUSTER_KIND=kind
    ZONE_VALUES=${ZONE_VALUES:-$CHART/ci/values.yaml}
    providers=$(kubectl --context "$CONTEXT" get nodes -o jsonpath='{range .items[*]}{.spec.providerID}{"\n"}{end}' 2>/dev/null)
    if [ -z "$providers" ] || grep -qv '^kind://' <<<"$providers"; then
      refuse "unreachable, or a node whose provider ID is not kind://"
    fi
    ;;
  zerotrust-a|zerotrust-b)
    [ "${ZTD_CONFIRM_CLUSTER:-}" = "$CONTEXT" ] \
      || refuse "a participant cluster: expected ZTD_CONFIRM_CLUSTER=$CONTEXT, found ${ZTD_CONFIRM_CLUSTER:+ZTD_CONFIRM_CLUSTER=}${ZTD_CONFIRM_CLUSTER:-it unset}"
    case ${ZTD_KEEP_ZONE:-} in
      '') ;;
      "$CONTEXT") KEEP=1;;
      *) refuse "expected ZTD_KEEP_ZONE unset or ZTD_KEEP_ZONE=$CONTEXT, found ZTD_KEEP_ZONE=$ZTD_KEEP_ZONE";;
    esac
    CLUSTER_KIND=provider
    zone_name=zone-${CONTEXT#zerotrust-}
    ZONE_VALUES=${ZONE_VALUES:-$CHART/zones/$zone_name.yaml}
    [ "$(yaml_get "$ZONE_VALUES" zone name 2>/dev/null)" = "$zone_name" ] \
      || refuse "expected a zone file whose zone.name is $zone_name, found '$(yaml_get "$ZONE_VALUES" zone name 2>/dev/null)' in $ZONE_VALUES"
    # The binding of the local context name to the cluster it points at: the API host's prefix, the
    # nodes' provider and the nodes' names (no address or domain is kept in the repository).
    api=$(kubectl config view --minify --context "$CONTEXT" -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null)
    api_host=${api#*://}; api_host=${api_host%%[:/]*}
    [[ $api_host == "api.$CONTEXT."* ]] || refuse "expected the context's API server host to begin with api.$CONTEXT., found '${api_host:-none}'"
    nodes=$(kubectl --context "$CONTEXT" get nodes -o jsonpath='{range .items[*]}{.metadata.name} {.spec.providerID}{"\n"}{end}' 2>/dev/null)
    [ -n "$nodes" ] || refuse "unreachable, or no node listed"
    bad=$(awk '$2 !~ /^onmetal:\/\// {print $1 " (provider ID " ($2 == "" ? "none" : $2) ")"}' <<<"$nodes")
    [ -z "$bad" ] || refuse "expected every node's provider ID to begin with onmetal://, found $(paste -sd, - <<<"$bad")"
    bad=$(awk -v c="--$CONTEXT-" '!index($1, c) {print $1}' <<<"$nodes")
    [ -z "$bad" ] || refuse "expected every node name to contain --$CONTEXT-, found $(paste -sd, - <<<"$bad")"
    ;;
  *) refuse "neither a kind cluster (kind-<name>) nor a participant cluster (zerotrust-a, zerotrust-b); the run uninstalls the zone";;
esac
INSTALL=$REPO/scripts/install-zone/install.sh
ZONE_NAME=$(yaml_get "$ZONE_VALUES" zone name)
# The run directory (see the header): outside the repository, one per run unless the caller names it.
# A run never writes into the repository, so a directory inside it is refused before the cluster is
# touched.
if [ -n "${ZTD_EVIDENCE_DIR:-}" ]; then EVID=$ZTD_EVIDENCE_DIR
else EVID=$(realpath -m -- "${XDG_STATE_HOME:-$HOME/.local/state}")/ztd/verify-mesh-identity/$CONTEXT; fi
case $EVID/ in
  "$REPO"/*) echo "verify-mesh-identity: refusing run directory '$EVID': it is inside the repository, which holds no record of a run" >&2; exit 125;;
esac
export ZONE_VALUES KUBE_CONTEXT=$CONTEXT
MGMT=$(yaml_get "$CHART/values.yaml" planes management namespace)
DATA=$(yaml_get "$CHART/values.yaml" planes data namespace)
TD=$(yaml_get "$ZONE_VALUES" zone trustDomain)
SPIRE_NS=spire-system; ISTIO_NS=istio-system
images_spire=""; images_istio=""; images_proxy=""
RELEASES="ztd:ztd-system spire-crds:$SPIRE_NS spire:$SPIRE_NS istio-base:$ISTIO_NS istiod:$ISTIO_NS istio-cni:$ISTIO_NS zone-policy:$ISTIO_NS ztd-openbao:$MGMT"
SA_ID="spiffe://$TD/ns/$DATA/sa/stand-in"
# The admission policy of zone-policy. The proxy status port its capture rule lets the injector
# exclude is read from the installed release in section 8, not from the chart's defaults.
POLICY=proxy-takes-spire-socket
STATUS_PORT=""

work=$(mktemp -d)
# restore_capture: puts the capture validation back into the live policy when it is missing from it
# and section 5 saved it (restore.json); a no-op otherwise, so it is safe to call more than once. A
# policy it cannot read (other than one already uninstalled) or cannot patch is named on stderr, as
# the capture validation may then still be lifted.
restore_capture() {
  local live
  [ -s "$work/restore.json" ] || return 0
  if ! live=$(kubectl --context "$CONTEXT" get validatingadmissionpolicy "$POLICY" -o json 2>"$work/restore.err"); then
    grep -q NotFound "$work/restore.err" \
      || echo "verify-mesh-identity: cannot read the admission policy $POLICY to put its capture validation back; it may still be lifted: $(head -1 "$work/restore.err")" >&2
    return 0
  fi
  jq -e '[.spec.validations[].expression | contains("variables.captureDefaults")] | index(true) == null' <<<"$live" >/dev/null || return 0
  kubectl --context "$CONTEXT" patch validatingadmissionpolicy "$POLICY" --type=json --patch-file "$work/restore.json" >/dev/null 2>"$work/restore.err" \
    || echo "verify-mesh-identity: the capture validation of the admission policy $POLICY could not be put back; it is still lifted: $(head -1 "$work/restore.err")" >&2
}
# keep_zone: 1 once the record of what remains passed (section 16), the CNI check included; kept: 1
# only once that record is written to the run directory, so an interrupt or a failed write before
# then still tears the zone down; written: 1 once both files of the evidence are written (an
# interrupt between that write and kept=1 keeps the zone the record names); cleaned: 1 once the
# teardown ran; installed: 1 once the run starts writing to the cluster (section 1), so a run that
# stops before (a failed routing check, an interrupt or an error in the preconditions) leaves the
# cluster as found, a zone it already runs included.
keep_zone=0; kept=0; written=0; cleaned=0; installed=0
# provider_cleanup: on a participant cluster, unless the run stopped before section 1 or ended with the
# zone kept or already torn down, removes everything the run put there (the fixture of section 13, the scratch namespace of
# section 8, the eight releases, the release namespace), so that an error, INT or TERM leaves the
# cluster as it was found; idempotent, every step ignores what is already gone.
# delete_stand_ins: removes the stand-in pods of section 5 while the SPIFFE CSI driver still runs, so
# that their csi.spiffe.io volumes unmount (once the spire release is gone they would hang in
# Terminating and hold their namespace); a no-op when there are none. The per-node SVID stand-ins of
# fixtures/svid-on-node.yaml go too, by their label (whatever nodes they were rendered for, a run
# interrupted before section 6 included), and the ServiceAccount of that fixture with them. So do the
# per-node meshed stand-ins of fixtures/mesh-on-node.yaml, their Services and ServiceAccounts, by their label.
delete_stand_ins() {
  sed -e "s/__DATA__/$DATA/g" -e "s/__MGMT__/$MGMT/g" fixtures/stand-ins.yaml \
    | kubectl --context "$CONTEXT" delete -f - --ignore-not-found --wait=true >/dev/null 2>&1
  kubectl --context "$CONTEXT" -n "$DATA" delete pod,service,serviceaccount -l app.kubernetes.io/name=mesh-on-node --ignore-not-found --wait=true >/dev/null 2>&1
  kubectl --context "$CONTEXT" -n "$SPIRE_NS" delete pod -l app.kubernetes.io/name=svid-on-node --ignore-not-found --wait=true >/dev/null 2>&1
  kubectl --context "$CONTEXT" -n "$SPIRE_NS" delete serviceaccount stand-in --ignore-not-found >/dev/null 2>&1
}
# shellcheck disable=SC2317  # called from the EXIT trap only
provider_cleanup() {
  [ "$CLUSTER_KIND" = provider ] && [ "$installed" = 1 ] && [ "$kept" != 1 ] && [ "$cleaned" != 1 ] || return 0
  [ "$keep_zone" = 1 ] && [ "$written" = 1 ] && return 0
  if [ "$keep_zone" = 1 ]; then
    echo "verify-mesh-identity: every check passed but the record of the kept zone was not written; no evidence of it exists, tearing it down on $CONTEXT" >&2
  else
    echo "verify-mesh-identity: the run did not end with the zone kept; tearing it down on $CONTEXT" >&2
  fi
  delete_stand_ins
  kubectl --context "$CONTEXT" -n kube-public delete pod declared-not-reconciled --ignore-not-found --wait=true >/dev/null 2>&1
  kubectl --context "$CONTEXT" label ns kube-public ztd.facis.io/plane- >/dev/null 2>&1
  kubectl --context "$CONTEXT" delete namespace mesh-identity-outside --ignore-not-found --wait=true >/dev/null 2>&1
  "$INSTALL" uninstall >/dev/null 2>&1
  kubectl --context "$CONTEXT" delete namespace ztd-system --ignore-not-found --wait=true >/dev/null 2>&1
  cleaned=1
}
# On any exit, an interrupt included, the capture validation lifted in section 5 is put back first;
# on a participant cluster the zone is then torn down unless the run kept it (kind: unchanged).
trap 'restore_capture; provider_cleanup; rm -rf "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
OUT=$work/evidence.md
failures=0
# The commit and the dirty flag describe the code that runs; neither refuses a run.
commit=$(git rev-parse HEAD)
dirty=false; [ -n "$(git status --porcelain)" ] && dirty=true
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# The default run directory is named by the run's UTC start; an existing one is never reused.
if [ -z "${ZTD_EVIDENCE_DIR:-}" ]; then
  base=$EVID/$(date -u -d "$started" +%Y%m%dT%H%M%SZ); EVID=$base; n=1
  while [ -e "$EVID" ]; do EVID=$base-$n; n=$((n+1)); done
fi

k() { kubectl --context "$CONTEXT" "$@"; }
h() { helm --kube-context "$CONTEXT" "$@"; }
say() { printf '%s\n' "$@" >> "$OUT"; }
code() { say '' '```'; say "$@"; say '```' ''; }
check() { # check <PASS-condition exit status> <title> <detail...>
  local status=$1; shift; local title=$1; shift
  if [ "$status" -eq 0 ]; then say "- PASS: $title"; else say "- **FAIL**: $title"; failures=$((failures+1)); fi
  [ $# -gt 0 ] && say "  $*"
  return 0
}
section() { say '' "## $1" ''; echo "== $1"; }
spire_server() { k -n "$SPIRE_NS" exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server "$@"; }
# agent_nodes: the nodes the SPIRE agent DaemonSet runs on, one per line, from its pods' spec.nodeName
agent_nodes() { k -n "$SPIRE_NS" get pods -o json | jq -r '.items[] | select(.metadata.ownerReferences[0].name == "spire-agent") | .spec.nodeName' | sort -u; }
# cilium_on <node>: the Cilium agent pod of that node (host network), through which the proof reads
# the node's host; the only use of kube-system is such a read-only exec
cilium_on() { k --request-timeout=30s -n kube-system get pod -l k8s-app=cilium --field-selector "spec.nodeName=$1" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null; }
# host_get <node> <address> <port>: GET /metrics on <address>:<port> from the host of <node>, through
# its Cilium agent (bash and /dev/tcp of the Cilium image, nothing installed, nothing written); the
# raw HTTP response on stdout; the API calls are bounded too, so a stalled API server cannot hang the run
host_get() {
  local C; C=$(cilium_on "$1")
  [ -n "$C" ] || return 1
  k --request-timeout=60s -n kube-system exec "$C" -c cilium-agent -- timeout 20 bash -c 'exec 3<>"/dev/tcp/$0/$1"; printf "GET /metrics HTTP/1.0\r\nHost: %s:%s\r\n\r\n" "$0" "$1" >&3; cat <&3' "$2" "$3" 2>/dev/null
}
# agent_answers <node>: the check that the SPIRE agent of <node> answers on 127.0.0.1:9988 with
# spire_agent samples
agent_answers() {
  local n; n=$(host_get "$1" 127.0.0.1 9988 | grep -c '^spire_agent')
  [ "$n" -gt 0 ]; check $? "node $1: the agent's metrics answer on 127.0.0.1:9988 (the contract with a collector on the node)" "$n spire_agent samples"
}
# metrics_answer <component> <family> <port>: the check that the endpoint of <component> in the SPIRE
# server pod answers on <port> with HTTP 200 and at least one sample of <family>, read from the host
# of the server pod's node (the kubelet's path to the pod, which its readiness probes take)
metrics_answer() {
  local node ip out code n
  node=$(k -n "$SPIRE_NS" get pod spire-server-0 -o jsonpath='{.spec.nodeName}' 2>/dev/null)
  ip=$(k -n "$SPIRE_NS" get pod spire-server-0 -o jsonpath='{.status.podIP}' 2>/dev/null)
  out=$([ -n "$node" ] && [ -n "$ip" ] && host_get "$node" "$ip" "$3")
  code=$(head -1 <<<"$out" | awk '{print $2}')
  n=$(grep -c "^$2" <<<"$out")
  [ "$code" = 200 ] && [ "$n" -gt 0 ]
  check $? "$1: the metrics endpoint answers on the server pod's port $3 (/metrics), HTTP 200 with samples of its own family $2, read from the host of its node through that node's Cilium agent" "node ${node:-unknown}, port $3, HTTP ${code:-no answer}, $n $2 samples"
}
# http <ns> <pod> <container> <url>: HTTP code and the first line of the body; denied(<curl exit>)
# only when the network refused the call (7 refused, 28 timed out, 52 empty reply, 56 reset);
# error(<exit>) for anything else (a name that does not resolve, an exec that failed, ...), which
# a negative check does not count as a denial.
http() {
  local out rc
  out=$(k -n "$1" exec "$2" -c "$3" -- curl -sS -m 15 -w '\n%{http_code}' "$4" 2>/dev/null); rc=$?
  case $rc in
    0) printf '%s %s' "$(tail -1 <<<"$out")" "$(head -1 <<<"$out" | cut -c1-110)";;
    7|28|52|56) echo "denied($rc)";;
    *) echo "error($rc)";;
  esac
}
# tcp <ns> <pod> <ip> <port>: "connected" when a TCP connection is established, denied(<curl exit>)
# when it was refused or timed out (7, 28), error(<exit>) when the probe itself failed (1: the exec
# failed, as curl never returns 1 for http://; 6: no such name; 126, 127: no curl)
tcp() {
  local rc
  k -n "$1" exec "$2" -c app -- curl -s -o /dev/null --connect-timeout 4 -m 6 "http://$3:$4/" >/dev/null 2>&1; rc=$?
  case $rc in 7|28) echo "denied($rc)";; 1|6|126|127) echo "error($rc)";; *) echo connected;; esac
}
fingerprint() { openssl x509 -noout -fingerprint -sha256 -in "$1" | cut -d= -f2; }
# metric <ns> <pod> <reporter>: istio_requests_total of the proxy for one reporter, summed
metric() {
  k -n "$1" exec "$2" -c istio-proxy -- pilot-agent request GET stats/prometheus 2>/dev/null \
    | awk -v r="reporter=\"$3\"" '/^istio_requests_total/ && index($0, r) { s += $NF } END { print s + 0 }'
}
# proxy_cert <ns> <pod> <out.pem>: the leaf of the certificate in use by the pod's proxy (its
# 'default' secret), read with istioctl proxy-config secret as section 8 does; a proxy istioctl
# cannot reach (a pod that is not Running cannot be port-forwarded to) is read through its own admin
# endpoint instead, as section 9 does. Status 0 when a certificate was written; 1 when the proxy
# answered and holds no 'default' certificate; 2 when neither read answered, with the first line of
# the error in <out.pem>.err. A read that fails is never taken for a proxy without a certificate.
proxy_cert() {
  local raw
  rm -f "$3" "$3.err"
  raw=$(timeout 60 istioctl --context "$CONTEXT" proxy-config secret "$2" -n "$1" -o json 2>/dev/null) && jq -e 'type == "object"' <<<"$raw" >/dev/null 2>&1 \
    || raw=$(k --request-timeout=60s -n "$1" exec "$2" -c istio-proxy -- pilot-agent request GET 'config_dump?resource=dynamic_active_secrets' 2>"$3.err")
  if ! jq -e 'type == "object"' <<<"$raw" >/dev/null 2>&1; then
    { grep -v '^$' "$3.err" 2>/dev/null | head -1 | grep . || echo "neither istioctl proxy-config secret nor the proxy's admin endpoint answered (60 s each)"; } >"$3.err.1"
    mv "$3.err.1" "$3.err"; return 2
  fi
  rm -f "$3.err"
  jq -r '(.dynamicActiveSecrets // .configs // [])[]? | select(.name == "default") | .secret
    | (.tlsCertificate.certificateChain.inlineBytes // .tls_certificate.certificate_chain.inline_bytes) // empty' <<<"$raw" 2>/dev/null \
    | head -1 | base64 -d 2>/dev/null | openssl x509 -out "$3" 2>/dev/null && [ -s "$3" ] && return 0
  rm -f "$3"; return 1
}
# socket_cert <ns> <pod> <container> <socket dir> <out.pem>: the leaf of the SVID the pod's Workload
# API client fetches over the mounted socket, as section 6 does; the JSON, which carries the private
# key, is dropped at once. Status 0 when a certificate was written; 1 when the agent answered that it
# issued no identity to the pod (PermissionDenied, as for section 6's unlabelled pod); 2 when the
# read failed otherwise, with the first line of the error in <out.pem>.err.
socket_cert() {
  local json
  rm -f "$5" "$5.err"
  json=$(k --request-timeout=60s -n "$1" exec "$2" -c "$3" -- /opt/spire/bin/spire-agent api fetch x509 -socketPath "$4/socket" -timeout 5s -output json 2>"$5.err")
  jq -r '.svids[0].x509_svid // empty' <<<"$json" 2>/dev/null | base64 -d 2>/dev/null | openssl x509 -inform DER -out "$5" 2>/dev/null
  json=""
  if [ -s "$5" ]; then rm -f "$5.err"; return 0; fi
  rm -f "$5"
  if grep -q 'PermissionDenied desc = no identity issued' "$5.err" 2>/dev/null; then rm -f "$5.err"; return 1; fi
  { grep -v -e '^$' -e '^command terminated' "$5.err" 2>/dev/null | tail -1 | grep . || echo "the fetch over the socket returned no SVID and no reason"; } >"$5.err.1"
  mv "$5.err.1" "$5.err"; return 2
}
# pod_gone <ns> <pod> <uid>: status 0 when the pod listed with <uid> no longer exists (not found, or
# its name now belongs to a pod with another uid), so a read that failed met a pod deleted after the
# listing; status 1 when the pod still exists or the lookup itself failed, so the failed read stands.
pod_gone() {
  local now
  now=$(k --request-timeout=30s -n "$1" get pod "$2" --ignore-not-found -o jsonpath='{.metadata.uid}' 2>/dev/null) || return 1
  [ "$now" != "$3" ]
}
# reader_ended <ns> <pod> <uid> <container>: status 0 when the pod listed with <uid> still exists, is
# terminating (deletionTimestamp set) and <container> no longer runs, so a read that failed met a
# reader that ended after the listing and nothing is in use; status 1 otherwise (the container still
# runs, the pod is not terminating, or the lookup failed), so the failed read stands. Asked only
# after pod_gone, so a pod that finished terminating stays gone.
reader_ended() {
  local js
  js=$(k --request-timeout=30s -n "$1" get pod "$2" -o json 2>/dev/null) || return 1
  jq -e --arg u "$3" --arg c "$4" '.metadata.uid == $u and .metadata.deletionTimestamp != null
    and ([(.status.initContainerStatuses // [])[], (.status.containerStatuses // [])[] | select(.name == $c and .state.running)] | length == 0)' <<<"$js" >/dev/null 2>&1
}
# cert_uri <pem>: the SPIFFE URI SAN of a certificate
cert_uri() { openssl x509 -noout -ext subjectAltName -in "$1" 2>/dev/null | grep -o 'URI:spiffe://[^,]*' | head -1 | sed 's/^URI://'; }
# on_node <node> <file> <pod>...: adds to each named Pod of the manifest file, in place, a required node
# affinity on kubernetes.io/hostname to <node>; used for the callers of the cross-node denials (section 5)
on_node() {
  python3 - "$@" <<'PY'
import sys, yaml
node, f, names = sys.argv[1], sys.argv[2], set(sys.argv[3:])
aff = {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [
    {"matchExpressions": [{"key": "kubernetes.io/hostname", "operator": "In", "values": [node]}]}]}}}
docs = [d for d in yaml.safe_load_all(open(f)) if d]
for d in docs:
    if d.get("kind") == "Pod" and d["metadata"]["name"] in names:
        d["spec"]["affinity"] = aff
yaml.safe_dump_all(docs, open(f, "w"), sort_keys=False)
PY
}
# node_of <ns> <pod>: the node a pod is scheduled on, empty when it is not (yet)
node_of() { k -n "$1" get pod "$2" -o jsonpath='{.spec.nodeName}' 2>/dev/null; }
# proxy_leaf <ns> <pod> <prefix>: the proxy's workload certificate (default) and root bundle (ROOTCA),
# read with istioctl proxy-config secret, as <prefix>-secret.json, <prefix>-leaf.pem and
# <prefix>-root.pem in $work; the trust domains of the ROOTCA bundle on stdout
proxy_leaf() {
  istioctl --context "$CONTEXT" proxy-config secret "$2" -n "$1" -o json >"$work/$3-secret.json" 2>/dev/null
  jq -r '.dynamicActiveSecrets[] | select(.name == "default") | .secret.tlsCertificate.certificateChain.inlineBytes' "$work/$3-secret.json" 2>/dev/null \
    | base64 -d >"$work/$3-chain.pem" 2>/dev/null
  # SPIRE serves ROOTCA as Envoy's SPIFFE certificate validator: one trust bundle per trust domain.
  jq -r --arg td "$TD" '.dynamicActiveSecrets[] | select(.name == "ROOTCA") | .secret.validationContext
    | (.trustedCa.inlineBytes // (.customValidatorConfig.typedConfig.trustDomains[]? | select(.name == $td) | .trustBundle.inlineBytes))' \
    "$work/$3-secret.json" 2>/dev/null | base64 -d >"$work/$3-root.pem" 2>/dev/null
  openssl x509 -in "$work/$3-chain.pem" -out "$work/$3-leaf.pem" 2>/dev/null || : >"$work/$3-leaf.pem"
  jq -r '[.dynamicActiveSecrets[] | select(.name == "ROOTCA") | .secret.validationContext.customValidatorConfig.typedConfig.trustDomains[]?.name] | join(",")' "$work/$3-secret.json" 2>/dev/null
}
# issued_by_spire <leaf.pem>: status 0 when the certificate's issuer is the SPIRE server CA (the subject
# of the bundle read from the server in section 6) and it chains to that bundle
issued_by_spire() {
  local issuer; issuer=$(openssl x509 -noout -issuer -nameopt RFC2253 -in "$1" 2>/dev/null)
  [ -n "$issuer" ] && [ "${issuer#issuer=}" = "${ca_subject#subject=}" ] && openssl verify -CAfile "$work/spire-bundle.pem" "$1" >/dev/null 2>&1
}
# mtls_requests <ns> <pod> <reporter> <label="value">: istio_requests_total of the proxy for one reporter
# and one more label, summed. A destination proxy labels a request it took over mutual TLS
# connection_security_policy="mutual_tls"; a source proxy labels its requests with
# destination_principal, the URI SAN of the certificate the receiver presented in the handshake.
mtls_requests() {
  k -n "$1" exec "$2" -c istio-proxy -- pilot-agent request GET stats/prometheus 2>/dev/null \
    | awk -v r="reporter=\"$3\"" -v l="$4" '/^istio_requests_total/ && index($0, r) && index($0, l) { s += $NF } END { print s + 0 }'
}
# routing_verdict <cilium-config data JSON> <nodes>: whether pod-to-pod traffic between nodes keeps the
# source pod's address, and so its identity at the destination. <nodes> holds one "<node> <pod range>"
# line per node and pod range. Cilium masquerades traffic to destinations outside
# ipv4-native-routing-cidr: in native routing with masquerading on (enable-ipv4-masquerade or
# enable-bpf-masquerade), a node whose pod range lies outside that range reaches a pod on another node
# as remote-node, not as itself. Prints the status (0 pass, 1 fail) on the first line and the detail on
# the second. An absent key is read as Cilium's default, and the record says so: routing-mode tunnel,
# tunnel-protocol vxlan, enable-ipv4-masquerade true, enable-bpf-masquerade false. A flag is read as
# Go reads a boolean (true/false in any case, 1/0, t/f); any other value, or a range that is not a
# network, fails the check with that value named. A cilium-config that could not be read (the run
# writes null for it), or one that holds no keys at all, fails the check with that reason: it is never
# read as all defaults.
# routing-verdict-begin
routing_verdict() {
  python3 - "$1" "$2" <<'PY'
import ipaddress, json, sys
def verdict(status, text):
    print(status); print(text); sys.exit()
try:
    d = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    d = None
if not isinstance(d, dict):
    verdict(1, "kube-system/cilium-config could not be read, so it cannot be shown that pod addresses are kept between nodes")
if not d:
    verdict(1, "kube-system/cilium-config holds no keys (Cilium writes its settings there), so it cannot be shown that pod addresses are kept between nodes")
nodes = [l.split() for l in open(sys.argv[2]) if l.strip()]
DEFAULTS = {"enable-ipv4-masquerade": "true", "enable-bpf-masquerade": "false"}
def flag(k):
    raw = d.get(k)
    v = DEFAULTS[k] if raw is None or raw == "" else str(raw)
    shown = f"{k}={v}" + (" (absent: Cilium's default)" if raw is None or raw == "" else "")
    b = {"true": True, "t": True, "1": True, "false": False, "f": False, "0": False}.get(v.strip().lower())
    return b, shown
mode = d.get("routing-mode") or "tunnel"
mode_text = d.get("routing-mode") or "tunnel (absent: Cilium's default)"
masq = {k: flag(k) for k in DEFAULTS}
flags = " ".join(shown for _, shown in masq.values())
if mode == "tunnel":
    proto = d.get("tunnel-protocol") or "vxlan (absent: Cilium's default)"
    verdict(0, f"routing-mode={mode_text} tunnel-protocol={proto} {flags}: pod addresses are kept between nodes")
if mode != "native":
    verdict(1, f"routing-mode={mode_text} {flags}: an unknown routing mode, so it cannot be shown that pod addresses are kept between nodes")
native = d.get("ipv4-native-routing-cidr") or ""
head = f"routing-mode={mode_text} ipv4-native-routing-cidr={native or 'none'} {flags}"
bad = [shown for b, shown in masq.values() if b is None]
if bad:
    verdict(1, f"{head}: {', '.join(bad)} is not a boolean, so it cannot be shown that masquerading is off")
if not any(b for b, _ in masq.values()):
    verdict(0, f"{head}: masquerading off, pod addresses are kept between nodes")
try:
    net = ipaddress.ip_network(native, strict=False) if native else None
except ValueError:
    verdict(1, f"{head}: ipv4-native-routing-cidr is not an IPv4 network, so it cannot be shown that pod addresses are kept between nodes")
v4 = [(n[0], n[1]) for n in nodes if len(n) > 1 and ":" not in n[1]]
if not v4:
    verdict(1, f"{head}: no node pod range could be read, so it cannot be shown that pod addresses are kept between nodes")
out, unread = [], []
for n, c in v4:
    try:
        r = ipaddress.ip_network(c, strict=False)
    except ValueError:
        unread.append(f"{n} ({c})"); continue
    if net is None or r.version != net.version or not r.subnet_of(net):
        out.append(f"{n} ({c})")
if unread:
    verdict(1, f"{head}: {len(unread)} node pod range(s) are not networks, so it cannot be shown that pod addresses are kept between nodes: {', '.join(unread)}")
if out:
    verdict(1, f"{head}: {len(out)} of {len(v4)} node pod ranges outside ipv4-native-routing-cidr, masqueraded to the node address between nodes: {', '.join(out)}")
verdict(0, f"{head}: all {len(v4)} node pod ranges inside ipv4-native-routing-cidr, pod addresses are kept between nodes")
PY
}
# routing-verdict-end

: > "$OUT"
say "# Mesh identity evidence ($started)" ''
if [ "$CLUSTER_KIND" = kind ]; then
  say "Cluster kind: **kind**, the local cluster from \`scripts/dev/kind-cilium-up.sh\` with Cilium chained. Keep opt-in: not applicable on kind; the run tears down the zone it installs." ''
else
  keep_text="not set: the run tears down the zone it installs"
  [ "$KEEP" = 1 ] && keep_text="set (\`ZTD_KEEP_ZONE=$CONTEXT\`): the zone stays installed only if every check passes, otherwise the run tears down the zone it installed"
  interim=""; [[ $TD == *.trust.invalid ]] && interim=" The trust domain \`$TD\` is **interim**: the zone is re-installed with its final name under the delegated trust-framework zone once that name is confirmed, and a zone on an interim name is not acceptance evidence."
  say "Cluster kind: **participant cluster** \`$CONTEXT\` (zone \`$ZONE_NAME\`), Cilium installed and managed by the provider, confirmed with \`ZTD_CONFIRM_CLUSTER=$CONTEXT\`. Keep opt-in: $keep_text.$interim Every IPv4 address of the cluster is replaced by \`<address>\` in this record." ''
fi
say "Cluster context \`$CONTEXT\`, zone file \`${ZONE_VALUES#"$REPO"/}\` (trust domain \`$TD\`), installed with \`scripts/install-zone/install.sh\`: the eight releases \`ztd\`, \`spire-crds\`, \`spire\`, \`istio-base\`, \`istiod\`, \`istio-cni\`, \`zone-policy\`, \`ztd-openbao\`. Commit \`$commit\`, tree dirty: $dirty. Versions in \`environment.json\`." ''
say "Placement: no pin. No pod the proof creates is held to istiod's node. Three placements are made on purpose: the per-node stand-ins one per node with a SPIRE agent (\`svid-on-<node>\` in \`$SPIRE_NS\`, section 6; the meshed \`mesh-on-<node>\` in \`$DATA\`, section 10), and the callers of the two cross-node refusals (\`mgmt-caller\`, \`unregistered\`) on a node other than the peer's, preferring one that is not istiod's either (section 5); the scheduler places every other pod. No release of the zone is held to a node: no pod of \`ztd-openbao\` carries a node affinity or a node selector (section 5)." ''
say 'Probe results: an HTTP code with the first line of the body when the call went through its proxies; `denied(28)` when a raw TCP connection timed out because the policy dropped the packets; `denied(56)` when the peer reset the connection; `error(<exit>)`, which fails a negative check, for any other failure (a name that does not resolve, an exec that failed).' ''

# --------------------------------------------------------------------------------------------
section "0. Preconditions"
server=$(k version -o json | jq -r .serverVersion.gitVersion)
recorded=$(yaml_get "$ZONE_VALUES" zone kubernetesVersion)
# majmin_patch <version>: major.minor.patch of a Kubernetes version (v1.34.7-gke.1 -> 1.34.7)
majmin_patch() { sed -n 's/^v\{0,1\}\([0-9]*\.[0-9]*\.[0-9]*\).*/\1/p' <<<"$1"; }
[ -n "$(majmin_patch "$server")" ] && [ "$(majmin_patch "$server")" = "$(majmin_patch "$recorded")" ]
check $? "native-sidecar-version: the zone file's zone.kubernetesVersion equals the server version the cluster runs (major.minor.patch)" "server $server, zone file $recorded"
python3 - "$server" <<'PY2'; check $? "native-sidecar-version: the server is Kubernetes 1.33 or later (native sidecar containers)" "server $server"
import re, sys
major, minor = map(int, re.match(r"v(\d+)\.(\d+)", sys.argv[1]).groups())
sys.exit(0 if (major, minor) >= (1, 33) else 1)
PY2
cni=$(k -n kube-system get ds cilium -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null)
[ -n "$cni" ]; check $? "Cilium is the CNI" "$cni"
excl=$(k -n kube-system get cm cilium-config -o jsonpath='{.data.cni-exclusive}' 2>/dev/null)
[ "$excl" = "false" ]; check $? "cni-exclusive=false (the Istio CNI plugin can chain)" "cni-exclusive=$excl"
# The cluster's CNI as found, read again at the end: the run reads it and never writes it.
cni_state() { printf 'image=%s generation=%s cilium-config.resourceVersion=%s' \
  "$(k -n kube-system get ds cilium -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null)" \
  "$(k -n kube-system get ds cilium -o jsonpath='{.metadata.generation}' 2>/dev/null)" \
  "$(k -n kube-system get cm cilium-config -o jsonpath='{.metadata.resourceVersion}' 2>/dev/null)"; }
cni_before=$(cni_state)
# cni_check: the CNI read again and compared with cni_before, as a check. On the keep path it is one of
# the checks of the record of what remains (section 16), before the zone is declared kept; on the
# teardown path it runs after the uninstall.
cni_check() {
  local cni_after; cni_after=$(cni_state)
  [ "$cni_after" = "$cni_before" ]; check $? "the Cilium DaemonSet (image, generation) and cilium-config (resource version) are unchanged by the run" "before \`$cni_before\`; after \`$cni_after\`"
}
say "  the Cilium DaemonSet and its ConfigMap as found: \`$cni_before\`"
# The routing check (routing_verdict above): pod-to-pod traffic between nodes must keep the source
# pod's address, and so its identity at the destination, or the label- and namespace-keyed openings drop
# a meshed pod's traffic to istiod and to its peers on other nodes. On a participant cluster the
# record's addresses (the pod ranges a failure names) are masked like every other address.
# A ConfigMap that cannot be read is written as null, which the check fails on (never as all defaults).
if cm_json=$(k -n kube-system get cm cilium-config -o json 2>/dev/null) \
  && jq -e '.data // {}' <<<"$cm_json" >"$work/cilium-config.json" 2>/dev/null; then :
else echo null >"$work/cilium-config.json"; fi
k get nodes -o json 2>/dev/null | jq -r '.items[] | .metadata.name as $n | (.spec.podCIDRs // [.spec.podCIDR // empty])[] | "\($n) \(.)"' >"$work/pod-ranges.txt" 2>/dev/null
mapfile -t routing < <(routing_verdict "$work/cilium-config.json" "$work/pod-ranges.txt" 2>&1)
routing_ok=0; [ "${routing[0]:-1}" = 0 ] && routing_ok=1
[ "$routing_ok" = 1 ]
check $? "pod-to-pod routing keeps a pod's address between nodes: no native routing with masquerading on and a node's pod range outside ipv4-native-routing-cidr (a pod on another node would reach a pod as remote-node, not as itself)" "${routing[1]:-the routing could not be read: ${routing[0]:-no output}}"
# The inotify instance limit of every node, read through the node's own Cilium agent (one per node,
# host /proc): the Istio CNI agent fails below 512. On kind every node shares this machine's kernel.
inotify_detail=""; inotify_read=0; inotify_ok=1
nodes_all=$(k get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
for NODE in $nodes_all; do
  C=$(k -n kube-system get pod -l k8s-app=cilium --field-selector "spec.nodeName=$NODE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  v=""
  [ -n "$C" ] && v=$(k -n kube-system exec "$C" -c cilium-agent -- cat /proc/sys/fs/inotify/max_user_instances 2>/dev/null | tr -d '[:space:]')
  if [[ $v =~ ^[0-9]+$ ]]; then
    inotify_read=$((inotify_read+1)); [ "$v" -ge 512 ] || inotify_ok=0
    inotify_detail="$inotify_detail $NODE=$v"
  else
    inotify_ok=0
    if [ -n "$C" ]; then inotify_detail="$inotify_detail $NODE=unreadable (through $C)"
    else inotify_detail="$inotify_detail $NODE=unreadable (no Cilium pod on the node)"; fi
  fi
done
nodes_n=$(grep -c . <<<"$nodes_all")
[ "$nodes_n" -gt 0 ] && [ "$inotify_read" -eq "$nodes_n" ] && [ "$inotify_ok" = 1 ]
check $? "every node allows 512 inotify instances, read on the node through its Cilium agent (the Istio CNI agent fails below)" "fs.inotify.max_user_instances, $inotify_read of $nodes_n nodes read:$inotify_detail"
# The nodes as found, for environment.json
provider=$(k get nodes -o jsonpath='{.items[0].spec.providerID}' | sed -n 's#^\([a-z0-9-]*\)://.*#\1#p')
nodes_json=$(k get nodes -o json | jq -c '[.items[] | {name: .metadata.name, osImage: .status.nodeInfo.osImage, kubelet: .status.nodeInfo.kubeletVersion, containerRuntime: .status.nodeInfo.containerRuntimeVersion}]')
code "$(k get nodes -o wide | sed 's/  */ /g')"

# A failed routing check stops the run here, before the clean slate: the zone could not work across
# nodes, so the proof neither uninstalls what the cluster runs nor installs anything. The record of the
# preconditions is written and the run exits with the number of failed checks. Sections 1 to 15 below
# run only when the routing check passed; they are not indented under this if, to keep them readable.
if [ "$routing_ok" != 1 ]; then
  not_kept="the routing check failed: the run stopped before the clean slate, nothing was uninstalled or installed"
  say '' "**The routing check failed, so the run stops here, before section 1.** Nothing was uninstalled or installed: the cluster is left as found, a zone it already runs included." ''
else
# From here on the run writes to the cluster: on a participant cluster the EXIT trap tears down what it
# installed unless the zone is kept.
installed=1

# --------------------------------------------------------------------------------------------
section "1. Clean slate"
delete_stand_ins
"$INSTALL" uninstall >"$work/clean.log" 2>&1
k get ns "$MGMT" "$DATA" "$SPIRE_NS" "$ISTIO_NS" >/dev/null 2>&1; [ $? -ne 0 ]; check $? "no plane namespace and no control-plane namespace exists before the install"
left=$(k get crd -o name | grep -E 'spiffe\.io|istio\.io' || true)
[ -z "$left" ]; check $? "no SPIRE or Istio custom resource definition exists before the install" "${left:-none}"

# --------------------------------------------------------------------------------------------
section "2. install-order-idempotent: the zone from an empty cluster, twice"
start=$(date +%s)
"$INSTALL" install >"$work/install1.log" 2>&1; rc=$?
check $rc "first installer run from an empty cluster returns 0, no manual step between the releases" "$(( $(date +%s) - start ))s"
code "$(grep -E '^(  [0-9]/8|  ztd-openbao is pinned|step|zone installed)' "$work/install1.log")"
[ $rc -ne 0 ] && code "$(tail -30 "$work/install1.log")"
for r in $RELEASES; do h get manifest "${r%%:*}" -n "${r#*:}" >"$work/manifest-1-${r%%:*}.yaml" 2>/dev/null; done
start=$(date +%s)
"$INSTALL" install >"$work/install2.log" 2>&1; rc=$?
check $rc "second installer run returns 0" "$(( $(date +%s) - start ))s; $(grep -c 'deployed, revision' "$work/install2.log") releases upgraded in place"
same=0; diffs=""
for r in $RELEASES; do
  h get manifest "${r%%:*}" -n "${r#*:}" >"$work/manifest-2-${r%%:*}.yaml" 2>/dev/null
  if [ -s "$work/manifest-1-${r%%:*}.yaml" ] && diff -q "$work/manifest-1-${r%%:*}.yaml" "$work/manifest-2-${r%%:*}.yaml" >/dev/null; then same=$((same+1)); else diffs="$diffs ${r%%:*}"; fi
done
[ "$same" -eq 8 ]; check $? "helm get manifest of every release is identical between the two runs, the bootstrap Job of ztd-openbao included" "$same of 8 identical${diffs:+; differ:$diffs}"
tail -1 "$work/install2.log" | grep -q '^zone installed: every pod'; check $? "every pod in the plane and control-plane namespaces is Ready (the installer's exit condition)" "$(tail -1 "$work/install2.log")"
code "$(h list -A -o json | jq -r '(["RELEASE","NAMESPACE","REVISION","STATUS","CHART"] | join(" ")), (.[] | [.name, .namespace, .revision, .status, .chart] | join(" "))')"
# The secret store, the eighth release: the bootstrap Job keeps its state in the Secret it owns (only
# the state field is read here), and the verification hook's log names each check and a hash of the
# fixture value, never a value or a token.
bao_state=$(k -n "$MGMT" get secret ztd-openbao-bootstrap -o jsonpath='{.data.state}' 2>/dev/null | base64 -d 2>/dev/null)
[ "$bao_state" = configured ]; check $? "ztd-openbao: the bootstrap initialised, unsealed and configured the store (Secret ztd-openbao-bootstrap, state configured)" "state ${bao_state:-missing}"
bao_log=$(k -n "$MGMT" logs job/ztd-verify-openbao -c verify 2>&1)
grep -qx 'OpenBao verified' <<<"$bao_log"; check $? "ztd-openbao: the verification hook passed after the second run (initialised and unsealed, kv-v2 at secret/, transit at transit/, the fixture value read and the transit key round-tripped)" "$(tail -1 <<<"$bao_log")"
code "$bao_log"
code "$(k -n "$MGMT" get pods -o wide | sed 's/  */ /g')"
images_spire=$(k -n "$SPIRE_NS" get pods -o jsonpath='{.items[*].spec.containers[*].image} {.items[*].spec.initContainers[*].image}' | tr ' ' '\n' | grep . | sort -u | paste -sd, -)
images_istio=$(k -n "$ISTIO_NS" get pods -o jsonpath='{.items[*].spec.containers[*].image} {.items[*].spec.initContainers[*].image}' | tr ' ' '\n' | grep . | sort -u | paste -sd, -)
unpinned=$(tr ',' '\n' <<<"$images_spire,$images_istio" | grep -v '@sha256:[0-9a-f]\{64\}$' || true)
[ -n "$images_spire" ] && [ -n "$images_istio" ] && [ -z "$unpinned" ]
check $? "every image the SPIRE and Istio pods run (containers and init containers) is pinned by digest" "$(tr ',' '\n' <<<"$images_spire,$images_istio" | grep -c .) images; not pinned: ${unpinned:-none}"
code "$(k get pods -n "$SPIRE_NS" -o wide | sed 's/  */ /g'; echo; k get pods -n "$ISTIO_NS" -o wide | sed 's/  */ /g')"

# --------------------------------------------------------------------------------------------
section "3. The identity-band checks of zone-policy, and a failing step"
st=$(h status zone-policy -n "$ISTIO_NS" -o json | jq -r .info.status)
[ "$st" = deployed ]; check $? "zone-policy is deployed: the server-healthy, trust-bundle-published and registrations-reconciled jobs (weights 20, 25, 30) passed" "$st"
left=$(k -n "$ISTIO_NS" get jobs -l ztd.facis.io/identity-check -o name 2>/dev/null)
[ -z "$left" ]; check $? "the identity-check jobs were removed by their hook delete policy" "${left:-none left}"
hooked=$(h get manifest zone-policy -n "$ISTIO_NS" | python3 -c 'import sys,yaml
print(sum(1 for d in yaml.safe_load_all(sys.stdin) if d and d["kind"]=="ClusterSPIFFEID" and "helm.sh/hook" in (d["metadata"].get("annotations") or {})))')
[ "$hooked" = 0 ] && k get clusterspiffeid plane-workloads >/dev/null 2>&1; check $? "the ClusterSPIFFEID is a regular resource of the release, not a hook" "ClusterSPIFFEIDs with a hook annotation: $hooked"

out=$(STEP_TIMEOUT=1s "$INSTALL" install 2>&1); rc=$?
line=$(grep -m1 'FAILED' <<<"$out")
[ $rc -ne 0 ] && grep -q 'step 1/8 FAILED: release ztd' <<<"$out" && ! grep -q 'step 2/8' <<<"$out"
check $? "a release that does not reach a ready state within its timeout (here 1 s) stops the installer at that step, non-zero, naming the release" "$line"
st=$(h status ztd -n ztd-system -o json | jq -r .info.status)
[ "$st" = deployed ]; check $? "the failed release was rolled back by the lifecycle step" "ztd: $st, $(h history ztd -n ztd-system --max 1 -o json | jq -r '.[0].description')"

# --------------------------------------------------------------------------------------------
section "4. The layout of the control planes"
code "$(k get ns "$MGMT" "$DATA" "$SPIRE_NS" "$ISTIO_NS" -L ztd.facis.io/plane,istio-injection | sed 's/  */ /g')"
for ns in "$SPIRE_NS" "$ISTIO_NS"; do
  [ "$(k get ns "$ns" -o jsonpath='{.metadata.labels.ztd\.facis\.io/plane}')" = management ] && [ -z "$(k get ns "$ns" -o jsonpath='{.metadata.labels.istio-injection}')" ]
  check $? "$ns is a management-plane namespace without the injection label"
done
code "$(for ns in "$SPIRE_NS" "$ISTIO_NS"; do k -n "$ns" get networkpolicy,ciliumnetworkpolicy -o custom-columns=NAMESPACE:.metadata.namespace,KIND:.kind,NAME:.metadata.name,OPENING:.metadata.annotations.ztd\\.facis\\.io/declared-opening --no-headers; done | sed 's/  */ /g')"
pols() { { k -n "$1" get networkpolicy -o name; k -n "$1" get ciliumnetworkpolicy -o name; } | sed 's#.*/##' | sort | tr '\n' ' ' | sed 's/ $//'; }
want_spire="allow-control-plane-openings allow-dns-egress allow-intra-plane allow-kube-api-egress default-deny"
want_istio="allow-control-plane-openings allow-dns-egress allow-intra-plane allow-kube-api-egress allow-mesh-control-plane-ingress default-deny"
[ "$(pols "$SPIRE_NS")" = "$want_spire" ]; check $? "$SPIRE_NS holds only the default deny, the DNS bypass, the intra-plane lane, the API lane and the entity-sourced openings (webhook, agents)" "$(pols "$SPIRE_NS")"
[ "$(pols "$ISTIO_NS")" = "$want_istio" ]; check $? "$ISTIO_NS holds only the default deny, the DNS bypass, the intra-plane lane, the API lane, the webhook opening and the sidecars' xDS opening" "$(pols "$ISTIO_NS")"
sidecars=$(k -n "$SPIRE_NS" get pods -o json | jq -r '.items[] | select([.spec.containers[].name, (.spec.initContainers // [])[].name] | index("istio-proxy")) | .metadata.name')
[ -z "$sidecars" ]; check $? "no SPIRE pod has an istio-proxy container" "${sidecars:-none}"
agents_ready=$(k -n "$SPIRE_NS" get ds spire-agent -o jsonpath='{.status.numberReady}')
attested=$(spire_server agent list -output json 2>/dev/null | jq '.agents | length')
[ -n "$attested" ] && [ "$attested" = "$agents_ready" ] && [ "$attested" -gt 0 ]; check $? "every SPIRE agent is attested by the server (through the identityServer opening)" "agents Ready $agents_ready, attested $attested"
server_td=$(k -n "$SPIRE_NS" get cm spire-server -o jsonpath='{.data.server\.conf}' | jq -r .server.trust_domain)
mesh_td=$(k -n "$ISTIO_NS" get cm istio -o jsonpath='{.data.mesh}' | awk '/^trustDomain:/ {print $2}')
[ "$server_td" = "$TD" ] && [ "$mesh_td" = "$TD" ]; check $? "the SPIRE server and the mesh run with the zone's trust domain" "SPIRE $server_td, mesh $mesh_td, zone file $TD"

# --------------------------------------------------------------------------------------------
section "5. Stand-in pods"
say 'From `scripts/verify-mesh-identity/fixtures/stand-ins.yaml`: in the data plane a meshed peer, a labelled caller with a Workload API client on the CSI socket, an unlabelled meshed pod, an unlabelled pod without proxy with a Workload API client, the matrix pair `pdp-adapter` and the cross-plane caller `data-plain`; in the management plane `tsa-policy-engine`, `openbao-standin` (a management-plane destination without a lane in the allow matrix, named apart from the real store, the release `ztd-openbao`) and `mgmt-caller`; in both a proxy-less `probe` for raw TCP probes. All in the service account `stand-in` unless noted.' ''
sed -e "s/__DATA__/$DATA/g" -e "s/__MGMT__/$MGMT/g" fixtures/stand-ins.yaml >"$work/stand-ins.yaml"
# The release ztd-openbao is held to no node, on every cluster: no pod of it (the server, the
# bootstrap Job's, the verification Job's) carries a node affinity or a node selector, and the
# scheduler placed each. The server pod must be among them, so the check cannot pass on no pod.
bao_pods=$(k -n "$MGMT" get pods -o json | jq -r '.items[] | select((.metadata.labels["app.kubernetes.io/name"] // "") as $n | ["openbao","ztd-openbao-bootstrap","ztd-verify-openbao"] | index($n)) | "\(.metadata.name)=\(.spec.nodeName // "none")\(if (.spec.affinity.nodeAffinity // null) != null or ((.spec.nodeSelector // {}) | length) > 0 then "(held)" else "" end)"')
bao_held=$(grep -F '(held)' <<<"$bao_pods" || true)
grep -q '^ztd-openbao-0=' <<<"$bao_pods" && [ -z "$bao_held" ]; check $? "ztd-openbao: no pod of the release carries a node affinity or a node selector (the server and its job pods, placed by the scheduler)" "$(paste -sd' ' <<<"${bao_pods:-no pod}")"
# The stand-ins that opt out of injection go apart: the capture rule refuses them (below).
# Their refusal is asked with a server dry-run create of a copy under other names (suffix
# -capture-check): a create of a name that exists would still reach admission, but kubectl apply of
# an unchanged object sends no request at all, and an update of a pod's spec fails on pod
# immutability before the policy is asked. The callers of the two cross-node refusals (mgmt-caller of
# section 11, unregistered of section 9) go apart too: they are placed once the peer's node is known.
python3 - "$work/stand-ins.yaml" "$work/stand-ins-meshed.yaml" "$work/stand-ins-proxyless.yaml" "$work/stand-ins-proxyless-check.yaml" "$work/stand-ins-cross-node.yaml" <<'PY'
import copy, sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
off = lambda d: (d["metadata"].get("annotations") or {}).get("sidecar.istio.io/inject") == "false"
cross = lambda d: d["kind"] == "Pod" and d["metadata"]["name"] in ("mgmt-caller", "unregistered")
yaml.safe_dump_all([d for d in docs if not off(d) and not cross(d)], open(sys.argv[2], "w"), sort_keys=False)
yaml.safe_dump_all([d for d in docs if cross(d)], open(sys.argv[5], "w"), sort_keys=False)
yaml.safe_dump_all([d for d in docs if off(d)], open(sys.argv[3], "w"), sort_keys=False)
check = [copy.deepcopy(d) for d in docs if off(d)]
for d in check: d["metadata"]["name"] += "-capture-check"
yaml.safe_dump_all(check, open(sys.argv[4], "w"), sort_keys=False)
PY
# The per-node SVID stand-ins (section 6): fixtures/svid-on-node.yaml rendered once per node the SPIRE
# agent runs on, each with its own node affinity. The per-node meshed stand-ins (section 10):
# fixtures/mesh-on-node.yaml rendered once per node the same way.
SVID_NODES=$(agent_nodes)
svid_files=(); svid_pods=(); mesh_files=(); mesh_pods=()
for NODE in $SVID_NODES; do
  sed "s/__NODE__/$NODE/g" fixtures/svid-on-node.yaml >"$work/svid-on-$NODE.yaml"
  svid_files+=(-f "$work/svid-on-$NODE.yaml"); svid_pods+=("pod/svid-on-$NODE")
  sed -e "s/__NODE__/$NODE/g" -e "s/__DATA__/$DATA/g" fixtures/mesh-on-node.yaml >"$work/mesh-on-$NODE.yaml"
  mesh_files+=(-f "$work/mesh-on-$NODE.yaml"); mesh_pods+=("pod/mesh-on-$NODE")
done
say "In \`$SPIRE_NS\`, from \`scripts/verify-mesh-identity/fixtures/svid-on-node.yaml\`: one unmeshed stand-in per node with a SPIRE agent ($(paste -sd, - <<<"$SVID_NODES" | sed 's/,/, /g')), \`svid-on-<node>\`, each placed on its node by a required node affinity (section 6)." ''
say "In \`$DATA\`, from \`scripts/verify-mesh-identity/fixtures/mesh-on-node.yaml\`: one meshed stand-in per node with a SPIRE agent, \`mesh-on-<node>\` with its Service and its own service account \`mesh-on-<node>\` (so each node's stand-in has its own SPIFFE ID), the identity label, each placed on its node by a required node affinity; each serves HTTP and calls the next node's (section 10)." ''
k apply -f "$work/stand-ins-meshed.yaml" "${svid_files[@]}" "${mesh_files[@]}" >/dev/null
# The callers of the cross-node refusals: once the peer is scheduled, mgmt-caller and unregistered are
# placed by a required node affinity on a node with a SPIRE agent other than the peer's, preferring one
# that is not istiod's node either (the first such node in name order).
PEER_NODE=""
for _ in $(seq 60); do PEER_NODE=$(node_of "$DATA" peer); [ -n "$PEER_NODE" ] && break; sleep 2; done
ISTIOD_NODE=$(k -n "$ISTIO_NS" get pod -l app=istiod -o jsonpath='{.items[0].spec.nodeName}' 2>/dev/null)
CROSS_NODE=$(grep -vxF -e "${PEER_NODE:-}" -e "${ISTIOD_NODE:-}" <<<"$SVID_NODES" | grep -m1 .)
cross_note="a node that is neither the peer's nor istiod's"
if [ -z "$CROSS_NODE" ]; then
  CROSS_NODE=$(grep -vxF -e "${PEER_NODE:-}" <<<"$SVID_NODES" | grep -m1 .)
  cross_note="no node with a SPIRE agent is neither the peer's nor istiod's, so the node other than the peer's is istiod's"
fi
if [ -n "$CROSS_NODE" ] && [ -n "$PEER_NODE" ]; then
  on_node "$CROSS_NODE" "$work/stand-ins-cross-node.yaml" mgmt-caller unregistered
  say "The peer runs on \`$PEER_NODE\`; \`mgmt-caller\` and \`unregistered\`, the callers of the cross-node refusals (sections 9 and 11), are placed on \`$CROSS_NODE\` by a required node affinity: $cross_note." ''
else
  say "The callers of the cross-node refusals (\`mgmt-caller\`, \`unregistered\`) are placed by the scheduler: the peer's node is ${PEER_NODE:-unknown} and no other node with a SPIRE agent was found to place them on. The refusals of sections 9 and 11 count only between two different nodes, so their checks pass only if the scheduler happens to put the caller on a node other than the peer's, and fail otherwise; the record of each names both nodes." ''
fi
k apply -f "$work/stand-ins-cross-node.yaml" >/dev/null
proxyless=$(python3 -c 'import sys,yaml
print(", ".join("`" + d["metadata"]["name"] + "` in " + d["metadata"]["namespace"] for d in yaml.safe_load_all(open(sys.argv[1])) if d))' "$work/stand-ins-proxyless.yaml")
say '' "The three proxy-less stand-ins ($proxyless) opt out of injection, which the capture rule of \`$POLICY\` refuses in a plane namespace (section 8). They stand for the program without a proxy that the later sections show the zone resisting anyway, so the proof creates them with that one validation lifted from the policy for the time of their creation, puts it back unchanged, and checks that it refuses them again; the template and socket rules stay in force throughout." ''
# proxyless_refused: status 0 when the API server refuses every one of the three as written: a server
# dry-run create of the renamed copy, one admission request per pod, which persists nothing
proxyless_refused() {
  k create --dry-run=server -f "$work/stand-ins-proxyless-check.yaml" >"$work/proxyless.out" 2>&1
  [ "$(grep -c "ValidatingAdmissionPolicy '$POLICY'.*denied request: capture rule" "$work/proxyless.out")" = 3 ]
}
# proxyless_admitted: status 0 when the API server admits all three (the dry run returns 0)
proxyless_admitted() { k create --dry-run=server -f "$work/stand-ins-proxyless-check.yaml" >"$work/proxyless.out" 2>&1; }
proxyless_refused
n=$(grep -c "ValidatingAdmissionPolicy '$POLICY'.*denied request: capture rule" "$work/proxyless.out")
[ "$n" = 3 ]; check $? "as written, each of the three proxy-less stand-ins is refused by the capture rule of $POLICY" "$n of 3 refused: $(grep -m1 -o 'denied request: .*' "$work/proxyless.out" | cut -c1-160)"
k get validatingadmissionpolicy "$POLICY" -o json >"$work/policy.json"
idx=$(jq '[.spec.validations[].expression | contains("variables.captureDefaults")] | index(true)' "$work/policy.json")
jq -c --argjson i "${idx:-null}" '[{op: "test", path: "/spec/validations/\($i)", value: .spec.validations[$i]}, {op: "remove", path: "/spec/validations/\($i)"}]' "$work/policy.json" >"$work/lift.json" 2>/dev/null
jq -c --argjson i "${idx:-null}" '[{op: "add", path: "/spec/validations/\($i)", value: .spec.validations[$i]}]' "$work/policy.json" >"$work/restore.json" 2>/dev/null
rc_create=1; held=0
# Each API server replica takes up a policy change on its own (a provider's control plane runs more
# than one), so one admitted dry run does not mean the next request is admitted: the create is
# retried while the capture rule still refuses it (any other error ends the retries), and after the
# restore the refusal must hold five times in a row, a second apart, which the check requires. The
# lift lasts at most about 45 s: up to 20 dry runs a second apart, then up to 10 creates 2 s apart.
if [ "${idx:-null}" != null ] && k patch validatingadmissionpolicy "$POLICY" --type=json --patch-file "$work/lift.json" >/dev/null 2>&1; then
  for _ in $(seq 20); do proxyless_admitted && break; sleep 1; done
  for _ in $(seq 10); do
    k apply -f "$work/stand-ins-proxyless.yaml" >/dev/null 2>"$work/proxyless-create.err"; rc_create=$?
    [ $rc_create -eq 0 ] && break
    grep -q 'denied request: capture rule' "$work/proxyless-create.err" || break
    sleep 2
  done
  [ $rc_create -eq 0 ] || cat "$work/proxyless-create.err" >&2
  restore_capture
  for _ in $(seq 60); do if proxyless_refused; then held=$((held+1)); [ $held -ge 5 ] && break; else held=0; fi; sleep 1; done
fi
check $rc_create "with the capture validation (index ${idx:-none}) lifted, the three proxy-less stand-ins are created"
diff <(jq -S .spec "$work/policy.json") <(k get validatingadmissionpolicy "$POLICY" -o json | jq -S .spec) >/dev/null && [ "$held" -ge 5 ]
check $? "the policy is put back unchanged (its spec equals the one read before the lift) and refuses the three again, five times in a row a second apart (each API server replica takes up the change on its own)" "$(k get validatingadmissionpolicy "$POLICY" -o json | jq '.spec.validations | length') validations in force; refusals held $held of 5 in a row"
k -n "$DATA" wait --for=condition=Ready pod/peer pod/caller pod/unregistered-svid pod/probe pod/pdp-adapter pod/data-plain --timeout=240s >/dev/null 2>&1; check $? "the labelled data-plane stand-ins are Ready"
k -n "$MGMT" wait --for=condition=Ready pod/tsa-policy-engine pod/openbao-standin pod/mgmt-caller pod/probe --timeout=240s >/dev/null 2>&1; check $? "the management-plane stand-ins are Ready"
# The per-node stand-ins are counted in section 6, node by node.
[ ${#svid_pods[@]} -gt 0 ] && k -n "$SPIRE_NS" wait --for=condition=Ready "${svid_pods[@]}" --timeout=240s >/dev/null 2>&1
# The per-node meshed stand-ins are counted in section 10, node by node.
[ ${#mesh_pods[@]} -gt 0 ] && k -n "$DATA" wait --for=condition=Ready "${mesh_pods[@]}" --timeout=240s >/dev/null 2>&1
sleep 10
code "$(k get pods -n "$DATA" -o wide | sed 's/  */ /g'; echo; k get pods -n "$MGMT" -o wide | sed 's/  */ /g'; echo; k get pods -n "$SPIRE_NS" -l app.kubernetes.io/name=svid-on-node -o wide | sed 's/  */ /g')"

# --------------------------------------------------------------------------------------------
section "6. svid-over-csi-socket"
vol=$(k -n "$DATA" get pod caller -o json | jq -r '[.spec.volumes[] | select(.csi.driver == "csi.spiffe.io") | .name] | join(",")')
[ -n "$vol" ]; check $? "the labelled pod mounts the csi.spiffe.io volume" "volumes: $vol (one for the Workload API client, one for the proxy)"
k -n "$DATA" exec caller -c svid -- /opt/spire/bin/spire-agent api fetch x509 -socketPath /run/spiffe/socket -output json >"$work/svid.json" 2>"$work/svid.err"
# The JSON carries the private key too; only the certificates and the ID are kept from it.
svid_id=$(jq -r '.svids[0].spiffe_id' "$work/svid.json" 2>/dev/null)
jq -r '.svids[0].x509_svid' "$work/svid.json" | base64 -d >"$work/svid-chain.der" 2>/dev/null
openssl x509 -inform DER -in "$work/svid-chain.der" -out "$work/svid.pem" 2>/dev/null
spire_server bundle show >"$work/spire-bundle.pem" 2>/dev/null
[ "$svid_id" = "$SA_ID" ]; check $? "the SVID fetched over the mounted socket carries the SPIFFE ID of the pod's service account in the zone's trust domain" "$svid_id"
issuer=$(openssl x509 -noout -issuer -nameopt RFC2253 -in "$work/svid.pem" 2>/dev/null)
ca_subject=$(openssl x509 -noout -subject -nameopt RFC2253 -in "$work/spire-bundle.pem" 2>/dev/null)
openssl verify -CAfile "$work/spire-bundle.pem" "$work/svid.pem" >/dev/null 2>&1; check $? "the SVID chains to the SPIRE server's CA (the bundle read from the server)" "${issuer}; SPIRE CA ${ca_subject}"
code "$(openssl x509 -noout -subject -issuer -dates -ext subjectAltName -nameopt RFC2253 -in "$work/svid.pem")"
spire_server entry show -output json >"$work/entries.json" 2>/dev/null
uid_caller=$(k -n "$DATA" get pod caller -o jsonpath='{.metadata.uid}')
uid_unreg=$(k -n "$DATA" get pod unregistered -o jsonpath='{.metadata.uid}')
uid_unreg_svid=$(k -n "$DATA" get pod unregistered-svid -o jsonpath='{.metadata.uid}')
entry_for() { jq -r --arg u "k8s:pod-uid:$1" '.entries[] | select([.selectors[] | "\(.type):\(.value)"] | index($u)) | "spiffe://\(.spiffe_id.trust_domain)\(.spiffe_id.path)"' "$work/entries.json"; }
[ "$(entry_for "$uid_caller")" = "$SA_ID" ]; check $? "the SPIRE server lists an entry for the labelled pod, created from the ClusterSPIFFEID" "$(entry_for "$uid_caller")"
[ -z "$(entry_for "$uid_unreg")$(entry_for "$uid_unreg_svid")" ]; check $? "the SPIRE server lists no entry for the two unlabelled pods"
out=$(k -n "$DATA" exec unregistered-svid -c svid -- /opt/spire/bin/spire-agent api fetch x509 -socketPath /run/spiffe/socket -timeout 5s 2>&1); rc=$?
[ $rc -ne 0 ]; check $? "an unlabelled pod's fetch over the mounted socket returns no SVID" "$(grep -v 'command terminated' <<<"$out" | tail -1)"
say '' "The \`caller\` above runs on one node, the scheduler's choice. Every node with a SPIRE agent, the \`caller\`'s included, is asked too, by the per-node stand-ins of section 5 (\`svid-on-<node>\`, the \`caller\`'s \`svid\` container alone, service account \`stand-in\`, the identity label). They are unmeshed and in \`$SPIRE_NS\` because that is the plane namespace without the injection label on every cluster the proof accepts, so they need no proxy and no opt-out; the fetch is a read over a Unix socket to the agent of the pod's own node and needs no lane. The meshed stand-ins of every node are shown in section 10. They are placed one per node by their own node affinity, so the SVID is shown on every node a workload can run on:" ''
SVID_NODE_ID="spiffe://$TD/ns/$SPIRE_NS/sa/stand-in"
svid_n=$(wc -w <<<"$SVID_NODES"); svid_ready=0; svid_state=""
for NODE in $SVID_NODES; do
  s=$(k -n "$SPIRE_NS" get pod "svid-on-$NODE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)
  [ "$s" = True ] && svid_ready=$((svid_ready+1))
  svid_state="$svid_state svid-on-$NODE=${s:-absent}"
done
[ "$svid_n" -gt 0 ] && [ "$svid_ready" -eq "$svid_n" ]
check $? "one per-node SVID stand-in is Ready on every node with a SPIRE agent" "$svid_ready of $svid_n Ready:${svid_state:- no agent node}"
for NODE in $SVID_NODES; do
  pod=svid-on-$NODE; on=$(k -n "$SPIRE_NS" get pod "$pod" -o jsonpath='{.spec.nodeName}' 2>/dev/null)
  id=""
  for _ in 1 2 3 4 5 6; do
    k -n "$SPIRE_NS" exec "$pod" -c svid -- /opt/spire/bin/spire-agent api fetch x509 -socketPath /run/spiffe/socket -output json >"$work/svid-node.json" 2>/dev/null
    id=$(jq -r '.svids[0].spiffe_id // empty' "$work/svid-node.json" 2>/dev/null)
    [ -n "$id" ] && break; sleep 5
  done
  # Only the certificate is kept; the JSON with the private key goes at once.
  jq -r '.svids[0].x509_svid // empty' "$work/svid-node.json" 2>/dev/null | base64 -d 2>/dev/null \
    | openssl x509 -inform DER -out "$work/svid-node.pem" 2>/dev/null || : >"$work/svid-node.pem"
  rm -f "$work/svid-node.json"
  [ "$id" = "$SVID_NODE_ID" ] && [ "$on" = "$NODE" ]
  check $? "node $NODE: the SVID fetched over the node's mounted socket by $pod carries the SPIFFE ID of its service account in the zone's trust domain" "pod on ${on:-no node}: ${id:-no SVID}"
  [ -s "$work/svid-node.pem" ] && openssl verify -CAfile "$work/spire-bundle.pem" "$work/svid-node.pem" >/dev/null 2>&1
  check $? "node $NODE: that SVID chains to the SPIRE server's CA (the bundle read from the server)" "$(openssl x509 -noout -issuer -nameopt RFC2253 -in "$work/svid-node.pem" 2>/dev/null || echo 'no certificate')"
done
stats=$(k get clusterspiffeid plane-workloads -o jsonpath='{.status.stats}')
say "  ClusterSPIFFEID \`plane-workloads\` status: \`$stats\`"

# --------------------------------------------------------------------------------------------
section "7. native-sidecar-version"
pod=$(k -n "$DATA" get pod caller -o json)
images_proxy=$(jq -r '.spec.initContainers[] | select(.name == "istio-proxy") | .image' <<<"$pod")
jq -e '[.spec.initContainers[] | select(.name == "istio-proxy" and .restartPolicy == "Always")] | length == 1' <<<"$pod" >/dev/null \
  && jq -e '[.spec.containers[] | select(.name == "istio-proxy")] | length == 0' <<<"$pod" >/dev/null
check $? "istio-proxy is an init container with restartPolicy Always (a native sidecar), not a regular container" "$(jq -r '[.spec.initContainers[] | "\(.name)(restartPolicy=\(.restartPolicy // "-"))"] | join(", ")' <<<"$pod")"
[ "$(jq -r '.status.conditions[] | select(.type == "Ready") | .status' <<<"$pod")" = True ]; check $? "the meshed pod is Ready"
grep -q '@sha256:[0-9a-f]\{64\}$' <<<"$images_proxy"; check $? "the injected proxy's image is pinned by digest" "$images_proxy"
images_init=$(jq -r '.spec.initContainers[] | select(.name != "istio-proxy") | "\(.name)=\(.image)"' <<<"$pod")
unpinned_init=$(grep -v '@sha256:[0-9a-f]\{64\}$' <<<"$images_init" || true)
grep -q '^istio-validation=' <<<"$images_init" && [ -z "$unpinned_init" ]
check $? "the injected init containers (istio-validation) are pinned by digest" "$(paste -sd, - <<<"$images_init")"

# --------------------------------------------------------------------------------------------
section "8. mesh-identity-issued-by-spire"
istioctl --context "$CONTEXT" proxy-config secret caller -n "$DATA" >"$work/secret.txt" 2>&1
code "$(cat "$work/secret.txt")"
rootca_domains=$(proxy_leaf "$DATA" caller proxy)
subj=$(openssl x509 -noout -subject -nameopt RFC2253 -in "$work/proxy-leaf.pem" 2>/dev/null)
p_issuer=$(openssl x509 -noout -issuer -nameopt RFC2253 -in "$work/proxy-leaf.pem" 2>/dev/null)
p_uri=$(openssl x509 -noout -ext subjectAltName -in "$work/proxy-leaf.pem" 2>/dev/null | grep -o 'URI:[^,]*' | sed 's/URI://')
grep -q 'O=SPIRE' <<<"$subj"; check $? "the proxy's workload certificate (default) has O = SPIRE in its subject" "$subj"
issued_by_spire "$work/proxy-leaf.pem"
check $? "its issuer is the SPIRE server CA and it chains to SPIRE's bundle" "$p_issuer"
[ "$p_uri" = "$svid_id" ]; check $? "its URI SAN equals the SVID fetched over the socket" "$p_uri"
[ -s "$work/proxy-root.pem" ] && [ "$(fingerprint "$work/proxy-root.pem")" = "$(fingerprint "$work/spire-bundle.pem")" ]
check $? "the proxy holds a root bundle under ROOTCA, and it is the SPIRE server's CA" "ROOTCA (SPIFFE validator, trust domains: ${rootca_domains:-none}) $(fingerprint "$work/proxy-root.pem" 2>/dev/null), SPIRE CA $(fingerprint "$work/spire-bundle.pem")"
[ "$rootca_domains" = "$TD" ]; check $? "the ROOTCA bundle trusts the zone's trust domain and no other" "${rootca_domains:-none}"
k -n "$SPIRE_NS" get cm istio-ca-root-cert -o jsonpath='{.data.root-cert\.pem}' >"$work/istiod-root.pem"
[ -s "$work/istiod-root.pem" ] && openssl x509 -noout -in "$work/istiod-root.pem" >/dev/null 2>&1 \
  && ! openssl verify -CAfile "$work/istiod-root.pem" "$work/proxy-leaf.pem" >/dev/null 2>&1; check $? "istiod's own CA did not issue it (istiod's root is a certificate, and the leaf does not verify against it)" "istiod root $(openssl x509 -noout -subject -nameopt RFC2253 -in "$work/istiod-root.pem")"
say '' "istiod's CA stays on, because it also signs istiod's own serving certificates. A proxy that found no SPIRE socket would ask it for a certificate; the admission policy \`proxy-takes-spire-socket\` of zone-policy keeps such a proxy out of the plane namespaces. Server-side dry runs, which persist nothing:" ''
out=$(k -n "$DATA" run optout-templates --image=registry.k8s.io/e2e-test-images/agnhost:2.53 --restart=Never \
  --annotations=inject.istio.io/templates=sidecar --dry-run=server -o name 2>&1); rc=$?
[ $rc -ne 0 ] && grep -q "proxy-takes-spire-socket" <<<"$out"
check $? "a pod that chooses its injection templates (inject.istio.io/templates: sidecar, which drops the SPIRE socket) is refused at admission" "$(grep -o 'denied request: .*' <<<"$out" | cut -c1-220)"
out=$(printf '%s\n' 'apiVersion: v1' 'kind: Pod' 'metadata: { name: optout-proxy, annotations: { sidecar.istio.io/inject: "false" } }' \
  'spec: { containers: [ { name: istio-proxy, image: "registry.k8s.io/e2e-test-images/agnhost:2.53" } ] }' | k -n "$DATA" create --dry-run=server -f - 2>&1); rc=$?
# The opt-out annotation also breaks the capture rule; the socket rule is evaluated first and named.
[ $rc -ne 0 ] && grep -q "proxy-takes-spire-socket" <<<"$out" && grep -q 'socket rule: a mesh proxy in a plane namespace must take its certificate from SPIRE' <<<"$out"
check $? "a pod that brings its own istio-proxy without the csi.spiffe.io socket is refused at admission" "$(grep -o 'denied request: .*' <<<"$out" | cut -c1-220)"
out=$(printf '%s\n' 'apiVersion: v1' 'kind: Pod' 'metadata: { name: optout-agent, annotations: { sidecar.istio.io/inject: "false" } }' \
  "spec: { containers: [ { name: mesh, image: \"$images_proxy\", args: [proxy, sidecar], volumeMounts: [ { name: istio-token, mountPath: /var/run/secrets/tokens } ] } ]," \
  '  volumes: [ { name: istio-token, projected: { sources: [ { serviceAccountToken: { audience: istio-ca, path: istio-token } } ] } } ] }' \
  | k -n "$DATA" create --dry-run=server -f - 2>&1); rc=$?
[ $rc -ne 0 ] && grep -q "proxy-takes-spire-socket" <<<"$out" && grep -q 'socket rule: a mesh proxy in a plane namespace must take its certificate from SPIRE' <<<"$out"
check $? "a pod that runs Istio's agent itself (proxyv2, proxy sidecar) under another container name, with its own istio-token volume and no injection, is refused at admission" "$(grep -o 'denied request: .*' <<<"$out" | cut -c1-220)"
STATUS_PORT=$(h get values zone-policy -n "$ISTIO_NS" --all -o json 2>/dev/null | jq -r '.proxySocketPolicy.statusPort // empty')
say '' "The same policy holds the capture rule (capture-at-injector-defaults). The Istio CNI plugin builds a pod's redirect rules from its capture annotations, so a port excluded from the capture reaches the application outside its proxy, where STRICT never sees it, and an unregistered pod of the namespace could reach it in plaintext. The injector writes those annotations onto every pod it injects, so the policy compares their values with the injector's defaults (interception mode \`REDIRECT\`, all inbound ports, the status port \`$STATUS_PORT\` as the only excluded inbound port, all outbound ranges) and refuses the optional capture annotations, the status-port, proxy-config, proxy-image and pod-supplied proxy overrides, and, in a namespace with the injection label, the injection opt-out. Server-side dry runs in \`$DATA\`:" ''
# capture_refused <pod> <kubectl run flags...>: status 0 when the API server refuses the pod naming
# the policy and its capture rule; the refusal is left in $out
capture_refused() {
  local name=$1; shift
  out=$(k -n "$DATA" run "$name" --image=registry.k8s.io/e2e-test-images/agnhost:2.53 --restart=Never "$@" --dry-run=server -o name 2>&1)
  [ $? -ne 0 ] && grep -q "ValidatingAdmissionPolicy '$POLICY'" <<<"$out" && grep -q 'denied request: capture rule' <<<"$out"
}
refusal() { grep -v '^Warning: ' <<<"$out" | head -1 | sed 's/^Error from server (Forbidden): //' | cut -c1-200; }
capture_refused capture-excluded-port --annotations=traffic.sidecar.istio.io/excludeInboundPorts=8080
check $? "capture-at-injector-defaults: a pod that excludes an application port from the capture (traffic.sidecar.istio.io/excludeInboundPorts: \"8080\") is refused at admission" "$(refusal)"
capture_refused capture-mode-none --annotations=sidecar.istio.io/interceptionMode=NONE
check $? "capture-at-injector-defaults: a pod that switches the capture off (sidecar.istio.io/interceptionMode: NONE) is refused at admission" "$(refusal)"
capture_refused capture-status-port --annotations=status.sidecar.istio.io/port=8080
check $? "capture-at-injector-defaults: a pod that moves the status port onto an application port (status.sidecar.istio.io/port: \"8080\"), naming no excluded port itself, is refused at admission" "$(refusal)"
capture_refused capture-proxy-config "--annotations=proxy.istio.io/config=discoveryAddress: pdp-adapter.$DATA.svc:15012"
check $? "capture-at-injector-defaults: a pod that overrides its proxy's configuration (proxy.istio.io/config with a discoveryAddress in the plane) is refused at admission" "$(refusal)"
capture_refused capture-opt-out --labels=sidecar.istio.io/inject=false
check $? "capture-at-injector-defaults: a pod that opts out of injection (label sidecar.istio.io/inject: \"false\"), and would run without a proxy, is refused at admission" "$(refusal)"
capture_refused capture-proxy-image --annotations=sidecar.istio.io/proxyImage=registry.k8s.io/e2e-test-images/agnhost:2.53
check $? "capture-at-injector-defaults: a pod that swaps its proxy's image (sidecar.istio.io/proxyImage) is refused at admission" "$(refusal)"
# A pod that brings its own istio-proxy container: the injector merges it over the injected proxy and
# records it in proxy.istio.io/overrides, which the capture rule refuses.
out=$(printf '%s\n' 'apiVersion: v1' 'kind: Pod' 'metadata: { name: capture-proxy-override }' \
  'spec: { containers: [ { name: app, image: "registry.k8s.io/e2e-test-images/agnhost:2.53" }, { name: istio-proxy, image: "registry.k8s.io/e2e-test-images/agnhost:2.53" } ] }' \
  | k -n "$DATA" create --dry-run=server -f - 2>&1); rc=$?
[ $rc -ne 0 ] && grep -q "ValidatingAdmissionPolicy '$POLICY'" <<<"$out" && grep -q 'denied request: capture rule' <<<"$out"
check $? "capture-at-injector-defaults: a pod that brings its own istio-proxy container (another image, merged over the injected proxy and recorded in proxy.istio.io/overrides) is refused at admission" "$(refusal)"
say '' "Behind the capture rule, the proxy rule of the same policy holds every mesh proxy to the injector's own, whatever path brought it into the pod: named \`istio-proxy\`, the image \`$images_proxy\`, the injector's arguments, environment, mounts, lifecycle, probes and securityContext, and only in a namespace with the injection label. Proxies that pass the socket and capture rules (each mounts the SPIRE socket, and no override is recorded), server-side dry runs in \`$DATA\`:" ''
# proxy_refused: status 0 when the last dry run ($rc, $out) was refused naming the policy and its proxy rule
proxy_refused() { [ "$rc" -ne 0 ] && grep -q "ValidatingAdmissionPolicy '$POLICY'" <<<"$out" && grep -q 'denied request: proxy rule' <<<"$out"; }
# A pod that claims to be injected already (sidecar.istio.io/status) has its own istio-proxy merged
# over the injected one without proxy.istio.io/overrides: the image is the pod's, the SPIRE socket
# mount the injector's.
out=$(printf '%s\n' 'apiVersion: v1' 'kind: Pod' 'metadata: { name: proxy-other-image, annotations: { sidecar.istio.io/status: "{\"containers\":[\"istio-proxy\"]}" } }' \
  'spec: { containers: [ { name: app, image: "registry.k8s.io/e2e-test-images/agnhost:2.53" }, { name: istio-proxy, image: "registry.k8s.io/e2e-test-images/agnhost:2.53" } ] }' \
  | k -n "$DATA" create --dry-run=server -f - 2>&1); rc=$?
proxy_refused
check $? "proxy rule: a pod whose istio-proxy runs another image and mounts the SPIRE socket (merged over the injected proxy under a pre-set sidecar.istio.io/status, so no override is recorded) is refused at admission, naming the proxy rule" "$(refusal)"
out=$(printf '%s\n' 'apiVersion: v1' 'kind: Pod' 'metadata: { name: proxy-second }' \
  "spec: { containers: [ { name: app, image: \"registry.k8s.io/e2e-test-images/agnhost:2.53\" }, { name: mesh, image: \"$images_proxy\"," \
  '    args: [proxy, sidecar, --domain, $(POD_NAMESPACE).svc.cluster.local, --proxyLogLevel=warning, --proxyComponentLogLevel=misc:error, --log_output_level=default:info],' \
  '    env: [ { name: PROXY_CONFIG, value: "{\"proxyBootstrapTemplatePath\": \"/etc/mesh/bootstrap.json\"}" } ],' \
  '    volumeMounts: [ { name: workload-socket, mountPath: /var/run/secrets/workload-spiffe-uds } ] } ] }' \
  | k -n "$DATA" create --dry-run=server -f - 2>&1); rc=$?
proxy_refused
check $? "proxy rule: a second proxy next to the injected one (container mesh, the injector's image and arguments, its own PROXY_CONFIG, the SPIRE socket mounted) is refused at admission: every mesh proxy is the injector's istio-proxy" "$(refusal)"
# Control: the same pre-set status with the injector's own image and nothing added is admitted, so
# the two refusals below come from what each adds.
out=$(printf '%s\n' 'apiVersion: v1' 'kind: Pod' 'metadata: { name: proxy-preset, annotations: { sidecar.istio.io/status: "{\"containers\":[\"istio-proxy\"]}" } }' \
  "spec: { containers: [ { name: app, image: \"registry.k8s.io/e2e-test-images/agnhost:2.53\" }, { name: istio-proxy, image: \"$images_proxy\" } ] }" \
  | k -n "$DATA" create --dry-run=server -f - 2>&1); rc=$?
check $rc "proxy rule: the same pre-set sidecar.istio.io/status with an istio-proxy of the injector's image and nothing else is admitted (the control for the next two refusals)" "$(grep -v '^Warning: ' <<<"$out" | head -1 | cut -c1-200)"
# The same pre-set status with the injector's own image: everything the injector writes stays, and
# only what the pod adds to istio-proxy differs. A postStart hook would run the pod's own command in
# the proxy container as UID 1337, whose traffic leaves without capture; NET_ADMIN would let it
# rewrite the pod's redirect rules.
out=$(printf '%s\n' 'apiVersion: v1' 'kind: Pod' 'metadata: { name: proxy-hook, annotations: { sidecar.istio.io/status: "{\"containers\":[\"istio-proxy\"]}" } }' \
  "spec: { containers: [ { name: app, image: \"registry.k8s.io/e2e-test-images/agnhost:2.53\" }, { name: istio-proxy, image: \"$images_proxy\"," \
  '    lifecycle: { postStart: { exec: { command: [sh, -c, "echo hook"] } } } } ] }' \
  | k -n "$DATA" create --dry-run=server -f - 2>&1); rc=$?
proxy_refused
check $? "proxy rule: a pod whose istio-proxy runs the injector's image but adds its own postStart hook (exec sh -c, under a pre-set sidecar.istio.io/status) is refused at admission: the proxy's lifecycle is the injector's (pilot-agent drain or wait) or none" "$(refusal)"
out=$(printf '%s\n' 'apiVersion: v1' 'kind: Pod' 'metadata: { name: proxy-net-admin, annotations: { sidecar.istio.io/status: "{\"containers\":[\"istio-proxy\"]}" } }' \
  "spec: { containers: [ { name: app, image: \"registry.k8s.io/e2e-test-images/agnhost:2.53\" }, { name: istio-proxy, image: \"$images_proxy\"," \
  '    securityContext: { capabilities: { add: [NET_ADMIN] } } } ] }' \
  | k -n "$DATA" create --dry-run=server -f - 2>&1); rc=$?
proxy_refused
check $? "proxy rule: a pod whose istio-proxy runs the injector's image but adds the NET_ADMIN capability (under a pre-set sidecar.istio.io/status) is refused at admission: the proxy's securityContext is the injector's (UID and GID 1337, non-root, every capability dropped, read-only root)" "$(refusal)"
# A subPath on the socket mount would put a file or a subdirectory of the SPIRE volume where the agent
# looks for the socket; it would find none and ask istiod's CA. The socket rule requires the mount whole.
out=$(printf '%s\n' 'apiVersion: v1' 'kind: Pod' 'metadata: { name: proxy-socket-subpath, annotations: { sidecar.istio.io/status: "{\"containers\":[\"istio-proxy\"]}" } }' \
  "spec: { containers: [ { name: app, image: \"registry.k8s.io/e2e-test-images/agnhost:2.53\" }, { name: istio-proxy, image: \"$images_proxy\"," \
  '    volumeMounts: [ { name: workload-socket, mountPath: /var/run/secrets/workload-spiffe-uds, subPath: socket } ] } ] }' \
  | k -n "$DATA" create --dry-run=server -f - 2>&1); rc=$?
[ $rc -ne 0 ] && grep -q "ValidatingAdmissionPolicy '$POLICY'" <<<"$out" && grep -q 'socket rule: a mesh proxy in a plane namespace must take its certificate from SPIRE' <<<"$out"
check $? "socket rule: a pod whose istio-proxy mounts the SPIRE socket volume with a subPath (under a pre-set sidecar.istio.io/status), so that its agent would find no socket and fall back to istiod's CA, is refused at admission, naming the socket rule: the socket mount is whole, without subPath, subPathExpr or mount propagation" "$(refusal)"
plain=$(k -n "$DATA" run optout-none --image=registry.k8s.io/e2e-test-images/agnhost:2.53 --restart=Never --dry-run=server -o json 2>&1)
jq -e '.spec.volumes[] | select(.name == "workload-socket" and .csi.driver == "csi.spiffe.io")' <<<"$plain" >/dev/null
check $? "an ordinary pod in the same namespace is admitted, its proxy on the SPIRE socket"
out=$(k -n "$DATA" run proxy-prometheus --image=registry.k8s.io/e2e-test-images/agnhost:2.53 --restart=Never \
  --annotations=prometheus.io/scrape=true --annotations=prometheus.io/port=9090 --dry-run=server -o json 2>&1)
jq -e '[(.spec.initContainers // [])[], .spec.containers[]] | map(select(.name == "istio-proxy")) | .[0].env | map(.name) | index("ISTIO_PROMETHEUS_ANNOTATIONS")' <<<"$out" >/dev/null
check $? "proxy rule: an ordinary pod annotated prometheus.io/scrape \"true\" and prometheus.io/port \"9090\" is admitted, its proxy carrying the ISTIO_PROMETHEUS_ANNOTATIONS the injector writes under the mesh's enablePrometheusMerge" \
  "$(jq -c '[(.spec.initContainers // [])[], .spec.containers[]] | map(select(.name == "istio-proxy")) | .[0].env | map(select(.name == "ISTIO_PROMETHEUS_ANNOTATIONS")) | .[0] // empty' <<<"$out" 2>/dev/null || grep -v '^Warning: ' <<<"$out" | head -1 | cut -c1-200)"
# The equality check reads the plain ordinary pod (optout-none), not the prometheus.io one above.
excluded=$(jq -r '.metadata.annotations["traffic.sidecar.istio.io/excludeInboundPorts"] // "absent"' <<<"$plain" 2>/dev/null)
mode=$(jq -r '.metadata.annotations["sidecar.istio.io/interceptionMode"] // "absent"' <<<"$plain" 2>/dev/null)
[ "$excluded" = "$STATUS_PORT" ] && [ "$mode" = REDIRECT ]
check $? "capture-at-injector-defaults: the equality rule admits exactly what the injector writes: the admitted pod carries traffic.sidecar.istio.io/excludeInboundPorts \"$STATUS_PORT\" (the status port alone) and sidecar.istio.io/interceptionMode REDIRECT" \
  "$(jq -c '.metadata.annotations // {} | with_entries(select(.key | test("^(traffic\\.)?sidecar\\.istio\\.io/(interceptionMode|includeInboundPorts|excludeInboundPorts|includeOutboundIPRanges)$")))' <<<"$plain" 2>/dev/null)"
say '' "The injection opt-out is refused only where the namespace carries the injection label. The control-plane namespaces the zone file declares \`mesh: false\` carry the plane label but no injection label, and Istio's own pods there opt out of injection; a server-side dry run of a pod built from the installed istiod Deployment's and istio-cni DaemonSet's pod templates, as their controllers would recreate them in \`$ISTIO_NS\`:" ''
for w in deployment/istiod daemonset/istio-cni-node; do
  out=$(k -n "$ISTIO_NS" get "$w" -o json | jq --arg n "capture-recreate-${w#*/}" \
    '{apiVersion: "v1", kind: "Pod", metadata: {name: $n, labels: .spec.template.metadata.labels, annotations: .spec.template.metadata.annotations}, spec: .spec.template.spec}' \
    | k -n "$ISTIO_NS" create --dry-run=server -f - 2>&1); rc=$?
  check $rc "capture-at-injector-defaults: the $w pod, which carries sidecar.istio.io/inject \"false\", is admitted in $ISTIO_NS (no injection label), so its controller can recreate it" "$(grep -v '^Warning: ' <<<"$out" | head -1 | cut -c1-200)"
  out=$(k -n "$ISTIO_NS" get "$w" -o json | jq --arg n "capture-recreate-${w#*/}" \
    '{apiVersion: "v1", kind: "Pod", metadata: {name: $n, labels: .spec.template.metadata.labels, annotations: .spec.template.metadata.annotations}, spec: (.spec.template.spec | del(.serviceAccountName, .serviceAccount))}' \
    | k -n "$DATA" create --dry-run=server -f - 2>&1); rc=$?
  [ $rc -ne 0 ] && grep -q "ValidatingAdmissionPolicy '$POLICY'" <<<"$out" && grep -q 'denied request: capture rule' <<<"$out"
  check $? "capture-at-injector-defaults: the same $w pod is refused in $DATA, which carries the injection label" "$(refusal)"
done
say '' "The policy also runs on every pod update and on every status update (\`pods/status\`, which can change annotations too). The capture and proxy rules look only at what an update changes (an annotation or label whose value is unchanged, a container whose name and image are unchanged is not checked again), so a running pod still takes a label after an Istio upgrade; what the update adds is checked, and an update may not remove the injector's \`sidecar.istio.io/status\` or capture annotations. Server-side dry runs against the running proxy-less \`probe\` in \`$DATA\`, which carries the opt-out from its creation in section 5, and against the running injected \`peer\`:" ''
out=$(k -n "$DATA" label pod probe mesh-identity/update-check=1 --dry-run=server 2>&1); rc=$?
check $rc "capture-at-injector-defaults: a label added to a running pod is admitted although the pod carries the opt-out: unchanged metadata is not checked again" "$(head -1 <<<"$out" | cut -c1-200)"
out=$(k -n "$DATA" annotate pod probe traffic.sidecar.istio.io/excludeInboundPorts=8080 --dry-run=server 2>&1); rc=$?
[ $rc -ne 0 ] && grep -q "ValidatingAdmissionPolicy '$POLICY'" <<<"$out" && grep -q 'denied request: capture rule' <<<"$out"
check $? "capture-at-injector-defaults: an update that adds an excluded port to the same running pod is refused" "$(refusal)"
out=$(k -n "$DATA" patch pod probe --subresource=status --type=merge \
  -p "{\"metadata\":{\"annotations\":{\"proxy.istio.io/config\":\"discoveryAddress: pdp-adapter.$DATA.svc:15012\"}}}" --dry-run=server 2>&1); rc=$?
[ $rc -ne 0 ] && grep -q "ValidatingAdmissionPolicy '$POLICY'" <<<"$out" && grep -q 'denied request: capture rule' <<<"$out"
check $? "capture-at-injector-defaults: the same annotation change through the pods/status subresource (proxy.istio.io/config added by a status update) is refused: the policy also matches status updates" "$(refusal)"
out=$(k -n "$DATA" patch pod peer --subresource=status --type=strategic \
  -p '{"status":{"conditions":[{"type":"mesh-identity/update-check","status":"True"}]}}' --dry-run=server 2>&1); rc=$?
check $rc "capture-at-injector-defaults: a status update that changes no annotation (a pod condition on the running injected peer) is admitted, as the kubelet's and the controllers' are" "$(grep -v '^Warning: ' <<<"$out" | head -1 | cut -c1-200)"
out=$(k -n "$DATA" annotate pod peer sidecar.istio.io/status- --dry-run=server 2>&1); rc=$?
[ $rc -ne 0 ] && grep -q "ValidatingAdmissionPolicy '$POLICY'" <<<"$out" && grep -q 'denied request: capture rule' <<<"$out"
check $? "capture-at-injector-defaults: an update that removes sidecar.istio.io/status from the running injected peer (without it the CNI plugin sets up no redirect the next time it runs for the pod) is refused" "$(refusal)"

say '' "Outside the plane namespaces the policy does not apply, and istiod's injector still injects a pod labelled \`sidecar.istio.io/inject: \"true\"\` with the templates it names. A pod in a scratch namespace without the plane label:" ''
OUTSIDE=mesh-identity-outside
k create namespace "$OUTSIDE" >/dev/null
out=$(k -n "$OUTSIDE" run outside --image=registry.k8s.io/e2e-test-images/agnhost:2.53 --restart=Never --labels=sidecar.istio.io/inject=true \
  --annotations=inject.istio.io/templates=sidecar --dry-run=server -o json 2>&1)
jq -e '[(.spec.initContainers // [])[].name] | index("istio-proxy")' <<<"$out" >/dev/null \
  && ! jq -e '.spec.volumes[] | select(.csi.driver == "csi.spiffe.io")' <<<"$out" >/dev/null
check $? "there it is admitted with a proxy and no SPIRE socket: that proxy would ask istiod's CA" "containers: $(jq -r '[(.spec.initContainers // [])[].name, .spec.containers[].name] | join(",")' <<<"$out" 2>/dev/null)"
printf '%s\n' 'apiVersion: v1' 'kind: Pod' 'metadata: { name: probe }' \
  'spec: { terminationGracePeriodSeconds: 2, containers: [ { name: app, image: "docker.io/curlimages/curl:8.10.1@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b", command: [sleep, "3600"] } ] }' \
  >"$work/outside-probe.yaml"
k -n "$OUTSIDE" create -f "$work/outside-probe.yaml" >/dev/null
k -n "$OUTSIDE" wait --for=condition=Ready pod/probe --timeout=120s >/dev/null 2>&1
ISTIOD_IP=$(k -n "$ISTIO_NS" get pod -l app=istiod -o jsonpath='{.items[0].status.podIP}')
r=$(tcp "$OUTSIDE" probe "$ISTIOD_IP" 15012)
case $r in denied*) true;; *) false;; esac; check $? "but istiod's CA (15012) is not reachable from a namespace without the plane label: the meshControlPlane opening admits the plane namespaces only" "→ $r"
k delete namespace "$OUTSIDE" --wait=true >/dev/null 2>&1

say '' "What no admission rule can close is a program that is not a mesh proxy by any of the policy's marks and calls istiod's CA on 15012 from a plane namespace itself. The guarantee against it is that no peer trusts istiod's CA. A certificate for the labelled caller's own SPIFFE ID, signed with istiod's CA key (read from \`istio-ca-secret\`, the key istiod signs every certificate with), is presented to the meshed peer's proxy from the proxy-less \`probe\` pod, next to the caller's SPIRE SVID:" ''
k -n "$ISTIO_NS" get secret istio-ca-secret -o jsonpath='{.data.ca-cert\.pem}' | base64 -d >"$work/istiod-ca.pem" 2>/dev/null
k -n "$ISTIO_NS" get secret istio-ca-secret -o jsonpath='{.data.ca-key\.pem}' | base64 -d >"$work/istiod-ca.key" 2>/dev/null
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj / -keyout "$work/istiod-leaf.key" -out "$work/istiod-leaf.csr" >/dev/null 2>&1
printf 'subjectAltName=critical,URI:%s\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nbasicConstraints=critical,CA:FALSE\n' "$SA_ID" >"$work/istiod-leaf.ext"
openssl x509 -req -in "$work/istiod-leaf.csr" -CA "$work/istiod-ca.pem" -CAkey "$work/istiod-ca.key" -set_serial "0x$(openssl rand -hex 8)" \
  -days 1 -extfile "$work/istiod-leaf.ext" -out "$work/istiod-leaf.pem" >/dev/null 2>&1
rm -f "$work/istiod-ca.key"
il_uri=$(openssl x509 -noout -ext subjectAltName -in "$work/istiod-leaf.pem" 2>/dev/null | grep -o 'URI:[^,]*' | sed 's/URI://')
openssl verify -CAfile "$work/istiod-root.pem" "$work/istiod-leaf.pem" >/dev/null 2>&1 && [ "$il_uri" = "$SA_ID" ]
check $? "the certificate verifies against istiod's root (istio-ca-root-cert) and carries the caller's SPIFFE ID" "$il_uri, $(openssl x509 -noout -issuer -nameopt RFC2253 -in "$work/istiod-leaf.pem" 2>/dev/null)"
jq -r '.svids[0].x509_svid_key' "$work/svid.json" | base64 -d | openssl pkey -inform DER -out "$work/svid.key" 2>/dev/null
for f in istiod-leaf.pem istiod-leaf.key svid.pem svid.key; do k -n "$DATA" exec -i probe -c app -- tee "/tmp/$f" <"$work/$f" >/dev/null; done
PEER_IP=$(k -n "$DATA" get pod peer -o jsonpath='{.status.podIP}')
# mtls <cert> <key> [curl option...]: an HTTPS request straight to the peer's proxy, presenting that
# client certificate; the options (a TLS version bound) go to curl as they stand. curl writes its
# error line to stdout (--stderr -) and the HTTP code on a line of its own, so the one stream keeps
# both whole (kubectl can interleave a container's stdout and stderr mid-line).
mtls() { local cert=$1 key=$2; shift 2; k -n "$DATA" exec probe -c app -- curl -sS --stderr - -k -m 15 "$@" --cert "/tmp/$cert" --key "/tmp/$key" -w '\n%{http_code}\n' "https://$PEER_IP:8080/hostname" 2>&1; }
out=$(mtls svid.pem svid.key)
[ "$(tail -1 <<<"$out")" = 200 ]; check $? "with the caller's SPIRE SVID the peer's proxy completes the handshake and the request succeeds" "→ $(tr '\n' ' ' <<<"$out")"
# Under TLS 1.3 the peer verifies the client certificate after the client has finished its side of
# the handshake, so its alert races curl's request: curl reads the alert, or writes into the closed
# connection first (55, broken pipe), which shows the refusal but not its reason. Up to three tries,
# each recorded with curl's error line and HTTP code (the last line of exactly three digits, curl's
# %{http_code}; kubectl may add "command terminated ..." after it). A try is unanswered only when the
# code is 000 (no HTTP reply); any other code (200, 503, ...) means the peer accepted the certificate,
# and no code at all means the try cannot be judged: both fail the check at once. One unanswered try
# must show the TLS alert in curl's own error line ("curl: (NN) ... alert ..."); with the code 000
# no reply was read, so no reply body can supply that text.
alert=1; refusals=""
for try in 1 2 3; do
  out=$(mtls istiod-leaf.pem istiod-leaf.key)
  code=$(grep -xE '[0-9]{3}' <<<"$out" | tail -1)
  err=$(grep -m1 -oE 'curl: \([0-9]+\) .*' <<<"$out")
  refusals="$refusals${refusals:+; }try $try: HTTP ${code:-none}${err:+, $err}"
  if [ "$code" != 000 ]; then alert=2; break; fi
  grep -q 'alert' <<<"$err" && { alert=0; break; }
done
[ "$alert" = 0 ]
check $? "with the istiod-signed certificate for the same SPIFFE ID the peer's proxy refuses the handshake with a TLS alert: its ROOTCA is SPIRE's bundle only (up to three tries, none answered)" "→ $refusals"
say '' "The security baseline sets TLS 1.3 as the minimum (ADR 005), and the \`istiod\` release raises the mesh mTLS minimum to it (\`meshConfig.meshMTLS.minProtocolVersion: TLSV1_3\`; Istio's default is TLS 1.2). The same SVID, once at TLS 1.3 and once with TLS 1.2 as the highest version offered:" ''
out=$(mtls svid.pem svid.key --tlsv1.3)
[ "$(tail -1 <<<"$out")" = 200 ]; check $? "at TLS 1.3 with the caller's SPIRE SVID the peer's proxy completes the handshake and the request succeeds" "→ $(tr '\n' ' ' <<<"$out")"
out=$(mtls svid.pem svid.key --tls-max 1.2)
[ "$(tail -1 <<<"$out")" != 200 ] && grep -qiE 'alert protocol version|tlsv1 alert|protocol version' <<<"$out"
check $? "capped at TLS 1.2 with the same SVID the peer's proxy refuses the handshake with a protocol alert: the mesh mTLS minimum is TLS 1.3" "→ $(grep -o 'curl: .*' <<<"$out" | head -1)"
k -n "$DATA" exec probe -c app -- rm -f /tmp/istiod-leaf.pem /tmp/istiod-leaf.key /tmp/svid.pem /tmp/svid.key >/dev/null 2>&1

# --------------------------------------------------------------------------------------------
section "9. unregistered-workload-cut-off"
# The pod never runs (its proxy is not ready), so istioctl cannot port-forward to it; the proxy's
# own admin endpoint is read through the running container instead.
active=$(k -n "$DATA" exec unregistered -c istio-proxy -- pilot-agent request GET 'config_dump?resource=dynamic_active_secrets' 2>/dev/null | jq -c '[.configs[]? | .name]')
warming=$(k -n "$DATA" exec unregistered -c istio-proxy -- pilot-agent request GET 'config_dump?resource=dynamic_warming_secrets' 2>/dev/null | jq -c '[.configs[]? | .name]')
[ -n "$active" ] && ! jq -e 'index("default")' <<<"$active" >/dev/null && jq -e 'index("default")' <<<"$warming" >/dev/null
check $? "the unlabelled pod's proxy holds no workload certificate: it asked for 'default' and was never served" "active secrets $active, still warming $warming"
log=$(k -n "$DATA" logs unregistered -c istio-proxy --tail=200 2>/dev/null | grep -m1 -o 'workload is not authorized for the requested identities[^{]*')
[ -n "$log" ]; check $? "the SPIRE agent refuses its proxy over SDS" "$log"
appstate=$(k -n "$DATA" get pod unregistered -o jsonpath='{.status.containerStatuses[?(@.name=="app")].state}')
grep -q waiting <<<"$appstate"; check $? "its application container never starts: the native sidecar holds it until the proxy has a certificate" "$appstate"
r=$(http "$DATA" unregistered istio-proxy "http://peer.$DATA.svc:8080/hostname")
from=$(node_of "$DATA" unregistered); to=$(node_of "$DATA" peer)
case $r in denied*) [ -n "$from" ] && [ -n "$to" ] && [ "$from" != "$to" ];; *) false;; esac
check $? "a call from its network namespace, on another node than the peer's, to the meshed peer is refused: the peer accepts mTLS only (STRICT)" "unregistered on ${from:-no node} → peer on ${to:-no node}: $r"
r=$(http "$DATA" caller app "http://peer.$DATA.svc:8080/hostname")
[ "${r%% *}" = 200 ]; check $? "the labelled pod's call to the same peer succeeds" "→ $r"

# --------------------------------------------------------------------------------------------
section "10. traffic-through-the-proxies"
src0=$(metric "$DATA" caller source); dst0=$(metric "$DATA" peer destination)
xfcc=$(k -n "$DATA" exec caller -c app -- curl -sS -m 15 "http://peer.$DATA.svc:8080/header?key=X-Forwarded-Client-Cert" 2>&1)
grep -qF "URI=$SA_ID" <<<"$xfcc"; check $? "the peer sees the caller's SPIFFE identity in X-Forwarded-Client-Cert" "$xfcc"
sleep 3
src1=$(metric "$DATA" caller source); dst1=$(metric "$DATA" peer destination)
[ "$src1" -gt "$src0" ] && [ "$dst1" -gt "$dst0" ]; check $? "both proxies counted the request (istio_requests_total)" "caller (reporter=source) $src0 → $src1, peer (reporter=destination) $dst0 → $dst1"
k -n "$DATA" exec peer -c istio-proxy -- pilot-agent request GET stats/prometheus 2>/dev/null | grep '^istio_requests_total' | grep -q 'connection_security_policy="mutual_tls"'
check $? "the peer's proxy records the requests as mutual_tls"
say '' '### mesh-on-every-node' ''
say "One meshed stand-in per node with a SPIRE agent (\`mesh-on-<node>\`, section 5), one check per node: placed on its node, Ready (so its native-sidecar proxy is ready), and the workload certificate its proxy holds is issued by the SPIRE CA with that stand-in's own SPIFFE ID (\`spiffe://$TD/ns/$DATA/sa/mesh-on-<node>\`, one service account per node), read with \`istioctl proxy-config secret\` and checked as in \`mesh-identity-issued-by-spire\` (section 8)." ''
MESH_NODES=$SVID_NODES
mesh_n=$(wc -w <<<"$MESH_NODES")
# mesh_id <node>: the SPIFFE ID of the meshed stand-in of <node>, from its own service account
mesh_id() { echo "spiffe://$TD/ns/$DATA/sa/mesh-on-$1"; }
for NODE in $MESH_NODES; do
  pod=mesh-on-$NODE; on=$(node_of "$DATA" "$pod")
  ready=$(k -n "$DATA" get pod "$pod" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)
  proxy_leaf "$DATA" "$pod" "mesh-$NODE" >/dev/null
  uri=$(openssl x509 -noout -ext subjectAltName -in "$work/mesh-$NODE-leaf.pem" 2>/dev/null | grep -o 'URI:[^,]*' | sed 's/URI://')
  iss=$(openssl x509 -noout -issuer -nameopt RFC2253 -in "$work/mesh-$NODE-leaf.pem" 2>/dev/null)
  [ "$on" = "$NODE" ] && [ "$ready" = True ] && [ "$uri" = "$(mesh_id "$NODE")" ] && issued_by_spire "$work/mesh-$NODE-leaf.pem"
  check $? "node $NODE: the meshed stand-in $pod runs on the node and is Ready, and its proxy's certificate is issued by the SPIRE CA with its own SPIFFE ID $(mesh_id "$NODE")" "on ${on:-no node}, Ready ${ready:-absent}, ${uri:-no certificate}, ${iss:-no issuer}"
done
say '' '### cross-node-calls' ''
say "With the nodes in name order, the meshed stand-in of node *i* calls the one of node *(i+1) mod N* through its Service (agnhost \`/header?key=X-Forwarded-Client-Cert\`): every node is then a caller and a receiver across a node boundary, in N calls. Each stand-in has its own SPIFFE ID, so the caller and the receiver of a call can be told apart. Each call is checked for: the two nodes differ, the receiver saw the caller's own SPIFFE ID in \`X-Forwarded-Client-Cert\`, the caller's proxy counted a request whose receiver presented the receiver's own SPIFFE ID in the handshake (reporter=source, \`destination_principal\`), and the receiver's proxy counted a request over mutual TLS (reporter=destination, \`connection_security_policy=\"mutual_tls\"\`)." ''
if [ "$mesh_n" -lt 2 ]; then
  false; check $? "a call crosses nodes through the mesh: two nodes with a SPIRE agent are needed, one to call from and one to receive" "nodes with a SPIRE agent: $mesh_n (${MESH_NODES:-none})"
else
  mapfile -t ring <<<"$MESH_NODES"
  for i in "${!ring[@]}"; do
    from=${ring[$i]}; to=${ring[$(( (i + 1) % mesh_n ))]}
    src=mesh-on-$from; dst=mesh-on-$to
    on_from=$(node_of "$DATA" "$src"); on_to=$(node_of "$DATA" "$dst")
    from_id=$(mesh_id "$from"); to_id=$(mesh_id "$to")
    s0=$(mtls_requests "$DATA" "$src" source "destination_principal=\"$to_id\""); d0=$(mtls_requests "$DATA" "$dst" destination 'connection_security_policy="mutual_tls"')
    xfcc=$(k -n "$DATA" exec "$src" -c curl -- curl -sS -m 15 "http://$dst.$DATA.svc:8080/header?key=X-Forwarded-Client-Cert" 2>&1)
    seen=$(grep -o 'URI=[^;,]*' <<<"$xfcc" | head -1 | sed 's/^URI=//')
    sleep 3
    s1=$(mtls_requests "$DATA" "$src" source "destination_principal=\"$to_id\""); d1=$(mtls_requests "$DATA" "$dst" destination 'connection_security_policy="mutual_tls"')
    [ -n "$on_from" ] && [ -n "$on_to" ] && [ "$on_from" != "$on_to" ] && [ "$seen" = "$from_id" ] && [ "$s1" -gt "$s0" ] && [ "$d1" -gt "$d0" ]
    check $? "call $((i + 1)) of $mesh_n: $src (node $on_from) → $dst (node $on_to) crosses nodes, the receiver sees the caller's own SPIFFE ID, the caller's proxy saw the receiver's own, and both proxies count it as mutual TLS" "caller node ${on_from:-none}, receiver node ${on_to:-none}, identity received ${seen:-none ($(head -1 <<<"$xfcc" | cut -c1-120))} (caller's: $from_id); caller (reporter=source, destination_principal=$to_id) $s0 → $s1, receiver (reporter=destination, mutual_tls) $d0 → $d1"
  done
fi

# --------------------------------------------------------------------------------------------
section "11. default-deny-with-chained-cni"
for P in $(k -n "$ISTIO_NS" get pod -l k8s-app=istio-cni-node -o jsonpath='{.items[*].metadata.name}'); do
  NODE=$(k -n "$ISTIO_NS" get pod "$P" -o jsonpath='{.spec.nodeName}')
  conf=$(k -n "$ISTIO_NS" exec "$P" -- sh -c 'ls /host/etc/cni/net.d/*.conflist | head -1')
  plugins=$(k -n "$ISTIO_NS" exec "$P" -- cat "$conf" | jq -r '[.plugins[].type] | join(" → ")')
  [[ "$plugins" == cilium-cni*istio-cni* ]]; check $? "the CNI configuration of node $NODE lists the Istio plugin after Cilium" "${conf#/host}: $plugins"
done
[ "$excl" = false ]; check $? "Cilium still runs with cni-exclusive=false" "cni-exclusive=$excl"
r=$(http "$DATA" data-plain app "http://openbao-standin.$MGMT.svc:8080/hostname")
case $r in denied*) true;; *) false;; esac; check $? "data-plane pod → openbao-standin (management): DENIED at the network layer with the proxies in place" "→ $r"
r=$(http "$DATA" data-plain app "http://tsa-policy-engine.$MGMT.svc:8080/hostname")
case $r in denied*) true;; *) false;; esac; check $? "data-plane pod → tsa-policy-engine (management): DENIED" "→ $r"
r=$(http "$DATA" pdp-adapter app "http://tsa-policy-engine.$MGMT.svc:8080/hostname")
[ "${r%% *}" = 200 ]; check $? "pdp-adapter → tsa-policy-engine: ALLOWED (matrix lane pdp-adapter-to-tsa), through the proxies" "→ $r"
r=$(http "$DATA" pdp-adapter app "http://openbao-standin.$MGMT.svc:8080/hostname")
case $r in denied*) true;; *) false;; esac; check $? "pdp-adapter → openbao-standin: DENIED (a lane is one pair, not a licence)" "→ $r"
r=$(http "$MGMT" mgmt-caller app "http://peer.$DATA.svc:8080/hostname")
from=$(node_of "$MGMT" mgmt-caller); to=$(node_of "$DATA" peer)
case $r in denied*) [ -n "$from" ] && [ -n "$to" ] && [ "$from" != "$to" ];; *) false;; esac
check $? "management pod → data plane, from another node than the peer's: DENIED (the default deny is both directions, across nodes)" "mgmt-caller on ${from:-no node} → peer on ${to:-no node}: $r"
r=$(k -n "$DATA" exec probe -c app -- nslookup "openbao-standin.$MGMT.svc.cluster.local" 2>&1 | grep -A1 '^Name:' | tr '\n' ' ')
[ -n "$r" ]; check $? "DNS bypass: names still resolve" "$r"

# --------------------------------------------------------------------------------------------
section "12. control-planes-under-default-deny"
istioctl --context "$CONTEXT" proxy-status -o json >"$work/ps.json" 2>/dev/null
unsynced=$(jq -r --arg ns "$DATA" '.resources[] | select(.node.metadata.NAMESPACE == $ns and (.node.id | test("^(caller|peer|pdp-adapter|data-plain)\\."))) | . as $r | .genericXdsConfigs[] | select(.configStatus != "SYNCED") | "\($r.node.id) \(.typeUrl) \(.configStatus)"' "$work/ps.json")
synced=$(jq -r --arg ns "$DATA" '[.resources[] | select(.node.metadata.NAMESPACE == $ns and (.node.id | test("^(caller|peer|pdp-adapter|data-plain)\\.")))] | length' "$work/ps.json")
[ "$synced" = 4 ] && [ -z "$unsynced" ]; check $? "the registered proxies reach istiod through the meshControlPlane opening and report SYNCED for every xDS type" "proxies $synced, not SYNCED: ${unsynced:-none}"
# The API server -> the webhooks, asked of each webhook now, by server-side dry runs that persist
# nothing: istiod's injector must add the proxy, and the controller-manager's validator must refuse
# a ClusterSPIFFEID whose template does not parse (its failurePolicy may be Ignore, so an admitted
# object would prove nothing; only the webhook's own refusal shows it was reached).
inj=$(k -n "$DATA" run webhook-probe --image=registry.k8s.io/e2e-test-images/agnhost:2.53 --restart=Never \
  --dry-run=server -o json 2>&1 | jq -r '[(.spec.initContainers // [])[].name, .spec.containers[].name] | join(",")' 2>&1)
grep -qw istio-proxy <<<"$inj"; check $? "the API server reaches istiod's injection webhook (15017) through the controlPlaneWebhooks opening: a dry-run pod in $DATA is injected" "containers: $inj"
cs=$(printf '%s\n' 'apiVersion: spire.spiffe.io/v1alpha1' 'kind: ClusterSPIFFEID' 'metadata: { name: webhook-probe }' \
  'spec: { spiffeIDTemplate: "spiffe://{{ .TrustDomain" }' | k create --dry-run=server -f - 2>&1)
grep -q 'admission webhook "vclusterspiffeid.kb.io" denied the request' <<<"$cs"
check $? "the API server reaches the controller-manager's webhook (9443) through the controlPlaneWebhooks opening: it refuses a ClusterSPIFFEID with a broken template" "$(head -c 300 <<<"$cs")"
SPIRE_IP=$(k -n "$SPIRE_NS" get pod spire-server-0 -o jsonpath='{.status.podIP}')
ISTIOD_IP=$(k -n "$ISTIO_NS" get pod -l app=istiod -o jsonpath='{.items[0].status.podIP}')
say '' "Raw TCP probes from the proxy-less \`probe\` pods to the SPIRE server ($SPIRE_IP) and istiod ($ISTIOD_IP), on every port they listen on:" ''
for ns in "$DATA" "$MGMT"; do
  for port in 8081 8080 9443 9988 8082 8083; do
    r=$(tcp "$ns" probe "$SPIRE_IP" "$port")
    case $r in denied*) true;; *) false;; esac; check $? "$ns → SPIRE server :$port DENIED" "→ $r"
  done
  for port in 15017 15014 15010 8080; do
    r=$(tcp "$ns" probe "$ISTIOD_IP" "$port")
    case $r in denied*) true;; *) false;; esac; check $? "$ns → istiod :$port DENIED" "→ $r"
  done
  r=$(tcp "$ns" probe "$ISTIOD_IP" 15012)
  [ "$r" = connected ]; check $? "$ns → istiod :15012 (xDS) reachable: the declared meshControlPlane opening" "→ $r"
done
# The agents run on the host network, outside every network policy: their metrics endpoint must be
# bound to the node's loopback. Their listening sockets are read in the host network namespace,
# through the host-networked Cilium agent of the same node.
for NODE in $(agent_nodes); do
  C=$(cilium_on "$NODE")
  listen=$(k -n kube-system exec "$C" -c cilium-agent -- cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk '$4 == "0A" && $2 ~ /:2704$/ {print $2}' | sort -u | tr '\n' ' ')
  [ -n "$listen" ] && ! grep -qvE '^(0100007F|00000000000000000000000001000000):2704$' <<<"$(tr ' ' '\n' <<<"$listen" | grep .)"
  check $? "node $NODE: the SPIRE agent's metrics port 9988 listens on the loopback only, not on the node's addresses" "listening (hex address:port): ${listen:-none}"
  agent_answers "$NODE"
done
say '' '### metrics-endpoints-answer' ''
say "The SPIRE server's metrics endpoint (pod port 9988) and the controller-manager's (pod port 8082, a container of \`spire-server-0\`) are denied to the workload planes (above); that they answer at all is read from the host of the node the server pod runs on, the kubelet's path to the pod that its readiness probes take, through that node's Cilium agent with the same read-only \`kubectl exec\` and \`/dev/tcp\` read as the agents' check: no lane, no pod, nothing written. A read answers when it returns HTTP 200 and at least one sample of the component's own family (\`spire_server_\`, \`controller_runtime_\`; the runtime's \`go_\` and \`process_\` families, which any Go binary exposes, do not count). Nothing in the zone scrapes these endpoints yet." ''
metrics_answer "the SPIRE server" spire_server_ 9988
metrics_answer "the SPIRE controller-manager" controller_runtime_ 8082

# --------------------------------------------------------------------------------------------
section "13. A declared registration without its entry fails the release"
say 'The registrations-reconciled check counts the labelled pods of every plane namespace past Pending (running, or finished as the completed job pods of the OpenBao release are) and compares them with what the controller-manager reconciled. To make one registration go unreconciled, the namespace `kube-public`, which the controller-manager is configured to ignore on every cluster (the default `ignoreNamespaces` of the SPIRE chart) and which holds no pod, is labelled as a plane for the duration of the step and gets a labelled pod; then zone-policy is upgraded through the lifecycle step with a 20 s check timeout. Afterwards the label and the pod are removed and the rollback restores the release.' ''
k label ns kube-public ztd.facis.io/plane=data --overwrite >/dev/null
k -n kube-public run declared-not-reconciled --image=docker.io/curlimages/curl:8.10.1@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b --labels=spiffe.io/spire-managed-identity=true --command -- sleep 3600 >/dev/null
k -n kube-public wait --for=condition=Ready pod/declared-not-reconciled --timeout=120s >/dev/null 2>&1
printf 'trustDomain: %s\nchecks:\n  timeoutSeconds: 20\n' "$TD" >"$work/zp-values.yaml"
k config view --minify --flatten --context "$CONTEXT" >"$work/kubeconfig"
KUBECONFIG=$work/kubeconfig LIFECYCLE_RELEASE=zone-policy LIFECYCLE_NAMESPACE=$ISTIO_NS LIFECYCLE_CHART=$REPO/deployment/helm/zone-policy \
  LIFECYCLE_VALUES_FILE=$work/zp-values.yaml LIFECYCLE_TIMEOUT=3m "$REPO/scripts/lifecycle.sh" deploy >"$work/lifecycle.log" 2>&1
res=$(grep '^RESULT_JSON=' "$work/lifecycle.log" | cut -d= -f2-)
[ "$(jq -r .ok <<<"$res")" = false ]
check $? "the upgrade fails and is rolled back" "$(if [ -n "$res" ]; then jq -r '.error.message' <<<"$res"; else echo "no result from the lifecycle step: $(grep -v '^$' "$work/lifecycle.log" | tail -1 | cut -c1-200)"; fi)"
jl=$(k -n "$ISTIO_NS" logs job/zone-policy-registrations-reconciled 2>/dev/null | grep -E '^(FAIL|ok)' | tail -2 | tr '\n' ' ')
grep -q 'FAIL every registration' <<<"$jl"; check $? "the registrations-reconciled job exits non-zero naming the gap" "$jl"
k -n "$ISTIO_NS" delete job -l ztd.facis.io/identity-check --ignore-not-found >/dev/null
k -n kube-public delete pod declared-not-reconciled --wait=true >/dev/null 2>&1
k label ns kube-public ztd.facis.io/plane- >/dev/null
st=$(h status zone-policy -n "$ISTIO_NS" -o json | jq -r .info.status)
[ "$st" = deployed ]; check $? "after the step the release is deployed again (rollback)" "$(h history zone-policy -n "$ISTIO_NS" --max 3 -o json | jq -r '[.[] | "\(.revision) \(.status)"] | join(", ")')"

# --------------------------------------------------------------------------------------------
section "14. registration-inventory"
say "A declared workload is a pod that runs in a plane namespace (one with the label \`ztd.facis.io/plane\`) and holds a SPIFFE certificate. The inventory is the set of registration entries on the SPIRE server. Both are read here from the live zone and compared by SPIFFE ID, in both directions; nothing is declared by a written list or by what the charts render. The entries are read once (\`spire-server entry show\`), then the pods once: every pod of a plane namespace, and every pod of any other namespace that has an \`istio-proxy\` container or a \`csi.spiffe.io\` volume, so that a certificate outside a plane cannot hide. The certificate in use is read from a meshed pod's proxy (\`istioctl proxy-config secret\`, its \`default\` secret) and from an unmeshed pod's Workload API client over the mounted socket (\`spire-agent api fetch x509\`); a pod with neither is not observable from outside. A reader that ran and failed (the read errors or times out) is a failed check of its own, never taken for a pod without a certificate, unless the pod, looked up again by name and uid, no longer exists (deleted after the listing: its entry is then one without a certificate in use, the pod is gone) or is terminating and the reader's container no longer runs (recorded as not running); a reader whose container is not running reads nothing, as nothing is in use. A terminating pod is read like any other while its containers run (they keep running through its grace period)." ''
say "Outcomes of an entry: **matched** (its pod runs in a plane namespace with the identity label and the certificate read from it carries the entry's ID and chains to the SPIRE CA); **entry without a certificate in use** (the pod is gone, or holds no certificate the proof can read; recorded, not failed); **entry outside a plane namespace** (failed); **entry not created by the registration rule** (failed: no \`k8s:pod-uid\` selector or a selector the rule does not write, a field the rule leaves unset (admin, downstream, DNS names, federation, hint, store, TTLs, expiry), a pod without the identity label, a parent other than the SPIRE agent of the pod's node, or an ID other than \`spiffe://$TD/ns/<namespace>/sa/<service account>\` of that pod; an entry whose namespace cannot be told is reported here, not as outside a plane). Then every certificate read: one that no entry of its own pod lists (**certificate without an entry**), one in a pod outside a plane namespace (**certificate outside a plane namespace**) or one that does not chain to the SPIRE CA fails, its issuer printed. Rows of the proof's own pods (service account \`stand-in\`, or a pod of \`fixtures/stand-ins.yaml\`) are marked \`fixture\`." ''
inv=$work/inventory; rm -rf "$inv"; mkdir -p "$inv"
spire_server entry show -output json >"$inv/entries.json" 2>"$inv/entries.err"; inv_rc=$?
spire_server bundle show >"$inv/bundle.pem" 2>/dev/null
k get namespaces -o json >"$inv/namespaces.json" 2>"$inv/k8s.err" && k get pods -A -o json >"$inv/pods.json" 2>>"$inv/k8s.err" && k get nodes -o json >"$inv/nodes.json" 2>>"$inv/k8s.err"
check $? "registration-inventory: the namespaces, pods and nodes of the cluster are read" "$(head -1 "$inv/k8s.err" | grep . || echo "$(jq '.items | length' "$inv/namespaces.json") namespaces, $(jq '.items | length' "$inv/pods.json") pods, $(jq '.items | length' "$inv/nodes.json") nodes")"
[ $inv_rc -eq 0 ] && jq -e '.entries | type == "array"' "$inv/entries.json" >/dev/null 2>&1
check $? "registration-inventory: the entries on the SPIRE server are read" "$(jq '.entries | length' "$inv/entries.json" 2>/dev/null || head -1 "$inv/entries.err") entries"
sed -e "s/__DATA__/$DATA/g" -e "s/__MGMT__/$MGMT/g" fixtures/stand-ins.yaml \
  | python3 -c 'import sys, yaml
for d in yaml.safe_load_all(sys.stdin):
    if d and d["kind"] == "Pod": print(d["metadata"]["namespace"] + "/" + d["metadata"]["name"])' >"$inv/fixtures.txt"
# The pods examined and their readers, one line each, fields separated by tabs, with whether the
# reader's container runs:
# <ns> <pod> proxy istio-proxy <running|stopped> <uid> - | <ns> <pod> socket <container> <running|stopped> <uid> <socket dir>
# The socket dir, a mountPath the pod's author chooses (spaces, tabs, newlines allowed), is the last
# field and escaped as jq's @tsv does (\\, \t, \n, \r), so no cluster data can shift a field;
# the loop below unescapes it. A terminating pod (deletionTimestamp set) is listed like any other:
# its containers keep running through its grace period; only a pod whose phase is final is not.
python3 - "$inv/namespaces.json" "$inv/pods.json" >"$inv/readers.txt" 2>"$inv/readers.err" <<'PY'
import json, sys
esc = lambda v: v.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")
plane = {n["metadata"]["name"] for n in json.load(open(sys.argv[1]))["items"] if "ztd.facis.io/plane" in (n["metadata"].get("labels") or {})}
for p in json.load(open(sys.argv[2]))["items"]:
    m, s = p["metadata"], p["spec"]
    if p["status"].get("phase") in ("Succeeded", "Failed"):
        continue
    ctrs = (s.get("initContainers") or []) + s["containers"]
    st = p["status"]
    running = {c["name"] for c in (st.get("initContainerStatuses") or []) + (st.get("containerStatuses") or []) if "running" in (c.get("state") or {})}
    up = lambda name: "running" if name in running else "stopped"
    csi = {v["name"] for v in s.get("volumes") or [] if (v.get("csi") or {}).get("driver") == "csi.spiffe.io"}
    proxy = any(c["name"] == "istio-proxy" for c in ctrs)
    if m["namespace"] not in plane and not proxy and not csi:
        continue
    if proxy:
        print(m["namespace"], m["name"], "proxy", "istio-proxy", up("istio-proxy"), m["uid"], "-", sep="\t")
    for c in s["containers"]:
        if c["name"] == "istio-proxy" or "spire-agent" not in c["image"]:
            continue
        for vm in c.get("volumeMounts") or []:
            if vm["name"] in csi:
                print(m["namespace"], m["name"], "socket", c["name"], up(c["name"]), m["uid"], esc(vm["mountPath"]), sep="\t"); break
PY
check $? "registration-inventory: the pods whose certificates are read are listed (every pod of a plane namespace, and every pod elsewhere with a proxy or a csi.spiffe.io volume)" "$(head -1 "$inv/readers.err" | grep . || echo "$(wc -l <"$inv/readers.txt") readers on $(cut -f1,2 "$inv/readers.txt" | sort -u | wc -l) pods")"
# certs.tsv, one line per reader: <ns> <pod> <reader> <status> <SPIFFE URI> <issuer> <chains to the
# SPIRE CA: 1|0> <error>. Status: ok (a certificate was read), none (the reader answered and the pod
# holds no certificate), stopped (the reader's container is not running, so nothing is in use and
# nothing is read), gone (the read failed and the pod, looked up again by name and uid, no longer
# exists: deleted after the listing, so its entry is one without a certificate in use), stopped too
# when the read failed on a terminating pod whose reader's container no longer runs, error (the read
# failed and the pod still exists with the reader running, or could not be looked up: a failed check
# of its own, never taken for "none").
: >"$inv/certs.tsv"
while IFS=$'\t' read -r ns pod reader ctr up uid dir; do
  printf -v dir '%b' "$dir"
  f=$inv/cert.pem; rm -f "$f" "$f.err"; uri=""; issuer=""; chains=0; err=""
  if [ "$up" != running ]; then
    st=stopped
  else
    if [ "$reader" = proxy ]; then proxy_cert "$ns" "$pod" "$f"; else socket_cert "$ns" "$pod" "$ctr" "$dir" "$f"; fi
    case $? in
      0) st=ok; uri=$(cert_uri "$f"); issuer=$(openssl x509 -noout -issuer -nameopt RFC2253 -in "$f" 2>/dev/null | sed 's/^issuer=//')
         openssl verify -CAfile "$inv/bundle.pem" "$f" >/dev/null 2>&1 && chains=1
         [ -n "$uri" ] || { st=error; err="the certificate read carries no SPIFFE URI"; };;
      1) st=none;;
      *) if pod_gone "$ns" "$pod" "$uid"; then st=gone; err=""
         elif reader_ended "$ns" "$pod" "$uid" "$ctr"; then st=stopped; err=""
         else st=error; err=$(tr '\t' ' ' <"$f.err" 2>/dev/null | cut -c1-200); fi;;
    esac
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$ns" "$pod" "$reader" "$st" "$uri" "$issuer" "$chains" "$err" >>"$inv/certs.tsv"
done <"$inv/readers.txt"
rm -f "$inv/cert.pem" "$inv/cert.pem.err"
python3 - "$inv" "$TD" >"$inv/report.md" 2>"$inv/report.err" <<'PY'
import json, sys
d, td = sys.argv[1], sys.argv[2]
PLANE, IDENT = "ztd.facis.io/plane", "spiffe.io/spire-managed-identity"
ents = json.load(open(f"{d}/entries.json")).get("entries") or []
nsl = {n["metadata"]["name"]: n["metadata"].get("labels") or {} for n in json.load(open(f"{d}/namespaces.json"))["items"]}
pods = json.load(open(f"{d}/pods.json"))["items"]
by_uid = {p["metadata"]["uid"]: p for p in pods}
by_key = {p["metadata"]["namespace"] + "/" + p["metadata"]["name"]: p for p in pods}
node_uid = {n["metadata"]["name"]: n["metadata"]["uid"] for n in json.load(open(f"{d}/nodes.json"))["items"]}
fixtures = {l.strip() for l in open(f"{d}/fixtures.txt") if l.strip()}
certs = []
for line in open(f"{d}/certs.tsv"):
    ns, pod, reader, status, uri, issuer, chains, err = line.rstrip("\n").split("\t")
    certs.append(dict(ns=ns, pod=pod, key=f"{ns}/{pod}", reader=reader, status=status, uri=uri if status == "ok" else "", issuer=issuer, chains=chains == "1", err=err))
RNAME = {"proxy": "proxy", "socket": "Workload API client"}
# Pods whose read failed and that, looked up again, no longer exist: deleted after the listing
gone_since = {c["key"] for c in certs if c["status"] == "gone"}
checks = []
def check(ok, title, detail=""): checks.append(dict(ok=ok, title=title, detail=detail))
plane = lambda ns: ns is not None and PLANE in nsl.get(ns, {})
meshed = lambda ns: nsl.get(ns, {}).get("istio-injection") == "enabled"
sa = lambda p: p["spec"].get("serviceAccountName") or "default"
labelled = lambda p: (p["metadata"].get("labels") or {}).get(IDENT) == "true"
template = lambda ns, s: f"spiffe://{td}/ns/{ns}/sa/{s}"
# The fields of an entry the registration rule (the ClusterSPIFFEID of zone-policy) leaves unset: an
# entry that sets any of them was not written by the rule, whatever its selectors and ID.
UNSET = ("admin", "downstream", "dns_names", "federates_with", "hint", "store_svid", "x509_svid_ttl", "jwt_svid_ttl", "expires_at")
agent_parent = lambda parent: parent.startswith("/spire/agent/k8s_psat/") and parent.rsplit("/", 1)[-1] in node_uid.values()
gone = lambda p: p is None or p["status"].get("phase") in ("Succeeded", "Failed")
def fixture(key, p):
    return "fixture" if key in fixtures or (p is not None and sa(p) == "stand-in") else ""
yn = lambda b: "yes" if b else "no"
out = []
say = out.append
# The entries, each with the pod its k8s:pod-uid names and the certificate read from that pod
say("### The entries on the SPIRE server")
say("")
say("| SPIFFE ID | pod | plane namespace | identity label | certificate in use | outcome | |")
say("|---|---|---|---|---|---|---|")
uid_ids, uid_failed = {}, {}  # pod uid -> SPIFFE IDs its entries list (entries that passed, entries that failed)
n = dict(matched=0, without=0, outside=0, rule=0)
outcomes = {}  # pod key -> [(SPIFFE ID, outcome)] of its entries
for e in ents:
    eid = f"spiffe://{e['spiffe_id']['trust_domain']}{e['spiffe_id']['path']}"
    sel, other = {}, []
    for s in e.get("selectors") or []:
        k_, _, v_ = s.get("value", "").partition(":")
        if s.get("type") == "k8s" and k_ in ("pod-uid", "ns", "sa"): sel.setdefault(k_, []).append(v_)
        else: other.append(f"{s.get('type')}:{s.get('value')}")
    parent = (e.get("parent_id") or {}).get("path", "")
    uid = (sel.get("pod-uid") or [None])[0]
    p = by_uid.get(uid) if uid else None
    path = e["spiffe_id"]["path"].split("/")
    shaped = len(path) == 5 and path[0] == "" and path[1] == "ns" and path[3] == "sa" and path[2] and path[4]
    ns = p["metadata"]["namespace"] if p else ((sel.get("ns") or [None])[0] or (path[2] if shaped else None))
    key = f"{ns}/{p['metadata']['name']}" if p else None
    podtxt = f"`{key}`" if p else ("gone" if uid else "none (no `k8s:pod-uid` selector)")
    reasons = []
    if not uid: reasons.append("no k8s:pod-uid selector")
    if other: reasons.append("selectors the rule does not write: " + ", ".join(other))
    extra = [f for f in UNSET if e.get(f) not in (None, False, 0, "", "0", [])]
    if extra: reasons.append("fields the rule does not write: " + ", ".join(f"{f}={json.dumps(e[f])}" for f in extra))
    if ns is None: reasons.append("no namespace: no pod, no k8s:ns selector, and an ID not of the template's shape /ns/<namespace>/sa/<service account>")
    if p:
        if not labelled(p): reasons.append(f"the pod carries no {IDENT} label")
        if eid != template(ns, sa(p)): reasons.append(f"the ID differs from {template(ns, sa(p))}")
        if sel.get("ns", [ns])[0] != ns or sel.get("sa", [sa(p)])[0] != sa(p): reasons.append("its k8s:ns or k8s:sa selector is not the pod's")
        nu = node_uid.get(p["spec"].get("nodeName") or "")
        if not (parent.startswith("/spire/agent/") and nu and parent.endswith("/" + nu)):
            reasons.append(f"its parent {parent or 'none'} is not the SPIRE agent of the pod's node")
    else:
        # The pod is gone (or never existed): what can still be checked is the template's shape, the
        # selectors against it, and a parent that is the SPIRE agent of a node of the cluster.
        if uid and sel.get("ns") and sel.get("sa") and eid != template(sel["ns"][0], sel["sa"][0]):
            reasons.append(f"the ID differs from {template(sel['ns'][0], sel['sa'][0])}")
        elif ns is not None and (not shaped or e["spiffe_id"]["trust_domain"] != td):
            reasons.append(f"the ID is not of the template's shape spiffe://{td}/ns/<namespace>/sa/<service account>")
        if uid and not agent_parent(parent):
            reasons.append(f"its parent {parent or 'none'} is not the SPIRE agent of a node of the cluster")
    pc = [c for c in certs if p and c["key"] == key]
    def certcell(c):
        if c["status"] == "ok": return f"{c['reader']}: `{c['uri']}`"
        return f"{c['reader']}: " + {"none": "none", "stopped": "not running", "gone": "pod deleted after the listing", "error": "**read failed**"}[c["status"]]
    certtxt = "; ".join(certcell(c) for c in pc) or "not read"
    if ns is not None and not plane(ns):
        outcome = "**entry outside a plane namespace**"; n["outside"] += 1
        if uid: uid_failed.setdefault(uid, set()).add(eid)
        check(False, f"registration-inventory: entry outside a plane namespace: {eid}", f"pod {key or podtxt}, namespace {ns or 'unknown'} carries no {PLANE} label" + (f"; also {'; '.join(reasons)}" if reasons else ""))
    elif reasons:
        outcome = "**entry not created by the registration rule**: " + "; ".join(reasons); n["rule"] += 1
        if uid: uid_failed.setdefault(uid, set()).add(eid)
        check(False, f"registration-inventory: entry not created by the registration rule: {eid}", f"pod {key or podtxt}: " + "; ".join(reasons))
    elif gone(p):
        uid_ids.setdefault(uid, set()).add(eid)
        outcome = "entry without a certificate in use: the pod is gone"; n["without"] += 1
    elif any(c["uri"] == eid and c["chains"] for c in pc):
        uid_ids.setdefault(uid, set()).add(eid)
        outcome = "matched"; n["matched"] += 1
    elif key in gone_since:
        uid_ids.setdefault(uid, set()).add(eid)
        outcome = "entry without a certificate in use: the pod is gone (deleted after the listing, before its certificate was read)"; n["without"] += 1
    else:
        uid_ids.setdefault(uid, set()).add(eid)
        if not pc: why = "not observable: the pod has no proxy and no Workload API client"
        elif any(c["status"] == "error" for c in pc): why = "its certificate could not be read (a failed check of its own, below)"
        elif all(c["status"] == "stopped" for c in pc): why = f"the pod is {p['status'].get('phase')} and its " + " and ".join(RNAME[c["reader"]] for c in pc) + (" are" if len(pc) > 1 else " is") + " not running"
        elif all(c["status"] in ("none", "stopped") for c in pc): why = "the pod holds no certificate yet"
        else: why = "the certificate read carries another ID or does not chain to the SPIRE CA"
        outcome = f"entry without a certificate in use: {why}"; n["without"] += 1
    if key: outcomes.setdefault(key, []).append((eid, outcome))
    say(f"| `{eid}` | {podtxt} | {yn(plane(ns))} ({ns or 'unknown'}) | {yn(p is not None and labelled(p)) if p else '-'} | {certtxt} | {outcome} | {fixture(key, p)} |")
if not ents: say("| none | | | | | | |")
say("")
say(f"{len(ents)} entries: {n['matched']} matched, {n['without']} without a certificate in use, {n['outside']} outside a plane namespace, {n['rule']} not created by the registration rule.")
say("")
if n["outside"] == 0: check(True, "registration-inventory: no entry on the SPIRE server is outside a plane namespace", f"{n['outside']} outside")
if n["rule"] == 0 and n["outside"] == 0: check(True, "registration-inventory: every entry on the SPIRE server was created by the registration rule (the k8s:pod-uid selector of a labelled pod of a plane namespace, the SPIRE agent of its node as parent, the template's ID)", f"{n['rule']} not created by the rule")
# Every reader that ran must have answered: a read that fails is a failed check, never "no certificate".
# There is no floor on the number matched: a zone whose entries nothing holds, or that has none, passes.
unread = [c for c in certs if c["status"] == "error"]
for c in unread:
    check(False, f"registration-inventory: the certificate in use could not be read: {c['key']} ({RNAME[c['reader']]})", c["err"] or "no reason given")
st = {k_: sum(c["status"] == k_ for c in certs) for k_ in ("ok", "none", "stopped", "gone", "error")}
if not unread: check(True, "registration-inventory: every certificate reader that ran answered (a read that fails is a failed check, not a pod without a certificate)", f"{len(certs)} readers: {st['ok']} certificates read, {st['none']} answered with none, {st['stopped']} not running, {st['gone']} on a pod deleted after the listing, {st['error']} failed")
# The other direction: every certificate read, against the entries of its own pod
say("### The certificates in use")
say("")
say("| pod | reader | SPIFFE ID | issuer | outcome | |")
say("|---|---|---|---|---|---|")
bad, failed = 0, {}  # one failed check per pod, SPIFFE ID and outcome, whichever readers saw it
for c in certs:
    p = by_key.get(c["key"])
    if c["status"] == "error":
        say(f"| `{c['key']}` | {c['reader']} | - | - | **could not be read** (a failed check of its own): {c['err']} | {fixture(c['key'], p)} |")
        continue
    if not c["uri"]: continue
    if not plane(c["ns"]):
        outcome, title, why = "**certificate outside a plane namespace**", "certificate outside a plane namespace", f"namespace {c['ns']} carries no {PLANE} label"
    elif p is not None and c["uri"] not in uid_ids.get(p["metadata"]["uid"], set()) and c["uri"] in uid_failed.get(p["metadata"]["uid"], set()):
        outcome, title, why = "**accounted for only by an entry that failed above**", None, None
    elif p is None or c["uri"] not in uid_ids.get(p["metadata"]["uid"], set()):
        outcome, title, why = "**certificate without an entry**", "certificate without an entry", "no entry of this pod lists the ID"
    elif not c["chains"]:
        outcome, title, why = "**not issued by the SPIRE CA**", "certificate not issued by the SPIRE CA", "it does not chain to the SPIRE bundle"
    else:
        outcome, title = "matched", None
    if outcome != "matched":
        bad += 1
    if title:
        f = failed.setdefault((c["key"], c["uri"], title), dict(readers=[], issuer=c["issuer"], why=why))
        f["readers"].append(RNAME[c["reader"]])
    say(f"| `{c['key']}` | {c['reader']} | `{c['uri']}` | {c['issuer']} | {outcome} | {fixture(c['key'], p)} |")
held = [c for c in certs if c["uri"]]
if not held and not unread: say("| none | | | | | |")
say("")
for (key, uri, title), f in failed.items():
    check(False, f"registration-inventory: {title}: {uri}", f"pod {key} (read from its {' and '.join(f['readers'])}): {f['why']}; issuer {f['issuer']}")
if bad == 0: check(True, "registration-inventory: every certificate in use read from the pods has an entry of its own pod, sits in a plane namespace and chains to the SPIRE CA", f"{len(held)} certificates read, {bad} not accounted for")
# The plane pods that hold no certificate
holders = {c["key"] for c in held}
without = [p for p in pods if plane(p["metadata"]["namespace"]) and not gone(p) and not p["metadata"].get("deletionTimestamp")
           and p["metadata"]["namespace"] + "/" + p["metadata"]["name"] not in holders | gone_since]
work_pods = [p for p in without if meshed(p["metadata"]["namespace"])]
cp_pods = [p for p in without if not meshed(p["metadata"]["namespace"])]
say("### Plane pods without an identity")
say("")
say("Every pod of a plane namespace from which no certificate was read, with its labels (not a failure of this section: STRICT and the admission policy own that).")
say("")
for p in work_pods:
    key = p["metadata"]["namespace"] + "/" + p["metadata"]["name"]
    labels = ", ".join(f"{k}={v}" for k, v in sorted((p["metadata"].get("labels") or {}).items())) or "none"
    pcs = [c for c in certs if c["key"] == key]
    if not pcs: why = "no proxy and no Workload API client"
    elif any(c["status"] == "error" for c in pcs): why = "its " + " or ".join(RNAME[c["reader"]] for c in pcs if c["status"] == "error") + " could not be read (a failed check above)"
    elif all(c["status"] == "stopped" for c in pcs): why = "its " + " and ".join(RNAME[c["reader"]] for c in pcs) + (" are" if len(pcs) > 1 else " is") + " not running"
    else: why = "no certificate held by its " + " or ".join(RNAME[c["reader"]] for c in pcs)
    say(f"- `{key}` ({why}; labels: {labels}){' fixture' if fixture(key, p) else ''}")
if not work_pods: say("- none in a namespace with the injection label")
if cp_pods:
    by_ns = {}
    for p in cp_pods: by_ns.setdefault(p["metadata"]["namespace"], []).append(p["metadata"]["name"])
    say("- control-plane namespaces (the plane label without the injection label, outside the mesh by design): " + "; ".join(f"`{ns}`: {', '.join(sorted(v))}" for ns, v in sorted(by_ns.items())))
real = [p for p in work_pods if not fixture(p["metadata"]["namespace"] + "/" + p["metadata"]["name"], p)]
say("")
say(f"{len(work_pods)} plane pods without an identity in namespaces with the injection label, {len(real)} of them not fixtures.")
# The secret store, the release ztd-openbao: installed after zone-policy, its server pod is a matched
# declared workload, and no pod of the release (server, bootstrap, verification) is a plane pod
# without an identity. A finished job pod is gone to this reader: its entry, if still listed, is one
# without a certificate in use.
BAO = ("openbao", "ztd-openbao-bootstrap", "ztd-verify-openbao")
bao_label = lambda p: (p["metadata"].get("labels") or {}).get("app.kubernetes.io/name")
servers = [p for p in pods if bao_label(p) == "openbao" and (p["metadata"].get("labels") or {}).get("component") == "server"
           and plane(p["metadata"]["namespace"]) and not gone(p)]
say("")
for p in servers:
    key = p["metadata"]["namespace"] + "/" + p["metadata"]["name"]
    oc = outcomes.get(key, [])
    say(f"The OpenBao server `{key}` (release `ztd-openbao`): " + ("; ".join(f"`{i}` {o}" for i, o in oc) if oc else "no entry") + ".")
if not servers: say("No OpenBao server pod runs in a plane namespace.")
unmatched = [p["metadata"]["namespace"] + "/" + p["metadata"]["name"] for p in servers
             if not any(o == "matched" for _, o in outcomes.get(p["metadata"]["namespace"] + "/" + p["metadata"]["name"], []))]
check(bool(servers) and not unmatched, "registration-inventory: the OpenBao server is a matched declared workload (release ztd-openbao, created after the registration rule)",
      (f"not matched: {', '.join(unmatched)}" if unmatched else f"{len(servers)} server pod(s) matched") if servers else "no OpenBao server pod in a plane namespace")
stray = [p["metadata"]["namespace"] + "/" + p["metadata"]["name"] for p in work_pods if bao_label(p) in BAO]
check(not stray, "registration-inventory: no OpenBao pod is a plane pod without an identity", f"without an identity: {', '.join(stray)}" if stray else "none")
json.dump(checks, open(f"{d}/checks.json", "w"))
print("\n".join(out))
PY
inv_rc=$?; inv_err=$(head -1 "$inv/report.err")
[ $inv_rc -eq 0 ]; check $? "registration-inventory: the inventory is compared" ${inv_err:+"$inv_err"}
say "$(cat "$inv/report.md")" ''
while IFS=$'\t' read -r ok title detail; do
  [ "$ok" = true ]; check $? "$title" "$detail"
done < <(jq -r '.[] | [(.ok | tostring), .title, .detail] | @tsv' "$inv/checks.json" 2>/dev/null)

# --------------------------------------------------------------------------------------------
section "15. Render guards (no cluster)"
python3 - "$ZONE_VALUES" "$work/no-td.yaml" <<'PY'
import sys, yaml
z = yaml.safe_load(open(sys.argv[1])); z["zone"].pop("trustDomain", None)
yaml.safe_dump(z, open(sys.argv[2], "w"))
PY
out=$(ZONE_VALUES=$work/no-td.yaml "$INSTALL" render spire 2>&1); rc=$?
[ $rc -ne 0 ] && grep -q 'zone.trustDomain' <<<"$out"; check $? "the spire release does not render without the trust domain" "$(tail -1 <<<"$out")"
out=$(ZONE_VALUES=$work/no-td.yaml "$INSTALL" render istiod 2>&1); rc=$?
[ $rc -ne 0 ] && grep -q 'zone.trustDomain' <<<"$out"; check $? "the istiod release does not render without the trust domain" "$(tail -1 <<<"$out")"
out=$(helm template ztd "$CHART" -f "$work/no-td.yaml" 2>&1); rc=$?
[ $rc -ne 0 ] && grep -q "/zone/trustDomain" <<<"$out"; check $? "the umbrella refuses a meshed zone without a trust domain, on the schema" "$(grep -o "at '/zone/trustDomain'.*" <<<"$out" | head -1)"
helm template ztd "$CHART" -f "$CHART/zones/ionos.yaml" >/dev/null 2>&1; check $? "the umbrella renders zones/ionos.yaml (mesh none) without a trust domain"
out=$(helm template ztd "$CHART" -f "$ZONE_VALUES" --set zone.kubernetesVersion=v1.32.0 2>&1); rc=$?
[ $rc -ne 0 ] && grep -q 'native sidecar' <<<"$out"; check $? "the umbrella refuses sidecar mode below Kubernetes 1.33" "$(grep -o 'mesh.mode sidecar needs.*' <<<"$out")"
out=$(helm template ztd "$CHART" -f "$ZONE_VALUES" --set cni.cilium.enabled=false 2>&1); rc=$?
[ $rc -ne 0 ] && grep -q 'derogation' <<<"$out"; check $? "the umbrella refuses a meshed zone without Cilium, naming the openings and the derogation" "$(grep -o 'mesh.mode sidecar needs Cilium[^:]*' <<<"$out")"
# The provider facts of the zone values (planes.namespaceLabels, networkPolicy.dns.ports,
# controlPlaneWebhooks.fromEndpoints): a label the umbrella sets itself is refused, and each shipped
# zone file (the kind file and every zones/*.yaml but the example) renders its facts and nothing else.
for key in ztd.facis.io/plane istio-injection; do
  out=$(helm template ztd "$CHART" -f "$ZONE_VALUES" --set-string "planes.namespaceLabels.${key//./\\.}=x" 2>&1); rc=$?
  [ $rc -ne 0 ] && grep -q "planes.namespaceLabels may not set $key" <<<"$out"
  check $? "the umbrella refuses planes.namespaceLabels setting $key, a label it sets itself" "$(grep -o 'planes.namespaceLabels may not set[^"]*' <<<"$out" | head -1)"
done
facts_ok=(0 0 0); facts_detail=("" "" "")
for zf in "$CHART/ci/values.yaml" "$CHART"/zones/*.yaml; do
  case $zf in *.example.yaml) continue;; esac
  helm template ztd "$CHART" -f "$zf" >"$work/facts.yaml" 2>"$work/facts.err" || { for i in 0 1 2; do facts_ok[i]=1; facts_detail[i]="${facts_detail[i]} ${zf#"$CHART"/}: no render ($(tail -1 "$work/facts.err"));"; done; continue; }
  # zone_facts <chart values> <zone file> <rendered>: one line per fact, "<0|1> <detail>" (0: as the zone states)
  mapfile -t res < <(python3 - "$CHART/values.yaml" "$zf" "$work/facts.yaml" <<'PY'
import json, sys, yaml
def merge(a, b):
    if isinstance(a, dict) and isinstance(b, dict):
        return {k: merge(a.get(k), b[k]) if k in b else a[k] for k in {**a, **b}}
    return b
v = merge(yaml.safe_load(open(sys.argv[1])), yaml.safe_load(open(sys.argv[2])) or {})
docs = [d for d in yaml.safe_load_all(open(sys.argv[3])) if d]
np = v["networkPolicy"]
# DNS bypass: every allow-dns-egress policy admits the zone's resolver ports, UDP and TCP, and no other
want = sorted((p, t) for p in (np["dns"].get("ports") or [53]) for t in ("UDP", "TCP"))
dns = [d for d in docs if d["kind"] == "NetworkPolicy" and d["metadata"]["name"] == "allow-dns-egress"]
got = {json.dumps(sorted((p["port"], p["protocol"]) for e in d["spec"]["egress"] for p in e["ports"])) for d in dns}
ok = bool(dns) and got == {json.dumps(want)} if np["dns"].get("enabled", True) else not dns
print(0 if ok else 1, f"dns ports {sorted({p for p, _ in want})} in {len(dns)} policies" + ("" if ok else f", found {sorted(got)}"))
# fromEndpoints: one rule per webhook target, on its port, with the zone's selectors; none without them
w = np["controlPlaneWebhooks"]
eps = w.get("fromEndpoints") or []
want = sorted((t["namespace"], str(t["port"]), json.dumps(eps, sort_keys=True)) for t in w["targets"]) if w.get("enabled") and eps else []
got = sorted((d["metadata"]["namespace"], p["port"], json.dumps([m["matchLabels"] for m in r["fromEndpoints"]], sort_keys=True))
             for d in docs if d["kind"] == "CiliumNetworkPolicy"
             for r in d["spec"].get("ingress") or [] if "fromEndpoints" in r
             for tp in r["toPorts"] for p in tp["ports"])
print(0 if got == want else 1, f"fromEndpoints rules {[(n, p) for n, p, _ in got] or 'none'}" + ("" if got == want else f", expected {[(n, p) for n, p, _ in want] or 'none'}"))
# namespace labels: every Namespace the umbrella renders carries them
labels = v["planes"].get("namespaceLabels") or {}
ns = [d for d in docs if d["kind"] == "Namespace"]
bad = [d["metadata"]["name"] for d in ns if any(d["metadata"]["labels"].get(k) != str(x) for k, x in labels.items())]
print(0 if ns and not bad else 1, f"namespace labels {sorted(labels) or 'none'} on {len(ns) - len(bad)} of {len(ns)} namespaces")
PY
)
  for i in 0 1 2; do
    [ "${res[i]%% *}" = 0 ] || facts_ok[i]=1
    facts_detail[i]="${facts_detail[i]} ${zf#"$CHART"/}: ${res[i]#* };"
  done
done
[ "${facts_ok[0]}" = 0 ]; check $? "each shipped zone file renders the DNS bypass on its own resolver port (networkPolicy.dns.ports), UDP and TCP" "${facts_detail[0]}"
[ "${facts_ok[1]}" = 0 ]; check $? "the webhook relay (controlPlaneWebhooks.fromEndpoints) renders only where the zone file names it, on the webhook ports" "${facts_detail[1]}"
[ "${facts_ok[2]}" = 0 ]; check $? "the zone file's planes.namespaceLabels reach every namespace the umbrella creates" "${facts_detail[2]}"

# --------------------------------------------------------------------------------------------
# The stand-ins are removed in every case: they are fixtures of the proof, never part of a kept zone.
delete_stand_ins
not_kept=""
if [ "$KEEP" != 1 ]; then
  if [ "$CLUSTER_KIND" = kind ]; then not_kept="no opt-in (kind)"; else not_kept="no opt-in (ZTD_KEEP_ZONE unset)"; fi
elif [ "$failures" -ne 0 ]; then
  not_kept="$failures check(s) failed"
else
  # The CNI read-back comes first on the keep path: a check of the decision to keep, like the record
  # below, so a changed CNI tears the zone down (on the teardown path it runs after the uninstall).
  before=$failures
  section "The cluster's CNI as found"
  say "Read again before the zone is declared kept: if it changed, the zone is torn down." ''
  cni_check
  section "16. What remains installed"
  say "The keep opt-in is set and every check above passed, so the teardown is replaced by this record, read from the cluster. Each item is a check, as is the CNI read-back above: if one fails, the zone is torn down after all." ''
  nodes_n=$(k get nodes -o name | grep -c .)
  rel=$(h list -A -o json | jq -r '.[] | "\(.name):\(.namespace) \(.status)"')
  n=0; for r in $RELEASES; do grep -qx "$r deployed" <<<"$rel" && n=$((n+1)); done
  [ "$n" -eq 8 ]; check $? "the eight releases are installed with status deployed" "$n of 8 deployed"
  code "$(h list -A -o json | jq -r '(["RELEASE","NAMESPACE","REVISION","STATUS","CHART"] | join(" ")), (.[] | [.name, .namespace, .revision, .status, .chart] | join(" "))')"
  sts=$(k -n "$MGMT" get sts ztd-openbao -o jsonpath='{.status.readyReplicas}/{.spec.replicas}')
  [ "${sts%/*}" = "${sts#*/}" ] && [ "${sts%/*}" -ge 1 ] 2>/dev/null; check $? "the OpenBao server StatefulSet is ready (unsealed)" "ztd-openbao ready $sts"
  sts=$(k -n "$SPIRE_NS" get sts spire-server -o jsonpath='{.status.readyReplicas}/{.spec.replicas}')
  [ "${sts%/*}" = "${sts#*/}" ] && [ "${sts%/*}" -ge 1 ] 2>/dev/null; check $? "the SPIRE server StatefulSet is ready" "spire-server ready $sts"
  cm=$(k -n "$SPIRE_NS" get pod spire-server-0 -o jsonpath='{.status.containerStatuses[?(@.name=="spire-controller-manager")].ready}')
  [ "$cm" = true ]; check $? "the SPIRE controller-manager (container spire-controller-manager of spire-server-0) is ready" "ready=$cm"
  for ds in spire-agent spire-spiffe-csi-driver; do
    nr=$(k -n "$SPIRE_NS" get ds "$ds" -o jsonpath='{.status.numberReady}')
    [ "$nr" = "$nodes_n" ]; check $? "the DaemonSet $ds has one ready pod on every node" "numberReady $nr, nodes $nodes_n"
  done
  attested=$(spire_server agent list -output json 2>/dev/null | jq '.agents | length')
  [ "$attested" = "$nodes_n" ]; check $? "the SPIRE server lists one attested agent per node" "attested $attested, nodes $nodes_n"
  # The three metrics endpoints again (section 12), as checks of the decision to keep.
  metrics_answer "the SPIRE server" spire_server_ 9988
  metrics_answer "the SPIRE controller-manager" controller_runtime_ 8082
  for NODE in $(agent_nodes); do agent_answers "$NODE"; done
  # The proof's fixtures are gone (delete_stand_ins ran above, its errors silenced): the stand-ins of
  # both planes and their Services and ServiceAccounts, the per-node meshed stand-ins and their
  # Services and ServiceAccounts, the per-node SVID stand-ins and the ServiceAccount stand-in of the SPIRE namespace, the kube-public pod, the scratch namespace, and
  # any SPIRE entry for a stand-in identity, the per-node meshed stand-ins' included (the controller-manager removes those once the pods are
  # gone, so they are waited for). A leftover is a failed check, so the zone is torn down after all.
  left=$( { sed -e "s/__DATA__/$DATA/g" -e "s/__MGMT__/$MGMT/g" fixtures/stand-ins.yaml | k get -f - --ignore-not-found -o name \
    && k -n "$DATA" get pods,services,serviceaccounts -l app.kubernetes.io/name=mesh-on-node -o name \
    && k -n "$SPIRE_NS" get pods -l app.kubernetes.io/name=svid-on-node -o name \
    && k -n "$SPIRE_NS" get serviceaccount stand-in --ignore-not-found -o name \
    && k -n kube-public get pod declared-not-reconciled --ignore-not-found -o name \
    && k get namespace mesh-identity-outside --ignore-not-found -o name; } 2>&1 || echo "a read failed")
  for _ in $(seq 30); do
    entries=$(spire_server entry show -output json 2>/dev/null | jq -er '[.entries[] | select(.spiffe_id.path | endswith("/sa/stand-in") or contains("/sa/mesh-on-")) | "spiffe://\(.spiffe_id.trust_domain)\(.spiffe_id.path)"] | join(" ")') || entries="the entries could not be read"
    [ -z "$entries" ] && break; sleep 2
  done
  # The certificates in use by the proxies of the plane namespaces (section 14's reader): none may
  # carry a stand-in identity. A listing or a read that fails is reported as a leftover, never
  # taken for none, so the zone is not kept on a read that could not look, unless the pod, looked up
  # again by name and uid, no longer exists (deleted after the listing) or is terminating with its
  # proxy no longer running; a proxy whose container is not running holds no certificate in use and
  # is not read. A terminating pod is read while its proxy runs. One tab-separated line per proxy.
  certs_left=""
  if plane_ns=$(k get ns -l ztd.facis.io/plane -o json 2>/dev/null | jq -ec '[.items[].metadata.name]') \
     && plane_pods=$(k get pods -A -o json 2>/dev/null | jq -er --argjson ns "$plane_ns" '[.items[] | select(.metadata.namespace as $n | $ns | index($n))
          | select(.status.phase != "Succeeded" and .status.phase != "Failed")
          | select([(.spec.initContainers // [])[].name, .spec.containers[].name] | index("istio-proxy"))
          | [.metadata.namespace, .metadata.name, .metadata.uid, (if [(.status.initContainerStatuses // [])[], (.status.containerStatuses // [])[] | select(.name == "istio-proxy" and .state.running)] | length > 0 then "running" else "stopped" end)] | @tsv] | join("\n")'); then
    while IFS=$'\t' read -r ns pod uid up; do
      if [ -z "$ns" ] || [ "$up" != running ]; then continue; fi
      proxy_cert "$ns" "$pod" "$work/left-cert.pem"
      case $? in
        0) u=$(cert_uri "$work/left-cert.pem"); [[ $u == */sa/stand-in || $u == */sa/mesh-on-* ]] && certs_left="$certs_left $ns/$pod=$u";;
        1) ;;
        *) pod_gone "$ns" "$pod" "$uid" || reader_ended "$ns" "$pod" "$uid" istio-proxy || certs_left="$certs_left $ns/$pod=unread($(cat "$work/left-cert.pem.err" 2>/dev/null))";;
      esac
    done <<<"$plane_pods"
  else
    certs_left="the plane namespaces or their pods could not be listed"
  fi
  rm -f "$work/left-cert.pem" "$work/left-cert.pem.err"; certs_left=${certs_left# }
  [ -z "$left" ] && [ -z "$entries" ] && [ -z "$certs_left" ]
  check $? "nothing of the proof's fixtures stays in the zone: no stand-in pod, Service or ServiceAccount in either plane, no per-node meshed stand-in, its Service or its ServiceAccount, no per-node SVID stand-in and no stand-in ServiceAccount in $SPIRE_NS, no kube-public pod, no scratch namespace, no SPIRE entry for a stand-in identity, and no proxy of a plane namespace holding a certificate for one, the per-node meshed stand-ins' included (every running proxy read)" "left: $(tr '\n' ' ' <<<"${left:-none}"); stand-in entries: ${entries:-none}; stand-in certificates: ${certs_left:-none}"
  code "$(k -n "$SPIRE_NS" get pods -o wide | sed 's/  */ /g')"
  server_td=$(k -n "$SPIRE_NS" get cm spire-server -o jsonpath='{.data.server\.conf}' | jq -r .server.trust_domain)
  td_note="final"; [[ $server_td == *.trust.invalid ]] && td_note="interim"
  [ "$server_td" = "$TD" ]; check $? "the SPIRE server runs with the zone file's trust domain" "$server_td ($td_note)"
  if [ "$failures" -eq "$before" ]; then
    keep_zone=1
    say '' "The zone stays installed on \`$CONTEXT\` with the trust domain \`$server_td\` ($td_note). An interim trust domain is fixed in the SPIRE root CA, so the zone is re-installed with its final name under the delegated trust-framework zone once that name is confirmed; until then this kept zone is not acceptance evidence. A later run of this proof starts from the clean slate (section 1) and uninstalls it first."
  else
    not_kept="$((failures - before)) check(s) of the CNI read-back and the record of what remains failed"
  fi
fi
CRDS_KEEP=$(k get crd -o json | jq -r '[.items[] | select(.spec.group == "spire.spiffe.io") | "\(.metadata.name)=\(.metadata.annotations["helm.sh/resource-policy"] // "none")"] | join(" ")')
if [ "$keep_zone" != 1 ]; then
  section "$([ "$KEEP" = 1 ] && [ "$failures" -gt 0 ] && [ -n "${before:-}" ] && echo 17 || echo 16). Teardown: uninstall in reverse order"
  say "Not kept: $not_kept." ''
  [ "$(wc -w <<<"$CRDS_KEEP")" = 3 ] && ! grep -q '=keep' <<<"$CRDS_KEEP"
  check $? "the three SPIRE CRDs carry no helm.sh/resource-policy keep, so the uninstall of spire-crds removes them through Helm alone (the installer deletes CRDs itself only for istio-base)" "$CRDS_KEEP"
  "$INSTALL" uninstall >"$work/uninstall.log" 2>&1; rc=$?
  head -1 "$work/uninstall.log" | grep -qx 'uninstall ztd-openbao: done' || rc=1
  check $rc "the installer uninstalls the eight releases in reverse order, ztd-openbao first" "$(grep -c 'done$' "$work/uninstall.log") releases removed; first: $(head -1 "$work/uninstall.log")"
  code "$(cat "$work/uninstall.log")"
  # The umbrella's release namespace holds nothing once the umbrella is uninstalled; it goes last.
  k delete namespace ztd-system --ignore-not-found --wait=true >/dev/null 2>&1
  cleaned=1
  for _ in $(seq 1 60); do k get ns "$MGMT" "$DATA" "$SPIRE_NS" "$ISTIO_NS" ztd-system >/dev/null 2>&1 || break; sleep 3; done
  left=$(k get ns "$MGMT" "$DATA" "$SPIRE_NS" "$ISTIO_NS" ztd-system --ignore-not-found -o name 2>/dev/null)
  [ -z "$left" ]; check $? "no plane, control-plane or release namespace (ztd-system) remains" "${left:-none}"
  left=$(k get crd -o name | grep -E 'spiffe\.io|istio\.io' || true)
  [ -z "$left" ]; check $? "no SPIRE or Istio custom resource definition remains" "${left:-none}"
  left=$(k get validatingwebhookconfiguration,mutatingwebhookconfiguration -o name | grep -E 'istio|spire' || true)
  [ -z "$left" ]; check $? "no admission webhook of either control plane remains" "${left:-none}"

  # ------------------------------------------------------------------------------------------
  section "The cluster's CNI as found"
  cni_check
fi
fi # routing_ok: the end of sections 1 to 15

# --------------------------------------------------------------------------------------------
say '' '## Result' ''
if [ "$failures" -eq 0 ]; then say 'All checks passed.'; else say "**$failures check(s) failed.**"; fi
if [ "$keep_zone" = 1 ]; then say '' "Zone kept: yes, installed on \`$CONTEXT\` (trust domain \`$TD\`)."
else say '' "Zone kept: no (not kept: $not_kept)."; fi

# environment.json: what the run was made on, and the cluster as found.
ver() { "$@" 2>/dev/null | head -1; }
host_kind="$(uname -s) $(uname -r)"
grep -qi microsoft /proc/version 2>/dev/null && host_kind="$host_kind (WSL)"
[ -r /etc/os-release ] && host_kind="$host_kind, $(. /etc/os-release && echo "$PRETTY_NAME")"
# write_environment <file>: environment.json from the run's variables; the kind fields (the node image
# and the kind version) only on kind
write_environment() {
  local node_image="" kind_version=""
  if [ "$CLUSTER_KIND" = kind ]; then
    node_image=$(sed -n 's/^NODE_IMAGE=\${KIND_NODE_IMAGE:-\(.*\)}$/\1/p' "$REPO/scripts/dev/kind-cilium-up.sh")
    kind_version=$(ver kind version)
  fi
  local interim=false; [[ $TD == *.trust.invalid ]] && interim=true
  local keptj=false; [ "$keep_zone" = 1 ] && keptj=true
  jq -n --arg commit "$commit" --argjson dirty "$dirty" --arg date "$started" --arg finished "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg host "$host_kind" --arg context "$CONTEXT" --arg clusterKind "$CLUSTER_KIND" --arg provider "$provider" \
    --argjson nodes "${nodes_json:-[]}" --arg zone "${ZONE_VALUES#"$REPO"/}" --arg zoneName "$ZONE_NAME" --arg td "$TD" \
    --argjson interim "$interim" --argjson kept "$keptj" --arg notKept "$not_kept" \
    --arg kind "$kind_version" --arg kubectl "$(kubectl version --client -o json 2>/dev/null | jq -r .clientVersion.gitVersion)" \
    --arg helm "$(ver helm version --short)" --arg istioctl "$(istioctl version --remote=false 2>/dev/null | sed 's/^client version: //' | head -1)" \
    --arg cilium "$(cilium version --client 2>/dev/null | head -1)" --arg server "$server" --arg cni "$cni" --arg nodeImage "$node_image" \
    --arg spire "$(sed -n 's/^SPIRE_VERSION=\([^ ]*\).*/\1/p' "$INSTALL")" --arg spireCrds "$(sed -n 's/^SPIRE_CRDS_VERSION=\(.*\)/\1/p' "$INSTALL")" \
    --arg istio "$(sed -n 's/^ISTIO_VERSION=\(.*\)/\1/p' "$INSTALL")" \
    --arg imgSpire "$images_spire" --arg imgIstio "$images_istio" --arg imgProxy "$images_proxy" \
    --argjson failures "$failures" '{
      commit: $commit, dirty: $dirty, date: $date, finished: $finished,
      host: { kind: $host },
      cluster: ({ context: $context, kind: $clusterKind, provider: $provider, kubernetes: $server, nodes: $nodes, cni: $cni }
        + (if $clusterKind == "kind" then { kindNodeImage: $nodeImage } else {} end)),
      zone: ({ file: $zone, name: $zoneName, trustDomain: $td, trustDomainInterim: $interim, kept: $kept }
        + (if $kept then {} else { notKept: $notKept } end)),
      tools: ((if $clusterKind == "kind" then { kind: $kind } else {} end) + { kubectl: $kubectl, helm: $helm, istioctl: $istioctl, cilium: $cilium }),
      charts: { "spire-crds": $spireCrds, spire: $spire, "istio-base": $istio, istiod: $istio, "istio-cni": $istio },
      images: { "spire-system": ($imgSpire | split(",")), "istio-system": ($imgIstio | split(",")), proxy: $imgProxy, cilium: $cni },
      result: { failures: $failures }
    }' >"$1"
}
write_environment "$work/environment.json"

if mkdir -p "$EVID"; then
  if [ "$CLUSTER_KIND" = kind ]; then
    cp "$OUT" "$EVID/evidence.md" && cp "$work/environment.json" "$EVID/environment.json" && written=1
  else
    # No address of a client cluster is kept in a record: every IPv4 address (nodes, pods, the
    # probed servers) is replaced in the record of a participant cluster. The loopback 127.0.0.1 is
    # no address of the cluster and stays, so the record still shows where the agents answer.
    mask() { sed -E 's/(^|[^0-9.])127\.0\.0\.1([^0-9.]|$)/\1@LOOPBACK@\2/g; s/(^|[^0-9.])127\.0\.0\.1([^0-9.]|$)/\1@LOOPBACK@\2/g
      s/(^|[^0-9.])([0-9]{1,3}\.){3}[0-9]{1,3}([^0-9.]|$)/\1<address>\3/g; s/(^|[^0-9.])([0-9]{1,3}\.){3}[0-9]{1,3}([^0-9.]|$)/\1<address>\3/g
      s/@LOOPBACK@/127.0.0.1/g' "$1"; }
    mask "$OUT" >"$EVID/evidence.md" && mask "$work/environment.json" >"$EVID/environment.json" && written=1
  fi
fi
if [ "$written" != 1 ]; then
  # No record, no kept zone: kept stays 0, so the EXIT trap tears a participant zone down.
  echo "verify-mesh-identity: the evidence could not be written to $EVID" >&2
  failures=$((failures+1))
  exit $(( failures > 124 ? 124 : failures ))
fi
# The zone counts as kept only now that its record is on disk (the EXIT trap tears it down before).
[ "$keep_zone" = 1 ] && kept=1
echo "evidence written ($failures failure(s); zone kept: $([ "$kept" = 1 ] && echo yes || echo "no, $not_kept")); run directory:"
# The last line of the output is the run directory, alone, so a caller takes it with tail -n 1.
echo "$EVID"
exit $(( failures > 124 ? 124 : failures ))
