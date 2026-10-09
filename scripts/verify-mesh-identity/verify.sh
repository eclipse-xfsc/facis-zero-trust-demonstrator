#!/usr/bin/env bash
# Evidence that the zone's mesh identities are SPIRE's, on the local kind cluster with Cilium chained
# (scripts/dev/kind-cilium-up.sh). Installs the zone from an empty cluster with
# scripts/install-zone/install.sh, twice, then proves with stand-in pods: an SVID over the CSI socket,
# the proxy's certificate and root bundle issued by SPIRE, no proxy without the SPIRE socket and a
# certificate from istiod's CA refused by a meshed peer, the proxy's traffic capture held at the
# injector's defaults (the capture rule), the TLS 1.3 minimum of mesh mTLS, an
# unregistered workload cut off, traffic through the proxies, the default deny intact with the
# chained CNI and both control planes inside it, the native-sidecar version rule, the identity-band checks, and a teardown that leaves nothing
# behind. Writes docs/evidences/mesh-identity/evidence.md and environment.json; the exit status is
# non-zero if any check failed. Never run by CI: the evidence is the record of a run on a cluster.
#
# Usage:
#   scripts/verify-mesh-identity/verify.sh           run the proof: DESTRUCTIVE, it uninstalls the zone
#                                                    from the cluster first and again at the end
#   scripts/verify-mesh-identity/verify.sh --help    this text; touches nothing
# Any other argument prints this text and exits 2 without touching the cluster.
#
# Environment:
#   KUBE_CONTEXT   kubectl context   (default: kind-ztd); refused unless it is a kind cluster (the
#                  context is named kind-<name> and every node's provider ID is kind://...)
#   ZONE_VALUES    zone file         (default: deployment/helm/ztd/ci/values.yaml, the kind zone)
#
# Every check is "<test>; check $? <title>": the status of the test is what the check records.
# shellcheck disable=SC2319,SC2016,SC2181,SC1091
set -uo pipefail
usage() { sed -n '2,/^# Every check/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }
case $# in
  0) ;;
  1) case $1 in -h|--help) usage; exit 0;; esac; usage >&2; echo "verify-mesh-identity: unknown argument: $1" >&2; exit 2;;
  *) usage >&2; echo "verify-mesh-identity: takes no arguments" >&2; exit 2;;
esac
if [ -n "${CI:-}" ]; then
  echo "verify-mesh-identity: refusing to run under CI; the evidence is written from a run on a cluster" >&2
  exit 2
fi
cd "$(dirname "$0")" || exit 1
REPO=$(git rev-parse --show-toplevel)
CHART=$REPO/deployment/helm/ztd
ZONE_VALUES=${ZONE_VALUES:-$CHART/ci/values.yaml}
CONTEXT=${KUBE_CONTEXT:-kind-ztd}
# The run uninstalls and reinstalls the zone: refuse any cluster that is not a local kind cluster,
# before anything is read from it or written to it.
case $CONTEXT in
  kind-?*) ;;
  *) echo "verify-mesh-identity: refusing context '$CONTEXT': not a kind cluster (kind-<name>); the run uninstalls the zone" >&2; exit 2;;
esac
providers=$(kubectl --context "$CONTEXT" get nodes -o jsonpath='{range .items[*]}{.spec.providerID}{"\n"}{end}' 2>/dev/null)
if [ -z "$providers" ] || grep -qv '^kind://' <<<"$providers"; then
  echo "verify-mesh-identity: refusing context '$CONTEXT': unreachable, or a node whose provider ID is not kind://" >&2
  exit 2
fi
INSTALL=$REPO/scripts/install-zone/install.sh
EVID=$REPO/docs/evidences/mesh-identity
export ZONE_VALUES KUBE_CONTEXT=$CONTEXT
# yaml_get <file> <key>... : one value out of a YAML file; the path travels as an argument, never inside the source
yaml_get() { python3 -c 'import sys,yaml
v=yaml.safe_load(open(sys.argv[1]))
for k in sys.argv[2:]: v=v[k]
print(v)' "$@"; }
MGMT=$(yaml_get "$CHART/values.yaml" planes management namespace)
DATA=$(yaml_get "$CHART/values.yaml" planes data namespace)
TD=$(yaml_get "$ZONE_VALUES" zone trustDomain)
SPIRE_NS=spire-system; ISTIO_NS=istio-system
images_spire=""; images_istio=""; images_proxy=""
RELEASES="ztd:ztd-system spire-crds:$SPIRE_NS spire:$SPIRE_NS istio-base:$ISTIO_NS istiod:$ISTIO_NS istio-cni:$ISTIO_NS zone-policy:$ISTIO_NS"
SA_ID="spiffe://$TD/ns/$DATA/sa/stand-in"
# The admission policy of zone-policy. The proxy status port its capture rule lets the injector
# exclude is read from the installed release in section 8, not from the chart's defaults.
POLICY=proxy-takes-spire-socket
STATUS_PORT=""

work=$(mktemp -d)
# restore_capture: puts the capture validation back into the live policy when it is missing from it
# and section 5 saved it (restore.json); a no-op otherwise, so it is safe to call more than once.
restore_capture() {
  [ -s "$work/restore.json" ] || return 0
  kubectl --context "$CONTEXT" get validatingadmissionpolicy "$POLICY" -o json 2>/dev/null \
    | jq -e '[.spec.validations[].expression | contains("variables.captureDefaults")] | index(true) == null' >/dev/null || return 0
  kubectl --context "$CONTEXT" patch validatingadmissionpolicy "$POLICY" --type=json --patch-file "$work/restore.json" >/dev/null
}
# On any exit, an interrupt included, the capture validation lifted in section 5 is put back first.
trap 'restore_capture; rm -rf "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
OUT=$work/evidence.md
failures=0
# The commit and the dirty flag are read before anything is written into the tree.
commit=$(git rev-parse HEAD)
dirty=false; [ -n "$(git status --porcelain)" ] && dirty=true
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)

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

: > "$OUT"
say "# Mesh identity evidence ($started)" ''
say "Cluster context \`$CONTEXT\`, zone file \`${ZONE_VALUES#"$REPO"/}\` (trust domain \`$TD\`), installed with \`scripts/install-zone/install.sh\`: the seven releases \`ztd\`, \`spire-crds\`, \`spire\`, \`istio-base\`, \`istiod\`, \`istio-cni\`, \`zone-policy\`. Commit \`$commit\`, tree dirty: $dirty. Versions in \`environment.json\`." ''
say 'Probe results: an HTTP code with the first line of the body when the call went through its proxies; `denied(28)` when a raw TCP connection timed out because the policy dropped the packets; `denied(56)` when the peer reset the connection; `error(<exit>)`, which fails a negative check, for any other failure (a name that does not resolve, an exec that failed).' ''

# --------------------------------------------------------------------------------------------
section "0. Preconditions"
server=$(k version -o json | jq -r .serverVersion.gitVersion)
recorded=$(yaml_get "$ZONE_VALUES" zone kubernetesVersion)
[ "$server" = "$recorded" ]; check $? "the zone file records the server version the cluster runs" "server $server, recorded $recorded"
python3 - "$server" <<'PY'; check $? "native-sidecar-version: the server is Kubernetes 1.33 or later (native sidecar containers)" "server $server"
import re, sys
major, minor = map(int, re.match(r"v(\d+)\.(\d+)", sys.argv[1]).groups())
sys.exit(0 if (major, minor) >= (1, 33) else 1)
PY
cni=$(k -n kube-system get ds cilium -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null)
[ -n "$cni" ]; check $? "Cilium is the CNI" "$cni"
excl=$(k -n kube-system get cm cilium-config -o jsonpath='{.data.cni-exclusive}' 2>/dev/null)
[ "$excl" = "false" ]; check $? "cni-exclusive=false (the Istio CNI plugin can chain)" "cni-exclusive=$excl"
inotify=$(cat /proc/sys/fs/inotify/max_user_instances 2>/dev/null || echo 0)
[ "$inotify" -ge 512 ]; check $? "the host allows 512 inotify instances (kind runs every node's agents on one kernel; the Istio CNI agent fails below)" "fs.inotify.max_user_instances=$inotify"
code "$(k get nodes -o wide | sed 's/  */ /g')"

# --------------------------------------------------------------------------------------------
section "1. Clean slate"
"$INSTALL" uninstall >"$work/clean.log" 2>&1
k get ns "$MGMT" "$DATA" "$SPIRE_NS" "$ISTIO_NS" >/dev/null 2>&1; [ $? -ne 0 ]; check $? "no plane namespace and no control-plane namespace exists before the install"
left=$(k get crd -o name | grep -E 'spiffe\.io|istio\.io' || true)
[ -z "$left" ]; check $? "no SPIRE or Istio custom resource definition exists before the install" "${left:-none}"

# --------------------------------------------------------------------------------------------
section "2. install-order-idempotent: the zone from an empty cluster, twice"
start=$(date +%s)
"$INSTALL" install >"$work/install1.log" 2>&1; rc=$?
check $rc "first installer run from an empty cluster returns 0, no manual step between the releases" "$(( $(date +%s) - start ))s"
code "$(grep -E '^(  [0-9]/7|step|zone installed)' "$work/install1.log")"
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
[ "$same" -eq 7 ]; check $? "helm get manifest of every release is identical between the two runs" "$same of 7 identical${diffs:+; differ:$diffs}"
tail -1 "$work/install2.log" | grep -q '^zone installed: every pod'; check $? "every pod in the plane and control-plane namespaces is Ready (the installer's exit condition)" "$(tail -1 "$work/install2.log")"
code "$(h list -A -o json | jq -r '(["RELEASE","NAMESPACE","REVISION","STATUS","CHART"] | join(" ")), (.[] | [.name, .namespace, .revision, .status, .chart] | join(" "))')"
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
[ $rc -ne 0 ] && grep -q 'step 1/7 FAILED: release ztd' <<<"$out" && ! grep -q 'step 2/7' <<<"$out"
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
say 'From `scripts/verify-mesh-identity/fixtures/stand-ins.yaml`: in the data plane a meshed peer, a labelled caller with a Workload API client on the CSI socket, an unlabelled meshed pod, an unlabelled pod without proxy with a Workload API client, the matrix pair `pdp-adapter` and the cross-plane caller `data-plain`; in the management plane `tsa-policy-engine`, `openbao` and `mgmt-caller`; in both a proxy-less `probe` for raw TCP probes. All in the service account `stand-in` unless noted.' ''
sed -e "s/__DATA__/$DATA/g" -e "s/__MGMT__/$MGMT/g" fixtures/stand-ins.yaml >"$work/stand-ins.yaml"
# The stand-ins that opt out of injection go apart: the capture rule refuses them (below).
# Their refusal is asked with a server dry-run create of a copy under other names (suffix
# -capture-check): a create of a name that exists would still reach admission, but kubectl apply of
# an unchanged object sends no request at all, and an update of a pod's spec fails on pod
# immutability before the policy is asked.
python3 - "$work/stand-ins.yaml" "$work/stand-ins-meshed.yaml" "$work/stand-ins-proxyless.yaml" "$work/stand-ins-proxyless-check.yaml" <<'PY'
import copy, sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
off = lambda d: (d["metadata"].get("annotations") or {}).get("sidecar.istio.io/inject") == "false"
yaml.safe_dump_all([d for d in docs if not off(d)], open(sys.argv[2], "w"), sort_keys=False)
yaml.safe_dump_all([d for d in docs if off(d)], open(sys.argv[3], "w"), sort_keys=False)
check = [copy.deepcopy(d) for d in docs if off(d)]
for d in check: d["metadata"]["name"] += "-capture-check"
yaml.safe_dump_all(check, open(sys.argv[4], "w"), sort_keys=False)
PY
k apply -f "$work/stand-ins-meshed.yaml" >/dev/null
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
rc_create=1
if [ "${idx:-null}" != null ] && k patch validatingadmissionpolicy "$POLICY" --type=json --patch-file "$work/lift.json" >/dev/null 2>&1; then
  for _ in $(seq 30); do proxyless_admitted && break; sleep 1; done
  k apply -f "$work/stand-ins-proxyless.yaml" >/dev/null; rc_create=$?
  restore_capture
  for _ in $(seq 30); do proxyless_refused && break; sleep 1; done
fi
check $rc_create "with the capture validation (index ${idx:-none}) lifted, the three proxy-less stand-ins are created"
diff <(jq -S .spec "$work/policy.json") <(k get validatingadmissionpolicy "$POLICY" -o json | jq -S .spec) >/dev/null && proxyless_refused
check $? "the policy is put back unchanged (its spec equals the one read before the lift) and refuses the three again" "$(k get validatingadmissionpolicy "$POLICY" -o json | jq '.spec.validations | length') validations in force"
k -n "$DATA" wait --for=condition=Ready pod/peer pod/caller pod/unregistered-svid pod/probe pod/pdp-adapter pod/data-plain --timeout=240s >/dev/null 2>&1; check $? "the labelled data-plane stand-ins are Ready"
k -n "$MGMT" wait --for=condition=Ready pod/tsa-policy-engine pod/openbao pod/mgmt-caller pod/probe --timeout=240s >/dev/null 2>&1; check $? "the management-plane stand-ins are Ready"
sleep 10
code "$(k get pods -n "$DATA" -o wide | sed 's/  */ /g'; echo; k get pods -n "$MGMT" -o wide | sed 's/  */ /g')"

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
istioctl --context "$CONTEXT" proxy-config secret caller -n "$DATA" -o json >"$work/secret.json" 2>/dev/null
jq -r '.dynamicActiveSecrets[] | select(.name == "default") | .secret.tlsCertificate.certificateChain.inlineBytes' "$work/secret.json" | base64 -d >"$work/proxy-chain.pem" 2>/dev/null
# SPIRE serves ROOTCA as Envoy's SPIFFE certificate validator: one trust bundle per trust domain.
jq -r --arg td "$TD" '.dynamicActiveSecrets[] | select(.name == "ROOTCA") | .secret.validationContext
  | (.trustedCa.inlineBytes // (.customValidatorConfig.typedConfig.trustDomains[]? | select(.name == $td) | .trustBundle.inlineBytes))' \
  "$work/secret.json" | base64 -d >"$work/proxy-root.pem" 2>/dev/null
rootca_domains=$(jq -r '[.dynamicActiveSecrets[] | select(.name == "ROOTCA") | .secret.validationContext.customValidatorConfig.typedConfig.trustDomains[]?.name] | join(",")' "$work/secret.json")
openssl x509 -in "$work/proxy-chain.pem" -out "$work/proxy-leaf.pem" 2>/dev/null
subj=$(openssl x509 -noout -subject -nameopt RFC2253 -in "$work/proxy-leaf.pem" 2>/dev/null)
p_issuer=$(openssl x509 -noout -issuer -nameopt RFC2253 -in "$work/proxy-leaf.pem" 2>/dev/null)
p_uri=$(openssl x509 -noout -ext subjectAltName -in "$work/proxy-leaf.pem" 2>/dev/null | grep -o 'URI:[^,]*' | sed 's/URI://')
grep -q 'O=SPIRE' <<<"$subj"; check $? "the proxy's workload certificate (default) has O = SPIRE in its subject" "$subj"
[ "${p_issuer#issuer=}" = "${ca_subject#subject=}" ] && openssl verify -CAfile "$work/spire-bundle.pem" "$work/proxy-leaf.pem" >/dev/null 2>&1
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
  | k -n "$OUTSIDE" create -f - >/dev/null
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
# client certificate; the options (a TLS version bound) go to curl as they stand
mtls() { local cert=$1 key=$2; shift 2; k -n "$DATA" exec probe -c app -- curl -sS -k -m 15 "$@" --cert "/tmp/$cert" --key "/tmp/$key" -w '\n%{http_code}' "https://$PEER_IP:8080/hostname" 2>&1; }
out=$(mtls svid.pem svid.key)
[ "$(tail -1 <<<"$out")" = 200 ]; check $? "with the caller's SPIRE SVID the peer's proxy completes the handshake and the request succeeds" "→ $(tr '\n' ' ' <<<"$out")"
out=$(mtls istiod-leaf.pem istiod-leaf.key)
[ "$(tail -1 <<<"$out")" != 200 ] && grep -q 'alert' <<<"$out"
check $? "with the istiod-signed certificate for the same SPIFFE ID the peer's proxy refuses the handshake: its ROOTCA is SPIRE's bundle only" "→ $(grep -o 'curl: .*' <<<"$out" | head -1)"
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
case $r in denied*) true;; *) false;; esac; check $? "a call from its network namespace to the meshed peer is refused: the peer accepts mTLS only (STRICT)" "→ $r"
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

# --------------------------------------------------------------------------------------------
section "11. default-deny-with-chained-cni"
for P in $(k -n "$ISTIO_NS" get pod -l k8s-app=istio-cni-node -o jsonpath='{.items[*].metadata.name}'); do
  NODE=$(k -n "$ISTIO_NS" get pod "$P" -o jsonpath='{.spec.nodeName}')
  conf=$(k -n "$ISTIO_NS" exec "$P" -- sh -c 'ls /host/etc/cni/net.d/*.conflist | head -1')
  plugins=$(k -n "$ISTIO_NS" exec "$P" -- cat "$conf" | jq -r '[.plugins[].type] | join(" → ")')
  [[ "$plugins" == cilium-cni*istio-cni* ]]; check $? "the CNI configuration of node $NODE lists the Istio plugin after Cilium" "${conf#/host}: $plugins"
done
[ "$excl" = false ]; check $? "Cilium still runs with cni-exclusive=false" "cni-exclusive=$excl"
r=$(http "$DATA" data-plain app "http://openbao.$MGMT.svc:8080/hostname")
case $r in denied*) true;; *) false;; esac; check $? "data-plane pod → openbao (management): DENIED at the network layer with the proxies in place" "→ $r"
r=$(http "$DATA" data-plain app "http://tsa-policy-engine.$MGMT.svc:8080/hostname")
case $r in denied*) true;; *) false;; esac; check $? "data-plane pod → tsa-policy-engine (management): DENIED" "→ $r"
r=$(http "$DATA" pdp-adapter app "http://tsa-policy-engine.$MGMT.svc:8080/hostname")
[ "${r%% *}" = 200 ]; check $? "pdp-adapter → tsa-policy-engine: ALLOWED (matrix lane pdp-adapter-to-tsa), through the proxies" "→ $r"
r=$(http "$DATA" pdp-adapter app "http://openbao.$MGMT.svc:8080/hostname")
case $r in denied*) true;; *) false;; esac; check $? "pdp-adapter → openbao: DENIED (a lane is one pair, not a licence)" "→ $r"
r=$(http "$MGMT" mgmt-caller app "http://peer.$DATA.svc:8080/hostname")
case $r in denied*) true;; *) false;; esac; check $? "management pod → data plane: DENIED (the default deny is both directions)" "→ $r"
r=$(k -n "$DATA" exec probe -c app -- nslookup "openbao.$MGMT.svc.cluster.local" 2>&1 | grep -A1 '^Name:' | tr '\n' ' ')
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
for NODE in $(k -n "$SPIRE_NS" get pods -o json | jq -r '.items[] | select(.metadata.ownerReferences[0].name == "spire-agent") | .spec.nodeName'); do
  C=$(k -n kube-system get pod -l k8s-app=cilium --field-selector "spec.nodeName=$NODE" -o jsonpath='{.items[0].metadata.name}')
  listen=$(k -n kube-system exec "$C" -c cilium-agent -- cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk '$4 == "0A" && $2 ~ /:2704$/ {print $2}' | sort -u | tr '\n' ' ')
  [ -n "$listen" ] && ! grep -qvE '^(0100007F|00000000000000000000000001000000):2704$' <<<"$(tr ' ' '\n' <<<"$listen" | grep .)"
  check $? "node $NODE: the SPIRE agent's metrics port 9988 listens on the loopback only, not on the node's addresses" "listening (hex address:port): ${listen:-none}"
  n=$(k -n kube-system exec "$C" -c cilium-agent -- bash -c 'exec 3<>/dev/tcp/127.0.0.1/9988; printf "GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n" >&3; cat <&3' 2>/dev/null | grep -c '^spire_agent')
  [ "$n" -gt 0 ]; check $? "node $NODE: the agent's metrics answer on 127.0.0.1:9988 (the contract with a node-local collector)" "$n spire_agent samples"
done

# --------------------------------------------------------------------------------------------
section "13. A declared registration without its entry fails the release"
say 'The registrations-reconciled check counts the running labelled pods of every plane namespace and compares them with what the controller-manager reconciled. To make one registration go unreconciled, the kind namespace `local-path-storage`, which the controller-manager is configured to ignore, is labelled as a plane for the duration of the step and gets a labelled pod; then zone-policy is upgraded through the lifecycle step with a 20 s check timeout. Afterwards the label and the pod are removed and the rollback restores the release.' ''
k label ns local-path-storage ztd.facis.io/plane=data --overwrite >/dev/null
k -n local-path-storage run declared-not-reconciled --image=docker.io/curlimages/curl:8.10.1@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b --labels=spiffe.io/spire-managed-identity=true --command -- sleep 3600 >/dev/null
k -n local-path-storage wait --for=condition=Ready pod/declared-not-reconciled --timeout=120s >/dev/null 2>&1
printf 'trustDomain: %s\nchecks:\n  timeoutSeconds: 20\n' "$TD" >"$work/zp-values.yaml"
k config view --minify --flatten --context "$CONTEXT" >"$work/kubeconfig"
res=$(KUBECONFIG=$work/kubeconfig LIFECYCLE_RELEASE=zone-policy LIFECYCLE_NAMESPACE=$ISTIO_NS LIFECYCLE_CHART=$REPO/deployment/helm/zone-policy \
  LIFECYCLE_VALUES_FILE=$work/zp-values.yaml LIFECYCLE_TIMEOUT=3m "$REPO/scripts/lifecycle.sh" deploy 2>/dev/null | grep '^RESULT_JSON=' | cut -d= -f2-)
[ "$(jq -r .ok <<<"$res")" = false ]; check $? "the upgrade fails and is rolled back" "$(jq -r '.error.message' <<<"$res")"
jl=$(k -n "$ISTIO_NS" logs job/zone-policy-registrations-reconciled 2>/dev/null | grep -E '^(FAIL|ok)' | tail -2 | tr '\n' ' ')
grep -q 'FAIL every registration' <<<"$jl"; check $? "the registrations-reconciled job exits non-zero naming the gap" "$jl"
k -n "$ISTIO_NS" delete job -l ztd.facis.io/identity-check --ignore-not-found >/dev/null
k -n local-path-storage delete pod declared-not-reconciled --wait=true >/dev/null 2>&1
k label ns local-path-storage ztd.facis.io/plane- >/dev/null
st=$(h status zone-policy -n "$ISTIO_NS" -o json | jq -r .info.status)
[ "$st" = deployed ]; check $? "after the step the release is deployed again (rollback)" "$(h history zone-policy -n "$ISTIO_NS" --max 3 -o json | jq -r '[.[] | "\(.revision) \(.status)"] | join(", ")')"

# --------------------------------------------------------------------------------------------
section "14. Render guards (no cluster)"
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

# --------------------------------------------------------------------------------------------
section "15. Teardown: uninstall in reverse order"
kept=$(k get crd -o json | jq -r '[.items[] | select(.spec.group == "spire.spiffe.io") | "\(.metadata.name)=\(.metadata.annotations["helm.sh/resource-policy"] // "none")"] | join(" ")')
[ "$(wc -w <<<"$kept")" = 3 ] && ! grep -q '=keep' <<<"$kept"
check $? "the three SPIRE CRDs carry no helm.sh/resource-policy keep, so the uninstall of spire-crds removes them through Helm alone (the installer deletes CRDs itself only for istio-base)" "$kept"
sed -e "s/__DATA__/$DATA/g" -e "s/__MGMT__/$MGMT/g" fixtures/stand-ins.yaml | k delete -f - --wait=true >/dev/null 2>&1
"$INSTALL" uninstall >"$work/uninstall.log" 2>&1; rc=$?
check $rc "the installer uninstalls the seven releases in reverse order" "$(grep -c 'done$' "$work/uninstall.log") releases removed"
code "$(cat "$work/uninstall.log")"
for _ in $(seq 1 60); do k get ns "$MGMT" "$DATA" "$SPIRE_NS" "$ISTIO_NS" >/dev/null 2>&1 || break; sleep 3; done
left=$(k get ns "$MGMT" "$DATA" "$SPIRE_NS" "$ISTIO_NS" --ignore-not-found -o name 2>/dev/null)
[ -z "$left" ]; check $? "no plane namespace and no control-plane namespace remains" "${left:-none}"
left=$(k get crd -o name | grep -E 'spiffe\.io|istio\.io' || true)
[ -z "$left" ]; check $? "no SPIRE or Istio custom resource definition remains" "${left:-none}"
left=$(k get validatingwebhookconfiguration,mutatingwebhookconfiguration -o name | grep -E 'istio|spire' || true)
[ -z "$left" ]; check $? "no admission webhook of either control plane remains" "${left:-none}"
say "  the umbrella's release namespace \`ztd-system\` remains, as expected: the installer creates it and no release owns it" ''

# --------------------------------------------------------------------------------------------
say '' '## Result' ''
if [ "$failures" -eq 0 ]; then say 'All checks passed.'; else say "**$failures check(s) failed.**"; fi

# environment.json: what the run was made on.
ver() { "$@" 2>/dev/null | head -1; }
node_image=$(sed -n 's/^NODE_IMAGE=\${KIND_NODE_IMAGE:-\(.*\)}$/\1/p' "$REPO/scripts/dev/kind-cilium-up.sh")
host_kind="$(uname -s) $(uname -r)"
grep -qi microsoft /proc/version 2>/dev/null && host_kind="$host_kind (WSL)"
[ -r /etc/os-release ] && host_kind="$host_kind, $(. /etc/os-release && echo "$PRETTY_NAME")"
jq -n --arg commit "$commit" --argjson dirty "$dirty" --arg date "$started" --arg finished "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg host "$host_kind" --arg context "$CONTEXT" --arg zone "${ZONE_VALUES#"$REPO"/}" --arg td "$TD" \
  --arg kind "$(ver kind version)" --arg kubectl "$(kubectl version --client -o json 2>/dev/null | jq -r .clientVersion.gitVersion)" \
  --arg helm "$(ver helm version --short)" --arg istioctl "$(istioctl version --remote=false 2>/dev/null | sed 's/^client version: //' | head -1)" \
  --arg cilium "$(cilium version --client 2>/dev/null | head -1)" --arg server "$server" --arg cni "$cni" --arg nodeImage "$node_image" \
  --arg spire "$(sed -n 's/^SPIRE_VERSION=\([^ ]*\).*/\1/p' "$INSTALL")" --arg spireCrds "$(sed -n 's/^SPIRE_CRDS_VERSION=\(.*\)/\1/p' "$INSTALL")" \
  --arg istio "$(sed -n 's/^ISTIO_VERSION=\(.*\)/\1/p' "$INSTALL")" \
  --arg imgSpire "$images_spire" --arg imgIstio "$images_istio" --arg imgProxy "$images_proxy" \
  --argjson failures "$failures" '{
    commit: $commit, dirty: $dirty, date: $date, finished: $finished,
    host: { kind: $host },
    cluster: { context: $context, kubernetes: $server, kindNodeImage: $nodeImage, cni: $cni },
    zone: { file: $zone, trustDomain: $td },
    tools: { kind: $kind, kubectl: $kubectl, helm: $helm, istioctl: $istioctl, cilium: $cilium },
    charts: { "spire-crds": $spireCrds, spire: $spire, "istio-base": $istio, istiod: $istio, "istio-cni": $istio },
    images: { "spire-system": ($imgSpire | split(",")), "istio-system": ($imgIstio | split(",")), proxy: $imgProxy, cilium: $cni },
    result: { failures: $failures }
  }' >"$work/environment.json"

mkdir -p "$EVID"
cp "$OUT" "$EVID/evidence.md"
cp "$work/environment.json" "$EVID/environment.json"
echo "evidence written to ${EVID#"$REPO"/} ($failures failure(s))"
exit $(( failures > 0 ))
