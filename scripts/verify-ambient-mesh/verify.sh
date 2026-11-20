#!/usr/bin/env bash
# Proof of the Istio ambient mesh on the demonstrator cluster (IONOS, Calico, no SPIRE; ADR-0018),
# after scripts/install-zone/install.sh installed it from the zone file. Installs nothing and
# changes no release: it places stand-in pods in the management and the data plane namespaces and in
# a throwaway namespace outside the mesh, proves with them, and removes them on exit, so that the
# cluster is left as it was found. Stops at the first unmet check. The checks, in order:
#   1 control plane   istiod available; istio-cni and ztunnel ready on every node
#   2 probes          the stand-ins' readiness probes pass under the default deny (Istio SNATs every
#                     connection from the node's network namespace, the kubelet's probes among them,
#                     to 169.254.7.127; the zone's ambientHostProbes opening)
#   3 enrolment       both plane namespaces carry istio.io/dataplane-mode=ambient (the label every
#                     in-the-mesh refusal of check 10 hangs on); ztunnel lists every enrolled
#                     stand-in with protocol HBONE, and the outside stand-in without it
#   4 identity        an allowed call (the allow-matrix lane pdp-adapter-to-tsa) succeeds, and
#                     ztunnel's access log shows it over HBONE between the two stand-ins' istiod-issued
#                     identities, spiffe://<zone.trustDomain>/ns/<namespace>/sa/<service account>
#   5 STRICT          a plaintext call from the throwaway namespace's stand-in, outside the mesh, to
#                     the data-plane target is refused by the target's ztunnel: a stand-in
#                     NetworkPolicy opens the network lane from that namespace to that target only, so
#                     only mTLS refuses it (a reset, not a timeout); an enrolled pod's call to the same
#                     target succeeds as the control
#   6 denied lane     a call outside the allow matrix (an unlabelled data-plane pod to the
#                     management stand-in) is refused
#   7 lane ports      a lane that names ports (workloads-to-otel-collector, 4317 and 4318) opens the
#                     HBONE port 15008 at the network layer: a data-plane pod reaches a collector
#                     stand-in on 4317, and is refused on another port the stand-in serves (8080),
#                     by zone-policy's ztunnel-enforced lane-port AuthorizationPolicy
#   8 webhook         a server-side dry run of an invalid Istio resource is denied by istiod's
#                     validating webhook (not by the CRD schema): the API server reached istiod on
#                     15017 through the zone's controlPlaneWebhooks opening (fromPods)
#   9 no sidecar      server-side dry runs, denied by zone-policy's no-sidecar-in-planes: a data-plane
#                     pod that chooses its injection templates, one that asks for injection, and one
#                     labelled istio.io/rev=default, which istiod's injector injects and the policy
#                     then refuses for what the injector left behind; admitted as controls: a plain
#                     data-plane pod, and in the mesh root namespace a copy of ztunnel's pod shape
#                     (a container istio-proxy, the labels istio.io/rev and sidecar.istio.io/inject=false)
#  10 in the mesh     server-side dry runs, denied by no-sidecar-in-planes in the namespaces enrolled
#                     in the mesh: a data-plane pod opted out (istio.io/dataplane-mode=none), a
#                     management-plane pod bypassing ztunnel's inbound capture, a data-plane pod on the
#                     host network and a management-plane pod with a hostPort; pods that could reach
#                     the node, its network or their own capture rules (the Pod Security Standards
#                     baseline): privileged with hostPID (in each plane), hostPID, hostIPC, a hostPath
#                     volume, an added NET_ADMIN, SYS_ADMIN (in an init container), all (lower case),
#                     SYS_MODULE or cap_dac_read_search (in an init container), a privileged init
#                     container, seccomp or AppArmor Unconfined, procMount Unmasked, a Windows
#                     hostProcess, SELinux type spc_t, the unsafe sysctl net.ipv4.ip_forward, a probe
#                     with a host; on the running data-plane stand-in, the opt-out label and the
#                     capture bypass written through pods/status, and a privileged, SYS_PTRACE or
#                     istio-proxy ephemeral container; admitted as controls: a data-plane pod adding
#                     baseline capabilities (chown, CAP_NET_BIND_SERVICE) with seccomp RuntimeDefault, a
#                     plain status update and a plain ephemeral container on that
#                     stand-in; in the mesh root namespace (not enrolled) a host-network pod, copies
#                     of the live pod templates of istiod, istio-cni and ztunnel (istio-cni and
#                     ztunnel add NET_ADMIN and SYS_ADMIN and mount hostPath volumes), and a status
#                     update of a live ztunnel pod
# Every object the run creates carries the label ztd.facis.io/proof-run=<a nonce of this run>, and only
# those are removed on exit; the run refuses to start while a pod, Service, ServiceAccount or
# NetworkPolicy named proof-* or labelled ztd.facis.io/proof=ambient-mesh exists in the plane
# namespaces (left by an earlier run still terminating, or someone else's).
# A passing run writes its dated record to docs/evidences/ambient-mesh-demonstrator/<UTC date>.md in
# the repository, the only file it writes there, to be committed as the evidence; a failing run
# writes the record to a temporary directory and prints its path. Never run by CI.
#
# Usage:
#   scripts/verify-ambient-mesh/verify.sh           run the proof (creates and removes stand-ins)
#   scripts/verify-ambient-mesh/verify.sh --help    this text; touches nothing
#
# Exit status: 0 every check passed; 1 a check failed (the run stopped there); 125 refused or not
# run (an argument, CI, the context or zone file guard, a missing tool): nothing written.
#
# Environment:
#   KUBE_CONTEXT         kubectl context (default: cluster-admin@ZeroTrustDemonstrator)
#   ZTD_CONFIRM_CLUSTER  the context name, typed for this run: the proof creates pods on that cluster
#   ZONE_VALUES          the zone file the cluster was installed from (default:
#                        deployment/helm/ztd/zones/ionos.yaml; the local copy with the API addresses
#                        reads the same). Refused unless it lies inside the repository (the record
#                        names it by its path there) and sets mesh.mode ambient and cni.derogation
#                        calico-ambient.
#   STANDIN_TIMEOUT      seconds to wait for the stand-ins to be Ready (default: 180)
# Every check is "<test>; check $? <title>": the status of the test is what the check records.
# shellcheck disable=SC2319,SC2015
set -uo pipefail
usage() { sed -n '2,/^set -uo pipefail$/p' "$0" | sed '$d' | grep -v '^# shellcheck' | sed 's/^# \{0,1\}//'; }
case $# in
  0) ;;
  1) case $1 in -h|--help) usage; exit 0;; esac; usage >&2; echo "verify-ambient-mesh: unknown argument: $1" >&2; exit 125;;
  *) usage >&2; echo "verify-ambient-mesh: takes no arguments" >&2; exit 125;;
esac
if [ -n "${CI:-}" ]; then
  echo "verify-ambient-mesh: refusing to run under CI; the evidence is the record of a run on the cluster" >&2
  exit 125
fi
[ -n "${ZONE_VALUES:-}" ] && ZONE_VALUES=$(realpath -m -- "$ZONE_VALUES")
cd "$(dirname "$0")" || exit 125
REPO=$(git rev-parse --show-toplevel) || exit 125
CHART=$REPO/deployment/helm/ztd
CONTEXT=${KUBE_CONTEXT:-cluster-admin@ZeroTrustDemonstrator}
ZONE_VALUES=${ZONE_VALUES:-$CHART/zones/ionos.yaml}
TIMEOUT=${STANDIN_TIMEOUT:-180}
refuse() { echo "verify-ambient-mesh: refusing: $*" >&2; exit 125; }

for tool in kubectl istioctl python3 git; do command -v "$tool" >/dev/null || refuse "missing tool: $tool"; done
python3 -c 'import yaml' 2>/dev/null || refuse "python3 needs PyYAML"
[ -f "$ZONE_VALUES" ] || refuse "zone file not found: $ZONE_VALUES"
case $ZONE_VALUES in
  "$REPO"/*) ;;
  *) refuse "the zone file must lie inside the repository (the evidence names it by its path there): $(basename -- "$ZONE_VALUES")";;
esac
[ "${ZTD_CONFIRM_CLUSTER:-}" = "$CONTEXT" ] \
  || refuse "context '$CONTEXT': the proof creates pods there; set ZTD_CONFIRM_CLUSTER=$CONTEXT for this run"

# The zone document: the umbrella's defaults with the zone file on top (as scripts/install-zone reads
# it). Prints: mode derogation trustDomain management-namespace data-namespace mesh-namespace.
read -r MODE DEROGATION TD MGMT DATA MESH_NS <<<"$(python3 - "$CHART/values.yaml" "$ZONE_VALUES" <<'PY'
import sys, yaml
def merge(base, top):
    if isinstance(base, dict) and isinstance(top, dict):
        out = dict(base)
        for k, v in top.items():
            out[k] = merge(base[k], v) if k in base else v
        return out
    return top
z = merge(yaml.safe_load(open(sys.argv[1])) or {}, yaml.safe_load(open(sys.argv[2])) or {})
print(z["mesh"]["mode"], (z.get("cni") or {}).get("derogation") or "-", z["zone"].get("trustDomain") or "-",
      z["planes"]["management"]["namespace"], z["planes"]["data"]["namespace"],
      z["networkPolicy"]["meshControlPlane"]["namespace"])
PY
)"
[ "$MODE" = ambient ] && [ "$DEROGATION" = calico-ambient ] \
  || refuse "the zone file ${ZONE_VALUES#"$REPO"/} sets mesh.mode $MODE and cni.derogation $DEROGATION; this proof is for the ambient zone under the derogation calico-ambient (ADR-0018)"
[ "$TD" != - ] || refuse "the zone file states no zone.trustDomain"
kubectl --context "$CONTEXT" version --request-timeout=10s >/dev/null 2>&1 || refuse "context '$CONTEXT' cannot be reached"
for ns in "$MGMT" "$DATA"; do
  left=$(kubectl --context "$CONTEXT" -n "$ns" get pod,service,serviceaccount,networkpolicy -o name 2>/dev/null | grep '/proof-'
         kubectl --context "$CONTEXT" -n "$ns" get pod,service,serviceaccount,networkpolicy -l ztd.facis.io/proof=ambient-mesh -o name 2>/dev/null)
  [ -z "$left" ] || refuse "$ns holds objects of the proof's names or label (an earlier run's, still terminating, or someone else's): $(sort -u <<<"$left" | paste -sd' '); remove them, then rerun"
done

# Stand-in images, pinned by digest; nothing here is consumed by the cluster's workloads.
AGNHOST=registry.k8s.io/e2e-test-images/agnhost:2.53@sha256:99c6b4bb4a1e1df3f0b3752168c89358794d02258ebebc26bf21c29399011a85
CURL=docker.io/curlimages/curl:8.10.1@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b
PLAIN=ztd-proof-plain          # the throwaway namespace, outside the mesh and outside the planes
PROOF_LABEL=ztd.facis.io/proof=ambient-mesh
RUN=r$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')   # this run's nonce: only objects carrying it are removed
RUN_LABEL=ztd.facis.io/proof-run=$RUN

k() { kubectl --context "$CONTEXT" "$@"; }
work=$(mktemp -d)
record=$work/record.md
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
commit=$(git rev-parse HEAD)
dirty=false; [ -n "$(git status --porcelain)" ] && dirty=true
say() { printf '%s\n' "$@" >>"$record"; }

CREATED_PLAIN=false   # the throwaway namespace is deleted only when this run created it
cleanup() {
  for ns in "$MGMT" "$DATA"; do
    k -n "$ns" delete pod,service,serviceaccount,networkpolicy -l "$RUN_LABEL" --ignore-not-found --wait=false >/dev/null 2>&1
  done
  if [ "$CREATED_PLAIN" = true ]; then
    k delete namespace "$PLAIN" --ignore-not-found --wait=false >/dev/null 2>&1
  fi
}
finish() { # finish <status>
  local status=$1 out
  cleanup
  say '' "Stand-ins removed on exit (the pods, Services, ServiceAccounts and the NetworkPolicy labelled with this run's \`$RUN_LABEL\`, and the namespace \`$PLAIN\` when this run created it)." ''
  if [ "$status" -eq 0 ]; then
    say '## Result' '' 'All checks passed.'
    out=$REPO/docs/evidences/ambient-mesh-demonstrator/$(date -u +%Y-%m-%d).md
    mkdir -p "$(dirname "$out")"; cp "$record" "$out"
    echo "verify-ambient-mesh: all checks passed; evidence written to ${out#"$REPO"/}"
  else
    say '## Result' '' "**FAILED**: $FAILED"
    echo "verify-ambient-mesh: FAILED: $FAILED; the record of the run is $record (not written to the repository)" >&2
  fi
  trap - EXIT INT TERM
  exit "$status"
}
FAILED="the run ended before its last check"
trap 'FAILED="interrupted"; finish 1' INT TERM
trap 'finish 1' EXIT
pass() { say "- PASS: $1"; [ $# -gt 1 ] && say "  $2"; return 0; }
fail() { FAILED=$1; say "- **FAIL**: $1"; [ $# -gt 1 ] && say "  $2"; finish 1; }
check() { # check <status> <title> [detail]
  if [ "$1" -eq 0 ]; then pass "$2" "${3:-}"; else fail "$2" "${3:-}"; fi
}
# call <namespace> <pod> <url>: the HTTP code, or failed(<curl exit>); 7 refused, 28 timed out, 52/56 reset
call() {
  local out rc
  out=$(k -n "$1" exec "$2" -- curl -sS -m 5 -o /dev/null -w '%{http_code}' "$3" 2>/dev/null); rc=$?
  if [ $rc -eq 0 ]; then echo "$out"; else echo "failed($rc)"; fi
}

nodes=$(k get nodes -o name | wc -l | tr -d ' ')
server=$(k version -o json | python3 -c 'import sys,json;print(json.load(sys.stdin)["serverVersion"]["gitVersion"])')
istio=$(k -n "$MESH_NS" get deploy istiod -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null)
say "# The ambient mesh on the demonstrator cluster ($started)" ''
say "Commit \`$commit\`, tree dirty: $dirty. Context \`$CONTEXT\`, Kubernetes $server, $nodes node(s)." ''
say "Zone file \`${ZONE_VALUES#"$REPO"/}\` (mesh.mode ambient, cni.derogation calico-ambient, trust domain \`$TD\`). istiod image \`${istio:-not found}\`." ''
say "Stand-in images \`$AGNHOST\` and \`$CURL\`. Call results: an HTTP code, or failed(<curl exit>)." ''

say '## 1. Control plane' ''
k -n "$MESH_NS" rollout status deploy/istiod --timeout=60s >/dev/null 2>&1
check $? "istiod is available" "$istio"
for ds in istio-cni-node ztunnel; do
  got=$(k -n "$MESH_NS" get ds "$ds" -o jsonpath='{.status.desiredNumberScheduled}/{.status.numberReady}' 2>/dev/null)
  [ "$got" = "$nodes/$nodes" ]; check $? "$ds ready on every node" "desired/ready $got of $nodes node(s)"
done

say '' '## 2. Stand-ins and their probes' ''
if k get namespace "$PLAIN" >/dev/null 2>&1; then
  fail "the throwaway namespace $PLAIN exists already (left by an earlier run, or someone else's): delete it, then rerun"
fi
k create namespace "$PLAIN" >/dev/null 2>&1 || fail "the throwaway namespace $PLAIN could not be created"
CREATED_PLAIN=true
server_pod() { # server_pod <namespace> <name> <matrix label>
  cat <<YAML
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: $2, namespace: $1, labels: {ztd.facis.io/proof: ambient-mesh, ztd.facis.io/proof-run: $RUN}}
---
apiVersion: v1
kind: Pod
metadata:
  name: $2
  namespace: $1
  labels: {ztd.facis.io/proof: ambient-mesh, ztd.facis.io/proof-run: $RUN, app.kubernetes.io/name: $3, proof-pod: $2}
spec:
  serviceAccountName: $2
  containers:
    - name: server
      image: $AGNHOST
      args: [netexec, --http-port=8080]
      ports: [{containerPort: 8080}]
      readinessProbe: {httpGet: {path: /hostname, port: 8080}, periodSeconds: 5}
---
apiVersion: v1
kind: Service
metadata: {name: $2, namespace: $1, labels: {ztd.facis.io/proof: ambient-mesh, ztd.facis.io/proof-run: $RUN}}
spec:
  selector: {proof-pod: $2}
  ports: [{port: 8080, targetPort: 8080}]
YAML
}
client_pod() { # client_pod <namespace> <name> <labels as a flow map>
  cat <<YAML
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: $2, namespace: $1, labels: {ztd.facis.io/proof: ambient-mesh, ztd.facis.io/proof-run: $RUN}}
---
apiVersion: v1
kind: Pod
metadata:
  name: $2
  namespace: $1
  labels: {ztd.facis.io/proof: ambient-mesh, ztd.facis.io/proof-run: $RUN$3}
spec:
  serviceAccountName: $2
  containers:
    - name: client
      image: $CURL
      command: ["sleep", "3600"]
      readinessProbe: {exec: {command: ["true"]}, periodSeconds: 5}
YAML
}
collector_pod() { # collector_pod <namespace> <name>: serves the lane's port 4317 and the off-lane 8080
  cat <<YAML
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: $2, namespace: $1, labels: {ztd.facis.io/proof: ambient-mesh, ztd.facis.io/proof-run: $RUN}}
---
apiVersion: v1
kind: Pod
metadata:
  name: $2
  namespace: $1
  labels: {ztd.facis.io/proof: ambient-mesh, ztd.facis.io/proof-run: $RUN, app.kubernetes.io/name: otel-collector, proof-pod: $2}
spec:
  serviceAccountName: $2
  containers:
    - name: lane
      image: $AGNHOST
      args: [netexec, --http-port=4317, --udp-port=8081]
      ports: [{containerPort: 4317}]
      readinessProbe: {httpGet: {path: /hostname, port: 4317}, periodSeconds: 5}
    - name: off-lane
      image: $AGNHOST
      args: [netexec, --http-port=8080, --udp-port=8082]
      ports: [{containerPort: 8080}]
      readinessProbe: {httpGet: {path: /hostname, port: 8080}, periodSeconds: 5}
---
apiVersion: v1
kind: Service
metadata: {name: $2, namespace: $1, labels: {ztd.facis.io/proof: ambient-mesh, ztd.facis.io/proof-run: $RUN}}
spec:
  selector: {proof-pod: $2}
  ports: [{name: otlp, port: 4317, targetPort: 4317}, {name: other, port: 8080, targetPort: 8080}]
YAML
}
plain_lane() { # plain_lane <namespace> <target pod> <from namespace>: a stand-in NetworkPolicy, the network lane to one target
  cat <<YAML
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: proof-plain-lane, namespace: $1, labels: {ztd.facis.io/proof: ambient-mesh, ztd.facis.io/proof-run: $RUN}}
spec:
  podSelector: {matchLabels: {proof-pod: $2}}
  policyTypes: [Ingress]
  ingress: [{from: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: $3}}}], ports: [{port: 8080, protocol: TCP}]}]
YAML
}
{
  server_pod "$MGMT" proof-tsa tsa-policy-engine
  collector_pod "$MGMT" proof-otel-collector
  server_pod "$DATA" proof-data-target proof-data-target
  client_pod "$DATA" proof-pdp-adapter ', app.kubernetes.io/name: pdp-adapter'
  client_pod "$DATA" proof-data-plain ''
  client_pod "$PLAIN" proof-outsider ''
  plain_lane "$DATA" proof-data-target "$PLAIN"
} >"$work/standins.yaml"
# The ServiceAccounts first: a pod is refused while its ServiceAccount does not exist yet.
python3 - "$work/standins.yaml" "$work/accounts.yaml" "$work/workloads.yaml" <<'PY'
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
yaml.safe_dump_all([d for d in docs if d["kind"] == "ServiceAccount"], open(sys.argv[2], "w"))
yaml.safe_dump_all([d for d in docs if d["kind"] != "ServiceAccount"], open(sys.argv[3], "w"))
PY
{ k apply -f "$work/accounts.yaml" && k apply -f "$work/workloads.yaml"; } >/dev/null 2>"$work/apply.err" \
  || fail "the stand-ins could not be created" "$(head -3 "$work/apply.err")"
k -n "$MGMT" wait --for=condition=Ready pod/proof-tsa pod/proof-otel-collector --timeout="${TIMEOUT}s" >/dev/null 2>&1 \
  && k -n "$DATA" wait --for=condition=Ready pod/proof-data-target pod/proof-pdp-adapter pod/proof-data-plain --timeout="${TIMEOUT}s" >/dev/null 2>&1 \
  && k -n "$PLAIN" wait --for=condition=Ready pod/proof-outsider --timeout="${TIMEOUT}s" >/dev/null 2>&1
check $? "every stand-in is Ready: the HTTP readiness probes of the two servers pass under the default deny, and those of the collector stand-in" \
  "$(for ns in "$MGMT" "$DATA"; do k -n "$ns" get pods -l "$PROOF_LABEL" --no-headers 2>/dev/null; done | awk '{print $1, $2, $3}' | paste -sd';')"

say '' '## 3. Enrolment by ztunnel' ''
for ns in "$MGMT" "$DATA"; do
  got=$(k get namespace "$ns" -o jsonpath='{.metadata.labels.istio\.io/dataplane-mode}' 2>&1)
  [ "$got" = ambient ]; check $? "$ns carries istio.io/dataplane-mode=ambient, the label that enrols it and that the admission refusals of section 10 hang on" "${got:-no label}"
done
istioctl --context "$CONTEXT" ztunnel-config workloads -o json >"$work/workloads.json" 2>"$work/istioctl.err" \
  || fail "istioctl ztunnel-config workloads" "$(head -2 "$work/istioctl.err")"
protocol() { python3 - "$work/workloads.json" "$1" "$2" <<'PY'
import json, sys
ws = json.load(open(sys.argv[1]))
ws = ws if isinstance(ws, list) else ws.get("workloads", ws)
m = [w for w in ws if w.get("namespace") == sys.argv[2] and w.get("name") == sys.argv[3]]
print(m[0].get("protocol", "?") if m else "absent")
PY
}
for p in "$MGMT/proof-tsa" "$MGMT/proof-otel-collector" "$DATA/proof-data-target" "$DATA/proof-pdp-adapter" "$DATA/proof-data-plain"; do
  got=$(protocol "${p%/*}" "${p#*/}"); [ "$got" = HBONE ]; check $? "$p is enrolled: ztunnel lists it with protocol HBONE" "$got"
done
got=$(protocol "$PLAIN" proof-outsider); [ "$got" != HBONE ]; check $? "$PLAIN/proof-outsider is not enrolled (outside the mesh)" "$got"

say '' '## 4. An allowed call, over mTLS with istiod-issued identities' ''
since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
r=$(call "$DATA" proof-pdp-adapter "http://proof-tsa.$MGMT.svc:8080/hostname")
[ "$r" = 200 ]; check $? "pdp-adapter -> tsa-policy-engine (the allow-matrix lane pdp-adapter-to-tsa): allowed" "-> $r"
src="spiffe://$TD/ns/$DATA/sa/proof-pdp-adapter"; dst="spiffe://$TD/ns/$MGMT/sa/proof-tsa"
line=
for _ in 1 2 3 4 5 6; do
  line=$(k -n "$MESH_NS" logs -l app=ztunnel --since-time="$since" --tail=-1 --max-log-requests=20 2>/dev/null \
    | grep -F "src.identity=\"$src\"" | grep -F "dst.identity=\"$dst\"" | tail -1)
  [ -n "$line" ] && break; sleep 5
done
[ -n "$line" ]; check $? "ztunnel's access log shows the call between $src and $dst (istiod's CA, the zone's trust domain)" "${line:0:400}"
istioctl --context "$CONTEXT" ztunnel-config certificates -o json >"$work/certs.json" 2>/dev/null
grep -qF "$src" "$work/certs.json" && grep -qF "$dst" "$work/certs.json"
check $? "ztunnel holds a certificate for each of the two identities" "$(grep -oE "spiffe://$TD/ns/[a-z0-9-]+/sa/proof-[a-z-]+" "$work/certs.json" | sort -u | paste -sd' ')"

say '' '## 5. STRICT: plaintext is refused' ''
r=$(call "$DATA" proof-data-plain "http://proof-data-target.$DATA.svc:8080/hostname")
[ "$r" = 200 ]; check $? "control: an enrolled data-plane pod -> the data-plane target (intra-plane lane): allowed" "-> $r"
r=$(call "$PLAIN" proof-outsider "http://proof-data-target.$DATA.svc:8080/hostname")
[[ "$r" == failed* ]] && [ "$r" != "failed(28)" ]
check $? "a pod of the throwaway namespace outside the mesh -> the same target, in plaintext over a network lane the stand-in NetworkPolicy proof-plain-lane opens: refused by the target's ztunnel (a reset, not a timeout)" "-> $r"

say '' '## 6. A lane outside the allow matrix' ''
r=$(call "$DATA" proof-data-plain "http://proof-tsa.$MGMT.svc:8080/hostname")
[[ "$r" == failed* ]]; check $? "an unlabelled data-plane pod -> tsa-policy-engine (management): refused" "-> $r"

say '' "## 7. The ports of a lane that names them" ''
r=$(call "$DATA" proof-data-plain "http://proof-otel-collector.$MGMT.svc:4317/hostname")
[ "$r" = 200 ]; check $? "a data-plane pod -> the collector stand-in on 4317 (the lane workloads-to-otel-collector, ports 4317 and 4318): allowed" "-> $r"
since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
r=$(call "$DATA" proof-data-plain "http://proof-otel-collector.$MGMT.svc:8080/hostname")
[[ "$r" == failed* ]] && [ "$r" != "failed(28)" ]
check $? "the same pod -> the same stand-in on 8080, a port it serves outside the lane, through the lane's HBONE opening 15008: refused by the destination's ztunnel (a reset, not a timeout)" "-> $r"
line=
for _ in 1 2 3 4 5 6; do
  line=$(k -n "$MESH_NS" logs -l app=ztunnel --since-time="$since" --tail=-1 --max-log-requests=20 2>/dev/null \
    | grep -F "lane-ports-workloads-to-otel-collector" | tail -1)
  [ -n "$line" ] && break; sleep 5
done
[ -n "$line" ]; check $? "ztunnel's log names the lane-port policy lane-ports-workloads-to-otel-collector (zone-policy) as the refusal" "${line:0:400}"

say '' "## 8. istiod's validating webhook" ''
cat >"$work/invalid.yaml" <<YAML
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: {name: proof-invalid, namespace: $DATA}
spec:
  rules: [{to: [{operation: {ports: ["not-a-port"]}}]}]
YAML
out=$(k apply --dry-run=server -f "$work/invalid.yaml" 2>&1); rc=$?
if [ $rc -eq 0 ]; then
  fail "the invalid AuthorizationPolicy was admitted: istiod's webhook did not validate it" "$out"
elif grep -q 'failed calling webhook' <<<"$out"; then
  fail "the API server could not reach istiod's webhook: check the controlPlaneWebhooks opening (istiod :15017) and its fromPods in the zone file" "${out:0:400}"
fi
grep -q 'admission webhook "validation.istio.io" denied the request' <<<"$out" && grep -q 'bad port' <<<"$out"
check $? "a server-side dry run of an AuthorizationPolicy with an invalid port (valid for the CRD schema) is denied by istiod's webhook, which the API server reached through the 15017 opening" "${out:0:400}"

say '' '## 9. No injected proxy in the planes' ''
nosidecar() { # nosidecar <namespace> <container name> <metadata fields> [<spec fields>] [<container fields>], fields as flow-map fragments: the server-side dry run's output
  k apply --dry-run=server -f - 2>&1 <<YAML
apiVersion: v1
kind: Pod
metadata: {name: proof-no-sidecar, namespace: $1, $3}
spec: {${4:-}containers: [{name: $2, image: $CURL, command: ["sleep", "1"]${5:-}}]}
YAML
}
out=$(nosidecar "$DATA" c 'annotations: {inject.istio.io/templates: grpc-simple}')
grep -q 'no-sidecar-in-planes' <<<"$out" && grep -q 'denied' <<<"$out"
check $? "a server-side dry run of a data-plane pod that chooses its injection templates (grpc-simple) is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(nosidecar "$DATA" c 'labels: {sidecar.istio.io/inject: "true"}')
grep -q 'no-sidecar-in-planes' <<<"$out" && grep -q 'denied' <<<"$out"
check $? "a server-side dry run of a data-plane pod that asks for injection (sidecar.istio.io/inject: \"true\") is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(nosidecar "$DATA" c 'labels: {istio.io/rev: default}')
grep -q 'no-sidecar-in-planes' <<<"$out" && grep -q 'denied' <<<"$out" && grep -q 'may not carry an injected proxy' <<<"$out"
check $? "a server-side dry run of a data-plane pod labelled istio.io/rev=default, which istiod's injector injects, is denied by the admission policy no-sidecar-in-planes for the injected proxy it would carry" "${out:0:400}"
out=$(nosidecar "$DATA" c 'labels: {app: proof-plain}'); rc=$?
[ $rc -eq 0 ] && ! grep -q 'denied' <<<"$out"
check $? "a server-side dry run of a plain data-plane pod is admitted (the policy refuses proxies, not pods)" "${out:0:400}"
out=$(nosidecar "$MESH_NS" istio-proxy 'labels: {istio.io/rev: default, sidecar.istio.io/inject: "false"}'); rc=$?
[ $rc -eq 0 ] && ! grep -q 'denied' <<<"$out"
check $? "a server-side dry run of ztunnel's pod shape in $MESH_NS (a container istio-proxy, istio.io/rev=default, sidecar.istio.io/inject=false) is admitted: the policy spares the mesh's own pods" "${out:0:400}"

say '' '## 10. A pod in an enrolled namespace stays in the mesh' ''
out=$(nosidecar "$DATA" c 'labels: {istio.io/dataplane-mode: none}')
grep -q 'no-sidecar-in-planes' <<<"$out" && grep -q 'denied' <<<"$out" && grep -q 'may not opt out' <<<"$out"
check $? "a server-side dry run of a data-plane pod opted out of the mesh (istio.io/dataplane-mode=none) is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(nosidecar "$MGMT" c 'annotations: {ambient.istio.io/bypass-inbound-capture: "true"}')
grep -q 'no-sidecar-in-planes' <<<"$out" && grep -q 'denied' <<<"$out" && grep -q 'bypass-inbound-capture' <<<"$out"
check $? "a server-side dry run of a management-plane pod bypassing ztunnel's inbound capture (ambient.istio.io/bypass-inbound-capture) is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(nosidecar "$DATA" c 'labels: {app: proof-plain}' 'hostNetwork: true, ')
grep -q 'no-sidecar-in-planes' <<<"$out" && grep -q 'denied' <<<"$out" && grep -q 'host network' <<<"$out"
check $? "a server-side dry run of a data-plane pod on the host network (hostNetwork: true) is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(nosidecar "$MGMT" c 'labels: {app: proof-plain}' '' ', ports: [{containerPort: 8080, hostPort: 18080}]')
grep -q 'no-sidecar-in-planes' <<<"$out" && grep -q 'denied' <<<"$out" && grep -q 'host network' <<<"$out"
check $? "a server-side dry run of a management-plane pod with a hostPort is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
refused() { # refused <text>: $out is a denial by no-sidecar-in-planes whose message holds <text> (an ERE)
  grep -q 'no-sidecar-in-planes' <<<"$out" && grep -q 'denied' <<<"$out" && grep -qE "$1" <<<"$out"
}
PRIV='may not run a privileged container'; HOSTNS='may not share the node'; HOSTPATH='may not mount a hostPath volume'; CAPS='may not add the capability'
for ns in "$DATA" "$MGMT"; do
  out=$(nosidecar "$ns" c 'labels: {app: proof-plain}' 'hostPID: true, ' ', securityContext: {privileged: true}')
  refused "$PRIV|$HOSTNS"
  check $? "a server-side dry run of a pod in $ns with hostPID and a privileged container (it could nsenter the node's network namespace) is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
done
out=$(nosidecar "$MGMT" c 'labels: {app: proof-plain}' 'hostPID: true, ')
refused "$HOSTNS"; check $? "a server-side dry run of a management-plane pod with hostPID alone is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(nosidecar "$DATA" c 'labels: {app: proof-plain}' 'hostIPC: true, ')
refused "$HOSTNS"; check $? "a server-side dry run of a data-plane pod with hostIPC is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(nosidecar "$MGMT" c 'labels: {app: proof-plain}' 'volumes: [{name: host, hostPath: {path: /}}], ')
refused "$HOSTPATH"; check $? "a server-side dry run of a management-plane pod with only a hostPath volume (/) is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(nosidecar "$DATA" c 'labels: {app: proof-plain}' '' ', securityContext: {capabilities: {add: [NET_ADMIN]}}')
refused "$CAPS"; check $? "a server-side dry run of a data-plane pod adding NET_ADMIN (it could remove its own capture rules) is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(nosidecar "$DATA" c 'labels: {app: proof-plain}' "initContainers: [{name: i, image: $CURL, command: [\"true\"], securityContext: {capabilities: {add: [SYS_ADMIN]}}}], ")
refused "$CAPS"; check $? "a server-side dry run of a data-plane pod whose init container adds SYS_ADMIN is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(nosidecar "$DATA" c 'labels: {app: proof-plain}' '' ', securityContext: {capabilities: {add: [all]}}')
refused "$CAPS"; check $? "a server-side dry run of a data-plane pod adding the capability all, in lower case, is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(nosidecar "$MGMT" c 'labels: {app: proof-plain}' "initContainers: [{name: i, image: $CURL, command: [\"true\"], securityContext: {privileged: true}}], ")
refused "$PRIV"; check $? "a server-side dry run of a management-plane pod with a privileged init container is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(nosidecar "$MGMT" c 'labels: {app: proof-plain}' '' ', securityContext: {capabilities: {add: [SYS_MODULE]}}')
refused "$CAPS"; check $? "a server-side dry run of a management-plane pod adding SYS_MODULE (outside the Pod Security Standards baseline: it could load a kernel module) is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(nosidecar "$DATA" c 'labels: {app: proof-plain}' "initContainers: [{name: i, image: $CURL, command: [\"true\"], securityContext: {capabilities: {add: [cap_dac_read_search]}}}], ")
refused "$CAPS"; check $? "a server-side dry run of a data-plane pod whose init container adds cap_dac_read_search (outside baseline, in lower case with the CAP_ prefix) is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(nosidecar "$DATA" c 'labels: {app: proof-plain}' 'securityContext: {seccompProfile: {type: RuntimeDefault}}, ' ', securityContext: {capabilities: {add: [chown, CAP_NET_BIND_SERVICE]}}'); rc=$?
[ $rc -eq 0 ] && ! grep -q 'denied' <<<"$out"
check $? "a server-side dry run of a data-plane pod adding the baseline capabilities chown and CAP_NET_BIND_SERVICE, with seccomp RuntimeDefault, is admitted (the control)" "${out:0:400}"
out=$(nosidecar "$DATA" c 'labels: {app: proof-plain}' 'securityContext: {seccompProfile: {type: Unconfined}}, ')
refused 'may not run without a seccomp profile'; check $? "a server-side dry run of a data-plane pod with seccomp Unconfined is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(nosidecar "$MGMT" c 'labels: {app: proof-plain}' '' ', securityContext: {appArmorProfile: {type: Unconfined}}')
refused 'may not run without an AppArmor profile'; check $? "a server-side dry run of a management-plane pod with AppArmor Unconfined is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(nosidecar "$DATA" c 'labels: {app: proof-plain}' 'hostUsers: false, ' ', securityContext: {procMount: Unmasked}')
refused 'may not unmask /proc'; check $? "a server-side dry run of a data-plane pod with procMount Unmasked is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(nosidecar "$DATA" c 'labels: {app: proof-plain}' 'hostNetwork: true, ' ', securityContext: {windowsOptions: {hostProcess: true}}')
refused 'may not run a Windows host process'; check $? "a server-side dry run of a data-plane pod with a Windows hostProcess container (which the API admits only with hostNetwork) is denied by the admission policy no-sidecar-in-planes for the host process" "${out:0:400}"
out=$(nosidecar "$MGMT" c 'labels: {app: proof-plain}' '' ', securityContext: {seLinuxOptions: {type: spc_t}}')
refused 'may not set an SELinux type'; check $? "a server-side dry run of a management-plane pod with SELinux type spc_t is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(nosidecar "$DATA" c 'labels: {app: proof-plain}' "securityContext: {sysctls: [{name: net.ipv4.ip_forward, value: '1'}]}, ")
refused 'may not set a sysctl'; check $? "a server-side dry run of a data-plane pod setting the unsafe sysctl net.ipv4.ip_forward is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(nosidecar "$MGMT" c 'labels: {app: proof-plain}' '' ', readinessProbe: {httpGet: {host: 192.0.2.1, port: 8080}}')
refused 'may not name a host in a probe'; check $? "a server-side dry run of a management-plane pod whose readiness probe names a host (the kubelet would call it from the node's network namespace) is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"

# The other write paths of a pod, on the running data-plane stand-in: pods/status (which can change
# labels and annotations) and pods/ephemeralcontainers (kubectl debug). Dry runs: nothing is changed.
status() { k -n "$1" patch pod "$2" --subresource=status --type=merge -p "$3" --dry-run=server 2>&1; }
ephemeral() { k -n "$DATA" patch pod proof-data-plain --subresource=ephemeralcontainers --type=strategic --dry-run=server 2>&1 \
  -p "{\"spec\":{\"ephemeralContainers\":[{\"name\":\"$1\",\"image\":\"$CURL\",\"command\":[\"sleep\",\"1\"]$2}]}}"; }
out=$(status "$DATA" proof-data-plain '{"metadata":{"labels":{"istio.io/dataplane-mode":"none"}}}')
refused 'may not opt out'; check $? "a server-side dry run of the opt-out label istio.io/dataplane-mode=none written to the running data-plane stand-in through pods/status is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(status "$DATA" proof-data-plain '{"metadata":{"annotations":{"ambient.istio.io/bypass-inbound-capture":"true"}}}')
refused 'bypass-inbound-capture'; check $? "a server-side dry run of the annotation ambient.istio.io/bypass-inbound-capture written to the same stand-in through pods/status is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(status "$DATA" proof-data-plain "{\"metadata\":{\"labels\":{\"ztd.facis.io/proof-status\":\"$RUN\"}}}"); rc=$?
[ $rc -eq 0 ] && ! grep -q 'denied' <<<"$out"
check $? "a server-side dry run of a plain label written to the same stand-in through pods/status is admitted (the control)" "${out:0:400}"
out=$(ephemeral proof-debug ',"securityContext":{"privileged":true}')
refused "$PRIV"; check $? "a server-side dry run of a privileged ephemeral container added to the same stand-in (pods/ephemeralcontainers) is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(ephemeral proof-debug ',"securityContext":{"capabilities":{"add":["SYS_PTRACE"]}}')
refused "$CAPS"; check $? "a server-side dry run of an ephemeral container adding SYS_PTRACE (kubectl debug --profile=general) added to the same stand-in is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(ephemeral istio-proxy '')
refused 'may not carry a proxy container'; check $? "a server-side dry run of an ephemeral container named istio-proxy added to the same stand-in is denied by the admission policy no-sidecar-in-planes" "${out:0:400}"
out=$(ephemeral proof-debug ''); rc=$?
[ $rc -eq 0 ] && ! grep -q 'denied' <<<"$out"
check $? "a server-side dry run of a plain ephemeral container added to the same stand-in is admitted (the control)" "${out:0:400}"

# The mesh root namespace is not enrolled: a host-network pod there, and copies of the mesh's own
# live pod templates, are admitted.
out=$(nosidecar "$MESH_NS" c 'labels: {app: proof-plain}' 'hostNetwork: true, '); rc=$?
[ $rc -eq 0 ] && ! grep -q 'denied' <<<"$out"
check $? "a server-side dry run of a host-network pod in $MESH_NS (not enrolled) is admitted" "${out:0:400}"
shape() { # shape <kind/name>: a Pod of that workload's pod template in the mesh root namespace
  k -n "$MESH_NS" get "$1" -o json | python3 -c '
import json, sys
w = json.load(sys.stdin); t = w["spec"]["template"]
print(json.dumps({"apiVersion": "v1", "kind": "Pod", "spec": t["spec"], "metadata": {
    "name": "proof-shape-" + w["metadata"]["name"], "namespace": w["metadata"]["namespace"],
    "labels": t["metadata"].get("labels", {}), "annotations": t["metadata"].get("annotations", {})}}))'
}
for w in deploy/istiod ds/istio-cni-node ds/ztunnel; do
  out=$(shape "$w" | k create --dry-run=server -f - 2>&1); rc=$?
  [ $rc -eq 0 ] && ! grep -q 'denied' <<<"$out"
  check $? "a server-side dry run of a copy of $w's live pod template in $MESH_NS (not enrolled) is admitted" "${out:0:400}"
done
zt=$(k -n "$MESH_NS" get pod -l app=ztunnel -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
out=$(status "$MESH_NS" "${zt:-ztunnel}" "{\"metadata\":{\"labels\":{\"ztd.facis.io/proof-status\":\"$RUN\"}}}"); rc=$?
[ -n "$zt" ] && [ $rc -eq 0 ] && ! grep -q 'denied' <<<"$out"
check $? "a server-side dry run of a status update of the live ztunnel pod $zt is admitted (the policy also sees pods/status, and spares the mesh's own pods)" "${out:0:400}"

finish 0
