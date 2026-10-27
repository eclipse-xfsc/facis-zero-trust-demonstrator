#!/usr/bin/env bash
# Evidence that the observability stack collects, carries, stores and alerts as specified, on the
# local kind cluster (both roles in one cluster: the kind zone of deployment/helm/ztd/ci/values.yaml
# and the demonstrator role of ci/demonstrator-values.yaml) or on a participant zone together with the
# demonstrator cluster. Expects both roles installed with scripts/install-zone/install.sh (see
# README.md next to this file); installs only its own fixtures (fixtures/), and removes them at the end.
# It stops and restores components of the zone to inject failures (the SPIRE server, one agent, one
# node collector, the zone gateway's egress, the status list, the entry); every change is undone on
# exit, interrupted or not.
#
# Checks, each named by what it proves:
#   pod-logs-collected          a pod's log lines, JSON and plain text, reach the entry with zone,
#                               namespace, pod and container; a node collector runs on every node the
#                               SPIRE agents run on
#   if01-fields-kept            an IF-01 event keeps correlation_id, run_id and seq as fields
#   spire-agents-scraped        every SPIRE agent is scraped, labelled with its node and zone
#   agents-stay-on-loopback     the agents answer their metrics only on 127.0.0.1:9988
#   spire-server-scraped        the SPIRE server and the controller-manager are scraped
#   spire-lane-is-narrow        from the gateway's pods, 9988 and 8082 answer, the registration port not
#   workload-otlp-accepted      a data-plane workload's OTLP is accepted on 4317/4318, another port not
#   correlated-trace            one trace holds the proxy's span and the echo's child span
#   revocation-probe-reports    the probe reports the status list up, and down when it stops
#   export-buffered-while-down  telemetry of a 60 s outage of the entry arrives afterwards; a full
#                               queue counts what it refuses and no workload restarts
#   unknown-client-refused      the entry refuses no certificate, a foreign CA, another zone's
#                               certificate and TLS 1.2
#   zone-taken-from-listener    data that claims another zone is stored under the listener's zone
#   other-egress-refused        the gateway's pods reach the entry and no other external address
#   no-route-into-zone          the demonstrator side cannot open a connection to a zone gateway or a
#                               node collector
#   query-surfaces-not-public   only the entry's listeners can be published; the query surfaces are
#                               ClusterIP Services
#   prometheus-scrapes-no-zone  the central Prometheus has no scrape target in a zone
#   gateway-holds-svid          the zone gateway is registered with SPIRE and its proxy holds an SVID
#   metrics-survive-restart     samples stored before a Prometheus restart are still there after it
#   missing-target-alerts       the SPIRE server, then one agent, stop: an alert within 30 s, resolved
#   vanished-agent-alerts       a node collector stops with its agent's series: an alert within 30 s
#   silent-zone-alerts          the gateway's egress is cut: a silent-zone alert within 30 s, resolved
#   revocation-endpoint-alerts  the status list stops: an alert within 30 s, resolved
#   no-private-key-in-records   no private-key material in the rendered manifests or the record
#   logs-queryable              PENDING: the log store is an open point of the design; never faked
#
# Writes evidence.md and record.json to a run directory outside the repository and prints it last.
# The record names the clusters, the transport in use (telemetryExport.entry.transport) and the
# measured detection time of each alert; a detection over 30 s fails its check.
#
# Usage:
#   scripts/verify-observability/verify.sh           run the proof
#   scripts/verify-observability/verify.sh --help    this text
#
# Exit status: 0 every check passed (pending checks are listed, not counted); 1-124 the number of
# failed checks; 125 refused or not run.
#
# Environment:
#   KUBE_CONTEXT          kind mode: the kind context holding both roles (default kind-ztd)
#   ZONE_CONTEXT, DEMONSTRATOR_CONTEXT
#                         zone mode: a participant zone and the demonstrator cluster; needs
#                         ZTD_CONFIRM_CLUSTER=<zone context>,<demonstrator context>, typed for the run
#   ZONE_VALUES           the zone's file (default: ci/values.yaml on kind)
#   DEMONSTRATOR_VALUES   the demonstrator's file (default: ci/demonstrator-values.yaml on kind,
#                         zones/ionos.yaml otherwise)
#   ECHO_IMAGE            the trace-echo image the fixtures run (default ztd-proof/trace-echo:dev,
#                         built from deployment/docker/trace-echo and loaded into kind)
#   VERIFY_INJECT_FAULT   spire-lane-is-narrow | other-egress-refused: open the path that check must
#                         find closed, so that it fails (proof that the check can fail)
#   ZTD_EVIDENCE_DIR      the run directory (default ~/.local/state/ztd/verify-observability/<context>/<UTC>)
# shellcheck disable=SC2016,SC2317,SC2015,SC2129
set -uo pipefail
usage() { sed -n '2,/^# shellcheck disable=SC2016,SC2317,SC2015,SC2129$/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }
case $# in
  0) ;;
  1) case $1 in -h|--help) usage; exit 0;; esac; usage >&2; exit 125;;
  *) usage >&2; exit 125;;
esac
[ -n "${ZONE_VALUES:-}" ] && ZONE_VALUES=$(realpath -m -- "$ZONE_VALUES")
[ -n "${DEMONSTRATOR_VALUES:-}" ] && DEMONSTRATOR_VALUES=$(realpath -m -- "$DEMONSTRATOR_VALUES")
[ -n "${ZTD_EVIDENCE_DIR:-}" ] && ZTD_EVIDENCE_DIR=$(realpath -m -- "$ZTD_EVIDENCE_DIR")
cd "$(dirname "$0")" || exit 125
HERE=$(pwd)
REPO=$(git rev-parse --show-toplevel)
CHART=$REPO/deployment/helm/ztd
refuse() { echo "verify-observability: refusing: $*" >&2; exit 125; }

if [ -n "${ZONE_CONTEXT:-}${DEMONSTRATOR_CONTEXT:-}" ]; then
  MODE=zone
  [ -n "${ZONE_CONTEXT:-}" ] && [ -n "${DEMONSTRATOR_CONTEXT:-}" ] || refuse "zone mode needs ZONE_CONTEXT and DEMONSTRATOR_CONTEXT"
  [ "${ZTD_CONFIRM_CLUSTER:-}" = "$ZONE_CONTEXT,$DEMONSTRATOR_CONTEXT" ] \
    || refuse "zone mode stops and restores components of $ZONE_CONTEXT: set ZTD_CONFIRM_CLUSTER=$ZONE_CONTEXT,$DEMONSTRATOR_CONTEXT"
  ZCTX=$ZONE_CONTEXT; DCTX=$DEMONSTRATOR_CONTEXT
  [ -n "${ZONE_VALUES:-}" ] || refuse "zone mode needs ZONE_VALUES"
  DEMONSTRATOR_VALUES=${DEMONSTRATOR_VALUES:-$CHART/zones/ionos.yaml}
else
  MODE=kind
  ZCTX=${KUBE_CONTEXT:-kind-ztd}; DCTX=$ZCTX
  case $ZCTX in kind-?*) ;; *) refuse "context $ZCTX is not a kind cluster (zone mode: ZONE_CONTEXT and DEMONSTRATOR_CONTEXT)";; esac
  ZONE_VALUES=${ZONE_VALUES:-$CHART/ci/values.yaml}
  DEMONSTRATOR_VALUES=${DEMONSTRATOR_VALUES:-$CHART/ci/demonstrator-values.yaml}
fi
case ${VERIFY_INJECT_FAULT:-} in ''|spire-lane-is-narrow|other-egress-refused) ;; *) refuse "VERIFY_INJECT_FAULT=$VERIFY_INJECT_FAULT is not a fault this proof can inject";; esac
for tool in kubectl jq python3 curl openssl; do command -v "$tool" >/dev/null || refuse "missing tool: $tool"; done

kz() { kubectl --context "$ZCTX" "$@"; }
kd() { kubectl --context "$DCTX" "$@"; }
kz version --request-timeout=10s >/dev/null 2>&1 || refuse "the zone's cluster ($ZCTX) cannot be reached"
kd version --request-timeout=10s >/dev/null 2>&1 || refuse "the demonstrator cluster ($DCTX) cannot be reached"

# fact <file> <key>: one fact of a zone file over the umbrella's defaults.
fact() {
  python3 - "$CHART/values.yaml" "$1" "$2" <<'PY'
import sys, yaml, json
def merge(b, t):
    if isinstance(b, dict) and isinstance(t, dict):
        o = dict(b)
        for k, v in t.items():
            o[k] = merge(b[k], v) if k in b else v
        return o
    return t
d = merge(yaml.safe_load(open(sys.argv[1])) or {}, yaml.safe_load(open(sys.argv[2])) or {})
for k in sys.argv[3].split("."):
    d = d.get(k) if isinstance(d, dict) else None
print("" if d is None else (json.dumps(d) if isinstance(d, (dict, list)) else d))
PY
}
ZONE=$(fact "$ZONE_VALUES" zone.name)
NSM=$(fact "$ZONE_VALUES" planes.management.namespace)
NSD=$(fact "$ZONE_VALUES" planes.data.namespace)
NSB=$(fact "$DEMONSTRATOR_VALUES" observabilityBackends.namespace)
TRANSPORT=$(fact "$ZONE_VALUES" telemetryExport.entry.transport)
ZPORT=$(fact "$ZONE_VALUES" telemetryExport.entry.port)
SERVER_NAME=$(fact "$ZONE_VALUES" telemetryExport.entry.serverName)
ENTRY_HOST=$(fact "$ZONE_VALUES" telemetryExport.entry.inCluster.host)
[ -n "$ENTRY_HOST" ] || ENTRY_HOST=$(fact "$ZONE_VALUES" telemetryExport.entry.address | cut -d/ -f1)
OTHER_ZONE=$(python3 - "$(fact "$DEMONSTRATOR_VALUES" observabilityBackends.entry.zones)" "$ZONE" <<'PY'
import json, sys
others = [z for z in json.loads(sys.argv[1]) if z["name"] != sys.argv[2]]
print(f"{others[0]['name']}:{others[0]['port']}" if others else "")
PY
)
# The zone gateway's pods (the chart's selector labels; the proof's stand-in lacks `component`).
GW_PODS=app.kubernetes.io/instance=otel-gateway,component=standalone-collector
PIN_WANTED=$(fact "$ZONE_VALUES" openbao.pinToMeshNode)
# shellcheck source=../tools/pins.env disable=SC1091
. "$REPO/scripts/tools/pins.env"
CLIENT_IMAGE=$(fact "$CHART/values.yaml" verification.image)
ECHO_IMAGE=${ECHO_IMAGE:-ztd-proof/trace-echo:dev}
RUN_ID=obs-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM
NS_SCRATCH=ztd-obs-scratch

STARTED=$(date -u +%Y%m%dT%H%M%SZ)
EVIDENCE=${ZTD_EVIDENCE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/ztd/verify-observability/$ZCTX/$STARTED}
case $EVIDENCE/ in "$REPO"/*) refuse "the run directory $EVIDENCE is inside the repository";; esac
mkdir -p "$EVIDENCE" || refuse "cannot create $EVIDENCE"
work=$(umask 077; mktemp -d)
LOG=$EVIDENCE/run.log
: >"$LOG"
say() { printf '%s\n' "$*" | tee -a "$LOG"; }

# ---- results
declare -a NAMES STATUS DETAIL
FAILED=0
record() { # record <name> <passed|failed|pending> <detail>
  NAMES+=("$1"); STATUS+=("$2"); DETAIL+=("$3")
  [ "$2" = failed ] && FAILED=$((FAILED + 1))
  say "$(printf '%-28s %-8s %s' "$1" "$2" "$3")"
}
declare -A DETECT

# ---- restoration of everything the proof changes
RESTORE=()
pop_restore() { RESTORE=("${RESTORE[@]:0:${#RESTORE[@]}-1}"); }
restore_all() {
  local i
  for (( i=${#RESTORE[@]}-1; i>=0; i-- )); do eval "${RESTORE[$i]}" >>"$LOG" 2>&1 || true; done
  RESTORE=()
}
cleanup() {
  restore_all
  kz -n "$NSD" delete pod obs-client --ignore-not-found --wait=false >/dev/null 2>&1
  kz -n "$NSD" delete deploy,svc -l app.kubernetes.io/part-of=verify-observability --ignore-not-found --wait=false >/dev/null 2>&1
  kz -n "$NSM" delete pod obs-gateway-standin --ignore-not-found --wait=false >/dev/null 2>&1
  kz -n "$NSM" delete deploy,svc -l app.kubernetes.io/part-of=verify-observability --ignore-not-found --wait=false >/dev/null 2>&1
  kz -n "$NSM" delete configmap status-list-fixture --ignore-not-found >/dev/null 2>&1
  kd -n "$NSB" delete pod obs-demonstrator-probe --ignore-not-found --wait=false >/dev/null 2>&1
  kz delete namespace "$NS_SCRATCH" --ignore-not-found --wait=false >/dev/null 2>&1
  rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ---- fixtures
PIN=""
if [ "$PIN_WANTED" = true ]; then
  node=$(kz -n istio-system get pod -l app=istiod -o jsonpath='{.items[0].spec.nodeName}')
  PIN="nodeSelector: { kubernetes.io/hostname: $node }"
fi
fixture() { # fixture <file>: the fixture with its placeholders filled
  sed -e "s|\${NS_MGMT}|$NSM|g; s|\${NS_DATA}|$NSD|g; s|\${NS_BACKENDS}|$NSB|g; s|\${NS_SCRATCH}|$NS_SCRATCH|g" \
      -e "s|\${ECHO_IMAGE}|$ECHO_IMAGE|g; s|\${CLIENT_IMAGE}|$CLIENT_IMAGE|g; s|\${RUN_ID}|$RUN_ID|g; s|\${PIN}|$PIN|g" \
      "$HERE/fixtures/$1"
}
say "verify-observability $RUN_ID: mode $MODE, zone $ZONE on $ZCTX, demonstrator on $DCTX, transport $TRANSPORT"
jq -r '.output.statusListCredential' "$REPO/features/fixtures/xfsc/status/allow.json" >"$work/status-list.json"
kz -n "$NSM" create configmap status-list-fixture --from-file=status-list.json="$work/status-list.json" \
  --dry-run=client -o yaml | kz apply -f - >>"$LOG"
kz create namespace "$NS_SCRATCH" --dry-run=client -o yaml | kz apply -f - >>"$LOG"
for f in status-list.yaml trace-echo.yaml client.yaml gateway-standin.yaml node-address-probe.yaml; do
  fixture "$f" | kz apply -f - >>"$LOG" || { say "fixture $f could not be applied"; exit 125; }
done
fixture demonstrator-probe.yaml | kd apply -f - >>"$LOG"
kz -n "$NSM" rollout status deploy/status-list --timeout=180s >>"$LOG" 2>&1
kz -n "$NSD" rollout status deploy/trace-echo --timeout=180s >>"$LOG" 2>&1
for p in "$NSD/obs-client" "$NSM/obs-gateway-standin" "$NS_SCRATCH/obs-node-address-probe"; do
  kz -n "${p%/*}" wait --for=condition=Ready "pod/${p#*/}" --timeout=180s >>"$LOG" 2>&1 || { say "fixture $p not Ready"; exit 125; }
done
kd -n "$NSB" wait --for=condition=Ready pod/obs-demonstrator-probe --timeout=180s >>"$LOG" 2>&1 || { say "the demonstrator probe is not Ready"; exit 125; }

# ---- helpers: queries from the demonstrator side, requests from the zone side
probe() { kd -n "$NSB" exec obs-demonstrator-probe -- "$@"; }
client() { kz -n "$NSD" exec -i obs-client -c client -- "$@"; }
standin() { kz -n "$NSM" exec -i obs-gateway-standin -c client -- "$@"; }
pq() { probe curl -s --max-time 10 --get --data-urlencode "query=$1" http://prometheus-server/api/v1/query; }
pqv() { pq "$1" | jq -r '.data.result[0].value[1] // empty'; }
jaeger_trace() { probe curl -s --max-time 10 "http://jaeger:16686/api/traces/$1"; }
am_alerts() { probe curl -s --max-time 10 'http://alertmanager:9093/api/v2/alerts?active=true&silenced=false&inhibited=false'; }
hex() { openssl rand -hex "$1"; }
now_ns() { date +%s%N; }
until_true() { # until_true <timeout-s> <command...>
  local deadline=$(( $(date +%s) + $1 )); shift
  while :; do "$@" >/dev/null 2>&1 && return 0; [ "$(date +%s)" -ge "$deadline" ] && return 1; sleep 2; done
}
span_json() { # span_json <trace id> <span id> <service> [zone claim]
  local t; t=$(now_ns)
  jq -nc --arg t "$1" --arg s "$2" --arg svc "$3" --arg z "${4:-}" --arg st "$t" --arg en "$((t + 1000000))" '
    {resourceSpans: [{resource: {attributes: ([{key: "service.name", value: {stringValue: $svc}}]
       + (if $z == "" then [] else [{key: "zone", value: {stringValue: $z}}] end))},
      scopeSpans: [{spans: [{traceId: $t, spanId: $s, name: "verify-observability", kind: 1,
        startTimeUnixNano: $st, endTimeUnixNano: $en,
        attributes: (if $z == "" then [] else [{key: "zone", value: {stringValue: $z}}] end)}]}]}]}'
}
post_otlp() { # post_otlp <signal> : body on stdin, from the data-plane client to the gateway; prints the HTTP code
  client curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H 'Content-Type: application/json' \
    --data-binary @- "http://otel-gateway.$NSM.svc.cluster.local:4318/v1/$1"
}
trace_has_zone() { # trace_has_zone <trace id> <zone>
  jaeger_trace "$1" | jq -e --arg z "$2" '[.data[0].processes[]?.tags[]? | select(.key == "zone") | .value] | length > 0 and all(. == $z)' >/dev/null
}

# wait_alert <timeout> <jq filter on one alert> <t0>: seconds from t0 until an active alert matches
# that started at or after t0 (an alert left over from an earlier failure never counts), or empty
wait_alert() {
  local t0=$3 deadline; deadline=$((t0 + $1))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if am_alerts | jq -e --argjson t0 "$t0" "[.[] | select($2) | select((.startsAt | sub(\"\\\\.[0-9]+Z\$\"; \"Z\") | fromdate) >= \$t0)] | length > 0" >/dev/null 2>&1; then
      echo $(( $(date +%s) - t0 )); return 0
    fi
    sleep 1
  done
  return 1
}
wait_resolved() { # wait_resolved <timeout> <jq filter>
  local deadline=$(( $(date +%s) + $1 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    am_alerts | jq -e "[.[] | select($2)] | length == 0" >/dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}
# alert_check <check> <label> <alert filter> <inject command> <restore command>: sets ALERT_T to the
# detection time and returns 0, or records the check as failed and returns 1. Never in a subshell.
ALERT_T=""
alert_check() {
  local name=$1 label=$2 filter=$3 inject=$4 restore=$5 t
  ALERT_T=""
  if ! wait_resolved 120 "$filter"; then record "$name" failed "$label: the alert was already active before the failure"; return 1; fi
  RESTORE+=("$restore")
  local at t0; at=$(date -u +%H:%M:%S); t0=$(date +%s)
  eval "$inject" >>"$LOG" 2>&1
  if t=$(wait_alert 60 "$filter" "$t0"); then
    DETECT["$name/$label"]="failure at $at, alert after ${t}s"
    eval "$restore" >>"$LOG" 2>&1; pop_restore
    if [ "$t" -gt 30 ]; then record "$name" failed "$label: alert after ${t}s, over 30 s"; return 1; fi
    if ! wait_resolved 180 "$filter"; then record "$name" failed "$label: alert after ${t}s, not resolved on recovery"; return 1; fi
    ALERT_T=$t; return 0
  fi
  DETECT["$name/$label"]="failure at $at, no alert within 60 s"
  eval "$restore" >>"$LOG" 2>&1; pop_restore
  record "$name" failed "$label: no alert within 60 s"; return 1
}

# Let the fixtures' first telemetry arrive.
sleep 20

# ---------------------------------------------------------------- collection
entry_log() { kd -n "$NSB" logs deploy/otel-entry --since=10m 2>/dev/null; }
# A debug-exporter record block that names the client pod and the marker.
log_record() { # log_record <marker>: the record block (resource and record) that holds the marker
  entry_log | python3 -c '
import sys, re
marker = sys.argv[1]
text = sys.stdin.read()
for block in text.split("ResourceLog #")[1:]:
    for rec in block.split("LogRecord #")[1:]:
        if marker in rec:
            print(block.split("ScopeLogs #")[0]); print(rec); sys.exit(0)
sys.exit(1)' "$1"
}
if until_true 90 log_record "plain text line $RUN_ID"; then
  plain=$(log_record "plain text line $RUN_ID")
  ok=true
  for want in "zone: Str($ZONE)" "k8s.namespace.name: Str($NSD)" "k8s.pod.name: Str(obs-client)" "k8s.container.name: Str(client)"; do
    grep -qF "$want" <<<"$plain" || ok=false
  done
  ds_desired=$(kz -n ztd-otel-node get ds otel-node-agent -o jsonpath='{.status.desiredNumberScheduled}')
  ds_ready=$(kz -n ztd-otel-node get ds otel-node-agent -o jsonpath='{.status.numberReady}')
  agents=$(kz -n spire-system get ds spire-agent -o jsonpath='{.status.desiredNumberScheduled}')
  [ "$ds_desired" = "$agents" ] && [ "$ds_ready" = "$ds_desired" ] || ok=false
  if $ok; then record pod-logs-collected passed "plain-text line of $NSD/obs-client at the entry with zone, namespace, pod and container; node collectors $ds_ready/$ds_desired, on every node of the $agents SPIRE agents"
  else record pod-logs-collected failed "record or node coverage incomplete (collectors $ds_ready/$ds_desired, agents $agents)"; fi
else record pod-logs-collected failed "the client pod's plain-text line did not reach the entry within 90 s"; fi

if if01=$(log_record "corr-$RUN_ID"); then
  ok=true
  for want in "correlation_id: Str(corr-$RUN_ID)" "run_id: Str($RUN_ID)" "seq: Double(1)" "ztd.if01: Bool(true)" "k8s.pod.name: Str(obs-client)"; do
    grep -qF "$want" <<<"$if01" || { ok=false; missing=$want; }
  done
  if $ok; then record if01-fields-kept passed "IF-01 event of obs-client kept correlation_id, run_id and seq as fields"
  else record if01-fields-kept failed "field missing: ${missing:-?}"; fi
else record if01-fields-kept failed "the IF-01 event did not reach the entry"; fi

agents_up=$(pq "up{job=\"spire-agent\",zone=\"$ZONE\"} == 1" | jq -r '[.data.result[].metric.node] | sort | join(",")')
agent_nodes=$(kz -n spire-system get pods -l app.kubernetes.io/name=agent -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}' | sort | paste -sd, -)
if [ -n "$agent_nodes" ] && [ "$agents_up" = "$agent_nodes" ]; then record spire-agents-scraped passed "up == 1 for the agent of every node ($agent_nodes), zone $ZONE"
else record spire-agents-scraped failed "agents scraped: '$agents_up', agents running on: '$agent_nodes'"; fi

node_ip=$(kz get node "${agent_nodes%%,*}" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
bind_ok=true; bind_detail=""
if [ "$MODE" = kind ]; then
  binds=$(docker exec "${agent_nodes%%,*}" sh -c 'cat /proc/net/tcp /proc/net/tcp6' 2>/dev/null \
    | awk 'NR>1 && $4=="0A" {print $2}' | grep -i ':2704$' | sort -u | paste -sd' ' -)
  # 0x2704 = 9988; 0100007F:2704 is 127.0.0.1:9988
  [ "$binds" = "0100007F:2704" ] || bind_ok=false
  bind_detail="listening sockets on 9988: $binds; "
fi
[ -n "$node_ip" ] || bind_ok=false
code=$(kz -n "$NS_SCRATCH" exec obs-node-address-probe -- curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$node_ip:9988/metrics" 2>/dev/null)
[ "$code" = 000 ] || bind_ok=false
if $bind_ok; then record agents-stay-on-loopback passed "${bind_detail}a pod asking $node_ip:9988 is refused"
else record agents-stay-on-loopback failed "${bind_detail}$node_ip:9988 answered HTTP $code"; fi

srv=$(pqv "max(last_over_time(up{job=\"spire-server\",zone=\"$ZONE\"}[30s]))")
cm=$(pqv "max(last_over_time(up{job=\"spire-controller-manager\",zone=\"$ZONE\"}[30s]))")
ns_srv=$(pqv "count(count by (__name__) ({__name__=~\"spire_server_.+\",zone=\"$ZONE\"}))")
ns_cr=$(pqv "count(count by (__name__) ({__name__=~\"controller_runtime_.+\",zone=\"$ZONE\"}))")
if [ "$srv" = 1 ] && [ "$cm" = 1 ] && [ "${ns_srv:-0}" -gt 0 ] && [ "${ns_cr:-0}" -gt 0 ]; then
  record spire-server-scraped passed "up == 1 for the server and the controller-manager; ${ns_srv} spire_server_ and ${ns_cr} controller_runtime_ series of $ZONE"
else record spire-server-scraped failed "server up=$srv controller-manager up=$cm spire_server_ series=$ns_srv controller_runtime_ series=$ns_cr"; fi

trust_domain=$(fact "$ZONE_VALUES" zone.trustDomain)
gw_id="spiffe://$trust_domain/ns/$NSM/sa/otel-gateway"
entry=$(kz -n spire-system exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server entry show -spiffeID "$gw_id" 2>/dev/null | sed -n 's/^Found \([0-9]*\) entr.*/\1/p')
gw_ready=$(kz -n "$NSM" get pod -l "$GW_PODS" -o json | jq -r '[.items[0].status.containerStatuses[]?, .items[0].status.initContainerStatuses[]? | select(.name == "istio-proxy" or .name == "opentelemetry-collector") | select(.ready)] | length')
if [ "${entry:-0}" -ge 1 ] && [ "$gw_ready" = 2 ]; then
  record gateway-holds-svid passed "the SPIRE server holds the entry $gw_id; the gateway's proxy and collector are ready (the proxy is ready only with its SVID)"
else record gateway-holds-svid failed "entries for $gw_id: ${entry:-0}; ready containers (proxy, collector): $gw_ready"; fi

# ---------------------------------------------------------------- declared lanes
server_ip=$(kz -n spire-system get pod spire-server-0 -o jsonpath='{.status.podIP}')
if [ "${VERIFY_INJECT_FAULT:-}" = spire-lane-is-narrow ]; then
  kz apply -f - >>"$LOG" <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: obs-injected-fault-egress, namespace: $NSM }
spec:
  podSelector: { matchLabels: { app.kubernetes.io/instance: otel-gateway } }
  policyTypes: [Egress]
  egress: [{ to: [{ namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: spire-system } } }], ports: [{ port: 8081 }] }]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: obs-injected-fault-ingress, namespace: spire-system }
spec:
  podSelector: { matchLabels: { app.kubernetes.io/name: server } }
  policyTypes: [Ingress]
  ingress: [{ from: [{ namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: $NSM } } }], ports: [{ port: 8081 }] }]
EOF
  RESTORE+=("kz -n $NSM delete networkpolicy obs-injected-fault-egress --ignore-not-found; kz -n spire-system delete networkpolicy obs-injected-fault-ingress --ignore-not-found")
  sleep 5
fi
c9988=$(standin curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$server_ip:9988/metrics")
c8082=$(standin curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$server_ip:8082/metrics")
# The registration port speaks TLS: reachable, the handshake completes (an HTTP answer and a TLS
# connect time); refused, neither. A bare TCP probe cannot tell an idle open connection from a dropped
# one, so the handshake is the test.
r8081=$(standin curl -sk -o /dev/null --max-time 8 -w '%{http_code} %{time_appconnect}' "https://$server_ip:8081/" </dev/null)
if [ "$c9988" = 200 ] && [ "$c8082" = 200 ] && [ "${r8081%% *}" = 000 ] && [ "${r8081#* }" = 0.000000 ]; then
  record spire-lane-is-narrow passed "from the gateway's pods: 9988 HTTP $c9988, 8082 HTTP $c8082, registration port 8081 refused (no TLS handshake)"
else record spire-lane-is-narrow failed "9988 HTTP $c9988, 8082 HTTP $c8082, 8081 answered (HTTP code and TLS connect time: $r8081)"; fi
[ "${VERIFY_INJECT_FAULT:-}" = spire-lane-is-narrow ] && restore_all

tid=$(hex 16)
c4318=$(span_json "$tid" "$(hex 8)" verify-observability | post_otlp traces)
# An empty OTLP/gRPC Export call (a gRPC frame of length 0) on 4317: the gateway answers grpc-status 0.
g4317=$(printf '\0\0\0\0\0' | client curl -s -o /dev/null -D - --max-time 10 --http2-prior-knowledge \
  -H 'content-type: application/grpc' -H 'te: trailers' --data-binary @- \
  "http://otel-gateway.$NSM.svc.cluster.local:4317/opentelemetry.proto.collector.trace.v1.TraceService/Export" \
  | tr -d '\r' | awk -F': ' 'tolower($1) == "grpc-status" {print $2}' | head -1)
gw_ip=$(kz -n "$NSM" get pod -l $GW_PODS -o jsonpath='{.items[0].status.podIP}')
if [ -n "$gw_ip" ]; then c13133=$(client curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$gw_ip:13133/"); else c13133=no-gateway-pod; fi
if [ "$c4318" = 200 ] && [ "$g4317" = 0 ] && until_true 60 trace_has_zone "$tid" "$ZONE" && [ "$c13133" = 000 ]; then
  record workload-otlp-accepted passed "from $NSD: OTLP/HTTP span on 4318 accepted (HTTP 200) and stored as trace $tid with zone $ZONE; OTLP/gRPC Export on 4317 answered grpc-status 0; the gateway's port 13133 refused"
else record workload-otlp-accepted failed "4318 HTTP $c4318, 4317 grpc-status '$g4317', trace $tid stored: $(trace_has_zone "$tid" "$ZONE" && echo yes || echo no), 13133 HTTP $c13133"; fi

# ---------------------------------------------------------------- traces through the mesh
tid=$(hex 16); psid=$(hex 8)
ecode=$(client curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "traceparent: 00-$tid-$psid-01" "http://trace-echo.$NSD.svc.cluster.local:8080/correlated")
correlated() {
  jaeger_trace "$tid" | jq -e '
    .data[0] as $t
    | ($t.spans | map({key: .spanID, value: .}) | from_entries) as $byId
    | [ $t.spans[] | select($t.processes[.processID].serviceName == "trace-echo")
        | (.references[]? | select(.refType == "CHILD_OF") | .spanID) as $p
        | $byId[$p] | select(. != null) | select($t.processes[.processID].serviceName != "trace-echo") ]
    | length > 0' >/dev/null
}
if [ "$ecode" = 200 ] && until_true 90 correlated; then
  services=$(jaeger_trace "$tid" | jq -r '[.data[0].processes[].serviceName] | unique | join(", ")')
  record correlated-trace passed "trace $tid holds the echo's span as the child of a proxy span (services: $services)"
else record correlated-trace failed "echo HTTP $ecode; trace $tid: $(jaeger_trace "$tid" | jq -c '[.data[0].processes[]?.serviceName]')"; fi

# ---------------------------------------------------------------- revocation probe
probe_up() { [ "$(pqv "max(last_over_time(httpcheck_status{zone=\"$ZONE\",http_status_class=\"2xx\"}[10s]))")" = 1 ] && [ -z "$(pqv "max(last_over_time(httpcheck_error{zone=\"$ZONE\"}[10s])) > 0")" ]; }
probe_down() { [ -n "$(pqv "max(last_over_time(httpcheck_error{zone=\"$ZONE\"}[10s])) > 0")" ] || [ "$(pqv "max(last_over_time(httpcheck_status{zone=\"$ZONE\",http_status_class=\"2xx\"}[10s]))")" = 0 ]; }
if until_true 60 probe_up; then
  RESTORE+=("kz -n $NSM scale deploy/status-list --replicas=1")
  kz -n "$NSM" scale deploy/status-list --replicas=0 >>"$LOG"; t0=$(date +%s)
  if until_true 40 probe_down; then t=$(( $(date +%s) - t0 ))
    kz -n "$NSM" scale deploy/status-list --replicas=1 >>"$LOG"; pop_restore
    kz -n "$NSM" rollout status deploy/status-list --timeout=120s >>"$LOG" 2>&1
    if until_true 60 probe_up; then record revocation-probe-reports passed "status list up, then down ${t}s after it stopped (probe every 5 s, seen at the backends), up again"
    else record revocation-probe-reports failed "down after ${t}s, not up again"; fi
  else record revocation-probe-reports failed "the stopped status list is not reported down within 40 s"; restore_all; fi
else record revocation-probe-reports failed "the status list is not reported up"; fi

# ---------------------------------------------------------------- buffering
entry_scale() { kd -n "$NSB" scale deploy/otel-entry --replicas="$1" >>"$LOG"; }
if [ "$MODE" = kind ] || [ "$DCTX" != "$ZCTX" ]; then
  RESTORE+=("kd -n $NSB scale deploy/otel-entry --replicas=1")
  entry_scale 0; kd -n "$NSB" wait --for=delete pod -l app.kubernetes.io/instance=otel-entry --timeout=60s >>"$LOG" 2>&1
  down_start=$(date +%s)
  tid=$(hex 16)
  bcode=$(span_json "$tid" "$(hex 8)" verify-observability-buffered | post_otlp traces)
  sleep $(( 60 - ($(date +%s) - down_start) ))
  down_end=$(date +%s)
  entry_scale 1; pop_restore
  kd -n "$NSB" rollout status deploy/otel-entry --timeout=120s >>"$LOG" 2>&1
  if until_true 120 trace_has_zone "$tid" "$ZONE"; then span_ok=yes; else span_ok=no; fi
  sleep 10
  samples=$(pqv "count_over_time(up{job=\"spire-server\",zone=\"$ZONE\"}[50s] @ $((down_end - 5)))")
  # Then a full queue: with the entry down again, more spans than the gateway's queue holds.
  restarts_before=$( (kz -n "$NSM" get pods -o json; kz -n "$NSD" get pods -o json; kz -n ztd-otel-node get pods -o json) | jq -s '[.[].items[].status.containerStatuses[]?.restartCount] | add')
  RESTORE+=("kd -n $NSB scale deploy/otel-entry --replicas=1")
  entry_scale 0; kd -n "$NSB" wait --for=delete pod -l app.kubernetes.io/instance=otel-entry --timeout=60s >>"$LOG" 2>&1
  gw_pod=$(kz -n "$NSM" get pod -l $GW_PODS -o jsonpath='{.items[0].metadata.name}')
  # The gateway's own metrics on its loopback, through a port-forward on a free local port.
  # kubectl itself in the background (not the kz function, whose subshell would outlive a kill).
  kubectl --context "$ZCTX" -n "$NSM" port-forward "pod/$gw_pod" :8888 >"$work/pf.log" 2>&1 & pf=$!
  RESTORE+=("kill $pf 2>/dev/null; wait $pf 2>/dev/null")
  pf_port=""
  for _ in $(seq 1 20); do
    pf_port=$(sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9]*\) .*/\1/p' "$work/pf.log" | head -1)
    [ -n "$pf_port" ] && break; sleep 1
  done
  cat "$work/pf.log" >>"$LOG"
  refused() { curl -sf --max-time 5 "http://127.0.0.1:$pf_port/metrics" | awk '/^otelcol_exporter_enqueue_failed_spans/ {s += $2} END {print s + 0}'; }
  metrics_read=no
  [ -n "$pf_port" ] && curl -sf --max-time 5 "http://127.0.0.1:$pf_port/metrics" >/dev/null && metrics_read=yes
  before=$(refused)
  python3 - "$work/flood.json" <<'PY'
import json, os, sys, time
t = time.time_ns()
spans = [{"traceId": os.urandom(16).hex(), "spanId": os.urandom(8).hex(), "name": "flood", "kind": 1,
          "startTimeUnixNano": str(t), "endTimeUnixNano": str(t + 1000)} for _ in range(5000)]
json.dump({"resourceSpans": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "verify-observability-flood"}}]},
           "scopeSpans": [{"spans": spans}]}]}, open(sys.argv[1], "w"))
PY
  codes=""
  for _ in $(seq 1 14); do codes="$codes $(post_otlp traces <"$work/flood.json")"; done
  sleep 3
  after=$(refused)
  after_read=no
  curl -sf --max-time 5 "http://127.0.0.1:$pf_port/metrics" >/dev/null && after_read=yes
  kill "$pf" 2>/dev/null; wait "$pf" 2>/dev/null; pop_restore
  entry_scale 1; pop_restore
  kd -n "$NSB" rollout status deploy/otel-entry --timeout=120s >>"$LOG" 2>&1
  restarts_after=$( (kz -n "$NSM" get pods -o json; kz -n "$NSD" get pods -o json; kz -n ztd-otel-node get pods -o json) | jq -s '[.[].items[].status.containerStatuses[]?.restartCount] | add')
  detail="span sent at the start of a 60 s outage (HTTP $bcode) stored afterwards: $span_ok; spire-server samples of the outage stored: ${samples:-0}; full queue: refused spans $before -> $after, the gateway's metrics read before/after: $metrics_read/$after_read (OTLP answers:$codes); container restarts $restarts_before -> $restarts_after"
  if [ "$bcode" = 200 ] && [ "$span_ok" = yes ] && [ "${samples:-0}" -ge 6 ] && [ "$metrics_read" = yes ] && [ "$after_read" = yes ] && [ "${after%.*}" -gt "${before%.*}" ] && [ "$restarts_before" = "$restarts_after" ]; then
    record export-buffered-while-down passed "$detail"
  else record export-buffered-while-down failed "$detail"; fi
fi

# ---------------------------------------------------------------- the entry: authentication and zone
tls_try() { # tls_try <extra curl args...>: curl's exit status of a TLS handshake with the entry
  standin curl -s -o /dev/null --max-time 10 --http2 --cacert /etc/ztd-telemetry/ca.crt \
    --connect-to "$SERVER_NAME:$ZPORT:$ENTRY_HOST:$ZPORT" "https://$SERVER_NAME:$ZPORT/" "$@" </dev/null
  echo $?
}
ok_cert=$(tls_try --cert /etc/ztd-telemetry/tls.crt --key /etc/ztd-telemetry/tls.key)
no_cert=$(tls_try)
tls12=$(tls_try --cert /etc/ztd-telemetry/tls.crt --key /etc/ztd-telemetry/tls.key --tls-max 1.2)
# A certificate of a CA the telemetry CA did not issue: throwaway test material, made here and removed.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj "/CN=$ZONE" \
  -keyout "$work/foreign.key" -out "$work/foreign.crt" >/dev/null 2>&1
standin sh -c 'umask 077; cat > /tmp/foreign.pem' < <(cat "$work/foreign.crt" "$work/foreign.key")
rm -f "$work/foreign.key"
foreign=$(tls_try --cert /tmp/foreign.pem)
standin rm -f /tmp/foreign.pem
other=skipped
if [ -n "$OTHER_ZONE" ] && [ "$MODE" = kind ]; then
  oz=${OTHER_ZONE%%:*}
  # The other zone's certificate, from its Secret on the demonstrator side, straight into the stand-in.
  standin sh -c 'umask 077; cat > /tmp/other.pem' < <(kd -n "$NSB" get secret "ztd-telemetry-client-$oz" -o json | jq -r '.data["tls.crt"], .data["tls.key"]' | base64 -d)
  other=$(tls_try --cert /tmp/other.pem)
  standin rm -f /tmp/other.pem
fi
# 0: handshake done (any HTTP answer); 35/56: refused in the handshake.
refused_code() { [ "$1" != 0 ] && [ "$1" != 28 ] && [ "$1" != 7 ]; }
if [ "$ok_cert" = 0 ] && refused_code "$no_cert" && refused_code "$foreign" && refused_code "$tls12" && { [ "$other" = skipped ] || refused_code "$other"; }; then
  record unknown-client-refused passed "listener $ZPORT: own certificate accepted; refused (curl exit): no certificate $no_cert, foreign CA $foreign, ${OTHER_ZONE:+certificate of ${OTHER_ZONE%%:*} $other, }TLS 1.2 $tls12"
else record unknown-client-refused failed "own certificate $ok_cert, no certificate $no_cert, foreign CA $foreign, other zone $other, TLS 1.2 $tls12"; fi

claim=$( [ "$ZONE" = zone-b ] && echo zone-a || echo zone-b )
tid=$(hex 16)
tcode=$(span_json "$tid" "$(hex 8)" verify-observability-claim "$claim" | post_otlp traces)
mcode=$(jq -nc --arg z "$claim" --arg r "$RUN_ID" --arg t "$(now_ns)" '{resourceMetrics: [{resource: {attributes: [{key: "service.name", value: {stringValue: "verify-observability-claim"}}, {key: "zone", value: {stringValue: $z}}]}, scopeMetrics: [{metrics: [{name: "ztd_proof_zone_claim", gauge: {dataPoints: [{asDouble: 1, timeUnixNano: $t, attributes: [{key: "zone", value: {stringValue: $z}}, {key: "run_id", value: {stringValue: $r}}]}]}}]}]}]}' | post_otlp metrics)
stored_zone() { pq "ztd_proof_zone_claim{run_id=\"$RUN_ID\"}" | jq -r '[.data.result[].metric.zone] | unique | join(",")'; }
for _ in $(seq 1 30); do [ -n "$(stored_zone)" ] && break; sleep 2; done
szone=$(stored_zone)
if [ "$tcode" = 200 ] && [ "$mcode" = 200 ] && [ "$szone" = "$ZONE" ] && until_true 60 trace_has_zone "$tid" "$ZONE"; then
  record zone-taken-from-listener passed "a metric and a span claiming zone=$claim were stored with zone=$ZONE only"
else record zone-taken-from-listener failed "metric stored with zone '$szone', span zone $(jaeger_trace "$tid" | jq -c '[.data[0].processes[]?.tags[]? | select(.key=="zone") | .value]')"; fi

# ---------------------------------------------------------------- egress, reverse direction, exposure
if [ "${VERIFY_INJECT_FAULT:-}" = other-egress-refused ]; then
  kz apply -f - >>"$LOG" <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: obs-injected-fault-world, namespace: $NSM }
spec:
  podSelector: { matchLabels: { app.kubernetes.io/instance: otel-gateway } }
  policyTypes: [Egress]
  egress: [{ to: [{ ipBlock: { cidr: 0.0.0.0/0 } }] }]
EOF
  RESTORE+=("kz -n $NSM delete networkpolicy obs-injected-fault-world --ignore-not-found")
  sleep 5
fi
world=$(standin curl -sk -o /dev/null -w '%{http_code}' --max-time 8 https://1.1.1.1/)
[ "${VERIFY_INJECT_FAULT:-}" = other-egress-refused ] && restore_all
if [ "$ok_cert" = 0 ] && [ "$world" = 000 ]; then
  record other-egress-refused passed "from the gateway's pods: the entry reached (handshake completed), https://1.1.1.1 refused"
else record other-egress-refused failed "entry handshake exit $ok_cert, https://1.1.1.1 HTTP $world"; fi

gw_ip=$(kz -n "$NSM" get pod -l "$GW_PODS" -o jsonpath='{.items[0].status.podIP}')
[ -n "$gw_ip" ] && [ -n "$node_ip" ] || { gw_ip=missing; node_ip=missing; }
rev_gw=$(probe curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$gw_ip:4318/v1/traces")
rev_node=$(probe curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$node_ip:13133/")
ctrl=$(probe curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://prometheus-server/-/ready)
if [ "$rev_gw" = 000 ] && [ "$rev_node" = 000 ] && [ "$ctrl" = 200 ]; then
  record no-route-into-zone passed "from $NSB: the zone gateway ($gw_ip:4318) and a node collector ($node_ip:13133) refused; Prometheus reached (control)"
else record no-route-into-zone failed "gateway HTTP $rev_gw, node collector HTTP $rev_node, control HTTP $ctrl"; fi

svc=$(kd -n "$NSB" get svc -o json | jq -c '[.items[] | {name: .metadata.name, type: .spec.type, ports: [.spec.ports[].port]}]')
entry_ports=$(python3 -c 'import json,sys; print(",".join(str(z["port"]) for z in json.loads(sys.argv[1])))' "$(fact "$DEMONSTRATOR_VALUES" observabilityBackends.entry.zones)")
if jq -e --arg ports "$entry_ports" '
     (map(select(.type != "ClusterIP" and .name != "otel-entry")) | length == 0)
     and (map(select(.name == "otel-entry"))[0].ports | map(tostring) | sort == ($ports | split(",") | sort))
     and (map(select(.name | test("^(prometheus-server|alertmanager|jaeger)$"))) | all(.type == "ClusterIP"))' <<<"$svc" >/dev/null; then
  record query-surfaces-not-public passed "only otel-entry may be published, on its listeners ($entry_ports); Prometheus, Alertmanager and Jaeger are ClusterIP"
else record query-surfaces-not-public failed "$svc"; fi

# ---------------------------------------------------------------- alerts
f_server=".labels.alertname == \"SpireServerDown\" and .labels.zone == \"$ZONE\""
if alert_check missing-target-alerts spire-server "$f_server" \
      "kz -n spire-system scale statefulset spire-server --replicas=0" \
      "kz -n spire-system scale statefulset spire-server --replicas=1; kz -n spire-system rollout status statefulset/spire-server --timeout=180s"; then
  t1=$ALERT_T
  agent_node=${agent_nodes%%,*}
  f_agent=".labels.alertname == \"SpireAgentDown\" and .labels.zone == \"$ZONE\" and .labels.node == \"$agent_node\""
  if alert_check missing-target-alerts "spire-agent on $agent_node" "$f_agent" \
        "kz -n spire-system patch ds spire-agent --type=merge -p '{\"spec\":{\"template\":{\"spec\":{\"nodeSelector\":{\"ztd.facis.io/verify-observability\":\"no-agent\"}}}}}'" \
        "kz -n spire-system patch ds spire-agent --type=json -p '[{\"op\":\"remove\",\"path\":\"/spec/template/spec/nodeSelector/ztd.facis.io~1verify-observability\"}]'; kz -n spire-system rollout status ds/spire-agent --timeout=180s"; then
    t2=$ALERT_T
    record missing-target-alerts passed "SpireServerDown for $ZONE after ${t1}s, SpireAgentDown for $ZONE node $agent_node after ${t2}s; both resolved on recovery"
  fi
fi

f_vanish=".labels.alertname == \"SpireAgentsMissing\" and .labels.zone == \"$ZONE\""
if alert_check vanished-agent-alerts "node collector on ${agent_nodes%%,*}" "$f_vanish" \
      "kz -n ztd-otel-node patch ds otel-node-agent --type=merge -p '{\"spec\":{\"template\":{\"spec\":{\"nodeSelector\":{\"ztd.facis.io/verify-observability\":\"no-collector\"}}}}}'" \
      "kz -n ztd-otel-node patch ds otel-node-agent --type=json -p '[{\"op\":\"remove\",\"path\":\"/spec/template/spec/nodeSelector/ztd.facis.io~1verify-observability\"}]'; kz -n ztd-otel-node rollout status ds/otel-node-agent --timeout=180s"; then
  t=$ALERT_T
  record vanished-agent-alerts passed "SpireAgentsMissing for $ZONE after ${t}s; resolved on recovery"
fi

kz -n "$NSM" get networkpolicy allow-telemetry-export-egress -o json \
  | jq 'del(.metadata.resourceVersion, .metadata.uid, .metadata.creationTimestamp, .metadata.generation, .metadata.managedFields, .status)' >"$work/egress.json"
f_silent=".labels.alertname == \"ZoneSilent\" and .labels.zone == \"$ZONE\""
if alert_check silent-zone-alerts "egress of $ZONE's gateway cut" "$f_silent" \
      "kz -n $NSM delete networkpolicy allow-telemetry-export-egress; kz -n $NSM delete pod -l $GW_PODS" \
      "kz create -f $work/egress.json; kz -n $NSM delete pod -l $GW_PODS; kz -n $NSM rollout status deploy/otel-gateway --timeout=180s"; then
  t=$ALERT_T
  record silent-zone-alerts passed "ZoneSilent for $ZONE after ${t}s; resolved when the egress returned"
fi

f_rev=".labels.alertname == \"RevocationEndpointDown\" and .labels.zone == \"$ZONE\""
if alert_check revocation-endpoint-alerts "status list stopped" "$f_rev" \
      "kz -n $NSM scale deploy/status-list --replicas=0" \
      "kz -n $NSM scale deploy/status-list --replicas=1; kz -n $NSM rollout status deploy/status-list --timeout=120s"; then
  t=$ALERT_T
  record revocation-endpoint-alerts passed "RevocationEndpointDown for $ZONE and its status-list URL after ${t}s; resolved when it answered again"
fi

# ---------------------------------------------------------------- no scrape into a zone
targets=$(probe curl -s --max-time 10 http://prometheus-server/api/v1/targets | jq -c '[.data.activeTargets[] | .scrapeUrl]')
if jq -e 'length > 0 and all(test("^https?://(localhost|127\\.0\\.0\\.1)(:|/)"))' <<<"$targets" >/dev/null; then
  record prometheus-scrapes-no-zone passed "Prometheus's only targets are its own ($targets); the zones' metrics arrive by remote write"
else record prometheus-scrapes-no-zone failed "targets: $targets"; fi

# ---------------------------------------------------------------- retention
mark=$(date +%s)
before=$(pqv "count_over_time(up{job=\"spire-server\",zone=\"$ZONE\"}[1m] @ $mark)")
kd -n "$NSB" delete pod -l app.kubernetes.io/name=prometheus,app.kubernetes.io/component=server --wait=true >>"$LOG" 2>&1
kd -n "$NSB" rollout status deploy/prometheus-server --timeout=180s >>"$LOG" 2>&1
prom_ready() { probe curl -sf http://prometheus-server/-/ready; }
until_true 120 prom_ready || true
after=$(pqv "count_over_time(up{job=\"spire-server\",zone=\"$ZONE\"}[1m] @ $mark)")
if [ -n "$before" ] && [ "${before:-0}" -gt 0 ] && [ "$after" = "$before" ]; then
  record metrics-survive-restart passed "$before samples of the minute before the restart, the same after it"
else record metrics-survive-restart failed "before $before, after $after"; fi

# ---------------------------------------------------------------- key material
mkdir -p "$EVIDENCE/render"
RENDER_DIR="$EVIDENCE/render/zone" ZONE_VALUES="$ZONE_VALUES" "$REPO/scripts/install-zone/install.sh" render >>"$LOG" 2>&1
RENDER_DIR="$EVIDENCE/render/demonstrator" ZONE_VALUES="$DEMONSTRATOR_VALUES" "$REPO/scripts/install-zone/install.sh" render >>"$LOG" 2>&1
# The log of the run holds the entry's debug output only through these checks' greps, never a key;
# the scan covers everything written to the run directory so far.
if hits=$(grep -rlE -- '-----BEGIN ([A-Z]+ )?PRIVATE KEY-----' "$EVIDENCE" 2>/dev/null) && [ -n "$hits" ]; then
  record no-private-key-in-records failed "private-key material in: $hits"
elif [ -z "$(ls -A "$EVIDENCE/render/zone" 2>/dev/null)" ] || [ -z "$(ls -A "$EVIDENCE/render/demonstrator" 2>/dev/null)" ]; then
  record no-private-key-in-records failed "the manifests of both roles could not be rendered into the record"
else
  record no-private-key-in-records passed "no private-key material in the rendered manifests of both roles ($(find "$EVIDENCE/render" -name '*.yaml' | wc -l) files) or the record"
fi

record logs-queryable pending "the log store is an open point of the design: the entry's log pipeline ends in its debug exporter, nothing stores or queries the records yet"

# ---------------------------------------------------------------- record
{
  echo "# Observability proof, $RUN_ID"
  echo
  echo "- Mode: $MODE"
  echo "- Zone: $ZONE on context \`$ZCTX\` ($(kz version -o json 2>/dev/null | jq -r .serverVersion.gitVersion))"
  echo "- Demonstrator: context \`$DCTX\` ($(kd version -o json 2>/dev/null | jq -r .serverVersion.gitVersion)), backends in \`$NSB\`"
  echo "- Transport in use: **$TRANSPORT** (telemetryExport.entry.transport), entry $ENTRY_HOST:$ZPORT"
  echo "- Started: $STARTED, finished: $(date -u +%Y%m%dT%H%M%SZ)"
  echo
  echo "| Check | Result | Detail |"
  echo "|---|---|---|"
  for i in "${!NAMES[@]}"; do echo "| \`${NAMES[$i]}\` | ${STATUS[$i]} | ${DETAIL[$i]//|/\\|} |"; done
  echo
  echo "## Detection times"
  echo
  echo "| Alert | Measured |"
  echo "|---|---|"
  for k in "${!DETECT[@]}"; do echo "| $k | ${DETECT[$k]} |"; done | sort
} >"$EVIDENCE/evidence.md"
{
  for i in "${!NAMES[@]}"; do jq -nc --arg n "${NAMES[$i]}" --arg s "${STATUS[$i]}" --arg d "${DETAIL[$i]}" '{check: $n, result: $s, detail: $d}'; done
} | jq -s --arg run "$RUN_ID" --arg mode "$MODE" --arg zone "$ZONE" --arg zctx "$ZCTX" --arg dctx "$DCTX" --arg transport "$TRANSPORT" \
    --argjson detect "$(for k in "${!DETECT[@]}"; do jq -nc --arg k "$k" --arg v "${DETECT[$k]}" '{($k): $v}'; done | jq -s 'add // {}')" \
    '{run: $run, mode: $mode, zone: $zone, zoneContext: $zctx, demonstratorContext: $dctx, transport: $transport, detection: $detect, checks: .}' \
    >"$EVIDENCE/record.json"
say "failed: $FAILED"
echo "$EVIDENCE"
[ "$FAILED" -le 124 ] || FAILED=124
exit "$FAILED"
