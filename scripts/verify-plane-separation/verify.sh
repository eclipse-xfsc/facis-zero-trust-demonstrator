#!/usr/bin/env bash
# Executes the plane-separation allow matrix (docs/architecture.md section 6) against a zone that is
# already installed, on the local kind cluster (scripts/dev/kind-cilium-up.sh, then
# scripts/install-zone/install.sh) or on a participant cluster kept installed by
# scripts/verify-mesh-identity (ZTD_KEEP_ZONE). It installs, upgrades and uninstalls nothing.
#
# The rows come from the umbrella rendered with the zone file under test (its allowMatrix and the
# NetworkPolicy pair of each row) and from the allow matrix of section 6, read with the shared heading-based
# reader (scripts/lib/doc-table.sh); a row present in only one of them, or a verdict they disagree on, fails
# the run. Every row is probed from every namespace labelled ztd.facis.io/plane=data:
#   - ALLOW row: the row's legitimate caller (its labels and service account) is served over mutual TLS
#     with the destination's identity (the control channel is green); an impostor (the row's labels,
#     another service account) is refused by the mesh, with a denial line carrying both SPIFFE IDs; an
#     unlabelled caller (the row's service account, not its labels) is dropped by the network layer. The
#     export row (every identity of the namespace) is refused off its ports 4317 and 4318.
#   - DENY rows (TSPA, the SPIRE server) and the catch-all row (every Service with ready endpoints in a
#     management-plane namespace, the SPIRE namespace or the Istio namespace that no row names): a TCP
#     connection from a proxy-less pod to every port of every endpoint is dropped by the network layer. A
#     meshed destination is probed again behind a probe-scoped network opening (one NetworkPolicy pair
#     admitting one prober of this run to that destination on that port), where its proxy refuses the
#     prober; an unmeshed destination is recorded "mesh: n/a" (the destination has no proxy; only the SPIRE and
#     Istio control planes run without one, declared in docs/specifications.md). istiod's xDS
#     port 15012 is recorded open as a declared opening (proposed) and counts neither as a denial nor as a
#     green channel; any other istiod port answering fails the run.
#   - The control channels of the management side: every SPIRE agent attested to the server, every proxy of
#     the data-plane namespaces SYNCED with istiod.
# The other direction, management plane -> data plane (section 6's row management-to-data, DENY at both
# layers by the default deny alone), is probed from every namespace labelled management plane (with the SPIRE
# and Istio namespaces): a TCP connection from a proxy-less pod to every port of every endpoint of every
# Service with ready endpoints in a data-plane namespace is dropped by the network layer; behind a
# probe-scoped opening, a meshed destination's proxy refuses a meshed prober (403 RBAC and a denial line) and,
# from a namespace without injection, resets a plain-text caller (mutual TLS STRICT); a data-plane destination
# without a proxy fails the run (it has no mesh layer, and the admission policy should have refused it). A data-plane namespace
# that runs no meshed Service gets a stand-in destination (fixtures/data-target.yaml). The run also fails
# when the rendered umbrella or the cluster holds a rule that admits that direction at either layer.
# A port of a meshed destination that no Service exposes is probed the same way, in plain text behind an
# opening, in both directions.
# A destination the zone does not run is a stand-in from fixtures/ with exactly the row's labels and service
# account; every caller is a stand-in. The record says real or stand-in for each destination.
# Before any probe, the routing precondition of scripts/lib/probe.sh stops the run when Cilium would
# masquerade pod traffic between nodes. At the end every fixture and opening is removed (also from an
# EXIT/INT/TERM trap) and the run fails when one remains or when the zone's NetworkPolicies,
# CiliumNetworkPolicies, AuthorizationPolicies or the capture rule of its admission policy differ from
# the snapshot taken at the start.
#
# Writes evidence.md, matrix.csv and environment.json to a run directory outside the repository and prints
# that directory as its last line. Never run by CI.
#
# Usage:
#   scripts/verify-plane-separation/verify.sh          run the matrix against the installed zone
#   scripts/verify-plane-separation/verify.sh --help   this text; touches nothing
#
# Exit status:
#   0        every check passed (declared openings and n/a lines are recorded, not counted)
#   1-124    the number of failed checks (capped at 124); the record is written
#   125      refused or not run (an argument, CI, the context guard, a run directory inside the repository
#            that git does not ignore, a leftover object of an earlier run, an admission policy that
#            cannot be read or holds no capture validation): nothing written
#   130/143  interrupted (INT/TERM); fixtures and openings are removed, no record
#
# Environment:
#   KUBE_CONTEXT          kubectl context (default: kind-ztd): a kind cluster (kind-<name>, every node's
#                         provider ID kind://...), or zerotrust-a / zerotrust-b with ZTD_CONFIRM_CLUSTER set
#                         to the context name (the guard of scripts/lib/proof.sh); anything else exit 125
#   ZTD_CONFIRM_CLUSTER   on a participant cluster: the context name, typed for this run
#   ZONE_VALUES           zone file (default: deployment/helm/ztd/ci/values.yaml on kind,
#                         deployment/helm/ztd/zones/zone-<a|b>.yaml on zerotrust-<a|b>)
#   ZTD_EVIDENCE_DIR      the run directory: created if missing, refused inside the repository unless git
#                         ignores it (the BDD harness's bundles/). Default: a new directory per run,
#                         ${XDG_STATE_HOME:-$HOME/.local/state}/ztd/verify-plane-separation/<context>/<UTC start>/
#
# Every check is "<test>; check $? <title>": the status of the test is what the check records.
# shellcheck disable=SC2016,SC2181,SC2319
set -uo pipefail
PROOF_NAME=verify-plane-separation PROOF_KEEP_OPT_IN=0 PROOF_ALLOW_IGNORED_RUN_DIR=1
PROOF_OTHER_CONTEXT="the run creates its fixtures and probe-scoped openings in the zone"
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=scripts/lib/proof.sh
. "$HERE/../lib/proof.sh"
# shellcheck source=scripts/lib/probe.sh
. "$HERE/../lib/probe.sh"
# shellcheck source=scripts/lib/doc-table.sh
. "$HERE/../lib/doc-table.sh"
# shellcheck source=scripts/verify-plane-separation/plan.sh
. "$HERE/plan.sh"
PART_OF=app.kubernetes.io/part-of=verify-plane-separation

# doc_rows <document>: the rows of section 6's allow matrix, one TSV line each (from, ZT-55 role, verdict,
# the row name in backticks or empty), read with the heading-based reader of scripts/check-plane-separation.sh.
# Status 1 when the table or one of its columns cannot be found.
doc_rows() {
  local doc=$1 doc_status=0 line verdict name
  fail() { echo "$PROOF_NAME: $1" >&2; doc_status=1; }
  load "allow matrix" "Allow matrix" && column "allow matrix" "From" && c_from=$col \
    && column "allow matrix" "ZT-55 role" && c_role=$col && column "allow matrix" "Allowed" && c_verdict=$col || return 1
  for line in "${lines[@]}"; do
    split_row "$line"
    verdict=${cells[$c_verdict]//\*/}; verdict=${verdict%% *}
    name=$(grep -o '(`[a-z0-9-]*`)\|; `[a-z0-9-]*`)' <<<"${cells[$c_from]}" | tr -d '();` ' | head -1)
    printf '%s\t%s\t%s\t%s\n' "${cells[$c_from]}" "${cells[$c_role]}" "$verdict" "$name"
  done
  return $doc_status
}
# doc_reverse_rows <document>: the rows of section 6's management plane -> data plane table, one TSV line each
# (from, verdict, the row name in backticks or empty). Status 1 when the table or a column cannot be found.
doc_reverse_rows() {
  local doc=$1 doc_status=0 line verdict name
  fail() { echo "$PROOF_NAME: $1" >&2; doc_status=1; }
  load "management plane -> data plane table" "Management plane → data plane" && column "management plane -> data plane table" "From" && c_from=$col \
    && column "management plane -> data plane table" "Allowed" && c_verdict=$col || return 1
  for line in "${lines[@]}"; do
    split_row "$line"
    verdict=${cells[$c_verdict]//\*/}; verdict=${verdict%% *}
    name=$(grep -o '(`[a-z0-9-]*`)' <<<"${cells[$c_from]}" | tr -d '();` ' | head -1)
    printf '%s\t%s\t%s\n' "${cells[$c_from]}" "$verdict" "$name"
  done
  return $doc_status
}
# csv_field <text>: one quoted CSV field
csv_field() { local s=${1//\"/\"\"}; printf '"%s"' "${s//$'\n'/ }"; }
# probe_line <verdict pass|fail|declared|n/a> <row> <namespace> <probe> <caller> <destination> <port>
#   <expected> <outcome> <layer> <evidence> <real|stand-in>: one line of matrix.csv and of the record; pass
#   and fail are checks, declared and n/a are recorded only.
probe_line() {
  # A probe whose exec lost curl's output was run again (probe_exec, scripts/lib/probe.sh): its evidence
  # says so, with what each attempt that observed nothing returned.
  if [ -n "${PROBE_NOTES:-}" ] && [ -s "$PROBE_NOTES" ]; then
    local lost; lost=$(paste -sd';' "$PROBE_NOTES"); : >"$PROBE_NOTES"
    set -- "${@:1:10}" "${11}; the exec lost curl's output, so the probe was run again: $lost" "${@:12}"
  fi
  local v=$1 f out=""; shift
  for f in "$1" "${ROLE[$1]:-}" "${@:2}"; do out+="${out:+,}$(csv_field "$f")"; done
  printf '%s,%s\n' "$out" "$(csv_field "$v")" >>"$CSV"
  local text="$1 from $2: $3 ($4 -> $5${6:+:$6}), expected $7, read $8; layer $9"
  case $v in
    pass) check 0 "$text" "${10}";;
    fail) check 1 "$text" "${10}";;
    *) say "- ${v^^}: $text" "  ${10}";;
  esac
  # The matrix table's cells: per layer, what each probe read (n/a with its reason, the declared opening).
  local key="$1|$2" cell="$3, $5:${6:-any} ${8%% *}"
  [ "$v" = n/a ] && cell="n/a ($5${6:+:$6}): ${10}"
  [ "$v" = declared ] && cell="$5:$6 open, declared opening (proposed)"
  [ "$v" = fail ] && cell="**FAIL** $cell"
  case $9 in
    network*) NETSUM[$key]+="${NETSUM[$key]:+; }$cell";;
    mesh*) MESHSUM[$key]+="${MESHSUM[$key]:+; }$cell";;
    control*) CHAN[$key]+="${CHAN[$key]:+; }:$6 ${8%% *}${v/pass/}";;
  esac
  return 0
}

# network_layer <outcome> <evidence> <denial line>: sets v (pass or fail) and ev for a network-layer probe.
# A drop is a denial at the network layer: curl timed out (denied(28)) or its connection was reset
# (denied(56)), or a meshed caller's proxy gave up connecting ("503 ... reset reason: connection timeout").
# When Hubble is available on the caller's node (<evidence> from network_evidence then begins "Hubble
# drop:" or "no Hubble drop line read"), a drop counts only with the policy drop Hubble recorded for the
# flow: a timeout alone also follows from an address no pod holds any more, so it is no network denial
# then. Without Hubble the drop's class is the evidence. A refusal (denied(7), any other 503) means the connection reached the destination's host, so it counts
# only when Hubble recorded a policy drop for the flow. A denial line in the destination's proxy means the
# mesh refused the call, not the network: the probe fails. A served attempt (connected, or any other HTTP
# status) fails with evidence that says it was served; a failed probe (error) or an outcome of no other
# class fails saying so.
network_layer() {
  v=fail; ev=$2
  if [ -n "$3" ]; then ev="denial line found, so the mesh refused it, not the network: $3"; return 0; fi
  case $1 in
    # http() keeps 110 characters of the body, which cuts Istio's retried form ("... retried and the
    # latest reset reason: connection timeout") short, hence the prefix
    "denied(28)"|"denied(56)"|"503 "*"reset reason: connection tim"*)
      if [[ $2 == "no Hubble drop line read"* ]]; then
        ev="dropped, but Hubble, available on the caller's node, recorded no policy drop for the flow: a timeout or reset alone does not show that the network layer refused it (an address no pod holds any more also times out); $2"
      else v=pass; fi;;
    "denied(7)"|"503 "*)
      if [[ $2 == "Hubble drop:"* ]]; then v=pass
      else ev="refused, not dropped: without a Hubble drop line for the flow a refusal does not show that the network layer refused it; $2"; fi;;
    connected|[0-9][0-9][0-9]" "*|[0-9][0-9][0-9])
      ev="served: the attempt reached the destination and was answered ($1), so neither layer refused it";;
    error*) ev="the probe itself failed ($1), so it shows nothing about either layer";;
    *) ev="the outcome $1 is neither a drop nor a refusal, so it does not show a network-layer denial";;
  esac
  return 0
}
# plaintext_layer <outcome> <mutual TLS mode> <Hubble forwarded line> <Hubble available 1|0>: sets v and ev
# for a plain-text probe without identity behind a probe-scoped opening (the mesh layer of a caller
# without a proxy, or of a destination port no Service exposes). The destination's proxy refuses such a
# caller only under mutual TLS STRICT, by resetting the connection; the denial log records authorization
# refusals only, so no denial line names it. The reset counts when Hubble shows the request forwarded to
# the destination (so the network let it through), or, without Hubble, on its class and the mode in force.
plaintext_layer() {
  v=fail
  if [ "$2" != STRICT ]; then ev="the mutual TLS mode in force for the port is ${2:-unknown}, not STRICT, so the mesh does not refuse a caller without a certificate"; return 0; fi
  case $1 in
    "denied(56)"|"denied(52)")
      if [ -n "$3" ]; then v=pass; ev="the network let the request through (Hubble: $3) and the destination's proxy reset it: mutual TLS STRICT refuses a caller without a certificate"
      elif [ "$4" = 1 ]; then ev="reset, but Hubble shows no forwarded segment carrying the request, so the reset is not shown to be the destination proxy's"
      else v=pass; ev="reset by the destination (Hubble not available on the caller's node: the outcome's class behind the opening and the STRICT mode in force are the evidence)"; fi;;
    connected|[0-9][0-9][0-9]" "*|[0-9][0-9][0-9]) ev="served in plain text ($1): the destination's proxy did not refuse a caller without an identity";;
    "denied(28)") ev="timed out: the network dropped the probe despite the opening, so it never reached the destination's proxy";;
    *) ev="the outcome $1 is not the reset of mutual TLS STRICT";;
  esac
  return 0
}
# unmeshed_layer <plan key>: the verdict (v) and the reason (ev) of the mesh layer of a destination without a
# proxy. A management-plane destination (key destinations) is one of the identity and mesh control planes,
# which run without a proxy by design: n/a, declared in docs/specifications.md (ZT-55). A data-plane
# destination (key reverseDestinations) has no such exception: the admission policy's capture rule refuses a
# pod without a proxy in an injected plane namespace, and ZT-55 asks for the mesh layer as well, so a
# data-plane workload without a proxy fails the run.
unmeshed_layer() {
  if [ "$1" = reverseDestinations ]; then
    v=fail; ev="a data-plane workload without a proxy: it has no mesh layer, which ZT-55 requires, and the admission policy's capture rule should have kept it out of an injected plane namespace"
  else
    v=n/a; ev="mesh: n/a, the destination has no proxy (the SPIRE and Istio control planes are not meshed)"
  fi
  return 0
}
# run_id: the id of a run, the value of the label verify-plane-separation/run of its probers and openings:
# "r" and 8 hex digits. The letter keeps it a string in every YAML reader: 8 hex digits alone can read as
# an integer (12345678) or a float (34230e05), and the API server refuses a label that is not a string.
run_id() { printf 'r%s\n' "$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"; }
# Sourced by verify_test.sh for the functions above: nothing below runs then.
[[ ${BASH_SOURCE[0]} == "$0" ]] || return 0

usage() { sed -n '2,/^# Every check/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }
case $# in
  0) ;;
  1) case $1 in -h|--help) usage; exit 0;; esac; usage >&2; echo "$PROOF_NAME: unknown argument: $1" >&2; exit 125;;
  *) usage >&2; echo "$PROOF_NAME: takes no arguments" >&2; exit 125;;
esac
proof_refuse_ci
[ -n "${ZONE_VALUES:-}" ] && ZONE_VALUES=$(realpath -m -- "$ZONE_VALUES")
[ -n "${ZTD_EVIDENCE_DIR:-}" ] && ZTD_EVIDENCE_DIR=$(realpath -m -- "$ZTD_EVIDENCE_DIR")
cd "$HERE" || exit 125
REPO=$(git rev-parse --show-toplevel)
CHART=$REPO/deployment/helm/ztd
CONTEXT=${KUBE_CONTEXT:-kind-ztd}
# shellcheck disable=SC2034  # read by the guard
KEEP=0
proof_guard_context
proof_run_dir verify-plane-separation
ZONE_NAME=$(yaml_get "$ZONE_VALUES" zone name)
TD=$(yaml_get "$ZONE_VALUES" zone trustDomain)
MGMT=$(yaml_get "$CHART/values.yaml" planes management namespace)
DATA=$(yaml_get "$CHART/values.yaml" planes data namespace)
SPIRE_NS=spire-system; ISTIO_NS=istio-system
POLICY=proxy-takes-spire-socket
# A run that finds the capture validation of the admission policy missing (an earlier run of this script
# or of verify-mesh-identity killed while it was lifted) refuses to start, naming the restore: the snapshot
# would take the lifted policy for the zone's (capture_start_check, scripts/lib/probe.sh).
capture_start_check
# A run that finds a fixture or opening of an earlier run refuses to start: its own cleanup could not tell
# them apart, and the snapshot would include them.
left=$(k get pods,services,serviceaccounts,networkpolicies -A -l "$PART_OF" -o name 2>&1) \
  || { echo "$PROOF_NAME: cannot list the objects of an earlier run: $(head -1 <<<"$left")" >&2; exit 125; }
if [ -n "$left" ]; then
  echo "$PROOF_NAME: refusing to start: objects labelled $PART_OF remain from an earlier run: $(paste -sd' ' <<<"$left")" >&2
  exit 125
fi

work=$(mktemp -d)
PROBE_NOTES=$work/probe-notes; : >"$PROBE_NOTES"
OUT=$work/evidence.md; CSV=$work/matrix.csv
failures=0; cleaned=0; created=0
RUN=$(run_id)
declare -A ROLE=() NETSUM=() MESHSUM=() CHAN=() KIND=() CALLER=()
# cleanup: removes every object of the run by its label, the openings included, and puts the capture
# validation back; idempotent. Called at the end of a run (section 10) and from the EXIT trap. The wait
# for the deletions is bounded (--timeout), so a stalled API server cannot hold the run, and what remains
# is then named.
cleanup() {
  [ "$created" = 1 ] && [ "$cleaned" != 1 ] || return 0
  restore_capture
  k delete pods,services,networkpolicies -A -l "$PART_OF" --ignore-not-found --wait=true --timeout=180s >/dev/null 2>&1
  k --request-timeout=60s delete serviceaccounts -A -l "$PART_OF" --ignore-not-found >/dev/null 2>&1
  cleaned=1
}
# on_exit: the EXIT trap. INT and TERM are ignored from its first line on, by the trap and the kubectl
# it runs, so a second Ctrl-C during a slow cleanup neither stops the deletions nor skips the message
# that names what remains.
# shellcheck disable=SC2317  # called from the EXIT trap only
on_exit() {
  trap '' INT TERM
  local was=$cleaned
  cleanup
  if [ "$created" = 1 ] && [ "$was" != 1 ]; then
    left=$(k --request-timeout=60s get pods,services,serviceaccounts,networkpolicies -A -l "$PART_OF" -o name 2>&1) \
      || left="(they could not be listed: $(head -1 <<<"$left"))"
    [ -z "$left" ] || echo "$PROOF_NAME: objects of the run remain: $(paste -sd' ' <<<"$left")" >&2
    [ "$(policy_snapshot)" = "$(cat "$work/snapshot-before" 2>/dev/null)" ] \
      || echo "$PROOF_NAME: the zone's policies differ from the snapshot taken at the start" >&2
  fi
  rm -rf "$work"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
commit=$(git rev-parse HEAD)
dirty=false; [ -n "$(git status --porcelain)" ] && dirty=true
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
proof_run_dir_new
printf '%s\n' 'row,role,namespace,probe,caller,destination,port,expected,outcome,layer,evidence,kind,verdict' >"$CSV"

# policy_snapshot: every NetworkPolicy, CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy and
# AuthorizationPolicy of the cluster but the run's own (kind, namespace/name, UID, resourceVersion), and the
# spec of the admission policy whose capture rule the run lifts, by hash; sorted, one per line.
policy_snapshot() {
  local kind
  for kind in networkpolicies ciliumnetworkpolicies ciliumclusterwidenetworkpolicies authorizationpolicies.security.istio.io; do
    k get "$kind" -A -o json 2>/dev/null | jq -r --arg k "$kind" '.items[]
      | select((.metadata.labels // {})["app.kubernetes.io/part-of"] != "verify-plane-separation")
      | "\($k) \(.metadata.namespace // "-")/\(.metadata.name) \(.metadata.uid) \(.metadata.resourceVersion)"'
  done | sort
  printf 'validatingadmissionpolicy %s spec-sha256 %s\n' "$POLICY" \
    "$(k get validatingadmissionpolicy "$POLICY" -o json 2>/dev/null | jq -S .spec | sha256sum | cut -d' ' -f1)"
}
# spiffe <namespace> <service account>
spiffe() { echo "spiffe://$TD/ns/$1/sa/$2"; }
# hubble_ok <node>: status 0 when the Cilium agent of <node> answers hubble observe (cached per node)
declare -A HUBBLE=()
hubble_ok() {
  if [ -z "${HUBBLE[$1]:-}" ]; then
    local C; C=$(cilium_on "$1")
    if [ -n "$C" ] && k --request-timeout=30s -n kube-system exec "$C" -c cilium-agent -- timeout 20 hubble observe --last 1 -o compact >/dev/null 2>&1
    then HUBBLE[$1]=1; else HUBBLE[$1]=0; fi
  fi
  [ "${HUBBLE[$1]}" = 1 ]
}
# node_now <node>: the time on <node>'s Cilium agent (RFC 3339, UTC) when Hubble is available there, so
# that a drop is looked up from the start of its own probe, on the clock that stamped it; empty otherwise
node_now() {
  hubble_ok "$1" || return 0
  k --request-timeout=30s -n kube-system exec "$(cilium_on "$1")" -c cilium-agent -- date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null
}
# drop_flow <node> <ns/pod> <ip> <port> <since>: the first policy drop Hubble recorded on <node> from that
# pod to <ip>:<port> since <since> (node_now, taken just before the probe), one compact line; empty when
# none, when <since> is empty or when Hubble is not available. The drop of an earlier probe of the same
# address lies before <since>, so it is never cited.
drop_flow() {
  [ -n "${5:-}" ] && hubble_ok "$1" || return 0
  k --request-timeout=30s -n kube-system exec "$(cilium_on "$1")" -c cilium-agent -- timeout 20 \
    hubble observe --since "$5" --type drop --from-pod "$2" --to-ip "$3" --to-port "$4" -o compact 2>/dev/null | grep -v '^$' | head -1 | cut -c1-240
}
# forwarded_flow <node> <ns/pod> <ip> <port> <since>: the first segment carrying data (PSH) Hubble saw
# forwarded on <node> from that pod to <ip>:<port> since <since>; empty when none or without Hubble
forwarded_flow() {
  [ -n "${5:-}" ] && hubble_ok "$1" || return 0
  k --request-timeout=30s -n kube-system exec "$(cilium_on "$1")" -c cilium-agent -- timeout 20 \
    hubble observe --since "$5" --verdict FORWARDED --from-pod "$2" --to-ip "$3" --to-port "$4" -o compact 2>/dev/null | grep 'PSH' | head -1 | cut -c1-240
}
# network_evidence <caller node> <ns/pod> <ips> <port> <since> <what the denial log showed>: the drop Hubble
# read (to any of the space-separated <ips>, the pods behind a Service), or what the outcome rests on without one
network_evidence() {
  local f="" ip
  for ip in $3; do f=$(drop_flow "$1" "$2" "$ip" "$4" "$5"); [ -n "$f" ] && break; done
  if [ -n "$f" ]; then echo "Hubble drop: $f; $6"
  elif hubble_ok "$1"; then echo "no Hubble drop line read for the flow: the outcome rests on its class, and $6"
  else echo "Hubble not available on the node's Cilium agent: the outcome rests on its class, and $6"; fi
}
# denials_start <ns> <pod>...: the denial log of each pod's proxy so far ($work/den-0-<pod>)
denials_start() { local ns=$1 p; shift; for p in "$@"; do denial_lines "$ns" "$p" >"$work/den-0-$p"; done; }
# denials_new <ns> <pod>...: the denial lines every one of those proxies wrote since denials_start, so that a
# line written by whichever pod served the attempt is read
denials_new() { local ns=$1 p; shift; for p in "$@"; do new_denials "$work/den-0-$p" "$ns" "$p"; done; }
# probe_start <dest ns> <dest pods> <caller node>: taken just before a network-layer probe: the denial log
# so far of every destination pod (space-separated) and the caller node's clock (T0, for drop_flow)
probe_start() { local pods; read -ra pods <<<"$2"; denials_start "$1" "${pods[@]}"; T0=$(node_now "$3"); }
# probe_denial <dest ns> <dest pods> <source SPIFFE ID or empty>: after the probe (and the few seconds Envoy
# takes to flush its log), the first denial line one of the destination pods' proxies wrote since
# probe_start, of <source> when one is given (a proxy-less probe has no identity, so then any new line counts)
probe_denial() {
  local pods; read -ra pods <<<"$2"
  sleep 3
  if [ -n "$3" ]; then denials_new "$1" "${pods[@]}" | jq -c --arg s "$3" 'select(.source == $s)' | head -1
  else denials_new "$1" "${pods[@]}" | head -1; fi
}
# other_node <node>: an agent node other than <node> (the first in name order), or <node> when none
other_node() { local n; n=$(grep -vxF -- "$1" <<<"$AGENT_NODES" | head -1); echo "${n:-$1}"; }
# prober_on <prefix> <node> <ns>: the name of this run's prober of that kind on a node other than <node>
prober_on() { local i n=0 o; o=$(other_node "$2"); for i in $AGENT_NODES; do [ "$i" = "$o" ] && { echo "$1-$n"; return; }; n=$((n+1)); done; echo "$1-0"; }
# not_through <outcome>: the opening is not in force yet (the probe was dropped or refused short of the
# destination's proxy); the mesh-layer probe behind an opening retries while it holds
not_through() { case $1 in denied*|"503 upstream connect error"*) return 0;; *) return 1;; esac; }

: >"$OUT"
say "# Plane-separation reachability evidence ($started)" ''
if [ "$CLUSTER_KIND" = kind ]; then
  say "Cluster kind: **kind**, the local cluster from \`scripts/dev/kind-cilium-up.sh\` with Cilium chained." ''
else
  interim=""; [[ $TD == *.trust.invalid ]] && interim=" The trust domain \`$TD\` is **interim**: a zone on an interim name is not acceptance evidence."
  say "Cluster kind: **participant cluster** \`$CONTEXT\` (zone \`$ZONE_NAME\`), confirmed with \`ZTD_CONFIRM_CLUSTER=$CONTEXT\`.$interim Every IPv4 and IPv6 address of the cluster is replaced by \`<address>\` in this record." ''
fi
say "Cluster context \`$CONTEXT\`, zone file \`${ZONE_VALUES#"$REPO"/}\` (trust domain \`$TD\`), the zone already installed (the run installs and uninstalls nothing). Commit \`$commit\`, tree dirty: $dirty. Run id \`$RUN\`." ''
say 'Layers. **Network layer**: a drop (`denied(28)` or `denied(56)` from curl, or a meshed caller'"'"'s `503 ... reset reason: connection timeout`) and no new denial line in the destination'"'"'s proxy, with the drop Hubble recorded for the flow wherever the caller node'"'"'s Cilium agent offers Hubble (a timeout alone also follows from an address no pod holds any more); a refusal (`denied(7)`, any other `503`) counts only with the drop Hubble recorded for the flow, which is cited whenever the node'"'"'s Cilium agent offers it. **Mesh layer**: the destination'"'"'s proxy refused the caller'"'"'s identity under the mesh default deny (`403 RBAC: access denied` for HTTP) and wrote one denial line with both SPIFFE IDs. **Control channel**: the legitimate caller served over mutual TLS, the destination principal read from the caller'"'"'s proxy. **n/a**: a destination without a proxy has no mesh layer. **Declared**: istiod'"'"'s xDS port, open to the meshed plane namespaces under a declared opening (proposed; `docs/specifications.md`), recorded and not counted.' ''

# --------------------------------------------------------------------------------------------
section "0. Preconditions"
routing_precondition
if [ "$routing_ok" != 1 ]; then
  bad_nodes=$(grep -o '[^ ,:]* ([0-9./]*)' <<<"${routing[1]:-}" | paste -sd, -)
  say '' "**The routing check failed, so the run stops here, before any probe** (nodes: ${bad_nodes:-see above}). Nothing was created in the zone." ''
  echo "$PROOF_NAME: the routing precondition failed; no probe was run (nodes: ${bad_nodes:-see the record})" >&2
fi
if [ "$routing_ok" = 1 ]; then
AGENT_NODES=$(agent_nodes)
[ -n "$AGENT_NODES" ]; check $? "the SPIRE agent runs on at least one node, where the stand-ins are placed" "$(paste -sd' ' <<<"${AGENT_NODES:-none}")"
code "$(k get nodes -o wide | sed 's/  */ /g')"

# --------------------------------------------------------------------------------------------
section "1. The rows: the rendered umbrella against section 6"
helm template ztd "$CHART" -f "$ZONE_VALUES" >"$work/umbrella.yaml" 2>"$work/helm.err"
check $? "the umbrella renders with the zone file under test" "$(head -1 "$work/helm.err")"
plan_rows "$CHART/values.yaml" "$ZONE_VALUES" "$work/umbrella.yaml" >"$work/rows.json" 2>"$work/rows.err"
check $? "the allowMatrix rows are read from the zone document and the rendered NetworkPolicy pairs" "$(jq -r '[.[].name] | join(" ")' "$work/rows.json" 2>/dev/null || head -1 "$work/rows.err")"
doc_rows "$REPO/docs/architecture.md" >"$work/doc-rows.tsv"
check $? "section 6's allow matrix is read by heading (scripts/lib/doc-table.sh)" "$(grep -c . "$work/doc-rows.tsv") rows"
while IFS=$'\t' read -r frm role _ name; do
  key=$name
  if [[ $role == "any management-plane destination"* ]]; then key=catch-all
  elif [ -z "$key" ]; then key=${frm#*→ }; key=${key%% (*}; key=$(tr 'A-Z ' 'a-z-' <<<"$key"); fi
  ROLE[$key]=$role
done <"$work/doc-rows.tsv"
plan_crosscheck "$work/rows.json" "$work/doc-rows.tsv" "$HERE/fixtures" >"$work/cross.txt"
while read -r verdict text; do
  [ "$verdict" = OK ] && check 0 "the two row sources agree and every row has a probe" "$text"
  [ "$verdict" = FAIL ] && check 1 "$text"
done <"$work/cross.txt"
mapfile -t ROWS < <(jq -r '.[].name' "$work/rows.json")
# The management plane -> data plane direction: section 6's table against the row the verifier probes, and
# the rule that disposes it (DENY by the default deny alone) against what the umbrella renders.
doc_reverse_rows "$REPO/docs/architecture.md" >"$work/doc-reverse.tsv"
check $? "section 6's management plane -> data plane table is read by heading" "$(grep -c . "$work/doc-reverse.tsv") rows"
plan_reverse_crosscheck "$work/doc-reverse.tsv" >"$work/cross-reverse.txt"
while read -r verdict text; do
  [ "$verdict" = OK ] && check 0 "the management plane -> data plane direction: $text"
  [ "$verdict" = FAIL ] && check 1 "$text"
done <"$work/cross-reverse.txt"
ROLE[management-to-data]="any data-plane workload (from the management plane)"
python3 -c 'import json,sys,yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
json.dump({"items": [d for d in docs if d.get("kind") == "Namespace"]}, open(sys.argv[2], "w"))
json.dump({"items": [d for d in docs if d.get("kind") in ("NetworkPolicy", "CiliumNetworkPolicy", "CiliumClusterwideNetworkPolicy", "AuthorizationPolicy")]}, open(sys.argv[3], "w"))' \
  "$work/umbrella.yaml" "$work/render-ns.json" "$work/render-pol.json" 2>"$work/render.err"
plan_reverse_rule "$work/render-ns.json" "$work/render-pol.json" "$ISTIO_NS" >"$work/rule-render.txt"
while read -r verdict text; do
  [ "$verdict" = OK ] && check 0 "the rendered umbrella: $text" "the expected outcome of every management plane -> data plane probe is a denial at both layers"
  [ "$verdict" = FAIL ] && check 1 "the rendered umbrella holds an opening of the management plane -> data plane direction that section 6 does not dispose: $text"
done <"$work/rule-render.txt"
[ -s "$work/rule-render.txt" ] || check 1 "the rendered umbrella's policies are read for the management plane -> data plane rule" "$(head -1 "$work/render.err")"

# --------------------------------------------------------------------------------------------
section "2. Snapshot of the zone's policies"
policy_snapshot >"$work/snapshot-before"
say "$(grep -c . "$work/snapshot-before") policies and the admission policy's spec read (kind, name, UID, resourceVersion); compared at the end."
mapfile -t DATANS < <(k get ns -l ztd.facis.io/plane=data -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
[ ${#DATANS[@]} -gt 0 ]; check $? "the data-plane namespaces are found by their label ztd.facis.io/plane=data" "${DATANS[*]:-none}"
# The rule of the management plane -> data plane direction against the policies the cluster holds (every
# release's, the mesh's AuthorizationPolicies included), the run's own excluded
k get ns -o json >"$work/ns.json"
for kind in networkpolicies ciliumnetworkpolicies ciliumclusterwidenetworkpolicies authorizationpolicies.security.istio.io; do k get "$kind" -A -o json 2>/dev/null; done \
  | jq -s '{items: [.[].items[] | select((.metadata.labels // {})["app.kubernetes.io/part-of"] != "verify-plane-separation")]}' >"$work/cluster-pol.json"
plan_reverse_rule "$work/ns.json" "$work/cluster-pol.json" "$ISTIO_NS" >"$work/rule-cluster.txt"
while read -r verdict text; do
  [ "$verdict" = OK ] && check 0 "the cluster's policies: $text"
  [ "$verdict" = FAIL ] && check 1 "the cluster holds an opening of the management plane -> data plane direction that section 6 does not dispose: $text"
done <"$work/rule-cluster.txt"
[ -s "$work/rule-cluster.txt" ] || check 1 "the cluster's policies are read for the management plane -> data plane rule"

# --------------------------------------------------------------------------------------------
section "3. Destinations: real or stand-in"
created=1
: >"$work/destinations.yaml"
declare -A DEST_SVC=() DEST_SA=() DEST_NODE=() DEST_POD=() DEST_PODS=()
for r in "${ROWS[@]}"; do
  row=$(jq -c --arg r "$r" '.[] | select(.name == $r)' "$work/rows.json")
  to_ns=$(jq -r .toNs <<<"$row"); to_sa=$(jq -r .toServiceAccount <<<"$row")
  sel=$(jq -r '.toSelector | to_entries | map("\(.key)=\(.value)") | join(",")' <<<"$row")
  # every running replica: a denial line is read from whichever of them served the attempt
  realpods=$(k -n "$to_ns" get pods -l "$sel,app.kubernetes.io/part-of!=verify-plane-separation" -o json 2>/dev/null \
    | jq -r --arg sa "$to_sa" '[.items[] | select(.spec.serviceAccountName == $sa and .status.phase == "Running") | .metadata.name] | join(" ")')
  real=${realpods%% *}
  [ -f "fixtures/rows/$r.yaml" ] || { KIND[$r]=none; continue; }
  sed -e "s/__TO__/$to_ns/g" -e "s/__FROM__/$DATA/g" "fixtures/rows/$r.yaml" >"$work/row-$r.yaml"
  if [ -n "$real" ]; then
    KIND[$r]=real
    labels=$(k -n "$to_ns" get pod "$real" -o json | jq -c '.metadata.labels')
    svc=$(k -n "$to_ns" get svc -o json | jq -r --argjson l "$labels" '[.items[] | select((.spec.selector // {}) as $s | ($s | length) > 0 and ($s | to_entries | all(.value == $l[.key])))] | .[0].metadata.name // empty')
    [ -n "$svc" ]; check $? "row $r: the zone runs its destination ($to_ns/$real, service account $to_sa): probed as **real**, through its Service" "Service ${svc:-none selects it}"
    DEST_SVC[$r]=$svc; DEST_POD[$r]=$real; DEST_PODS[$r]=$realpods
  else
    KIND[$r]=stand-in
    DEST_SVC[$r]=$(python3 -c 'import sys,yaml
print(next(d["metadata"]["name"] for d in yaml.safe_load_all(open(sys.argv[1])) if d and d["kind"] == "Service"))' "$work/row-$r.yaml")
    DEST_POD[$r]=${DEST_SVC[$r]}; DEST_PODS[$r]=${DEST_SVC[$r]}
    say "- row $r: no pod matching the row's selector \`$sel\` under service account \`$to_sa\` runs in $to_ns: a **stand-in** from \`fixtures/rows/$r.yaml\`"
  fi
  DEST_SA[$r]=$to_sa
done
# The stand-in destinations of the rows the zone runs no destination for, and TSPA's when the zone runs
# none. A row with a real destination gets nothing applied.
standins=()
for r in "${ROWS[@]}"; do [ "${KIND[$r]:-}" = stand-in ] && standins+=("$r"); done
python3 - "$work" "${standins[@]}" >"$work/destinations.yaml" <<'PY'
import sys, yaml
work, rows = sys.argv[1], sys.argv[2:]
out = []
for r in rows:
    docs = [d for d in yaml.safe_load_all(open(f"{work}/row-{r}.yaml")) if d]
    to_ns = next(d["metadata"]["namespace"] for d in docs if (d["metadata"].get("annotations") or {}).get("verify-plane-separation/role") == "destination")
    out += [d for d in docs if d["metadata"]["namespace"] == to_ns]
print(yaml.safe_dump_all(out, sort_keys=False) if out else "")
PY
tspa_real=$(k -n "$MGMT" get pods -l 'app.kubernetes.io/name=tspa,app.kubernetes.io/part-of!=verify-plane-separation' -o name 2>/dev/null | head -1)
if [ -n "$tspa_real" ]; then KIND[tspa]=real; say "- TSPA: the zone runs it ($tspa_real): probed as **real**"
else KIND[tspa]=stand-in; say "- TSPA: the zone runs none: a **stand-in** from \`fixtures/tspa.yaml\`"
  { echo '---'; sed "s/__MGMT__/$MGMT/g" fixtures/tspa.yaml; } >>"$work/destinations.yaml"; fi
KIND[spire-server]=real
# A data-plane namespace that runs no meshed Service gets a stand-in destination for the management plane ->
# data plane direction, so that both layers are probed in it.
k get svc -A -o json >"$work/svc.json"; k get endpointslices -A -o json >"$work/eps.json"; k get pods -A -o json >"$work/pods.json"
plan_plan "$work/rows.json" "$work/doc-rows.tsv" "$work/ns.json" "$work/svc.json" "$work/eps.json" "$work/pods.json" "$SPIRE_NS" "$ISTIO_NS" >"$work/plan-0.json"
for ns in "${DATANS[@]}"; do
  if jq -e --arg ns "$ns" '[.reverseDestinations[] | select(.namespace == $ns and .meshed)] | length > 0' "$work/plan-0.json" >/dev/null; then
    say "- data plane $ns: runs a meshed Service, probed as **real** from the management plane"
  else
    say "- data plane $ns: runs no meshed Service: a **stand-in** from \`fixtures/data-target.yaml\` is probed from the management plane"
    { echo '---'; sed "s/__NS__/$ns/g" fixtures/data-target.yaml; } >>"$work/destinations.yaml"
  fi
done
cp "$work/destinations.yaml" "$work/destinations.apply.yaml"
# drop_existing <file>: the file without the objects the zone already has under the same name (any object
# not labelled as the run's), so that a run never applies over, and its cleanup never deletes, an object of
# the zone. A ServiceAccount found is used as found; any other object found fails the run, named, because
# its stand-in cannot be created beside it.
drop_existing() {
  local f=$1 found=() kind ns name l
  while read -r kind ns name; do
    [ -n "$name" ] || continue
    l=$(k -n "$ns" get "$kind" "$name" -o jsonpath='{.metadata.labels.app\.kubernetes\.io/part-of}' 2>/dev/null) || continue
    [ "$l" = verify-plane-separation ] && continue
    found+=("$kind/$ns/$name")
    [ "$kind" = ServiceAccount ] || check 1 "the stand-in $kind $ns/$name is not applied: the zone already has an object of that name (not the run's), which the run never changes"
  done < <(python3 -c 'import sys,yaml
for d in yaml.safe_load_all(open(sys.argv[1])):
    if d: print(d["kind"], d["metadata"]["namespace"], d["metadata"]["name"])' "$f")
  python3 - "$f" "${found[@]}" <<'PY'
import sys, yaml
f, existing = sys.argv[1], set(sys.argv[2:])
docs = [d for d in yaml.safe_load_all(open(f)) if d and f'{d["kind"]}/{d["metadata"]["namespace"]}/{d["metadata"]["name"]}' not in existing]
yaml.safe_dump_all(docs, open(f, "w"), sort_keys=False)
PY
}
drop_existing "$work/destinations.apply.yaml"
if grep -q 'kind:' "$work/destinations.apply.yaml"; then
  k apply -f "$work/destinations.apply.yaml" >/dev/null 2>"$work/dest.err"; check $? "the stand-in destinations are created" "$(head -1 "$work/dest.err")"
  for ns in $(python3 -c 'import sys,yaml
print(" ".join(sorted({d["metadata"]["namespace"] for d in yaml.safe_load_all(open(sys.argv[1])) if d and d["kind"] == "Pod"})))' "$work/destinations.apply.yaml"); do
    k -n "$ns" wait --for=condition=Ready pod -l "$PART_OF" --timeout=240s >/dev/null 2>&1
    check $? "the stand-in destinations in $ns are Ready"
  done
fi
for r in "${ROWS[@]}"; do
  to_ns=$(jq -r --arg r "$r" '.[] | select(.name == $r) | .toNs' "$work/rows.json")
  DEST_NODE[$r]=$(node_of "$to_ns" "${DEST_POD[$r]}")
done

# --------------------------------------------------------------------------------------------
section "4. The probe plan"
k get ns -o json >"$work/ns.json"; k get svc -A -o json >"$work/svc.json"
k get endpointslices -A -o json >"$work/eps.json"; k get pods -A -o json >"$work/pods.json"
plan_plan "$work/rows.json" "$work/doc-rows.tsv" "$work/ns.json" "$work/svc.json" "$work/eps.json" "$work/pods.json" "$SPIRE_NS" "$ISTIO_NS" >"$work/plan.json"
check $? "the probe plan is built from the zone's namespaces, Services, EndpointSlices and pods"
say "Data-plane namespaces: $(jq -r '.dataNamespaces | join(", ")' "$work/plan.json"). Management-plane namespaces searched for destinations: $(jq -r '.managementNamespaces | join(", ")' "$work/plan.json")." ''
say "Destinations of the DENY and catch-all rows (every Service with ready endpoints in those namespaces that no allowMatrix row names):" ''
code "$(jq -r '.destinations[] | "\(.row)\t\(.namespace)/\(.service)\t\(if .standIn then "stand-in" else "real" end)\t\(if .meshed then "meshed" else "no proxy" end)\tports \([.targets[].port] | unique | map(tostring) | join(","))"' "$work/plan.json" | command column -t -s $'\t')"
say "Management components section 6 names by example and the zone does not run (reported absent): $(jq -r '.absentExamples | join(", ") | if . == "" then "none" else . end' "$work/plan.json")." ''
mapfile -t SRCNS < <(jq -r '.sourceNamespaces[]' "$work/plan.json")
mapfile -t INJECTED < <(jq -r '.injectedNamespaces[]' "$work/plan.json")
[ ${#SRCNS[@]} -gt 0 ]; check $? "the management-plane namespaces the management plane -> data plane direction is probed from are found" "${SRCNS[*]:-none}; with injection: ${INJECTED[*]:-none}"
say "Destinations of the management plane -> data plane direction (every Service with ready endpoints in a data-plane namespace):" ''
code "$(jq -r '.reverseDestinations[] | "\(.row)\t\(.namespace)/\(.service)\t\(if .standIn then "stand-in" else "real" end)\t\(if .meshed then "meshed" else "no proxy" end)\tports \([.targets[].port] | unique | map(tostring) | join(","))"' "$work/plan.json" | command column -t -s $'\t')"
jq -e '.reverseDestinations | length > 0' "$work/plan.json" >/dev/null; check $? "the management plane -> data plane direction has a destination in the data plane" "$(jq '.reverseDestinations | length' "$work/plan.json") Service(s)"
k get peerauthentications.security.istio.io -A -o json >"$work/pa.json" 2>/dev/null || echo '{"items": []}' >"$work/pa.json"

# --------------------------------------------------------------------------------------------
section "5. Callers and probers"
nodes_arr=()
while read -r n; do [ -n "$n" ] && nodes_arr+=("$n"); done <<<"$AGENT_NODES"
: >"$work/probers.yaml"
# The probers of both directions: in every data-plane namespace and in every management-plane namespace the
# management plane -> data plane direction is probed from. A namespace without injection gets the proxy-less
# probes only (a mesh prober there would have no proxy); its probes need no lift of the capture rule.
PROBENS=("${DATANS[@]}" "${SRCNS[@]}")
for ns in "${PROBENS[@]}"; do
  for i in "${!nodes_arr[@]}"; do
    { echo '---'; sed -e "s/__NS__/$ns/g" -e "s/__NODE__/${nodes_arr[$i]}/g" -e "s/__I__/$i/g" -e "s/__RUN__/$RUN/g" fixtures/probes.yaml; } >>"$work/probers.yaml"
  done
done
python3 - "$work/probers.yaml" "$work/meshed.yaml" "$work/proxyless.yaml" "$work/proxyless-check.yaml" "$work/plain.yaml" "${INJECTED[@]}" <<'PY'
import copy, sys, yaml
injected = set(sys.argv[6:])
docs, seen = [], set()
for d in yaml.safe_load_all(open(sys.argv[1])):
    if not d: continue
    key = (d["kind"], d["metadata"]["namespace"], d["metadata"]["name"])
    if key not in seen: seen.add(key); docs.append(d)
off = lambda d: (d["metadata"].get("annotations") or {}).get("sidecar.istio.io/inject") == "false"
inj = lambda d: d["metadata"]["namespace"] in injected
yaml.safe_dump_all([d for d in docs if not off(d) and inj(d)], open(sys.argv[2], "w"), sort_keys=False)
yaml.safe_dump_all([d for d in docs if off(d) and inj(d)], open(sys.argv[3], "w"), sort_keys=False)
yaml.safe_dump_all([d for d in docs if off(d) and not inj(d)], open(sys.argv[5], "w"), sort_keys=False)
chk = [copy.deepcopy(d) for d in docs if off(d) and inj(d)]
for d in chk: d["metadata"]["name"] += "-capture-check"
yaml.safe_dump_all(chk, open(sys.argv[4], "w"), sort_keys=False)
PY
n_proxyless=$(grep -c '^kind: Pod' "$work/proxyless.yaml")
# shellcheck disable=SC2317  # called by capture_lift_create
proxyless_refused() { k create --dry-run=server -f "$work/proxyless-check.yaml" >"$work/proxyless.out" 2>&1; [ "$(grep -c "ValidatingAdmissionPolicy '$POLICY'.*denied request: capture rule" "$work/proxyless.out")" = "$n_proxyless" ]; }
# shellcheck disable=SC2317  # called by capture_lift_create
proxyless_admitted() { k create --dry-run=server -f "$work/proxyless-check.yaml" >"$work/proxyless.out" 2>&1; }
# The callers of each row, in its own namespace on a node other than its destination's; in another data
# namespace only the legitimate caller, which the row's lane does not admit there.
for ns in "${DATANS[@]}"; do
  for r in "${ROWS[@]}"; do
    [ -f "$work/row-$r.yaml" ] || continue
    from_ns=$(jq -r --arg r "$r" '.[] | select(.name == $r) | .fromNs' "$work/rows.json")
    sed -e "s/__FROM__/$ns/g" "fixtures/rows/$r.yaml" | sed "s/__TO__/__dest__/g" >"$work/callers-$ns-$r.yaml"
    python3 - "$work/callers-$ns-$r.yaml" "$([ "$ns" = "$from_ns" ] && echo all || echo caller)" <<'PY'
import sys, yaml
f, which = sys.argv[1], sys.argv[2]
docs = [d for d in yaml.safe_load_all(open(f)) if d and d["metadata"]["namespace"] != "__dest__"]
role = lambda d: (d["metadata"].get("annotations") or {}).get("verify-plane-separation/role")
if which == "caller":
    pods = [d for d in docs if d["kind"] == "Pod" and role(d) == "caller"]
    sas = {p["spec"]["serviceAccountName"] for p in pods}
    docs = [d for d in docs if d in pods or (d["kind"] == "ServiceAccount" and d["metadata"]["name"] in sas)]
yaml.safe_dump_all(docs, open(f, "w"), sort_keys=False)
PY
    mapfile -t pods < <(python3 -c 'import sys,yaml
for d in yaml.safe_load_all(open(sys.argv[1])):
    if d and d["kind"] == "Pod": print(d["metadata"]["name"])' "$work/callers-$ns-$r.yaml")
    target=$(other_node "${DEST_NODE[$r]:-none}")
    on_node "$target" "$work/callers-$ns-$r.yaml" "${pods[@]}"
    drop_existing "$work/callers-$ns-$r.yaml"
    k apply -f "$work/callers-$ns-$r.yaml" >/dev/null 2>"$work/callers.err" || check 1 "row $r: its callers in $ns are created" "$(head -1 "$work/callers.err")"
    CALLER["$r|$ns"]="${pods[0]} (on $target; destination on ${DEST_NODE[$r]:-unknown})"
  done
done
k apply -f "$work/meshed.yaml" >/dev/null 2>"$work/meshed.err"; check $? "the meshed probers (mesh-prober-<i>, one per node with a SPIRE agent, in each probing namespace with injection) are created" "$(head -1 "$work/meshed.err")"
if grep -q '^kind: Pod' "$work/plain.yaml"; then
  k apply -f "$work/plain.yaml" >/dev/null 2>"$work/plain.err"
  check $? "the proxy-less probes of the namespaces without injection are created as written" "$(grep -o 'namespace: .*' "$work/plain.yaml" | sort -u | paste -sd' ' -); $(head -1 "$work/plain.err")"
fi
proxyless_refused; check $? "as written, each proxy-less probe is refused by the capture rule of $POLICY" "$(grep -c 'denied request: capture rule' "$work/proxyless.out") of $n_proxyless refused"
capture_lift_create "$work/proxyless.yaml" proxyless_refused proxyless_admitted
check $rc_create "with the capture validation (index ${idx:-none}) lifted, the proxy-less probes (probe-<i>, one per node) are created" ${lift_reason:+"$lift_reason"}
diff <(jq -S .spec "$work/policy.json") <(k get validatingadmissionpolicy "$POLICY" -o json | jq -S .spec) >/dev/null && [ "$held" -ge 5 ]
check $? "the admission policy is put back unchanged and refuses the probes again, five times in a row" "refusals held $held of 5"
for ns in "${PROBENS[@]}"; do
  k -n "$ns" wait --for=condition=Ready pod -l "$PART_OF" --timeout=300s >/dev/null 2>&1
  check $? "every caller and prober of the run in $ns is Ready"
done
code "$(for ns in $(printf '%s\n' "${PROBENS[@]}" "$MGMT" | sort -u); do k -n "$ns" get pods -l "$PART_OF" -o wide 2>/dev/null | sed 's/  */ /g'; done)"

# --------------------------------------------------------------------------------------------
section "6. The control channels of the management plane"
agents=$(spire_server agent list -output json 2>/dev/null); [ -n "$agents" ] || agents="{}"
mapfile -t agent_pod_nodes < <(k -n "$SPIRE_NS" get pods -o json | jq -r '.items[] | select(.metadata.ownerReferences[0].name == "spire-agent") | .spec.nodeName' | sort -u)
missing=""
for n in "${agent_pod_nodes[@]}"; do
  ok=$(jq -r --arg n "agent_node_name:$n" '[.agents[]? | select((.banned // false) | not) | select([.selectors[]? | .value] | index($n))] | length' <<<"$agents")
  [ "${ok:-0}" -gt 0 ] || missing="$missing $n"
  [ "${ok:-0}" -gt 0 ]; check $? "control channel: the SPIRE agent of node $n is attested to the server (and not banned)" "attested agents for the node: ${ok:-0}"
done
[ ${#agent_pod_nodes[@]} -gt 0 ] && [ -z "$missing" ]; check $? "control channel: every SPIRE agent is attested" "${#agent_pod_nodes[@]} agents; not attested:${missing:- none}"
istioctl --context "$CONTEXT" proxy-status -o json >"$work/ps.json" 2>/dev/null
nsj=$(printf '%s\n' "${DATANS[@]}" | jq -R . | jq -cs .)
proxies=$(jq -r --argjson ns "$nsj" '[.resources[]? | select(.node.metadata.NAMESPACE as $n | $ns | index($n))] | length' "$work/ps.json" 2>/dev/null)
unsynced=$(jq -r --argjson ns "$nsj" '.resources[]? | select(.node.metadata.NAMESPACE as $n | $ns | index($n)) | . as $r | .genericXdsConfigs[]? | select(.configStatus != "SYNCED" and .configStatus != "NOT_SENT") | "\($r.node.id) \(.typeUrl | sub(".*/"; "")) \(.configStatus)"' "$work/ps.json" 2>/dev/null)
[ "${proxies:-0}" -gt 0 ] && [ -z "$unsynced" ]
check $? "control channel: every proxy of the data-plane namespaces holds a configuration SYNCED with istiod (a type istiod never sent is NOT_SENT)" "proxies ${proxies:-0}; not SYNCED: ${unsynced:-none}"

# --------------------------------------------------------------------------------------------
section "7. ALLOW rows"
for ns in "${DATANS[@]}"; do
  for r in "${ROWS[@]}"; do
    [ -f "$work/callers-$ns-$r.yaml" ] || { probe_line fail "$r" "$ns" legitimate - - "" "a probe" "no fixture" "control channel" "the row has no fixture, so no probe" none; continue; }
    row=$(jq -c --arg r "$r" '.[] | select(.name == $r)' "$work/rows.json")
    from_ns=$(jq -r .fromNs <<<"$row"); to_ns=$(jq -r .toNs <<<"$row"); from_sa=$(jq -r '.fromServiceAccount // empty' <<<"$row")
    svc=${DEST_SVC[$r]}; host="$svc.$to_ns.svc"; dest_id=$(spiffe "$to_ns" "${DEST_SA[$r]}"); dpods=${DEST_PODS[$r]}
    read -ra dpod_list <<<"$dpods"
    mapfile -t ports < <(jq -r '.ports[]' <<<"$row")
    [ ${#ports[@]} -gt 0 ] || mapfile -t ports < <(k -n "$to_ns" get svc "$svc" -o jsonpath='{range .spec.ports[*]}{.port}{"\n"}{end}' 2>/dev/null)
    caller=$r-caller; cnode=$(node_of "$ns" "$caller")
    dips=$(for dp in "${dpod_list[@]}"; do k -n "$to_ns" get pod "$dp" -o jsonpath='{.status.podIP}'; echo; done | paste -sd' ' -)
    csrc=$(spiffe "$ns" "$(k -n "$ns" get pod "$caller" -o jsonpath='{.spec.serviceAccountName}' 2>/dev/null)")
    if [ "$ns" != "$from_ns" ]; then
      for p in "${ports[@]}"; do
        probe_start "$to_ns" "$dpods" "$cnode"
        o=$(http "$ns" "$caller" app "http://$host:$p/")
        line=$(probe_denial "$to_ns" "$dpods" "$csrc")
        network_layer "$o" "$(network_evidence "$cnode" "$ns/$caller" "$dips" "$p" "$T0" "no new denial line of $csrc in the destination's proxy")" "$line"
        probe_line "$v" "$r" "$ns" "legitimate labels outside the row's namespace" "$caller" "$host" "$p" "dropped (the lane admits $from_ns only), no denial line" "$o" "network" "$ev" "${KIND[$r]}"
      done
      continue
    fi
    for p in "${ports[@]}"; do
      before=$(mtls_requests "$ns" "$caller" source "destination_principal=\"$dest_id\"")
      o=$(http "$ns" "$caller" app "http://$host:$p/")
      after=$(mtls_requests "$ns" "$caller" source "destination_principal=\"$dest_id\"")
      if [ "${o%% *}" = 200 ] && [ "$after" -gt "$before" ]; then v=pass; else v=fail; fi
      probe_line "$v" "$r" "$ns" "legitimate caller" "$caller" "$host" "$p" "200 over mTLS, destination principal $dest_id" "$o" "control channel" "the caller's proxy counted $((after - before)) request(s) to destination_principal $dest_id (istio_requests_total, reporter source)" "${KIND[$r]}"
    done
    if [ -n "$from_sa" ]; then
      imp=$r-impostor
      denials_start "$to_ns" "${dpod_list[@]}"
      o=$(http "$ns" "$imp" app "http://$host:${ports[0]}/"); sleep 3
      denials_new "$to_ns" "${dpod_list[@]}" >"$work/den-new"
      line=$(jq -c --arg s "$(spiffe "$ns" "$imp")" --arg d "$dest_id" 'select(.source == $s and .destination == $d and (((.detail // "") + " " + (.termination // "")) | test("(^| )rbac_access_denied")))' "$work/den-new" | head -1)
      if [ "$o" = "403 RBAC: access denied" ] && [ -n "$line" ]; then v=pass; else v=fail; fi
      probe_line "$v" "$r" "$ns" "impostor (row labels, service account $imp)" "$imp" "$host" "${ports[0]}" "403 RBAC and a denial line with both SPIFFE IDs" "$o" "mesh" "${line:-no denial line naming the impostor}" "${KIND[$r]}"
      un=$r-unlabelled; unode=$(node_of "$ns" "$un"); usrc=$(spiffe "$ns" "$from_sa")
      probe_start "$to_ns" "$dpods" "$unode"
      o=$(http "$ns" "$un" app "http://$host:${ports[0]}/")
      line=$(probe_denial "$to_ns" "$dpods" "$usrc")
      network_layer "$o" "$(network_evidence "$unode" "$ns/$un" "$dips" "${ports[0]}" "$T0" "no new denial line of $usrc in the destination's proxy")" "$line"
      probe_line "$v" "$r" "$ns" "unlabelled (service account $from_sa, no row labels)" "$un" "$host" "${ports[0]}" "dropped, no denial line" "$o" "network" "$ev" "${KIND[$r]}"
    else
      probe_line n/a "$r" "$ns" "impostor" - "$host" "" "n/a" "not probed" "mesh" "the row admits every identity of $from_ns, so no identity is an impostor" "${KIND[$r]}"
      probe_line n/a "$r" "$ns" "unlabelled" - "$host" "" "n/a" "not probed" "network" "the row selects every pod of $from_ns, so no pod lacks its labels" "${KIND[$r]}"
      # The export row: limited to its ports. The stand-in serves 8080 too; a real collector is asked on
      # every port of its Service beyond the row's.
      mapfile -t off < <(k -n "$to_ns" get svc "$svc" -o json | jq -r --argjson p "$(jq -c .ports <<<"$row")" '.spec.ports[].port | select(. as $x | $p | index($x) | not)')
      [ ${#off[@]} -gt 0 ] || off=(8080)
      for p in "${off[@]}"; do
        probe_start "$to_ns" "$dpods" "$cnode"
        o=$(http "$ns" "$caller" app "http://$host:$p/")
        line=$(probe_denial "$to_ns" "$dpods" "$csrc")
        network_layer "$o" "$(network_evidence "$cnode" "$ns/$caller" "$dips" "$p" "$T0" "no new denial line of $csrc in the destination's proxy")" "$line"
        probe_line "$v" "$r" "$ns" "off the row's ports" "$caller" "$host" "$p" "dropped (the row admits $(jq -r '.ports | map(tostring) | join(" and ")' <<<"$row") only), no denial line" "$o" "network" "$ev" "${KIND[$r]}"
      done
    fi
  done
done

# --------------------------------------------------------------------------------------------
section "8. DENY rows and the catch-all row"
# apply_opening <caller ns> <prober> <dest ns> <dest selector JSON> <port>: the probe-scoped opening of
# fixtures/opening.yaml for that prober, destination and port
apply_opening() {
  # shellcheck disable=SC2001
  sed -e "s/__NS__/$1/g" -e "s/__DEST_NS__/$3/g" -e "s/__PORT__/$5/g" -e "s/__RUN__/$RUN/g" -e "s/__PROBER__/$2/g" \
    -e "s|__DEST_SELECTOR__|$(sed 's/[&|]/\\&/g' <<<"$4")|g" fixtures/opening.yaml >"$work/opening.yaml"
  k apply -f "$work/opening.yaml" >/dev/null 2>"$work/opening.err" || check 1 "the probe-scoped opening to $3 ($4):$5 is applied" "$(head -1 "$work/opening.err")"
}
# remove_opening: deletes the opening; sets gone to what of the run's NetworkPolicies remains (empty: none)
remove_opening() {
  k delete -f "$work/opening.yaml" --ignore-not-found --wait=true >/dev/null 2>&1
  gone=$(k get networkpolicy -A -l "$PART_OF" -o name 2>/dev/null)
}
# mesh_probe <row> <caller ns> <destination JSON> <service port> <target port> <real|stand-in>: the meshed
# prober of <caller ns> calls the destination's Service behind a probe-scoped opening; the destination's
# proxy must refuse it (403 RBAC for HTTP) and one of the destination's pods must log a denial line with
# both SPIFFE IDs. Every pod the Service selects is read, so the line of whichever pod served the attempt
# is found; the prober is placed by the first pod's node.
mesh_probe() {
  local drow=$1 ns=$2 d=$3 sport=$4 tport=$5 dkind=$6 dns dsvc dsel dsa prober o line served pods
  dns=$(jq -r .namespace <<<"$d"); dsvc=$(jq -r .service <<<"$d"); dsel=$(jq -c .selector <<<"$d"); dsa=$(jq -r .serviceAccount <<<"$d")
  mapfile -t pods < <(jq -r '.pods[].name' <<<"$d")
  prober=$(prober_on mesh-prober "$(jq -r '.pods[0].node' <<<"$d")" "$ns")
  apply_opening "$ns" "$prober" "$dns" "$dsel" "$tport"
  denials_start "$dns" "${pods[@]}"
  o=""
  for _ in 1 2 3 4 5; do o=$(http "$ns" "$prober" app "http://$dsvc.$dns.svc:$sport/"); not_through "$o" || break; sleep 3; done
  sleep 3
  line=$(denials_new "$dns" "${pods[@]}" | jq -c --arg s "$(spiffe "$ns" mesh-prober)" --arg d "$(spiffe "$dns" "$dsa")" 'select(.source == $s and .destination == $d and (((.detail // "") + " " + (.termination // "")) | test("(^| )rbac_access_denied")))' | head -1)
  remove_opening
  served=0; [[ ${o%% *} =~ ^[0-9]+$ ]] && [ "$o" != "403 RBAC: access denied" ] && served=1
  if [ "$served" = 0 ] && [ -n "$line" ] && [ -z "$gone" ]; then v=pass; else v=fail; fi
  probe_line "$v" "$drow" "$ns" "behind a probe-scoped opening" "$prober" "$dns/$dsvc" "$sport" "refused by the destination's proxy, a denial line with both SPIFFE IDs, the opening removed" "$o" "mesh" "${line:-no denial line naming the prober in any of the ${#pods[@]} pod(s) the Service selects}; opening removed: $([ -z "$gone" ] && echo yes || echo "no: $gone")" "$dkind"
}
# plaintext_probe <row> <caller ns> <destination JSON> <pod> <ip> <node> <port> <real|stand-in>: the
# proxy-less probe of <caller ns> sends a plain-text request, without identity, to <ip>:<port> behind a
# probe-scoped opening; mutual TLS STRICT at the destination's proxy must reset it (plaintext_layer)
plaintext_probe() {
  local drow=$1 ns=$2 d=$3 pod=$4 ip=$5 node=$6 port=$7 dkind=$8 dns dsel prober pnode o fwd mode hub labels
  dns=$(jq -r .namespace <<<"$d"); dsel=$(jq -c .selector <<<"$d")
  prober=$(prober_on probe "$node" "$ns"); pnode=$(node_of "$ns" "$prober")
  labels=$(jq -c --arg p "$pod" '[.pods[] | select(.name == $p)][0].labels // {}' <<<"$d")
  apply_opening "$ns" "$prober" "$dns" "$dsel" "$port"
  T0=$(node_now "$pnode")
  for _ in 1 2 3 4 5; do o=$(http "$ns" "$prober" app "http://$ip:$port/"); [ "$o" = "denied(28)" ] || break; sleep 3; done
  fwd=$(forwarded_flow "$pnode" "$ns/$prober" "$ip" "$port" "$T0")
  remove_opening
  mode=$(plan_mtls_mode "$work/pa.json" "$dns" "$labels" "$port" "$ISTIO_NS")
  hub=0; hubble_ok "$pnode" && hub=1
  plaintext_layer "$o" "$mode" "$fwd" "$hub"
  [ -z "$gone" ] || v=fail
  probe_line "$v" "$drow" "$ns" "plain text, no identity, behind a probe-scoped opening" "$prober" "$dns/$pod" "$port" "reset by the destination's proxy (mutual TLS STRICT), the opening removed" "$o" "mesh" "$ev; mutual TLS mode in force: $mode; opening removed: $([ -z "$gone" ] && echo yes || echo "no: $gone")" "$dkind"
}
# probe_destinations <plan key> <caller ns>: every destination of the plan's list from <caller ns>. The
# network layer: a raw TCP connection from a proxy-less probe on another node to every port of every
# endpoint. The mesh layer of a meshed destination: from a namespace with injection, the meshed prober
# through each Service port (a pod port once per namespace: two Services selecting the same pods are probed
# once); a pod port no Service exposes, and every port from a namespace without injection, in plain text
# without identity. A destination without a proxy has no mesh layer (n/a).
declare -A MESH_DONE=()
probe_destinations() {
  local key=$1 ns=$2 n di d drow dns dsvc dkind meshed pod ip node port declared prober pnode o line seen inj=0 sport tport c tp dp now readdr
  local -a cand=()
  printf '%s\n' "${INJECTED[@]}" | grep -qxF -- "$ns" && inj=1
  n=$(jq ".$key | length" "$work/plan.json")
  for di in $(seq 0 $((n - 1))); do
    d=$(jq -c ".${key}[$di]" "$work/plan.json")
    drow=$(jq -r .row <<<"$d"); dns=$(jq -r .namespace <<<"$d"); dsvc=$(jq -r .service <<<"$d")
    dkind=$(jq -r 'if .standIn then "stand-in" else "real" end' <<<"$d"); meshed=$(jq -r .meshed <<<"$d")
    case $drow in catch-all) KIND[catch-all]=real;; management-to-data) [ "${KIND[$drow]:-}" = real ] || KIND[$drow]=$dkind;; esac
    while read -r pod ip node port declared; do
      prober=$(prober_on probe "$node" "$ns"); pnode=$(node_of "$ns" "$prober")
      # The plan was built in section 4: the destination pod's address is read again just before its probe,
      # so that a pod replaced since then is probed at its address now, and a pod gone is named, not probed
      # at an address no pod holds (whose timeout would read as a drop).
      readdr=""
      if now=$(k -n "$dns" get pod "$pod" -o jsonpath='{.status.podIP}' 2>"$work/readdr.err"); then
        if [ -z "$now" ]; then
          probe_line fail "$drow" "$ns" "TCP, proxy-less" "$prober" "$dns/$dsvc ($pod)" "$port" "dropped" "not probed" "network" "the destination pod has no address now (it had $ip when the probe plan was built in section 4), so the probe would show nothing" "$dkind"
          continue
        fi
        [ "$now" != "$ip" ] && { readdr="; the pod's address was read again before the probe: $ip in the probe plan, $now now, probed at $now"; ip=$now; }
      elif grep -q NotFound "$work/readdr.err"; then
        probe_line fail "$drow" "$ns" "TCP, proxy-less" "$prober" "$dns/$dsvc ($pod)" "$port" "dropped" "not probed" "network" "the destination pod is gone since the probe plan was built in section 4, so the probe would show nothing" "$dkind"
        continue
      fi
      if [ "$meshed" = true ]; then probe_start "$dns" "$pod" "$pnode"; else T0=$(node_now "$pnode"); fi
      o=$(tcp "$ns" "$prober" "$ip" "$port")
      if [ "$declared" = true ]; then
        if [ "$o" = connected ]; then v=declared; else v=pass; fi
        probe_line "$v" "$drow" "$ns" "TCP to istiod's xDS port" "$prober" "$dns/$dsvc ($pod)" "$port" "open, declared opening (proposed): docs/specifications.md, ZT-55 xDS entry" "$o" "network" "the meshControlPlane opening admits the meshed plane namespaces to 15012; cited, not counted" "$dkind"
        continue
      fi
      if [ "$meshed" = true ]; then line=$(probe_denial "$dns" "$pod" ""); seen="no new denial line in the destination's proxy"
      else line=""; seen="the destination has no proxy to write a denial line"; fi
      network_layer "$o" "$(network_evidence "$pnode" "$ns/$prober" "$ip" "$port" "$T0" "$seen")" "$line"
      probe_line "$v" "$drow" "$ns" "TCP, proxy-less" "$prober" "$dns/$dsvc ($pod)" "$port" "dropped" "$o" "network" "$ev$readdr" "$dkind"
    done < <(jq -r '.targets[] | "\(.pod) \(.ip) \(.node) \(.port) \(.declared)"' <<<"$d")
    if [ "$meshed" != true ]; then
      unmeshed_layer "$key"
      if [ "$v" = n/a ]; then probe_line n/a "$drow" "$ns" "mesh layer" - "$dns/$dsvc" "" "n/a" "not probed" "mesh" "$ev" "$dkind"
      else probe_line "$v" "$drow" "$ns" "mesh layer" - "$dns/$dsvc" "" "a proxy at the destination" "no proxy" "mesh" "$ev" "$dkind"; fi
      continue
    fi
    if [ "$inj" = 1 ]; then
      while read -r tp; do cand+=("$di|$tp"); done < <(jq -r '.targets[] | "\(.pod) \(.ip) \(.node) \(.port)"' <<<"$d" | tr ' ' '|')
      while read -r sport tport; do
        [ "$tport" = null ] && tport=$sport
        dp=$(jq -r '.pods[0].name' <<<"$d")
        if [ -n "${MESH_DONE["$ns|$dns/$dp|$tport"]:-}" ]; then
          say "- $drow from $ns: $dns/$dsvc:$sport leads to $dp:$tport, probed at the mesh layer already through ${MESH_DONE["$ns|$dns/$dp|$tport"]}"
          continue
        fi
        MESH_DONE["$ns|$dns/$dp|$tport"]=$dns/$dsvc:$sport
        mesh_probe "$drow" "$ns" "$d" "$sport" "$tport" "$dkind"
      done < <(jq -r '.servicePorts[] | "\(.port) \(.targetPort)"' <<<"$d")
    else
      # No meshed prober in a namespace without injection: every pod port is probed in plain text.
      while read -r pod ip node port; do
        [ -n "${MESH_DONE["$ns|$dns/$pod|$port"]:-}" ] && continue
        MESH_DONE["$ns|$dns/$pod|$port"]=plain
        plaintext_probe "$drow" "$ns" "$d" "$pod" "$ip" "$node" "$port" "$dkind"
      done < <(jq -r '.targets[] | "\(.pod) \(.ip) \(.node) \(.port)"' <<<"$d")
    fi
  done
  # A port of a meshed pod that no Service led to: a meshed caller would reach the bare pod address through
  # its proxy's passthrough, in plain text and without its identity, so it is probed that way, from the
  # proxy-less probe, and refused by mutual TLS STRICT.
  for c in "${cand[@]}"; do
    IFS='|' read -r di pod ip node port <<<"$c"
    d=$(jq -c ".${key}[$di]" "$work/plan.json"); dns=$(jq -r .namespace <<<"$d")
    [ -n "${MESH_DONE["$ns|$dns/$pod|$port"]:-}" ] && continue
    MESH_DONE["$ns|$dns/$pod|$port"]=plain
    plaintext_probe "$(jq -r .row <<<"$d")" "$ns" "$d" "$pod" "$ip" "$node" "$port" "$(jq -r 'if .standIn then "stand-in" else "real" end' <<<"$d")"
  done
}
for ns in "${DATANS[@]}"; do probe_destinations destinations "$ns"; done

# --------------------------------------------------------------------------------------------
section "9. Management plane → data plane"
say "Section 6's row \`management-to-data\`: DENY at both layers by the default deny alone; the rule was checked against the rendered umbrella (section 1) and the cluster's policies (section 2). Probed from: ${SRCNS[*]}." ''
for ns in "${SRCNS[@]}"; do probe_destinations reverseDestinations "$ns"; done

# --------------------------------------------------------------------------------------------
section "10. Cleanup"
cleanup
left=$(k get pods,services,serviceaccounts,networkpolicies -A -l "$PART_OF" -o name 2>/dev/null)
[ -z "$left" ]; check $? "no fixture, prober or opening of the run remains" "${left:-none}"
policy_snapshot >"$work/snapshot-after"
diff "$work/snapshot-before" "$work/snapshot-after" >"$work/snapshot.diff"
check $? "the zone's policies equal the snapshot taken at the start (NetworkPolicy, CiliumNetworkPolicy, AuthorizationPolicy, the admission policy's spec)" "$(head -c 400 "$work/snapshot.diff" | tr '\n' ' ')"
fi # routing_ok

# --------------------------------------------------------------------------------------------
if [ "${routing_ok:-0}" = 1 ]; then
  say '' '## The matrix' ''
  say '| Row | ZT-55 role | Caller'"'"'s namespace | Legitimate caller | Network layer | Mesh layer | Destination |' '|---|---|---|---|---|---|---|'
  for key in $(python3 -c 'import csv,sys
seen = []
for r in csv.DictReader(open(sys.argv[1])):
    k = r["row"] + "|" + r["namespace"]
    if k not in seen: seen.append(k); print(k)' "$CSV"); do
    r=${key%%|*}; ns=${key#*|}
    say "| $r | ${ROLE[$r]:-} | $ns | ${CALLER[$key]:-—}${CHAN[$key]:+: ${CHAN[$key]}} | ${NETSUM[$key]:-—} | ${MESHSUM[$key]:-—} | ${KIND[$r]:-—} |"
  done
  say '' "Per row (\`matrix.csv\`, decided as the Annex scenario decides it):" ''
  code "$(plan_decide "$CSV")"
fi
say '' '## Result' ''
if [ "$failures" -eq 0 ]; then say 'All checks passed.'; else say "**$failures check(s) failed.**"; fi

jq -n --arg commit "$commit" --argjson dirty "$dirty" --arg date "$started" --arg finished "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg context "$CONTEXT" --arg clusterKind "$CLUSTER_KIND" --arg zone "${ZONE_VALUES#"$REPO"/}" --arg zoneName "$ZONE_NAME" --arg td "$TD" \
  --arg run "$RUN" --arg server "$(k version -o json 2>/dev/null | jq -r .serverVersion.gitVersion)" \
  --arg kubectl "$(kubectl version --client -o json 2>/dev/null | jq -r .clientVersion.gitVersion)" --arg helm "$(helm version --short 2>/dev/null)" \
  --arg istioctl "$(istioctl version --remote=false 2>/dev/null | head -1)" \
  --arg cni "$(k -n kube-system get ds cilium -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null)" \
  --argjson hubble "$(for n in "${!HUBBLE[@]}"; do printf '{"node":"%s","available":%s}\n' "$n" "$([ "${HUBBLE[$n]}" = 1 ] && echo true || echo false)"; done | jq -cs .)" \
  --argjson failures "$failures" '{commit: $commit, dirty: $dirty, date: $date, finished: $finished, run: $run,
    cluster: {context: $context, kind: $clusterKind, kubernetes: $server, cni: $cni, hubble: $hubble},
    zone: {file: $zone, name: $zoneName, trustDomain: $td, trustDomainInterim: ($td | endswith(".trust.invalid"))},
    tools: {kubectl: $kubectl, helm: $helm, istioctl: $istioctl}, result: {failures: $failures}}' >"$work/environment.json"
written=0
if mkdir -p "$EVID"; then
  if [ "$CLUSTER_KIND" = kind ]; then
    cp "$OUT" "$EVID/evidence.md" && cp "$CSV" "$EVID/matrix.csv" && cp "$work/environment.json" "$EVID/environment.json" && written=1
  else
    proof_mask "$OUT" >"$EVID/evidence.md" && proof_mask "$CSV" >"$EVID/matrix.csv" && proof_mask "$work/environment.json" >"$EVID/environment.json" && written=1
  fi
fi
if [ "$written" != 1 ]; then
  echo "$PROOF_NAME: the record could not be written to $EVID" >&2
  failures=$((failures+1)); proof_exit
fi
echo "record written ($failures failure(s)); run directory:"
# The last line of the output is the run directory, alone, so a caller takes it with tail -n 1.
echo "$EVID"
proof_exit
