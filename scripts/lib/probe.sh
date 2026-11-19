# Shared probing machinery of the cluster proofs (scripts/verify-mesh-identity/verify.sh,
# scripts/verify-plane-separation/verify.sh): placement of stand-ins across nodes, the HTTP and TCP
# probes and their outcome classes, the denial log of a proxy, reads on a node through its Cilium
# agent, the capture-rule lift for proxy-less stand-ins, and the routing precondition. Sourced after
# scripts/lib/proof.sh (k, check); defines functions only. Each function reads the globals it names
# (CONTEXT, SPIRE_NS, TD, work, POLICY, ...).
# shellcheck shell=bash disable=SC2016,SC2034,SC2154

# restore_capture: puts the capture validation back into the live policy when it is missing from it
# and section 5 saved it (restore.json); a no-op otherwise, so it is safe to call more than once. A
# policy it cannot read (other than one already uninstalled) or cannot patch is named on stderr, as
# the capture validation may then still be lifted.
restore_capture() {
  local live
  [ -s "$work/restore.json" ] || return 0
  if ! live=$(kubectl --context "$CONTEXT" get validatingadmissionpolicy "$POLICY" -o json 2>"$work/restore.err"); then
    grep -q NotFound "$work/restore.err" \
      || echo "$PROOF_NAME: cannot read the admission policy $POLICY to put its capture validation back; it may still be lifted: $(head -1 "$work/restore.err")" >&2
    return 0
  fi
  jq -e '[.spec.validations[].expression | contains("variables.captureDefaults")] | index(true) == null' <<<"$live" >/dev/null || return 0
  kubectl --context "$CONTEXT" patch validatingadmissionpolicy "$POLICY" --type=json --patch-file "$work/restore.json" >/dev/null 2>"$work/restore.err" \
    || echo "$PROOF_NAME: the capture validation of the admission policy $POLICY could not be put back; it is still lifted: $(head -1 "$work/restore.err")" >&2
}
# capture_index <policy JSON file>: the index of the capture validation of the admission policy (the one
# validation that reads variables.captureDefaults), null when the policy holds none
capture_index() { jq '[.spec.validations[]?.expression | contains("variables.captureDefaults")] | index(true)' "$1"; }
# capture_restore_hint: how to put a lifted capture validation back by hand: the zone-policy release
# applied again at its deployed revision. The lift's patch took the field .spec.validations, so a plain
# helm upgrade or rollback (and so scripts/install-zone/install.sh install) stops on that field
# manager's conflict; --force-conflicts takes the field back.
capture_restore_hint() {
  printf '%s' "rev=\$(helm --kube-context $CONTEXT -n ${ISTIO_NS:-istio-system} status zone-policy -o json | jq .version); helm --kube-context $CONTEXT -n ${ISTIO_NS:-istio-system} rollback zone-policy \"\$rev\" --force-conflicts"
}
# capture_start_check: exits 125, before the run creates anything, when the admission policy cannot be
# read or holds no capture validation. A run killed while the validation was lifted (SIGKILL, OOM, a
# reboot: no trap runs) leaves the policy so, and its restore file went with its work directory; a run
# that started then would take the lifted policy for the zone's, and the policy would keep admitting
# pods without a proxy in the injected plane namespaces. The message names the restore.
capture_start_check() {
  local live
  if ! live=$(kubectl --context "$CONTEXT" get validatingadmissionpolicy "$POLICY" -o json 2>&1); then
    echo "$PROOF_NAME: refusing to start: cannot read the admission policy $POLICY of zone-policy: $(head -1 <<<"$live")" >&2
    exit 125
  fi
  if [ "$(capture_index /dev/stdin <<<"$live")" = null ]; then
    echo "$PROOF_NAME: refusing to start: the admission policy $POLICY holds no capture validation (no validation reads variables.captureDefaults), so it admits pods without a proxy in the injected plane namespaces. A run of verify-plane-separation or verify-mesh-identity killed while the validation was lifted leaves it so. Put it back from the zone-policy release, then run again: $(capture_restore_hint)" >&2
    exit 125
  fi
}
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
# The outcome of a probe is read from curl's own exit code, which curl writes on its standard output
# (-w '%{exitcode}', a line "curl-exit=<code>"), never from the exit status of kubectl exec: on a loaded
# API server kubectl exec has been seen to return 0 for a curl that timed out (its error line said
# "Timeout was reached" and Hubble recorded the SYN dropped by policy), which read a dropped probe as
# served. An attempt whose output carries no such line observed nothing and is run again (probe_exec); a
# probe that never carries one is error(no exit code): it shows nothing about either layer, and is never
# read as a denial.
CURL_EXIT_FMT='curl-exit=%{exitcode}'
# curl_exit <output>: curl's exit code from the last "curl-exit=<code>" line of <output>; empty when none
curl_exit() { sed -n 's/^curl-exit=\([0-9][0-9]*\)$/\1/p' <<<"$1" | tail -1; }
# probe_exec <kubectl exec arguments...>: runs curl through kubectl exec and prints its output. An attempt
# whose output holds no curl exit code observed nothing (the exec lost curl's output, so neither a served
# attempt nor a denial was seen): it is run again, at most twice more, 2 s apart. An attempt that holds an
# exit code, whatever it is, is never run again. Each attempt that observed nothing is written to the file
# $PROBE_NOTES when the caller sets it (the exec's exit status and the first line kubectl wrote on stderr),
# so that the record says the probe was run again; after three such attempts the output is the last one's,
# which the outcome functions read as error(no exit code).
probe_exec() {
  local out rc i err
  err=$(mktemp)
  for i in 1 2 3; do
    out=$(k "$@" 2>"$err"); rc=$?
    [ -n "$(curl_exit "$out")" ] && break
    [ -n "${PROBE_NOTES:-}" ] && printf 'attempt %s held no curl exit code (kubectl exec exit %s; %s)\n' "$i" "$rc" \
      "$(grep -v '^curl: (' "$err" | grep . | head -1 | cut -c1-160 | sed 's/^/kubectl: /;' | grep . || echo 'nothing from kubectl on stderr')" >>"$PROBE_NOTES"
    [ "$i" -lt 3 ] && sleep 2
  done
  rm -f "$err"
  printf '%s' "$out"
}
# http <ns> <pod> <container> <url>: HTTP code and the first line of the body; denied(<curl exit>)
# only when the network refused the call (7 refused, 28 timed out, 52 empty reply, 56 reset);
# error(<exit>) for anything else (a name that does not resolve, an exec that failed, ...), which
# a negative check does not count as a denial.
http() {
  http_outcome "$(probe_exec -n "$1" exec "$2" -c "$3" -- curl -sS -m 15 -w "\n%{http_code}\n$CURL_EXIT_FMT\n" "$4" 2>/dev/null)"
}
# http_outcome <output of the curl of http()>: the outcome class of http(), from curl's own exit code
http_outcome() {
  local rc rest
  rc=$(curl_exit "$1")
  case $rc in
    "") echo "error(no exit code)";;
    0) rest=$(sed '/^curl-exit=[0-9]*$/d' <<<"$1")
       printf '%s %s' "$(tail -1 <<<"$rest")" "$(head -1 <<<"$rest" | cut -c1-110)";;
    7|28|52|56) echo "denied($rc)";;
    *) echo "error($rc)";;
  esac
}
# tcp <ns> <pod> <ip> <port>: "connected" when a TCP connection is established, denied(<curl exit>)
# when it was refused or timed out (7, 28), error(<exit>) when the probe itself failed (6: no such name;
# 1, 126, 127: curl did not run as asked; no exit code: every attempt's exec lost curl's output, or
# kubectl could not exec at all)
tcp() {
  tcp_outcome "$(probe_exec -n "$1" exec "$2" -c app -- curl -s -o /dev/null --connect-timeout 4 -m 6 -w "$CURL_EXIT_FMT\n" "http://$3:$4/" 2>/dev/null)"
}
# tcp_outcome <output of the curl of tcp()>: the outcome class of tcp(), from curl's own exit code
tcp_outcome() {
  local rc; rc=$(curl_exit "$1")
  case $rc in "") echo "error(no exit code)";; 7|28) echo "denied($rc)";; 1|6|126|127) echo "error($rc)";; *) echo connected;; esac
}
# denial_lines <ns> <pod>: the denial-log lines the pod's proxy has written so far (the access-log
# provider denial-log of the istiod release, enabled for refused requests and connections by
# zone-policy's Telemetry mesh-default), one compact JSON object per line; the proxy's own log lines
# are not JSON objects with these keys and are dropped
denial_lines() {
  k -n "$1" logs "$2" -c istio-proxy 2>/dev/null | jq -cR 'fromjson? | select(type == "object" and has("source") and has("destination") and has("detail"))' 2>/dev/null
}
# new_denials <before-file> <ns> <pod>: the denial lines written since <before-file> was taken with
# denial_lines (Envoy flushes its file log about once a second, so the caller waits a few seconds)
new_denials() { denial_lines "$2" "$3" | tail -n +"$(( $(grep -c . "$1") + 1 ))"; }
# metric <ns> <pod> <reporter>: istio_requests_total of the proxy for one reporter, summed
metric() {
  k -n "$1" exec "$2" -c istio-proxy -- pilot-agent request GET stats/prometheus 2>/dev/null \
    | awk -v r="reporter=\"$3\"" '/^istio_requests_total/ && index($0, r) { s += $NF } END { print s + 0 }'
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
# routing_precondition: reads kube-system/cilium-config and the nodes' pod ranges into $work and records
# the routing check (routing_verdict above) as a check; sets routing (status, detail) and routing_ok.
routing_precondition() {
  if cm_json=$(k -n kube-system get cm cilium-config -o json 2>/dev/null) \
    && jq -e '.data // {}' <<<"$cm_json" >"$work/cilium-config.json" 2>/dev/null; then :
  else echo null >"$work/cilium-config.json"; fi
  k get nodes -o json 2>/dev/null | jq -r '.items[] | .metadata.name as $n | (.spec.podCIDRs // [.spec.podCIDR // empty])[] | "\($n) \(.)"' >"$work/pod-ranges.txt" 2>/dev/null
  mapfile -t routing < <(routing_verdict "$work/cilium-config.json" "$work/pod-ranges.txt" 2>&1)
  routing_ok=0; [ "${routing[0]:-1}" = 0 ] && routing_ok=1
  [ "$routing_ok" = 1 ]
  check $? "pod-to-pod routing keeps a pod's address between nodes: no native routing with masquerading on and a node's pod range outside ipv4-native-routing-cidr (a pod on another node would reach a pod as remote-node, not as itself)" "${routing[1]:-the routing could not be read: ${routing[0]:-no output}}"
}
# capture_lift_create <manifest> <refused-fn> <admitted-fn>: creates the proxy-less pods of <manifest>,
# which the capture rule of $POLICY refuses as written, with that one validation lifted from the policy
# for the time of their creation, then puts it back (restore_capture). <admitted-fn> and <refused-fn>
# are the caller's server dry runs of a renamed copy (admitted once the lift is in force; refused once
# it is back). Sets idx (the validation's index), rc_create (0 when created), held (the refusals in a
# row after the restore) and lift_reason (why nothing was lifted, empty otherwise); leaves the policy as
# read in $work/policy.json.
capture_lift_create() {
  k get validatingadmissionpolicy "$POLICY" -o json >"$work/policy.json"
  idx=$(capture_index "$work/policy.json")
  lift_reason=""
  if [ "${idx:-null}" = null ]; then
    lift_reason="the admission policy $POLICY holds no capture validation to lift (no validation reads variables.captureDefaults): an earlier run killed while it was lifted leaves it so; put it back with: $(capture_restore_hint)"
    echo "$PROOF_NAME: $lift_reason" >&2
  fi
  jq -c --argjson i "${idx:-null}" '[{op: "test", path: "/spec/validations/\($i)", value: .spec.validations[$i]}, {op: "remove", path: "/spec/validations/\($i)"}]' "$work/policy.json" >"$work/lift.json" 2>/dev/null
  jq -c --argjson i "${idx:-null}" '[{op: "add", path: "/spec/validations/\($i)", value: .spec.validations[$i]}]' "$work/policy.json" >"$work/restore.json" 2>/dev/null
  rc_create=1; held=0
  # Each API server replica takes up a policy change on its own (a provider's control plane runs more
  # than one), so one admitted dry run does not mean the next request is admitted: the create is
  # retried while the capture rule still refuses it (any other error ends the retries), and after the
  # restore the refusal must hold five times in a row, a second apart, which the check requires. The
  # lift lasts at most about 45 s: up to 20 dry runs a second apart, then up to 10 creates 2 s apart.
  if [ "${idx:-null}" != null ] && k patch validatingadmissionpolicy "$POLICY" --type=json --patch-file "$work/lift.json" >/dev/null 2>&1; then
    for _ in $(seq 20); do "$3" && break; sleep 1; done
    for _ in $(seq 10); do
      k apply -f "$1" >/dev/null 2>"$work/proxyless-create.err"; rc_create=$?
      [ $rc_create -eq 0 ] && break
      grep -q 'denied request: capture rule' "$work/proxyless-create.err" || break
      sleep 2
    done
    [ $rc_create -eq 0 ] || cat "$work/proxyless-create.err" >&2
    restore_capture
    for _ in $(seq 60); do if "$2"; then held=$((held+1)); [ $held -ge 5 ] && break; else held=0; fi; sleep 1; done
  fi
}
