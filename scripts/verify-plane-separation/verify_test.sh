#!/usr/bin/env bash
# Offline test of scripts/verify-plane-separation/verify.sh: no cluster is read or written. A fake kubectl
# on PATH answers the few reads the verifier makes before it would probe, and the pure part (plan.sh and
# the section-6 reader) is fed canned input.
#   - the cross-check names a row missing from section 6 and a verdict section 6 flips;
#   - the probe plan holds a second data-plane namespace and a management Service no row names;
#   - every fixture carries exactly its row's labels and service account (the umbrella rendered with the
#     kind zone file);
#   - a run directory inside the repository (not ignored by git) and CI=1 exit 125 with nothing written;
#   - a cilium-config with native routing, masquerading on and a node's pod range outside the native range
#     stops the run before any probe, naming the node;
#   - the management plane -> data plane direction: section 6's table against the row the verifier probes,
#     the rule (no policy admits that direction) against the rendered umbrella (the ambient one too, with its
#     clusterwide Cilium policy) and against canned policies that open it, clusterwide Cilium policies included, the reverse destinations of the plan, and the mutual TLS mode in force for a port;
#   - the network-layer attribution: a drop counts, a refusal only with a Hubble drop line, a served attempt
#     is named served;
#   - the probe outcome: read from curl's own exit code (its write-out line), never from the exit status of
#     kubectl exec, so a timed-out probe whose exec returned 0 is a drop; an attempt whose output was lost is
#     run again (three attempts at most, each recorded), and a probe that never holds an exit code is a
#     failed probe, never a denial;
#   - the run id: it leads with a letter, so no YAML reader takes its label for a number (8 hex digits
#     alone can read as 12345678 or 34230e05) in the probers or the openings;
#   - the plain-text probe: only a reset under mutual TLS STRICT counts;
#   - a destination without a proxy: n/a in the management plane, a failure in the data plane;
#   - the per-row decision over matrix.csv (the cases internal/bdd's decider is held to as well).
# Usage: scripts/verify-plane-separation/verify_test.sh   (exit 0 when every case passes)
# shellcheck disable=SC2016,SC2317,SC2015  # the sourced verify.sh returns early, which shellcheck reads as an exit
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(git -C "$HERE" rev-parse --show-toplevel)
T=$(mktemp -d)
trap '[ -n "${KEEP_T:-}" ] || rm -rf "$T"' EXIT
failed=0
ok() { echo "ok   $1"; }
ko() { echo "FAIL $1"; [ $# -gt 1 ] && printf '     %s\n' "${@:2}"; failed=$((failed+1)); }

# ---- 3.1 the cross-check ---------------------------------------------------------------------
# A document whose allow matrix lacks atls-gateway-to-tcr and says DENY for backend-to-verification-service.
python3 - "$REPO/docs/architecture.md" "$T/doc.md" <<'PY'
import sys
out = []
for line in open(sys.argv[1]):
    if line.startswith("| aTLS gateway → TCR resolve"):
        continue
    if line.startswith("| backend → verification service"):
        line = line.replace("| ALLOW (named pair) |", "| **DENY** |", 1)
    out.append(line)
open(sys.argv[2], "w").writelines(out)
PY
# shellcheck source=scripts/verify-plane-separation/verify.sh
. "$HERE/verify.sh"
doc_rows "$T/doc.md" >"$T/doc-rows.tsv" || ko "doc_rows reads the fixture document"
doc_rows "$REPO/docs/architecture.md" >"$T/doc-rows-real.tsv" || ko "doc_rows reads docs/architecture.md"
if command -v helm >/dev/null; then
  helm template ztd "$REPO/deployment/helm/ztd" -f "$REPO/deployment/helm/ztd/ci/values.yaml" >"$T/umbrella.yaml" 2>/dev/null
else
  : >"$T/umbrella.yaml"
fi
plan_rows "$REPO/deployment/helm/ztd/values.yaml" "$REPO/deployment/helm/ztd/ci/values.yaml" "$T/umbrella.yaml" >"$T/rows.json"
out=$(plan_crosscheck "$T/rows.json" "$T/doc-rows.tsv" "$HERE/fixtures"); rc=$?
if [ "$rc" -ne 0 ] && grep -q 'row atls-gateway-to-tcr: allowMatrix row of the umbrella absent from section 6' <<<"$out" \
  && grep -q 'row backend-to-verification-service: section 6 says DENY' <<<"$out"; then
  ok "3.1 the cross-check fails naming the missing row and the flipped verdict"
else ko "3.1 the cross-check fails naming the missing row and the flipped verdict" "$out"; fi
# A row added to the umbrella without a fixture has no probe.
jq '. + [{"name": "new-row", "fromNs": "ztd-data", "fromSelector": {"app.kubernetes.io/name": "x"}, "fromServiceAccount": "x",
  "toNs": "ztd-mgmt", "toSelector": {"app.kubernetes.io/name": "y"}, "toServiceAccount": "y", "ports": [], "rendered": true}]' "$T/rows.json" >"$T/rows-new.json"
out=$(plan_crosscheck "$T/rows-new.json" "$T/doc-rows-real.tsv" "$HERE/fixtures"); rc=$?
if [ "$rc" -ne 0 ] && grep -q 'row new-row: no fixture file' <<<"$out" && grep -q 'row new-row: allowMatrix row of the umbrella absent from section 6' <<<"$out"; then
  ok "3.1 a row added to the matrix without a probe fails the run, named"
else ko "3.1 a row added to the matrix without a probe fails the run, named" "$out"; fi
if [ -s "$T/umbrella.yaml" ]; then
  out=$(plan_crosscheck "$T/rows.json" "$T/doc-rows-real.tsv" "$HERE/fixtures"); rc=$?
  [ "$rc" -eq 0 ] && ok "3.1 the shipped document, umbrella and fixtures agree" || ko "3.1 the shipped document, umbrella and fixtures agree" "$out"
else echo "skip 3.1 the shipped sources agree (helm not on PATH)"; fi

# ---- 4.1 fixtures against their rows ---------------------------------------------------------
if [ -s "$T/umbrella.yaml" ]; then
  out=$(plan_fixtures "$HERE/fixtures" "$T/rows.json"); rc=$?
  [ "$rc" -eq 0 ] && ok "4.1 every fixture's labels and service account equal its allowMatrix row" || ko "4.1 every fixture's labels and service account equal its allowMatrix row" "$out"
  jq '(.[] | select(.name == "pdp-adapter-to-tsa") | .fromServiceAccount) = "someone-else"' "$T/rows.json" >"$T/rows-sa.json"
  out=$(plan_fixtures "$HERE/fixtures" "$T/rows-sa.json"); rc=$?
  [ "$rc" -ne 0 ] && grep -q "row pdp-adapter-to-tsa: the caller's service account pdp-adapter is not the row's someone-else" <<<"$out" \
    && ok "4.1 a fixture whose service account is not its row's is named" || ko "4.1 a fixture whose service account is not its row's is named" "$out"
fi
grep -L 'app.kubernetes.io/part-of: verify-plane-separation' "$HERE"/fixtures/*.yaml "$HERE"/fixtures/rows/*.yaml >"$T/unmarked"
[ ! -s "$T/unmarked" ] && ok "4.1 every fixture file carries the part-of label" || ko "4.1 every fixture file carries the part-of label" "$(cat "$T/unmarked")"

# ---- 3.2 the probe plan ----------------------------------------------------------------------
cat >"$T/ns.json" <<'JSON'
{"items": [
 {"metadata": {"name": "ztd-data", "labels": {"ztd.facis.io/plane": "data", "istio-injection": "enabled"}}},
 {"metadata": {"name": "ztd-data-2", "labels": {"ztd.facis.io/plane": "data"}}},
 {"metadata": {"name": "ztd-mgmt", "labels": {"ztd.facis.io/plane": "management"}}},
 {"metadata": {"name": "spire-system", "labels": {"ztd.facis.io/plane": "management"}}},
 {"metadata": {"name": "istio-system", "labels": {"ztd.facis.io/plane": "management"}}},
 {"metadata": {"name": "kube-system", "labels": {}}}]}
JSON
cat >"$T/svc.json" <<'JSON'
{"items": [
 {"metadata": {"namespace": "ztd-mgmt", "name": "admin-api"}, "spec": {"selector": {"app": "admin-api"}, "ports": [{"port": 9000, "targetPort": 9000}]}},
 {"metadata": {"namespace": "ztd-mgmt", "name": "tsa-policy-engine"}, "spec": {"selector": {"app.kubernetes.io/name": "tsa-policy-engine"}, "ports": [{"port": 8080}]}},
 {"metadata": {"namespace": "spire-system", "name": "spire-server"}, "spec": {"selector": {"app": "server"}, "ports": [{"port": 8081}]}},
 {"metadata": {"namespace": "istio-system", "name": "istiod"}, "spec": {"selector": {"app": "istiod"}, "ports": [{"port": 15012}, {"port": 15017, "targetPort": 15017}]}},
 {"metadata": {"namespace": "kube-system", "name": "kube-dns"}, "spec": {"selector": {"k8s-app": "kube-dns"}, "ports": [{"port": 53}]}},
 {"metadata": {"namespace": "ztd-data-2", "name": "app"}, "spec": {"selector": {"app": "app"}, "ports": [{"port": 8443, "targetPort": 8443}]}}]}
JSON
cat >"$T/eps.json" <<'JSON'
{"items": [
 {"metadata": {"namespace": "ztd-mgmt", "labels": {"kubernetes.io/service-name": "admin-api"}}, "endpoints": [{"conditions": {"ready": true}, "targetRef": {"kind": "Pod", "name": "admin-api-0"}}], "ports": [{"port": 9000}]},
 {"metadata": {"namespace": "ztd-mgmt", "labels": {"kubernetes.io/service-name": "tsa-policy-engine"}}, "endpoints": [{"targetRef": {"kind": "Pod", "name": "tsa-policy-engine"}}], "ports": [{"port": 8080}]},
 {"metadata": {"namespace": "spire-system", "labels": {"kubernetes.io/service-name": "spire-server"}}, "endpoints": [{"targetRef": {"kind": "Pod", "name": "spire-server-0"}}], "ports": [{"port": 8081}]},
 {"metadata": {"namespace": "istio-system", "labels": {"kubernetes.io/service-name": "istiod"}}, "endpoints": [{"targetRef": {"kind": "Pod", "name": "istiod-1"}}], "ports": [{"port": 15012}, {"port": 15017}]},
 {"metadata": {"namespace": "kube-system", "labels": {"kubernetes.io/service-name": "kube-dns"}}, "endpoints": [{"targetRef": {"kind": "Pod", "name": "coredns"}}], "ports": [{"port": 53}]},
 {"metadata": {"namespace": "ztd-data-2", "labels": {"kubernetes.io/service-name": "app"}}, "endpoints": [{"targetRef": {"kind": "Pod", "name": "app-0"}}, {"targetRef": {"kind": "Pod", "name": "app-1"}}], "ports": [{"port": 8443}]}]}
JSON
cat >"$T/pods.json" <<'JSON'
{"items": [
 {"metadata": {"namespace": "ztd-mgmt", "name": "admin-api-0", "labels": {"app": "admin-api"}}, "spec": {"nodeName": "n1", "serviceAccountName": "admin", "containers": [{"name": "app", "ports": [{"containerPort": 9000}, {"containerPort": 9090}]}, {"name": "istio-proxy"}]}, "status": {"podIP": "10.0.0.5"}},
 {"metadata": {"namespace": "ztd-mgmt", "name": "tsa-policy-engine", "labels": {"app.kubernetes.io/name": "tsa-policy-engine"}}, "spec": {"nodeName": "n2", "containers": [{"name": "app"}]}, "status": {"podIP": "10.0.0.6"}},
 {"metadata": {"namespace": "spire-system", "name": "spire-server-0", "labels": {"app": "server"}}, "spec": {"nodeName": "n1", "containers": [{"name": "spire-server", "ports": [{"containerPort": 8081}, {"containerPort": 9988}]}]}, "status": {"podIP": "10.0.0.7"}},
 {"metadata": {"namespace": "istio-system", "name": "istiod-1", "labels": {"app": "istiod"}}, "spec": {"nodeName": "n2", "containers": [{"name": "discovery", "ports": [{"containerPort": 8080}]}]}, "status": {"podIP": "10.0.0.8"}},
 {"metadata": {"namespace": "kube-system", "name": "coredns", "labels": {"k8s-app": "kube-dns"}}, "spec": {"nodeName": "n1", "containers": [{"name": "c"}]}, "status": {"podIP": "10.0.0.9"}},
 {"metadata": {"namespace": "ztd-data-2", "name": "app-0", "labels": {"app": "app"}}, "spec": {"nodeName": "n1", "containers": [{"name": "app"}, {"name": "istio-proxy"}]}, "status": {"podIP": "10.0.1.1"}},
 {"metadata": {"namespace": "ztd-data-2", "name": "app-1", "labels": {"app": "app"}}, "spec": {"nodeName": "n2", "containers": [{"name": "app"}, {"name": "istio-proxy"}]}, "status": {"podIP": "10.0.1.2"}}]}
JSON
plan_plan "$T/rows.json" "$T/doc-rows-real.tsv" "$T/ns.json" "$T/svc.json" "$T/eps.json" "$T/pods.json" spire-system istio-system >"$T/plan.json"
problems=()
[ "$(jq -c .dataNamespaces "$T/plan.json")" = '["ztd-data","ztd-data-2"]' ] || problems+=("data namespaces: $(jq -c .dataNamespaces "$T/plan.json")")
jq -e '.destinations[] | select(.row == "catch-all" and .service == "admin-api" and .meshed and ([.targets[].port] == [9000, 9090]))' "$T/plan.json" >/dev/null || problems+=("admin-api not planned under the catch-all row on ports 9000 and 9090")
jq -e '.destinations[] | select(.row == "spire-server" and (.meshed | not) and ([.targets[].port] == [8081, 9988]))' "$T/plan.json" >/dev/null || problems+=("the SPIRE server not planned on every port")
jq -e '.destinations[] | select(.service == "istiod") | .targets[] | select(.port == 15012 and .declared)' "$T/plan.json" >/dev/null || problems+=("istiod 15012 not marked declared")
jq -e '[.destinations[] | select(.service == "tsa-policy-engine" or .service == "kube-dns")] | length == 0' "$T/plan.json" >/dev/null || problems+=("a row's destination or a non-management Service planned under the catch-all")
[ ${#problems[@]} -eq 0 ] && ok "3.2 the plan holds the second data-plane namespace and the unlisted management Service" || ko "3.2 the plan holds the second data-plane namespace and the unlisted management Service" "${problems[@]}"
problems=()
jq -e '.reverseDestinations | length == 1 and (.[0] | .row == "management-to-data" and .namespace == "ztd-data-2" and .service == "app" and .meshed and ([.pods[].name] == ["app-0", "app-1"]) and ([.targets[] | "\(.ip):\(.port)"] == ["10.0.1.1:8443", "10.0.1.2:8443"]))' "$T/plan.json" >/dev/null \
  || problems+=("reverse destinations: $(jq -c '[.reverseDestinations[] | {row, namespace, service}]' "$T/plan.json")")
[ "$(jq -c .sourceNamespaces "$T/plan.json")" = '["istio-system","spire-system","ztd-mgmt"]' ] || problems+=("sources: $(jq -c .sourceNamespaces "$T/plan.json")")
[ "$(jq -c .injectedNamespaces "$T/plan.json")" = '["ztd-data"]' ] || problems+=("injected: $(jq -c .injectedNamespaces "$T/plan.json")")
jq -e '[.destinations[] | select(.namespace == "ztd-data-2")] | length == 0' "$T/plan.json" >/dev/null || problems+=("a data-plane Service planned as a management-plane destination")
[ ${#problems[@]} -eq 0 ] && ok "9 the plan probes every data-plane Service (both replicas) from every management-plane namespace" || ko "9 the plan probes every data-plane Service from every management-plane namespace" "${problems[@]}"

# ---- 9 the management plane -> data plane direction -------------------------------------------
doc_reverse_rows "$REPO/docs/architecture.md" >"$T/rev.tsv" || ko "doc_reverse_rows reads docs/architecture.md"
out=$(plan_reverse_crosscheck "$T/rev.tsv"); rc=$?
[ "$rc" -eq 0 ] && grep -q '^OK ' <<<"$out" && ok "9 section 6 disposes management-to-data as DENY, the row the verifier probes" || ko "9 section 6 disposes management-to-data as DENY" "$out"
sed 's/\tDENY\t/\tALLOW\t/' "$T/rev.tsv" >"$T/rev-flip.tsv"
out=$(plan_reverse_crosscheck "$T/rev-flip.tsv"); rc=$?
[ "$rc" -ne 0 ] && grep -q 'row management-to-data: section 6 says ALLOW' <<<"$out" && ok "9 a flipped verdict of management-to-data fails, named" || ko "9 a flipped verdict of management-to-data fails, named" "$out"
: >"$T/rev-none.tsv"
out=$(plan_reverse_crosscheck "$T/rev-none.tsv"); rc=$?
[ "$rc" -ne 0 ] && grep -q 'no management plane -> data plane table' <<<"$out" && ok "9 a section 6 without the management plane -> data plane table fails" || ko "9 a section 6 without the table fails" "$out"
if [ -s "$T/umbrella.yaml" ]; then
  python3 -c 'import json,sys,yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
json.dump({"items": [d for d in docs if d.get("kind") == "Namespace"]}, open(sys.argv[2], "w"))
json.dump({"items": [d for d in docs if d.get("kind") in ("NetworkPolicy", "CiliumNetworkPolicy", "CiliumClusterwideNetworkPolicy", "AuthorizationPolicy")]}, open(sys.argv[3], "w"))' "$T/umbrella.yaml" "$T/rns.json" "$T/rpol.json"
  out=$(plan_reverse_rule "$T/rns.json" "$T/rpol.json" istio-system); rc=$?
  [ "$rc" -eq 0 ] && grep -q '^OK ' <<<"$out" && ok "9 the rendered umbrella admits no management plane -> data plane path" || ko "9 the rendered umbrella admits no management plane -> data plane path" "$out"
  # The parked ambient mode renders the umbrella's one clusterwide Cilium policy (the kubelet host-probe
  # exception, a single CIDR): it is read, and admits no management plane -> data plane path.
  helm template ztd "$REPO/deployment/helm/ztd" -f "$REPO/deployment/helm/ztd/ci/values.yaml" --set mesh.mode=ambient --set cni.cilium.enabled=true 2>/dev/null \
    | python3 -c 'import json,sys,yaml
docs = [d for d in yaml.safe_load_all(sys.stdin) if d]
json.dump({"items": [d for d in docs if d.get("kind") in ("NetworkPolicy", "CiliumNetworkPolicy", "CiliumClusterwideNetworkPolicy", "AuthorizationPolicy")]}, open(sys.argv[1], "w"))' "$T/rpol-ambient.json"
  out=$(plan_reverse_rule "$T/rns.json" "$T/rpol-ambient.json" istio-system); rc=$?
  [ "$rc" -eq 0 ] && grep -q '^OK ' <<<"$out" && jq -e '[.items[] | select(.kind == "CiliumClusterwideNetworkPolicy")] | length == 1' "$T/rpol-ambient.json" >/dev/null \
    && ok "9 the ambient umbrella's clusterwide Cilium policy (one CIDR) is read and admits no management plane -> data plane path" \
    || ko "9 the ambient umbrella's clusterwide Cilium policy is read and admits no management plane -> data plane path" "$out"
fi
cat >"$T/open-pol.json" <<'JSON'
{"items": [
 {"kind": "NetworkPolicy", "metadata": {"namespace": "ztd-data", "name": "allow-intra-plane"}, "spec": {"podSelector": {}, "ingress": [{"from": [{"podSelector": {}}]}], "egress": [{"to": [{"podSelector": {}}]}]}},
 {"kind": "NetworkPolicy", "metadata": {"namespace": "ztd-data", "name": "scrape"}, "spec": {"podSelector": {}, "ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"ztd.facis.io/plane": "management"}}}]}]}},
 {"kind": "NetworkPolicy", "metadata": {"namespace": "ztd-mgmt", "name": "to-data"}, "spec": {"podSelector": {}, "egress": [{"to": [{"namespaceSelector": {"matchExpressions": [{"key": "kubernetes.io/metadata.name", "operator": "In", "values": ["ztd-data-2"]}]}}]}]}},
 {"kind": "NetworkPolicy", "metadata": {"namespace": "ztd-mgmt", "name": "api"}, "spec": {"podSelector": {}, "egress": [{"to": [{"ipBlock": {"cidr": "10.0.0.1/32"}}]}]}},
 {"kind": "CiliumNetworkPolicy", "metadata": {"namespace": "ztd-data", "name": "cluster-in"}, "spec": {"ingress": [{"fromEntities": ["cluster"]}]}},
 {"kind": "AuthorizationPolicy", "metadata": {"namespace": "istio-system", "name": "default-deny"}, "spec": {}},
 {"kind": "AuthorizationPolicy", "metadata": {"namespace": "ztd-data", "name": "from-mgmt"}, "spec": {"rules": [{"from": [{"source": {"principals": ["spiffe://td/ns/ztd-mgmt/sa/x"]}}]}]}},
 {"kind": "AuthorizationPolicy", "metadata": {"namespace": "ztd-data", "name": "own"}, "spec": {"rules": [{"from": [{"source": {"namespaces": ["ztd-data"]}}]}]}},
 {"kind": "CiliumClusterwideNetworkPolicy", "metadata": {"name": "everyone-in"}, "spec": {"endpointSelector": {}, "ingress": [{"fromEntities": ["cluster"]}]}},
 {"kind": "CiliumClusterwideNetworkPolicy", "metadata": {"name": "mgmt-to-data-in"}, "specs": [{"endpointSelector": {"matchLabels": {"k8s:io.kubernetes.pod.namespace": "ztd-data-2"}}, "ingress": [{"fromEndpoints": [{"matchLabels": {"k8s:io.cilium.k8s.namespace.labels.ztd.facis.io/plane": "management"}}]}]}]},
 {"kind": "CiliumClusterwideNetworkPolicy", "metadata": {"name": "mgmt-out"}, "spec": {"endpointSelector": {"matchExpressions": [{"key": "io.kubernetes.pod.namespace", "operator": "In", "values": ["ztd-mgmt"]}]}, "egress": [{"toEndpoints": [{}]}]}},
 {"kind": "CiliumClusterwideNetworkPolicy", "metadata": {"name": "hostprobes"}, "spec": {"endpointSelector": {}, "ingress": [{"fromCIDR": ["169.254.7.127/32"]}]}},
 {"kind": "CiliumClusterwideNetworkPolicy", "metadata": {"name": "into-mgmt"}, "spec": {"endpointSelector": {"matchLabels": {"k8s:io.kubernetes.pod.namespace": "ztd-mgmt"}}, "ingress": [{"fromEndpoints": [{}]}]}},
 {"kind": "CiliumClusterwideNetworkPolicy", "metadata": {"name": "hosts"}, "spec": {"nodeSelector": {}, "ingress": [{"fromEntities": ["cluster"]}]}}]}
JSON
out=$(plan_reverse_rule "$T/ns.json" "$T/open-pol.json" istio-system); rc=$?
problems=()
for want in 'NetworkPolicy ztd-data/scrape: an ingress rule admits the management-plane namespace' 'NetworkPolicy ztd-mgmt/to-data: an egress rule admits the data-plane namespace(s) ztd-data-2' \
  'CiliumNetworkPolicy ztd-data/cluster-in: an ingress rule admits the entity cluster' 'AuthorizationPolicy ztd-data/from-mgmt: an ALLOW rule admits the management plane (ztd-mgmt)' \
  'CiliumClusterwideNetworkPolicy -/everyone-in: an ingress rule of the endpoints of ztd-data, ztd-data-2 admits the entity cluster' \
  'CiliumClusterwideNetworkPolicy -/mgmt-to-data-in: an ingress rule of the endpoints of ztd-data-2 admits endpoints of the management-plane namespace(s) ztd-mgmt, spire-system, istio-system' \
  'CiliumClusterwideNetworkPolicy -/mgmt-out: an egress rule of the endpoints of ztd-mgmt admits endpoints of the data-plane namespace(s) ztd-data, ztd-data-2'; do
  grep -qF "FAIL $want" <<<"$out" || problems+=("not named: $want")
done
grep -qE 'allow-intra-plane|ztd-mgmt/api|default-deny|ztd-data/own|hostprobes|into-mgmt|-/hosts' <<<"$out" && problems+=("a rule that does not open the direction is named")
[ "$rc" -ne 0 ] && [ ${#problems[@]} -eq 0 ] && ok "9 a rule that admits management plane -> data plane at either layer fails, named" || ko "9 a rule that admits management plane -> data plane fails, named" "${problems[@]}" "$out"
cat >"$T/pa.json" <<'JSON'
{"items": [
 {"metadata": {"namespace": "istio-system", "name": "default"}, "spec": {"mtls": {"mode": "STRICT"}}},
 {"metadata": {"namespace": "ztd-data-2", "name": "ns"}, "spec": {"mtls": {"mode": "PERMISSIVE"}}},
 {"metadata": {"namespace": "ztd-mgmt", "name": "wl"}, "spec": {"selector": {"matchLabels": {"app": "a"}}, "mtls": {"mode": "UNSET"}, "portLevelMtls": {"9090": {"mode": "DISABLE"}}}}]}
JSON
problems=()
m() { local got; got=$(plan_mtls_mode "$T/pa.json" "$2" "$3" "$4" istio-system); [ "$got" = "$1" ] || problems+=("$2 $3 $4: $got, expected $1"); }
m STRICT ztd-data '{}' 8080
m PERMISSIVE ztd-data-2 '{}' 8443
m STRICT ztd-mgmt '{"app":"a"}' 8080
m DISABLE ztd-mgmt '{"app":"a"}' 9090
[ ${#problems[@]} -eq 0 ] && ok "9 the mutual TLS mode in force follows Istio's precedence (port, workload, namespace, mesh)" || ko "9 the mutual TLS mode in force follows Istio's precedence" "${problems[@]}"

# ---- 6.2 refusals ----------------------------------------------------------------------------
mkdir -p "$T/bin"
cat >"$T/bin/kubectl" <<'SH'
#!/usr/bin/env bash
echo "$*" >>"$FAKE_LOG"
case "$*" in
  *"get nodes -o jsonpath"*providerID*) printf 'kind://docker/ztd/n1\nkind://docker/ztd/n2\n';;
  *"-l app.kubernetes.io/part-of=verify-plane-separation -o name"*) ;;
  *"get validatingadmissionpolicy proxy-takes-spire-socket -o json"*) [ -s "$FAKE_DIR/policy.json" ] || { echo 'Error from server (NotFound): validatingadmissionpolicies "proxy-takes-spire-socket" not found' >&2; exit 1; }; cat "$FAKE_DIR/policy.json";;
  *"get cm cilium-config -o json"*) cat "$FAKE_DIR/cilium-config.json";;
  *"get nodes -o json"*) cat "$FAKE_DIR/nodes.json";;
  *"version"*) echo '{}';;
  *) exit 1;;
esac
SH
chmod +x "$T/bin/kubectl"
export FAKE_LOG=$T/kubectl.log FAKE_DIR=$T
echo '{"data": {"routing-mode": "native", "ipv4-native-routing-cidr": "10.244.0.0/16", "enable-ipv4-masquerade": "true"}}' >"$T/cilium-config.json"
# The admission policy as zone-policy installs it: its capture validation reads variables.captureDefaults.
echo '{"spec": {"validations": [{"expression": "true"}, {"expression": "variables.captureDefaults.all(k, true)"}]}}' >"$T/policy.json"
cat >"$T/nodes.json" <<'JSON'
{"items": [{"metadata": {"name": "node-in"}, "spec": {"podCIDR": "10.244.1.0/24"}}, {"metadata": {"name": "node-out"}, "spec": {"podCIDR": "10.96.5.0/24"}}]}
JSON
inside=$REPO/scripts/verify-plane-separation/run-record-test
PATH=$T/bin:$PATH KUBE_CONTEXT=kind-fake ZTD_EVIDENCE_DIR=$inside "$HERE/verify.sh" >"$T/out" 2>&1; rc=$?
if [ "$rc" -eq 125 ] && [ ! -e "$inside" ] && grep -q 'refusing run directory' "$T/out"; then ok "6.2 a run directory inside the repository exits 125, nothing written"
else ko "6.2 a run directory inside the repository exits 125, nothing written" "exit $rc" "$(tail -2 "$T/out")"; rm -rf "$inside"; fi
PATH=$T/bin:$PATH CI=1 KUBE_CONTEXT=kind-fake ZTD_EVIDENCE_DIR=$T/ci-run "$HERE/verify.sh" >"$T/out" 2>&1; rc=$?
if [ "$rc" -eq 125 ] && [ ! -e "$T/ci-run" ]; then ok "6.2 CI=1 exits 125, nothing written"
else ko "6.2 CI=1 exits 125, nothing written" "exit $rc"; fi
PATH=$T/bin:$PATH KUBE_CONTEXT=other ZTD_EVIDENCE_DIR=$T/other-run "$HERE/verify.sh" >"$T/out" 2>&1; rc=$?
[ "$rc" -eq 125 ] && [ ! -e "$T/other-run" ] && ok "6.2 a context that is neither kind nor a participant exits 125" || ko "6.2 a context that is neither kind nor a participant exits 125" "exit $rc"

# A run killed while the capture validation was lifted (no trap ran) leaves the policy without it: the next
# run refuses before it creates or snapshots anything, and names the restore; so does a policy it cannot read.
cp "$T/policy.json" "$T/policy-installed.json"
echo '{"spec": {"validations": [{"expression": "true"}]}}' >"$T/policy.json"
: >"$FAKE_LOG"
PATH=$T/bin:$PATH KUBE_CONTEXT=kind-fake ZTD_EVIDENCE_DIR=$T/lifted-run "$HERE/verify.sh" >"$T/out" 2>&1; rc=$?
writes=$(grep -E ' (apply|exec|create|delete|patch) ' "$FAKE_LOG" || true)
if [ "$rc" -eq 125 ] && [ ! -e "$T/lifted-run" ] && [ -z "$writes" ] && grep -q 'holds no capture validation' "$T/out" \
  && grep -qF 'rollback zone-policy "$rev" --force-conflicts' "$T/out" && ! grep -q 'cilium-config' "$FAKE_LOG"; then
  ok "6.2 an admission policy left without its capture validation exits 125 before anything is read or created, naming the restore"
else ko "6.2 an admission policy left without its capture validation exits 125, naming the restore" "exit $rc" "writes: ${writes:-none}" "$(tail -2 "$T/out")"; fi
: >"$T/policy.json"
PATH=$T/bin:$PATH KUBE_CONTEXT=kind-fake ZTD_EVIDENCE_DIR=$T/nopolicy-run "$HERE/verify.sh" >"$T/out" 2>&1; rc=$?
[ "$rc" -eq 125 ] && [ ! -e "$T/nopolicy-run" ] && grep -q 'cannot read the admission policy proxy-takes-spire-socket' "$T/out" \
  && ok "6.2 an admission policy that cannot be read exits 125, nothing written" || ko "6.2 an admission policy that cannot be read exits 125" "exit $rc" "$(tail -2 "$T/out")"
cp "$T/policy-installed.json" "$T/policy.json"
ci_problems=()
[ "$(capture_index "$T/policy.json")" = 1 ] || ci_problems+=("installed policy: $(capture_index "$T/policy.json")")
echo '{"spec": {"validations": [{"expression": "true"}]}}' >"$T/policy-lifted.json"
[ "$(capture_index "$T/policy-lifted.json")" = null ] || ci_problems+=("lifted policy: $(capture_index "$T/policy-lifted.json")")
echo '{"spec": {}}' >"$T/policy-empty.json"
[ "$(capture_index "$T/policy-empty.json")" = null ] || ci_problems+=("policy without validations: $(capture_index "$T/policy-empty.json")")
[ ${#ci_problems[@]} -eq 0 ] && ok "capture index: found in the installed policy, null once lifted or without validations" || ko "capture index" "${ci_problems[@]}"

# ---- 6.3 the routing precondition ------------------------------------------------------------
: >"$FAKE_LOG"
PATH=$T/bin:$PATH KUBE_CONTEXT=kind-fake ZTD_EVIDENCE_DIR=$T/routing-run "$HERE/verify.sh" >"$T/out" 2>&1; rc=$?
probed=$(grep -E ' (apply|exec|create|delete|patch) ' "$FAKE_LOG" || true)
if [ "$rc" -ge 1 ] && [ "$rc" -le 124 ] && [ -z "$probed" ] && grep -q 'node-out' "$T/out" && ! grep -q 'node-in (' "$T/out" \
  && grep -q 'before any probe' "$T/routing-run/evidence.md" && [ "$(tail -n 1 "$T/out")" = "$T/routing-run" ]; then
  ok "6.3 native routing with masquerading and a pod range outside the native range stops the run before any probe, naming the node"
else ko "6.3 the routing precondition stops the run before any probe, naming the node" "exit $rc" "writes: ${probed:-none}" "$(tail -3 "$T/out")"; fi

# ---- the stand-ins expire on their own ---------------------------------------------------------
# A stand-in caller carries its row's labels and, where the zone has it, its real service account (so its
# SPIFFE identity); a run killed outright (no trap) would leave it running. Every Pod of the fixtures is
# bounded by activeDeadlineSeconds, well past a run's length.
dl_problems=$(python3 - "$HERE/fixtures" <<'PY2'
import glob, os, sys, yaml
for f in sorted(glob.glob(os.path.join(sys.argv[1], "**", "*.yaml"), recursive=True)):
    for d in yaml.safe_load_all(open(f)):
        if d and d.get("kind") == "Pod" and not (isinstance(d["spec"].get("activeDeadlineSeconds"), int) and 3600 <= d["spec"]["activeDeadlineSeconds"] <= 14400):
            print(f"{os.path.basename(f)} {d['metadata']['name']}: activeDeadlineSeconds {d['spec'].get('activeDeadlineSeconds')}")
PY2
)
[ -z "$dl_problems" ] && ok "every Pod of the fixtures stops on its own (activeDeadlineSeconds between 1 h and 4 h)" || ko "every Pod of the fixtures stops on its own" "$dl_problems"

# ---- address redaction ------------------------------------------------------------------------
# proof_mask (scripts/lib/proof.sh), shared with verify-mesh-identity: every IPv4 and IPv6 address of a
# participant cluster goes, a dual-stack node or pod address, a bracketed Hubble address, an IPv4-mapped
# one and a CIDR included; the loopbacks, the unspecified address, clock times, MAC addresses, digests and
# versions stay.
cat >"$T/mask-in.txt" <<'TXT'
node-1 Ready 10.0.0.5 fd00:10:244::5 2001:db8::1,10.244.1.7
Nov 10 20:01:26.123 ztd-data/probe-0 (fd00::a:1) -> [fd00:10:96::1]:8080 policy-verdict DROPPED
on 127.0.0.1:15000 [::1]:15000 [::]:15012 ::ffff:10.1.2.3 fe80::1%eth0.
sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b aa:bb:cc:dd:ee:ff 12:34:56 v1.31.1
{"ip":"2001:db8:0:0:0:0:0:2","cidr":"fd00:10:244::/64"} 10.244.0.0/16 from fd00::1: drop
hostIP:fd00::5 hostIP:10.0.0.5 podIP:2001:db8::7,
TXT
cat >"$T/mask-want.txt" <<'TXT'
node-1 Ready <address> <address> <address>,<address>
Nov 10 20:01:26.123 ztd-data/probe-0 (<address>) -> [<address>]:8080 policy-verdict DROPPED
on 127.0.0.1:15000 [::1]:15000 [::]:15012 <address> <address>.
sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b aa:bb:cc:dd:ee:ff 12:34:56 v1.31.1
{"ip":"<address>","cidr":"<address>/64"} <address>/16 from <address>: drop
hostIP:<address> hostIP:<address> podIP:<address>,
TXT
out=$(diff "$T/mask-want.txt" <(proof_mask "$T/mask-in.txt"))
[ -z "$out" ] && ok "address redaction: every IPv4 and IPv6 address goes; loopbacks, times, MAC addresses, digests and versions stay" \
  || ko "address redaction: every IPv4 and IPv6 address goes" "$out"
# A probe's HTTP body is cut by bytes (cut -c1-110), so a multibyte character at the cut leaves a byte
# that is no UTF-8 in the record: the mask passes it unchanged, masks the addresses around it and succeeds.
body="$(printf 'x%.0s' $(seq 109))é tail"
printf '| 403 %s | 10.0.0.9 fd00::9 |\n' "$(head -1 <<<"$body" | cut -c1-110)" >"$T/mask-bytes.md"
printf '| 403 %s | <address> <address> |\n' "$(head -1 <<<"$body" | cut -c1-110)" >"$T/mask-bytes-want.md"
( set -o pipefail; proof_mask "$T/mask-bytes.md" >"$T/mask-bytes-out.md" ); rc=$?
if [ "$rc" -eq 0 ] && cmp -s "$T/mask-bytes-want.md" "$T/mask-bytes-out.md"; then
  ok "address redaction: a record cut inside a multibyte character is masked byte for byte"
else
  ko "address redaction: a record cut inside a multibyte character is masked byte for byte" "rc $rc; $(cmp "$T/mask-bytes-want.md" "$T/mask-bytes-out.md" 2>&1)"
fi

# ---- network-layer attribution ---------------------------------------------------------------
# A drop counts; a refusal counts only with a Hubble drop line; a denial line in the destination's proxy
# always fails the probe.
nl_problems=()
nl() { network_layer "$2" "$3" "$4"; [ "$v" = "$1" ] || nl_problems+=("outcome '$2' evidence '$3' denial '$4': $v, expected $1"); }
nl pass 'denied(28)' 'Hubble not available on the node'"'"'s Cilium agent: the outcome rests on its class' ''
nl pass 'denied(28)' 'Hubble drop: Nov 9 ztd-data/probe-0 -> 10.0.0.1:8200 policy-verdict:none DENIED' ''
# With Hubble available and no policy drop for the flow, a timeout (or reset) is no network denial: an
# address no pod holds any more (a destination replaced since the plan) times out too.
nl fail 'denied(28)' 'no Hubble drop line read for the flow: the outcome rests on its class' ''
nl fail 'denied(56)' 'no Hubble drop line read for the flow: the outcome rests on its class' ''
nl fail '503 upstream connect error or disconnect/reset before headers. reset reason: connection timeout' 'no Hubble drop line read for the flow' ''
nl pass 'denied(56)' 'Hubble not available' ''
nl pass '503 upstream connect error or disconnect/reset before headers. reset reason: connection timeout' 'x' ''
nl pass '503 upstream connect error or disconnect/reset before headers. retried and the latest reset reason: connection tim' 'x' ''
nl fail 'denied(7)' 'Hubble not available on the node' ''
nl fail 'denied(7)' 'no Hubble drop line read for the flow' ''
nl pass 'denied(7)' 'Hubble drop: Nov 9 ztd-data/probe-0 -> 10.0.0.1:8080 policy-verdict:none DENIED' ''
nl fail '503 upstream connect error or disconnect/reset before headers. reset reason: connection failure' 'Hubble not available' ''
nl fail 'denied(28)' 'x' '{"source":"spiffe://td/ns/ztd-data/sa/a"}'
nl fail 'connected' 'x' ''
nl fail '200 ok' 'no Hubble drop line read for the flow: the outcome rests on its class' ''
nl fail 'denied(52)' 'x' ''
nl fail 'error(6)' 'x' ''
# A served attempt's evidence says it was served, not what a drop check read.
for o in '200 ok' 'connected' '404 not found'; do
  network_layer "$o" 'no Hubble drop line read for the flow: the outcome rests on its class' ''
  [[ $ev == "served: "* ]] || nl_problems+=("outcome '$o': evidence '$ev' does not say it was served")
done
network_layer 'error(6)' 'x' ''; [[ $ev == "the probe itself failed"* ]] || nl_problems+=("error(6): evidence '$ev'")
network_layer 'denied(28)' 'no Hubble drop line read for the flow: x' ''; [[ $ev == "dropped, but Hubble, available"* ]] || nl_problems+=("denied(28) without a Hubble drop: evidence '$ev'")
[ ${#nl_problems[@]} -eq 0 ] && ok "network layer: drops count (only with a Hubble drop where Hubble is available), refusals only with a Hubble drop, a denial line fails, a served attempt is named served" \
  || ko "network layer: drops count, refusals only with a Hubble drop, a denial line fails" "${nl_problems[@]}"

# ---- the run id stays a string label --------------------------------------------------------------
# 8 hex digits alone can read as an integer (12345678) or, to kubectl's YAML reader, a float (34230e05), and
# the API server refuses a label that is not a string; PyYAML reads 34230e05 as a string and writes it back
# unquoted, so the probers that verify.sh loads and dumps carry it plain. The run id leads with a letter,
# and every run label of the rendered probers (after that load and dump) and openings is that id, as a
# string that no YAML 1.1 or 1.2 resolver reads as a number.
rid_problems=()
numeric='^[-+]?(0x[0-9a-fA-F_]+|0o?[0-7_]+|[0-9][0-9_]*(:[0-5]?[0-9])*|(\.[0-9_]+|[0-9][0-9_]*(\.[0-9_]*)?)([eE][-+]?[0-9]+)?|\.(inf|Inf|INF|nan|NaN|NAN))$'
for _ in $(seq 50); do r=$(run_id); [[ $r =~ ^r[0-9a-f]{8}$ ]] || rid_problems+=("run_id gave '$r'"); done
for rid in r34230e05 r12345678 "$(run_id)"; do
  sed -e "s/__NS__/ztd-data/g" -e "s/__NODE__/n0/g" -e "s/__I__/0/g" -e "s/__RUN__/$rid/g" "$HERE/fixtures/probes.yaml" >"$T/probes-$rid.yaml"
  sed -e "s/__NS__/ztd-data/g" -e "s/__DEST_NS__/ztd-mgmt/g" -e "s/__PORT__/8080/g" -e "s/__RUN__/$rid/g" -e "s/__PROBER__/probe-0/g" \
    -e 's|__DEST_SELECTOR__|{"app.kubernetes.io/name":"tspa"}|g' "$HERE/fixtures/opening.yaml" >"$T/opening-$rid.yaml"
  python3 -c 'import sys, yaml
yaml.safe_dump_all([d for d in yaml.safe_load_all(open(sys.argv[1])) if d], open(sys.argv[2], "w"), sort_keys=False)' "$T/probes-$rid.yaml" "$T/probes-$rid.dumped.yaml"
  mapfile -t vals < <(grep -ho 'verify-plane-separation/run: [^,}]*' "$T/probes-$rid.dumped.yaml" "$T/opening-$rid.yaml" | sed 's/^verify-plane-separation\/run: //')
  [ ${#vals[@]} -eq 4 ] || rid_problems+=("run id $rid: ${#vals[@]} run labels found, expected 4 (two probers, two selectors)")
  for v in "${vals[@]}"; do
    plain=${v//\"/}; plain=${plain//\'/}
    [ "$plain" = "$rid" ] || rid_problems+=("run id $rid: label value $v")
    [ "$v" = "$plain" ] && [[ $v =~ $numeric ]] && rid_problems+=("run id $rid: plain label value $v reads as a number")
  done
done
[ ${#rid_problems[@]} -eq 0 ] && ok "run id: leads with a letter, so its label stays a string in the probers (after verify.sh's YAML load and dump) and the openings" \
  || ko "run id: the run label stays a string" "${rid_problems[@]}"

# ---- the probe outcome: curl's own exit code ----------------------------------------------------
# A loaded API server's kubectl exec returned 0 for a curl that timed out (the network had dropped the SYN),
# which the probe read as "connected": the outcome comes from curl's write-out line, whatever exec returns.
po_problems=()
po() { local got; got=$("$1" "$2"); [ "$got" = "$3" ] || po_problems+=("$1 '${2//$'\n'/\\n}': '$got', expected '$3'"); }
po tcp_outcome 'curl-exit=28' 'denied(28)'
po tcp_outcome 'curl-exit=7' 'denied(7)'
po tcp_outcome 'curl-exit=0' connected
po tcp_outcome 'curl-exit=56' connected
po tcp_outcome 'curl-exit=6' 'error(6)'
po tcp_outcome '' 'error(no exit code)'
po tcp_outcome 'curl-exit=' 'error(no exit code)'
po http_outcome $'hello\nsecond line\n200\ncurl-exit=0' '200 hello'
po http_outcome $'RBAC: access denied\n403\ncurl-exit=0' '403 RBAC: access denied'
po http_outcome $'\n000\ncurl-exit=28' 'denied(28)'
po http_outcome $'\n000\ncurl-exit=56' 'denied(56)'
po http_outcome $'\n000\ncurl-exit=6' 'error(6)'
po http_outcome '' 'error(no exit code)'
# Through tcp() and http() with kubectl exec stubbed: its exit status is ignored either way.
k() { printf '%s' "$STUB_OUT"; return "$STUB_RC"; }
STUB_OUT=$'curl-exit=28\n' STUB_RC=0; o=$(tcp ns pod 10.0.0.1 8200); [ "$o" = 'denied(28)' ] || po_problems+=("tcp, exec 0, curl 28: '$o'")
STUB_OUT='' STUB_RC=0; o=$(tcp ns pod 10.0.0.1 8200); [ "$o" = 'error(no exit code)' ] || po_problems+=("tcp, exec 0, no output: '$o'")
STUB_OUT='' STUB_RC=28; o=$(tcp ns pod 10.0.0.1 8200); [ "$o" = 'error(no exit code)' ] || po_problems+=("tcp, exec 28, no output: '$o'")
STUB_OUT=$'\n000\ncurl-exit=28\n' STUB_RC=0; o=$(http ns pod app http://x/); [ "$o" = 'denied(28)' ] || po_problems+=("http, exec 0, curl 28: '$o'")
# An attempt that observed nothing (no exit code in its output) is run again, at most three attempts in all,
# each written to $PROBE_NOTES; an attempt that holds any exit code is never run again.
k() { local n; n=$(($(cat "$T/calls") + 1)); echo "$n" >"$T/calls"; [ "$n" -le "$STUB_LOST" ] && { echo 'error: stream lost' >&2; return 0; }; printf '%s' "$STUB_OUT"; }
PROBE_NOTES=$T/notes
echo 0 >"$T/calls"; : >"$PROBE_NOTES"; STUB_LOST=1 STUB_OUT=$'curl-exit=28\n'; o=$(tcp ns pod 10.0.0.1 8200)
[ "$o" = 'denied(28)' ] && [ "$(cat "$T/calls")" = 2 ] && [ "$(grep -c 'attempt 1 held no curl exit code (kubectl exec exit 0; kubectl: error: stream lost)' "$PROBE_NOTES")" = 1 ] \
  || po_problems+=("one lost attempt, then curl 28: '$o' after $(cat "$T/calls") call(s), notes: $(cat "$PROBE_NOTES")")
echo 0 >"$T/calls"; : >"$PROBE_NOTES"; STUB_LOST=0 STUB_OUT=$'curl-exit=0\n'; o=$(tcp ns pod 10.0.0.1 8200)
[ "$o" = connected ] && [ "$(cat "$T/calls")" = 1 ] && [ ! -s "$PROBE_NOTES" ] || po_problems+=("served at once: '$o' after $(cat "$T/calls") call(s)")
echo 0 >"$T/calls"; : >"$PROBE_NOTES"; STUB_LOST=0 STUB_OUT=$'\n000\ncurl-exit=6\n'; o=$(http ns pod app http://x/)
[ "$o" = 'error(6)' ] && [ "$(cat "$T/calls")" = 1 ] || po_problems+=("an error with an exit code is not run again: '$o' after $(cat "$T/calls") call(s)")
echo 0 >"$T/calls"; : >"$PROBE_NOTES"; STUB_LOST=9 STUB_OUT=$'curl-exit=28\n'; o=$(tcp ns pod 10.0.0.1 8200)
[ "$o" = 'error(no exit code)' ] && [ "$(cat "$T/calls")" = 3 ] && [ "$(grep -c . "$PROBE_NOTES")" = 3 ] \
  || po_problems+=("three lost attempts: '$o' after $(cat "$T/calls") call(s), $(grep -c . "$PROBE_NOTES") note(s)")
unset -f k; unset PROBE_NOTES
[ ${#po_problems[@]} -eq 0 ] && ok "probe outcome: curl's own exit code decides; an exec status of 0 for a timed-out curl reads denied(28); only an attempt that observed nothing is run again (three at most, each recorded)" \
  || ko "probe outcome: curl's own exit code decides" "${po_problems[@]}"

# ---- the plain-text probe behind an opening ----------------------------------------------------
pt_problems=()
pt() { plaintext_layer "$2" "$3" "$4" "$5"; [ "$v" = "$1" ] || pt_problems+=("outcome '$2' mode '$3' forwarded '$4' hubble '$5': $v ($ev), expected $1"); }
pt pass 'denied(56)' STRICT 'Nov 10 a -> b:8202 to-endpoint FORWARDED (TCP Flags: ACK, PSH)' 1
pt pass 'denied(56)' STRICT '' 0
pt fail 'denied(56)' STRICT '' 1
pt fail 'denied(56)' PERMISSIVE 'x PSH' 1
pt fail 'denied(28)' STRICT '' 1
pt fail '200 ok' STRICT 'x PSH' 1
pt fail 'connected' STRICT '' 0
[ ${#pt_problems[@]} -eq 0 ] && ok "plain text: only a reset under mutual TLS STRICT that reached the destination counts" || ko "plain text: only a reset under mutual TLS STRICT counts" "${pt_problems[@]}"

# ---- a destination without a proxy -------------------------------------------------------------
# A management-plane destination without a proxy (the SPIRE and Istio control planes) is n/a at the mesh
# layer; a data-plane one fails the run, with a reason that names that case.
unmeshed_layer destinations; um1="$v|$ev"
unmeshed_layer reverseDestinations; um2="$v|$ev"
[[ $um1 == "n/a|"*"control planes are not meshed"* ]] && [[ $um2 == "fail|a data-plane workload without a proxy"* ]] \
  && ok "no proxy: n/a for a management-plane destination, a failure for a data-plane one" \
  || ko "no proxy: n/a for a management-plane destination, a failure for a data-plane one" "$um1" "$um2"

# ---- the per-row decision --------------------------------------------------------------------
# The cases internal/bdd's decider is held to as well (TestDecidePlaneMatrixSharedCases): the verdict of
# each row, then "held" or "not held".
for f in "$REPO"/internal/bdd/testdata/plane-matrix/*.csv; do
  out=$(plan_decide "$f"); rc=$?
  got=$({ grep -v '^FAIL ' <<<"$out"; [ "$rc" -eq 0 ] && echo held || echo 'not held'; } | grep -v '^$')
  [ "$got" = "$(cat "${f%.csv}.want")" ] && ok "decide: $(basename "$f" .csv)" || ko "decide: $(basename "$f" .csv)" "$out"
done

echo
[ "$failed" -eq 0 ] && echo "verify_test: all cases passed" || echo "verify_test: $failed case(s) failed"
exit $(( failed > 0 ))
