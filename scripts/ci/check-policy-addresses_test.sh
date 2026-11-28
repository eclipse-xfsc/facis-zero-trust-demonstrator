#!/usr/bin/env bash
# Cases for check-policy-addresses.sh: an ipBlock planted in a rendering it is given fails the check,
# naming the policy; a zone file that turns the API lane on without Cilium (the derogation branch of
# the umbrella, an ipBlock to the API server's address) is reported, naming the zone file and the
# policy; an address with a port, an IPv6 address starting with "::" and Istio's negated block keys
# (notIpBlocks, notRemoteIpBlocks) fail, while host names and SPIFFE principals pass; the committed
# zone files pass. Every input is written to a temporary directory.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
check=$here/check-policy-addresses.sh
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

command -v helm >/dev/null || { echo 'helm is not on PATH - the cases need it' >&2; exit 1; }
python3 -c 'import yaml' 2>/dev/null || { echo 'python3 needs PyYAML - the cases need it' >&2; exit 1; }

failures=0
fail() { # case detail
  echo "FAIL  $1 ($2)"
  sed 's/^/        /' "$work/log"
  failures=$((failures + 1))
}
# expect <case> <want-exit> <grep pattern the output must hold> <check argument...>
expect() {
  local name=$1 want=$2 pattern=$3 got
  shift 3
  if "$check" "$@" >"$work/log" 2>&1; then got=0; else got=$?; fi
  if [ "$got" != "$want" ]; then fail "$name" "exit $got, want $want"
  elif ! grep -qE -- "$pattern" "$work/log"; then fail "$name" "the output does not match /$pattern/"
  else echo "ok    $name"; fi
}

# 1. A planted ipBlock: the CI zone's umbrella rendering with one ingress rule of the matrix lane
#    pdp-adapter-to-tsa widened to an address block.
helm template ztd "$root/deployment/helm/ztd" -n ztd-system -f "$root/deployment/helm/ztd/ci/values.yaml" >"$work/clean.yaml"
python3 - "$work/clean.yaml" "$work/ztd.yaml" <<'PY'
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
planted = False
for d in docs:
    if d.get("kind") == "NetworkPolicy" and d["metadata"]["name"] == "allow-pdp-adapter-to-tsa-ingress":
        d["spec"]["ingress"][0]["from"].append({"ipBlock": {"cidr": "10.0.0.0/8"}})
        planted = True
if not planted:
    sys.exit("the test found no allow-pdp-adapter-to-tsa-ingress to plant an ipBlock in")
yaml.safe_dump_all(docs, open(sys.argv[2], "w"), sort_keys=False)
PY
expect "a planted ipBlock fails, naming the policy" 1 \
  'FAIL planted: ztd NetworkPolicy ztd-mgmt/allow-pdp-adapter-to-tsa-ingress: key ipBlock' \
  --manifest planted "$work/ztd.yaml"
expect "the same rendering without it passes" 0 'planted: [0-9]+ policies, no undeclared address' \
  --manifest planted "$work/clean.yaml"

# 2. The derogation branch: the API lane on, Cilium off (and so no mesh, which the umbrella refuses
#    without Cilium). The umbrella renders the ipBlock lane and the check reports it.
python3 - "$root/deployment/helm/ztd/ci/values.yaml" "$work/derogated.yaml" <<'PY'
import sys, yaml
zone = yaml.safe_load(open(sys.argv[1]))
zone.setdefault("cni", {}).setdefault("cilium", {})["enabled"] = False
zone.setdefault("mesh", {})["mode"] = "none"
api = zone.setdefault("networkPolicy", {}).setdefault("kubeApi", {})
api["enabled"] = True
api["cidrs"] = ["172.18.0.0/16"]
for opening in ("meshControlPlane", "controlPlaneWebhooks", "identityServer"):
    zone["networkPolicy"].setdefault(opening, {})["enabled"] = False
yaml.safe_dump(zone, open(sys.argv[2], "w"), sort_keys=False)
PY
expect "a zone with the API lane and no Cilium is reported" 1 \
  "FAIL $work/derogated.yaml: ztd NetworkPolicy [a-z-]+/allow-kube-api-egress: key ipBlock" \
  "$work/derogated.yaml"

# 3. Addresses that a plain parse misses, each alone in an AuthorizationPolicy: an IPv4 address with
#    a port, a bracketed IPv6 address with a port, IPv6 addresses starting with "::" (loopback and
#    IPv4-mapped), and Istio's negated block keys. A host name with a port and a SPIFFE principal
#    are not addresses and pass.
# policy <file> <source or to> <key> <JSON list>: one AuthorizationPolicy with that one field.
policy() {
  local field
  case $2 in
    source) field="- from: [{source: {$3: $4}}]" ;;
    to) field="- to: [{operation: {$3: $4}}]" ;;
  esac
  cat >"$1" <<EOF
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: {name: planted, namespace: ztd-mgmt}
spec:
  action: ALLOW
  rules:
    $field
EOF
}
ap='planted: [a-z0-9-]+ AuthorizationPolicy ztd-mgmt/planted'
policy "$work/v4-port.yaml" to hosts '["10.0.0.1:8080"]'
expect "an IPv4 address with a port fails" 1 "FAIL $ap: address 10\.0\.0\.1 at spec\.rules\.0\.to\.0\.operation\.hosts\.0" \
  --manifest planted "$work/v4-port.yaml"
policy "$work/v6-port.yaml" to hosts '["[fd00::1]:8080"]'
expect "a bracketed IPv6 address with a port fails" 1 "FAIL $ap: address \[fd00::1\]:8080 at spec\.rules\.0\.to\.0\.operation\.hosts\.0" \
  --manifest planted "$work/v6-port.yaml"
policy "$work/v6-loopback.yaml" to hosts '["::1"]'
expect "an IPv6 address starting with :: fails" 1 "FAIL $ap: address ::1 at spec\.rules\.0\.to\.0\.operation\.hosts\.0" \
  --manifest planted "$work/v6-loopback.yaml"
policy "$work/v6-mapped.yaml" source principals '["::ffff:10.1.2.3"]'
expect "an IPv4-mapped IPv6 address fails" 1 "FAIL $ap: address ::ffff:10\.1\.2\.3 at spec\.rules\.0\.from\.0\.source\.principals\.0" \
  --manifest planted "$work/v6-mapped.yaml"
policy "$work/not-ip.yaml" source notIpBlocks '["::1"]'
expect "the key notIpBlocks fails" 1 "FAIL $ap: key notIpBlocks at spec\.rules\.0\.from\.0\.source\.notIpBlocks" \
  --manifest planted "$work/not-ip.yaml"
policy "$work/not-remote.yaml" source notRemoteIpBlocks '["::ffff:10.1.2.3"]'
expect "the key notRemoteIpBlocks fails" 1 "FAIL $ap: key notRemoteIpBlocks at spec\.rules\.0\.from\.0\.source\.notRemoteIpBlocks" \
  --manifest planted "$work/not-remote.yaml"
policy "$work/names.yaml" source principals '["cluster.local/ns/ztd-mgmt/sa/ztd-openbao-bootstrap"]'
printf -- '---\n' >>"$work/names.yaml"
policy "$work/names-to.yaml" to hosts '["openbao.ztd-mgmt.svc.cluster.local:8200"]'
cat "$work/names-to.yaml" >>"$work/names.yaml"
expect "a host name with a port and a SPIFFE principal pass" 0 'planted: 2 policies, no undeclared address' \
  --manifest planted "$work/names.yaml"

# 4. The Connector gateway's edge hops outside the mesh: declared only in a connector-gateway render
#    (--edge-manifest) and only in the exact shape the chart renders; the annotations alone admit nothing.
edge() { # file hop kind spec-yaml [route]
  { printf 'apiVersion: v1\nkind: %s\nmetadata:\n  name: edge\n  namespace: ztd-data\n  annotations:\n' "$3"
    printf '    ztd.facis.io/connector-hop: %s\n' "$2"
    [ -n "${5:-}" ] && printf '    ztd.facis.io/connector-route: %s\n' "$5"
    printf 'spec:\n%s\n' "$4"; } >"$1"
}
peer='  endpointSelector: {matchLabels: {io.cilium.k8s.policy.serviceaccount: ztd-connector-gateway}}
  egress: [{toCIDR: ["192.0.2.10/32"], toPorts: [{ports: [{port: "443", protocol: TCP}]}]}]'
entry='  podSelector: {matchLabels: {app: gw}}
  policyTypes: [Ingress]
  ingress: [{from: [{ipBlock: {cidr: 0.0.0.0/0}}], ports: [{protocol: TCP, port: 8443}]}]'
edge "$work/edge-peer.yaml" gateway-to-peer CiliumNetworkPolicy "$peer" egress
expect "the gateway's egress to the peer entry is declared in a gateway render" 0 \
  'EDGE planted: edge-peer CiliumNetworkPolicy ztd-data/edge: declared Connector edge hop gateway-to-peer' \
  --edge-manifest planted "$work/edge-peer.yaml"
expect "the same hop outside a gateway render fails" 1 'FAIL planted: edge-peer CiliumNetworkPolicy ztd-data/edge: key toCIDR' \
  --manifest planted "$work/edge-peer.yaml"
edge "$work/edge-entry.yaml" outside-to-entry NetworkPolicy "$entry" ingress
expect "the entry's public ingress is declared in a gateway render" 0 'EDGE planted: edge-entry NetworkPolicy' \
  --edge-manifest planted "$work/edge-entry.yaml"
edge "$work/edge-noroute.yaml" gateway-to-peer CiliumNetworkPolicy "$peer"
expect "the hop annotation without a route fails" 1 'FAIL planted: edge-noroute CiliumNetworkPolicy ztd-data/edge: key toCIDR' \
  --edge-manifest planted "$work/edge-noroute.yaml"
edge "$work/edge-wide.yaml" gateway-to-peer CiliumNetworkPolicy '  endpointSelector: {matchLabels: {app: backend}}
  egress: [{toCIDR: ["10.0.0.0/8"]}]' egress
expect "a peer hop with another selector, a range and no ports fails" 1 'FAIL planted: edge-wide CiliumNetworkPolicy ztd-data/edge: key toCIDR' \
  --edge-manifest planted "$work/edge-wide.yaml"
edge "$work/edge-ingress.yaml" gateway-to-peer CiliumNetworkPolicy "$peer
  ingress: [{fromCIDR: [\"10.0.0.0/8\"]}]" egress
expect "a peer hop that also admits ingress fails" 1 'FAIL planted: edge-ingress CiliumNetworkPolicy ztd-data/edge: key fromCIDR' \
  --edge-manifest planted "$work/edge-ingress.yaml"
edge "$work/edge-kind.yaml" outside-to-entry CiliumNetworkPolicy "$peer" ingress
expect "an entry hop of another kind fails" 1 'FAIL planted: edge-kind CiliumNetworkPolicy ztd-data/edge: key toCIDR' \
  --edge-manifest planted "$work/edge-kind.yaml"
for bad in 0 '""' null; do
  edge "$work/edge-port.yaml" gateway-to-peer CiliumNetworkPolicy "  endpointSelector: {matchLabels: {io.cilium.k8s.policy.serviceaccount: ztd-connector-gateway}}
  egress: [{toCIDR: [\"192.0.2.10/32\"], toPorts: [{ports: [{port: $bad, protocol: TCP}]}]}]" egress
  expect "a peer hop on port $bad (every port) fails" 1 'FAIL planted: edge-port CiliumNetworkPolicy ztd-data/edge: key toCIDR' \
    --edge-manifest planted "$work/edge-port.yaml"
done
edge "$work/edge-null.yaml" outside-to-entry NetworkPolicy '  podSelector: {matchLabels: {app: gw}}
  policyTypes: [Ingress]
  ingress: [{from: [{ipBlock: {cidr: 0.0.0.0/0}}], ports: [{protocol: TCP, port: null}]}]' ingress
expect "an entry hop without a port fails" 1 'FAIL planted: edge-null NetworkPolicy ztd-data/edge: key ipBlock' \
  --edge-manifest planted "$work/edge-null.yaml"
gw=$root/deployment/helm/connector-gateway
for bad in 0 70000 '""'; do
  if helm template g "$gw" -f "$gw/ci/values.yaml" --set-string "egress.peer.port=$bad" >/dev/null 2>"$work/gw.err"; then
    fail "the gateway chart refuses egress.peer.port=$bad" "it rendered"
  elif ! grep -q 'egress.peer.port must be one TCP port' "$work/gw.err"; then
    fail "the gateway chart refuses egress.peer.port=$bad" "$(head -1 "$work/gw.err")"
  else echo "ok    the gateway chart refuses egress.peer.port=$bad"; fi
done
if helm template g "$gw" -f "$gw/ci/values.yaml" -f "$gw/ci/ingress-values.yaml" --set-string ingress.port=0 >/dev/null 2>"$work/gw.err" \
  || ! grep -q 'ingress.port must be one TCP port' "$work/gw.err"; then
  fail "the gateway chart refuses ingress.port=0" "$(head -1 "$work/gw.err")"
else echo "ok    the gateway chart refuses ingress.port=0"; fi
python3 - "$work/ztd.yaml" "$work/annotated.yaml" <<'PY'
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
for d in docs:
    if d.get("kind") == "NetworkPolicy" and d["metadata"]["name"] == "allow-pdp-adapter-to-tsa-ingress":
        d["metadata"].setdefault("annotations", {}).update({"ztd.facis.io/connector-hop": "outside-to-entry", "ztd.facis.io/connector-route": "ingress"})
        d["spec"]["ingress"][0]["from"].append({"ipBlock": {"cidr": "10.0.0.0/8"}})
yaml.safe_dump_all(docs, open(sys.argv[2], "w"), sort_keys=False)
PY
expect "an in-mesh policy given the edge annotations still fails" 1 \
  'FAIL planted: annotated NetworkPolicy ztd-mgmt/allow-pdp-adapter-to-tsa-ingress: key ipBlock' \
  --edge-manifest planted "$work/annotated.yaml"

# 5. The committed zone files, the CI zone file and the component charts.
expect "every committed zone file and component chart passes" 0 'no policy of any zone or component chart names an undeclared address'

if [ "$failures" -ne 0 ]; then
  echo "$failures case(s) failed"
  exit 1
fi
echo "every case passed"
