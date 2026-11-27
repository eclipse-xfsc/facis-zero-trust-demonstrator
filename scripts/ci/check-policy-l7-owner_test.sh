#!/usr/bin/env bash
# Cases for check-policy-l7-owner.sh: an http rule planted in a rendered Cilium policy fails the check,
# naming the policy, its namespace and the rule kind; a kafka rule in the second entry of a specs list
# too; each port field that sends traffic to Cilium's L7 proxy without a rule (listener, serverNames,
# terminatingTLS, originatingTLS), and an Envoy configuration of Cilium, fail too; an allow-matrix policy whose owner annotation is removed fails, naming the policy, its namespace
# and its kind, at both layers (a NetworkPolicy of the umbrella and an AuthorizationPolicy of
# zone-policy); a dns rule passes; the clean renderings and the committed zone files pass. Every input is
# written to a temporary directory.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
check=$here/check-policy-l7-owner.sh
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

# The CI zone's renderings: the umbrella, and zone-policy through the installer (which also renders
# ztd-openbao).
zone=$root/deployment/helm/ztd/ci/values.yaml
helm template ztd "$root/deployment/helm/ztd" -n ztd-system -f "$zone" >"$work/ztd.yaml"
ZONE_VALUES=$zone RENDER_DIR=$work/mesh "$root/scripts/install-zone/install.sh" render zone-policy >/dev/null
cp "$work/mesh/zone-policy.yaml" "$work/zone-policy.yaml"

# plant <in> <out> <python statement on the list of documents `docs`>: a planted copy of a rendering;
# the statement sets `planted` true when it found its target
plant() {
  python3 - "$1" "$2" "$3" <<'PY'
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
planted = False
def named(kind, name):
    return [d for d in docs if d.get("kind") == kind and d["metadata"]["name"] == name]
exec(sys.argv[3])
if not planted:
    sys.exit("the test found nothing to plant in: " + sys.argv[3])
yaml.safe_dump_all(docs, open(sys.argv[2], "w"), sort_keys=False)
PY
}

# 1. An http rule in a rendered Cilium policy: the API lane of the management plane.
mkdir -p "$work/http"
plant "$work/ztd.yaml" "$work/http/ztd.yaml" '
for d in docs:
    if d.get("kind") == "CiliumNetworkPolicy" and d["metadata"]["name"] == "allow-kube-api-egress" and d["metadata"]["namespace"] == "ztd-mgmt":
        d["spec"]["egress"][0]["toPorts"] = [{"ports": [{"port": "443", "protocol": "TCP"}], "rules": {"http": [{"method": "GET"}]}}]
        planted = True'
expect "a planted http rule fails, naming the policy, its namespace and the rule kind" 1 \
  'FAIL planted: ztd CiliumNetworkPolicy ztd-mgmt/allow-kube-api-egress: L7 rule http at spec\.egress\.0\.toPorts\.0\.rules\.http' \
  --manifest planted "$work/http/ztd.yaml"

# 2. A kafka rule in the second entry of a specs list, on a cluster-wide policy.
mkdir -p "$work/kafka"
python3 - "$work/kafka/extra.yaml" <<'PY'
import sys, yaml
yaml.safe_dump({"apiVersion": "cilium.io/v2", "kind": "CiliumClusterwideNetworkPolicy",
                "metadata": {"name": "planted-kafka"},
                "specs": [{"endpointSelector": {}, "egress": [{"toEntities": ["kube-apiserver"]}]},
                          {"endpointSelector": {}, "ingress": [{"toPorts": [{"ports": [{"port": "9092"}], "rules": {"kafka": [{"topic": "t"}]}}]}]}]},
               open(sys.argv[1], "w"))
PY
expect "a kafka rule in specs[1] of a cluster-wide policy fails" 1 \
  'FAIL planted: extra CiliumClusterwideNetworkPolicy <cluster>/planted-kafka: L7 rule kafka at specs\.1\.ingress\.0\.toPorts\.0\.rules\.kafka' \
  --manifest planted "$work/kafka/extra.yaml"

# 3. A dns rule is not L7 enforcement on a meshed path: it passes.
mkdir -p "$work/dns"
python3 - "$work/dns/extra.yaml" <<'PY'
import sys, yaml
yaml.safe_dump({"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
                "metadata": {"name": "dns-aware", "namespace": "ztd-data"},
                "spec": {"endpointSelector": {}, "egress": [{"toPorts": [{"ports": [{"port": "53", "protocol": "ANY"}], "rules": {"dns": [{"matchPattern": "*"}]}}]}]}},
               open(sys.argv[1], "w"))
PY
expect "a dns rule passes" 0 "planted: 1 Cilium objects, 0 allow-matrix policies, none sends traffic to Cilium's L7 proxy" \
  --manifest planted "$work/dns/extra.yaml"

# 3b. Each port field that sends traffic to Cilium's proxy without an L7 rule, one per policy, and an
# Envoy configuration of Cilium, namespaced and cluster-wide.
mkdir -p "$work/proxy"
python3 - "$work/proxy" <<'PY'
import sys, yaml
fields = {"listener": {"envoyConfig": {"kind": "CiliumEnvoyConfig", "name": "x"}, "name": "l"},
          "serverNames": ["outbound_.8080_._.tsa-policy-engine.ztd-mgmt.svc.cluster.local"],
          "terminatingTLS": {"secret": {"name": "t"}},
          "originatingTLS": {"secret": {"name": "t"}}}
for k, v in fields.items():
    yaml.safe_dump({"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
                    "metadata": {"name": f"planted-{k.lower()}", "namespace": "ztd-data"},
                    "spec": {"endpointSelector": {}, "egress": [{"toPorts": [{"ports": [{"port": "8080", "protocol": "TCP"}], k: v}]}]}},
                   open(f"{sys.argv[1]}/{k}.yaml", "w"))
for kind, ns in (("CiliumEnvoyConfig", "ztd-mgmt"), ("CiliumClusterwideEnvoyConfig", None)):
    meta = {"name": "planted-envoy"} | ({"namespace": ns} if ns else {})
    yaml.safe_dump({"apiVersion": "cilium.io/v2", "kind": kind, "metadata": meta,
                    "spec": {"services": [{"name": "tsa-policy-engine", "namespace": "ztd-mgmt"}], "resources": []}},
                   open(f"{sys.argv[1]}/{kind}.yaml", "w"))
PY
for k in listener serverNames terminatingTLS originatingTLS; do
  expect "the field $k without an L7 rule fails, naming the policy and the field" 1 \
    "FAIL planted: $k CiliumNetworkPolicy ztd-data/planted-${k,,}: redirect to Cilium's proxy $k at spec\.egress\.0\.toPorts\.0\.$k" \
    --manifest planted "$work/proxy/$k.yaml"
done
expect "a CiliumEnvoyConfig fails, naming it" 1 \
  'FAIL planted: CiliumEnvoyConfig CiliumEnvoyConfig ztd-mgmt/planted-envoy: an Envoy configuration of Cilium' \
  --manifest planted "$work/proxy/CiliumEnvoyConfig.yaml"
expect "a CiliumClusterwideEnvoyConfig fails, naming it" 1 \
  'FAIL planted: CiliumClusterwideEnvoyConfig CiliumClusterwideEnvoyConfig <cluster>/planted-envoy: an Envoy configuration of Cilium' \
  --manifest planted "$work/proxy/CiliumClusterwideEnvoyConfig.yaml"

# 4. An owner annotation removed, at each layer.
mkdir -p "$work/owner"
plant "$work/ztd.yaml" "$work/owner/ztd.yaml" '
for d in named("NetworkPolicy", "allow-pdp-adapter-to-tsa-ingress"):
    d["metadata"]["annotations"].pop("ztd.facis.io/l7-owner")
    planted = True'
expect "a NetworkPolicy of a row without its owner fails, naming the policy, its namespace and its kind" 1 \
  'FAIL planted: ztd NetworkPolicy ztd-mgmt/allow-pdp-adapter-to-tsa-ingress: allow-matrix policy of pdp-adapter-to-tsa without the annotation ztd.facis.io/l7-owner' \
  --manifest planted "$work/owner/ztd.yaml"
plant "$work/zone-policy.yaml" "$work/owner/zone-policy.yaml" '
for d in named("AuthorizationPolicy", "allow-backend-to-verification-service"):
    d["metadata"]["annotations"].pop("ztd.facis.io/l7-owner")
    planted = True'
expect "an AuthorizationPolicy of a pair without its owner fails" 1 \
  'FAIL planted: zone-policy AuthorizationPolicy ztd-mgmt/allow-backend-to-verification-service: allow-matrix policy of backend-to-verification-service without the annotation' \
  --manifest planted "$work/owner/zone-policy.yaml"
plant "$work/zone-policy.yaml" "$work/owner/cilium-owner.yaml" '
for d in named("AuthorizationPolicy", "allow-pdp-adapter-to-tsa"):
    d["metadata"]["annotations"]["ztd.facis.io/l7-owner"] = "cilium"
    planted = True'
expect "an owner other than sidecar or none fails" 1 \
  "allow-pdp-adapter-to-tsa: allow-matrix policy of pdp-adapter-to-tsa names the L7 owner 'cilium'" \
  --manifest planted "$work/owner/cilium-owner.yaml"

# 5. The clean renderings, and the committed zone files and the CI zone file.
expect "the clean renderings pass, listing each owner" 0 \
  'ztd-mgmt/allow-pdp-adapter-to-tsa \(pdp-adapter-to-tsa\): sidecar' \
  --manifest clean "$work/ztd.yaml" "$work/zone-policy.yaml"
expect "every committed zone file passes" 0 "no Cilium object of any zone sends traffic to Cilium's L7 proxy"

if [ "$failures" -ne 0 ]; then
  echo "$failures case(s) failed"
  exit 1
fi
echo "every case passed"
