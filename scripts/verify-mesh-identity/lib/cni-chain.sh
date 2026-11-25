# shellcheck shell=bash
# The per-node reading of the CNI chain, shared by the mesh identity proof
# (scripts/verify-mesh-identity/verify.sh, section default-deny-with-chained-cni) and the proof of the chain
# across a Cilium upgrade (scripts/verify-cni-chaining-upgrade/verify.sh), so that the two cannot drift.
# Sourced, never run. Reads only: a kubectl exec into each Istio CNI node agent, which mounts the node's
# CNI configuration directory at /host/etc/cni/net.d.
#
#   cni_chain <context> <istio namespace>
#       one tab-separated line per istio-cni-node pod: <node> <conflist path on the node> <plugin types,
#       joined by " → ">; the path and the order are empty when they cannot be read
#   cni_chain_ok <plugin order>
#       status 0 when the order lists the Istio plugin after Cilium (cilium-cni first, istio-cni after it)

cni_chain() {
  local ctx=$1 ns=$2 pod node conf plugins
  for pod in $(kubectl --context "$ctx" -n "$ns" get pod -l k8s-app=istio-cni-node -o jsonpath='{.items[*].metadata.name}'); do
    node=$(kubectl --context "$ctx" -n "$ns" get pod "$pod" -o jsonpath='{.spec.nodeName}')
    conf=$(kubectl --context "$ctx" -n "$ns" exec "$pod" -- sh -c 'ls /host/etc/cni/net.d/*.conflist | head -1')
    plugins=$(kubectl --context "$ctx" -n "$ns" exec "$pod" -- cat "$conf" | jq -r '[.plugins[].type] | join(" → ")')
    printf '%s\t%s\t%s\n' "$node" "${conf#/host}" "$plugins"
  done
}

cni_chain_ok() {
  [[ "$1" == cilium-cni*istio-cni* ]]
}
