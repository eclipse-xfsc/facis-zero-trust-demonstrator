#!/usr/bin/env bash
# Two local zones for cross-zone integration while the OSC zone clusters are not provided: kind
# clusters ztd-zone-a and ztd-zone-b, each built by kind-cilium-up.sh the way the zones run
# (Cilium, cni.exclusive=false, the target Kubernetes minor). Both sit on kind's Docker network, so
# a workload in one zone reaches the other through a node address and a NodePort.
# Integration only: nothing run on these clusters is acceptance evidence.
#
# Writes to .dev/zones/: a kubeconfig and a zone values file per zone, and <zone>.peer.env with the
# peer zone's node address. The user's default kubeconfig is not touched. Ends with a cross-zone
# check: a pod in zone A opens a TCP connection to a service in zone B.
#
#   scripts/dev/zones-up.sh      # safe to re-run
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="$root/.dev/zones"
check_image="registry.k8s.io/e2e-test-images/agnhost:2.53"

for tool in kind kubectl helm cilium docker python3; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done

mkdir -p "$out"
chmod 700 "$out"

for zone in zone-a zone-b; do
  kubeconfig="$out/kubeconfig-$zone"
  clusters="$(kind get clusters)"
  # The helper selects the cluster's context; it does so in this zone's own kubeconfig only.
  if grep -qx "ztd-$zone" <<<"$clusters"; then
    kind export kubeconfig --name "ztd-$zone" --kubeconfig "$kubeconfig" >/dev/null
  fi
  KUBECONFIG="$kubeconfig" KIND_CLUSTER="ztd-$zone" "$root/scripts/dev/kind-cilium-up.sh"
  chmod 600 "$kubeconfig"
  version="$(kubectl --kubeconfig "$kubeconfig" version -o json \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["serverVersion"]["gitVersion"])')"
  image="$(kubectl --kubeconfig "$kubeconfig" -n kube-system get ds cilium \
    -o jsonpath='{.spec.template.spec.containers[0].image}')"
  image="${image%%@*}"; cilium="${image##*:}"; cilium="${cilium#v}"
  cat >"$out/$zone.yaml" <<VALUES
# Local zone, written by scripts/dev/zones-up.sh. Not a target cluster. kubernetesVersion and the
# Cilium version are read from the cluster; the other values are the fixed local defaults of a kind
# zone.
zone:
  name: $zone
  kubernetesVersion: $version
  storageClass: standard
  loadBalancer:
    type: none
mesh:
  mode: ambient
cni:
  cilium:
    enabled: true
    version: $cilium
VALUES
done

# A zone's peer is reached at the peer's worker node on kind's Docker network.
node_ip() {
  local ip
  ip="$(docker inspect -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}' "ztd-$1-worker")"
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "no kind address for ztd-$1-worker" >&2; return 1; }
  echo "$ip"
}
ip_a="$(node_ip zone-a)"
ip_b="$(node_ip zone-b)"
printf 'PEER_ZONE=zone-b\nPEER_ADDRESS=%s\n' "$ip_b" >"$out/zone-a.peer.env"
printf 'PEER_ZONE=zone-a\nPEER_ADDRESS=%s\n' "$ip_a" >"$out/zone-b.peer.env"

# Cross-zone check: an echo service in zone B on a NodePort, connected to from a pod in zone A.
# Names are unique per run, so a previous run's leftovers cannot collide with this one.
kb=(kubectl --kubeconfig "$out/kubeconfig-zone-b")
ka=(kubectl --kubeconfig "$out/kubeconfig-zone-a")
check="ztd-zone-check-$(date +%s)"
cleanup() {
  "${kb[@]}" delete namespace "$check" --wait=false --ignore-not-found >/dev/null 2>&1 || true
  "${ka[@]}" delete pod "$check" --ignore-not-found >/dev/null 2>&1 || true
}
trap cleanup EXIT

"${kb[@]}" create namespace "$check" >/dev/null
"${kb[@]}" apply -n "$check" -f - >/dev/null <<MANIFEST
apiVersion: apps/v1
kind: Deployment
metadata: {name: echo}
spec:
  selector: {matchLabels: {app: echo}}
  template:
    metadata: {labels: {app: echo}}
    spec:
      containers:
        - name: echo
          image: $check_image
          args: [netexec, --http-port=8080]
          ports: [{containerPort: 8080}]
---
apiVersion: v1
kind: Service
metadata: {name: echo}
spec:
  type: NodePort
  selector: {app: echo}
  ports: [{port: 8080, targetPort: 8080}]
MANIFEST
"${kb[@]}" -n "$check" rollout status deploy/echo --timeout=180s >/dev/null
port="$("${kb[@]}" -n "$check" get service echo -o jsonpath='{.spec.ports[0].nodePort}')"

if output="$("${ka[@]}" run "$check" --rm -i --restart=Never --quiet --pod-running-timeout=3m \
  --image "$check_image" --command -- /agnhost connect --timeout=10s "$ip_b:$port" 2>&1)"; then
  echo "zones ready: zone A reaches zone B at $ip_b:$port; files in ${out#"$root"/}/"
else
  echo "cross-zone check failed: $output" >&2
  exit 1
fi
