#!/usr/bin/env bash
# Local cluster for chart work: kind without its default CNI, with Cilium chained the way
# the zones run it (cni.exclusive=false, ADR-0009). The cluster is the substitute for the
# client clusters while they are not available; it proves what does not depend on them.
#
# Idempotent: re-running on an existing cluster only re-applies the Cilium release. Changing the
# node image needs `kind delete cluster --name ztd` first. Differs from scripts/dev/kind-up.sh (the
# BDD pool cluster) in one thing that matters here: the CNI. kind's default CNI enforces
# NetworkPolicy as well, but it brings no Cilium CRDs, and in the parked ambient mode with Cilium
# (the excursion of scripts/verify-umbrella) the chart renders a cluster-wide Cilium policy. On
# that cluster the chart installs only with cni.cilium.enabled=false; this one proves it the way
# the zones run it: Istio sidecar mode over the chained Cilium (ADR-0009), ambient as the excursion.
#   KIND_CLUSTER      cluster name            (default: ztd)
#   KIND_NODE_IMAGE   kindest/node image      (default: v1.35.5 by digest, the Kubernetes minor the IONOS target runs)
#   CILIUM_VERSION    Cilium chart version    (default: 1.20.2)
set -euo pipefail

CLUSTER=${KIND_CLUSTER:-ztd}
NODE_IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95}
CILIUM_VERSION=${CILIUM_VERSION:-1.20.2}

for tool in kind kubectl helm cilium; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --config - <<KIND
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true   # Cilium is the CNI, as in the zones
nodes:
  - role: control-plane
  - role: worker
KIND
fi
kubectl config use-context "kind-${CLUSTER}" >/dev/null

helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1 || true
helm repo update cilium >/dev/null
# cni.exclusive=false lets the Istio CNI plugin chain behind Cilium in any mode (ADR-0009, osc.md step 1).
helm upgrade --install cilium cilium/cilium --version "$CILIUM_VERSION" -n kube-system \
  --set cni.exclusive=false \
  --set ipam.mode=kubernetes \
  --set image.pullPolicy=IfNotPresent \
  --wait --timeout 10m

cilium status --wait --wait-duration 5m
kubectl wait --for=condition=Ready nodes --all --timeout=5m
server=$(kubectl version -o json | python3 -c 'import sys,json;print(json.load(sys.stdin)["serverVersion"]["gitVersion"])')
echo "cluster ${CLUSTER} ready: Kubernetes ${server}, Cilium ${CILIUM_VERSION}, cni.exclusive=false"
