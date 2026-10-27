# OSC zone A

Zone A of the target environment: the dedicated managed cluster `zerotrust-a` on T-Systems OSC
(Gardener), measured with cluster rights.

| Capability | Result | Detail |
|---|---|---|
| Kubernetes version | **measured** | v1.34.7 |
| Nodes | **measured** | 3 visible |
| CNI | **measured** | cilium |
| NetworkPolicy enforcement | **measured** | enforced: reachable, refused under a deny policy, reachable again once removed |
| Storage classes | **measured** | default (csi.onmetal.de) |
| Persistent volume (default class) | **measured** | claim bound and mounted by a pod in 21 s |
| LoadBalancer service | **measured** | address assigned in 1 s (address not recorded) |
| Ingress classes | **measured** | none |

Measured 2026-10-16T15:19:22Z by `scripts/baseline/capabilities.sh` as `system:serviceaccount:kube-system:ztd-cluster-admin`, in namespace `ztdcap-zhvmq015`.

## Cilium configuration

Read from `kube-system/cilium-config`; the cluster runs no kube-proxy.

| Setting | Value |
|---|---|
| Cilium image | v1.18.8 (OSC Gardener build) |
| `kube-proxy-replacement` | true |
| `routing-mode` | native |
| `cni-exclusive` | false |
| `bpf-lb-sock-hostns-only` | true |
| `enable-l7-proxy` / `external-envoy-proxy` | true / true |
| `enable-hubble` | true |
| `cluster-name` / `cluster-id` | default / unset |
