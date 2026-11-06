# IONOS cluster

The CI/CD and visualization cluster, measured with cluster rights in a temporary namespace that the
script deletes afterwards.

| Capability | Result | Detail |
|---|---|---|
| Kubernetes version | **measured** | v1.35.6 |
| Nodes | **measured** | 1 visible |
| CNI | **measured** | calico-node |
| NetworkPolicy enforcement | **measured** | enforced: reachable, refused under a deny policy, reachable again once removed |
| Storage classes | **measured** | ionos-cloud-essential (cloud.ionos.com);ionos-cloud-performance (cloud.ionos.com);ionos-enterprise-hdd (cloud.ionos.com);ionos-enterprise-ssd (cloud.ionos.com) |
| Persistent volume (default class) | **measured** | claim bound and mounted by a pod in 37 s |
| LoadBalancer service | **measured** | address assigned in 29 s (address not recorded) |
| Ingress classes | **measured** | ztd-public (traefik.io/ingress-controller) |

Measured 2026-10-08T16:59:03Z by `scripts/baseline/capabilities.sh` as `system:serviceaccount:kube-system:cluster-admin`, in namespace `ztdcap-zrmwvfbr`.
