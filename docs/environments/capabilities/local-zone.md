# Local zone

Zone A of the local two-zone setup (`scripts/dev/zones-up.sh`), measured with cluster rights. A kind
cluster on one machine: **not** a target cluster and not evidence for one.

| Capability | Result | Detail |
|---|---|---|
| Kubernetes version | **measured** | v1.35.5 |
| Nodes | **measured** | 2 visible |
| CNI | **measured** | cilium |
| NetworkPolicy enforcement | **measured** | enforced: reachable, refused under a deny policy, reachable again once removed |
| Storage classes | **measured** | standard (rancher.io/local-path) |
| Persistent volume (default class) | **measured** | claim bound and mounted by a pod in 4 s |
| LoadBalancer service | **unknown** | no address within 60 s |
| Ingress classes | **measured** | none |

Measured 2026-10-08T16:55:14Z by `scripts/baseline/capabilities.sh` as `kubernetes-admin`, in namespace `ztdcap-1b97snut`.
