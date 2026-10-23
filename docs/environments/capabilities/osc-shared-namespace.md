# OSC shared-cluster namespace

The interim namespace on a shared OSC cluster, measured with its namespace-scoped service account.
This is **not** one of the two zone clusters: it carries no mesh, no workload identity and no admission
control, and its own allow-all policies make the NetworkPolicy test inconclusive.

| Capability | Result | Detail |
|---|---|---|
| Kubernetes version | **measured** | v1.32.9 |
| Nodes | **forbidden** | this identity may not list nodes |
| CNI | **forbidden** | this identity may not list daemonsets in kube-system |
| NetworkPolicy enforcement | **unknown** | the connection survived a deny policy, but other policies in the namespace (zero-trust-allow-all-ingress-egress,zero-trust-allow-dns,zero-trust-allow-same-namespace,zero-trust-default-deny) may allow it; policies are additive |
| Storage classes | **measured** | default (csi.onmetal.de) |
| Persistent volume (default class) | **measured** | claim bound and mounted by a pod in 13 s |
| LoadBalancer service | **measured** | address assigned in 6 s (address not recorded) |
| Ingress classes | **measured** | nginx (k8s.io/ingress-nginx) |

Measured 2026-10-08T16:56:15Z by `scripts/baseline/capabilities.sh` as `system:serviceaccount:zero-trust:zero-trust-access`, in namespace `zero-trust`.
