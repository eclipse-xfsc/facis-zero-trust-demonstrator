# ztd-network-check: unrestricted egress narrowed (2026-11-21)

The namespace `ztd-network-check` (both zones, created by hand on 20 Oct 2026, unmeshed) runs the DaemonSet
`source-ip-check`: a Python HTTP server on 8080 that answers each request with its caller's source address,
the pod-to-pod source-address check of the network baseline. Its pods initiate nothing of their own; the
check is run by calling one pod from another. Nothing in the repository or the deployment tooling uses it.
It is kept (a diagnostic an operator may still run) and its NetworkPolicy `diagnostic-traffic` narrowed from
`egress: [{}]` (anywhere) to the same pods on 8080, the only peers its ingress admitted; applied on both
zones at about 21:40Z. Rollback: re-apply the recorded previous policy (kept outside the repository).

Probe from one `source-ip-check` pod (Python `urllib`, 5 s):

| Zone | Target | Before | After |
|---|---|---|---|
| zone A | the next `source-ip-check` pod, 8080 | connected | connected |
| zone A | an address outside the cluster, 443 | connected | refused (`URLError`, timed out) |
| zone B | the next `source-ip-check` pod, 8080 | connected | connected |
| zone B | an address outside the cluster, 443 | connected | refused (`URLError`, timed out) |

The applied policies, before and after on both zones: [network-check-policies-2026-11-21.md](network-check-policies-2026-11-21.md).
