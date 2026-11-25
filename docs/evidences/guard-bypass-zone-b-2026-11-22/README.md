# Guard bypass proof on zone B

Records of `scripts/verify-guard-bypass/verify.sh` against zone B (context `zerotrust-b`,
namespace `ztd-m3-b`), 2026-11-22 00:50-00:52 UTC, verdict PASS. The zone's releases were not
changed: the guard path is the one deployed there since 27 Oct (chart `guard-0.1.0`, revision 2).

| Step | Result | Evidence |
|---|---|---|
| Guarded call first | `POST https://160.44.12.245/demo` through the public Participant, guard and resource: `success`; the resource's record of the same request id carries the client of the token store's substituted upstream token (`ztd-store`), which only the guard obtains | `guarded.json`, `guarded-resource-record.jsonl` |
| Direct call, meshed, wrong identity | A probe Job under the Participant's service account calls `ztd-protected-resource:8080/demo` directly: `403 RBAC: access denied`. Receiver side: the resource's own sidecar logged the denial with both SPIFFE IDs (`rbac_access_denied_matched_policy[none]`), and its counter `http.inbound_0.0.0.0_8080;.rbac.denied` went 0 -> 1 | `meshed-response.txt`, `meshed-receiver-log.txt`, `meshed-stats-*.txt` |
| Direct call, without a sidecar | Not even creatable: the zone's admission rule `proxy-takes-spire-socket` refuses a pod without the mesh in the namespace | `unmeshed-events.json` |
| Nothing reached the application | The resource container logged no line while the probes ran | `resource-app-log-during-probes.txt` (empty) |
| Namespace as found | Every AuthorizationPolicy, PeerAuthentication, NetworkPolicy, Deployment, Service and Helm release has the same resourceVersion/revision before and after; no probe object remains | `before/`, `after/`, `objects.diff` (empty), `verdict.txt` |

The only opening was the probe's own pod label (`app.kubernetes.io/name=ztd-guard`), which the
resource's network policy admits on port 8080, so that the packet reaches the receiver and the mesh
decides; the probes were never Service endpoints (readiness never passes) and were deleted on exit.
