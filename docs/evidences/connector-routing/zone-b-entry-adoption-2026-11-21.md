# Zone B entry adopted by the connector-gateway chart (2026-11-21)

Release `ztd-edge` (chart `deployment/helm/connector-gateway` 0.1.0, ingress role) installed into
`ztd-m3-b` on `zerotrust-b` at 20:27:47Z from commit `895531dc`, with `--take-ownership --force-conflicts`,
adopting the entry applied by hand on 27 Oct (Deployment, ConfigMap, Service, ServiceAccount, NetworkPolicy
and PeerAuthentication `ztd-edge`/`ztd-edge-tls`); the hand-applied AuthorizationPolicy `ztd-m3-edge-public`
was then deleted, the chart's `ztd-edge-public` (same rule: port 8443) in its place. Rehearsed first on
kind (`scripts/verify-connector-routing/kind.sh`, record `kind-2026-11-21.md`). Addresses are masked.

| Check | Before | After |
|---|---|---|
| Guarded path through the entry (`verify_public_route.py`: TLS verified against the entry's CA, two reset runs, `POST /demo` outcome `success`, equal normalized results) | PASS, 20:25:51Z | PASS, 20:28:25Z; again PASS 20:45:06Z after both zones' proofs |
| Business result hash of the guarded call | `86e76b6a…ddc0c9` | `86e76b6a…ddc0c9` (unchanged) |
| Entry Service UID, node port, load-balancer address | `b93751e5-15a1-4f36-b6dd-fdece0ff4a88`, 31390, `<address>` | unchanged (UID, node port, same address) |
| Calls of an outside client to `GET /health`, every 0.5 s, 20:27:35Z–20:28:14Z (across the adoption and its rolling replacement) | | 42 answered 200, none failed |
| Admission (`ztd-m3-b` is admission-enforced) | | the replacement pod admitted at the first attempt |
| Entry access log | none (the hand-applied entry logged nothing) | one JSON line per request (`role: ingress`, method, path, status, upstream, user agent, request id) |

What changed in the entry: its Envoy configuration (same route, every path to `ztd-participant:8080`, plus
the access log), mounted at `/etc/gateway`; a 5 s `preStop` pause; the configuration digest annotation;
`helm.sh/resource-policy: keep` on the Service. Server-side apply keeps the fields the hand-applied object
set and the chart does not (the former mount `/etc/edge` and the ConfigMap key `envoy.json`, both unused).

Rollback state (recorded before the change, outside the repository): the hand-applied objects, cleaned for
re-apply. Order, fail-closed: re-apply `ztd-m3-edge-public` first, then the previous ConfigMap and
Deployment (`kubectl apply --server-side --force-conflicts`), wait for the rollout and rerun the guarded-path
check, then drop only the release record (`kubectl -n ztd-m3-b delete secret -l owner=helm,name=ztd-edge`)
and `ztd-edge-public`. Never `helm uninstall ztd-edge`: the Service carries the zone's address.
