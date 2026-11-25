# Two tenants on zone A, isolation proven both ways (ZT-53)

2026-11-22, context `zerotrust-a`. Verdict of the proof: PASS (21 checks, `proof/verdict.txt`).

## What was changed

| Step | Result | Record |
|---|---|---|
| Pre-change state | releases, `ztd` history (revision 4, chart ztd-0.3.0) and values, namespaces; `tenant-a`/`tenant-b` absent | `before/` |
| Umbrella `ztd` upgraded through `scripts/lifecycle.sh` (server-side dry run, `--wait --wait-for-jobs`, rollback on failure) | revision 5, chart ztd-0.4.0: the live values unchanged except `planes.extra` + `tenant-a`, `tenant-b` (data plane) and `cni.cilium.version` 1.19.6, which the 0.4.0 schema requires; the layout verification hook passed. The render against revision 4 differed only by the two namespaces with their baseline policies (default deny, DNS, intra-namespace, istiod), the `ztd.facis.io/l7-owner` annotation on 14 existing policies and the chart label | `ztd-values-applied.json`, `umbrella-upgrade.log`, `after/` |
| `ztd-tenant-tenant-a`, `ztd-tenant-tenant-b` installed by `scripts/install-zone/install.sh install` from `deployment/helm/ztd/zones/zone-a.yaml` | revision 1 each; `tenant-data` 2/2 (Envoy runtime by digest, SPIRE identity, sidecar) | `tenants-install.log`, `after/releases.json` |

Nothing else changed: `after/releases.json` differs from `before/` by those three lines; the other
namespaces differ only by the chart label. The zone file's other drift from the live umbrella
(`ztd-otel-node`, telemetry) was deliberately not applied: the upgrade used the live values.

## The proof (`scripts/verify-tenants/verify.sh --live`, `proof/`)

| Case, A->B and B->A | Enforcing layer |
|---|---|
| Own data service (control) | 200 with the tenant's name |
| Other tenant's data service | Cilium: `Policy denied DROPPED` (Hubble, the caller's node); behind a probe-scoped opening the receiver's sidecar: 403, `rbac_access_denied_matched_policy[none]` with both SPIFFE IDs, rbac.denied 0 -> 1 |
| OpenBao in `ztd-mgmt` from either tenant | Cilium DROPPED; behind an opening OpenBao's sidecar: 403, rbac.denied +1 |
| Other tenant's `tenant-credentials`, read and change | API server 403 Forbidden for the other tenant's administrator; the owner 200 (body not recorded) |
| Other tenant's `ztd-policy-config`, read and change | API server 403 Forbidden; the owner 404 (authorized; no guard there yet, see below) |

Probe pods and the temporary openings were deleted; every object of `tenant-a`, `tenant-b` and
`ztd-mgmt` has the same resourceVersion before and after (`proof/objects-*.diff` empty).

## Not done live

The tenant guards (guard chart in tenant mode: target tenant from configuration, policy membership,
`m3-tenant-membership`, tenant on the IF-01 v2 events) need guard and policy-evaluator images built
from this branch; none is published, so they were not deployed here. That layer is proven on kind
(`../tenants-kind-2026-11-22`) and against the real connector and token store
(`TestTwoTenantsWithRealConnectorStorePolicyPostgresAndOpenBao`).

## Rollback

    helm uninstall ztd-tenant-tenant-b -n tenant-b
    helm uninstall ztd-tenant-tenant-a -n tenant-a
    helm rollback ztd 4 -n ztd-system --wait     # removes tenant-a and tenant-b with their policies

## Zone-file deployment: held

`zone-file-vs-live.txt`: installing the umbrella from the zone file instead of the live values would
add, besides nothing for the tenants (already identical), the `ztd-otel-node` namespace, the
observability scrape openings (spire-system ingress, ztd-mgmt egress) with a new Service
`spire-server-metrics` beside the running SPIRE server, and the connector and token-store openings
to OpenBao. These open lanes to running components that belong to other tracks (telemetry, OpenBao
auth), so the zone-file deployment was not applied; it waits for confirmation that they are meant for
zone A. Admission: `admission-preflight.txt` (read-only) shows the tenant namespaces' images in the
trusted repository except the injected Istio proxy, which zone A's trust policy does not allow-list
yet, as for `ztd-data`; zone A keeps `admission.enforceDataPlane` off.
