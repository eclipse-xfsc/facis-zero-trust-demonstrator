# Two-tenant isolation on kind (ZT-53)

`scripts/verify-tenants/verify.sh --kind`, 2026-11-22, verdict PASS (28 checks, `verdict.txt`).
A throwaway single-node kind cluster with Cilium 1.20.2 (Hubble on), the kind zone installed by
`scripts/install-zone` (umbrella, SPIRE, Istio 1.31.1 sidecar mode, zone-policy, OpenBao) with
`tenant-a` and `tenant-b` as `planes.extra` data-plane namespaces and their `ztd-tenant-*` releases
and each tenant's guard and policy evaluator (`ztd-guard-<tenant>`, `deployment/helm/guard` in tenant
mode, from the zone file's `tenants.guard`), all through the zone installer (`kind-zone.yaml`,
`install-zone.txt`), with the guard and policy-evaluator images built from this branch after the
merge of feat/m3-closeout and the review fixes.

| Case, both directions | Enforcing layer and record |
|---|---|
| Own data service (control) | 200 with the tenant's name (`data-own-*.http`) |
| Other tenant's data service | network: Cilium `Policy denied DROPPED` from the caller's agent (`data-*-network-flows.txt`); behind a probe-scoped opening, the receiver's sidecar: 403 `RBAC: access denied`, its rbac.denied counter +1 (`data-*-mesh.http`, `-mesh-receiver-log.txt`) |
| OpenBao (management plane) from either tenant | network: Cilium DROPPED (`secret-store-*-network-flows.txt`); behind an opening, OpenBao's sidecar: 403, rbac.denied +1 |
| Other tenant's `tenant-credentials`, read and change | API server: 403 Forbidden for the other tenant's administrator (`credentials-*-reads-*.json`, `-changes-*.json`); the owner reads its own (200, body not recorded) |
| Other tenant's guard policy `ztd-policy-config`, read and change | API server: 403 Forbidden, both; owner 200 |
| Own member through own guard (control) | 200 from the tenant's data service; guard and policy IF-01 v2 events carry `tenant` |
| Other tenant's member through the guard | 403 `POL-RULE-DENY`, rule `m3-tenant-membership`, decided by the target tenant's policy; both events carry the target tenant (`guard-*-to-*-{guard,policy}-event.json`) |

The guard's issuer key set and token-store calls are an Envoy stand-in in each tenant namespace (the
guard and policy are real); the same decisions against the real connector, token store, PostgreSQL
and OpenBao, plus the store refusing each tenant's guard the other tenant's upstream routes
(`TOK-ROUTE-DENIED`), are `TestTwoTenantsWithRealConnectorStorePolicyPostgresAndOpenBao`
(services/token-store/internal/server). Probe pods and openings were removed; objects of both
tenants and of `ztd-mgmt` unchanged before and after (`before-*.json`, `after-*.json`).
