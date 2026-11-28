# Tenant (ZT-53)

One release per tenant, into the tenant's namespace. The namespace itself is the umbrella's: a
data-plane entry of `planes.extra` in the zone file, so the baseline applies to it like any plane
namespace (default deny both ways, the DNS lane, the intra-namespace lane, istiod, the mesh label and
the SPIFFE identities of `zone-policy`'s ClusterSPIFFEID). The zone installer installs it as
`ztd-tenant-<name>` from the zone file's `tenants` block.

What the release adds, all scoped to the tenant:

| Object | Purpose |
|---|---|
| ServiceAccounts `ztd-participant`, `tenant-data`, `tenant-admin` | the tenant's identities: the caller of its guard, its data service, its administrator |
| Secret `tenant-credentials` | the tenant's credential material, generated at install and kept on upgrade |
| Role and RoleBinding `tenant-owner` | the tenant's administrator alone may get, update or patch `tenant-credentials` and the guard's `ztd-policy-config` and `ztd-guard-config` in this namespace; no other tenant's identity is bound here |
| Deployment and Service `tenant-data`, PeerAuthentication STRICT, AuthorizationPolicy `tenant-data-members` | the tenant's data service, answering over mutual TLS to the tenant's members only (`members`, default the Participant `ztd-participant`) |
| NetworkPolicy `participant-to-tenant-guards` | with `guardNamespaces`: the tenant's Participant to the other tenants' guards on 8080, where their policy denies it (`m3-tenant-membership`); nothing else crosses |

The tenant's guard is the guard chart in tenant mode (`tenant.enabled`, its README) in the same
namespace. No tenant workload has a path to the management plane, where the secret store runs: the
baseline opens none, and this chart adds none. `scripts/verify-tenants` proves the isolation in both
directions.
