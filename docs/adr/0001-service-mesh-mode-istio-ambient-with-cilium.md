# ADR-0001: Service mesh mode — Istio Ambient with Cilium

- **Status:** Accepted
- **Date:** 2026-09-08
- **Deciders:** Technical Design Authority (Kevin Kupilas), Project Leader (Robert Koning)
- **Requirement basis:** SRS 2.3.3; ZT-23, ZT-24, ZT-26, ZT-55, ZT-58, ZT-61
- **Follow-up requirement:** F-08

## Context

The SRS prescribes a secure service mesh with SPIFFE/SPIRE workload identity but does not fix the mesh
data-plane mode. Istio can run in sidecar mode or in ambient mode; Cilium is used as the CNI in all three
target clusters. Running Istio sidecars over a Cilium CNI that also enforces L7 policy creates two competing
L7 enforcement points on the same traffic path, which makes a policy decision non-deterministic and makes the
fail-closed behaviour required by ZT-26 and ZT-55 impossible to demonstrate reliably.

## Decision

The implementation baseline is **Istio Ambient with Cilium**.

1. Cilium is configured with `cni.exclusive=false` so that the Istio CNI plugin can chain behind it.
2. Exactly one L7 enforcement owner is assigned per traffic path. Where Istio waypoint proxies enforce L7
   policy, Cilium is restricted to L3/L4 for that path, and vice versa. The assignment is recorded per traffic
   path in the mesh configuration and is part of the WP05 exit criteria.
3. SPIRE-issued SVIDs are delivered to mesh workloads through the SPIFFE CSI driver (ZT-24).

## Consequences

- Positive: no sidecar injection into application pods, lower resource footprint per workload, and a single
  deterministic L7 decision point per path, which is what the fail-closed acceptance scenarios assert.
- Positive: ambient mode keeps the participant and protected-resource mocks replaceable without touching the
  mesh configuration, as required by the WP09 Definition of Done.
- Negative: ambient mode has a narrower operational track record than sidecar mode. Mitigation: WP05 contains
  an explicit feasibility and decision gate before the mesh is baselined; if the gate fails, the fallback is
  Istio sidecar mode with Cilium restricted to L3/L4, recorded as a superseding ADR.
- Negative: `cni.exclusive=false` requires the CNI chaining order to be verified after every Cilium upgrade.
  This is covered by the lifecycle tests in WP12.

## References

- SRS 2.3.3 — service mesh and enforcement constraints
- Project Plan v1.7, section 4, "Service-mesh declaration (F-08)"
- Annex A v1.7 — ZT-23, ZT-24, ZT-26, ZT-55, ZT-58, ZT-61

## Note — IONOS cluster as provided (2026-09-23)

This note records a fact and does not reopen the decision. The IONOS cluster was provided with the
provider-managed Calico CNI, and it runs no mesh and no demonstration workload today
([IONOS setup](../environments/ionos.md)). The statement above that Cilium is the CNI "in all three
target clusters" therefore holds only for the clusters that run the mesh, and no mesh-based policy
applies on the IONOS cluster. Whether that cluster needs Cilium and the mesh is decided with its
visualization stage, for the Technical Design Authority, and recorded here when it is.
