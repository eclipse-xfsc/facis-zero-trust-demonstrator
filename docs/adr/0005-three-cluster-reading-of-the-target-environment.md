# ADR-0005: Three-cluster reading of the target environment

- **Status:** Accepted
- **Date:** 2026-09-08
- **Deciders:** Technical Design Authority (Kevin Kupilas), Project Leader (Robert Koning)
- **Requirement basis:** SRS 2.4.1 and SRS 2.7; WP02 exit criteria
- **Follow-up requirement:** F-05

## Context

SRS 2.4.1 describes two cloud environments. SRS 2.7 requires a dedicated CI/CD environment on IONOS Cloud in
addition to the T-Systems Open Sovereign Cloud environments. Read strictly, the two clauses give different
cluster counts, and the difference is not cosmetic: the service mesh, SPIRE, OPA Gatekeeper and the
observability stack are installed per cluster, so the count drives effort, the trust-zone topology and the
inter-cluster acceptance scenarios.

## Decision

The solution is delivered across **three managed Kubernetes clusters**: two on T-Systems Open Sovereign Cloud
and one on IONOS Cloud with its own CI/CD. This reading is recorded as an explicit assumption in the approved
project plan rather than resolved silently.

WP02 exit criteria accordingly require all three clusters reachable, the TRAIN DNS zone created and reachable,
and the XFSC stack deployed.

## Consequences

- Positive: SRS 2.7 is satisfied without a separate deviation request, and the two federation and trust zones
  required by ZT-03 map cleanly onto the T-Systems clusters.
- Positive: the acceptance scenarios for inter-cluster communication and admission policy are written against
  three clusters from the start, so no rework is needed if FACIS confirms this reading.
- Negative: per-cluster installation of mesh, SPIRE, Gatekeeper and observability is three deployments rather
  than two, which is reflected in the WP02 and WP12 effort. If FACIS confirms a two-cluster reading instead,
  the reduction is handled as a plan change under the written-agreement rule.

## Refinement

[ADR-0012](0012-central-observability-backends.md) refines the observability part of the per-cluster
installation: the collectors are installed in every participant cluster, the backends (Prometheus,
Alertmanager, Jaeger) once, on the IONOS cluster.

## References

- SRS 2.4.1, SRS 2.7
- Project Plan v1.7, section 1 — "Environment assumption"
- Annex A v1.7 — ZT-03, TDR-BDD deployment cases
