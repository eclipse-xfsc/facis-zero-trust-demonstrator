# Architecture decisions

Architecture Decision Records capture the decisions that shape this demonstrator, why they were
taken, and what would cause them to be revisited. A decision recorded here is settled: reopening it
is a change with a named cost, not a discussion.

## Governing decisions

These five were taken by the project's Technical Design Authority and Project Leader on
2026-09-08 and govern everything built afterwards.

| ADR | Decision |
|---|---|
| [0001](0001-service-mesh-mode-istio-ambient-with-cilium.md) | Service mesh mode — Istio Ambient with Cilium |
| [0002](0002-gatekeeper-external-data-provider-for-cosign-verification.md) | Gatekeeper external data provider for cosign verification |
| [0003](0003-oauth2-authorisation-surface-in-the-go-connector.md) | OAuth2 authorisation surface in the Go connector |
| [0004](0004-openbao-as-x509-key-value-store.md) | OpenBao as X.509 key-value store |
| [0005](0005-three-cluster-reading-of-the-target-environment.md) | Three-cluster reading of the target environment |

## TDR decisions

The six decisions the Technical Development Requirements prescribe (ADR 001–006: Helm, ORCE, the
automation stack, Keycloak, the security baseline, logging) are binding. How each is applied is
recorded in [TDR decisions ADR 001–006](tdr-decisions.md).

## Format

Each record states its status, date, deciders, the requirements it answers, the context, the
decision itself, and the consequences — including the trigger that would flip it.
