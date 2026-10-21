# Architecture decisions

Architecture Decision Records capture the decisions that shape this demonstrator, why they were
taken, and what would cause them to be revisited. A decision recorded here is settled: reopening it
is a change with a named cost, not a discussion.

## Governing decisions

The first five were taken by the project's Technical Design Authority and Project Leader on
2026-09-08 and govern everything built afterwards. 0009 is the superseding record that the
first one's fallback clause foresaw, under the number planning allocated to it: it was proposed by
the delivery team on 2026-10-03 for the same deciders, and it replaces 0001 as the governing
mesh-mode decision. A superseded record keeps
its text and is read through the record that supersedes it.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-service-mesh-mode-istio-ambient-with-cilium.md) | Service mesh mode — Istio Ambient with Cilium | Superseded by 0009 |
| [0002](0002-gatekeeper-external-data-provider-for-cosign-verification.md) | Gatekeeper external data provider for cosign verification | Accepted |
| [0003](0003-oauth2-authorisation-surface-in-the-go-connector.md) | OAuth2 authorisation surface in the Go connector | Accepted |
| [0004](0004-openbao-as-x509-key-value-store.md) | OpenBao as X.509 key-value store | Accepted |
| [0005](0005-three-cluster-reading-of-the-target-environment.md) | Three-cluster reading of the target environment | Accepted |
| [0009](0009-service-mesh-mode-istio-sidecar-with-cilium.md) | Service mesh mode — Istio sidecar with Cilium (supersedes 0001) | Proposed |

## TDR decisions

The six decisions the Technical Development Requirements prescribe (ADR 001–006: Helm, ORCE, the
automation stack, Keycloak, the security baseline, logging) are binding. How each is applied is
recorded in [TDR decisions ADR 001–006](tdr-decisions.md).

## Implementation decisions

Implementation decisions are taken by the delivery team as the work proceeds, usually as the outcome
of a spike, and they are subordinate to the governing decisions above: an implementation record may
settle how a requirement is met, never whether a governing decision holds.

**These records live here, in this folder and in the same four-digit numbering series as the
governing ones.** A number is allocated when the decision is identified during planning, which is
normally before the record is written, so the sequence has gaps: a missing number is a record that is
allocated and not yet written, never one that was removed. Planning material may write the number
without its leading zero; the repository always writes four digits.

A spike's working notes are not an ADR. They stay with the spike; what comes here is the decision,
its reasons, the requirements it answers, and what would reopen it.

| ADR | Decision |
|---|---|
| [0011](0011-mock-tee-evidence-format-and-provisioning.md) | Mock TEE evidence — format, release artefact, and provisioning |

## Format

Each record states its status, date, deciders, the requirements it answers, the context, the
decision itself, and the consequences — including the trigger that would flip it.
