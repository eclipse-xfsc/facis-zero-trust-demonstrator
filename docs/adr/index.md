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
