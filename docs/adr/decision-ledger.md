# Decision ledger

Every architecture decision of the demonstrator, where it is recorded, its status, and the evidence
behind it. A decision is settled only when its record is merged with status Accepted; a record in an
open pull request, or a number allocated and not yet written, is listed as such and is not presented
as settled. Status as of 8 October 2026.

## Decisions

Numbers are allocated in planning ([Architecture decisions](index.md)). The planning records of
9 September 2026, kept with the delivery plan rather than in this repository, allocated 0007–0015;
where this ledger says "planning record", that is its source, and the decision still needs a record
here before it counts as settled.

| Decision | Number | Record | Status | Spike and evidence |
|---|---|---|---|---|
| Service mesh mode | 0001 | [Istio Ambient with Cilium](0001-service-mesh-mode-istio-ambient-with-cilium.md) | Accepted (governing); proposed to be superseded by 0009 | Mesh feasibility gate (WP05) |
| Service mesh mode, fallback | 0009 | Istio sidecar with Cilium — in pull request #20 | Proposed, supersedes 0001 | Mesh identity evidence in pull request #20 |
| Admission: cosign verification provider | 0002 | [Gatekeeper external data provider](0002-gatekeeper-external-data-provider-for-cosign-verification.md) | Accepted (governing) | First-party provider in `services/admission-provider`; CI admission jobs |
| Admission provider: fork or first-party | 0014 | not written | Settled by 0002: built first-party, no separate record needed | as 0002 |
| OAuth2 authorisation surface | 0003 | [In the Go connector](0003-oauth2-authorisation-surface-in-the-go-connector.md) | Accepted (governing) | DCR and DPoP spike |
| vp_token to access-token mechanism | 0007 | not written | Superseded by 0003 | — |
| OAuth2 library behind the provider contract | — | pull request #19, filed as 0012 | Proposed | Library evaluation in pull request #19. **Number conflict:** 0012 is allocated to the policy artefact chains |
| Key material store | 0004 | [OpenBao](0004-openbao-as-x509-key-value-store.md) | Accepted, pending the client's licence decision (F-07) | Secrets baseline in pull request #16 |
| Connector token store | 0013 | not written | Planning record: design decided, storage engine proposed; not yet recorded here | — |
| Target environment | 0005 | [Three-cluster reading](0005-three-cluster-reading-of-the-target-environment.md) | Accepted (governing), recorded assumption | — |
| Guard proxy and policy hook (Envoy, ext_authz) | 0008 | not written | Planning record: decided; not yet recorded here, waits for the ext_authz spike | ext_authz spike, not started |
| Session attestation through `cmcd` | 0010 | pull request #17 | Proposed | Channel-binding evidence in pull request #17 |
| Mock TEE evidence | 0011 | [Format and provisioning](0011-mock-tee-evidence-format-and-provisioning.md) | Accepted for the format; provisioning items open | Mock-attestation samples in `docs/contracts/samples` |
| Policy artefact chains (Gatekeeper and TSA) | 0012 | not written | Planning record: decided. The client has since answered that infrastructure policies load into Gatekeeper before TSA exists and software policies go through TSA; not yet recorded here | — |
| Interface registry (IF-01 to IF-08) | 0015 | not written | Implemented as the registry in [API documentation](../api-docs.md) | Contract checks in CI |
| TRAIN launch-digest carrier | — | none | Open: no entry field exists. Asked of the client, who has defined no variant and asked us to propose one; our proposal is a `Type`/`Value` list ([Specification changes](../specifications.md)), not yet confirmed | TSPA API verification |
| Observability without Grafana | — | [Specification changes](../specifications.md) | Declared deviation: the SRS's alternative clause is taken (Grafana is AGPL-3.0) | — |
| Gateway API scope: a `GatewayClass`-scoped operator | — | [Specification changes](../specifications.md) | Declared reading, pending the client's confirmation | — |
| Licence scan and release SBOM as workflows in this repository | — | [Specification changes](../specifications.md), [CI/CD](../ci-cd.md) | Declared deviation: the shared organisation workflows cannot build this module | — |
| TDR ADR 001–006 | — | [TDR decisions](tdr-decisions.md) | Binding (prescribed) | — |

## Open items

- **Number conflict:** pull request #19 files the OAuth2 library record as 0012, which planning
  allocated to the policy artefact chains. One of the two takes a new number before either merges.
- **Records to write:** 0008 (after the ext_authz spike), 0012 (with the client's answer on the policy
  split), 0013 (when the storage engine is chosen).
- **TRAIN launch-digest carrier:** asked of the client, who asked us to propose one; the proposal waits
  for confirmation and then needs a record.
- **Deviations declared to the client (F-05):** the package sent on 11 September 2026 has not been
  located, so this ledger is not yet compared with it. Until it is, the deviation status in
  [Specification changes](../specifications.md#deviation-status) stands unchanged.
