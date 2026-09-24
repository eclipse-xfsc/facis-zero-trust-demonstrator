# Changes and additions to source specifications

Where the implementation departs from, or adds to, the Software Requirements Specification and the
Technical Development Requirements — and why.

Each entry records the specification clause, what changed, the reason, and the decision record that
governs it. Architecture decisions themselves live in [`adr/`](adr/index.md); this page is the index
from specification clause to decision, so a reviewer can start from the requirement rather than from
the decision.

## Readings and additions

| Specification clause | What the implementation does | Reason | Decision |
|---|---|---|---|
| SRS 2.3.3 — secure service mesh with SPIFFE/SPIRE, mode unspecified | Istio **Ambient** with Cilium as CNI, `cni.exclusive=false`, one named L7 enforcement owner per traffic path | The SRS fixes the identity model but not the data-plane mode; leaving it unfixed would put mesh and CNI in contention for L7 enforcement | [ADR-0001](adr/0001-service-mesh-mode-istio-ambient-with-cilium.md) |
| ZT-10, ZT-12, ZT-37 — admission must refuse unsigned images | A first-party Go external-data provider verifies Cosign signatures for OPA Gatekeeper; Ratify v1 is the documented fallback | Gatekeeper cannot verify signatures itself and the upstream provider is archived, so the component has to be built rather than adopted | [ADR-0002](adr/0002-gatekeeper-external-data-provider-for-cosign-verification.md) |
| ZT-21, ZT-22 — DCR, OID4VP-derived tokens, DPoP-bound storage, with Keycloak as identity provider | The OAuth2 authorisation surface is implemented in the Go Connector; Keycloak is used unmodified for realm, client, role and scope management | Keycloak's DPoP support is preview and OID4VCI experimental; the authoritative decision stays on the enforcement path rather than depending on preview features | [ADR-0003](adr/0003-oauth2-authorisation-surface-in-the-go-connector.md) |
| ZT-11 — key material stored in OpenBao | OpenBao is used as prescribed, deployed as a cluster-internal service and consumed unmodified through its API | OpenBao is MPL-2.0 where the rest of the baseline is Apache-2.0; a written licence exception was submitted rather than the component silently swapped | [ADR-0004](adr/0004-openbao-as-x509-key-value-store.md) · [licence exception](dependencies.md#licence-exceptions) |
| SRS 2.4.1 and SRS 2.7 — two cloud environments, plus a dedicated CI/CD environment on IONOS | Three managed clusters: two on T-Systems Open Sovereign Cloud, one on IONOS with its own CI/CD | Read strictly the two clauses give different cluster counts, and the count drives the per-cluster installation effort and the trust-zone topology | [ADR-0005](adr/0005-three-cluster-reading-of-the-target-environment.md) |
| SRS 2.6.2 — assumes Grafana plugins for observability, and permits another technology | Grafana is not shipped; visualization is the demonstrator UI plus the Prometheus and Jaeger interfaces | Grafana's core has been AGPL-3.0 since v8, which breaches the Apache-2.0-compatibility rule; the SRS's own alternative clause is taken | [licence exception](dependencies.md#licence-exceptions) |
| ZT-34 — the reverse proxy accepts Ingress or Gateway API resources as configuration | A `GatewayClass`-scoped operator translates Gateway and HTTPRoute resources into proxy configuration | The clause asks for resources-as-configuration, not a conformant Gateway API implementation; scoping to a GatewayClass keeps the operator small and the scope agreed | pending confirmation |
| TDR, OSS microservice repository — `.github/workflows`: the Eclipse Dash licence scanner and the build workflows are referenced from the standard organisation workflows | The Go tests reference the shared `go-test.yml`. The licence scan and the release SBOM run as workflows in this repository that do what the shared ones do — the same Eclipse Dash tool with the same review arguments, the same `cyclonedx-gomod` version and the same rule of attaching an SBOM to every release — with the pinned actions and declared permissions this repository requires of its own workflows | The shared scanner sets up Go 1.21 and the shared SBOM generator Go 1.23.8, with no input to change either, and an older Go refuses a module whose `go` directive is newer — this module declares Go 1.27. The scanner's Go step only builds a module list it never uses; the Eclipse Dash tool reads `go.sum` directly. The shared scanner also fetches its jar through a redirect that now answers 404 with an HTML page, which surfaces as `invalid or corrupt jarfile` | [CI/CD — Go version](ci-cd.md#go-version) · declared here, pending confirmation; the two workflows go back to references once the shared ones accept a Go version or read `go.mod` |
| ZT-31, ZT-71 — mock attestation in JSON for any TEE vendor | Evidence is produced by the CMC software driver in a vendor-agnostic report envelope, with one sample artefact per vendor profile | No TEE hardware is in scope; the mock has to be honest about being a mock and carry the same structure a real driver would emit | pending spike outcome |
| ZT-35, ZT-64 — expected launch digests uploaded to TRAIN by the pipeline and fetched by the peer | TSPA's trust-list entry has no digest field; the value must ride in an existing `Type`/`Value` list, with the connector's identifier in `ServiceTypeIdentifier` (the TCR lookup key) | TRAIN's data model was built for credential issuers; the SRS assumes TRAIN stores measurements without fixing where | [TRAIN trust-list publishing](tspa-publish-api.md) · pending (design decision on the digest carrier) |

## Deviation status

Every reading above is declared rather than assumed. The five governing ADRs were submitted to FACIS
as the F-05 deviation package and the OpenBao licence exception as F-07; both are open at the time of
writing. A reading that FACIS declines is handled as a plan change under the written-agreement rule,
not absorbed into the implementation.

The CI workflow reading was added after that package, when the first Go module arrived, and is not yet
part of a submitted deviation package: it is declared here so that it is not mistaken for an omission.
