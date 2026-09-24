# OSS dependencies and external references

Third-party components the demonstrator depends on, and the upstream projects it integrates with
but does not own.

## Licence compliance

Every dependency clears Eclipse Dash before it ships. The scan runs on every pull request and a
dependency Dash marks `restricted` blocks the merge; anything Dash cannot clear automatically goes
to the Eclipse IP team for review. See [CI/CD](ci-cd.md).

A dependency under a licence the project cannot accept is replaced, not waived. The exception below
is the only other route, and it is not a way to waive the rule.

Generated inventories — the CycloneDX SBOM and the Dash summary — are published with each release
and are the authoritative list. This page records the components chosen and why.

## Licence exceptions

When a component under a non-Apache-2.0-compatible licence is **prescribed by the requirements** and
therefore cannot be replaced, the Technical Development Requirements oblige us to inform the client
in writing *before* it is included. The merge stays blocked until the client's written decision
arrives.

A licence exception notice states:

- the component, its version and its licence;
- the requirement that prescribes it, and why no compliant alternative satisfies that requirement;
- how the component is consumed — a deployed service called through its API, or code linked into a
  deliverable — since that is what decides whether its obligations reach project code;
- the effect on the Apache-2.0 outbound licence of the demonstrator;
- the decision requested, and what happens if it is declined.

### Worked example — OpenBao

**Licence Exception Notice v1.0** (8 September 2026, submitted with Project Plan v1.7) covers
OpenBao, MPL-2.0, prescribed by ZT-11, and Grafana, AGPL-3.0, for optional internal use. OpenBao is
deployed as a cluster-internal service and consumed unmodified through its API, so its file-level
copyleft does not reach newly developed components, which stay Apache-2.0. The FACIS decision is
open and tracked as follow-up requirement F-07.

The reasoning, the consequences if the exception is declined, and the references are recorded in
[ADR-0004](adr/0004-openbao-as-x509-key-value-store.md).

## External XFSC components

The demonstrator integrates XFSC components rather than reimplementing them: the Trust Services API
for policy evaluation, the Organisation Credential Manager for wallets, TRAIN for trust anchoring,
and ORCE for orchestration. Versions are pinned at deployment and recorded with the release.

## Go dependencies

Direct dependencies of the Go module. Transitive dependencies are listed in the SBOM.

| Dependency | Version | Licence | Purpose |
|---|---|---|---|
| `authelia.com/provider/oauth2` | v0.3.2 | Apache-2.0 | OAuth 2.0 framework behind the connector's provider adapter: RFC 7591 client registration and RFC 9449 DPoP. Requires Go 1.27.x. |
| `golang.org/x/crypto` | v0.57.0 | BSD-3-Clause | bcrypt hashing of client secrets |
| `github.com/cucumber/godog` | v0.16.0 | MIT | runs the Go acceptance scenarios (`internal/bdd`) |
| `github.com/cucumber/gherkin/go/v42` | v42.0.0 | MIT | parses the feature files for the Annex verbatim check (`cmd/bddpack`) |
| `github.com/cucumber/messages/go/v34` | v34.2.0 | MIT | the Gherkin document model used with it |
| `github.com/santhosh-tekuri/jsonschema/v6` | v6.0.3 | Apache-2.0 | validates SBOMs and mock attestations against their JSON Schemas at admission |

The admission check validates SBOMs against the official CycloneDX 1.5, 1.6 and 1.7 JSON Schemas and
the schemas they reference (CycloneDX specification tag 1.7.2, Apache-2.0), vendored in
`internal/cosignverify/schemas/` and pinned by SHA-256. CycloneDX 1.7 is accepted because it is what
the pinned Syft and Grype write by default.

## JavaScript development dependencies

Used by the acceptance harness only; never shipped in an image.

| Dependency | Version | Licence | Purpose |
|---|---|---|---|
| `@cucumber/cucumber` | 13.2.1 | MIT | runs the JavaScript acceptance scenarios |
| `ajv` | 8.20.0 | MIT | validates the interface contracts (JSON Schema and OpenAPI documents) against their fixtures |
| `ajv-formats` | 3.0.1 | MIT | the string formats (date-time, uri, …) Ajv checks |
| `yaml` | 2.9.1 | ISC | reads the OpenAPI documents for validation (already present as a dependency of `@cucumber/cucumber`) |

The contract check also uses the official OpenAPI 3.1 JSON Schema (`schema/2025-09-15`, Apache-2.0,
from the OpenAPI Initiative), vendored in `docs/contracts/tooling/oas-3.1/` and pinned by SHA-256.

## Supply-chain, policy and test tooling

Used by CI and the release workflow; never shipped inside a demonstrator image. Everything is pinned in
`scripts/tools/pins.env`:

- the executables (cosign, Syft, Grype, gator) and the Gatekeeper chart archive by SHA-256 — installed
  by `scripts/tools/install.sh`, which refuses a download whose checksum does not match;
- the container images (Gatekeeper, PostgreSQL, OpenBao, the test registry) by digest — pulled by
  digest where they are used.

The JavaScript packages above are pinned by exact version with integrity hashes in `package-lock.json`.

| Tool | Version | Licence | Purpose |
|---|---|---|---|
| cosign (Sigstore) | v2.6.2 | Apache-2.0 | signs images by digest and attaches attestations (classic `.sig`/`.att` layout, key-based) |
| Syft (Anchore) | 1.52.0 | Apache-2.0 | CycloneDX SBOM of each image and of the repository |
| Grype (Anchore) | 0.119.0 | Apache-2.0 | adds the known-vulnerability references to the SBOM before it is signed |
| gator (OPA Gatekeeper) | v3.23.1 | Apache-2.0 | offline tests of the admission constraints |
| OPA Gatekeeper (Helm chart) | 3.23.1 | Apache-2.0 | admission control with the first-party external-data provider |
| PostgreSQL | 16.10 (test service) | PostgreSQL License | token-store integration tests |
| OpenBao | 2.7.0 (test service) | MPL-2.0 | token-store integration tests only; its use in the demonstrator is the declared licence exception |
| Docker Distribution registry | 2.8.3 (test service) | Apache-2.0 | a local registry for signing and verification tests in CI |

## Go dependencies being added

Added to the Go module together with the code that uses them; each goes through the licence gate like any
other dependency.

| Dependency | Version | Licence | Purpose |
|---|---|---|---|
| `github.com/jackc/pgx/v5` | v5.11.0 | MIT | PostgreSQL driver of the token store |

The admission provider talks to OCI registries through a small first-party client built on the Go
standard library rather than a general-purpose registry library, to keep its dependency set minimal.

