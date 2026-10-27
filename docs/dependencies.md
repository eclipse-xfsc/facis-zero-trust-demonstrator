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
| `go.opentelemetry.io/otel`, `/otel/sdk`, `/otel/trace`, `/otel/exporters/otlp/otlptrace/otlptracehttp` | v1.47.0 | Apache-2.0 | the OpenTelemetry Go SDK of the observability proof's echo service (`tools/trace-echo`): W3C trace-context propagation and one server span per request, exported by OTLP/HTTP |

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
| OpenBao (Helm chart `openbao`) | chart 0.28.3, server v2.5.4 | MPL-2.0 | the zone's X.509 key-value store, the release `ztd-openbao`: a dependency of the project chart `deployment/helm/ztd-openbao`, locked in its `Chart.lock`, its archive pinned by sha256 in `dependencies.sha256` ([Secrets](secrets.md)); covered by the declared licence exception |
| Docker Distribution registry | 2.8.3 (test service) | Apache-2.0 | a local registry for signing and verification tests in CI |

## Go dependencies being added

Added to the Go module together with the code that uses them; each goes through the licence gate like any
other dependency.

| Dependency | Version | Licence | Purpose |
|---|---|---|---|
| `github.com/jackc/pgx/v5` | v5.11.0 | MIT | PostgreSQL driver of the token store |

The admission provider talks to OCI registries through a small first-party client built on the Go
standard library rather than a general-purpose registry library, to keep its dependency set minimal.

## Identity and service mesh

The identity path and the mesh ([Workload identity](workload-identity.md)) are installed from the
upstream charts as they ship, one Helm release per chart, by `scripts/install-zone/install.sh`,
which pins each chart by version and by the sha256 of the chart archive (the Istio charts: of the
release archive). The container images the charts run are pinned separately, by tag and digest
(the multi-arch index digest of the tag, read from its registry), in the values files under
`deployment/helm/values/`: the SPIRE server, agent, controller-manager and SPIFFE CSI driver, the
CSI node-driver registrar, the server's `busybox` init container and `kubectl` hook image, and
Istio's `pilot`, `proxyv2` (the injected proxy and the injected `istio-validation` init container)
and `install-cni`. The images the charts already pin by digest are left
as they ship. One image stays a tag: `busybox:1.28` in Istio's `grpc-simple` injection template,
which only a pod that chooses its injection templates would run, and the `zone-policy` admission
policy refuses such a pod in every plane namespace. The values the repository sets on the charts
are listed with their reasons in `deployment/helm/values/README.md`.

| Component | Version | Installed through | Licence | Why |
|---|---|---|---|---|
| SPIRE (server, agent, controller-manager, SPIFFE CSI driver) | v1.15.3 | chart `spire` 0.30.2 and chart `spire-crds` 0.6.1, from the SPIFFE hardened charts `https://spiffe.github.io/helm-charts-hardened/` | Apache-2.0 | the only issuer of workload and mesh identities (ZT-24): attests every pod and serves its SVID over the CSI-mounted Workload API socket and to the mesh proxy over SDS |
| Istio, sidecar mode | 1.31.1 | charts `base`, `istiod` and `cni` 1.31.1, from the Istio release archive `istio-1.31.1-linux-amd64.tar.gz` (`manifests/charts`), pinned by its published sha256 | Apache-2.0 | the service mesh of [ADR-0009](adr/0009-service-mesh-mode-istio-sidecar-with-cilium.md): native sidecars that take their certificates from SPIRE, mesh-wide STRICT mTLS, the CNI plugin chained behind Cilium |
| Cilium | 1.20.2 on kind; 1.18.8 on the participant clusters | kind: chart `cilium/cilium` 1.20.2, by `scripts/dev/kind-cilium-up.sh`, the version a kind run of `scripts/verify-mesh-identity/verify.sh` shows; the participant clusters of zone A and zone B: installed and upgraded by the provider (Gardener), never by the zone, found at 1.18.8, the version a participant-cluster run of the same script shows in its preconditions and `environment.json` (see `scripts/verify-mesh-identity/README.md`) (the chaining proven on every node; cross-node pod traffic masqueraded by the provider's configuration, so the mesh is proven node-locally there and fails across nodes until the provider changes it; a kind pass on 1.20.2 supports but does not prove a fix for the provider's 1.18.8 pod network) | Apache-2.0 | the CNI and the enforcer of the network policies, with `cni.exclusive=false` (`cni-exclusive=false` in `cilium-config`) so that the Istio plugin can chain |
| istioctl | 1.31.1 | the operator's machine | Apache-2.0 | reads a proxy's secrets and sync status in the proof; never installs |

The Istio 1.31 charts are taken from the release archive because Istio's Helm repository and OCI
registry do not carry them (on 2026-10-06 the repository's index stopped at 1.31.0-rc.0); the
archive is the release Istio publishes, and its charts are the same charts.

**Upgrades.** An upgrade changes the pinned version and digest in the installer and re-reads the
digest of every image tag in the values files (`docker buildx imagetools inspect <image>:<tag>`
prints the index digest), then reruns `scripts/verify-mesh-identity/verify.sh`, whose record goes
to the run directory outside the repository. The local proof runs on kind node v1.35.8 with Cilium
1.20.2; the participant clusters run Kubernetes v1.34.7 with the provider's
Cilium 1.18.8, and the same proof is re-run there with the keep opt-in. At every Istio minor upgrade the
[ADR-0009](adr/0009-service-mesh-mode-istio-sidecar-with-cilium.md) reopen check
(`scripts/mesh-mode/check-upstream-state.sh`) runs alongside the proof. The SPIRE charts are
upgraded as a pair (`spire-crds` first), because the controller-manager in `spire` is built
against the CRDs of its `spire-crds`.

## Observability

The observability stack ([ADR-0012](adr/0012-central-observability-backends.md)) is installed from
upstream charts by `scripts/install-zone/install.sh`: the collectors in each participant zone, the
backends on the demonstrator cluster. Every chart is pinned by version and by the sha256 of its archive
(the digest its repository's `index.yaml` publishes), and every image by tag and multi-arch index
digest, all in `scripts/tools/pins.env`; the installer sets the images on the charts. The values the
repository sets are in `deployment/helm/values/` (`otel-node.yaml`, `otel-gateway.yaml`,
`otel-entry.yaml`, `prometheus.yaml`, `alertmanager.yaml`, `jaeger.yaml`).
`scripts/verify-observability/check-rendered-images.sh` fails CI when a rendered image of these
releases is not pinned by digest, is not in its list of accepted images with their licences, or is a
Grafana or Loki component.

| Component | Version | Installed through | Licence | Why |
|---|---|---|---|---|
| OpenTelemetry Collector (contrib distribution) | 0.162.0 | chart `opentelemetry-collector` 0.176.1, `https://open-telemetry.github.io/opentelemetry-helm-charts`, three releases: `otel-node`, `otel-gateway` (zones), `otel-entry` (demonstrator cluster) | Apache-2.0 | ZT-27's primary aggregation and export tool: pod logs, SPIRE metrics, OTLP from workloads and proxies, the revocation probe, the mutual-TLS entry |
| Prometheus | v3.15.0 | chart `prometheus` 29.37.0, `https://prometheus-community.github.io/helm-charts`, release `prometheus`, subcharts off | Apache-2.0 | ZT-27's metrics store, by remote write; the alert rules of ZT-52 and ZT-51 |
| Alertmanager | v0.34.1 | chart `alertmanager` 2.1.1, same repository, release `alertmanager` | Apache-2.0 | emits every alert (ZT-52, "emit alerts via the observability stack") |
| Prometheus config reloader | v0.94.1 | the reloader both charts run beside the server | Apache-2.0 | reloads the rules and the route when their ConfigMap changes |
| Jaeger (v2, all-in-one, Badger storage) | 2.22.0 | chart `jaeger` 4.16.1, `https://jaegertracing.github.io/helm-charts`, release `jaeger` | Apache-2.0 | ZT-27's OTel-compatible tracing backend |
| cert-manager | v1.21.2 | on the demonstrator cluster: installed there already, found at v1.21.2; on kind: chart `cert-manager` v1.21.2, `https://charts.jetstack.io`, by `scripts/dev/kind-cert-manager-up.sh` | Apache-2.0 | issues the telemetry CA, the entry's server certificate and the zones' client certificates (project chart `deployment/helm/telemetry-issuers`) |
| Cilium CLI | v0.20.1 | `scripts/tools/install.sh cilium-cli`, CI only | Apache-2.0 | waits for Cilium in the kind run of the observability proof |

**Excluded: Grafana and Loki.** Both are AGPL-3.0, which breaches the Apache-2.0-compatibility rule;
neither is installed. The Prometheus and Jaeger interfaces, reached with cluster access, are the
visualization of the observability data on the IONOS cluster until the demonstrator UI takes over
([Specifications](specifications.md)). The log store is an open point of ADR-0012; whichever is chosen
gets its row here and its pin in `scripts/tools/pins.env`.

**Upgrades.** An upgrade changes a version and its digest in `scripts/tools/pins.env` (and, for an
image, the index digest read with `docker buildx imagetools inspect <image>:<tag>`), then reruns
`scripts/verify-observability/verify.sh` on kind.
