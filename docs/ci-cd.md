# CI/CD

Continuous integration for this repository **references the shared Eclipse XFSC workflows** in
[`eclipse-xfsc/dev-ops`](https://github.com/eclipse-xfsc/dev-ops/tree/main/.github/workflows)
rather than copying them. Keeping the bodies upstream is what the Technical Development
Requirements ask for, and it means a fix to a shared workflow reaches this repository without a
pull request here.

Two workflows are the exception, and run in this repository instead: the licence scan and the SBOM.
The shared versions cannot process this module — see [Go version](#go-version) for why and for what
would let them be referenced again. This is a departure from the Technical Development Requirements
and is declared as such in [Specification changes](specifications.md#readings-and-additions).

## Workflows in this repository

| Workflow | Triggers | What it does |
|---|---|---|
| `.github/workflows/eclipse-dash.yml` | every pull request, schedule, release, manual | Runs the Eclipse Dash licence scanner on `go.sum` and files IP review requests for dependencies |
| `.github/workflows/sbom.yml` | schedule, release, manual | Generates a CycloneDX SBOM for every release that has none and attaches it |
| `.github/workflows/docs.yml` | push to `main` affecting `docs/`, manual | Builds the MkDocs site and publishes it to the `gh-pages` branch |
| `.github/workflows/workflow-hygiene.yml` | every pull request, manual | Fails the pull request when an action is not pinned to a commit or a token scope is too wide |
| `.github/workflows/ci.yml` | every pull request, push to `main`, published release, manual | Go lint and tests, image build with the Linux assertion and a Trivy scan, chart lint and dry-run render; on a published release, the chart packaging and publication (see [Chart release](#chart-release)) |
| `.github/workflows/release.yml` | manual, push to a `candidate/**` branch | Release candidate: builds, pushes, signs and attests every image by digest, then verifies each one (see [Image signing](#image-signing)) |
| `.github/workflows/measurement-determinism.yml` | pull request and push to `main` touching the check, manual | Measures one fixture on a hosted runner, in a container, and on a deliberately divergent checkout, and requires the normalised measurement to be the same on all three |

## The service pipeline

`ci.yml` is one pipeline shape that every service in the monorepo reuses, so quality is consistent
and nobody hand-rolls their own:

| Job | What it does | Blocking |
|---|---|---|
| `Go tests` | Calls the shared `go-test.yml`, which runs the tests of every Go module it finds | yes |
| `Go lint` | `golangci-lint run ./...`, with a pinned golangci-lint built by the Go version `go.mod` names | yes |
| `Image build and scan` | Builds each context under `deployment/docker/` for `linux/amd64`, asserts the built image's OS, then scans it with Trivy for HIGH and CRITICAL vulnerabilities | yes |
| `Chart lint and render` | `scripts/check-charts.sh`: `helm lint` and a `helm template` dry-run render of every chart under `deployment/helm/` and of the fixture charts under `features/fixtures/charts/`; then `scripts/check-charts_test.sh`, the cases that hold the script to refusing a package when a chart fails | yes |
| `Release charts` | On a published release only, once every other gate job of the workflow has passed: packages the charts under `deployment/helm/` at the release version, attaches them to the release with their checksums and, when a registry is configured, pushes them as OCI chart artefacts — see [Chart release](#chart-release) | yes — a release whose gates fail ships no chart |

ZT-13 requires Linux images. The pipeline reads the OS back off the built image with
`docker image inspect` and fails if it is anything but `linux/amd64`, rather than trusting the
Dockerfile to be right. The platform it read is printed in the job output either way.

Each job passes quietly while the thing it checks does not exist yet — no Go module, no build
context, no chart — so the pipeline is green on an empty skeleton and starts enforcing the moment
the first service lands.

### Go module layout

The demonstrator is **one Go module at the repository root**, with each service a package under
`services/` and shared code in `internal/`. This is not a style preference: the Eclipse Dash
scanner and the shared SBOM generator both read the root `go.sum`, and a module per service would
leave the licence gate and the release SBOM with nothing to read.

### Go version

`go.mod` declares **Go 1.27**. The version is not chosen freely: a module cannot declare a lower Go
version than its dependencies, and `authelia.com/provider/oauth2` v0.3.2, which the connector's
OAuth2 provider is built on, requires Go 1.27.

Nothing in the shared org workflows reads `go.mod`. Each sets up its own fixed Go version, and
`actions/setup-go` disables automatic toolchain download, so an older Go stops with
`go.mod requires go >= 1.27` before it does any work. How each job gets its Go version:

| Job | How it gets Go | Consequence |
|---|---|---|
| `Go tests` (shared `go-test.yml`) | `go-version` input, default 1.24 | `ci.yml` passes `1.27`; keep it in step with `go.mod` by hand |
| `Go lint`, BDD suite, `sbom.yml` | `go-version-file: go.mod` | follow `go.mod` by themselves |
| Licence scan in `eclipse-dash.yml` | none | the Eclipse Dash tool reads `go.sum` and needs no Go toolchain |
| shared `eclipse-dash-licence-go.yml` | hard-coded 1.21, no input | cannot run on this module — not used |
| shared `sbom-golang.yml` | hard-coded 1.23.8, no input | cannot run on this module — not used |

The last two are why the licence scan and the SBOM run locally. The local jobs do what the shared
ones do — the same Eclipse Dash tool with the same review arguments, the same `cyclonedx-gomod`
version and the same rule of attaching an SBOM to every release that lacks one — with the pinned
actions and declared permissions this repository requires of its own workflows. They can go back to
being references once the shared workflows accept a Go version or read `go.mod`; that is a change to
propose in `eclipse-xfsc/dev-ops`.

## Image signing

The candidate job of `release.yml` builds every image under `deployment/docker/` for `linux/amd64`,
labels it `eu.facis.ztd.signing-key=interim` and pushes it to `ghcr.io/<owner>/<repository>/<name>`.
Then, for each image digest:

1. `scripts/supplychain/sbom.sh` — the Syft SBOM of the image, scanned by digest, enriched by Grype with
   the known vulnerabilities (CycloneDX JSON);
2. `go run ./cmd/mockattest` — the mock attestation (ZT-71), checked against the schema admission
   enforces;
3. `scripts/supplychain/sign-attest.sh` — the cosign signature and both attestations, the same commands
   the CI interop and kind tests use;
4. verification of every digest against the committed public key
   (`docs/contracts/keys/interim-cosign.pub`), with the admission provider's own code
   (`cmd/imageverify`) and with `cosign verify` / `verify-attestation`.

The private key is the `COSIGN_INTERIM_KEY` secret (with `COSIGN_INTERIM_PASSWORD`) of the protected
`release` environment; without it, or without the public key, the job fails before anything is
signed. The interim key is not the client trust chain; it is replaced by the client key and Harbor.
The job creates no tag and no release.

It checks the key before it builds anything: the secret must be set and must be the private half of
the committed public key, so a missing environment, secret or key file stops the job before an image
is pushed. GHCR creates new packages as private; the job verifies them with its own token, but a
cluster pulls and verifies anonymously, so the candidate packages must be made public in the package
settings (once per package) before a cluster can admit them.

## Chart release

The Technical Development Requirements deliver the Helm charts with each release. The candidate
stage above creates no tag and no release; the charts are delivered when a release is published, by
the `Release charts` job of `ci.yml`, and only after every gate job of that workflow has passed —
the lifecycle jobs included, which may be skipped while the repository variable is off but not
failed or cancelled. The lint and dry-run render are the gate in front of the package, so a chart
that fails either is never released, which is the rule of Annex A row TDR-BDD-11. The pull-request
job and the release job run the same `scripts/check-charts.sh`, which checks every chart first and
packages only when all of them pass, so the gate a pull request clears is the gate the release is
held to. Each package is then linted and rendered again with the chart's own values: the version
now differs from `Chart.yaml`, and a template that reads it renders differently. One failing
package leaves no package at all. `scripts/check-charts_test.sh` holds the script to that in the
chart job, against charts it writes itself: a set that passes is packaged at the version with
matching checksums, and one failing chart leaves no package, at the source or once packaged.

A release is tagged `vX.Y.Z`, or `vX.Y.Z-prerelease`. The charts are packaged at that version — the
tag drives `--version` and `--app-version`, over the development version in each `Chart.yaml` — so
the release and every chart in it carry one version, and the documentation of a release describes
the charts it ships. A tag that is not semantic versioning stops the job before it names a package,
and so does build metadata (`+`): the charts put their version into the `helm.sh/chart` label, and
`+` is not allowed in a label value. The packages and a `SHA256SUMS` file are attached to the
release as assets.

Publication to a registry stays off until one exists. When the repository variable `CHART_REGISTRY`
names the OCI path for charts (for example `harbor.example.org/facis/charts`) and the secrets
`CHART_REGISTRY_USER` and `CHART_REGISTRY_PASSWORD` hold a robot account allowed to push there, the
job also pushes every package with `helm push` and prints the digest of each into the run summary.
That digest is what a zone file pins: the lifecycle workflow accepts a chart only as a local path or
as an `oci://` reference pinned by digest.

Locally, `scripts/check-charts.sh` runs the same check, and
`scripts/check-charts.sh --package dist --version 0.0.0-local` the same packaging, for a look at what
a release would ship.

## Lifecycle scenarios on the client targets

The `bdd` job runs on every pull request: `bddpack -check`, the strict and catalogue runs of both
runners and the cluster dry run, then `bddreport --require-complete` over the five reports, so a
row that is uncovered or failed fails the job (see [BDD acceptance](bdd.md#the-harness)). The dry
run exists only in this job: where a cluster run happens, its real report is used instead.

The `bdd-cluster` job runs the cluster scenarios (TDR-BDD-01..04 and TDR-BDD-06) against each client
target, and `bdd-cluster-report` merges every target into one traceability sheet in which a row is
proven only if it passed everywhere. They run on pushes to `main`, on every published release and
on demand — never on pull requests — and one run at a time per target. Evidence is published even
when the run fails, and the job keeps its failure. See [BDD acceptance](bdd.md) for what they prove. Each target's evidence and the cross-target
sheet also carry a `bdd-catalogue.md` rendered from that run (`bddpack -evidence`), whose evidence
basis column says what each row was proven with — for example the fixture release.

Both jobs stay off until the repository variable `BDD_CLUSTER_ENABLED` is `true`. A target
`<KEY>` (for example `IONOS`) then needs, as repository secrets, `BDD_<KEY>_OBSERVER_KUBECONFIG`
(the read-only observer identity — never an administrator credential), `BDD_<KEY>_ORCE_URL`,
`BDD_<KEY>_ORCE_READ_TOKEN`, `BDD_<KEY>_ORCE_HTTP_USER` and `BDD_<KEY>_ORCE_HTTP_PASS`, and as a
repository variable `BDD_<KEY>_ORCE_LOGS_CMD`, plus its entry in the job's matrix.

## Image scan exceptions

Every image is scanned and a HIGH or CRITICAL finding fails the build. When a finding sits in an
upstream component that this project cannot fix in its own layer, a `scan-exception.json` next to
the image's Dockerfile may exclude named paths from the gate. It must carry an expiry date, the
reason and the tracking of the upstream fix; the job prints it into the run summary and fails the
build once it has expired. The ORCE image carries one for the upstream ORCE runtime and kubectl,
expiring 13 November 2026.

## Repository protection and least privilege

The demonstrator applies its own zero-trust posture to the delivery machine (ZT-56): nothing reaches
`main` unreviewed, and no pipeline holds a credential wider than the job in front of it needs.

### Branch protection

`main` is protected by a ruleset an organisation administrator applies — it is an Eclipse XFSC
organisation setting and cannot be declared from this repository's tree. The required ruleset:

| Rule | Setting |
|---|---|
| Direct pushes to `main` | Blocked; changes arrive by pull request |
| Approving reviews | At least one, from someone other than the author |
| Stale approvals | Dismissed when new commits are pushed |
| Required status checks | `Workflow hygiene`, `Licence gate`, `Go lint`, `Image build and scan`, `Chart lint and render` |
| Force pushes and branch deletion | Blocked |
| Enforcement | Applies to administrators |

### Token scopes

The repository's default workflow token is read-only — an administrator setting applied alongside the
ruleset above. Every workflow then declares its own top-level `permissions:` block rather than
relying on that default, and a job that needs more than read access grants it at the job level with
a comment naming the reason: `docs.yml` writes to `gh-pages`, `sbom.yml` uploads the SBOM onto a
release, the release candidate job pushes images and signatures to GHCR (`packages: write`), and the
`Release charts` job attaches the packaged charts to a release. Wildcard scopes (`write-all`) are
never used.

### Action pinning

Third-party actions are referenced by full commit SHA with the version in a trailing comment, so a
moved tag cannot change what runs in the pipeline:

```yaml
uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
```

The shared `eclipse-xfsc/dev-ops` workflows stay on `@main` on purpose: the Technical Development
Requirements ask for the shared bodies to be referenced rather than copied, and pinning them would
stop fixes reaching this repository. The residual risk is accepted for workflows inside the
project's own organisation and does not extend to anything outside it. Dependabot proposes the SHA
bumps weekly.

`scripts/check-workflow-hygiene.sh` enforces all three rules — pinning, a declared permissions block,
and no wildcard write scope — on every pull request. Run it locally before pushing:

```bash
scripts/check-workflow-hygiene.sh
```

## Licence scanning

Every third-party dependency must clear Eclipse Dash before it ships. The scan is a **blocking
pull-request gate**: a dependency Dash marks `restricted` fails the `Licence gate` job and the
merge is refused.

The scanner reads `go.sum`, so the gate skips itself while no Go module exists — a
preceding job looks for the file and the scan runs only when it is there. The workflow itself is
not filtered by path, so the required check is always reported: a skipped job counts as passing,
whereas a workflow that never starts leaves the pull request waiting forever.

On a run that can see the organisation's review token the scanner files IP review requests for
whatever it cannot clear. A pull request from a fork cannot see that secret, so there the same tool
runs check-only: it files nothing, but it still fails on a licence that is not approved. If the
licence services cannot be reached the job fails and asks to be rerun, rather than pass unverified.

Dependencies that Dash cannot clear automatically go to the Eclipse IP team for review. A dependency
under a licence that the project cannot accept is replaced, not waived — and where the requirements
prescribe the component and leave no alternative, it goes to the client as a written licence
exception before it is merged. The process and the OpenBao worked example are in
[OSS dependencies](dependencies.md#licence-exceptions).

## Documentation publication

`docs.yml` builds the MkDocs site and pushes it to the `gh-pages` branch. GitHub Pages must be
enabled on the repository with its source set to that branch — a one-time repository setting a
maintainer applies.

## Adding a workflow

Reference the shared workflow rather than reimplementing it, unless it cannot run on this module
(see [Go version](#go-version)):

```yaml
jobs:
  call-remote-workflow:
    secrets: inherit
    uses: eclipse-xfsc/dev-ops/.github/workflows/<workflow>.yml@main
```
