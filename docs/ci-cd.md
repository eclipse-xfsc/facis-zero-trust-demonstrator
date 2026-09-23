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
| `.github/workflows/ci.yml` | every pull request, push to `main`, manual | Go lint and tests, image build with the Linux assertion and a Trivy scan, chart lint and dry-run render |
| `.github/workflows/measurement-determinism.yml` | pull request and push to `main` touching the check, manual | Measures one fixture on a hosted runner, in a container, and on a deliberately divergent checkout, and requires the normalised measurement to be the same on all three |

## The service pipeline

`ci.yml` is one pipeline shape that every service in the monorepo reuses, so quality is consistent
and nobody hand-rolls their own:

| Job | What it does | Blocking |
|---|---|---|
| `Go tests` | Calls the shared `go-test.yml`, which runs the tests of every Go module it finds | yes |
| `Go lint` | `golangci-lint run ./...`, with a pinned golangci-lint built by the Go version `go.mod` names | yes |
| `Image build and scan` | Builds each context under `deployment/docker/` for `linux/amd64`, asserts the built image's OS, then scans it with Trivy for HIGH and CRITICAL vulnerabilities | yes |
| `Chart lint and render` | `helm lint` and a `helm template` dry-run render of every chart under `deployment/helm/` | yes |

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
release. Wildcard scopes (`write-all`) are never used.

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
