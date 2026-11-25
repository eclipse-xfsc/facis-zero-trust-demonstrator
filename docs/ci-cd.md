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
| `.github/workflows/sbom.yml` | schedule, release, manual, `candidate/**` push | Generates, checks and signs a CycloneDX SBOM for every release that lacks a verifying one, and attaches both |
| `.github/workflows/docs.yml` | push to `main` affecting `docs/`, manual | Builds the MkDocs site and publishes it to the `gh-pages` branch |
| `.github/workflows/workflow-hygiene.yml` | every pull request, manual | Fails the pull request when an action is not pinned to a commit or a token scope is too wide |
| `.github/workflows/ci.yml` | every pull request, push to `main`, published release, manual | Go lint and tests, image build with the Linux assertion and a Trivy scan, chart lint and dry-run render, the release set check, the admission catalogue and the admission reconciler each on a kind cluster (see [Admission reconciler](#admission-reconciler)); on a release published by hand, the chart gate once more and the chart packaging and publication (see [Chart release](#chart-release)) |
| `.github/workflows/release.yml` | manual, push to a `candidate/**` branch, push of a tag `v*` | Release candidate: the chart gate (see [Chart gate](#chart-gate)), then builds, pushes, signs and attests every image by digest and verifies each one (see [Image signing](#image-signing)); beside it the secrets baseline (see [Secrets](secrets.md#the-baseline-proof-tdr-bdd-08)). On a tag, the release: the charts packaged at the tag's version, the repository SBOM signed, the BDD suite run, and the GitHub release created with every artefact and the notes that list each one with its digest (see [Release](#release)) |
| `.github/workflows/deploy-ionos.yml` | a successful run of `release.yml` for a tag `v*`, manual with a release tag | Verifies the release manifest and the ORCE image signature against the committed key, deploys the ORCE chart from the release to the IONOS cluster with `helm upgrade --install --rollback-on-failure` and the namespaced deployer of the protected environment `ionos`, then checks the rollout, the running digest and HTTPS on the host; off until `IONOS_DEPLOY_ENABLED` is `true` (see [IONOS](environments/ionos.md#deploying-from-the-pipeline)) |
| `.github/workflows/signing-environment-audit.yml` | manual only | Proves that the `release` environment refuses a run from a ref outside its allowlist and records the verdict (see [Signing environment audit](#signing-environment-audit)) |
| `.github/workflows/measurement-determinism.yml` | pull request and push to `main` touching the check, manual | Measures one fixture on a hosted runner, in a container, and on a deliberately divergent checkout, and requires the normalised measurement to be the same on all three |
| `.github/workflows/token-store.yml` | pull requests touching the token store, the connector, the Participant, the Protected Resource (their services and their `cmd/` entry points), the shared `internal/` packages, the images of the token store, the connector, the Participant and the Protected Resource, the chart or the pinned images; pushes to `main`; manual | Runs the whole token path against a PostgreSQL and an OpenBao from the pinned images, once with opaque and once with signed access tokens, and fails on any skipped test: the schema migrations and queries, the store (replay check, acquisition and its recovery, substitution, renewal) with the real connector binary as the peer zone, the connector's conformance suite on the database stores, the shared packages, and the Participant and Protected Resource end to end through the real connector, their `cmd/` entry points included; then the chart's lifecycle (install, upgrade, uninstall) and the service's readiness against PostgreSQL and OpenBao on kind; then the failure catalogue on kind, every induced failure of the store with its reason code and recovery; the records of both are the run's artefacts and the verdicts go to the job summary |
| `.github/workflows/policy-hook.yml` | pull requests touching the policy-hook probe, its script, the guard, the policy evaluator, the guard chart, the pinned Envoy image or the policy fixtures; manual | Runs the guard policy-hook proofs (`scripts/verify-policy-hook/verify.sh`) against Envoy from the pinned image, uploads the records as an artefact and writes the verdict and the latency numbers to the job summary; then sends gRPC and REST calls through an Envoy of the same pinned image, configured with the guard chart's rendered bootstrap, to the guard's runtime and the policy evaluator's rules (`TestGuardedGRPCThroughEnvoy`) |
| `.github/workflows/admission-evidence.yml` | manual only | Runs the admission evidence pack on one cluster from the protected `admission-evidence` environment and keeps the pack as an artefact, linked to this run and to the fixture run it used (see [Admission evidence](#admission-evidence)) |
| `.github/workflows/connector.yml` | pull requests touching the connector service, the shared client and DPoP packages, the images of the connector and the token store, either chart, the proof or the pinned images; pushes to `main`; manual | Installs the connector chart on kind against a PostgreSQL and an OpenBao from the pinned images, its migration hook applying the schema with the token-store image, waits for the connector to be ready on all four checks, reverts the newest migration and has an upgrade apply it again, registers a client through the registrar with the connector's own image, has the policy refuse a registration with its specific error, and reads both decisions back from the audit trail and the security-state feed; the records are the run's artefact and the verdict goes to the job summary |
| `.github/workflows/attestation-provision.yml` | pull requests touching the provisioning command, package, zone files or proof; manual | Runs the provisioning package's unit tests and `scripts/attestation-provision/prove.sh`: every zone provisioned from Git through its own `estserver` and `cmcd`, a measurement change, and a refused signer. Uploads the run's records |
| `.github/workflows/atls-channel-binding.yml` | pull requests touching the attested channel, its probe or its proof scripts; manual | Re-runs the three attested-channel proofs (`scripts/atls-probe/`) as plain processes, uploads the run's records and writes the verdicts to the job summary. It never writes the committed evidence |

## The service pipeline

`ci.yml` is one pipeline shape that every service in the monorepo reuses, so quality is consistent
and nobody hand-rolls their own:

| Job | What it does | Blocking |
|---|---|---|
| `Go tests` | Calls the shared `go-test.yml`, which runs the tests of every Go module it finds | yes |
| `Go lint` | `golangci-lint run --config .golangci.yml ./...`, with a pinned golangci-lint built by the Go version `go.mod` names. `.golangci.yml` adds `depguard` to the standard linters: only `internal/atls` may import the CMC attested-TLS library, and the test-only `internal/atls/atlstest` may not be imported from non-test code | yes |
| `Image build and scan` | Builds each context under `deployment/docker/` for `linux/amd64`, asserts the built image's OS, then scans it with Trivy for HIGH and CRITICAL vulnerabilities | yes |
| `Chart lint and render` | `scripts/ci/check-charts.sh`: `helm lint` and a `helm template` render of every chart under `deployment/helm/` and `features/fixtures/charts/`, dependencies built from `Chart.lock` and their archives checked against the sha256 committed in the chart's `dependencies.sha256` (`scripts/ci/verify-chart-dependencies.sh`; the archive of a `file://` dependency, packaged from the checkout, has no stable digest and is exempt); then `scripts/ci/check-charts_test.sh`, the cases that hold the script to refusing a package when a chart fails. Two checks then read the policies the umbrella, `zone-policy` and `ztd-openbao` render with every shipped zone file and the CI zone file (render path `scripts/ci/render-zones.sh`), each with its test: `scripts/ci/check-policy-addresses.sh`, no IP address in a policy (ZT-25) other than the Connector gateway's two declared hops outside the mesh (egress to the peer zone's entry, the entry's public ingress), also over every other chart rendered with its `ci/values.yaml` and each `ci/<variant>-values.yaml`, and `scripts/ci/check-policy-l7-owner.sh`, no Cilium policy with a port field that sends traffic to Cilium's L7 proxy (an `http`, `kafka`, `l7` or `l7proto` rule, `listener`, `serverNames`, `terminatingTLS`, `originatingTLS`), no Cilium Envoy configuration, and every rendered allow-matrix policy carrying its single L7 owner `ztd.facis.io/l7-owner`, and every Connector route policy of `deployment/helm/connector-gateway` the owner of its hop (SRS 2.3.3, Table 4; ADR-0009) | yes |
| `Release set` | `scripts/supplychain/release-set_test.sh`: the cases that hold the release's set check to refusing a set with a piece missing or at another version, and to listing every artefact with its digest — see [Release](#release) | yes |
| `Release charts` | On a release published by hand only, once every other gate job of the workflow has passed: runs the chart gate with its server dry-run on a disposable cluster, packages the charts under `deployment/helm/` at the release version, attaches them to the release with their checksums and, when a registry is configured, pushes them as OCI chart artefacts — see [Chart release](#chart-release). A release the release workflow creates carries its charts already | yes — a release whose gates fail ships no chart |

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

The last two are why the licence scan and the SBOM run locally. The licence job does what the shared
one does — the same Eclipse Dash tool with the same review arguments — and the SBOM job keeps the
shared rule of attaching an SBOM to every release that lacks one, with the pinned actions and declared
permissions this repository requires of its own workflows. The SBOM job goes further than the shared
one: it uses the pinned Syft, the same tool as the image SBOMs, checks the result and signs it (see
[Release SBOM](#release-sbom)). They can go back to
being references once the shared workflows accept a Go version or read `go.mod`; that is a change to
propose in `eclipse-xfsc/dev-ops`.

## Chart gate

No release candidate is built unless every chart passes (TDR-BDD-11). The `chart-gate` job of
`release.yml` creates a disposable kind cluster, installs the CRDs the charts render against (Cilium's
network policies, Gatekeeper's external-data `Provider` and Argo CD's `Application` and `AppProject`,
each from a chart or manifest pinned in `scripts/tools/pins.env`), and
runs the row in cluster mode: `scripts/ci/check-charts.sh --server-dry-run` lints, renders and
dry-runs every chart against that API server, and two deliberately broken charts under
`features/fixtures/broken-charts/` must be refused by the check each targets — one by `helm lint`,
one only by the server dry-run (it ships a resource whose API the cluster does not serve). The step
also checks that the `candidate` job needs the gate. The `candidate` job has `needs: [chart-gate]`,
and so has the `release` job; any later job that publishes charts or creates a release must need it
too, or run it again. On a release tag the gate job itself packages the charts, on the cluster it
just ran on (see [Release](#release)); the `Release charts` job of `ci.yml` runs on a release
published by hand, which no gate run is tied to, so it creates the same disposable cluster and runs
the same script with `--server-dry-run` before it packages anything (see [Chart release](#chart-release)).

A server dry-run renders the chart, discovers the API and its schemas and checks existing resources.
It does not run admission webhooks or hooks, and proves nothing about the release at runtime: that is
what the lifecycle scenarios and the secrets baseline install for real. Without `--server-dry-run`,
as in the pull-request job, the script records the server dry-run as not run, never as passed.

The gate and the secrets baseline (TDR-BDD-08) run on a disposable cluster in `release.yml`, which
decides both rows with a sheet of its own; the pull-request sheet and the client-target sheets list
them as not run.

## Cilium upgrades

The mesh relies on the Istio CNI plugin chained after Cilium on every node, and ADR-0001 and ADR-0009
require that order to be checked again after every Cilium upgrade. The pipeline only renders, so the
check is a proof run on a disposable kind cluster: `scripts/verify-cni-chaining-upgrade/verify.sh`
installs the zone over Cilium at the zones' version, upgrades Cilium with `helm upgrade --reset-then-reuse-values` (the release's own values over the new chart's defaults),
and checks before and after the upgrade the chain on every node, `cni-exclusive=false`, an allow-matrix
lane served through the proxies and the default deny; after the upgrade also a pod created after it,
which must hold a SPIRE-issued certificate for its own SPIFFE ID and be served on its lane
([the proof](https://github.com/eclipse-xfsc/facis-zero-trust-demonstrator/tree/main/scripts/verify-cni-chaining-upgrade)).
Run it, and keep its run directory with the change, whenever the pinned Cilium version
(`CILIUM_CRDS_VERSION` in `scripts/tools/pins.env`, the default of `scripts/dev/kind-cilium-up.sh`) or
the zones' version changes. On the participant clusters the provider upgrades Cilium; there the mesh
identity proof detects the upgrade at its next run, failing when the running Cilium differs from the
zone file's `cni.cilium.version`, and its chain section is the re-check after the recorded version is
updated
([OSC environment](environments/osc.md#1-cni-verify-the-providers-cilium)).

## Admission reconciler

The `admission-gitops` job proves the path from Git to the cluster that
[deployment/argocd](../deployment/argocd/README.md) builds: a kind cluster with Gatekeeper and the
pinned Argo CD, handed the admission policy of the revision under test by `scripts/argocd/install.sh`,
fetched from the repository the revision came from (the pull request's head repository and commit, or
the pushed commit). The job checks out that same commit, not the merge commit, so the catalogue the
cluster converged to can be compared file by file with the checkout. It then proves what the zones
rely on: every Application `Synced/Healthy`, the zone's repository prefix patched into the
allowed-repositories constraint, a hand-edited constraint put back (`scripts/argocd/drift-check.sh`),
a hand-edited child Application put back by its parent, and one `argocd_app_info` series with
`sync_status="Synced"` per Application in the controller's metrics. What it cannot prove on a
disposable cluster is a change *merged* after the install reaching the cluster: that is the same
reconciliation the self-heal exercises, and it is observed on the zones after a merge.

## Image signing

The candidate job of `release.yml` builds every image under `deployment/docker/` for `linux/amd64`,
labels it `eu.facis.ztd.signing-key=<source>` (`interim` by default) and pushes it to
`ghcr.io/<owner>/<repository>/<name>`.
Then, for each image digest:

1. `scripts/supplychain/sbom.sh` — the Syft SBOM of the image, scanned by digest, enriched by Grype with
   the known vulnerabilities (CycloneDX JSON);
2. `go run ./cmd/mockattest` — the mock attestation (ZT-71), checked against the schema admission
   enforces;
3. `scripts/supplychain/sign-attest.sh` — the cosign signature and both attestations, the same commands
   the CI interop and kind tests use;
4. verification of every digest against the committed public key of the selected source
   (`docs/contracts/keys/interim-cosign.pub` by default), with the admission provider's own code
   (`cmd/imageverify`) and with `cosign verify` / `verify-attestation`.

The key is the one the repository variable `SIGNING_KEY_SOURCE` selects ([Key source](#key-source));
by default the `COSIGN_INTERIM_KEY` secret (with `COSIGN_INTERIM_PASSWORD`) of the protected
`release` environment. Without it, or without its committed public key, the job fails before
anything is signed. The interim key is not the client trust chain; it is replaced by the client key
and Harbor. The job creates no tag and no release.

It checks the key before it builds anything: the secret must be set and must be the private half of
the committed public key, so a missing environment, secret or key file stops the job before an image
is pushed. GHCR creates new packages as private; the job verifies them with its own token, but a
cluster pulls and verifies anonymously unless the admission provider is given read credentials, so
the candidate packages must be made public in the package settings (once per package) before such a
cluster can admit them. With Harbor ([Image registry](#image-registry)) the push and the checks use
two different robot accounts.

## Release SBOM

`sbom.yml` gives every published release two assets: `sbom.json`, the CycloneDX inventory of the Go
module at the release tag, and `sbom.json.sig`, its signature. For each release, `scripts/supplychain/repo-sbom.sh`:

1. scans the tag's checkout with the pinned Syft, Go module only (the images have their own SBOMs);
2. checks it with `go run ./cmd/sbomcheck`: valid CycloneDX against the schemas admission uses, and every
   module the tag's tidy `go.mod` requires present at the required version, replacements resolved. With
   module graph pruning a tidy `go.mod` lists every module that supplies a package to any build or test, on
   any platform and build tag, so transitive dependencies are included;
3. signs it with `cosign sign-blob` and the selected key ([Key source](#key-source)), in the profile
   the images use (key-based, no transparency log), and verifies the signature against that source's
   public key before anything is uploaded.

A release counts as done only when both assets are attached and the signature verifies against a key
of the set — every public key committed under `docs/contracts/keys/`. A release that carries neither
file is signed from its tag on the next run; the monthly run, or one started by hand, covers every
release (`scripts/supplychain/sbom-backfill.sh`). A half-finished upload, or a pair that verifies
against no key of the set, is regenerated only when its release was signed with the current key — the
key its `release-manifest.json` names, or the interim key for a release without one — and otherwise
fails the run for a person to decide: an existing asset of an old release is never replaced under a
new key. Which assets a release carries is read from its asset list; a listing or a download that
fails fails the run for that release, so an unreadable asset is never taken for a missing one.
Removing a public key from the set is how a key is retired; the releases it signed then fail that run. A release the
[release workflow](#release) creates carries the pair from the start, written by the same script with
the same key, so this workflow finds it verifying and leaves it.

To verify a release's SBOM:

```bash
gh release download <tag> --pattern 'sbom.json*' --pattern release-manifest.json
# the key the release was signed with; a release without a manifest was signed with the interim key
key=$(jq -r .publicKey release-manifest.json 2>/dev/null || echo docs/contracts/keys/interim-cosign.pub)
cosign verify-blob --key "$key" --insecure-ignore-tlog=true --signature sbom.json.sig sbom.json
```

The interim key is replaced by the client key with the rest of the signing chain. The key lives in the
`release` environment; for the run that a published release starts — which runs on the tag — to reach
it, the environment must admit the release tags (`v*`) as well as `main` and `candidate/*`. That is a
repository setting; until it is applied, the monthly or a manual run signs new releases.

## Chart release

The Technical Development Requirements deliver the Helm charts with each release. The candidate
stage above creates no tag and no release; the charts are delivered by the [release](#release) stage
of `release.yml`, which the push of a release tag starts: its chart gate packages them, at the tag's
version, on the cluster it just proved them on, and the release job attaches them to the release it
creates. A release published by hand on GitHub gets its charts from the `Release charts` job of
`ci.yml` instead, and only after every gate job of that workflow has passed — the lifecycle jobs
included, which may be skipped while the repository variable is off but not failed or cancelled.
That job runs the [chart gate](#chart-gate) once more, on a disposable kind cluster of its own with
the same CRDs: no gate run is tied to a release published by hand, and a published chart must not
skip the server dry-run. Lint, render and the server dry-run are the gate in front of the package,
so a chart that fails any of them is never released, which is the rule of Annex A row TDR-BDD-11.
The pull-request job, the release gate and both release jobs run the same `scripts/ci/check-charts.sh`,
which checks every chart first and packages only when all of them pass, so the gate a pull request
clears is the gate the release is held to. Each package is then checked again as its source was,
with the chart's own values: the version now differs from `Chart.yaml`, and a template that reads
it renders differently. One failing package leaves no package at all.
`scripts/ci/check-charts_test.sh` holds the script to that in the chart job, against charts it
writes itself: a set that passes is packaged at the version with matching checksums, and one failing
chart leaves no package, at the source or once packaged.

A release is tagged `vX.Y.Z`, or `vX.Y.Z-prerelease`. The charts are packaged at that version — the
tag drives `--version` and `--app-version`, over the development version in each `Chart.yaml` — so
the release and every chart in it carry one version, and the documentation of a release describes
the charts it ships. A tag that is not semantic versioning stops the job before it names a package,
and so does build metadata (`+`): the charts put their version into the `helm.sh/chart` label, and
`+` is not allowed in a label value. The packages and a `SHA256SUMS` file are attached to the
release as assets.

Publication to a registry stays off until one exists. When the repository variable `CHART_REGISTRY`
names the OCI path for charts (for example `harbor.example.org/facis/charts`) and the secrets
`CHART_REGISTRY_USER` and `CHART_REGISTRY_PASSWORD` hold a robot account allowed to push there, both
release jobs also push every package with `helm push` and print the digest of each into the run
summary; the release job records it in the manifest as well. That digest is what a zone file pins:
the lifecycle workflow accepts a chart only as a local path or as an `oci://` reference pinned by
digest.

Locally, `scripts/ci/check-charts.sh` runs the same check, and
`scripts/ci/check-charts.sh --package dist --version 0.0.0-local` the same packaging, for a look at
what a release would ship; with a cluster in the current kube context, `--server-dry-run` adds the
gate's dry-run to both.

## Release

A release is one push of a tag `vX.Y.Z` (or `vX.Y.Z-prerelease`) by a maintainer. The tag starts
`release.yml` as a candidate branch does, and that run becomes the release: the [chart gate](#chart-gate),
the images and the [secrets baseline](secrets.md#the-baseline-proof-tdr-bdd-08) run as on a candidate,
with the tag's version as the image tag, and the `release` job then gathers everything the run
produced and creates the GitHub release from it. One version, the tag's, is carried by every
artefact: the charts are packaged at it (`--version` and `--app-version`), the images are tagged with
it, and the release job checks that each image's version tag still names the digest that was signed
before anything is listed.

The release job, in order:

1. `scripts/supplychain/repo-sbom.sh` — the [repository SBOM](#release-sbom), signed and verified, with
   the script and the key `sbom.yml` uses;
2. the BDD suite for the tag, as the `bdd` job of `ci.yml` runs it on a pull request, with one
   difference: the two rows this run proved on a cluster, TDR-BDD-08 and TDR-BDD-11, come from the
   audit's and the gate's reports instead of the dry-run listing — a listing beside a real report
   keeps a row from passing ([BDD acceptance](bdd.md#the-traceability-sheet)). `bddreport
   --require-complete` then merges every report of the run into one sheet;
3. the chart push, when `CHART_REGISTRY` is set ([Chart release](#chart-release)), each digest
   recorded;
4. `scripts/supplychain/release-set.sh` — the set, checked: every image reference is a digest and has
   the SBOM attested to it, bound to that digest as admission binds it; every chart package is at the
   version and in `SHA256SUMS`; the repository SBOM has its signature; the mock attestation and the
   cucumber-JSON are there, with the sheet merged from them. A piece missing or at another version
   refuses the set, and no release is created. The script writes `release-manifest.json` — every
   asset with its SHA-256, and the images and charts with what each digest belongs to — and
   `RELEASE_NOTES.md`, the same list for the release page with the commands that check it;
5. the manifest signed with the selected key (`cosign sign-blob`, the profile of the images) and
   verified;
6. `scripts/supplychain/verify-release.sh` — the last gate: the manifest must name the selected
   source's public key and its signature must verify; the upload set must be exactly the signed
   list — every asset of the manifest present with its signed SHA-256, nothing it does not list;
   `sbom.json.sig` must verify, and every image of
   the manifest must carry, by digest, a signature and both attestations that verify against that
   key, read with the job's read credentials. One that does not stops the job: the tag stays without
   a release (`scripts/supplychain/verify-release_test.sh` holds it to that);
7. `gh release create`, with the notes and every asset. A rerun completes or replaces the release
   with its own set: an asset of the same name is overwritten, one the set does not carry is removed.

The release carries: the chart packages and their `SHA256SUMS`; `sbom.json` and `sbom.json.sig`;
one `<image>.cdx.json` per image and `mock-attestation.json`; `did.json` when `SIGNING_DID_WEB` is
set ([Trust anchor](#trust-anchor-didweb)); the cucumber-JSON of every run as
`bdd-*.json`, with `bdd-traceability.md` and `.csv`; `release-manifest.json` and its `.sig`. The
images themselves are in the registry, listed in the notes and the manifest by digest.
`scripts/supplychain/release-set_test.sh` holds the script to the refusals above, against sets it
writes itself; the `Release set` job of `ci.yml` runs it on every pull request.

To consume a release:

```bash
gh release download vX.Y.Z
sha256sum -c SHA256SUMS
key=$(jq -r .publicKey release-manifest.json)       # a path in this repository's docs/contracts/keys/, never a downloaded key
cosign verify-blob --key "$key" --insecure-ignore-tlog=true \
  --signature release-manifest.json.sig release-manifest.json
jq -r '.images[].reference' release-manifest.json   # what a zone file pins: repository@sha256:<digest>
```

Each image's `reference` is `repository@sha256:<digest>`, without the tag: the admission policy
denies a reference that carries a tag and a digest together (`ADM-NOT-DIGEST`). The release version
is the image's `tag` field.

Two rules of GitHub shape this. A release created with the workflow's own token starts no other
workflow (`workflow_dispatch` and `repository_dispatch` are the exceptions), so the `Release charts`
job of `ci.yml`, `sbom.yml` and the lifecycle jobs do not run for it: the charts and the SBOM are
delivered by the release job with the same scripts, and the lifecycle rows (TDR-BDD-01..04, 06) stay
with the runs on `main` and on demand. And the `release` environment, which holds the key, admits
only the refs it is configured for: for a tag run to reach it the environment must admit `v*`, the
same repository setting the [release SBOM](#release-sbom) needs; without it the run stops at the
images job, before an image is pushed.

A release published by hand on GitHub is not the set: `ci.yml` attaches its charts and `sbom.yml`
its SBOM, but no image is built for it and no notes list it.

## Signing configuration

Every job that holds signing key material uses the protected `release` environment: the
candidate and release jobs of `release.yml`, the job of `sbom.yml` and the job of
`admission-fixtures.yml`. Each part below is off until the input named for it exists; until then
the workflows behave as they did with the interim key on GitHub's hosted runner.

### Signing runner

The three signing workflows run their signing job on the runner the repository variable
`SIGNING_RUNNER` names: a JSON array of runner labels, for example
`["self-hosted","ztd-signing"]`. A first job, `Signing runner`, checks the value with
`scripts/supplychain/runner-labels.sh` and hands it to `runs-on` through `fromJSON`; a value that
is not a non-empty array of plain labels fails that job, so no signing job starts on a runner nobody
chose. Unset, the jobs run on `ubuntu-latest`. The chart gate, the secrets baseline and the audits
hold no key and stay on hosted runners.

Activation: register the runner with the repository, give it the labels, check it is online
(Settings → Actions → Runners), then set `SIGNING_RUNNER`. The runner needs Docker with Buildx, Git,
`jq`, `gh` and Python 3; Go, Helm and Node are installed by the jobs, cosign, Syft and Grype by
`scripts/tools/install.sh` (linux/amd64). `scripts/supplychain/runner-labels_test.sh` holds the
check to its refusals.

### Signing environment audit

That a signing workflow refuses an unauthorised trigger cannot be asserted inside the protected job:
a job the environment refuses never starts. `signing-environment-audit.yml` proves it from outside,
started by hand: its `Environment audit` job (no secret; `contents: write` for a disposable branch,
`actions: write` to dispatch, `checks: read` for annotations) creates a branch it owns,
`audit/env-probe-<run id>-<attempt>`, at the current commit, or takes the `probe_ref` input, dispatches the same workflow on it in probe mode,
waits for that run and decides with `scripts/supplychain/env-audit.sh`: **refused** when the
`Environment probe` job — which names the `release` environment and holds nothing — failed with
GitHub's "not allowed to deploy" annotation — read from the job's check run, `check_run_url` — before
any step ran; **admitted** when a step ran;
**inconclusive** otherwise (for example, the job waiting for a reviewer). Only *refused* passes. The
record, `env-audit.json`, is the run's artefact and is the evidence for ZT-10. Annotations that
cannot be read fail the audit. The owned branch's deletion is armed before the branch is created,
retried, and counts a branch already gone as deleted; a branch it cannot delete fails the audit, so
none is left behind silently. A `probe_ref` given by hand is never deleted. An allowlisted ref (`main`, `candidate/*`, `v*`) is refused as a probe.

Activation: apply the environment allowlist ([Release tags and the release environment](#release-tags-and-the-release-environment)),
then run the workflow from `main` and keep the artefact. Two points are *inferred, not yet observed*:
that the job token may create a branch at a commit that carries workflow files (if it may not, create
a branch outside the allowlist by hand and pass it as `probe_ref`), and the exact wording of GitHub's
refusal, matched loosely (`not allowed to deploy to release` or `environment protection rules`).
`scripts/supplychain/env-audit_test.sh` holds the verdict to its cases.

### Signing log audit

No log of a job that holds the key may show key material (ZT-10). Each signing workflow ends with
a `Signing log audit` job that runs once the signing jobs have completed, successful or failed, reads
their published logs through the API (`actions: read`, no secret) and runs
`scripts/secrets/log_audit.py signing-audit`: PEM private-key blocks, the same blocks base64-encoded,
cosign's encrypted-key markers, a password or token variable printed with a value instead of `***`,
and Vault/OpenBao token shapes. It records counts and verdicts only, never a matched text, in the
`signing-log-audit` artefact, and fails on any hit. A job that never started — skipped, or refused by
the environment — is recorded and not scanned; a run in which none of the named jobs exists fails,
because the names no longer match the workflow. The canary audit of the secrets baseline is a
separate mode of the same script and is unchanged. `scripts/secrets/log_audit_test.py` holds the
patterns and the verdicts to their cases.

### Key source

`SIGNING_KEY_SOURCE` selects where the signing key comes from; `scripts/supplychain/key-source.sh`
turns it into the cosign key reference and the one public key every check verifies against, and the
`Select the signing key` step writes both into the job's environment (references and paths, never
key material). `check-key.sh` then requires the key to be reachable and to be the private half of
that public key before anything is built.

| `SIGNING_KEY_SOURCE` | cosign key | Inputs | Public key |
|---|---|---|---|
| `interim` (default) | `env://COSIGN_INTERIM_KEY` | secrets `COSIGN_INTERIM_KEY`, `COSIGN_INTERIM_PASSWORD` | `docs/contracts/keys/interim-cosign.pub` |
| `client` | `env://COSIGN_CLIENT_KEY` | secrets `COSIGN_CLIENT_KEY` (a cosign key file), `COSIGN_CLIENT_PASSWORD` | `docs/contracts/keys/client-cosign.pub` |
| `openbao-transit` | `hashivault://<SIGNING_TRANSIT_KEY>` | variables `SIGNING_TRANSIT_KEY`, `SIGNING_VAULT_ADDR`, optional `SIGNING_TRANSIT_PATH` (default `transit`); secret `SIGNING_VAULT_TOKEN` | `docs/contracts/keys/openbao-transit-cosign.pub` |

With `openbao-transit` the private key never leaves OpenBao: cosign's HashiCorp Vault KMS asks the
transit engine to sign. OpenBao serves the same transit API, so this is expected to work unchanged —
*an inference, not yet run against the deployed OpenBao*. The transit key must be of a type cosign
accepts (`ecdsa-p256` is the safe choice), the token's policy needs only `read` on
`<mount>/keys/<key>` and `update` on `<mount>/sign/<key>`, and the signing runner must reach
`SIGNING_VAULT_ADDR`. The signing steps receive only the selected source's secrets — the others are
passed as empty — and a secret left empty stays empty: a client key without a password is used
without one, never with the interim password.

Activation, per source: commit the source's public key under `docs/contracts/keys/` by pull request
(`cosign public-key --key hashivault://<key>` prints it for transit), add its secrets to the
`release` environment and its variables to the repository, then set `SIGNING_KEY_SOURCE`. The
committed public key is the only verification key of the source: the release manifest and notes,
`sbom.yml` and the did:web anchor all read it from there. `scripts/supplychain/keys_test.sh` holds the
selection, the key check and the SBOM key set to their refusals.

### Trust anchor (did:web)

ZT-11 asks for the trust anchor to be provided via did:web and linked over TRAIN.
`go run ./cmd/didweb -did <host[:port][/path]> -key <public key> [-key ...]` writes the DID document:
one `JsonWebKey2020` verification method per key, its fragment the key's RFC 7638 thumbprint, each an
assertion method; the same keys give the same bytes in any order (`cmd/didweb/main_test.go`, which
also checks the thumbprint against RFC 7638's own example). Once the repository variable
`SIGNING_DID_WEB` names where the document is served, the release job generates it from the selected
source's public key, the release carries it as `did.json`, and the manifest names the DID as
`trustAnchor`. Unset, no document is generated and `trustAnchor` is `null`.

The document is served, unchanged, at the URL a did:web resolver reads: `https://<host>/.well-known/did.json`
for a bare host (`did:web:<host>`), `https://<host>/<path>/did.json` for a host with a path
(`did:web:<host>:<path segments>`); `didweb` prints the URL. Then TRAIN links it: the signing DID is
entered in the trust list of the framework through TSPA, so a verifier that resolves the framework's
chain (`_scheme._trust.<zone>` → trust list, [TRAIN DNS zone](train-dns.md)) finds the key the
releases are signed with. The key material stays where the [key source](#key-source) keeps it — in
OpenBao's transit engine with `openbao-transit`; only the public key is published.

The anchor's place is decided by the project lead: the image-signing trust anchor is
`did:web:tspa.facis.cloud:ztd:release-keys`, served at
`https://tspa.facis.cloud/ztd/release-keys/did.json`, next to TSPA. TSPA keeps its own root DID,
`did:web:tspa.facis.cloud` at `/.well-known/did.json`; the path form keeps the two documents apart,
since one host has one root document. `cmd/didweb` maps that DID to that URL (path form, not
`.well-known`), held by its test.

Activation: set the repository variable `SIGNING_DID_WEB` to `tspa.facis.cloud/ztd/release-keys`;
cut a release; have TSPA's web server serve the release's `did.json`, unchanged, at
`https://tspa.facis.cloud/ztd/release-keys/did.json`; check it
(`curl -fsS https://tspa.facis.cloud/ztd/release-keys/did.json | cmp - did.json`); and register
`did:web:tspa.facis.cloud:ztd:release-keys` in the trust list through TSPA. A new signing key (a change
of key source) means a new `did.json` from the next release, served in place of the old one.

### Image registry

The images and their signatures go to this repository's GHCR namespace until the repository
variables `HARBOR_HOST` (a host, optional `:port`, no scheme) and `HARBOR_PROJECT` name a Harbor
project; `scripts/supplychain/registry.sh` then answers `<HARBOR_HOST>/<HARBOR_PROJECT>` for the
candidate images, the release job and the admission fixtures. Two Harbor robot accounts, as
secrets of the `release` environment:

| Secrets | Used for |
|---|---|
| `HARBOR_PUSH_USER`, `HARBOR_PUSH_PASSWORD` | the push of the images, their signatures and attestations |
| `HARBOR_READ_USER`, `HARBOR_READ_PASSWORD` | every check after the push: `cmd/imageverify`, `cosign verify` and `verify-attestation` (a Docker config of their own, `VERIFY_DOCKER_CONFIG`), and the release job, which only reads |

On GHCR both roles are the job token, as before. The credentials are chosen by the registry's kind,
never by fallback: with `HARBOR_HOST` set, an empty Harbor secret stays empty and
`scripts/supplychain/registry-login.sh` fails before anything is sent, so the job token never goes to
Harbor. Activation: create the project and the two robot
accounts in Harbor (push: push and pull on the project; read: pull only), add the four secrets,
set the two variables, and add the Harbor path to the admission chart's `trust.repositories`. A
cluster that pulls from a private project needs the read account as well: an image pull secret for
the workloads, and `registryAuth.secretName` for the admission provider (the `admission` chart,
`deployment/helm/admission/README.md`).
`scripts/supplychain/registry_test.sh` holds the selection to its refusals.

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

## Cluster reachability

The `cluster-reachability` job checks, for each client cluster (IONOS, OSC zone A, OSC zone B), that
the API server answers the pipeline and that the observer identity authenticates (`kubectl version`,
`kubectl auth whoami`). It runs on pushes to `main`, on releases and on demand, never on pull requests,
and does not depend on `BDD_CLUSTER_ENABLED`. A target is checked once its secret
`BDD_<KEY>_OBSERVER_KUBECONFIG` is set (`IONOS`, `ZONE_A`, `ZONE_B`); until then the run says it was
not checked, and never that it was reachable. Once the secrets are in place, the repository variable
`CLUSTER_REACHABILITY_REQUIRED` (comma-separated targets, for example `ionos,zone-a,zone-b`) makes the
check mandatory: a listed target whose secret is missing fails the job instead of being skipped.

The OSC zones have no BDD pool, so their observer is the service account in
[deployment/ci/reachability-observer.yaml](https://github.com/eclipse-xfsc/facis-zero-trust-demonstrator/blob/main/deployment/ci/reachability-observer.yaml): the
manifest grants it nothing, so it holds only what every authenticated identity is bound to by default
(API discovery, the server version, a review of its own access). A cluster administrator applies it,
checks its effective rights (`kubectl auth can-i --list --as=system:serviceaccount:ztd-ci:ztd-ci-observer`),
builds the kubeconfig from the token in `ztd-ci/ztd-ci-observer-token` and hands it to a maintainer
for the secret. The token does not expire; deleting that Secret revokes it.

## Admission evidence

`admission-evidence.yml` runs `scripts/admission/evidence-pack.sh` on one cluster (`zone-a`, `zone-b` or
`ionos`) with the fixture list of a named "Admission fixtures" run, and uploads the pack as the
artefact `admission-evidence-<target>`. The pack's index records this run and the fixture run, so the
evidence names the pipeline runs that produced it. The fault cases take the provider and Gatekeeper
down and remove the webhook for a short time before restoring them, so the job is started by hand, one
cluster at a time (a concurrency group per cluster), from the protected environment
`admission-evidence`, which should require a reviewer. It needs, in that environment:

| Name | Kind | Content |
|---|---|---|
| `ADMISSION_ZONE_A_ADMIN_KUBECONFIG`, `ADMISSION_ZONE_B_ADMIN_KUBECONFIG`, `ADMISSION_IONOS_ADMIN_KUBECONFIG` | secret | an administrator kubeconfig for the cluster (the fault cases scale Gatekeeper and the provider) |

Until it is set, the job stops with a notice and records nothing. The provider's settings - image,
trust keys, repositories, digest allow-list, registry credentials, replicas - are read from the
cluster before any fault and are what every restore puts back; nothing the job is given replaces them.
The key the index names is the selected signing key source (`SIGNING_KEY_SOURCE`, as for the
fixtures). The job builds the umbrella chart's dependencies from `Chart.lock` first (the umbrella
layout's restore upgrades release `gatekeeper` from it), and the fault script dry-runs its restore
before it injects anything, refusing to start if the restore could not run. Namespaces carrying the
admission label are never counted as outside admission, whatever the job passes.

## Image scan exceptions

Every image is scanned and a HIGH or CRITICAL finding fails the build. When a finding sits in an
upstream component that this project cannot fix in its own layer, a `scan-exception.json` next to
the image's Dockerfile may exclude named paths from the gate. It must carry an expiry date, the
reason and the tracking of the upstream fix; the job prints it into the run summary and fails the
build once it has expired. The ORCE image carries one for the upstream ORCE runtime and kubectl, expiring 18 December 2026;
the Helm it builds from source is back under the gate. The TSPA image carries one for the
dependencies of the upstream TRAIN trust-framework manager inside its WAR, expiring the same day; the
Tomcat it runs on and its operating system packages stay under the gate.

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

### Release tags and the release environment

A release exists only as the output of `release.yml` on a tag `v*`, and the run refuses to publish
anything whose signatures do not verify ([Release](#release), step 6). What the repository tree cannot
enforce are the two settings that keep anyone else from reaching the key or from creating a tag;
a repository administrator applies them:

| Setting | Required value |
|---|---|
| Tag ruleset, target `refs/tags/v*` | Restrict creations, updates and deletions; bypass list: the release maintainers only. A tag cannot be moved to another commit once its release exists |
| Environment `release`, deployment branches and tags | Selected refs only: `main`, `candidate/*` and tags `v*` (plus `fixtures/*` while the admission fixtures are published) — no other branch, no pull-request ref |
| Environment `release`, secrets | Only the inputs of the selected key source and the Harbor robot accounts ([Signing configuration](#signing-configuration)) |

With the ruleset a tag that was not pushed by a maintainer does not exist, and with the allowlist a
run from any other ref stops before the signing job starts: GitHub refuses the job with
"not allowed to deploy to release", and no step — none of the key — runs. The
[signing environment audit](#signing-environment-audit) records that refusal.

### Token scopes

The repository's default workflow token is read-only — an administrator setting applied alongside the
ruleset above. Every workflow then declares its own top-level `permissions:` block rather than
relying on that default, and a job that needs more than read access grants it at the job level with
a comment naming the reason: `docs.yml` writes to `gh-pages`, `sbom.yml` uploads the SBOM onto a
release, the release candidate job pushes images and signatures to GHCR (`packages: write`), the
release job creates the release with its set (`contents: write`) and reads the image manifests back
(`packages: read`), and the `Release charts` job attaches the packaged charts to a release. The
signing log audits read job logs (`actions: read`), and the signing environment audit creates and
deletes its probe branch and dispatches its probe (`contents: write`, `actions: write`, `checks: read`). Wildcard
scopes (`write-all`) are never used.

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

`docs.yml` builds the MkDocs site and pushes it to the `gh-pages` branch, both at the branch root
and under `docs/`. GitHub Pages must be enabled on the repository with its source set to that
branch — a one-time repository setting a maintainer applies. The folder may be `/` (preferred) or
`/docs`; the site is identical in both.

## Adding a workflow

Reference the shared workflow rather than reimplementing it, unless it cannot run on this module
(see [Go version](#go-version)):

```yaml
jobs:
  call-remote-workflow:
    secrets: inherit
    uses: eclipse-xfsc/dev-ops/.github/workflows/<workflow>.yml@main
```
