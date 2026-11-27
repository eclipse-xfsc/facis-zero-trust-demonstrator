# Packaging and containers

How the demonstrator is built, packaged and shipped.

## Artefacts

| Artefact | Built from | Published as |
|---|---|---|
| Service images | `deployment/docker/` | OCI images at the release version, signed by digest |
| Helm charts | `deployment/helm/` | Packaged at the release version and attached to the GitHub release with checksums; pushed as OCI chart artefacts once a registry is configured |
| SBOM | CI | CycloneDX, signed: one of the repository per release, one of each image attested to it |
| Mock attestation | CI, at signing time | JSON document, attested to each image and attached to the release |
| BDD reports | CI | The cucumber-JSON of the release's BDD runs and the traceability sheet merged from them, attached to the release |
| Release manifest and notes | CI | `release-manifest.json`, signed, and the release notes: every artefact above with its digest |

One release carries all of them at one version — the tag's — and nothing less: the release workflow
refuses to create a release with a piece missing or at another version (see [CI/CD — Release](ci-cd.md#release)).

## Rules

- Images are referenced by digest, never by mutable tag, everywhere a cluster consumes them.
- Every image is signed and carries its attestations; admission control rejects any that are not.
- Nothing is built or pushed from a developer machine.

Pipeline configuration is documented in [CI/CD](ci-cd.md).
