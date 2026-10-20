# Packaging and containers

How the demonstrator is built, packaged and shipped.

## Artefacts

| Artefact | Built from | Published as |
|---|---|---|
| Service images | `deployment/docker/` | OCI images, signed by digest |
| Helm charts | `deployment/helm/` | Packaged at the release version and attached to the GitHub release with checksums; pushed as OCI chart artefacts once a registry is configured |
| SBOM | CI | CycloneDX, signed, one per release |
| Mock attestation | CI, at signing time | JSON document per image |

## Rules

- Images are referenced by digest, never by mutable tag, everywhere a cluster consumes them.
- Every image is signed and carries its attestations; admission control rejects any that are not.
- Nothing is built or pushed from a developer machine.

Pipeline configuration is documented in [CI/CD](ci-cd.md).
