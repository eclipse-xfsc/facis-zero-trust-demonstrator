# FACIS Zero Trust Demonstrator (FACIS.ZTD)

An Apache-2.0 Zero Trust demonstrator built for the FACIS project and released inside the
Eclipse XFSC organisation. It shows, end to end and in the open, how two organisations in separate
Kubernetes zones can call each other's services with every hop authenticated, authorised and
attested — and, just as importantly, what a refusal looks like when any of that fails.

## Concept and scope

The demonstrator stands up two demonstration zones and lets a participant backend in one call a
protected resource in the other. Along the way it exercises the parts of a zero-trust architecture
that are usually asserted rather than shown:

- **Workload identity** issued by SPIRE and carried by the service mesh, so every workload proves
  what it is before it talks to anything.
- **Admission control** that refuses to start an image that is not signed and attested.
- **An authorization connector** that registers clients dynamically, issues tokens bound to the
  holder's key (DPoP), and substitutes upstream credentials so a caller's own proof is never
  forwarded onward.
- **A policy guard** in front of every protected resource, evaluating Rego policy on each request
  and returning a reason — and an OID4VP link — when it says no.
- **An attested channel** between the zones, where both ends prove which software they are running
  during the TLS handshake and the evidence is bound to that exact connection.
- **Verifiable credentials and trust lists**, so who is trusted is data that can be published,
  audited and revoked rather than configuration nobody can see.
- **An ORCE-based demonstrator UI** that shows each step and each decision live, including the
  refusals.

Scope is deliberately a demonstrator: mock attestation stands in for real TEE hardware, and the
demonstration services are purpose-built. What is *not* mocked is the security machinery itself.

## Repository layout

| Path | Contents |
|---|---|
| `services/` | Go services — connector, guard adapter, token store, gateway, demonstration services |
| `flows/` | ORCE orchestration flows |
| `ui/` | ORCE Builder nodes and the demonstrator UI |
| `deployment/helm/` | Helm charts, including the umbrella chart that installs a full zone |
| `deployment/docker/` | Container build contexts |
| `docs/` | Project documentation, published to GitHub Pages via MkDocs |
| `docs/adr/` | Architecture Decision Records |
| `docs/contracts/` | Interface contracts — OpenAPI and JSON Schema definitions, with their samples |
| `scripts/` | Developer and operations scripts |
| `tools/` | Checks that run in CI but are not part of the delivered module |
| `.github/workflows/` | CI, referencing the shared workflows in `eclipse-xfsc/dev-ops` |

This is a monorepo: sub-projects are folders in this single repository, and it is the single source
of truth for the demonstrator.

## Installation and setup

The demonstrator targets Kubernetes 1.29 or later. Full instructions live in the documentation:

- [Deployment and teardown](docs/deployment.md)
- [Features and journeys](docs/features.md)
- [Packaging and containers](docs/packaging.md)
- [Keycloak integration](docs/keycloak.md)
- [CI/CD pipeline](docs/ci-cd.md)
- [API documentation](docs/api-docs.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Architecture decisions](docs/adr/)

Environment variables and chart values are documented alongside each chart under
`deployment/helm/`.

## Documentation

Documentation is written in Markdown under `docs/` and built with [MkDocs](https://www.mkdocs.org/).
To preview it locally:

```bash
pip install mkdocs
mkdocs serve
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions require a signed
[Eclipse Contributor Agreement](https://www.eclipse.org/legal/ECA.php).

## Contact

Maintained by ATLAS IoT LAB GmbH for the FACIS project.

- Project contact: <d.pires@atlas-ios.de>
- Eclipse XFSC developer list: <https://accounts.eclipse.org/mailing-list/xfsc-dev>

## License

Apache License 2.0 — see [LICENSE](LICENSE).

`SPDX-License-Identifier: Apache-2.0`
