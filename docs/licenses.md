# Licenses

## The project

The demonstrator is released under the **Apache License 2.0** ([LICENSE](https://github.com/eclipse-xfsc/facis-zero-trust-demonstrator/blob/main/LICENSE),
`SPDX-License-Identifier: Apache-2.0`). Every component developed in this repository is under that
licence.

## How third-party licences are checked

- **Go dependencies** go through the Eclipse Dash licence gate on every pull request
  (`.github/workflows/eclipse-dash.yml`). A dependency Dash cannot clear is sent to the Eclipse IP
  team for review, and a `restricted` licence blocks the merge. At the time of writing the gate
  reports Go dependencies still awaiting that IP review; the review, not a waiver, closes it.
- **Every release** publishes a CycloneDX SBOM with licences (`.github/workflows/sbom.yml`); it is
  the authoritative inventory.
- The chosen components and the reasons for them are recorded in
  [OSS dependencies](dependencies.md).

## Components this repository ships or runs

| Component | Version | Licence | Where |
|---|---|---|---|
| ORCE (upstream image `ecofacis/xfsc-orce`) and Node-RED | 2.0.13 / 4.0.9 | Apache-2.0 | base of the ORCE image, `deployment/docker/orce` |
| Helm | v4.3.0 | Apache-2.0 | inside the ORCE image, and chart QA in CI |
| kubectl | v1.35.8 | Apache-2.0 | inside the ORCE image |
| `pause` image (Kubernetes) | pinned by digest | Apache-2.0 | the lifecycle fixture chart (test data) |
| Go module dependencies | see [OSS dependencies](dependencies.md#go-dependencies) | Apache-2.0, BSD-3-Clause, MIT | services and the acceptance harness |
| `@cucumber/cucumber` | 13.2.1 | MIT | JavaScript acceptance runner (development only, not shipped) |

## Licence exceptions

A component under a licence that is not Apache-2.0-compatible and that the requirements prescribe
is declared to the client in writing before it is included
([the procedure](dependencies.md#licence-exceptions)). The Licence Exception Notice v1.0 of
8 September 2026 covers **OpenBao** (MPL-2.0, prescribed by ZT-11) and **Grafana** (AGPL-3.0, for
optional internal use only; the delivered visualization uses Prometheus and Jaeger instead). The
client's decision is open and tracked as follow-up requirement F-07.

## Image scan exceptions are not licence exceptions

The ORCE image carries a time-boxed **vulnerability** scan exception for findings inside the
upstream ORCE runtime ([CI/CD](ci-cd.md#image-scan-exceptions)). It concerns security findings, not
licences, and it expires on 13 November 2026.
