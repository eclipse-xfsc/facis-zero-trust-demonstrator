# FACIS Zero Trust Demonstrator

This is the documentation for the FACIS Zero Trust Demonstrator (FACIS.ZTD), an Apache-2.0
demonstrator released inside the Eclipse XFSC organisation.

The demonstrator stands up two demonstration zones and lets a participant backend in one zone call
a protected resource in the other, with every hop authenticated, authorised and attested. It is
built to show the refusals as clearly as the successes: a revoked credential, a wrong scope or a
tampered measurement each produce a distinct, explained denial.

## Where to start

| If you want to | Read |
|---|---|
| Understand what the demonstrator does | [Features and journeys](features.md) |
| Drive it and read what it tells you | [Using the demonstrator](usage.md) |
| Stand it up or tear it down | [Deployment](deployment.md) |
| Set up a specific cluster step by step | [Environments](environments/index.md) |
| Know how it is built and shipped | [Packaging and containers](packaging.md) |
| Follow the orchestrated journeys | [Orchestrated flows](flows.md) |
| Wire up identity | [Keycloak integration](keycloak.md) |
| Call its APIs | [API documentation](api-docs.md) |
| See how acceptance is proven | [BDD acceptance](bdd.md) and the [BDD catalogue](bdd-catalogue.md) of every Annex A row |
| Understand the pipeline | [CI/CD](ci-cd.md) |
| Diagnose a problem | [Troubleshooting](troubleshooting.md) |
| Check what it depends on | [OSS dependencies](dependencies.md) and [Licenses](licenses.md) |
| Find where we depart from the specification | [Specification changes](specifications.md) |
| Understand why it is built this way | [Architecture decisions](adr/index.md), including how the [TDR decisions ADR 001–006](adr/tdr-decisions.md) are applied |

## Conventions this documentation follows

Documentation follows the [Eclipse Project Handbook](https://www.eclipse.org/projects/handbook/):
everything a contributor or user needs lives in this repository, in Markdown, under `docs/` or in
the README, and is published from the same commit as the code it describes.

The FAP Partner Onboarding project is the reference for structure —
[its specification](https://github.com/eclipse-xfsc/facis/tree/main/FAP/Partner%20Onboarding%20(Reference%20FAP)/specification)
and [its implementation](https://github.com/eclipse-xfsc/facis-fap-partner-onboarding) — so a reader
who knows one FACIS repository can navigate this one without relearning where things are.

How the project applies the handbook's contribution, intellectual-property and release rules is in
[CONTRIBUTING.md](https://github.com/eclipse-xfsc/facis-zero-trust-demonstrator/blob/main/CONTRIBUTING.md#eclipse-project-handbook).

The site is built with [MkDocs](https://www.mkdocs.org/) and published to GitHub Pages on every
change to `main`.

## Project context

FACIS.ZTD is delivered for the FACIS project and published in Eclipse XFSC. The wider FACIS
programme — Federation Architecture Patterns, machine-readable SLAs, digital contracting and the
other demonstrators — is indexed at
[eclipse-xfsc/facis](https://github.com/eclipse-xfsc/facis).

## Licence

Apache License 2.0. `SPDX-License-Identifier: Apache-2.0`
