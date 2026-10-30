# Demonstrator UI, flows and identity handoff

This contribution adds the demonstrator UI, ORCE flows, component tests and a
reproducible Keycloak chart. It uses the identity/scenario contracts and the
deployed sample-service interface recorded in pull request #27, commit
`075aa150d7308bb7330a4e3ed8f79b5e07319bf9`. Integrate those prerequisite changes
before installing this contribution on a clean environment.

## Contents

| Path | Purpose |
| --- | --- |
| `ui/demonstrator/INSTALL.md` | Runtime requirements, clean installation and upgrade instructions |
| `ui/demonstrator/src/` | HTML, CSS, JavaScript and vendored Vue with its licence |
| `flows/demonstrator/` | Identity/session, journey, application-interface and five-file UI installer flows |
| `deployment/helm/facis-ztd-keycloak/` | Realm/client/roles/personas, basic subject scope and `/dev` callback/logout configuration |
| `tests/demonstrator/` | Component tests and coverage notes |
| `.github/workflows/demonstrator-tests.yml` | Separate component-test CI job; no deployment or secrets required |

The ORCE editor is under `/dev/`; the demonstrator is under `/dev/facis-demo/`.
Use the exact callback/logout URLs in the installation instructions. The UI uses
authorization code with PKCE S256 and requires matching verified access/ID token
subjects. Operator actions are authorized on the backend; observers view shared
results without starting or changing journeys.

## Validation recorded 12 October 2026

- All 60 component tests passed locally on Node v24.19.0/Windows.
- Browser checks passed for fresh operator/observer login and ordinary UI logout,
  successful call, revoked credential, wrong scope and presentation-required fixtures.
- The Participant sample endpoint returned the expected success, denied, unavailable,
  error and slow-response outcomes. The UI displayed request/correlation IDs.
- Participant, Resource and DNS configuration fields were read-only. Allowed preview
  payloads were checked, malformed measurement input was rejected, and Apply remained disabled.
- All 42 supplied flow nodes were present in the refreshed editor. Inspected differences
  were formatting/editor metadata or equivalent installer representations; the five
  embedded UI assets matched byte-for-byte. This is not a runtime commit attestation.
- Helm v4.3.0 lint/render checks cover the chart. Live image pull, configuration import
  and resource adoption have not been independently tested for this package.

## Limits and remaining integration checks

Security decisions in these journeys use fixtures. The application sample HTTP call
is real, but it does not prove the Connector/guard trusted path or two-zone acceptance.
Configuration is preview-only; policy registry validation, real API replacement and
governed application of changes remain later integration work.

The Participant connection currently uses an endpoint-specific TLS verification
exception for the supplied self-signed certificate, visibly labelled in the UI.
There is no encoded expiry. Agree the exception and expiry or supply a trusted
certificate/CA before treating this as final TLS acceptance. Do not generalize the
exception to Keycloak or other endpoints.

Actual administrator-initiated logout, isolated front/back-channel delivery,
refresh reuse/expiry, direct forged-request tests, clean target installation and
formal BDD remain target-environment checks. Local handler tests do not prove them.

Keep Participant credentials in the HTTP Request node's private credential settings.
The chart references Kubernetes Secrets and supports External Secrets/OpenBao;
preserve existing persona credentials when installing/upgrading. A first install
without the existing credential source can generate new persona passwords. Do not
commit credential files, rendered Secrets, kubeconfigs or token dumps.
