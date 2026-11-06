# Demonstrator UI, flows and identity handoff

This contribution adds the demonstrator UI, ORCE flows, component tests and a
reproducible Keycloak chart. It uses the identity/scenario contracts and the
deployed sample-service interface recorded in upstream change 27, commit
`075aa150d7308bb7330a4e3ed8f79b5e07319bf9`. Integrate those prerequisite changes
before installing this contribution on a clean environment.

## Contents

| Path | Purpose |
| --- | --- |
| `ui/demonstrator/INSTALL.md` | Runtime requirements, clean installation and upgrade instructions |
| `ui/demonstrator/src/` | HTML, CSS, JavaScript and vendored Vue with its licence |
| `flows/demonstrator/` | Identity/session, journey, application-interface and nine-file UI installer flows |
| `deployment/helm/facis-ztd-keycloak/` | Realm/client/roles/personas, basic subject scope and `/dev` callback/logout configuration |
| `tests/demonstrator/` | Component tests and coverage notes |
| `.github/workflows/demonstrator-tests.yml` | Separate component-test CI job; no deployment or secrets required |

The ORCE editor is under `/dev/`; the demonstrator is under `/dev/facis-demo/`.
Use the exact callback/logout URLs in the installation instructions. The UI uses
authorization code with PKCE S256 and requires matching verified access/ID token
subjects. Operator actions are authorized on the backend; observers view shared
results without starting or changing journeys.

## Current delivery assembled 21 October 2026

This delivery combines the existing UI/identity/chart contribution with the B2
application changes on collaboration main `86c7148810a091eb7a35089449c5a5fc0cd7fa34`.
Existing platform, CI, chart-gate and service files from that baseline are retained.
The earlier UI contribution remains unmerged, so it is carried as a prerequisite;
the Keycloak chart and identity implementation are unchanged from that contribution.

The final suite passes **140 component tests, zero failures and zero skipped** on
Node v24.19.0/Windows, matching the supplied Linux result. Helm v4.3.0 strict lint
and existing-mode rendering pass. These are local checks, not a live release test.
The original source handoff recorded the staged results below as features were added;
69, 86, 90 and 119 are historical intermediate counts, not the final total.

Compared with the previous UI export, three existing function bodies change:
`facis-native-ui-files`, `journey-sample-fixtures` and `journey-engine`. Five nodes
add the separate, default-disabled Connector tab. Follow the complete upgrade
steps in `ui/demonstrator/INSTALL.md`; do not import the combined flow over an
existing installation. Review the new branding and fixture behavior separately
from live Connector and real-API acceptance, which remain blocked on approved inputs.

## Initial UI-only synchronization recorded 21 October 2026

The 42 application flow nodes were compared with the current ORCE editor. Only the UI installer function changed. The installer now includes all nine UI assets, including the logo and favicons. The approved colors and logo size are retained; measurement and policy validation feedback is associated with each field. All 69 component tests passed on Node v24.19.0/Linux. Identity and service authorization logic are unchanged.

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

## Connector adapter component preparation on 21 October 2026

The server-side module `flows/demonstrator/connector-adapter.mjs` implements
registration, client-credentials tokens and DPoP protected calls against the
30 September OAuth2 contract. Its configuration and usage are in
`flows/README.md`. Seventeen new local HTTP contract tests cover success,
nonce challenges, refusal at each stage, invalid token/registration responses,
redirect rejection, response bounds, timeouts and correlation IDs. The full
component suite passes 86 tests. No UI or deployed flow changes are included in
this adapter update. The Connector registration/token endpoints, guard and trust
services are not deployed for the B2 test window; live BDD-ZT-039/074 execution
remains blocked. This component is ready for contract reconciliation and wiring
once the approved route and event schema are available.

The Connector adapter now also has a separately importable Node-RED flow,
`flows/demonstrator/connector-adapter-flow.json`, included in the combined export.
It is disconnected from Journey, has no automatic inject and is disabled by
server environment by default. Four additional checks exercise the embedded
Function, default-disabled behavior, source/export equality, transport handling
and refusal. The complete component suite passes 90 tests. Existing UI and
identity nodes are unchanged by this flow addition.

## Protected Resource fixture integration on 21 October 2026

Thirteen server-owned resource fixture cases are available in the existing
Journey catalogue. Role combinations return distinct synthetic content; missing
or unauthorized rights and invalid/revoked/expired contexts withhold protected
content. An unavailable security dependency returns unavailable without content.
The final outcome is correlated with Journey evidence and remains visibly
fixture-only. Viewer roles and browser claims are not service authorization.
The new 29 checks bring the full component suite to 119 passing tests. The
live role mapping and security interface are still blocked; these fixture
results do not close BDD-ZT-041/075 live acceptance.

## Replaceable application adapter preparation on 21 October 2026

Separate Participant and Protected Resource adapters can select local mocks or
loopback HTTP sample servers through one common pipeline. All four combinations
pass local execution with the same request/result contract. Interface descriptors
are checked before execution; incompatible responses, wrong correlation IDs,
refusal, timeout and unavailable targets cannot fall back to a mock. Real targets
remain disabled pending client confirmation. The module is separate from the
currently deployed Journey and does not change Connector, trust or policy logic.
Usage and the two local sample contracts are documented in `flows/README.md`.
The complete component suite now passes 140 tests, including 21 replacement
checks. These results prepare BDD-ZT-007/077 and do not close their live acceptance.
