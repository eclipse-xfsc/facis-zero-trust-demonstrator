# Keycloak integration

The realm, client, roles, claims and lifetimes are fixed in the [Identity model](identity-model.md).

Keycloak is the demonstrator's identity provider and is used as a **stock product** — the custom
OAuth2 surface lives in the Go connector instead, precisely so that Keycloak is never forked. See
[ADR-0003](adr/0003-oauth2-authorisation-surface-in-the-go-connector.md).

## Realm as code

The realm is not configured by hand in the admin console. Clients, roles, scopes and the
demonstration personas are held as a realm export in this repository and applied by the pipeline, so
that a fresh cluster reaches the same identity configuration as the last one.

| Held in Git | Not held in Git |
|---|---|
| Realm settings, clients, roles, scopes, client scopes | Client secrets and any key material |
| The demonstration personas and their role assignments | Runtime sessions and tokens |
| Login theme selection and required actions | Anything a viewer creates during a demonstration |

Secrets are injected at apply time from OpenBao. A realm export containing a secret is a defect —
the export is committed, so what is in it is public.

## OIDC login

The demonstrator UI authenticates its **viewer** — the person driving the demonstration — through
the standard OIDC redirect flow against Keycloak. Role claims from the resulting token gate which
actions that viewer may trigger, so that a read-only observer cannot revoke a credential or tamper
with a measurement mid-demonstration.

Three states are shown explicitly rather than being allowed to look like a fault:

- **expired** — the session ended; the UI says so and offers re-authentication;
- **denied** — the viewer is authenticated but lacks the role for the action they clicked;
- **logged out** — the session is cleared at both ends, not only in the browser.

## Connector boundary

This is the distinction that matters, and it is the reason Keycloak is never forked:

| Keycloak issues | The Go connector issues |
|---|---|
| Identity for **people** — the viewer driving the demonstrator UI | Authorization for **machines** — the participant backend calling a protected resource |
| Realm, client, role and scope management | Dynamic Client Registration for participant backends |
| Standard OIDC tokens for the UI session | Access tokens derived from a verified OID4VP presentation, DPoP-bound |

The authoritative allow/deny decision for a protected resource stays on the connector and guard
path. Keycloak is not asked to reinterpret it, and nothing outside that path overrides it. The
reasoning, including why Keycloak's own DPoP and OID4VCI support is not depended on, is in
[ADR-0003](adr/0003-oauth2-authorisation-surface-in-the-go-connector.md).

## Packaged runtime and integration proof

The viewer identity flows (OIDC UI at `/dev/facis-demo/`, identity endpoints at `/dev/ztd/`, the
authenticated journey receiver) are proven as a component, not yet packaged: the ORCE image keeps its
own built-in authentication and copies only the lifecycle flow, so a deployed ORCE does not serve these
routes until they are packaged with a separate review. When they are, set the ORCE chart's `identity.issuer` to the Keycloak
chart's `keycloak.publicUrl` plus `/realms/facis-ztd`; set `identity.uiOrigin` and the ingress host
to the same UI origin configured in Keycloak's `ui.origin`. These become `FACIS_OIDC_ISSUER` and
`FACIS_UI_ORIGIN` in the function runtime. Both require HTTPS. The realm's exact redirect/logout
URLs must agree; no password grant or Keycloak service token is introduced.

Viewer command decisions emit `ui.authorization` with `state`, `reason_code`, `action` and a
server-generated `correlation_id`; the response carries the same ID in `X-Request-ID`. No session,
password or token is logged. IF-08 keeps Basic authentication; only the exact identity routes and
static UI assets use the viewer boundary. The legacy unauthenticated socket interface is not loaded.

Run `PATH=/opt/homebrew/bin:$PATH scripts/verify-keycloak/run.sh` for the isolated local-services
TDR-BDD-05 proof. It uses the Helm-rendered realm, real PKCE logins and JWKS, then verifies the
machine chain and its refusal of a Keycloak viewer token. See the
[proof instructions](../scripts/verify-keycloak/README.md) and
[run record](evidences/bdd-keycloak-2026-11-23/README.md). Packaged sample journeys remain
samples; the machine authorization proof runs the real Go services separately, as the identity
model requires.
