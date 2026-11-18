# Identity model

This page fixes the identity model the demonstrator realm is built against: the realm, its client,
roles, scopes and claims, token and session lifetimes, logout, personas and secret handling. The
realm export in Git ([Keycloak integration](keycloak.md)) implements this page; where the two
disagree, this page is changed first, through review.

## What Keycloak is for

Keycloak authenticates **people**: the viewer who drives the demonstrator UI and, with the
[privileged-operations runner](privileged-access.md), the operators who call it. It does not authorize
the participant path; its one machine identity is the runner's own service account, which
administers the realm's users. A participant backend calling a protected resource is authorized by the Go connector and
the guard, with tokens derived from a verified credential presentation and bound to a key
([ADR-0003](adr/0003-oauth2-authorisation-surface-in-the-go-connector.md)). Nothing in this model
reaches that path, and no Keycloak token is accepted by the guard.

Keycloak runs on the IONOS cluster, next to ORCE and the UI it serves, as a stock product with no
custom providers or extensions.

## Realm and client

| Item | Value |
|---|---|
| Realm | `facis-ztd` |
| Client | `ztd-ui`, public (no client secret) |
| Flow | Authorization code with PKCE, method `S256` required |
| Disabled | Implicit flow, direct access grants (password grant), service account, device flow |
| Redirect URIs | The UI's callback on its own hostname, listed exactly; no wildcards |
| Web origins | The UI's origin only |
| Consent | Off: the realm's clients are all first-party (`ztd-ui`; with the [privileged-operations runner](privileged-access.md), also `ztd-access` and `ztd-access-runner`) |
| Front-channel logout | On, with the UI's logout URL |
| Back-channel logout | On, to the UI backend, so a server-side session ends with the Keycloak session |

## Roles

Two realm roles. A viewer holds exactly one; a user with neither is authenticated but can do nothing.

| Role | May |
|---|---|
| `ztd-observer` | Watch journeys, read panels, decisions and evidence, open the scenario catalogue |
| `ztd-operator` | Everything an observer may, plus start and reset a journey, choose its inputs, and preview, validate and apply a configuration change |

The action-by-action mapping, including which configuration changes an operator may make, is in
[Scenario decisions](scenarios.md). An observer who attempts an operator action is shown the
`denied` state; a configuration change attempted without the role is rejected with
`CFG-NOT-AUTHORISED`.

## Tokens and claims

The UI backend validates every access token before it acts: signature against the realm's JWKS,
issuer `https://<keycloak-host>/realms/facis-ztd`, audience `ztd-ui`, expiry. It reads only these
claims:

| Claim | Use |
|---|---|
| `sub` | Session key |
| `preferred_username` | Shown in the UI; written as `requested_by` in a configuration change |
| `realm_access.roles` | Gates the actions in the table above |
| `aud` | Must contain `ztd-ui` (audience mapper on the client) |

Client scopes: `openid`, `profile` and `roles` as defaults, nothing optional. No other claim is
mapped, and no claim carries a credential, a measurement or anything from the connector path.

## Lifetimes and session states

| Setting | Value | Why |
|---|---|---|
| Access token | 5 minutes | A removed role stops working within five minutes |
| SSO session idle | 30 minutes | A presenter pausing does not lose the session |
| SSO session max | 8 hours | One demonstration day |
| Refresh token | Rotated on use; reuse revokes the session | A copied refresh token is detected |

The UI renders three states of its own rather than letting them look like faults: **expired** (the
session ended; re-authenticate), **denied** (authenticated, but the role does not allow the action)
and **logged out** (cleared at both ends through the logout flow, not only in the browser).

## Personas

| Persona | Role | Use |
|---|---|---|
| `demo-operator` | `ztd-operator` | Drives a demonstration |
| `demo-observer` | `ztd-observer` | Shows that a watcher cannot change anything |
| `bdd-operator` | `ztd-operator` | Acceptance runs |
| `bdd-observer` | `ztd-observer` | Acceptance runs, negative cases |

Personas are in the realm export without credentials. Passwords are set at apply time.

## Secrets

The export contains no secret ([Keycloak integration](keycloak.md)). The apply job reads from
OpenBao's KV v2 mount `secret`:

| Path | Holds |
|---|---|
| `secret/data/keycloak/admin` | The admin credential the apply job uses |
| `secret/data/keycloak/personas/<persona>` | Each persona's password |

The public client has no secret. Tokens and passwords never appear in logs or evidence.

## Service access (unchanged)

This model changes nothing on the service-to-service paths; their contracts stay as pinned:

| Path | Authentication | Contract |
|---|---|---|
| ORCE lifecycle API | HTTP Basic on ORCE HTTP nodes | [IF-08](api-docs.md) |
| Security-state feed | Inside the mesh only, from the UI's workload identity | [IF-01](api-docs.md) |
| Participant backend to protected resource | Connector and guard, DPoP-bound tokens | [IF-02](api-docs.md), ADR-0003 |

Moving the lifecycle API and the feed to Keycloak-issued service credentials, which the TDR's
"service credential management" would allow, is a proposed contract change. It would change IF-01
and IF-08, the ORCE configuration, the clients and the acceptance scenarios together, through a
versioned contract review; until then it is not part of this model.

## Verification

The model is met when, on an empty Keycloak, the realm imported from Git lets both `demo-` personas
log in through the UI; an observer's attempt to start a journey renders `denied`; an expired access
token renders `expired`; and logout ends the session in the UI backend and in Keycloak. These are the
identity steps of the Keycloak, policy and token integration scenario in the
[BDD catalogue](bdd-catalogue.md).
