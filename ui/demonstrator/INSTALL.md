# Demonstrator installation

Use the approved ORCE/Node-RED runtime with `node-red-contrib-uibuilder` installed. Enable Function node external modules for the identity function's built-in `crypto`, `https`, and `url` imports. The supplied installer targets the container user directory `/data`; its runtime user must be able to write `/data/uibuilder/facis-demo/src`. For a different user directory, change the nine destination paths in the installer before deploying.

## Update an existing installation

1. Export and securely retain the current flows before changing the installation. Preserve runtime credentials, environment settings and the existing node IDs/wiring. Schedule the update when no shared demonstration is running.
2. In the existing `Sample scenario adapter` Function node (ID `journey-sample-fixtures`), replace **On Message** with `flows/demonstrator/journey-sample-fixtures.js`. In `Execute sample Journey` (ID `journey-engine`), replace **On Message** with `flows/demonstrator/journey-engine.js`. Retain each node's other settings and wiring. These updates add the server-owned Resource fixture catalogue and its execution behavior.
3. In `Write canonical UI files` (ID `facis-native-ui-files`), replace **On Message** with `flows/demonstrator/ui-installer.js`. In `Report file installed`, keep the body synchronized with `flows/demonstrator/ui-install-report.js` (unchanged from the previous delivery).
4. In `Install static UI files`, select overwrite, enable directory creation, disable append newline, and use `msg.filename` for the filename. Preserve the existing installer wiring. The runtime user must be able to write both the `assets` and `vendor` subdirectories.
5. The identity function source is unchanged from the previous UI delivery. If upgrading from an older version, synchronize `Validate identity and session` from `identity-on-start.js` (**On Start**), `identity-on-message.js` (**On Message**) and `identity-on-stop.js` (**On Stop**). Retain imports `crypto` as `crypto`, `https` as `https`, and `url` as `nodeUrl`.
6. Optionally import `flows/demonstrator/connector-adapter-flow.json` once, only if no `Connector adapter` tab is already present. This independent preparation flow has no Journey wiring and remains inactive unless `CONNECTOR_ADAPTER_ENABLED=true` is explicitly configured. Leave it disabled until approved live inputs are supplied. Do not import the combined export as well.
7. Deploy. Run the existing `Install UI assets` inject once manually. Wait for `Report file installed` to show `All 9 UI files installed`. Keep automatic injection disabled after installation. Resolve any File node errors before proceeding, then reload the UI with the browser cache disabled.
8. Check the logo/favicon, field-local validation, operator and observer login, and the Resource fixture catalogue. On a disposable demonstration run, verify fixture outcomes/evidence and observer read-only behavior. Existing shared runs should be preserved until their owner agrees to reset them. Connector and real replacement acceptance remain blocked on the approved external inputs.

If an upgrade fails, restore the saved flow export and reinstall the previous release's UI assets. Do not restore credentials from an untrusted flow export or change Keycloak configuration as part of this UI update.

Do not import the combined export over existing flows: duplicate routes and nodes can interfere with the running installation. Updating these existing nodes does not restore deleted demonstration or diagnostic flows.

## Clean installation

In a new editor installation, use Import > Clipboard and paste each complete JSON file from `flows/demonstrator`, choosing a new flow for each: `application-interface.json`, `journey_flow.json`, `system_flow.json`, `identity_flow.json`, then `ui-install.json`. The optional independent `connector-adapter-flow.json` can be imported separately; it stays disabled until the server environment enables it. Alternatively import `current-facis-flows.json` once; do not use both methods. Confirm the cross-flow link nodes are connected and the uibuilder node URL is `facis-demo`. Enter the approved Participant credentials in the existing HTTP Request node's credential settings. Deploy, then run `Install UI assets` as above.

The supplied origin is `https://orce.85-215-131-155.sslip.io`, with public HTTP routes under `/dev`. Preserve that proxy/root configuration. For another origin or root, update the identity origin, callback/post-logout paths, UI route prefix, and the approved Keycloak client configuration together.

## Installed assets

The installer embeds and overwrites these exact files without downloads:

| Source below `ui/demonstrator/src/` | Destination below `/data/uibuilder/facis-demo/src/` |
| --- | --- |
| `index.html` | `index.html` |
| `index.css` | `index.css` |
| `index.js` | `index.js` |
| `vendor/vue.global.js` | `vendor/vue.global.js` |
| `vendor/LICENSE.vue` | `vendor/LICENSE.vue` |
| `assets/Facis-logo.svg` | `assets/Facis-logo.svg` |
| `assets/favicon-32x32.png` | `assets/favicon-32x32.png` |
| `assets/favicon-192x192.png` | `assets/favicon-192x192.png` |
| `assets/apple-touch-icon-180x180.png` | `assets/apple-touch-icon-180x180.png` |

HTML loads Vue from `./vendor/vue.global.js`. Its MIT licence is included beside it. The separate `../uibuilder/uibuilder.iife.min.js` client is served by the installed uibuilder runtime; installing this source ZIP alone does not install that Node-RED dependency.

Open `/dev/facis-demo/`. Check HTTP 200 responses for `index.css`, `index.js`, `vendor/vue.global.js`, `vendor/LICENSE.vue`, and `/dev/uibuilder/uibuilder.iife.min.js`. Verify both operator and observer logins against the approved `facis-ztd` realm and `ztd-ui` client. Operator can advance a journey and preview configuration; observer can view shared progress and cannot mutate it.

## Session and logout checks

This boundary uses authorization code with PKCE S256. Access and ID token subjects must exist and match. Each action revalidates the signed access token. An expired access token requires login; it cannot authorize an action. An active session refreshes when fewer than 60 seconds remain, shares concurrent refresh requests, requires a new refresh token, and rejects changed subject or session ID. Confirm the approved Keycloak client supplies rotating refresh tokens; a failed or nonrotating refresh ends the local session.

Keycloak client endpoints for this origin are:

- Redirect URI: `https://orce.85-215-131-155.sslip.io/dev/ztd/oidc/callback`
- Post-logout redirect URI: `https://orce.85-215-131-155.sslip.io/dev/facis-demo/`
- Front-channel logout URL: `https://orce.85-215-131-155.sslip.io/dev/ztd/oidc/frontchannel-logout` (requires `iss` and `sid`)
- Back-channel logout URL: `https://orce.85-215-131-155.sslip.io/dev/ztd/oidc/backchannel-logout` (POST form `logout_token`; requires a signed token with the back-channel logout event and `sid` or `sub`)

Run `node --test tests/demonstrator/*.test.cjs` from the repository root for component verification. Tests cover expiry, concurrent refresh, refresh rejection/reuse, changed roles, front-/back-channel invalidation, replay rejection, and logout during refresh.

For live acceptance, use separate operator and observer sessions. Verify refresh near expiry, rejection after expiry, UI logout, Keycloak administrator-initiated logout, and both configured logout channels. After each logout, a command with the previous session cookie must return 401; the UI's next session poll must disable operation. Check Keycloak's actual refresh reuse policy and endpoint delivery in the approved environment. Passing source tests does not establish that the deployed realm sends these events or uses the required refresh settings.
