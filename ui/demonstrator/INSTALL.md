# Demonstrator installation

Use the approved ORCE/Node-RED runtime with `node-red-contrib-uibuilder` installed. Enable Function node external modules for the identity function's built-in `crypto`, `https`, and `url` imports. The installer uses the built-in `fs` module imported as `nodeFS` in `Write canonical UI files`. The supplied installer targets the container user directory `/data`; its runtime user must be able to write `/data/uibuilder/facis-demo/src`. For a different user directory, change `destinationRoot` in the installer before deploying.

## Update an existing installation

1. Back up the existing flows using the editor's Export command and retain the previous release's UI assets. Keep existing credential settings, environment settings and unrelated flows. Schedule the update when no shared demonstration is running.
2. In the existing `Validate identity and session` Function node, replace **On Start** with `flows/demonstrator/identity-on-start.js`, **On Message** with `identity-on-message.js`, and **On Stop** with `identity-on-stop.js`. In Setup retain imports `crypto` as `crypto`, `https` as `https`, and `url` as `nodeUrl`.
3. Copy the release assets into a separate directory readable by ORCE. From the repository root, run `mkdir -p /data/facis-demo-release/ui/demonstrator` and `cp -R ui/demonstrator/src /data/facis-demo-release/ui/demonstrator/` inside the runtime container, or mount that directory read-only at the same path. Set `FACIS_UI_SOURCE_DIR` if using another absolute source path. In the existing `Write canonical UI files` Function node, replace **On Message** with `flows/demonstrator/ui-installer.js` and import built-in `fs` as `nodeFS` in Setup. In `Report file installed`, replace **On Message** with `flows/demonstrator/ui-install-report.js`.
4. In `Install static UI files`, select overwrite, enable directory creation, disable append newline, and use `msg.filename` for the filename. Preserve the existing installer wiring.
5. Update `Execute sample Journey` (`journey-engine`) from `journey-engine.js`; this makes shared token results available to observers and labels their provenance correctly. When upgrading from before the B2 fixture delivery, also update `Sample scenario adapter` from `journey-sample-fixtures.js`.
6. Complete the Participant node additions and identity link wiring described under **Hosted Participant token integration** below before deploying. Updating the function body alone does not add its third output or the new cross-flow links.
7. Deploy. Run the existing `Install UI assets` inject once manually. Wait for `Report file installed` to show `All 9 UI files installed`. Keep automatic injection disabled. Resolve any File node errors before proceeding, then reload the UI with the browser cache disabled.
8. Verify operator and observer login, Participant state/history, token response display and the existing fixture journeys. Coordinate any shared live reset first. The optional independent Connector adapter remains separate from this hosted Participant integration; do not enable it as part of this update.

If the upgrade fails, restore the saved flow export and the previous UI assets using that release's installation procedure. Preserve existing credentials and Keycloak settings. For the new staged-file installer, stage all nine assets from the same release before running it; do not mix versions or use the destination as the staging directory.

Do not import the combined export over existing flows: duplicate routes and nodes can interfere with the running installation. Updating these existing nodes does not restore deleted demonstration or diagnostic flows.

## Clean installation

In a new editor installation, use Import > Clipboard and paste each complete JSON file from `flows/demonstrator`, choosing a new flow for each: `application-interface.json`, `journey_flow.json`, `system_flow.json`, `identity_flow.json`, then `ui-install.json`. The optional independent `connector-adapter-flow.json` can be imported separately; it stays disabled until the server environment enables it. Alternatively import `current-facis-flows.json` once; do not use both methods. Confirm the cross-flow link nodes are connected and the uibuilder node URL is `facis-demo`. Only the older HTTP-sample route uses credentials in its HTTP Request node; the new hosted token endpoint requires no Basic Auth credentials. Stage the UI source directory and configure the installer module as described above. Deploy, then run `Install UI assets` as above.

The supplied origin is `https://orce.85-215-131-155.sslip.io`, with public HTTP routes under `/dev`. Preserve that proxy/root configuration. For another origin or root, update the identity origin, callback/post-logout paths, UI route prefix, and the approved Keycloak client configuration together.

## Installed assets

The installer reads these real files from the staged release source and overwrites the destinations without downloads. Asset bytes are not embedded in JavaScript or flow exports. All nine source files must be present and nonempty before any writes are emitted:

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

## Hosted Participant token integration

The new Participant client is separate from the existing fixture and HTTP-sample
adapters. Its fixed upstream origin is `https://160.44.12.245`. It calls GET
`/state`, POST `/reset` and POST `/demo` from ORCE only. No Basic credential or
Keycloak user token is forwarded to this origin.

Update the existing identity Function's On Start and On Message from their
matching source files; set its outputs to three and preserve the supplied
identity export's wires and links. Add `Authenticated Participant request`
(`facis-native-participant-out`) and wire the identity function's third output
to it. Link it to `participant-runtime-in`. Link `participant-runtime-reply`
back to the existing `Journey HTTP result` (`facis-native-journey-in`), retaining
that node's existing Journey link and HTTP response wiring.
The Journey export includes the new `participant-runtime-in`,
`participant-runtime` and `participant-runtime-reply` nodes. The runtime Function
uses built-in `https` as `nodeHTTPS`, `crypto` as `nodeCrypto` and `fs` as `nodeFS`.
Preserve existing nodes, credentials and unrelated flows; do not import duplicate
routes. Use the combined export only for a clean installation.

The complete public `flows/demonstrator/facis-demo-ca.crt` is embedded in the
runtime Function and used by its outbound HTTPS client with certificate and
hostname verification enabled. No runtime mount is required for that embedded
copy. To use a managed CA file instead, set `PARTICIPANT_CA_FILE` to the mounted
path readable by Node-RED (for example `/data/certs/facis-demo-ca.crt`). A curl
CA option does not configure this runtime. No global TLS bypass is added.

The hosted runtime response was observed with `source: sample` and `mode: token`.
The token client defaults to that exact source, independently of the old
sample-mode validator. `PARTICIPANT_TOKEN_SOURCE` is an optional explicit override
for a changed deployment contract. Mode remains strictly `token`. Validation
requires matching request/correlation IDs, bounded content and separate
full-report/summary-only success shapes. Contract mismatches expose only
sanitized source, mode and reason-code observations.

Direct verified HTTPS from the ORCE runtime returned `/state` HTTP 200 with
mode token/state ready and `/demo` HTTP 200 with RESOURCE_REPORT_RETURNED. The
supplied CA and hostname verification remained enabled. An earlier external
client's certificate error does not apply to this runtime connection.

Reinstall the UI with the synchronized nine-file installer. In the new
Participant view, authenticated observers can read service state/history;
only operators may reset or request token reports. The existing authenticated
POST `/dev/ztd/api/journey` boundary carries commands `participant-state`,
`participant-reset` and `participant-demo`. All retain origin/session/CSRF checks.
Reset additionally requires `data.confirmShared: "yes"` after the UI confirmation
that the shared service affects all users. It never retries POST automatically.

For a shared live reset, coordinate with other users first. Verify idle is shown
before polling, then observe ready or a reported failed state. A reset 503 with
`reason: reset_wait_timeout` retains the last known view and re-reads state.
Polling stops on view close/logout, avoids overlapping requests and backs off
when settled or unreachable. History is rendered from the service, including
rapid transitions that occur between polls. No registration, attestation,
renewal step or percentage is synthesized.
