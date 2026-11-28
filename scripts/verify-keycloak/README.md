# Keycloak, policy and token proof (TDR-BDD-05)

Run from the repository root on a workstation with Docker, Helm, Go, Node, Python 3 and OpenSSL:

```bash
PATH=/opt/homebrew/bin:$PATH scripts/verify-keycloak/run.sh
```

This creates three uniquely named disposable containers (stock Keycloak, PostgreSQL, OpenBao),
imports the **Helm-rendered realm**, and runs only `@TDR-BDD-05` in the Go cluster mode. It never
uses kubectl or changes a context. Port 18443 must be free; set `KEYCLOAK_LOCAL_PORT` to change it.
Containers, temporary certificates, credentials and tokens are removed on exit. Do not use shell
tracing. The certificate is trusted with `NODE_EXTRA_CA_CERTS`, never by disabling TLS validation.
The public `ztd-ui` client keeps code + PKCE S256; password/direct grants remain disabled. Test
personas receive random passwords only in the temporary realm import.

The proof performs standard interactive login over HTTPS, parses the stock login form, submits the
persona credentials, then sends the resulting code through the production UIAuth callback. Its
real HTTPS transport obtains tokens and JWKS from Keycloak. It asserts operator dispatch, observer
refusals (including configuration preview), expired sessions and logout at both ends (the refresh
token is refused after Keycloak logout). Refusals must have matching `ui.authorization` records.
No token issuer, JWKS, code exchange or viewer decision is stubbed in this proof.

It then runs the real guard/connector/policy/token-store catalogue with PostgreSQL and OpenBao,
including refusal of the Keycloak viewer token at the machine guard, and a real verified
presentation → DPoP token → protected call integration. The guard and policy must record both the
allowed control and the insufficient-scope refusal under matching correlation IDs; the revoked
credential must be recorded as refused. This follows the two separate boundaries in
`docs/identity-model.md`: a Keycloak token does not authorize a machine or replace a presentation.

Evidence is written under `bundles/bdd/evidence/bdd-tdr-005/local-services/<run>/`:
`target.json`, `viewer.json`, `catalogue.json`, `vp-e2e.txt`, and Go test JSON logs. A missing,
skipped or failed Go test fails the row. The cucumber report is `bundles/bdd/keycloak-<run>.json`.
Tokens never belong in that bundle; the guard's transient input is a mode-0600 file removed after
use. Dry-run lists the row as not run, never as acceptance evidence.

Limits: this is a local-services proof, not a deployment of ORCE or a mesh. It executes the exact
UIAuth source in a Node harness; dispatch is observed at the authenticated command boundary. The
machine proof is the existing real Go integration chain, with its documented fixture role outcomes;
its additional end-to-end test verifies an actual SD-JWT presentation. The two flows are separate
as specified by the identity model. Browser rendering of the packaged UI is not
tested here; UI sample journeys remain sample journeys.
