# Privileged access

Administrative operations on the demonstrator are done by one service, the privileged-operations
runner (`services/accessrunner`, chart `deployment/helm/access`), and only with an approval that
someone other than the caller signed, that names the caller, and that is valid for a bounded time.
The runner checks all of it on every call. No person is given the credentials the operations need:
the runner holds them.

## What the runner does

| Role | Operation | Parameters | What it changes |
|---|---|---|---|
| `cluster-operator` | `cluster-restart` | a plane namespace, a deployment | the pod template annotation `ztd.facis.io/restartedAt`, nothing else |
| `cluster-operator` | `cluster-logs` | a plane namespace, a pod, a container, 1 to 1000 lines | nothing; returns the lines |
| `user-admin` | `keycloak-list-users` | none | nothing; returns the first 100 users of `facis-ztd` and whether they are enabled |
| `user-admin` | `keycloak-disable-user`, `keycloak-enable-user` | a username | the user's enabled flag, refused for a user holding `ztd-operator` or `admin` or any `realm-management` role, directly, by a group or by a composite |

The table is `Roles` in `services/accessrunner/policy.go`; a grant names the digest of it
(`policy_version`), so a grant approved under one set of roles is refused under another.

## A call

`POST /v1/operations/<operation>` over TLS 1.3 (the runner serves no plain HTTP; its certificate is
the Secret `tls.secretName`), with the caller's access token and `{"grant": "<JWS>", "params": {...}}`.

1. **The caller.** An access token of realm `facis-ztd` from the login client `ztd-access`
   (authorization code with PKCE S256, no password or implicit flow), for the audience
   `ztd-access-runner`, of type `Bearer`, signed ES256 by the realm's P-256 key, and not expired, with
   no grace. The caller is the token's `sub`. The runner fetches the realm's key set again after a
   minute and does not use one older than five minutes, so a key the realm removes stops verifying
   within about a minute, and a key set it cannot fetch within five.
2. **The grant.** A compact JWS (`typ ztd-access-grant+jwt`, ES256) by an approver listed in the
   runner's configuration with their Keycloak `sub` and public key; the key that signed must be the
   approver the grant names. The approver is not the subject; the subject is the caller; the target
   and the policy version are the runner's; `0 < not_after - not_before <= 8 h`; now is within them;
   the operation is in both the grant's list and the role; the grant id (one line of letters, digits,
   `.`, `_` and `-`) is not in the ConfigMap `ztd-access-revocations`, which is read through the
   Kubernetes API on every call. A list that cannot be read, has no `revoked` key or holds a line that
   is not a grant id refuses the call. The chart creates the list at install only when it does not exist;
   an upgrade, a rollback or a reinstall leaves it as it is, and it stays when the release is
   uninstalled.
3. **The parameters** are held to the operation's form: plane namespaces only, Kubernetes names,
   no other field.
4. **The time** is checked again just before the operation starts.
5. **The record.** One JSON log line per call: the operation and the outcome, and each of the
   authenticated caller, the grant id and approver, and the parameters once its check has passed, so a
   refused call names only what was verified. No token, grant or log content is written.

A grant is signed offline with `cmd/access-grant sign` and the approver's own key; `access-grant
verify` checks one against a trust file, without the revocation list. Neither holds a privileged
credential.

## What it holds

- **Kubernetes:** the ServiceAccount `ztd-access-runner`, with `patch` on deployments and `get` on
  pods' logs in each plane namespace, and `get` on its revocation list. Kubernetes cannot confine a
  patch to one annotation; the runner does.
- **Keycloak:** the confidential client `ztd-access-runner` (service account only, no login flows,
  full scope off) with `view-users`, `manage-users` and `view-clients` of `realm-management` in
  `facis-ztd`. `view-clients` is what reading a user's client roles needs. Keycloak does not stop
  this client from acting on a privileged user; the runner's own check does.
- The import creates both clients only while the Keycloak chart's `accessRunner.enabled` is on.
  Turning it off afterwards does not remove them (the import does not delete clients): to withdraw
  the runner, disable or delete `ztd-access` and `ztd-access-runner` in the realm. The realm's P-256 key
  provider is added whatever the setting.
- The runner client's secret is one value, letters, digits, `-` and `_` only, in two Secrets: the
  Keycloak chart's `accessRunner.secretRef` in Keycloak's namespace and the access chart's
  `keycloak.secretRef` in the runner's. The import places it in the realm's JSON as it is.

## What it does not cover

These keep privileges outside the runner, and are not time-bound by it:

- the runner's own credentials, and whoever can change the runner, its chart or its configuration
  (the approvers, the target, the plane namespaces);
- the Keycloak bootstrap administrator of the master realm, and the administrator credential the
  realm import job uses;
- the administrative kubeconfigs of the clusters held today (`docs/environments/`);
- a stolen caller token together with a grant for that caller, until the token or the grant ends or
  the grant is revoked: the access token is a bearer token;
- an operation already started when its grant ends, which completes.

A user disabled through the runner can be enabled again by the realm import when that user is one of
the imported personas, since the import sets `enabled`. Nothing stops the runner acting on a persona;
that the runner's targets are the users created at run time is a convention of operation. The bound holds on synchronised clocks. The Annex row for least privilege stays pending: it
also asks that identities in general receive only the minimum access, which this covers for the
privileged operations only.

## Proof

`scripts/verify-access-runner/verify.sh` brings up kind and a Keycloak container over TLS with the
realm applied by the same import tool and settings as the Keycloak chart's job, installs the access
chart, and runs `TestRunnerAgainstKindAndKeycloak` with the runner binary out of the cluster, as the
chart's ServiceAccount, with the chart's rendered configuration and its own TLS certificate. Callers
log in through the PKCE flow. Each operation is performed and its result and effect checked (only
the annotation changed in the pod template; the log lines; the user list; a user disabled and
enabled). Each refusal is shown with the pod templates and the users unchanged: no token, a token of
another client, another caller's grant, a self-approved grant, a tampered grant, an operation outside
the grant, a namespace outside the plane, an extra parameter, a user privileged by role and one by
group. A revoked grant stays refused across a chart upgrade and a rollback; an unreadable revocation
list refuses; a grant stops working at its end with the same caller token; plain HTTP is not served;
and `kubectl auth can-i` shows the ServiceAccount allowed its operations and refused the other
namespaces, verbs and resources the test names. `services/accessrunner` has unit tests of the grant
and caller-token rules, the revocation list's format, the key set's expiry, the bounds on grant times
and the time check just before an operation starts.

The proof does not run the runner's pod (the chart is installed with no replicas), so the
NetworkPolicy, the mounts of the Secrets and the in-cluster service path are rendered and linted but
not exercised.
