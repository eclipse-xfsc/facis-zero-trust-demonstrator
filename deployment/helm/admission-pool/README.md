# admission-pool

Namespaces under admission control for the admission-proof scenarios (ZT-72) and the namespaced
identity the acceptance runner uses there. Installed after Gatekeeper, the provider
([admission](../admission)) and the constraints ([deployment/admission](../../admission)).

| Object | Scope | Purpose |
|---|---|---|
| One `Namespace` per entry of `namespaces` | cluster | labelled `facis.ztd/admission-proof=true`, so the Gatekeeper webhook and the constraints apply; enforces the restricted Pod Security Standard |
| `Role`/`RoleBinding` `ztd-adm-tester` | each namespace | pods and `pods/ephemeralcontainers`: get, list, watch, create, delete, update, patch; Deployments and ReplicaSets: get, list, watch, create, delete; events: get, list |
| `ServiceAccount` `ztd-adm-tester` | the first namespace | only when `tester.serviceAccount.create` is `true`; no token is mounted into pods |

The tester has no cluster-scoped rights and nothing outside these namespaces. Setting up and breaking
the admission path (scaling the provider or Gatekeeper to zero, removing the webhook) is done by the
cluster administrator, never with this identity.

| Value | Default | Meaning |
|---|---|---|
| `namespaces` | `ztd-adm-001`, `ztd-adm-002` | the namespaces under admission control |
| `tester.serviceAccount.create` | `true` | create the ServiceAccount |
| `tester.serviceAccount.name` | `ztd-adm-tester` | its name |
| `tester.serviceAccount.namespace` | `""` | its namespace; empty means the first entry of `namespaces` |
