# API documentation

## Interface registry

The demonstrator's cross-component interfaces are identified `IF-01` through `IF-08` and frozen at
v1 before the components consuming them are built:

| Interface | Purpose |
|---|---|
| IF-01 | Security-state event stream to the demonstrator UI |
| IF-02 | Connector authorization surface — registration and token issuance |
| IF-03 | Credential verification outcome |
| IF-04 | Observability and evidence |
| IF-05 | Policy decision input and output |
| IF-06 | Governed configuration change |
| IF-07 | Attested channel control |
| IF-08 | Scenario driver hooks |

OpenAPI and JSON Schema definitions are published under `docs/` alongside this page as each
interface is frozen.

## IF-08 — deployment lifecycle command

The scenario driver hook that deploys and uninstalls a release through the ORCE workflow. It is
what the lifecycle acceptance scenarios (TDR-BDD-01..04) drive, and it is the same workflow an
operator uses.

- **Command:** `POST /lifecycle` on ORCE, HTTP Basic (`httpNodeAuth`), TLS 1.3, management plane
  only — [OpenAPI definition](lifecycle.openapi.yaml). The answer comes at once: `202` with
  `data.accepted`, or `400` with `errors.fields` naming each invalid parameter.
- **Result:** asynchronous, kept in the ORCE flow context under `lifecycle.jobs[requestId]` —
  [JSON Schema](lifecycle-result.schema.json). Read it with the ORCE admin API,
  `GET /context/flow/ztd-lifecycle-tab/lifecycle`, using a read-only bearer token.
- **Reason codes** (`errors.action`): `valuesSchemaRejected`, `dryRunRejected`, `deployFailed`,
  `uninstallFailed`, `releaseNotFound`, `clusterUnreachable`, `duplicateRequest`, `systemError`.
  A parameter the cluster refuses (for example a namespace outside the BDD pool) comes back in
  `errors.fields`.

## Conventions

- REST APIs are described with OpenAPI 3; asynchronous interfaces with JSON Schema.
- Structured data carries a JSON-LD context and a SHACL shape where the content is meant to be
  interoperable rather than internal.
- Error responses use a shared reason-code vocabulary, so a refusal is machine-readable and not
  just a status code.
