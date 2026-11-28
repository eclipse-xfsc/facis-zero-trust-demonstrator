# Replaceable application interfaces (API dock)

The demonstrator ships two application mocks: the Participant backend (`services/participant`) and the
Protected Resource (`services/protectedresource`). Each sits in a dock with a documented interface, so
another API can take its place without a change to the Connector, the guard, the token store, the
policy or any trust setting. This page names the two interfaces, how a replacement is configured, what
is refused at configuration time, and how the replacement is proved (Annex rows ZT-07 and ZT-77).

## The protected-resource dock

The Resource's interface towards its callers is `POST /demo` with
`{"resource":"sample-report","action":"read"}` and the answer documented in
[application services](application-services.md): requestId, correlationId, source, mode, outcome,
reasonCode, explanation, timestamp and safeData, with the success shape
`{resource, action, report: {id, title, content}}`. The Participant checks every answer against that
contract, so a replacement answers in it; the reason codes and the scope table do not change.

Behind that interface the Resource calls a `ResourceAdapter`
(`Request(context.Context, ResourceRequest) (ResourceResult, error)`), chosen by
`PROTECTED_RESOURCE_ADAPTER_MODE`: `sample` and `sample-alternative` are the supplied mocks,
`cloud-api` docks a real API. Only the adapter settings change:

```sh
PROTECTED_RESOURCE_ADAPTER_MODE=cloud-api
PROTECTED_RESOURCE_CLOUD_TOKEN_FILE=/var/run/cloud-api/token
# optional: another base URL for the same API (HTTPS only), and the CA bundle of a private endpoint
# PROTECTED_RESOURCE_CLOUD_API_URL=https://api.ionos.com/cloudapi/v6
# PROTECTED_RESOURCE_CLOUD_CA_FILE=/var/run/cloud-api/ca.pem
```

The adapter makes one read-only call, the IONOS Cloud API's list operation
`GET {base}/datacenters?depth=0&limit=100` with `Authorization: Bearer <token>`
([provider reference](https://api.ionos.com/docs/cloud/v6/): server `https://api.ionos.com/cloudapi/v6`,
`GET /datacenters`, query parameters `depth` and `limit`, token authentication, answer a `collection`
whose `items` are of type `datacenter`). It returns the documented report with the number of data
centers on that first page; no provider string, identifier or metadata is forwarded or logged. The
token is read from the mounted file on every call (rotation; a lost file fails closed), never from an
environment value. Redirects are refused, TLS is verified, the request deadline applies, the answer is
limited to 1 MiB. Failures carry fixed reason codes (`CLOUD_ACCESS_DENIED`, `CLOUD_UPSTREAM_UNAVAILABLE`,
`CLOUD_RESPONSE_INVALID`, `CLOUD_REQUEST_FAILED`, `CLOUD_CREDENTIAL_INVALID`). In token mode only
`report:read` reaches the adapter; `report:summary` and other scopes are refused with a recorded
`RESOURCE_SCOPE_INSUFFICIENT`. Every completed request is logged with the adapter that answered it
(`"adapter":"cloud-api"`).

### Refused at configuration time

The Resource does not start when its dock is misconfigured:

- an unknown adapter name, a missing, empty or malformed token file, a base URL that is not HTTPS or
  carries credentials or a query, an unreadable CA bundle: refused when the configuration is loaded;
- an API that does not answer as the documented interface: before serving, the Resource makes the
  adapter's one call (`CheckInterface`). Anything but the documented collection is refused and logged
  as `protected resource configuration rejected` with `reasonCode` `CLOUD_INTERFACE_REJECTED` and the
  cause (`CLOUD_RESPONSE_INVALID`, `CLOUD_ACCESS_DENIED`, `CLOUD_UPSTREAM_UNAVAILABLE`,
  `CLOUD_REQUEST_FAILED`), and the process exits. A provider that is unreachable at start is therefore a
  refused start, not a degraded one.

### Mounted secret and chart

Layer `deployment/helm/application-service/ci/cloud-resource-values.yaml` over the guarded-resource
values. The chart mounts the Secret `protected-resource-cloud-api` (key `token`) read-only. The
deployment needs an admitted image that contains the adapter and a destination-scoped TCP/443 egress
rule and mesh egress route to the provider; the fixture grants no blanket egress. No zone deployment is
part of this change.

```sh
PATH=/opt/homebrew/bin:$PATH scripts/ci/check-charts.sh deployment/helm/application-service
```

## The participant-backend dock

A participant backend docks at the Connector through its documented interface
([OAuth2 provider](oauth2-provider.md), [Connector](connector.md)): it is registered through dynamic
client registration (confidential client, `client_secret_basic`, DPoP-bound, its scopes and resource
audiences), asks for a challenge, exchanges a verified presentation for a DPoP-bound token and calls
the protected route with a fresh proof per call. `internal/connectorclient` is the client side of that
interface; the supplied Participant uses it, and so can any other backend.

Refused at configuration time: a backend that does not satisfy the interface is not registered. The
Connector answers `400 invalid_client_metadata`, reason `registration_rejected`, and writes the audit
row and token event `TOK-REGISTRATION-REJECTED` with the rule (`dcr.dpop_bound` for a client without
DPoP binding, `dcr.auth_method` for a public client, `dcr.members` for metadata outside the interface).

## Proofs

```sh
go test -count=1 ./services/protectedresource       # adapter, settings, interface check; offline
```

The journey needs the token path's local services (a PostgreSQL and an OpenBao with transit, as for
the other authorization rows):

```sh
TOKEN_STORE_TEST_DATABASE_URL=postgres://... TRANSIT_TEST_ADDR=http://127.0.0.1:8200 TRANSIT_TEST_TOKEN=... \
BDD_TARGET=local-services BDD_RUN_ID=<run> BDD_MODE=cluster GODOG_CUCUMBER_OUT=bundles/bdd/apidock-cluster-report.json \
  go test ./internal/bdd -godog.tags='@ZT-07,@ZT-77'
```

`TestAPIDockJourney` (`services/participant/apidock_test.go`) runs the real connector binary once, the
supplied Participant and the Resource built as `cmd/protected-resource` builds it. It first runs the
journey on the supplied mocks, then docks the cloud adapter behind the same public URL against a local
stand-in that answers as the provider documents the list operation, and repeats the journey with the
Participant's existing token; a second participant backend, registered through DCR and written against
the Connector's interface only, makes the same call; the Connector's keys and the Resource's trust
settings are compared before and after; an API answering another interface is refused at
configuration time. That decides ZT-07.

ZT-77 asks for a real-world API. `TestAPIDockLive` is the same journey with the provider itself docked
and runs only when a token file is named:

```sh
API_DOCK_LIVE_TOKEN_FILE=/absolute/path/to/token   # added to the command above
```

Without that file the ZT-77 scenario is skipped and reported not run; the stand-in never decides it.
The token is read from the file by the Resource only; it is never printed, logged or recorded. The call
is the read-only list above.
