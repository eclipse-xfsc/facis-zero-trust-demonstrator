# connector

The zone's connector ([services/connector](../../../services/connector)): the OAuth2 authorization
surface that registers participant backends through dynamic client registration behind a policy
gate, with every decision in the audit trail and on the security-state feed; issues DPoP-bound,
ES256-signed access tokens through an OpenBao transit key; and publishes that key. The chart runs
it as a Deployment with its own ServiceAccount and identity label, a Service on its API port, and
liveness and readiness probes, where readiness is green only while the database is reachable at
the schema the connector needs, the key-value store is initialised and unsealed, the pinned signing
key resolves, and the registrar is seeded. The design is in [docs/connector.md](../../../docs/connector.md)
and the endpoints in [docs/oauth2-provider.md](../../../docs/oauth2-provider.md).

## Before the install

The connector stands on four things the chart does not create:

1. **The schema**, applied by the token-store chart (`deployment/helm/token-store`) into the same
   database. Install that chart first; the connector needs schema version 4 and reports
   `schema_behind` until it is there.
2. **The database URL**, in a Secret of the release namespace under `database.existingSecret`,
   the same Secret the token-store chart reads. The chart never carries the credential.
3. **OpenBao**, at `openbao.address` (the umbrella chart's under the release name `ztd` by
   default, which the umbrella ships disabled: enable it there, or point the address at the
   zone's), with a transit key for the access tokens, `ecdsa-p256`, not exportable, created before
   the install, and a token in `openbao.existingTokenSecret` whose policy allows reading
   `transit/keys/<key>` and updating `transit/sign/<key>`.
4. **The connector's secrets**, in one Secret under `secrets.existingSecret`: the access-token HMAC
   secret and the registration-token HMAC secret (32 bytes or more, and different) and the
   registrar's client secret (32 bytes or more), which is the credential handed to whoever
   registers clients.

```bash
kubectl -n ztd-mgmt create secret generic connector-secrets \
  --from-literal=token-secret="$(openssl rand -hex 24)" \
  --from-literal=registration-secret="$(openssl rand -hex 24)" \
  --from-literal=registrar-secret="$(openssl rand -hex 24)"
kubectl -n ztd-mgmt create secret generic connector-openbao --from-literal=token='...'
helm upgrade --install connector deployment/helm/connector -n ztd-mgmt \
  --set image.digest=sha256:... --set zone=a \
  --set database.existingSecret=token-store-database \
  --set openbao.existingTokenSecret=connector-openbao --set secrets.existingSecret=connector-secrets \
  --set issuer=https://connector-a.example --set signing.key=connector-at --set signing.version=1 \
  --set 'registrar.scopes={connector:client_registration,resource.read}' \
  --set 'registrar.audiences={https://resource.example}' \
  --wait
```

`--wait` returns once the pod is Ready, that is, once all four readiness checks answered `ok`.

## Values

| Key | Default | Meaning |
|---|---|---|
| `image.repository` | the project's `connector` image | Image of the service, and of `connector register` |
| `image.digest` | none, required | `sha256:` digest; the chart refuses a tag |
| `zone` | none, required | `a` or `b`: the source of the security-state events is `connector-<zone>` |
| `database.existingSecret` | none, required | Secret in the release namespace holding the connection URL under `database.secretKey` |
| `database.secretKey` | `url` | Key of the connection URL in that Secret |
| `openbao.address` | `http://ztd-openbao.ztd-mgmt.svc:8200` | The key-value store's base URL, `http(s)://host[:port]`; the chart refuses anything else |
| `openbao.existingTokenSecret` | none, required | Secret holding the key-value store token, mounted as a file |
| `openbao.tokenSecretKey` | `token` | Key of the token in that Secret |
| `secrets.existingSecret` | none, required | Secret holding the three connector secrets, mounted as files |
| `secrets.tokenSecretKey` | `token-secret` | Key of the access-token HMAC secret |
| `secrets.registrationSecretKey` | `registration-secret` | Key of the registration-token HMAC secret |
| `secrets.registrarSecretKey` | `registrar-secret` | Key of the registrar's client secret |
| `issuer` | none, required | `iss` of the access tokens, `https://…` |
| `registrationEndpoint` | the Service's own address | `POST /oauth2/register` as clients reach it: the audience a registration token carries |
| `signing.key` | none, required | The transit key that signs the access tokens |
| `signing.version` | none, required | Its pinned version, 1 or more |
| `registrar.id` | `ztd-registrar` | Client id of the registrar, seeded at start |
| `registrar.scopes` | `[connector:client_registration]` | Its scopes; the registration scope among them, plus every scope it may give the clients it registers |
| `registrar.audiences` | `[]` | The resource audiences registered clients may name; the chart prepends the registration endpoint |
| `registrar.delegableScopes` | `[]` | Verified-presentation scopes it may grant beyond its own token's |
| `verifiedPresentation.configMap` | empty | ConfigMap with the trusted issuers and the scope map; enables the verified-presentation grant |
| `verifiedPresentation.issuersKey` | `issuers.json` | Key of the issuers file in that ConfigMap |
| `verifiedPresentation.scopeMapKey` | `scopes.json` | Key of the scope map in that ConfigMap |
| `accessTokenLifespan` | `5m` | Lifetime of the access tokens |
| `dpop.enforce` | `true` | Require a DPoP proof from every client at the token endpoint |
| `dpop.nonce` | `true` | Challenge with a server DPoP nonce |
| `replicas` | `1` | Pods of the service |
| `server.readinessTimeoutSeconds` | `2` | Budget of one `/readyz` evaluation; the probe's `timeoutSeconds` is this plus one |
| `server.drainDelaySeconds` | `5` | On SIGTERM, how long `/readyz` answers 503 while the listeners stay open |
| `server.shutdownTimeoutSeconds` | `10` | Drain of the listeners after that delay; `terminationGracePeriodSeconds` is the drain delay plus this plus the readiness budget plus five |
| `server.logLevel` | `info` | `debug`, `info`, `warn` or `error` |
| `serviceAccount.name` | `ztd-connector` | The ServiceAccount the pod runs as, always; the last segment of the connector's SPIFFE ID |
| `serviceAccount.create` | `true` | Create that ServiceAccount; off, it is managed outside the chart and must exist |
| `identity.spireManagedIdentity` | `true` | Set the pod label `spiffe.io/spire-managed-identity: "true"` the SPIRE registration selects |
| `resources` | small | Requests and limits of the service's container |

## How the service behaves

- **Startup.** The pod starts whether or not its dependencies are there: the connector binds its
  listeners, builds its signer and seeds its registrar in the background with backoff, and reports
  not ready until everything answers. No URL and no secret is logged.
- **Readiness.** The kubelet probes `/readyz` on the ops port every five seconds; 200 only when
  `postgres`, `openbao`, `signing_key` and `registrar` are all `ok`. A registrar that exists with
  other settings is never overwritten and keeps the pod not ready (`registrar: conflict`).
- **Liveness.** `/healthz` answers 200 while the process serves, so a dependency outage never
  restarts the pod.
- **Registration.** `POST /oauth2/register` sits behind the connector's policy gate. A request
  whose token the connector's store does not know goes to the library unjudged and is refused
  401. For a known token the metadata must be one strict JSON object with only the contract's
  members, a `client_name`, a `client_secret_basic` client, `dpop_bound_access_tokens: true`,
  offered grant types, scope tokens never naming the registration scope, and one or more absolute
  audiences. A violation is refused with 400 `invalid_client_metadata`, reason
  `registration_rejected`, and a description naming the rule; the library's own refusals keep
  their shape. At most two registrations run at once, so a burst cannot hold the database pool.
  Every decision writes an `audit_event` row and one IF-01 `token_event` line. An accepted
  registration's row commits with the client, before the answer; a refusal's is written after its
  answer has left.
- **Stop.** On SIGTERM `/readyz` answers 503 with `"draining": true` at once, both listeners keep
  answering for `server.drainDelaySeconds`, then drain within `server.shutdownTimeoutSeconds`.
- **Records and events.** JSON on stdout, one object per line. Every record names the service and
  the pod; the IF-01 events beside them name their source, `connector-<zone>`, and a run id minted
  at every start. Every request record and every event of a request carries its `correlation_id`.
  No secret, token, proof or header is among them.

## Registering a client

The same image registers a client the way a participant obtains its credentials: a Pod or Job
running `connector register` with the registrar's secret mounted writes the strict
`{"client_id","client_secret"}` file the participant reads as `PARTICIPANT_CREDENTIALS_FILE`.

```bash
connector register --connector http://ztd-connector.ztd-mgmt.svc:8080 \
  --registrar-id ztd-registrar --registrar-secret-file /var/run/secrets/connector/registrar-secret \
  --client-name "participant backend" --scope resource.read --audience https://resource.example \
  --out /out/credentials.json --request-id my-registration
```

Exit codes: 0 registered and written; 1 refused by the connector (the reason on stderr); 2 usage,
including an existing `--out`, with nothing sent; 3 no answer an IF-02 call gives, or a local
failure; 4 registered but the credentials not delivered. The file appears only complete, so a
killed run never leaves an empty `--out` behind. The details are in
[docs/connector.md](../../../docs/connector.md#registering-a-participant). The registrar's token must carry the client's scopes and audiences, so a registrar whose
`registrar.scopes` and `registrar.audiences` do not cover them is refused the token first. A
client for a verified-presentation scope also needs `--delegable-scopes` naming
`registrar.delegableScopes`, which the registrar's token need not carry and, for a
verified-presentation scope, cannot. A
mounted Secret is owned by root: a pod running the command as a non-root user needs `fsGroup` to
read the registrar's secret, as the chart's own Deployment sets it.

## Identity

The pod runs as the ServiceAccount `serviceAccount.name`, `ztd-connector` by default, in the
management plane, with the label `spiffe.io/spire-managed-identity: "true"`: under both mesh
modes its SPIFFE ID is `spiffe://<trust domain>/ns/<namespace>/sa/ztd-connector`. The mesh
terminates mTLS for it, as for every zone workload: the listeners are plain HTTP inside the pod,
no ServiceAccount token is mounted (the SVID comes from the SPIFFE CSI driver), and the pod carries
no sidecar annotation and excludes no port. Participant backends in the data plane reach it
through an allow-matrix lane of the umbrella chart (data to management, port 8080, pods labelled
`app.kubernetes.io/name: ztd-connector`), which the umbrella adds when the connector joins a zone.

## Verify

Without a cluster, the connector's tests run against a PostgreSQL and an OpenBao with the transit
engine (`TOKEN_STORE_TEST_DATABASE_URL`, `TRANSIT_TEST_ADDR`, `TRANSIT_TEST_TOKEN`), as the
`Token store` workflow runs them in both token modes. The chart, the registration path and the
audit trail are proven on a throwaway kind cluster by `scripts/verify-connector/verify.sh`, which
the `Connector` workflow runs on every change to the connector, its image, either chart or the
pinned images.
