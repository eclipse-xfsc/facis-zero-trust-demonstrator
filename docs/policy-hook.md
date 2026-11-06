# Guard policy hook

The guard is the Envoy proxy in front of every protected resource. On each request it asks a
policy hook whether to forward the request, and with which headers, or to refuse it, and with
what answer. The hook asks the policy engine with the policy input of
[IF-05](api-docs.md) and acts on its decision; on an allow that carries the substitution
obligation it asks the token store for the upstream credential
([token store API](contracts/token-store.v1.openapi.yaml)). Which Envoy filter carries that call,
and why, is recorded in the
[decision on the policy hook](adr/0008-envoy-ext-authz-as-the-guard-policy-hook.md): `ext_authz`,
with `ext_proc` as the alternative that differs in the filter block only.

This page describes the hook as it is verified today — against a real Envoy from the pinned image,
deciding from the contract fixtures, with a stand-in token store — and how to run that
verification. The guard's deployment, the policy engine client and the token store are later work;
what is fixed here is the behaviour at the hook.

## The request path

```text
caller ── TLS ──▶ guard (Envoy) ── ext_authz ──▶ policy hook ── IF-05 ──▶ policy engine
                      │                              │
                      │                              └── substitute ──▶ token store
                      └── forward, with the hook's headers ──▶ upstream
```

One call per request, before routing. The hook answers in one of three ways:

| Decision | What Envoy does | Status |
|---|---|---|
| allow | forwards the request with the hook's header mutation applied | the upstream's |
| deny | answers the caller itself with the hook's status, headers and body | the one the reason-code registry gives the code: 403 `POL-RULE-DENY`, 401 `POL-PRESENTATION-REQUIRED` |
| no answer: the hook is unreachable, resets, or exceeds its timeout | refuses the request itself (`failure_mode_allow: false`) with a local reply the bootstrap defines | 503 `POL-PDP-UNAVAILABLE` |

## What the hook does with a request

The hook's core (`cmd/policy-hook-probe/internal/hook`) is transport-neutral: it turns one request
into one outcome, and one package (`internal/envoyhook`) translates that outcome into the messages
of either filter. A
decision therefore does not depend on which filter carries it, which is what the filter-parity
proof confirms.

1. **Correlation.** The hook generates a request id and replaces any inbound `x-request-id`. The
   id is the `correlation_id` of the policy input and of the decision event.
2. **Authentication result.** The caller's `Authorization` and `DPoP` headers are turned into the
   `token` member of the policy input — present or not, and if present its `client_id`, `jkt`,
   `scope`, `aud` and `proof_valid`. The verification uses fixed tokens; the guard's own token
   check feeds this in the deployed hook.
3. **Policy input.** `correlation_id`, the caller's SPIFFE ID (from the connection when the
   transport authenticated one, else the configured source), the method, path without query and
   host, the token, and `tenant` (`null` when there is none). The input is what the contract
   fixtures hold, member for member.
4. **Decision.** The decision is validated against the rules of the decision schema before it is
   acted on. One that does not validate, an error from the engine, or a decision later than the
   hook's own bound (150 ms by default) all become a 503 `POL-PDP-UNAVAILABLE` refusal.
5. **Allow.** The hook sets `x-request-id`, and with the `substitute_upstream_token` obligation
   sets `Authorization` and `DPoP` to the token store's values, asked for exactly the upstream
   method and `https://<published host><route path>`. It removes `X-Forwarded-For`,
   `X-Forwarded-Host`, `X-Forwarded-Proto`, `Forwarded` and every `x-facis-*` header of the caller,
   and the caller's `Authorization` and `DPoP` when nothing is substituted; `traceparent` and
   `tracestate` pass through. These are the rules of
   [Header propagation, guard to gateway](api-docs.md#header-propagation-guard-to-gateway). A
   substitution the token store refuses is a refusal to the caller with the store's code and
   status (`TOK-NO-UPSTREAM` 409, for example); a store that cannot be reached is
   `TOK-STORE-UNAVAILABLE` 503. The request is then not forwarded.
6. **Deny.** The caller receives the status of the reason code, `Content-Type: application/json`,
   `x-facis-reason-code` with the code, `x-request-id`, and a body:

   ```json
   {"error": "insufficient_entitlement", "reason_code": "POL-RULE-DENY", "rule_id": "data.facis.guard.deny_no_entitlement"}
   {"error": "presentation_required", "reason_code": "POL-PRESENTATION-REQUIRED", "oid4vp_link": "https://zone-a.example/present?challenge=fx"}
   ```

   The body is the decision's `deny_body` plus the reason code and, for a rule denial, the rule.
   The OID4VP link travels only with `POL-PRESENTATION-REQUIRED`: the decision schema requires it
   there and the hook passes on what the decision carries.
7. **Event.** One [IF-01](api-docs.md) `decision` event per request, as a JSON line: `allowed`,
   or `denied` with the reason code and the rule. It carries no token.

## When the hook cannot answer

Envoy, not the hook, refuses the request then. The bootstrap sets `failure_mode_allow: false`, a
0.25 s bound on the call, and a local reply for the filter's error: status 503, `Content-Type:
application/json`, `x-facis-reason-code: POL-PDP-UNAVAILABLE` and the body
`{"error": "policy_unavailable", "reason_code": "POL-PDP-UNAVAILABLE"}`. The reply is selected by a
CEL filter on the response code details (`ext_authz_error` or `ext_proc_error`), so it applies to
both filters and to nothing else. A hook whose process died is refused at once, on the connection
reset; one that stopped answering with its connections open is refused when the bound elapses.
The fail-closed proof shows both, under load, and that the hook is used again as soon as it
listens again — Envoy keeps no state about it.

The Envoy-side bound is the one that holds. The hook's own 150 ms bound on a decision exists so
that a slow engine is reported as `POL-PDP-UNAVAILABLE` by the hook, with a decision event, rather
than by Envoy's local reply, which emits none.

## ext_proc: the same hook on the other filter

The hook serves both `envoy.service.auth.v3.Authorization` (ext_authz) and
`envoy.service.ext_proc.v3.ExternalProcessor` (ext_proc) on one listener. Under ext_proc only the
request-headers phase is decided; every other phase Envoy is configured not to send, and would be
passed through unchanged. An allow is a header mutation and `CONTINUE`; a deny is an immediate
response with the same status, headers and body.

Switching the guard from one to the other is a change of the filter block of its bootstrap, between
the markers `# policy-hook-filter: begin` and `# policy-hook-filter: end`:

```yaml
# ext_authz
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    transport_api_version: V3
    failure_mode_allow: false
    status_on_error: { code: ServiceUnavailable }
    grpc_service:
      envoy_grpc: { cluster_name: policy-hook }
      timeout: 0.25s
```

```yaml
# ext_proc
- name: envoy.filters.http.ext_proc
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor
    failure_mode_allow: false
    message_timeout: 0.25s
    processing_mode:
      request_header_mode: SEND
      response_header_mode: SKIP
      request_body_mode: NONE
      response_body_mode: NONE
      request_trailer_mode: SKIP
      response_trailer_mode: SKIP
    grpc_service:
      envoy_grpc: { cluster_name: policy-hook }
      timeout: 0.25s
```

Nothing else changes: not the hook, not the policy input, not the decisions, not the local reply.
The filter-parity proof renders both bootstraps, sends the contract's input fixtures through each
and records that status, headers, body and the headers the upstream received are identical, and
that the two bootstraps are identical outside the markers (`filter-switch.diff` is the whole
difference).

## Running the verification

The proofs live in `cmd/policy-hook-probe` and the script that runs them in
`scripts/verify-policy-hook/verify.sh`. The script builds the probe, pulls the pinned Envoy image
when needed, starts the echo upstream and the hook as processes and Envoy as one container,
drives requests through Envoy, checks the records it wrote and leaves them, with `verdict.txt`
and `environment.json`, in a folder git ignores:

```sh
scripts/verify-policy-hook/verify.sh                 # about two minutes; writes .dev/policy-hook-evidence/
scripts/verify-policy-hook/verify.sh --out DIR       # writes elsewhere
scripts/verify-policy-hook/verify.sh --verify DIR    # only re-checks existing records
```

The variables and the records are listed in `scripts/README.md`. No record is committed: the
workflow `.github/workflows/policy-hook.yml` runs the script on a Linux runner for every pull
request that touches it, uploads the records as an artefact and writes the verdict to the job
summary. The latency numbers to quote are those, since a local run on macOS measures Envoy through
Docker Desktop's port forwarding.

The hook can also be run on its own, deciding from the fixtures, to point another Envoy at it:

```sh
go run ./cmd/policy-hook-probe serve --listen 127.0.0.1:9001 --fixtures docs/contracts/fixtures \
  --ops 127.0.0.1:9002
```

`DPoP fx-token-read` is the entitled token (allow, with substitution), `DPoP fx-token-none` the
token without the entitlement (rule denial), no token asks for a presentation.

## Boundaries that tests hold

- Only `internal/envoyhook` imports the Envoy API; the core, the harness and the fixtures see
  `hook.Outcome` alone (`TestEnvoyAPIIsImportedOnlyByEnvoyhook`).
- The statuses the hook answers with are the ones the reason-code registry gives each code
  (`TestStatusesMatchTheRegistry`).
- The decision events the hook writes validate against the IF-01 event schema, and the decision
  rules the hook applies accept every valid decision fixture and refuse every invalid one.
- The three bootstraps differ only between the markers.

## Not here yet

This page and the proofs establish the hook's behaviour; the hook runs as a verification binary
only. The guard's deployable adapter — the policy engine
client, the token store client, the guard's own token check feeding the policy input, and the
Helm wiring that attaches the filter to the mesh's Envoy — is recorded as open in the
[decision on the policy hook](adr/0008-envoy-ext-authz-as-the-guard-policy-hook.md).
