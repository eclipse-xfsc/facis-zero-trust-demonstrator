# Scenario decisions

This page fixes, for every journey in [Orchestrated flows](flows.md), the inputs a viewer may choose,
the values they may take, what each step emits on the security-state feed ([IF-01](api-docs.md)),
how each journey ends, and which role may run it. It also fixes the configuration boundary: which
governed changes ([IF-06](api-docs.md)) the UI may offer. The UI, the flows and the acceptance
scenarios are built against this page; a change to it goes through review like a contract change.

## Conventions

- **Zones.** The participant backend is in zone A; the protected resource is in zone B. The
  connector that registers clients and issues tokens for zone B's resources is `connector-b`; the
  token store holding upstream tokens for the backend is `token-store-a`; `gateway-a` opens the
  attested channel and `gateway-b` terminates it; `guard-b` decides at the resource.
- **Runs.** Every start of a journey is one `run_id`. Every request inside a run carries one
  `correlation_id`. The UI groups and orders by them as IF-01 prescribes.
- **Unknown, not stale.** On a sequence gap or a stale feed a panel shows `UNKNOWN`
  (`VIS-STALE`, `VIS-DISCONNECTED`), never its last value.
- **Reset.** Every journey starts from the seeded state; the reset hook restores it, including any
  revoked credential or altered measurement from the previous run.
- **Fixture-only.** Until the services in "Live from" exist, a run is driven from the fixture
  package in `features/fixtures/xfsc/` and the contract fixtures in `docs/contracts/fixtures/`, and
  its result is reported as fixture-only, never as live evidence.

## Participant profiles

The machine identities a journey runs with. They are not viewer accounts; viewers are in the
[Identity model](identity-model.md).

| Profile | Credential | Presented | Token scope | Used by |
|---|---|---|---|---|
| `participant-reader` | role `participant`, entitlement `read` | yes | `read` | Successful call, revoked credential |
| `participant-no-entitlement` | role `participant`, no entitlement | yes | `read` | Wrong scope |
| `participant-unpresented` | none yet | no | none | Credential issuance (start), presentation-required variant |

## Journeys

Priority sets the order of delivery and of the demonstration: P1 first.

| Journey | Priority | Role to start | Inputs (allowed values, default first) | Live from |
|---|---|---|---|---|
| Successful call | P1 | operator | profile: `participant-reader` | connector and guard; attested channel |
| Revoked credential | P1 | operator | profile: `participant-reader`; credential to revoke: the profile's own | as above, plus the verification service |
| Wrong scope | P1 | operator | profile: `participant-no-entitlement`; variant: `rule-deny` (default) or `presentation-required` (profile `participant-unpresented`) | connector and guard |
| Tampered measurement | P2 | operator | gateway: `gateway-b` (default) or `gateway-a`; measurement: a digest that differs from the published one (the UI offers one generated value) | attested channel |
| Configuration change | P2 | operator | see [Configuration boundary](#configuration-boundary) | governed pipeline |
| Credential issuance | P3, provisional | operator | profile: `participant-unpresented` | OCM W-Stack; the scenario is still to be aligned with the client |
| Deployment lifecycle | — | operator | IF-08 command | available |

An observer may open any journey and watch a run started by an operator; every start, reset or input
control is disabled for the observer and returns `denied` if called.

### Successful call

| # | Step | Source | Kind | State | Reason |
|---|---|---|---|---|---|
| 1 | Backend registers | `connector-b` | `token_event` | `registered` | |
| 2 | Credential presented and verified | `verification` | `credential_event` | `verified` | |
| 3 | Token issued and key-bound | `connector-b` | `token_event` | `issued` | |
| 4 | Attested channel up | `gateway-a` | `channel_state` | `connecting` → `handshake` → `attested` | |
| 5 | Guard decides | `guard-b` | `decision` | `allowed` | |
| 6 | Resource responds | `guard-b` | `step` | `responded` | |

Ends in: the resource payload, every step green.

Step 1 is live: the connector emits `registered` with the new `client_id` in `detail` on an
accepted registration, and `refused` with `TOK-REGISTRATION-REJECTED` and the policy rule in
`rule_id` on one its policy refuses ([Connector service](connector.md#security-state-events)).

### Revoked credential

The operator revokes the profile's credential (its status-list bit is set), then starts the run.

| # | Step | Source | Kind | State | Reason |
|---|---|---|---|---|---|
| 1 | Presentation checked against the status list | `verification` | `credential_event` | `revoked` | `CRED-REVOKED` |
| 2 | Grant refused | `connector-b` | `token_event` | `refused` | `CRED-OUTCOME-NOT-VERIFIED` |
| 3 | Token store fails closed | `token-store-a` | `token_event` | `refused` | `TOK-NO-UPSTREAM` |

Ends in: a refusal showing `CRED-REVOKED` as the cause. No channel is opened and no decision is
asked of the guard.

### Wrong scope

| # | Step | Source | Kind | State | Reason |
|---|---|---|---|---|---|
| 1 | Credential verified | `verification` | `credential_event` | `verified` | |
| 2 | Token issued | `connector-b` | `token_event` | `issued` | |
| 3 | Attested channel up | `gateway-a` | `channel_state` | `attested` | |
| 4 | Guard denies | `guard-b` | `decision` | `denied` | `POL-RULE-DENY`, `rule_id` `data.facis.guard.deny_no_entitlement` |

Ends in: a denial naming the rule and the reason code. In the `presentation-required` variant, step 4
is `denied` with `POL-PRESENTATION-REQUIRED` and the denial carries the OID4VP link to present a
credential; steps 1–3 do not occur.

### Tampered measurement

The operator replaces the expected measurement of the chosen gateway through the scenario hook. This
is a scenario input, reset after the run; the governed change of a measurement is the configuration
change journey.

| # | Step | Source | Kind | State | Reason |
|---|---|---|---|---|---|
| 1 | Handshake starts | `gateway-a` | `channel_state` | `connecting` → `handshake` | |
| 2 | Report compared and refused | `gateway-a` | `channel_state` | `refused` | `CHAN-MEASUREMENT-MISMATCH` |

Ends in: the handshake aborted. The proof that no application traffic passed is the absence of any
`guard-b` decision event for the run's `correlation_id`.

### Configuration change

The operator chooses a change from the [Configuration boundary](#configuration-boundary). It moves
through the IF-06 phases; the UI shows each record as it changes.

| # | Step | Record | Phase | Reason |
|---|---|---|---|---|
| 1 | Previewed | IF-06 change | `preview` | |
| 2 | Validated (JSON Schema, and SHACL for domain data) | IF-06 change | `validated` or `rejected` | `CFG-SCHEMA-INVALID`, `CFG-SHAPE-INVALID` |
| 3 | Applied as a pull request | IF-06 change | `applied`, with `pr_url` | |
| 4 | Next run of the affected journey | IF-01 events | as that journey | |

Ends in: the affected journey's outcome changed, traceable to the pull request. `requested_by` is the
operator's `preferred_username`. A change requested without the operator role is `rejected` with
`CFG-NOT-AUTHORISED`.

### Credential issuance (provisional)

| # | Step | Source | Kind | State | Reason |
|---|---|---|---|---|---|
| 1 | First call refused | `guard-b` | `decision` | `denied` | `POL-PRESENTATION-REQUIRED` |
| 2 | Credential issued to the wallet | open: IF-01 has no issuer source yet | | | |
| 3 | Next call | as Successful call | | | |

Ends in: the previously refused call permitted. The issuer's events need an IF-01 source, which is a
contract change; the journey's details follow its alignment with the client.

## Configuration boundary

What the UI may offer as an IF-06 change in this phase. Every change needs the operator role, is
validated before it is applied, and is applied only as a pull request; the UI never applies anything
to a cluster directly.

| Kind | Offered | Target | Payload | Validation |
|---|---|---|---|---|
| `trust-zone` | yes | `zone-a` or `zone-b` | `{"zone": "<target>"}` | target is a known zone |
| `policy-ref` | yes | `guard-a` or `guard-b` | `{"bundle": "<name>", "revision": "<revision>"}` | bundle and revision exist in the registry |
| `measurement` | yes | `zone-a-gateway` or `zone-b-gateway` | `{"digest": "sha256:<64 hex>"}` | digest present and well-formed |
| `mock-replacement` | yes | `participant-backend` or `protected-resource` | `{"adapter": "mock"}` or `{"adapter": "real"}` | `real` only once the client has chosen the API |
| `protected-resource` | no — read-only in this phase | | | |
| `participant-backend` | no — read-only in this phase | | | |
| `dns-record` | no — read-only in this phase | | | |

The payload shapes above are fixed here for the UI and the pipeline; they become part of the IF-06
contract when per-kind payload schemas are added to it.
