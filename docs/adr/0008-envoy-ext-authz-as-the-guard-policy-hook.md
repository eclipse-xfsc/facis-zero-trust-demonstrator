# ADR-0008: Envoy ext_authz as the guard's policy hook

- **Status:** Proposed. One dependent item remains open: the guard's deployable adapter (see Open
  items).
- **Date:** 2026-10-09
- **Deciders:** Delivery team, from the policy-hook verification of October 2026. Confirmation by
  the deciders of the OAuth2-surface decision is pending.
- **Requirement basis:** ZT-19, ZT-20
- **Related:** [OAuth2 authorisation surface in the Go connector](0003-oauth2-authorisation-surface-in-the-go-connector.md)
  — the tokens the guard authenticates before it asks policy are the connector's. The mesh-mode
  record (0009, allocated, in review) decides the Envoy the hook attaches to; the policy artefact
  chains record (0012, allocated, not yet written) decides where the policy bundles the engine
  evaluates come from. Neither is touched here.
- **Where it is implemented:** `cmd/policy-hook-probe` (the hook as verified, and the proofs),
  `scripts/verify-policy-hook/` (the script that runs them and the Envoy bootstraps), run on every
  pull request by `.github/workflows/policy-hook.yml`, whose artefact and job summary are the
  records; [Guard policy hook](../policy-hook.md) (the behaviour).

## Context

The guard is the Envoy proxy in front of every protected resource. For every request it must
obtain a policy decision — Rego evaluated by the policy engine, with the policy input and decision
the interface registry fixes as IF-05 — and act on it: forward the request with the upstream
credential substituted, or refuse it with a reason code and, when a presentation is required, the
OID4VP link. A refusal has to be answered to the caller with a status, headers and a body; an
allow has to change the request's headers before it is routed; and a policy service that cannot be
reached must mean refusal, never passage.

Envoy offers two filters for an external decision. `ext_authz` makes one call per request in the
header phase and takes back either header mutations for the forwarded request or a complete
response for the caller; its failure behaviour is a setting of the filter. `ext_proc` opens a
stream per request over which the processor may act on any phase — request and response headers,
bodies, trailers — with header mutations and immediate responses; it is newer, gRPC-only, and
richer than the hook needs. One had to be chosen for the guard, the other kept reachable, and the
failure behaviour and the cost of the hook established before the guard and the policy adapter
are built on it.

## Decision

### 1. The hook is `ext_authz`

The guard asks its policy decision through Envoy's `ext_authz` filter over gRPC
(`envoy.service.auth.v3.Authorization`): one `Check` per request, before routing.

**Reasons**

1. Everything the hook has to do happens in the header phase, and `ext_authz` does all of it.
   On an allow the filter applies the hook's header mutation: `Authorization` and `DPoP` replaced
   by the token store's values, the caller's forwarding and `x-facis-*` headers removed, a
   generated request id set. On a deny the filter answers the caller with the hook's status,
   headers and body — the reason code and the OID4VP link included. Both are proven against
   Envoy v1.36.10 (the header-mutation and deny-response proofs).
2. Failing closed is a setting, not code: `failure_mode_allow: false`, `status_on_error` and a
   timeout on the call. A local reply of the bootstrap gives the caller a reason code,
   `POL-PDP-UNAVAILABLE`, even when the hook itself is gone. Proven under load with the hook
   killed and with the hook frozen: every request started after the strike was refused with 503
   and the reason code, none outlived the timeout plus a few milliseconds, and the restarted hook
   was used again at once (the fail-closed proof).
3. It is the hook the mesh exposes. Istio attaches `ext_authz` to sidecars, gateways and
   waypoints through an `AuthorizationPolicy` with the `CUSTOM` action and an extension provider
   in the mesh configuration, without an `EnvoyFilter`; `ext_proc` has no such attachment and
   needs an `EnvoyFilter`, which the mesh-mode record would have to allow for.
4. Its cost is small and no higher than `ext_proc`'s. The measured added latency is in section 4.

**Costs accepted**

- Policy sees headers only: a request body is not part of the policy input. Nothing in the
  interface registry needs it.
- No action in the response phase. The upstream nonce challenge the API documentation describes
  (a `DPoP-Nonce` answer from the upstream, retried once with a new proof) cannot be handled inside
  `ext_authz`; where it lives is an open item.
- One decision per request, taken before routing, from the headers Envoy presents; the hook does
  not see the route the request will take.

**Rejected alternatives**

- `ext_proc` as the hook now. It carries the same decisions identically (section 2) at the same
  cost, but needs an `EnvoyFilter` on the mesh and brings phases the hook does not use. It stays
  the documented alternative.
- A Lua or Wasm filter inside the proxy: policy logic in the proxy, in another language than the
  services, with no Go test harness and no contract fixtures to drive it.
- A Go reverse proxy as the guard, in place of Envoy: a second proxy in the request path, and the
  mesh's Envoy would no longer be the single L7 enforcement owner of the path that the mesh-mode
  decisions require.

### 2. The hook is transport-neutral, so the switch to `ext_proc` is a configuration change

The hook's core turns one request into one outcome — the headers to set and remove, or the
status, headers and body to answer — and one package translates that outcome into the messages of
each filter. The hook serves both services on one listener.

**Reasons.** The decision then does not depend on the filter that carries it. The filter-parity
proof sends the contract's policy-input fixtures through an `ext_authz` bootstrap and through an
`ext_proc` bootstrap and records that status, headers, body and the headers the upstream received
are identical for every case, and that the two bootstraps are identical outside the filter block
between the markers `# policy-hook-filter: begin` and `end` (the filter-parity proof and its `filter-switch.diff`).
Moving the guard to `ext_proc` is that block, re-verified by the same proofs.

**Costs accepted.** The hook carries the `ext_proc` service and its tests although the guard does
not use it; the Envoy API types of both filters are a dependency of the module (kept inside one
package by a test).

**Rejected alternative.** Deciding `ext_authz` and writing only its translation. The switch would
then be a rewrite under time pressure, not a configuration change, and the claim that the two are
interchangeable would rest on reading rather than on a run.

### 3. Failure behaviour and the bound on a call

A hook call is bounded at 0.25 s on the Envoy side (`grpc_service.timeout`, and
`message_timeout` under `ext_proc`), with `failure_mode_allow: false`; when the call fails or
exceeds the bound, Envoy refuses the request with the local reply: 503, `Content-Type:
application/json`, `x-facis-reason-code: POL-PDP-UNAVAILABLE` and the body
`{"error": "policy_unavailable", "reason_code": "POL-PDP-UNAVAILABLE"}`, selected by the response
code details `ext_authz_error` or `ext_proc_error` so that it applies to a hook failure and to
nothing else. The hook bounds its own decision at 0.15 s, below Envoy's bound, so that a slow
engine is refused by the hook, with a decision event, rather than by Envoy, which emits none.

**Reasons.** The caller always receives a reason code, whichever side refuses. The Envoy-side
bound is what holds when the hook is frozen (connections open, nothing answered): the proof shows
those requests refused at the bound, and a dead hook refused at once on the connection reset.
Both values are proposed; the deployment may tune them, within the rule that the hook's bound
stays below Envoy's.

**Costs accepted.** A refusal Envoy makes on its own has no decision event; it is in Envoy's
access log and in the filter's counters (`ext_authz.error`). The observability work has to carry
it to the feed, or the panel shows the guard as unavailable from the counters.

### 4. Measured latency and the proposed budget

The latency proof sends the same allowed request, with substitution, through three bootstraps
that differ in the filter block only — no hook, `ext_authz`, `ext_proc` — 2000 times each after
a warm-up, at concurrency 1 and 8, and records the percentiles of each and the hook's added
latency, the difference to the no-hook run. The hook decides from fixtures, so the figures are
the cost of the hook and its transport; the engine's own evaluation time is not in them.

Local run (Darwin arm64, Docker 28.5.1, Envoy v1.36.10, 2026-10-09; `latency.json` of that run):

| Bootstrap | Concurrency | p50 ms | p95 ms | p99 ms | max ms | added p50 ms | added p99 ms |
|---|---|---|---|---|---|---|---|
| baseline | 1 | 0.373 | 0.584 | 0.974 | 4.115 | — | — |
| baseline | 8 | 0.877 | 1.555 | 2.216 | 14.48 | — | — |
| ext-authz | 1 | 0.638 | 1 | 1.455 | 13.205 | 0.265 | 0.481 |
| ext-authz | 8 | 1.433 | 2.188 | 3.15 | 16.489 | 0.556 | 0.934 |
| ext-proc | 1 | 0.634 | 1.296 | 2.352 | 14.174 | 0.261 | 1.378 |
| ext-proc | 8 | 1.327 | 1.819 | 2.19 | 2.734 | 0.45 | -0.026 |

The numbers that count are those of a Linux host: a local run on macOS measures Envoy through
Docker Desktop's port forwarding. The pull-request workflow runs the proof on a hosted Linux
runner and writes its numbers to the job summary; they replace the local table above when the
record is accepted. The records of a run are not committed: the workflow's artefact holds them.

**Proposed budget.** The hook adds at most 1 ms at p50 and 5 ms at p99 to a request at the
guard, at the demonstrator's load of at most eight concurrent requests per guard, engine
evaluation excluded. The budget is proposed from the measurement, is to be confirmed with the
Linux figure, and is what the target-cluster run of the guard is measured against.

## Consequences

- Positive: the guard's policy hook is one call in the header phase with the semantics the
  interface registry fixes — proven against a real Envoy, not inferred — and the policy adapter
  can be built on a core that is already tested against the contract fixtures and both filters.
- Positive: the failure behaviour is a bootstrap setting with a reason code for the caller, so a
  policy outage is a refusal that the UI can name.
- Negative: the proofs pin Envoy v1.36.10, whose upstream line leaves support on 2026-10-14. A
  bump is a change of the pin in `scripts/tools/pins.env` re-verified by the same proofs; what
  matters more is the Envoy the mesh ships, against which the hook is verified again when it is
  attached (the mesh-mode record names the Istio release).
- Negative: policy decides on headers only, and the response phase is out of the hook's reach;
  the upstream nonce retry needs another home.
- Negative: two Envoy API modules and gRPC enter the module and the licence scan; a test keeps
  the Envoy types inside one package.

**What would reopen this decision:** a policy that needs the request body; a need to act on the
response phase that the guard's router cannot meet; a measured p99 above the budget on the target
cluster; Envoy or the mesh withdrawing or restricting `ext_authz` extension providers; or the
mesh's waypoint moving to a proxy that attaches policy differently.

## Open items

- **The deployable adapter.** This record proves the hook; the hook runs as the verification
  binary only, and nothing here is the guard's adapter. The guard's
  adapter needs the policy engine client behind the same decider interface, the token store
  client for substitution, the guard's own token check feeding the policy input, the extension
  provider in the mesh configuration with the `AuthorizationPolicy` that attaches it, and an
  image. It belongs to the guard and policy work.
- **The upstream nonce retry.** The API documentation's once-only retry with a new proof is not
  an `ext_authz` capability; the router's retry policy or the adapter's own upstream call are the
  candidates.
- **The Linux figure.** Section 4 quotes a local run until the pull-request workflow has run; the
  summary of that run supplies the numbers to enter.
- **Refusals Envoy makes alone.** They have no decision event; the observability work decides how
  the feed learns of them.

## References

- Envoy: the `ext_authz` HTTP filter, the `ext_proc` HTTP filter, local reply configuration, and
  the CEL expression filter over response code details
- Istio: external authorization through `AuthorizationPolicy` `CUSTOM` and extension providers
- RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP); OpenID for Verifiable
  Presentations
- [Guard policy hook](../policy-hook.md) — the behaviour as verified and how to run the proofs
- [API documentation](../api-docs.md) — the policy interface, the reason-code registry and the
  header rules the hook applies
