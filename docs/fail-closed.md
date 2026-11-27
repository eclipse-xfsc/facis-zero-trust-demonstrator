# Fail-closed behaviour of the guard

The guard refuses a request whenever a dependency it needs for that request does not answer, and it
reports each dependency's state so that an outage can be detected and alerted within 30 seconds, when
the observability stack scrapes the guard and evaluates its rules as described under Alerts. This
page covers the guard's own dependencies: the policy engine, the connector's key set and the token
store. The other control-plane components the requirement names, TRAIN, SPIRE and OCM, are not on
the guard's request path in this code and are not covered here; the acceptance row for fail-secure
behaviour stays pending until they are.

## What the guard answers

Every request is decided on its own: nothing the guard reports ever lets a request through. The
table is the hook's answer to a request that reaches it; separately, a guard that reports a
dependency down is not ready, and the mesh's routing then takes it out of its Service, so ordinary
traffic may not reach it at all.

| Dependency unreachable | A request is | Reported | Alert |
|---|---|---|---|
| Policy engine | refused, 503 `POL-PDP-UNAVAILABLE` | `policy_engine` down | `ZtdGuardDependencyDown{dependency="policy_engine"}` |
| Token store | refused, 503 `replay_unavailable` (the replay check is the first call) | `token_store` down | `ZtdGuardDependencyDown{dependency="token_store"}` |
| Token store, for substitution only | refused, 503 `TOK-STORE-UNAVAILABLE` | up, while its readiness answers | none |
| Connector key set, guard already holds the keys | **allowed** by the hook: the verifier keeps the keys it fetched for up to 5 minutes (`MaxStale`) | `key_set` down | `ZtdGuardDependencyDown{dependency="key_set"}` |
| Connector key set, guard never had them | refused, 503 `key_set_unavailable` | `key_set` down | as above |
| The guard itself (its metrics) | not answered: Envoy refuses without its hook (`failure_mode_allow: false`) | none | `ZtdGuardScrapeFailing` |

"Key set unreachable" is the guard's path to the connector's key set; the token store reaches the
connector on its own path, and its readiness also checks the connector's issuer keys, so a stopped
connector can bring the token store down too.

When the key set returns, a guard that never had the keys keeps refusing until its verifier fetches
it again. The verifier fetches only when a request needs the keys, and at most once every 30 seconds
after its last attempt (`MinRefresh`), so recovery takes a request and up to 30 seconds plus the
fetch, although the guard reports ready as soon as its own check succeeds. The degraded case that
stays open on purpose is the warm guard's: a key rotation is not interrupted by a short connector
outage, at the price of verifying with keys the connector may no longer publish for up to five
minutes.

## What the guard reports

`cmd/guard` checks each dependency every 5 seconds, with a 2-second timeout, on the path the guard
itself uses and without a side effect: the policy engine must answer a request from no participant
with a valid denial, the key set must hold a key the verifier would use, the token store's
`/readyz` must answer 200 (that readiness itself checks PostgreSQL, OpenBao and the store's signing
keys, so it also falls when they do). A dependency counts as up only while its last check succeeded
at most 8 seconds ago; never checked means down.

- `GET /readyz` on the ops port answers 200 when all three are up and 503 with the list of those that
  are not. The chart uses it as the guard container's readiness, so a guard that cannot decide is
  taken out of its Service; `/healthz` stays the liveness check.
- `GET /metrics` serves `ztd_guard_dependency_up{dependency}` (all three always present) and
  `ztd_guard_refusals_total{reason_code}`, every refusal counted once by a code from the known set
  (others as `other`).

## Alerts

`deployment/helm/guard/alerts/guard-rules.yaml` is a plain Prometheus rule file for the scrape job
`ztd-guard`: a dependency down, a guard that cannot be scraped, a guard that does not report all three
dependencies, and no guard discovered. Each fires after 10 seconds. With a scrape every 5 seconds
(1-second timeout) and the group evaluated every 5 seconds, a dependency that stays down fires within
about 28 seconds of the outage (5 s to the next check, 2 s for it, 5 s to the next scrape, 1 s for
it, 5 s to the next evaluation, 10 s pending), and a guard whose checks stop within about 29 seconds.
These intervals are requirements on the observability stack that loads the file; it also owns
delivering a firing alert. The chart opens the guard's `/metrics` to one named scraper only
(`metrics.scraper`, see the chart's README).

`TestGuardFailsClosedPerDependency` (`services/token-store/internal/server`) proves this with the real
connector, policy evaluator, token store, PostgreSQL and OpenBao behind the real `cmd/guard`, each
made unreachable in turn at its network edge (new connections are closed without an answer; the
processes keep running), requests sent to the hook as Envoy sends them, and Prometheus from the
pinned image loading the rule file: the refusal and its code, readiness, the alert firing within 30
seconds of the outage (about 15 seconds in practice), recovery, the warm and the cold guard during a
key-set outage, the scrape alert when the guard stops, and the missing-series alert for a target that
reports two dependencies of three and then none, as one alert throughout. It does not run a mesh: the
scraper's authorization, the mesh's routing around a guard that is not ready, and the protected
resource behind the guard are not part of it. `ZtdGuardTargetAbsent` fires only when no guard at all
is discovered, and is not exercised.
