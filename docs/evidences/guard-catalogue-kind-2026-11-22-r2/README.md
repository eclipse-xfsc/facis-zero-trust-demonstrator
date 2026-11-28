# Guard catalogue on kind after the review (supersedes the run in ../guard-catalogue-kind-2026-11-22)

Records of `scripts/verify-guard-catalogue/verify.sh`, verdict PASS, run 2026-11-22 on a disposable
kind cluster (taken under the shared kind lock and deleted after the run) at the commit and tree
`environment.json` names. Same cases and layout as the first run (its README explains every file),
plus the feed bridge deployed from `deployment/helm/feed-bridge` in the mesh:

- the producer identity posted the guard's and the policy's lines to `/ingest` (`feed-ingest.json`);
- the UI's identity read both feed versions (`events/feed-v1-*`, `events/feed-v2-*`,
  `events/snapshot-v1-*`, `events/snapshot-v2-*`) and found the allowed request's events;
- the Participant's identity reading the feed and another identity posting to `/ingest` were refused
  by the bridge's sidecar, `403 RBAC: access denied` (`responses/feed-participant.http`,
  `responses/feed-intruder-ingest.http`).

Latency, same conditions as before (100 sequential samples each, curl in the participant's
pod, single-node kind on a shared laptop): guarded presentation-required denial p50 5.8 ms, p99
22.3 ms; mesh round trip without the guard p50 1.9 ms, p99 7.2 ms.
