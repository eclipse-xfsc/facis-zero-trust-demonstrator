# ADR-0017: Collectors per cluster, observability backends central on the demonstrator cluster

- **Status:** Proposed
- **Date:** 2026-10-21
- **Requirement basis:** ZT-27 (observability through the OpenTelemetry Collector, Prometheus and an
  OTel-compatible tracing backend), ZT-52 (control-plane failures detected and alerted within 30
  seconds), ZT-51 (revocation endpoint availability monitored), ZT-26 (observability APIs bypass the
  Zero Trust Connector with their own ingress and egress), ZT-15 (the visualization runs on the IONOS
  Cloud), ZT-55 (placement in the plane model)
- **Refines:** [ADR-0005](0005-three-cluster-reading-of-the-target-environment.md)

## Context

ADR-0005 reads the target environment as three clusters and lists the observability stack among the
components "installed per cluster". Read literally, each zone would run its own Prometheus and Jaeger. That gives three stores to compare by hand, and it puts the visualization in the zones,
where ZT-15 places it on the IONOS Cloud. Without Grafana, which is excluded by licence
([Specifications](../specifications.md)), the Prometheus and Jaeger interfaces are that visualization.

Two facts of the zones shape what can run there. The SPIRE agents bind their metrics to the node's
loopback (`deployment/helm/values/spire.yaml`), so only a collector on the host network of each node
can read them. And every plane namespace with injection runs mesh-wide STRICT mTLS, with an admission
policy that lets no port of a meshed pod out of mTLS, so a meshed collector cannot take traffic from a
pod without an SVID.

## Decision

**Collectors run in every participant zone; the backends run once, on the demonstrator cluster.**

- In each participant zone (zone A, zone B; kind in development) two collectors from the upstream
  OpenTelemetry Collector chart, installed by `scripts/install-zone/install.sh`:
  - the **node collectors** (release `otel-node`, namespace `ztd-otel-node`, management plane, no
    mesh): a host-network DaemonSet that reads every pod's log lines from `/var/log/pods` (read-only)
    and scrapes its own node's SPIRE agent on `127.0.0.1:9988`;
  - the **zone gateway** (release `otel-gateway`, the management namespace, meshed, with an SVID):
    receives OTLP from the workloads and the mesh proxies along the allow-matrix row
    `workloads-to-otel-collector`, scrapes the SPIRE server and the controller-manager through the
    declared lane `observabilityScrape`, reads node readiness, and probes the revocation status list.

  Both export straight to the demonstrator cluster: the node collectors have no SVID, and the gateway
  is STRICT, so relaying node traffic through the gateway would need a port outside mTLS.
- On the **demonstrator cluster** (`deployment/helm/ztd/zones/ionos.yaml`, `zone.role: demonstrator`),
  in the namespace `ztd-observability`, outside both SPIFFE trust domains: a receiving collector (the
  entry), Prometheus (metrics by remote write; it scrapes nothing in a zone; the alert rules) and
  Jaeger.
- **Alerts are Prometheus rules in the `firing` state.** An alert is emitted when its rule fires, and
  is read from Prometheus's alerts API (`/api/v1/alerts`), which lists only what the rules evaluate,
  and the `ALERTS{ztd_source="collector"}` series: every rule labels its alert so. The proof records
  each firing alert with its detection time as evidence. No source names a receiver to route an
  alert to.
- **The alerts read only the collectors' own signals.** The zone gateway's OTLP receiver is open to
  every data-plane workload (the allow-matrix row), so what arrives there is untrusted. Two layers
  keep it out of the alerts, and either one alone suffices:
  - **Source label.** The health signals the rules read (the scrapes' `up`, `k8s_cluster`'s node and
    DaemonSet metrics, the probe's `httpcheck_*`, the collectors' own `otelcol_*`) are stamped
    `ztd.source=collector` by the collector that produces them, on a pipeline that carries no OTLP.
    The gateway's OTLP metrics pipeline sets `ztd.source=workload`, overwriting any value the client
    sent. Every selector of the rules, on the inputs and on the rules' own recorded series
    (`ztd:*`, which keep the label), requires `ztd_source="collector"`, and every alert labels itself
    `ztd_source: collector`.
  - **Reserved names.** The same pipeline drops every metric whose name Prometheus would store as a
    health input, a recorded `ztd:` series or the alert series (`ALERTS`, `ALERTS_FOR_STATE`): the
    remote write turns other characters into `_` and trims them at the ends, so the filter matches
    those names with any separator, leading or trailing characters and case. Names such as `uptime`
    or `ztd_proof_zone_claim` pass.

  So a workload can neither keep a failed component's series up, raise a false alert, nor break a
  rule's match with a series of the same name. Alerts are read from `/api/v1/alerts`, which lists only
  what the rules evaluate, or from `ALERTS{ztd_source="collector"}`.
  `scripts/verify-observability/test-alert-rules.sh` checks the rendered rules, pipelines and filter
  (each reserved name in its separator, case and edge variants) and runs promtool cases with forged
  series, recorded-series names included.
- **Logs are exported to files, not to a query service.** The entry's log pipeline of each zone ends
  in the collector's `file` exporter: the zone's records as OTLP JSON lines in
  `/var/lib/ztd-logs/<zone>.jsonl` on a persistent volume of the cluster's storage class
  (`otel-entry-logs`), rotated by size with nine backups, the rotation size set by the installer so
  that every zone's files fit in the volume. Each record keeps its zone, namespace, pod, container,
  timestamps and IF-01 fields, so the records of one request are found by `correlation_id`. That is
  what the sources ask for logs: ZT-27 requires events exported from the cluster in OTel format, and
  names retention only for metrics and a backend only for traces; IF-04 and ADR 006 fix the JSON
  record format. No source asks for a log query service, so none is installed: Loki is excluded by
  licence, and OpenSearch would add a store and its operation for no stated need. The proof's
  `logs-exported` check reads the files.
- **Authentication** (default of an open point): mutual TLS 1.3. A cert-manager root on the
  demonstrator cluster issues the entry's server certificate and one intermediate per zone; each
  zone's client certificate is issued by its intermediate. The entry has one listener per zone (zone A
  4317, zone B 4417), each trusting only that zone's intermediate, and its pipeline overwrites the
  `zone` attribute: the zone is the listener's, never the client's. The keys are generated on the
  demonstrator cluster and copied into the zones by the installer step `telemetry-client-certs`; none
  is in the repository.
- **Transport:** the entry's address is a zone-file value (`telemetryExport.entry`). During the
  contingency period it is the public address of the entry's `LoadBalancer`, restricted to the zones'
  egress addresses; after the move to the CUG interconnect it is the CUG address. The path is a declared
  bypass of the Zero Trust Connector under ZT-26, class observability export, outward only
  ([Architecture](../architecture.md), section 6).

### Detection budget (ZT-52)

| Step | Missing target | Silent zone | Vanished agent | Revocation probe |
|---|---|---|---|---|
| Scrape or probe interval | 5 s | (window) | (window) | 5 s |
| Collector batch timeout | 1 s | | | 1 s |
| Export latency | at most 2 s | | | at most 2 s |
| Absence window | | 15 s | 10 s | |
| Probe timeout | | | | 2 s |
| Rule evaluation interval | 5 s | 5 s | 5 s | 5 s |
| Alert `for` | 10 s | 5 s | 10 s | 10 s |
| **Worst case** | **23 s** | **25 s** | **25 s** | **25 s** |

There is no routing stage: the firing state is the alert. The silent-zone rule's window already
holds the alert back, so its `for` is 5 s rather than 10 s; with 10 s its worst case would be 30 s,
not below the limit. Export latency covers the zone gateway's send, the entry's batch and its remote
write to Prometheus. The probe's request is bounded by its timeout, below the probe interval and the
rule's lookback: an unbounded probe that hangs leaves no sample, and the alert would never fire.
`scripts/verify-observability/test-alert-rules.sh` checks in CI that the rendered values are these,
and the proof measures each alert on a cluster and fails one that arrives later than 30 s. The budget
counts from the moment the failed component stops answering; the proof counts from the command that
injects the failure and polls every second, so its figures also hold the component's shutdown (a
pod's termination, the mesh's endpoint update) and the poll.

## Consequences

- Positive: one store per signal on the demonstrator, read by zone (every series, span and log record
  carries `zone`, and each zone's logs have their own file); the visualization runs on IONOS (ZT-15); no zone decision changes (agents on the loopback,
  STRICT mTLS mesh-wide, the allow-matrix row as it was).
- Positive: the transport is a zone-file value, so the move to the CUG changes no chart.
- Negative: the demonstrator cluster has one node and the backends have no replicas: losing that node
  stops alerting for every zone. Accepted for a demonstrator.
- Negative: no alert is routed or notified anywhere; a firing alert is seen in Prometheus and in the
  proof's evidence record only. Accepted until an operator channel is named.
- Negative: each zone's client key is mounted on every node collector. That pod already runs on the
  host network with read access to every pod's logs, so the key adds no new trust boundary.
- Negative: during the contingency period the demonstrator cluster has a public entry. Only the
  per-zone mutual-TLS listeners are behind it, with the zones' egress addresses as source ranges.
- Negative: what a workload sends over OTLP is trusted only as far as its own telemetry. A
  data-plane pod can still send traces, logs and metrics of unreserved names under any service name
  (stored with `ztd_source="workload"`),
  flood the gateway's queue (which then refuses new data, health signals included, until it drains)
  or stop sending; the alerts never read its metrics, and a silent or flooded gateway raises
  `ZoneSilent` or shows in the gateway's refused-item counters. The OTLP receiver has no
  authentication of its own beyond the mesh's mTLS and the allow-matrix row. Accepted for a
  demonstrator; an `AuthorizationPolicy` per sending identity would narrow it.
- Negative: while the export path is down, the collectors buffer in a bounded queue (file-backed on
  the node collectors). A full queue refuses new data and counts it
  (`otelcol_exporter_enqueue_failed_*`); a batch still unsent after the 30 min retry window is dropped
  and counted (`otelcol_exporter_send_failed_*`). Nothing in the zone waits on it. The upstream
  sending queue has no drop-oldest mode, and no source asks for one.
- Negative: the logs are files, searched on the cluster (a pod that mounts the volume read-only), not
  through a query interface. Their retention is the volume: once a zone's backups are used up, its
  oldest file is removed.
- Reopen when: an operator channel to notify is named (its routing delay then counts in the
  budget); a source or FACIS asks for logs queryable through a service; FACIS confirms a reading of ADR-0005 that requires backends per cluster; the open
  point on zone authentication settles on bearer tokens (the listener per zone stays, its trust
  changes); or the demonstrator cluster gains a second node, which allows replicated backends.
