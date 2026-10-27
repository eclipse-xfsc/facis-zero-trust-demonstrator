# verify-observability

Evidence that the observability stack ([ADR-0012](../../docs/adr/0012-central-observability-backends.md))
collects, carries, stores and alerts as specified. Three scripts:

| Script | Needs | What it proves |
|---|---|---|
| `verify.sh` | a cluster: kind with both roles, or a participant zone with the demonstrator cluster | every check below, on a running installation; writes a record outside the repository |
| `test-alert-rules.sh` | no cluster (docker, or `promtool` on `PATH`) | the alert rules under `promtool test rules` with `alert-rules.test.yaml`, and the rendered intervals equal to the detection budget (every worst case below 30 s) |
| `check-rendered-images.sh` | no cluster | every image of the observability releases pinned by digest and under an accepted licence; no Grafana or Loki |

CI runs the last two in the chart job and `verify.sh` on kind in the job `Observability proof (kind)`.

## Running `verify.sh` on kind

Both roles share the kind cluster: the kind zone (`deployment/helm/ztd/ci/values.yaml`) and the
demonstrator role (`deployment/helm/ztd/ci/demonstrator-values.yaml`), whose entry is a ClusterIP
Service reached in the cluster (transport `in-cluster`).

```bash
scripts/dev/kind-cilium-up.sh && scripts/dev/kind-cert-manager-up.sh
scripts/install-zone/install.sh install ztd spire-crds spire istio-base istiod istio-cni zone-policy ztd-openbao
ZONE_VALUES=deployment/helm/ztd/ci/demonstrator-values.yaml TELEMETRY_ZONES=kind=kind-ztd \
  scripts/install-zone/install.sh install
scripts/install-zone/install.sh install otel-node otel-gateway
docker build --platform linux/amd64 -f deployment/docker/trace-echo/Dockerfile -t ztd-proof/trace-echo:dev .
kind load docker-image ztd-proof/trace-echo:dev --name ztd
scripts/verify-observability/verify.sh
```

It installs only its fixtures (`fixtures/`: the meshed echo `tools/trace-echo`, the static server of
the fixture status list `features/fixtures/xfsc/status/allow.json`, a meshed data-plane client, a
stand-in with the zone gateway's labels, a probe on the demonstrator side, a probe in a scratch
namespace) and removes them at the end. To inject failures it stops and restores components: the
SPIRE server (scaled to 0), one SPIRE agent and one node collector (a temporary `nodeSelector` that
matches no node), the zone gateway's egress (its policy deleted and the gateway restarted), the
status list, and the entry (60 s, twice). Every change is undone on exit, interrupted or not.

## Running it against a zone and the demonstrator cluster

```bash
ZONE_CONTEXT=zerotrust-a DEMONSTRATOR_CONTEXT=cluster-admin@ZeroTrustDemonstrator \
ZTD_CONFIRM_CLUSTER=zerotrust-a,cluster-admin@ZeroTrustDemonstrator \
ZONE_VALUES=deployment/helm/ztd/zones/zone-a.yaml ECHO_IMAGE=<the signed trace-echo image by digest> \
  scripts/verify-observability/verify.sh
```

`ZTD_CONFIRM_CLUSTER` is required because the run stops and restores the zone's SPIRE server, an
agent, a node collector and the zone gateway. The fixtures take the zone's node pin. Checks that need
the kind host (the agents' listening sockets read from the node) skip that part and keep the probe
from a pod. The record names the transport (`telemetryExport.entry.transport`): the contingency over
public transit until the CUG, then `cug`; after the move the proof runs again and its record is
archived next to the contingency one.

## Checks

Each check is named by what it proves; the result is `passed`, `failed` or `pending`.

| Check | What it proves |
|---|---|
| `pod-logs-collected` | a pod's plain-text line reaches the entry with zone, namespace, pod and container; a node collector runs on every node the SPIRE agents run on |
| `if01-fields-kept` | an IF-01 event keeps `correlation_id`, `run_id` and `seq` as fields |
| `spire-agents-scraped` | every SPIRE agent is scraped (`up == 1`), labelled with its node and zone |
| `agents-stay-on-loopback` | the agents listen on `127.0.0.1:9988` only, and a pod asking a node address on 9988 is refused |
| `spire-server-scraped` | the SPIRE server and the controller-manager are scraped; their series arrive with the zone |
| `spire-lane-is-narrow` | from the zone gateway's pods 9988 and 8082 answer, the registration port 8081 is refused |
| `workload-otlp-accepted` | a data-plane workload's OTLP/HTTP span (4318) and OTLP/gRPC call (4317) are accepted and stored with the zone; another gateway port is refused |
| `correlated-trace` | one trace holds a proxy's span and the echo's span as its child |
| `revocation-probe-reports` | the probe reports the status list up, down within one probe interval of it stopping, and up again |
| `export-buffered-while-down` | a span sent and metrics produced during a 60 s outage of the entry arrive afterwards; a full queue counts what it refuses, and no container restarts |
| `unknown-client-refused` | the entry refuses no certificate, a foreign CA, another zone's certificate and TLS 1.2, and accepts the zone's own |
| `zone-taken-from-listener` | a metric and a span claiming another zone are stored under the listener's zone only |
| `other-egress-refused` | the zone gateway's pods reach the entry and no other external address |
| `no-route-into-zone` | from the demonstrator side, the zone gateway and a node collector are refused (Prometheus reached as the control) |
| `query-surfaces-not-public` | only the entry can be published, on its listener ports; Prometheus, Alertmanager and Jaeger are ClusterIP |
| `prometheus-scrapes-no-zone` | the central Prometheus's only scrape target is itself: no address in a zone |
| `gateway-holds-svid` | the SPIRE server holds the zone gateway's entry, and its proxy is ready (only with an SVID) |
| `metrics-survive-restart` | the samples of the minute before a Prometheus restart are all there after it |
| `missing-target-alerts` | the SPIRE server, then one agent, stop: an alert naming the zone (and the node) within 30 s, resolved on recovery |
| `vanished-agent-alerts` | a node collector stops with its agent's series: an alert within 30 s |
| `silent-zone-alerts` | the zone gateway's egress is cut: a silent-zone alert within 30 s, resolved when it returns |
| `revocation-endpoint-alerts` | the status list stops: an alert naming the zone and the URL within 30 s, resolved when it answers |
| `no-private-key-in-records` | no private-key material in the rendered manifests of both roles or in the record |
| `logs-queryable` | **pending**: the log store is an open point of ADR-0012; never reported passed until a store answers a query by pod and by `correlation_id` |

An alert counts only when it started after the failure was injected, so an alert left from an earlier
failure is never mistaken for the detection. The detection time is measured from the injection to
the alert seen in Alertmanager's API; one above 30 s fails its check.

`VERIFY_INJECT_FAULT=spire-lane-is-narrow` (an extra policy opening 8081 to the gateway) or
`VERIFY_INJECT_FAULT=other-egress-refused` (an extra egress to any address) opens the path the check
must find closed, to show the check fails.

## The record

`evidence.md` and `record.json` (checks, details, the transport, the clusters and each alert's
measured detection time), the rendered manifests of both roles (`render/`) and the run log go to
`ZTD_EVIDENCE_DIR`, or a new directory under
`${XDG_STATE_HOME:-$HOME/.local/state}/ztd/verify-observability/<context>/`, printed as the last line.
The repository holds no record of a run. Exit status: 0 when every check passed (pending ones are
listed, not counted), 1-124 the number of failed checks, 125 refused or not run.
