# trace-echo

A proof-only HTTP echo service instrumented with the OpenTelemetry Go SDK. It extracts the W3C
`traceparent` of each request, emits one server span as the child of the caller's span, and answers
with the trace id and span id it emitted. `scripts/verify-observability/verify.sh` runs it behind a
mesh proxy (`scripts/verify-observability/fixtures/trace-echo.yaml`) for the check
`correlated-trace`: one trace holds the proxy's span and the echo's child span. It is never installed
as part of a zone; the first real service follows the same pattern.

| Setting | Meaning |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP/HTTP endpoint of the zone gateway, e.g. `http://otel-gateway.ztd-mgmt.svc:4318` |
| `OTEL_SERVICE_NAME` | the service name of its spans |
| `LISTEN_ADDR` | listen address, default `:8080` |
| `SERVE_FILE` | `<url path>=<file>`: serve that file at that path instead of echoing (the proof's static server of the fixture status list, `scripts/verify-observability/fixtures/status-list.yaml`); no span |

```bash
go test ./tools/trace-echo/...
docker build --platform linux/amd64 -f deployment/docker/trace-echo/Dockerfile -t trace-echo .
```

The image is built, scanned and signed like the other images in `deployment/docker/`.
