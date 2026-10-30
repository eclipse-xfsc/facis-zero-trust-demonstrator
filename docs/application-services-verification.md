# Application service verification

What was checked for the [Participant and Protected Resource services](application-services.md), and
where they currently run. These are sample application checks: they show that the services build,
deploy, start and answer. They are not evidence for authorization, credential revocation, scope
enforcement, attestation or any zero-trust acceptance row.

## Source checks

| Check | Result |
| --- | --- |
| `go build ./cmd/participant ./cmd/protected-resource` | Pass |
| `go test ./services/participant/... ./services/protectedresource/...` | Pass |
| `go vet` and `golangci-lint` v2.13.2 on the module | Pass, 0 issues |
| Images built by the release workflow, `linux/amd64`, signed with the interim key | Pass |

## Shared OSC namespace — 10 October 2026

Installed into namespace `zero-trust` on the shared OSC cluster with the namespace's service account,
one `deployment/helm/application-service` release per service.

| Release | Image | Reached at |
| --- | --- | --- |
| `protected-resource` | `ghcr.io/fune5tiatlas/facis-zero-trust-demonstrator/protected-resource@sha256:4e1d926f22ae0c6207810ccbe8788af0ecbc5aad7b3ceb28a1e00ac4b0adc325` | `http://protected-resource.zero-trust.svc.cluster.local:8086`, in the namespace only |
| `participant` | `ghcr.io/fune5tiatlas/facis-zero-trust-demonstrator/participant@sha256:0c0048b89ce945acac4be8e243c4e2b90be820a24b6622d6d30892eb7bca4286` | `http://participant.zero-trust.svc.cluster.local:8085` in the namespace; `https://participant.zero-trust.160-44-12-115.sslip.io` through the shared ingress, with HTTP basic authentication |

Effective settings: Participant `http-sample`, 5 s request timeout, Resource URL as above; Resource
`sample` mode and adapter, 5 s request timeout, 2 s slow delay; log level `info` on both.

| Check | Result |
| --- | --- |
| Both pods ready, health probes on `/health` | Pass |
| `scripts/smoke-application-services.mjs` against both Services (port-forward) | Pass, 12 checks |
| Ingress without credentials | `401` |
| Through the ingress: success, denied, unavailable, error, slow | `200`, `403`, `503`, `502`, `200` after 2.3 s |
| The same `requestId` and `correlationId` in both services' JSON logs | Pass |

Not in place on this route: the ingress serves the controller's self-signed certificate and accepts
TLS 1.2 ([Application workloads](environments/application-workloads.md)); the namespace's allow-all
policies widen each release's own network policy.
