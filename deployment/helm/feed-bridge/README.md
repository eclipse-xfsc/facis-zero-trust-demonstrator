# Feed bridge

The IF-01 feed bridge (`cmd/feed-bridge`, docs/api-docs.md: IF-01, feed bridge) in the mesh. It
authenticates nobody itself, so this chart is its access control: STRICT mTLS on its pod, an
AuthorizationPolicy admitting only the UI's identity (`ui.namespace`, `ui.serviceAccount`) to the
feed (`GET /snapshot`, `/events`, `/v2/snapshot`, `/v2/events`) and only the `producers` to
`POST /ingest`, and a network policy limiting ingress to those namespaces on 8090. `trustDomain` is
the zone's. The image carries the IF-01 event schemas it validates every line against.

| Value | Meaning |
|---|---|
| `image.repository`, `image.digest` | the bridge image (`deployment/docker/feed-bridge`), by digest |
| `trustDomain` | the zone's SPIFFE trust domain |
| `ui.namespace`, `ui.serviceAccount` | the one identity admitted to the feed |
| `producers` | `[{namespace, serviceAccount}]` admitted to `/ingest` |
| `budgetBytes` | the bytes of event lines all runs together keep (runs beyond are answered 410) |
| `podAnnotations` | native sidecar by default; `proxy.istio.io/config` is refused |
| `networkPolicy.istiod` | the egress to istiod's xDS and CA port |

`scripts/verify-guard-catalogue/verify.sh` installs it on kind and proves that the UI's identity reads
the feed while the Participant's identity is refused by the bridge's sidecar.
