# application-service

One application service as its own Helm release, outside the umbrella chart
([Application workloads](../../../docs/environments/application-workloads.md)). It creates a
Deployment by image digest, a Service, the service's own `NetworkPolicy` and, optionally, an ingress
route. It creates no cluster-scoped objects.

| Value | Meaning |
| --- | --- |
| `name` | Deployment and Service name; reached in the namespace as `<name>.<namespace>.svc` |
| `image.repository`, `image.digest` | The image, deployed by `sha256` digest only |
| `port`, `healthPath` | Container and Service port; HTTP path of both probes |
| `env` | The process environment as `NAME: value`; never secret values |
| `resources` | Defaults fit the OSC shared namespace's LimitRange |
| `networkPolicy.ingressFrom` | Peers allowed to reach `port`; empty denies all inbound traffic |
| `networkPolicy.egress` | Egress rules besides DNS; empty denies all other egress |
| `ingress.enabled`, `ingress.host`, `ingress.className` | Route through the ingress controller |
| `ingress.tlsSecret` | `kubernetes.io/tls` Secret for the host; empty serves the controller's default certificate |
| `ingress.basicAuthSecret` | Secret with an htpasswd `auth` key; the route then requires HTTP basic authentication |

Secrets the values name are created in the namespace by the deploying identity before the install.
The Participant and Protected Resource releases are recorded in
[Application service verification](../../../docs/application-services-verification.md).
