# ORCE chart

ORCE (the first-party image built from `deployment/docker/orce`) on the IONOS visualization
cluster. It replaces the interim `orce.yaml` manifest and keeps its names and its selector, so a
release can adopt the hand-installed objects (`--take-ownership`, once). `deploy-ionos.yml`
installs it from each release; the steps are in
[docs/environments/ionos.md](../../../docs/environments/ionos.md#3-orce).

| Renders | Contents |
|---|---|
| `Deployment/orce` | one replica, non-root, all capabilities dropped, RuntimeDefault seccomp; credentials from the existing Secret; runs as the existing ServiceAccount `orce` |
| `Service/orce` | port 1880 |
| `NetworkPolicy/orce-ingress` | admits port 1880 from pods of the release namespace and from the ingress controller's pods only |
| `Ingress/orce` | HTTPS on `ingress.host`, certificate from cert-manager (`ingress.clusterIssuer`) |

| Value | Default | Meaning |
|---|---|---|
| `image.repository` | `ghcr.io/eclipse-xfsc/facis-zero-trust-demonstrator/orce` | where the release workflow pushes the image |
| `image.digest` | — (required) | `sha256:…`; a tag is refused |
| `imagePullSecrets` | `[]` | docker-registry Secrets, for a private registry |
| `credentialsSecret` | `orce-credentials` | ORCE_ADMIN_USER, ORCE_ADMIN_PASSWORD_HASH, ORCE_HTTP_USER, ORCE_HTTP_PASSWORD_HASH, ORCE_READ_TOKEN; never rendered by the chart |
| `serviceAccountName` | `orce` | managed outside the chart; the BDD pool binds it as deployer |
| `ingress.host` | `orce.85-215-131-155.sslip.io` | **interim**: the sslip.io name of the IONOS load balancer, until the client's DNS name exists |
| `ingress.className` | `ztd-public` | the cluster's Traefik |
| `ingress.clusterIssuer` | `ztd-public-acme` | cert-manager ClusterIssuer |
| `ingress.tlsSecretName` | `orce-public-tls` | where cert-manager writes the certificate |
| `ingressController.namespace`, `.podLabels` | `ztd-edge`, `app.kubernetes.io/name: traefik` | the only pods outside the namespace that may reach ORCE |

**TLS 1.3.** The Ingress names no TLSOption, so Traefik applies its `default` TLSOption, which
`deployment/ingress/traefik-tls-options.yaml` sets to a TLS 1.3 minimum for every host it
terminates. The chart does not create a TLSOption: a second `default` would make Traefik drop both.

**Shared host.** On IONOS the interim host also routes `/dev` and `/dev/fscloud` to another
ORCE in `xfsc-orce-dev`. Traefik prefers the longer path, so those stay where they are and
everything else on the host reaches this ORCE.
