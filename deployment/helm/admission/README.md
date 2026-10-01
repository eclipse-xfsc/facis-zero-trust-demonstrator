# admission

The image-verification provider for Gatekeeper external data
([services/admission-provider](../../../services/admission-provider)). Gatekeeper calls it for every
image a constrained workload uses; it answers, per image, `verified` or the admission reason code
(`ADM-*`, [reason-codes.json](../../../docs/contracts/reason-codes.json)) of the first check that
failed: digest reference, allowed repository, cosign signature by a trusted key, SBOM attestation,
mock attestation.

Install order: Gatekeeper, then this chart (the `Provider` kind comes from Gatekeeper's CRDs), then
the constraints. The chart installs into Gatekeeper's namespace and refuses any other.

## Gatekeeper prerequisite: no response cache

Gatekeeper caches provider answers for three minutes by default. With that cache on, a `verified`
answer keeps admitting an image for up to three minutes after its key or repository is removed from
the trust policy. The provider keeps its own cache, keyed on the trust policy's revision and emptied
when the policy changes, so Gatekeeper's cache must be off. Install Gatekeeper with:

```yaml
externaldataProviderResponseCacheTTL: 0s
```

and check the running controller before installing this chart:

```bash
kubectl -n gatekeeper-system get deploy gatekeeper-controller-manager \
  -o jsonpath='{.spec.template.spec.containers[0].args}' | tr ',' '\n' | grep response-cache-ttl
# expected: --external-data-provider-response-cache-ttl=0s
```

## What it installs

| Object | Purpose |
|---|---|
| `Deployment`/`Service` `ztd-admission-provider` | the provider: HTTPS on 8443 (TLS 1.3 only, client certificate required), metrics and health on 9090 |
| `Secret` `ztd-admission-provider-tls` | the provider's own CA and server certificate, generated on first install and kept on upgrade |
| `ConfigMap` `ztd-admission-provider-trust` | the trust policy, one `policy.json`: allowed repository prefixes and trusted cosign public keys, read together so an update is never half applied |
| `Provider` `ztd-image-verifier` | Gatekeeper's pointer to the provider, with the provider CA as `caBundle` |

The provider trusts only client certificates that chain to the CA of Gatekeeper's webhook
certificate Secret; it mounts that Secret's `ca.crt` and nothing else from it. It re-reads its TLS
material, Gatekeeper's CA and the trust policy every 10 s, so a rotation or a trust change applies
without a restart and empties the verification cache. An invalid trust policy is not replaced by the
previous one: the provider answers with a system error, which the constraints deny, until it is fixed.
It runs as a non-root user with a read-only root filesystem and no service account token.

## Values

| Value | Default | Meaning |
|---|---|---|
| `image.repository` | `ghcr.io/eclipse-xfsc/facis-zero-trust-demonstrator/admission-provider` | provider image |
| `image.digest` | — (required) | `sha256:` digest; the chart refuses a tag |
| `replicas` | `2` | provider replicas |
| `gatekeeper.namespace` | `gatekeeper-system` | Gatekeeper's namespace; must equal the release namespace |
| `gatekeeper.certSecret` | `gatekeeper-webhook-server-cert` | Gatekeeper's webhook certificate Secret (its `ca.crt` is the client CA) |
| `provider.name` | `ztd-image-verifier` | name of the `Provider` the constraints refer to |
| `provider.timeoutSeconds` | `2` | Gatekeeper's deadline for a provider call |
| `requestTimeout` | `1s` | the provider's own deadline; an image not verified by then is answered `ADM-PROVIDER-DOWN` |
| `trust.repositories` | — (required) | allowed repository prefixes, `host/path` |
| `trust.publicKeys` | — (required) | trusted cosign public keys, PEM (ECDSA P-256) |
| `tls.validityDays` | `825` | validity of the generated CA and server certificate; delete the Secret and upgrade to rotate |
| `insecurePlainHTTPRegistry` | `""` | a plain-http test registry (`host:port`); empty in any real deployment |

## Metrics

`/metrics` on port 9090: `ztd_admission_verdicts_total{code}`, `ztd_admission_cache_hits_total`,
`ztd_admission_cache_misses_total`, `ztd_admission_system_errors_total` and the histogram
`ztd_admission_request_duration_seconds`.
