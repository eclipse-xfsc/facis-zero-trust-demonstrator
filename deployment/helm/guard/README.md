# M3 namespace guard

Standalone Envoy plus deployable ext_authz adapter and a real deny-default IF-05
evaluator. The adapter binds only loopback in the Envoy pod. Every `/demo` call
requires the Participant's mesh identity and a valid incoming DPoP token/proof,
then a policy allow and real token-store substitution. The guard records incoming
proofs in PostgreSQL through the store API before substitution. Failure of the
hook, verifier, policy or store refuses the request.

Public configuration is in ConfigMaps; image values contain digests only. The
scoped full-report and summary acquisition tenants must be distinct, configured
consistently in guard and token store, and issue matching upstream scopes. A
summary caller cannot select the full-report tenant. IF-03 fixture signing remains
an explicit demo dependency; policy decisions and authentication are not fixtures.

The chart provides STRICT mTLS and caller AuthorizationPolicies for guard,
policy evaluator and Resource, plus guard-only Resource ingress NetworkPolicy.
The Resource's application chart must have `networkPolicy.ingressFrom: []` or the
same guard-only rule. Remove any preliminary probe/Participant ingress policy:
Kubernetes policies combine their allowed traffic. Render the complete namespace
inventory to check no broader ingress policy defeats this one.

Guard and policy pods force `proxyHeaders.forwardedClientCert: SANITIZE_SET` and
URI certificate details; this is the inbound-sidecar API documented in the
[Istio proxy schema](https://github.com/istio/api/blob/master/mesh/v1alpha1/proxy.proto).
The namespace Envoy preserves that trusted sidecar header only to its local hook;
the hook removes it before upstream forwarding. Effective sidecar sanitization
and Resource mesh denial still require live probes. Do not expose this Envoy
without Istio injection, STRICT mTLS and these network/identity policies.

Supply admitted image overrides for every injected container through
`podAnnotations`, and explicit DNS/mesh control egress. Resource uses one replica.
Ops and Envoy admin are not exposed through Services. No global mesh
extensionProvider, admission exemption or trust-domain modification is required.

`ci/values.yaml` contains placeholders for rendering only. A render or local
integration test is not evidence of FACIS admission, mTLS or bypass refusal.
External Participant forwarding stays disabled until the live guard matrix passes.

On rollout failure, stop the external route and tear down the complete owned
slice or restore a proven guarded revision. Do not uninstall this chart while
leaving an externally reachable Resource: its authorization resources are part
of the security boundary. The full slice deployment/teardown remains a prerequisite.

The guard's `config.published_base_url`, the Protected Resource's public base URL,
and the token-store route `TargetPrefix` must be identical. Incoming Host must
match that configured authority. Envoy restricts its virtual host to this value
and rewrites the upstream Host to the resource Service's fully qualified name,
so Istio cannot route a substituted credential according to a caller-chosen Host.

Set `networkPolicy.istiod.enabled=true` for explicit TCP 15012 access to Istiod,
or supply the required mesh-control peers in `networkPolicy.egress`. Empty control
egress is rejected because the sidecar holds application startup. The participant
service-account value also identifies its application label for ingress policy.

## Audience boundary

Set `config.inbound_audience` to `https://guard.facis.invalid` and
`config.upstream_audience` to `https://resource.facis.invalid`, or supply two
distinct deployment-specific identifiers. Empty, equal, whitespace-containing or
legacy `config.audience` settings are refused. The policy evaluator receives the
verified inbound audience; only the substitution request uses the upstream one.
Audiences are claim identifiers, independent of the common published URL used for
DPoP target binding and the internal Service Host rewrite.

Register Participant clients only for the inbound audience and set
`PARTICIPANT_AUDIENCE` to it. Register each token-store route client only for the
upstream audience and use that audience in its acquisition and substitution
routes. Set `PROTECTED_RESOURCE_AUDIENCE` to the upstream audience. The
operator-only Connector registrar may provision both roles, but each registration
token must name only its registration endpoint and the intended client audience.
Neither workload receives registrar credentials or registration scope.

Replace existing broad client registrations before enabling the guarded path;
chart changes do not narrow existing database clients. Migrate both audience
settings, client registrations, Participant configuration, Resource verifier and
store routes together. There is no single-audience fallback. The files
`../application-service/ci/guarded-participant-values.yaml` and
`../application-service/ci/guarded-resource-values.yaml` are render-only examples.

A direct Resource call with a Participant token must fail audience verification
even with a valid DPoP proof. Keep mesh and network bypass controls as additional
boundaries. Local cryptographic proof does not establish live mesh enforcement.

Admission-labelled namespaces require the pinned Envoy image mirrored under
`ghcr.io/eclipse-xfsc/...`. The default uses that repository and a digest only;
the version tag is informational. Preserve the `ENVOY_IMAGE` manifest digest from
`scripts/tools/pins.env` and supply the required signatures/attestations before
deployment. The public chart gate checks the default digest against that pin.
