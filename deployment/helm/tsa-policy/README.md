# TSA policy service

The XFSC TSA policy service (eclipse-xfsc/custom-policy-agent v1.1.4, pinned by digest) as the
guard's decision engine, with the `tsa-bundle` sidecar that verifies signed Rego bundles before the
TSA loads them and activates the one Git declares without a restart. Design, publishing and
rollback: [docs/tsa-policy.md](../../../docs/tsa-policy.md).

One pod, `tsa-policy-engine`: NATS and a git daemon as loopback-only native sidecars (the TSA needs
both at start-up), the TSA on `127.0.0.1:8081`, and the bundle sidecar on port 8080, which forwards
only `POST` of the configured policy's evaluation path. The TSA starts empty: until a verified bundle
is active every evaluation fails and the pod is not ready.

## Values

| Value | Meaning |
|---|---|
| `images.*` | repository and digest of each container; digests only. `tsa` and `nats` default to the pinned upstream digests under the `ghcr.io/eclipse-xfsc/...` mirror (`scripts/tools/pins.env`, checked by the chart gate); `git` and `bundle` are built from `deployment/docker/` and must be set |
| `bundle.ref`, `bundle.revision` | the active bundle: a digest reference printed by `scripts/supplychain/publish-tsa-bundle.sh` and its revision; changed by pull request only |
| `bundle.repository` | the only repository bundles are accepted from |
| `bundle.plainHTTPRegistries` | registries reached over http (a local test registry only) |
| `bundle.pollSeconds` | how often the sidecar compares the TSA with the declaration |
| `trustRoot` | the PEM key every bundle and bundle artefact must be signed with; default the interim signing key |
| `policy` | the policy's TSA coordinates; the guard's is `policies/facis/guard/1.0`. The version names only the path served to the adapters: each bundle is stored under its revision and the sidecar forwards to the active one |
| `trustDomain`, `callers` | the IF-05 adapters allowed to evaluate (`{namespace, name}`; `name` is the service account and the pods' `app.kubernetes.io/name`) |
| `networkPolicy.istiod`, `networkPolicy.egress` | mesh-control egress and the egress to the bundle registry; without registry egress no bundle is fetched and every evaluation fails closed |

Changing `bundle.*` changes only the `tsa-policy-bundle` ConfigMap, which carries no checksum onto the
pod: the running sidecar picks it up (the kubelet refreshes the file within about a minute). The
chart gate renders two declarations and fails if anything in the pod template differs. Changing
anything else changes `tsa-policy-config` and restarts the pod, which then fails closed until it has
imported the declared bundle again.

The chart provides STRICT mTLS, an AuthorizationPolicy admitting only the callers' principals to
`POST` the evaluation path, and a NetworkPolicy admitting only the callers' pods on 8080 with DNS,
optional istiod and the configured egress out. Point the guard chart at it with
`tsa.evaluationURL=http://tsa-policy-engine.<namespace>:8080/policy/policies/facis/guard/1.0/evaluation`
and the matching `networkPolicy.egress`.

`ci/values.yaml` holds render-only placeholders. Admission-labelled namespaces need every image
mirrored or built and signed first; the local proof is `scripts/verify-tsa-policy/verify.sh`.
