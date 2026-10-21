# zone-policy — the identity policy of one zone

The one project chart of the identity path, and the last of the seven releases of a zone
(`scripts/install-zone/install.sh`), because it uses the CRDs the SPIRE and Istio releases own. It
installs into `istio-system`, the mesh root namespace:

- **`ClusterSPIFFEID` `plane-workloads`**: the registration by selector. Every pod with
  `spiffe.io/spire-managed-identity: "true"` in a namespace that carries the umbrella's plane label
  gets `spiffe://<trust domain>/ns/<namespace>/sa/<service account>`. A regular resource that the
  SPIRE controller-manager reconciles into entries, never a hook.
- **`PeerAuthentication` `default`** in `istio-system`: mesh-wide mutual TLS in `STRICT` mode, so a
  workload without a SPIRE entry has no mesh connection.
- **`ValidatingAdmissionPolicy` `proxy-takes-spire-socket`** and its binding: in every namespace
  with the plane label, a pod may not choose its injection templates (`inject.istio.io/templates`),
  and every mesh proxy of a pod (a container, init container or ephemeral container named
  `istio-proxy`, running the `proxyv2` image, or naming `pilot-agent`; the injector's
  `istio-validation` init container aside) must mount the `csi.spiffe.io` volume `workload-socket`
  at `/var/run/secrets/workload-spiffe-uds`. Without it a pod could drop the `spire` injection
  template, or run Istio's agent under another name, and that agent would take a certificate from
  istiod's CA, which stays on because it also signs istiod's own serving certificates. Evaluated
  after injection, on pod creation, pod updates and ephemeral containers; pods without a proxy are
  not concerned by this socket rule (STRICT leaves them outside the mesh), but the capture rule
  below refuses them. A program without these marks can still ask istiod's CA for a certificate;
  no peer trusts it (docs/workload-identity.md, "The proxy").
  The same policy holds **the capture rule** and **the proxy rule** (see below).
- **The identity-band checks**: three post-install and post-upgrade Jobs in the `identity` band of
  the hook-weight scheme (`templates/_hooks.tpl` is a copy of the umbrella's helper). They only read,
  through the Kubernetes API, with a read-only ServiceAccount, and a failure fails the release:

| Job | Weight | Fails the release when |
|---|---|---|
| `server-healthy` | 20 | the SPIRE server's StatefulSet is not Ready (its readiness probe is the server's health endpoint) or an agent is not Ready |
| `trust-bundle-published` | 25 | the server has published no X.509 authority in `spire-bundle`, or the controller-manager or the mesh runs with another trust domain than `trustDomain` |
| `registrations-reconciled` | 30 | the controller-manager reports an entry or render failure, a selected pod without its entry, or fewer selected pods than the running labelled pods of the plane namespaces |

Each check waits up to `checks.timeoutSeconds` for its condition. A failed job is kept for an hour
so that its log can be read; a successful one is removed by the hook delete policy.

The design is in [docs/workload-identity.md](../../../docs/workload-identity.md).

## The capture rule

The Istio CNI plugin builds each injected pod's redirect rules from the pod's capture annotations.
A registered pod annotated `traffic.sidecar.istio.io/excludeInboundPorts: "8080"` has that port
delivered to the application outside its proxy: the mesh-wide `STRICT` policy never sees the
connection, and an unregistered pod of the same namespace reaches it in plaintext. The third
validation of `proxy-takes-spire-socket` therefore pins the capture, in every namespace with the
plane label:

- The injector writes four capture annotations onto **every** pod it injects, and the policy runs
  after the injector, so it cannot refuse their presence; it compares their values with the
  injector's defaults instead. A pod is admitted only when each of them that it carries equals:

  | Annotation | Required value |
  |---|---|
  | `sidecar.istio.io/interceptionMode` | `REDIRECT` (not `NONE`, not `TPROXY`) |
  | `traffic.sidecar.istio.io/includeInboundPorts` | `*` |
  | `traffic.sidecar.istio.io/excludeInboundPorts` | the status port alone, `proxySocketPolicy.statusPort` (`15020`) |
  | `traffic.sidecar.istio.io/includeOutboundIPRanges` | `*` |

- These are refused whenever present: the optional capture annotations
  `traffic.sidecar.istio.io/excludeOutboundIPRanges`, `includeOutboundPorts`,
  `excludeOutboundPorts`, `excludeInterfaces`, `kubevirtInterfaces` and
  `istio.io/reroute-virtual-interfaces`; `status.sidecar.istio.io/port`, which moves the status
  port and so excludes an application port without naming `excludeInboundPorts`;
  `proxy.istio.io/config`, which can point the proxy at another discovery server;
  `sidecar.istio.io/proxyImage`, `sidecar.istio.io/bootstrapOverride`,
  `sidecar.istio.io/userVolume` and `userVolumeMount`, which swap the proxy's image, replace its
  bootstrap or mount the pod's volumes into it; and `proxy.istio.io/overrides`, which the injector
  writes when the pod brings its own `istio-proxy` container and merges it over the injected one.
  The injector writes none of these on a pod that does not ask for them.
- The injection opt-out `sidecar.istio.io/inject`, as an annotation or a label and whatever its
  value, is refused in a namespace with the injection label (`istio-injection` or `istio.io/rev`),
  because a pod without a proxy there is reachable in plaintext like an excluded port. The plane
  namespaces the zone file declares `mesh: false` (`istio-system`, `spire-system`) carry no
  injection label, and istiod and the `istio-cni` node agents, which opt out of injection, are
  admitted there, so their controllers can recreate them. The umbrella writes the injection label
  from the plane entry's `mesh` field and its verification hook checks it; every other clause
  applies in those namespaces too.

**The proxy rule** (fourth validation): every mesh proxy must be the injector's own. A proxy of
another image, or a second `proxyv2` container with its own `--templateFile`, `PROXY_CONFIG` or
bootstrap, that mounts the SPIRE socket would pass the socket rule and could accept plaintext on the
inbound capture port, and `proxy.istio.io/overrides` does not catch every path (a pod that arrives
with `sidecar.istio.io/status` already set has its own `istio-proxy` merged over the injected one
without the annotation). So a mesh proxy is admitted only:

- in a namespace with the injection label (none in a `mesh: false` plane namespace, where nothing is
  injected), and only under the name `istio-proxy`, so there is no second proxy under another name;
- with the image `proxySocketPolicy.proxyImage` and no command;
- with the arguments the 1.31.1 injector writes: `proxy sidecar --domain
  $(POD_NAMESPACE).svc.<cluster domain>`, the three log-level flags, and only `--stsPort`,
  `--log_as_json` or `--outlierLogPath` besides;
- with no `envFrom`, only the environment variables the injector writes, `PILOT_CERT_PROVIDER`,
  `CA_ADDR`, `ISTIO_META_INTERCEPTION_MODE` and `TRUST_DOMAIN` at the injector's values, and
  `PROXY_CONFIG` an empty object (the zone sets no per-pod proxy configuration, so the injector
  writes `{}`; `ISTIO_BOOTSTRAP_OVERRIDE` is not among the allowed names);
- with only the injector's volume mounts, each at the injector's path, and the service-account
  token, none with `subPath`, `subPathExpr` or mount propagation, over volumes of the injector's
  kinds: the SPIRE socket a `csi.spiffe.io` volume, `istio-podinfo` the downward API, `istio-token`
  a projected service-account token and nothing else, `istiod-ca-cert` and `istio-ca-crl` their
  configMaps (`istio-ca-root-cert`, `istio-ca-crl`), `istio-envoy`, `istio-data`,
  `credential-socket` and `workload-certs` `emptyDir` (on an injected pod the injector's template
  owns these volumes; the pin matters where the injector does not run);
- with the injector's lifecycle: none, or `exec [pilot-agent, wait]` as `postStart` (when
  `holdApplicationUntilProxyStarts` is on) and `exec [pilot-agent, request,
  --debug-port=<status port>, POST, drain]` as `preStop` (native sidecars), so no command of the pod
  runs in the proxy container as UID 1337;
- with the injector's probes: no liveness probe, and the startup and readiness probes, when present,
  `httpGet /healthz/ready` on `15021` with no host (their timings follow the
  `readiness.status.sidecar.istio.io/*` annotations and stay free);
- with the injector's `securityContext`: `runAsUser` and `runAsGroup` 1337, `runAsNonRoot`, no
  privilege escalation, not privileged, read-only root filesystem, capabilities `drop: [ALL]` and
  none added, and no `seLinuxOptions`, `seccompProfile`, `appArmorProfile`, `procMount` or
  `windowsOptions`. `sidecar.istio.io/capNetBindService: "true"`, with which the injector runs the
  proxy as root with `NET_BIND_SERVICE`, is therefore refused.

The allowed environment variables (`proxyEnv`) are the ones the 1.31.1 injector writes for this
zone, from the template and from its code after the template: `ISTIO_KUBE_APP_PROBERS` when it
rewrites an application's probes, and `ISTIO_PROMETHEUS_ANNOTATIONS` when a pod carries
`prometheus.io/*` annotations (the mesh sets `enablePrometheusMerge`). Variables it writes only
under settings the zone does not make (`COMPLIANCE_POLICY`, `GODEBUG`, `ISTIO_META_NETWORK`, the
datadog tracer's, `meshConfig.defaultConfig.proxyMetadata` keys) are refused; the change that makes
such a setting extends `proxyEnv`.

**Updates.** The policy also runs on every pod update (a label, a finalizer, an image, an added
ephemeral container) and on every update of `pods/status`, which can change a pod's annotations and
labels as well (the agent rereads its annotations from the downward-API file `istio-podinfo`
whenever the proxy restarts, and the CNI plugin reads them when the pod's sandbox is recreated).
The capture and proxy rules look only at what the update changes: an annotation or label whose
value is unchanged, and a container whose name and image are unchanged (nothing else of an existing
container can change), is not checked again, so a pod admitted before an Istio upgrade still takes
metadata updates while its proxy runs the previous image. A changed image or a new ephemeral proxy
is checked in full. An update may not remove `sidecar.istio.io/status` or one of the four capture
annotations the injector wrote, nor change `sidecar.istio.io/status`: the CNI plugin sets up no
redirect for a pod without the status annotation the next time it runs for the pod. The template
and socket rules, which do not depend on the Istio version, check the whole pod on every pod
update; they do not run on a status update, which cannot change the pod's spec, so the kubelet's
and the controllers' status updates are never refused by them.

An ordinary pod satisfies both rules with exactly what the injector writes. A workload that needs a
capture exception or a proxy setting gets it mesh-wide through the charts (for example
`meshConfig.defaultConfig`) in its own change, never through a pod annotation. The rule does not
cover what bypasses the capture without an annotation: capture is iptables inside the pod's
network namespace, so a host-networked pod or a container with `NET_ADMIN` steps around it, and the
redirect rules let UID and GID 1337, the proxy's own, leave without capture, so an application
container running as 1337 (by its `securityContext` or its image's `USER`) sends its outbound
traffic past the proxy. The injector also skips host-networked pods, so such a pod could bring its
own `istio-proxy` with its own environment. Those belong to a Pod Security level on the plane
namespaces with a `runAsUser`/`runAsGroup` rule, the follow-up change. Under the mesh's
`enablePrometheusMerge`, the proxy's agent fetches the metrics path a pod names in its
`prometheus.io/*` annotations from the application and serves it on the status port, which is
outside the capture: that one path is readable in plaintext, as on any Istio sidecar with the merge
on. The probe rewrite (`ISTIO_KUBE_APP_PROBERS`, on by default) does the same for every `httpGet`
probe of an application container: the agent fetches the probe's path from the application and
serves it on the status port as `/app-health/<container>/livez`, `readyz` or `startupz`, readable
in plaintext by any pod of the namespace. The variable is not pinned: a pod chooses its own probe
paths and the injector writes whatever they are, so a probe path must reveal nothing beyond health.
Two more things stay open for the Pod Security follow-up: the proxy's other environment values
(`ISTIO_META_CLUSTER_ID`, `ISTIO_META_NODE_NAME`, `ISTIO_META_WORKLOAD_NAME`, `ISTIO_META_OWNER`,
`OTEL_RESOURCE_ATTRIBUTES`, also through `valueFrom`) are not pinned; they change how istiod files
and labels the proxy (registry lookup, telemetry), not its certificate, which SPIRE issues for the
pod's service account. And an ephemeral container that targets `istio-proxy`, or
`shareProcessNamespace`, lets another container (as root, or as UID 1337) reach the proxy's process.

**Status-port coupling.** `proxySocketPolicy.statusPort` must equal the `istiod` release's
`global.proxy.statusPort`, which `deployment/helm/values/istiod.yaml` leaves at Istio's default,
`15020`. If the two differ, the injector writes a different exclusion than the policy expects and
every injected pod in a plane namespace is refused: the symptom is loud on purpose, rather than an
application port silently excluded.

**Proxy-image coupling.** `proxySocketPolicy.proxyImage` must equal the `istiod` release's
`global.proxy.image` in `deployment/helm/values/istiod.yaml`, the whole reference with its digest.
If the two differ, every injected pod in a plane namespace is refused by the proxy rule; an Istio
upgrade changes both. `scripts/install-zone/install.sh` refuses to render or install a zone whose
two proxy images or two status ports differ, and CI runs that check with every render.

## Values

| Key | Default | Meaning |
|---|---|---|
| `trustDomain` | none, required | The zone's trust domain, `zone.trustDomain` of the zone file (the installer fills it) |
| `spire.namespace` | `spire-system` | Where the `spire` release runs |
| `spire.className` | `spire-system-spire` | The controller-manager's class: `<release namespace>-<release name>` of the `spire` release |
| `spire.serverStatefulSet`, `spire.agentDaemonSet` | `spire-server`, `spire-agent` | Read by `server-healthy` |
| `spire.bundleConfigMap`, `spire.controllerManagerConfigMap` | `spire-bundle`, `spire-controller-manager` | Read by `trust-bundle-published` |
| `mesh.namespace`, `mesh.configMap` | `istio-system`, `istio` | The mesh root namespace and the mesh configuration |
| `registration.name` | `plane-workloads` | Name of the `ClusterSPIFFEID` |
| `registration.identityLabel` | `spiffe.io/spire-managed-identity: "true"` | The switch a workload carries to get an identity |
| `registration.planeLabel` | `ztd.facis.io/plane` | The umbrella's plane label; namespaces that carry it are selected |
| `peerAuthentication.mode` | `STRICT` | The only value accepted |
| `proxySocketPolicy.name` | `proxy-takes-spire-socket` | Name of the admission policy and its binding |
| `proxySocketPolicy.volume`, `proxySocketPolicy.mountPath`, `proxySocketPolicy.driver` | `workload-socket`, `/var/run/secrets/workload-spiffe-uds`, `csi.spiffe.io` | The volume, mount path and CSI driver every mesh proxy must have; those of Istio's `sidecar` template and the istiod values file |
| `proxySocketPolicy.statusPort` | `15020` | The proxy's status port, the one inbound port the capture rule lets the injector exclude; must equal the `istiod` release's `global.proxy.statusPort` (integer, required) |
| `proxySocketPolicy.proxyImage` | `docker.io/istio/proxyv2:1.31.1@sha256:d86c…` | The injected proxy's whole image reference, by digest; the proxy rule admits no other image for a mesh proxy; must equal the `istiod` release's `global.proxy.image` (string, required) |
| `checks.enabled` | `true` | The identity-band jobs |
| `checks.image` | `curlimages/curl` by digest | Image of the jobs (the umbrella's verification image) |
| `checks.timeoutSeconds` | `180` | How long each check waits before it fails the release |

`ci/values.yaml` is the kind zone, the file the CI chart job renders with.

```bash
helm lint deployment/helm/zone-policy -f deployment/helm/zone-policy/ci/values.yaml
helm template zone-policy deployment/helm/zone-policy -n istio-system \
  -f deployment/helm/zone-policy/ci/values.yaml
```
