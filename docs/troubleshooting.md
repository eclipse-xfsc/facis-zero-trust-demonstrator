# Troubleshooting

Symptoms, causes and checks for the demonstrator.

## Reading a refusal

The demonstrator is built so that a refusal explains itself. Before debugging, read the denial: the
guard returns the layer and the rule that produced the decision, and the matching audit entry
carries the same reason code. A refusal with a reason is working as designed — the question is
whether the reason is the one you expected.

## Workload identity and mesh enrolment

| Symptom | Likely cause | Check |
|---|---|---|
| A pod starts but no traffic reaches it | It never received an SVID, so the mesh has no identity to route to | Look for a SPIRE registration entry matching the pod's service account; a missing entry is the answer, not a mesh problem |
| The SVID exists but the SPIFFE ID is wrong | The registration selector matches more, or less, than intended | Compare the SPIFFE ID in the workload's certificate with the selector that produced it |
| Traffic works between two pods that should not be able to talk | L7 enforcement is owned by neither component on that path, or by both | Check which component owns L7 for that path in the mesh configuration — [ADR-0009](adr/0009-service-mesh-mode-istio-sidecar-with-cilium.md) requires exactly one: where the sidecar enforces L7, Cilium is held to L3/L4 |
| The Istio CNI plugin never chains | Cilium claimed the CNI configuration exclusively | Confirm Cilium is installed with `cni.exclusive=false` |
| A meshed pod stays `Init:1/2`, its application container never starts, and its proxy holds no workload certificate | The pod has no SPIRE entry: it lacks the label `spiffe.io/spire-managed-identity: "true"`, or its namespace lacks the plane label, so the native sidecar never becomes ready under STRICT | `istioctl proxy-config secret <pod> -n <ns>` shows no `default` entry; the proxy logs `workload is not authorized for the requested identities ["default"]`; `spire-server entry show` lists no entry with `k8s:pod-uid:<pod uid>`. Add the label; never relax STRICT |
| The proxy has a `default` certificate but no `ROOTCA`, and every mTLS handshake fails validation | The SPIRE agent serves no resource under the name the proxy asks for its validation context: the SDS names of the `spire` release were changed | `istioctl proxy-config secret <pod>` lists `default` and no `ROOTCA`; the `spire-agent` ConfigMap must hold `sds` with `default_svid_name` `default`, `default_all_bundles_name` `ROOTCA` and `default_bundle_name` `null` ([the SDS contract](workload-identity.md#the-sds-contract)) |
| A pod is stuck in `ContainerCreating` with `MountVolume.SetUp failed for volume … csi.spiffe.io` | The SPIRE agent or the SPIFFE CSI driver is not Ready on that node, so the socket cannot be mounted yet | `kubectl -n spire-system get pods -o wide` for the agent and the CSI driver on the pod's node; the agent's log names an attestation failure (for example the server unreachable on 8081, which is the `identityServer` opening) |
| The umbrella refuses to render: `mesh.mode sidecar needs Cilium (cni.cilium.enabled)` | The zone file sets `cni.cilium.enabled: false` while the mesh runs, so the control-plane openings by entity cannot be rendered | The zone's CNI is not Cilium: a declared derogation of the preferred stack is needed before that zone is installed ([Workload identity](workload-identity.md#openings-under-the-default-deny)); on a Cilium cluster, correct the zone file |
| A `ClusterSPIFFEID` or `PeerAuthentication` is refused with `failed calling webhook … context deadline exceeded` | The API server cannot reach the webhook pod under the default deny | `cilium-dbg monitor --type drop` on the webhook pod's node shows the dropped SYN and its source identity; the `controlPlaneWebhooks` opening admits `kube-apiserver`, `host` and `remote-node` on the webhook port |
| The `istio-cni-node` pods crash with `couldn't initialize inotify: too many open files` (kind) | The host's inotify instance limit, shared by every kind node | `sysctl fs.inotify.max_user_instances`; raise it to 512 (`sudo sysctl -w fs.inotify.max_user_instances=512`), the value kind's known issues give |
| A pod in a plane namespace is refused with `ValidatingAdmissionPolicy 'proxy-takes-spire-socket' … denied request` | The pod names its own injection templates (`inject.istio.io/templates`), or has a mesh proxy (a container named `istio-proxy`, running the `proxyv2` image, or naming `pilot-agent`) that does not mount the SPIRE socket; that proxy would take a certificate from istiod's CA instead of SPIRE | The message names which rule refused it. Remove the annotation, any `istio-proxy` override and any container of your own that runs `proxyv2` or `pilot-agent` from the pod template; the default injection already carries the socket ([the proxy](workload-identity.md#the-proxy)) |
| A pod in a plane namespace is refused with `ValidatingAdmissionPolicy 'proxy-takes-spire-socket' … denied request: capture rule` | The pod's capture annotations differ from the injector's defaults, or it carries an outbound or interface exclusion, `status.sidecar.istio.io/port`, `proxy.istio.io/config`, a proxy image, bootstrap or volume annotation, `proxy.istio.io/overrides` (its own `istio-proxy` container), or, in a namespace with the injection label, the injection opt-out `sidecar.istio.io/inject` (annotation or label); any of these would let traffic reach or leave the application outside its proxy, or replace the proxy | First, if every injected pod is refused, the two status ports differ: `zone-policy` `proxySocketPolicy.statusPort` must equal `istiod` `global.proxy.statusPort` (both `15020` by default). Otherwise remove the capture and proxy annotations and the opt-out from the pod template; an exception is declared mesh-wide in the charts, never per pod ([the capture rule](workload-identity.md#the-capture-rule)) |
| A pod in a plane namespace is refused with `ValidatingAdmissionPolicy 'proxy-takes-spire-socket' … denied request: proxy rule` | A mesh proxy of the pod is not the injector's `istio-proxy`: a second proxy under another name, a proxy in a namespace without the injection label, another image, a command, arguments other than the injector's, `envFrom`, an environment variable the injector does not write (such as `ISTIO_BOOTSTRAP_OVERRIDE`) or one at another value (`PROXY_CONFIG` other than `{}`), a volume mount the injector does not write, or a lifecycle hook, probe or `securityContext` other than the injector's (including `sidecar.istio.io/capNetBindService: "true"`, which runs the proxy as root) | First, if every injected pod is refused, the two proxy images differ: `zone-policy` `proxySocketPolicy.proxyImage` must equal `istiod` `global.proxy.image` (`scripts/install-zone/install.sh` refuses such a zone before it installs). Otherwise remove the pod's own proxy container, `proxyv2` or `pilot-agent` container, or a pre-set `sidecar.istio.io/status` annotation ([the capture rule](workload-identity.md#the-capture-rule)) |
| `install-zone: the zone file sets mesh.revision "<revision>"` (or `mesh.mode "<mode>"`), `but this installer installs the default, unrevisioned istiod in sidecar mode only`, and nothing is rendered or installed | The zone file asks for a revisioned mesh or for a mode other than sidecar (ambient, or `none`), which `scripts/install-zone/install.sh` does not install; the umbrella would otherwise label the plane namespaces for an injector that never comes | Set `mesh.mode: sidecar` and remove `mesh.revision` from the zone file; a zone without a mesh (`none`, such as the IONOS zone) installs the umbrella alone through `scripts/lifecycle.sh`, not through the installer ([install-zone](https://github.com/eclipse-xfsc/facis-zero-trust-demonstrator/tree/main/scripts/install-zone)) |
| The `zone-policy` release fails at an identity check | The check's job names what is missing: the server or an agent not Ready, no bundle, a trust domain that differs from the zone file, or a labelled pod without an entry | `kubectl -n istio-system logs job/zone-policy-<check>`; the failed job is kept for an hour |

## Admission control rejections

| Symptom | Likely cause | Check |
|---|---|---|
| An image will not start and the event is generic | Gatekeeper refused it but the reason did not reach the event | Read the provider's decision, which carries the reason code; a refusal with no reason code is a defect in the provider |
| A correctly signed image is refused | The verification key does not match the key the image was signed with | Compare the signing key used by the pipeline with the key material the provider was configured with |
| An unsigned image starts | The constraint is not bound to that namespace, or the provider is not reachable | Confirm the constraint's scope, then confirm the provider answers — an unreachable provider must fail closed, not open |

## Token issuance, DPoP proofs and the token store

| Symptom | Likely cause | Check |
|---|---|---|
| Registration succeeds but no token is issued | The presentation did not verify, so there is nothing to derive a token from | Read the verification outcome first; the token failure is downstream of it |
| A token is rejected on use | The DPoP proof is not bound to the key that requested the token, or is being replayed | Compare the proof's key thumbprint with the one recorded at issuance |
| The upstream call carries the caller's own token | Substitution did not happen | Trace the outbound request — the caller's proof must never be forwarded onward |
| Everything fails after a control-plane blip | The token store failed closed, as designed | Confirm the alert was raised; fail-secure is the correct behaviour, silence is not |

## Attested channel handshake failures

| Symptom | Likely cause | Check |
|---|---|---|
| The handshake aborts | The peer's measurement does not match the expected value | Compare the report's measurement with the expected value resolved from TRAIN; a mismatch is a working refusal |
| The handshake aborts and the expected value is absent | The trust-list entry is missing or stale, not the peer | Resolve the peer's digest through TRAIN directly before suspecting the peer |
| The report verifies but the channel is refused | The evidence is not bound to this connection | Confirm the TLS exporter value is present in the report's user data — an unbound report is a replay risk, so refusal is correct |
| Application traffic appears after a failed handshake | A serious defect | This must be impossible and is asserted by an acceptance scenario; treat any instance as a stop-the-line finding |

## Credential verification and trust-list staleness

| Symptom | Likely cause | Check |
|---|---|---|
| A credential that worked yesterday is refused | It was revoked | Check the status list entry before anything else |
| Verification fails for every credential at once | The status list or the trust anchor is unreachable | Check reachability; an unreachable list must deny, and the alert tells you which one it was |
| A peer that should be trusted is not listed | The trust list has not been republished since the peer was added | Compare the published trust list with what the connector resolved, not with what you expect it to contain |

## Deployment lifecycle and the acceptance scenarios

Met while building and running the lifecycle pack (TDR-BDD-01..06) on kind and IONOS.

| Symptom | Likely cause | Check |
|---|---|---|
| A scenario fails before it starts with "the pool namespace is not in its baseline state" | A previous run was interrupted and left a release or objects behind | `kubectl -n <pool namespace> get all,secrets`; uninstall the leftover release through ORCE (an `uninstall` command), not by hand, then rerun |
| `cluster-state.sh` exits 2, "the cluster could not be observed" | The observer kubeconfig is wrong, expired or points at another cluster; API errors are never retried into a pass | `kubectl --kubeconfig <observer> auth whoami`, then `get namespace kube-system` — the UID must be the target's |
| The lifecycle result says `valuesSchemaRejected` for a release you expect to be valid | Its values fail the chart's `values.schema.json`; that is the refusal TDR-BDD-02 relies on | `helm template <chart> -f <values>` locally shows the schema error |
| ORCE starts with the upstream demo flows instead of the lifecycle flow | An old or upstream image: the upstream image sets `FLOWS=flows.json` | The first-party image fixes `flowFile` to `lifecycle.json`; the ORCE log's `Flows file` record must name `/data/lifecycle.json` |
| ORCE refuses to start: "must be set: ORCE does not start without its credentials" | A key of the `orce-credentials` Secret is missing | Compare the Secret's keys with [the ORCE install](environments/ionos.md#3-orce) |
| The ORCE context read returns 401 | The read token is wrong, or it was sent without `Bearer ` | The read token is the `ORCE_READ_TOKEN` of the Secret; it can read, never write |
| No JSON refusal record for a request in the ORCE log (rows 02 and 06) | An image without the JSON log handler, or the log command reads another pod | Every line of `kubectl -n ztd-orce logs deployment/orce` must be one JSON object ([ORCE logging](flows.md#orce-logging)) |
| ORCE is slow to start on an Apple Silicon machine | The image is `linux/amd64` only and runs emulated | Expected locally; allow a few minutes |
| `helm` commands behave differently from the docs | Another Helm major version | The project pins Helm v4.3.0 for chart QA and inside the ORCE image |

## Logs

Records sent through the ORCE logging API are one JSON object per line
([ORCE logging](flows.md#orce-logging)); output outside that API is not. The Go services'
logging convention is set with the observability stack (ZT-27). Correlate by the request identifier
carried across hops rather than by timestamp.
