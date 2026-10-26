# T-Systems Open Sovereign Cloud — zone A and zone B

The two demonstration zones. Zone A holds the participant backend that makes the call; zone B holds
the protected resource it calls. Each is a separate cluster with its own workload identity,
admission control and policy enforcement, and the interesting part of the demonstrator is what
happens between them.

!!! warning "Cluster not yet provided"
    The two OSC clusters have not been provided yet (status of 23 September 2026). This page is
    written from the platform baseline and the decisions that govern it; nothing on it has been run
    against a real OSC cluster. Every step says how it will be verified, and the page is confirmed
    against the clusters on first stand-up, as the [IONOS guide](ionos.md) already is.

## Before you start

You need:

- a kubeconfig for each of the two OSC clusters, with rights to create namespaces and
  cluster-scoped resources;
- credentials for the container registry the images are pulled from, and network reachability to it
  from both clusters;
- the DNS zone delegation for the trust framework in place, or the trust-list steps will not
  resolve;
- Helm v4.3.0, the version the pipeline pins, kubectl, `jq`, `curl` and `python3` with PyYAML
  (the zone installer), and istioctl 1.31.1 to inspect the proxies;
- this repository checked out, and the values file for the zone you are installing.

Check the version first — everything below assumes 1.29 or later, and the mesh needs 1.33 or later:

```bash
kubectl version -o json | jq -r '.serverVersion.gitVersion'
```

## 1. CNI

Cilium is installed first and must not claim exclusive ownership of the CNI configuration
directory, or the Istio CNI plugin cannot chain behind it:

```bash
helm upgrade --install cilium cilium/cilium -n kube-system \
  --set cni.exclusive=false
```

**Verify:** every Cilium pod is `Running`, and `cilium status` reports the cluster healthy.

## 2. The zone layout

Steps 2 to 4 are one command. The zone installer installs the zone from its zone file as seven Helm
releases, in this order, each through the deployment lifecycle step (`scripts/lifecycle.sh`: a
server-side dry run, then `helm upgrade --install --wait` with rollback on failure), each waiting on
the previous, and stops at the first release that fails, naming it:

| # | Release | Namespace | Chart | Step |
|---|---|---|---|---|
| 1 | `ztd` | `ztd-system` | `deployment/helm/ztd`, the umbrella | 2 |
| 2 | `spire-crds` | `spire-system` | `spire-crds` 0.6.1 | 3 |
| 3 | `spire` | `spire-system` | `spire` 0.30.2 (SPIRE v1.15.3) | 3 |
| 4 | `istio-base` | `istio-system` | Istio `base` 1.31.1 | 4 |
| 5 | `istiod` | `istio-system` | Istio `istiod` 1.31.1 | 4 |
| 6 | `istio-cni` | `istio-system` | Istio `cni` 1.31.1 | 4 |
| 7 | `zone-policy` | `istio-system` | `deployment/helm/zone-policy` | 3 and 4 |

First fill the zone file, `deployment/helm/ztd/zones/<zone>.yaml`, from the cluster
(`zones/zone-a.example.yaml` shows each fact with the command that reads it). Besides the cluster
facts, a zone that runs the mesh states:

- `zone.trustDomain`: the zone's SPIFFE trust domain, which is **the DNS zone delegated to this
  trust zone**, confirmed by the Technical Design Authority. It is fixed at the first install
  ([Workload identity](../workload-identity.md#the-trust-domain)); without it nothing renders.
- `networkPolicy.kubeApi`: enabled, with the API server's port as the endpoint slice of the
  `kubernetes` Service shows it (`kubectl get endpointslices -n default -l
  kubernetes.io/service-name=kubernetes`).
- `zone.kubernetesVersion` 1.33 or later, `cni.cilium.enabled: true`, the control-plane namespaces
  `spire-system` and `istio-system` in `planes.extra` with `mesh: false`, and the openings
  `meshControlPlane`, `controlPlaneWebhooks` and `identityServer` enabled.

Then plan, and install:

```bash
ZONE_VALUES=deployment/helm/ztd/zones/<zone>.yaml KUBE_CONTEXT=<context> \
  scripts/install-zone/install.sh plan
ZONE_VALUES=deployment/helm/ztd/zones/<zone>.yaml KUBE_CONTEXT=<context> \
  scripts/install-zone/install.sh install
```

The installer exits 0 only when every release is deployed and every pod of the plane and
control-plane namespaces is Ready; run again, it changes nothing. Its
[README](https://github.com/eclipse-xfsc/facis-zero-trust-demonstrator/tree/main/scripts/install-zone)
lists the tools it needs.

The first release, the umbrella, lays the zone down before any component is installed: the
management and data-plane namespaces and the two control-plane namespaces, default-deny network
policies in both directions, the declared openings, the allow-matrix lanes from the data plane
into the management plane, and the hook-weight bands the jobs of the components plug into. It
creates every namespace the later releases install into; they create none.

**Verify:** `ztd-mgmt` and `ztd-data` exist with their `ztd.facis.io/plane` label and the mesh
label for the zone's mode, `spire-system` and `istio-system` with the plane label and without the
mesh label, each holds a `default-deny` NetworkPolicy, and the release's post-install verification
job completed; the release fails on its own if the layout is not what the chart declared. The
design, the bands and the evidence script are in [Umbrella chart](../umbrella-chart.md).

## 3. Workload identity

Releases 2 and 3 install SPIRE into `spire-system`, in this order: `spire-crds` (its CRDs), then
`spire` (the server, the agents on every node, the SPIFFE CSI driver and the controller-manager), so
that SVIDs reach workloads through a mounted volume rather than through a secret. Release 7,
`zone-policy`, registers the workloads by
selector: every pod with `spiffe.io/spire-managed-identity: "true"` in a plane namespace gets
`spiffe://<trust domain>/ns/<namespace>/sa/<service account>`. The registration is a regular
resource that the controller-manager reconciles into entries, never a hook job; the jobs that check
the server, the trust bundle and the entries sit in the `identity` band of the hook-weight scheme
and fail the release when identity is not there. Details: [Workload identity](../workload-identity.md).

The zone facts this step needs, in the zone file `deployment/helm/ztd/zones/<zone>.yaml`:

- `zone.trustDomain`: the zone's SPIFFE trust domain, the DNS zone delegated to this trust zone,
  confirmed by the Technical Design Authority and fixed at the first install;
- `spire-system` in `planes.extra` with `mesh: false`, and the openings `identityServer` and
  `controlPlaneWebhooks` enabled;
- `networkPolicy.kubeApi` enabled with the API server's port, which the agents and the
  controller-manager need.

The same installer command as step 2 installs these releases, after `ztd`:

```bash
ZONE_VALUES=deployment/helm/ztd/zones/<zone>.yaml KUBE_CONTEXT=<context> \
  scripts/install-zone/install.sh install
```

**Verify:** the installer reports `spire-crds`, `spire` and `zone-policy` deployed (the identity checks passed);
`kubectl -n spire-system exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server agent
list` shows one attested agent per node that runs workloads; a labelled test pod receives, over the
mounted socket, an SVID whose SPIFFE ID matches its service account
([Checking an identity](../workload-identity.md#checking-an-identity)).

## 4. Mesh

Releases 4 to 6 install Istio in sidecar mode, with the default, unrevisioned istiod (sidecar under
[ADR-0009](../adr/0009-service-mesh-mode-istio-sidecar-with-cilium.md), which superseded the ambient
baseline of ADR-0001; ambient is the parked alternative) into `istio-system`: its CRDs, istiod, and
the Istio CNI plugin chained behind Cilium. Sidecar mode is the only mode the installer installs:
it refuses, before it renders or installs anything, a zone file whose `mesh.mode` is not `sidecar`
(absent counts as sidecar) or whose `mesh.revision` is set, and names the setting. The plane namespaces already carry the matching label,
`istio-injection=enabled`. Sidecars are injected as native sidecar containers, which is why the
cluster's Kubernetes version is recorded in the zone file against that requirement. The sidecar
takes its certificate and its trust bundle from the SPIRE agent over SDS, never from istiod, and
release 7 makes mutual TLS `STRICT` mesh-wide, so a workload without a SPIRE entry has no mesh
identity and no mesh connection. Exactly one component enforces L7 policy on any given traffic
path — where the sidecar does it, Cilium is held to L3/L4 for that path, and the assignment is
recorded in the mesh configuration.

**Verify:** every pod in a plane namespace carries the injected proxy as a native sidecar
(`istio-proxy` among its init containers with `restartPolicy: Always`); `istioctl proxy-config
secret <pod>` shows `default` and `ROOTCA` issued by the SPIRE CA; a request between two meshed
workloads carries a SPIRE-issued identity. The executed proof of all of it on kind is
[the mesh identity evidence](../evidences/mesh-identity/README.md).

## 5. Admission control

OPA Gatekeeper is installed together with the signature-verification external-data provider. From
this point an image whose Cosign signature does not verify against the client key material cannot
start.

**Verify:** deploy an unsigned image and confirm it is refused, and that the refusal names the
reason code rather than a generic admission error. A cluster where that image starts is not
configured.

## 6. The demonstrator workloads

The demonstrator services install into the data plane as regular resources; the jobs they bring
sit in the `workloads` band of the hook-weight scheme. A workload cannot become READY before its
identity exists: its container does not start until the SPIFFE CSI driver has mounted the socket
directory, and it holds no SVID until the agent answers on that socket with a matching
registration.

**Verify:** the management and data-plane namespaces both reconcile, no pod is in `CrashLoopBackOff`,
and the demonstrator UI answers.

## 7. The trust boundary between the zones

With both zones up, the attested channel between them is exercised. Both ends present evidence of
the software they are running, and that evidence is bound to the TLS connection it was presented on.

**Verify:** run the successful journey end to end from zone A, then the tampered-measurement
journey, and confirm the second one aborts the handshake before any application traffic flows.

## Teardown

Components uninstall in the reverse order of their installation; the layout goes last. The
installer does it for the seven releases of steps 2 to 4. Helm removes the SPIRE CRDs with
`spire-crds`; Istio's `base` chart marks its CRDs to be kept by Helm, so the installer deletes the
CRDs that release owned:

```bash
ZONE_VALUES=deployment/helm/ztd/zones/<zone>.yaml KUBE_CONTEXT=<context> \
  scripts/install-zone/install.sh uninstall
```

The umbrella's release namespace `ztd-system` remains: the installer creates it before the first
release and no release owns it. It holds nothing once the umbrella is uninstalled; delete it last:

```bash
kubectl --context <context> delete namespace ztd-system
```

**Verify:** no namespace, CRD or secret belonging to the demonstrator survives. This is asserted by
an acceptance scenario, not by eye.

## Operations

- **Logs and traces** are collected by the OpenTelemetry Collector and read through the Prometheus
  and Jaeger interfaces; there is no Grafana in this deployment, and
  [why](../specifications.md#readings-and-additions) is recorded.
- **A refusal is diagnosed by its reason code**, not by grepping for stack traces — see
  [Troubleshooting](../troubleshooting.md).
- **Certificate and key material** lives in OpenBao and is never written into a chart value or a
  container image.
