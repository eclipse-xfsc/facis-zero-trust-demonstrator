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
- the DNS zone delegation for the trust framework in place ([TRAIN DNS zone](../train-dns.md)), or
  the trust-list steps will not resolve;
- Helm v4.3.0, the version the pipeline pins, and kubectl;
- this repository checked out, and the values file for the zone you are installing.

Check the version first — everything below assumes 1.29 or later:

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

The umbrella chart lays the zone down before any component is installed: the management and
data-plane namespaces, default-deny network policies in both directions, the allow-matrix lanes
from the data plane into the management plane, and the hook-weight bands the jobs of the
components plug into. It installs into its own release namespace, which is not a plane namespace,
from the zone's values file:

```bash
helm upgrade --install ztd deployment/helm/ztd -n ztd-system --create-namespace \
  -f deployment/helm/ztd/zones/<zone>.yaml --wait
```

**Verify:** `ztd-mgmt` and `ztd-data` exist with their `ztd.facis.io/plane` label and the mesh
label for the zone's mode, each holds a `default-deny` NetworkPolicy, and the release's
post-install verification job completed; the release fails on its own if the layout is not what
the chart declared. The design, the bands and the evidence script are in
[Umbrella chart](../umbrella-chart.md).

## 3. Workload identity

SPIRE is installed into the management plane laid down in step 2, with its controller-manager and
the SPIFFE CSI driver, so that SVIDs reach workloads through a mounted volume rather than through a
secret. Registrations are regular resources that the controller-manager reconciles into entries,
never hook jobs; the jobs that check the server, the trust bundle and the entries sit in the
`identity` band of the hook-weight scheme.

**Verify:** the SPIRE server has an entry for each registered workload selector, and a test pod
receives an SVID whose SPIFFE ID matches its service account.

## 4. Mesh

Istio is installed in the mode the zone's values file names (`mesh.mode`: ambient under
ADR-0001, sidecar if a superseding decision flips it); the plane namespaces already carry the matching
label. Exactly one component enforces L7 policy on any given traffic path — where a waypoint proxy
does it, Cilium is held to L3/L4 for that path, and the assignment is recorded in the mesh
configuration.

**Verify:** the ztunnel daemonset is ready on every node, and a request between two meshed workloads
carries an identity the waypoint can name.

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

Components uninstall in the reverse order of their installation; the layout goes last:

```bash
helm uninstall ztd -n ztd-system
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
