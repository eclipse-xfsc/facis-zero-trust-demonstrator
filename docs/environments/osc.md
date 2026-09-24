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

## 2. Workload identity

SPIRE is installed with its controller-manager and the SPIFFE CSI driver, so that SVIDs reach
workloads through a mounted volume rather than through a secret.

**Verify:** the SPIRE server has an entry for each registered workload selector, and a test pod
receives an SVID whose SPIFFE ID matches its service account.

## 3. Mesh

Istio is installed in ambient mode. Exactly one component enforces L7 policy on any given traffic
path — where a waypoint proxy does it, Cilium is held to L3/L4 for that path, and the assignment is
recorded in the mesh configuration.

**Verify:** the ztunnel daemonset is ready on every node, and a request between two meshed workloads
carries an identity the waypoint can name.

## 4. Admission control

OPA Gatekeeper is installed together with the signature-verification external-data provider. From
this point an image whose Cosign signature does not verify against the client key material cannot
start.

**Verify:** deploy an unsigned image and confirm it is refused, and that the refusal names the
reason code rather than a generic admission error. A cluster where that image starts is not
configured.

## 5. The demonstrator

The zone installs as a single umbrella chart, which orders the components so that workload identity
exists before any workload that needs it:

```bash
helm install ztd deployment/helm/ztd -n ztd-mgmt --create-namespace -f <values file for the zone>
```

**Verify:** the management and data-plane namespaces both reconcile, no pod is in `CrashLoopBackOff`,
and the demonstrator UI answers.

## 6. The trust boundary between the zones

With both zones up, the attested channel between them is exercised. Both ends present evidence of
the software they are running, and that evidence is bound to the TLS connection it was presented on.

**Verify:** run the successful journey end to end from zone A, then the tampered-measurement
journey, and confirm the second one aborts the handshake before any application traffic flows.

## Teardown

```bash
helm uninstall ztd -n ztd-mgmt
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
