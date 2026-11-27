# Application workloads

Where the demonstrator's application services run while the platform clusters are being provided,
how they are installed, and what the current access allows. The platform itself — mesh, identity,
admission — is installed by the umbrella chart on clusters with cluster rights ([OSC](osc.md),
[IONOS](ionos.md)); this page covers what runs on top of it, and what can run before it exists.

## Placement

| Cluster | Runs | Access |
|---|---|---|
| IONOS | ORCE, the demonstrator UI, Keycloak ([Identity model](../identity-model.md)) | Cluster rights ([IONOS](ionos.md)) |
| OSC, shared cluster, namespace `zero-trust` | Application services for interim integration: participant backend, protected-resource mock, their adapters | Namespace-scoped service account |
| OSC zone A and zone B (dedicated, requested) | The full zones: platform plus application services | Cluster rights once provided |

The shared-cluster namespace is an interim test route. It carries no mesh, no workload identity and
no admission control, so nothing run there is evidence for a zero-trust requirement; it shows that
the application services deploy, start and answer.

## Installing application charts

Application services are installed as their own Helm releases, **outside the umbrella chart**. The
umbrella creates namespaces and, with verification on, cluster roles; a namespace-scoped identity
cannot install it, and an application release must not need to.

- One release per service, values-only: the image by digest, the hostname, the secret names.
- No cluster-scoped objects: no namespaces, CRDs, cluster roles or webhooks.
- Each release brings its own default-deny `NetworkPolicy` and the allow rules it needs. The shared
  namespace ships with allow-all policies, which are not relied on.

## The OSC shared namespace as found

Recorded on 7–8 October 2026 with the namespace's service account.

| Item | Value |
|---|---|
| Kubernetes | v1.32.9 |
| May create | Deployments, services, secrets, ingresses, network policies, roles and role bindings, `pods/exec`, in the namespace |
| May not create | Namespaces, CRDs, cluster roles and bindings, admission webhooks, CSI drivers; nodes are not visible |
| Quota | 2.5 CPU and 10 GiB requests and limits, 30 pods, 20 services, 40 secrets, 10 PVCs, 50 GiB storage |
| Per-container limits | Minimum request 100m CPU and 128 Mi; default request 250m and 256 Mi; default limit 1 CPU and 1 Gi; maximum 4 CPU and 8 Gi |
| CNI | Cilium |
| Ingress | Class `nginx`, one public address shared by the cluster |
| Storage | Class `default` (CSI), `WaitForFirstConsumer` |
| Images | Public registries reachable (a Docker Hub image pulled) |

**Smoke test, 8 October 2026.** An unprivileged nginx deployment with a service and an ingress was
created with the namespace's service account, rolled out, answered `200` over HTTP and HTTPS from
outside the cluster through the ingress, and was deleted. A container requesting less than the
LimitRange minimum is refused at pod creation, not at apply.

## Local two-zone setup

For cross-zone integration until the OSC zone clusters exist. **Integration only:** nothing run on
it is acceptance evidence.

```bash
scripts/dev/zones-up.sh     # about 10 minutes; safe to re-run
scripts/dev/zones-down.sh   # removes both zones and the files below
```

It builds two kind clusters, `ztd-zone-a` and `ztd-zone-b`, each with
`scripts/dev/kind-cilium-up.sh` (Cilium with `cni.exclusive=false`,
Kubernetes 1.35), on kind's Docker network. A workload in one zone reaches the other zone at the
peer's worker-node address and a `NodePort`. The script ends by checking exactly that: a pod in
zone A opens a TCP connection to a service in zone B, and the run fails if it cannot. Your default
kubeconfig is not touched; each zone has its own.

It writes to `.dev/zones/` (not in Git):

| File | Holds |
|---|---|
| `kubeconfig-zone-a`, `kubeconfig-zone-b` | Cluster-admin on the local zone |
| `zone-a.yaml`, `zone-b.yaml` | The zone values file for the umbrella chart: `kubernetesVersion` and `cni.cilium.version` read from the cluster, the rest the fixed defaults of a kind zone |
| `zone-a.peer.env`, `zone-b.peer.env` | `PEER_ZONE` and `PEER_ADDRESS`: where the other zone is reached |

Needs `kind`, `kubectl`, `helm`, `cilium`, `python3` and Docker. The four nodes used 3.5 GB of memory
in a run with 8 GB given to Docker.

## Routes, TLS and DNS

Services are reached through the shared ingress controller. Two things are not in place yet:

- **Certificates.** The cluster has no certificate manager; HTTPS is served with the controller's
  default self-signed certificate. A release that is reached from outside brings its certificate as
  a `kubernetes.io/tls` secret, for a hostname that resolves to the ingress address.
- **TLS 1.3 only.** The shared controller accepts TLS 1.2 as well as 1.3. Enforcing 1.3 is a
  controller setting the cluster's operator owns; until it is set, a route through it does not meet
  the TLS 1.3 requirement and is not used as evidence for it.

Hostnames are requested per service; none is assigned yet.

## Secrets

Values never enter Git. On the shared namespace, the deploying identity creates each secret as a
Kubernetes `Secret` with the name the chart's values reference; the chart reads it by name. On the
dedicated clusters the same names are filled from OpenBao. Each chart lists the secret names it
expects in its values file.

## Logs

`kubectl logs` with the namespace's service account. Components log structured JSON
([TDR decisions](../adr/tdr-decisions.md)); tokens and passwords are never logged.

## Runtimes

| Runtime | Version |
|---|---|
| Kubernetes, IONOS | v1.35.6 |
| Kubernetes, OSC shared cluster | v1.32.9 |
| Helm | v4.3.0, as the pipeline pins it |
| Images | `linux/amd64`, referenced by digest |
