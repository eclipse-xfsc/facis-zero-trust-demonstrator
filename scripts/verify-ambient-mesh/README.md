# verify-ambient-mesh

The proof of the Istio ambient mesh on the demonstrator cluster (IONOS Cloud, the provider's Calico,
no SPIRE; [ADR-0018](../../docs/adr/0018-service-mesh-on-the-demonstrator-cluster.md)). It runs after
`scripts/install-zone/install.sh` has installed the cluster's ambient path from the zone file, and it
installs nothing itself: it places stand-in pods, proves with them, and removes them on exit.

```bash
ZONE_VALUES=<local copy of deployment/helm/ztd/zones/ionos.yaml> \
ZTD_CONFIRM_CLUSTER=cluster-admin@ZeroTrustDemonstrator \
  scripts/verify-ambient-mesh/verify.sh
```

`KUBE_CONTEXT` defaults to `cluster-admin@ZeroTrustDemonstrator` and `ZONE_VALUES` to
`deployment/helm/ztd/zones/ionos.yaml` (the local copy with the API addresses reads the same). The
script refuses, before it reads the cluster, a run under CI, a run without `ZTD_CONFIRM_CLUSTER`
equal to the context, a zone file outside the repository (the record names the zone file by its
path in the repository, so no local path is committed; the local copy goes under the ignored
`.dev/`), and a zone file that does not set `mesh.mode: ambient` with
`cni.derogation: calico-ambient`. It also refuses to start while a pod, Service, ServiceAccount or
NetworkPolicy named `proof-*` or labelled `ztd.facis.io/proof=ambient-mesh` exists in the plane
namespaces (an earlier run's, still terminating, or someone else's).

## Stand-ins

All are labelled `ztd.facis.io/proof=ambient-mesh` and `ztd.facis.io/proof-run=<a nonce of the
run>`, each with its own ServiceAccount, so that each has its own identity, and all images are
pinned by digest. On exit the run removes only the objects carrying its own nonce, and the
throwaway namespace when it created it:

| Stand-in | Namespace | Role |
|---|---|---|
| `proof-tsa` | management plane | HTTP server with a readiness probe, labelled as `tsa-policy-engine` (the destination of the allow-matrix lane `pdp-adapter-to-tsa`) |
| `proof-otel-collector` | management plane | two HTTP servers in one pod with readiness probes, on 4317 (a port of the lane `workloads-to-otel-collector`) and on 8080 (a port outside it), labelled as `otel-collector` |
| `proof-data-target` | data plane | HTTP server with a readiness probe |
| `proof-pdp-adapter` | data plane | client labelled as `pdp-adapter` (the source of that lane) |
| `proof-data-plain` | data plane | enrolled client without a matrix label |
| `proof-outsider` | `ztd-proof-plain` | client in a throwaway namespace outside the mesh and the planes, created and deleted by the run |
| `proof-plain-lane` | data plane | a NetworkPolicy, not a pod: ingress from `ztd-proof-plain` to `proof-data-target` on 8080 only, so that check 5's plaintext call meets an open network lane |

A pod opted out of the mesh in a plane namespace is no longer possible as a stand-in:
`no-sidecar-in-planes` refuses it (check 10).

## Checks

The run stops at the first check that fails.

1. **Control plane**: istiod is available; the `istio-cni-node` and `ztunnel` DaemonSets are ready
   on every node.
2. **Probes**: every stand-in becomes Ready. The servers' HTTP readiness probes pass under the
   default deny because the umbrella opens `169.254.7.127/32` (Istio SNATs every connection from
   the node's network namespace to an ambient pod to it, the kubelet's probes among them) into every
   meshed plane namespace. Istio's platform prerequisites do not list
   Calico, so this is checked, not assumed.
3. **Enrolment**: both plane namespaces carry `istio.io/dataplane-mode=ambient`, the label that
   enrols them and that every refusal of check 10 hangs on; `istioctl ztunnel-config workloads`
   lists every enrolled stand-in with protocol `HBONE`, and the outside stand-in without it.
4. **Identity**: the call over the allow-matrix lane succeeds, and ztunnel's access log records it
   between `spiffe://<zone.trustDomain>/ns/<data>/sa/proof-pdp-adapter` and
   `spiffe://<zone.trustDomain>/ns/<management>/sa/proof-tsa`: identities that istiod's CA issued in
   the zone's trust domain. `istioctl ztunnel-config certificates` must hold both.
5. **STRICT**: the outside pod's plaintext call to the data-plane target is refused with a reset
   (not a timeout) although `proof-plain-lane` opens the network lane to it, while an enrolled
   pod's call to the same target succeeds.
6. **Denied lane**: the unlabelled data-plane pod's call to the management stand-in is refused.
7. **Lane ports**: a lane that names ports opens the HBONE port 15008 at the network layer, and
   ztunnel delivers a connection on 15008 to any port of the destination pod. The enrolled data-plane
   pod's call to the collector stand-in on 4317 succeeds; its call on 8080, a port the stand-in
   serves outside the lane, must be refused with a reset, and ztunnel's log must name the
   `zone-policy` lane-port policy `lane-ports-workloads-to-otel-collector` (a DENY
   `AuthorizationPolicy` from the data-plane namespace to every port but 4317 and 4318).
8. **Webhook**: a server-side dry run of an `AuthorizationPolicy` with a non-numeric port, which the
   CRD schema accepts, must be denied by `validation.istio.io`. A "failed calling webhook" answer,
   which the webhook's `failurePolicy: Fail` also turns into a refusal, fails the check and names
   the `controlPlaneWebhooks` opening and its `fromPods` (on the demonstrator cluster the
   `konnectivity-agent` pods, inferred from the cluster's layout; the run of 2026-11-15 passed with
   that opening in place). No `PeerAuthentication` was found that
   the 1.31 CRD schema accepts and istiod refuses, so the resource is an `AuthorizationPolicy`.
9. **No sidecar**: server-side dry runs of a data-plane pod that chooses its injection templates
   (`inject.istio.io/templates: grpc-simple`), of one labelled `sidecar.istio.io/inject: "true"` and
   of one labelled `istio.io/rev: default` (which istiod's injector injects; the policy then refuses
   the injected proxy) must each be denied by `zone-policy`'s admission policy
   `no-sidecar-in-planes`. As controls, a plain data-plane pod and, in the mesh root namespace, a pod
   of ztunnel's shape (a container `istio-proxy`, the labels `istio.io/rev: default` and
   `sidecar.istio.io/inject: "false"`) must be admitted. A namespace label that asks for injection is
   not tried, since it would change a namespace; the same rule on the injected pod refuses it.
   Nothing is created.
10. **In the mesh**: server-side dry runs, each of which must be denied by `no-sidecar-in-planes`
   (the plane namespaces are enrolled in the mesh):
   - leaving the mesh: a data-plane pod labelled `istio.io/dataplane-mode: none`, a management-plane
     pod annotated `ambient.istio.io/bypass-inbound-capture`;
   - the node's network: a data-plane pod with `hostNetwork: true` and a management-plane pod with a
     `hostPort` (a host-network pod would reach every ambient pod in plaintext through the
     169.254.7.127 SNAT); in each plane a pod with `hostPID` and a privileged container (it could
     `nsenter` the node's network namespace); a management-plane pod with `hostPID` alone, a
     data-plane pod with `hostIPC`, a management-plane pod with only a `hostPath` volume of `/`, and
     a management-plane pod with a privileged init container;
   - its own capture rules and the node, the rest of the Pod Security Standards `baseline`: a
     data-plane pod adding `NET_ADMIN`, one whose init container adds `SYS_ADMIN`, one adding `all`
     in lower case, a management-plane pod adding `SYS_MODULE`, a data-plane pod whose init
     container adds `cap_dac_read_search` (the policy admits only `baseline`'s capabilities and
     compares names case-insensitively, with or without `CAP_`); a data-plane pod with seccomp
     `Unconfined`, a management-plane pod with AppArmor `Unconfined`, a data-plane pod with
     `procMount: Unmasked`, one with a Windows `hostProcess` container, a management-plane pod with
     SELinux type `spc_t`, a data-plane pod setting the unsafe sysctl `net.ipv4.ip_forward`, and a
     management-plane pod whose readiness probe names a host;
   - the other write paths, on the running stand-in `proof-data-plain`: the opt-out label and the
     capture bypass written through `pods/status`, and a privileged ephemeral container, one adding
     `SYS_PTRACE` (`kubectl debug --profile=general`) and one named `istio-proxy` added through
     `pods/ephemeralcontainers`.

   As controls, these must be admitted: a data-plane pod adding the `baseline` capabilities `chown`
   and `CAP_NET_BIND_SERVICE` with seccomp `RuntimeDefault`; a plain label written through `pods/status` and a plain
   ephemeral container on the same stand-in; a host-network pod and copies of the live pod templates of `istiod`,
   `istio-cni-node` and `ztunnel` in the mesh root namespace, which is not enrolled (istio-cni and
   ztunnel add `NET_ADMIN` and `SYS_ADMIN` and mount `hostPath` volumes); and a status update of the
   live ztunnel pod. Nothing is created or changed.

The admission cases of checks 9 and 10 also run in CI, against the rendered policy in a throwaway
kind cluster: `admission-kind.sh` (job "Ambient admission (kind)"). It needs `BIN`, a directory with
the pinned `kind` and `kubectl` (`scripts/tools/install.sh`), and docker; it does not touch the
demonstrator cluster.

## The record

A passing run writes its record, dated, to `docs/evidences/ambient-mesh-demonstrator/<UTC date>.md`:
the commit, the context, the Kubernetes version, the node count, the istiod image (the Istio
version) and every result. The script is the only writer of that directory, and the record is
committed as the evidence. A failing run writes its record to a temporary directory and prints the
path; nothing is written to the repository.
