# ADR-0018: Service mesh on the demonstrator cluster — Istio ambient on Calico, without SPIRE

- **Status:** Accepted on 2026-11-18 by the Project Leader
- **Date:** 2026-11-14 (decided), 2026-11-18 (confirmed in writing and the deviation approved)
- **Decided by:** Project Leader (Daniel Pires)
- **Approval of the deviation:** the Project Leader (Daniel Pires), 2026-11-18. No separate approval
  of the Technical Design Authority is required. The FACIS written agreement (F-05) is sought in the
  next F-05 update; its date and reference are added when it is recorded.
- **Proposer:** the delivery team
- **Refines:** [ADR-0005](0005-three-cluster-reading-of-the-target-environment.md), the three-cluster
  reading: how the mesh is installed on its IONOS cluster
- **Scope:** the demonstrator cluster on IONOS Cloud (`deployment/helm/ztd/zones/ionos.yaml`) only.
  The participant zones stay under
  [ADR-0009](0009-service-mesh-mode-istio-sidecar-with-cilium.md), whose text is not changed.
- **Requirement basis:** ZT-23, ZT-01, ZT-15; declared not met on this cluster: ZT-24, SRS § 5.1.2,
  ZT-60 ([Specification changes](../specifications.md))
- **Evidence:** the dated record of `scripts/verify-ambient-mesh/verify.sh` under
  `docs/evidences/ambient-mesh-demonstrator/`, written by a passing run on the cluster

## Context

ADR-0005 places a third cluster on IONOS Cloud, beside the two participant clusters: the demonstrator
cluster, which runs the CI/CD and the visualization of the demonstrator (ZT-15) and no demonstration
workload. ZT-23 requires "a service mesh based on Istio or Cilium ... implemented in each Kubernetes
cluster", and ZT-01 requires the mesh to "protect communication between all services running for the
Demonstrator". The cluster is about to carry service-to-service traffic of its own: the receiving
OpenTelemetry collector to Prometheus and Jaeger, and the visualization to both. Until now it ran no
mesh, and its zone file set `mesh.mode: none`.

ADR-0009 baselines the zones' mesh on Istio sidecar mode with SPIRE as the certificate source and
Cilium as the CNI, and its scope statement leaves this cluster out ("The IONOS cluster is out of scope
for this record: it runs Calico, holds no demonstration workload and no mesh"). Three facts of the
cluster shape the decision (read-only, 2026-11-14):

- The CNI is Calico v3.30.7, managed by IONOS through its own deployment, and cannot be replaced: the
  Cilium policies of the umbrella chart, which name the API server and the host-networked SPIRE agents
  by entity, cannot be rendered there.
- The cluster has one node, the API server is managed outside the cluster and reaches the pods through
  the provider's `konnectivity-agent` pods, and the provider's admission accepts the privileged
  DaemonSets of the Istio CNI agent and ztunnel at `system-node-critical` (server-side dry runs).
- Upstream Istio does not support SPIRE in ambient mode ("Ambient mode does not support SPIRE
  integration", checked by `scripts/mesh-mode/check-upstream-state.sh`).

An earlier decision for this cluster, sidecar mode with SPIRE on a persistent volume, would have kept
ZT-24, but needs SPIRE's host-networked agents and CSI driver on a cluster the provider manages, and a
derogation for the SPIRE openings on Calico.

## Decision

On the demonstrator cluster the mesh is **Istio in ambient mode on the provider's Calico, without
SPIRE**:

1. The zone file sets `mesh.mode: ambient`. `scripts/install-zone/install.sh` installs it on its
   ambient path: the umbrella, `istio-base`, `istiod` (ambient profile, istiod's own CA as the only
   certificate source), `istio-cni` (ambient on, chained behind Calico), `ztunnel` and `zone-policy`
   with `spire.enabled: false`: the mesh-wide STRICT `PeerAuthentication`, the lane-port policies
   (item 3) and an admission policy that keeps injected proxies out of the plane namespaces and,
   in the namespaces enrolled in the mesh, refuses a pod that opts out of it, bypasses ztunnel's
   inbound capture, uses the host network, or could reach the node's network or its own capture
   rules another way (the other controls of the Pod Security Standards `baseline` profile:
   privileged, `hostPID`, `hostIPC`, `hostPath`, an added capability outside `baseline`'s list,
   seccomp or AppArmor `Unconfined`, `procMount`, `hostProcess`, SELinux, unsafe sysctls, a host in
   a probe or a lifecycle hook). No `spire-crds`, `spire`,
   SPIRE resource of `zone-policy` or `ztd-openbao` is installed.
2. The ambient path pins its own Istio release, 1.31.4 or later, by archive sha256 and image
   digests. 1.31.4, released on 6 November 2026, is the release of the security bulletin
   [ISTIO-SECURITY-2026-009](https://istio.io/latest/news/security/istio-security-2026-009/), which
   fixes among others an ambient-mode bypass of a port-level STRICT `PeerAuthentication`
   (GHSA-rr2c-p22p-6r9r), an istiod crash on an `AuthorizationPolicy` with an empty `to` or `from`
   entry in ambient mode (GHSA-8jw7-82jp-wr2c) and a ztunnel panic on a malformed `traceparent`
   header (GHSA-77vw-rg85-wx5x). The zones' sidecar pin is unchanged.
3. The umbrella chart renders the mesh without Cilium only under the declared CNI derogation
   `cni.derogation: calico-ambient`, allowed with `mesh.mode: ambient` and Cilium disabled and
   requiring the API endpoint addresses and the webhook source pods. Its openings are Kubernetes
   NetworkPolicies under the default deny: the webhook source pods to istiod's webhook port (15017),
   ztunnel to istiod's xDS port (15012), the node's network namespace (Istio SNATs every connection
   from it to an ambient pod to 169.254.7.127: the kubelet's probes, and any host-network pod) on
   every port into every meshed plane namespace, the API lane by address, and the HBONE port 15008 on every allow-matrix lane that
   names ports. Through 15008 ztunnel delivers a connection to any port of the destination pod, so
   the lane's ports are held at the mesh layer: `zone-policy` renders one DENY `AuthorizationPolicy`
   per destination of those lanes, enforced by ztunnel, refusing every other port from the lane's
   source namespace (ZT-55, ZT-26). Every other combination of a mesh without Cilium is still refused.
4. The trust domain is the interim `ionos.trust.invalid`, istiod's `meshConfig.trustDomain`, not
   federated with the zones' trust domains and without alias, replaced when the final trust domains
   are decided.
5. The API endpoint addresses stay out of the repository: the operator installs from a local copy of
   the zone file, and CI renders it with documentation-range addresses.

### Why this cluster differs from ADR-0009

ADR-0009 rejects istiod-issued mesh identities on the participant zones, because there ZT-24 and
ZT-60 require every mesh identity to come from SPIRE. That reason has no counterpart here, for three
reasons recorded with the decision:

- No workload on this cluster presents an identity to the participant zones. The zones export
  telemetry to it over mTLS with their own CA, not over the mesh, and its mesh is a trust domain of
  its own with no federation. A SPIRE-issued identity here would have no consumer.
- Ambient mode is the client's recorded preference, which ADR-0009 keeps ("Ambient is parked, not
  abandoned"), and upstream Istio cannot give it SPIRE identities.
- Ambient mode meshes the CI/CD and visualization workloads without injecting a proxy into their
  pods.

The cost is the deviation from ZT-24, SRS § 5.1.2 and ZT-60 on this cluster alone, declared in
[Specification changes](../specifications.md) and approved by the Project Leader.

Of ADR-0009's scope statement, this record takes over the sentence on the IONOS cluster: that cluster
now runs a mesh, in ambient mode on Calico, under this record. Everything else ADR-0009 decides stays
its own and applies to the participant zones.

## Consequences

- Positive: ZT-23 can be met on the demonstrator cluster, and the in-cluster traffic of the
  visualization and the observability stack runs under mesh-wide STRICT mTLS (ZT-01) with an identity
  per service account. No proxy is injected into the tooling's pods.
- Positive: one installer and one umbrella chart serve both paths; the participant zones' render is
  unchanged byte for byte.
- Negative: no SPIRE on this cluster. The mesh identities come from istiod's CA, so ZT-24, SRS § 5.1.2
  and ZT-60 are not met here; this is declared as a deviation in
  [Specification changes](../specifications.md). The cluster holds no identity toward the participant
  zones, and there is no trust between its mesh and theirs.
- Negative: the trust domain is interim; moving to the final one reissues every workload certificate.
- Negative: the cluster has one node. When the provider's maintenance replaces it, the mesh is down
  until istio-cni and ztunnel come back with the new node. Accepted for a tooling cluster.
- Negative: two facts were inferred, not observed, when this was decided: the webhook calls arrive
  from the `konnectivity-agent` pods, and Calico applies the probe lane to the SNAT-ed probes. The
  proof fails on either; the remedy is a corrected zone fact or opening, not a new decision. Its runs
  of 2026-11-15 and 2026-11-23 passed with both openings in place
  ([evidence](../evidences/ambient-mesh-demonstrator/2026-11-23.md), the record of the second).
- Negative: traffic from the node's network namespace bypasses the mesh. Istio SNATs every
  connection from it to an ambient pod to 169.254.7.127, which ztunnel lets past without mTLS, and
  the probe opening admits that address on every port, as the kubelet's probes need. A host-network
  pod therefore reaches every port of every ambient pod in plaintext, past STRICT and the lane-port
  policies, and so does any pod that can enter the node's network namespace (a privileged `hostPID`
  pod, with `nsenter`). A pod with `NET_ADMIN` could also delete the capture rules istio-cni writes in
  its own network namespace and leave the mesh.
- In the namespaces enrolled in the mesh (`ztd-mgmt`, `ztd-data`) `zone-policy`'s
  `no-sidecar-in-planes` refuses, on every write path of a pod (create and update, `pods/status`,
  `pods/ephemeralcontainers`): the opt-out (`istio.io/dataplane-mode` other than `ambient`, or
  `ambient.istio.io/bypass-inbound-capture`), `hostNetwork`, a `hostPort`, a privileged container,
  `hostPID`, `hostIPC`, a `hostPath` volume, and the other controls of the Pod Security Standards
  `baseline` profile (Kubernetes 1.35): an added capability outside `baseline`'s list (`AUDIT_WRITE`,
  `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `KILL`, `MKNOD`, `NET_BIND_SERVICE`, `SETFCAP`,
  `SETGID`, `SETPCAP`, `SETUID`, `SYS_CHROOT`; compared in any case, with or without `CAP_`, so
  `NET_ADMIN`, `SYS_ADMIN`, `ALL`, `SYS_MODULE`, `DAC_READ_SEARCH`, `SYS_RAWIO`, `SYS_PTRACE` and
  `NET_RAW` are refused), a seccomp or AppArmor profile `Unconfined` (the AppArmor field, or an
  annotation `container.apparmor.security.beta.kubernetes.io/*` other than `runtime/default` or
  `localhost/*`), a `procMount` other than `Default`, a Windows `hostProcess`, an SELinux type
  other than `container_t`, `container_init_t`, `container_kvm_t` or `container_engine_t` or any
  SELinux user or role, a sysctl outside `baseline`'s safe set, and a host in a probe or a
  lifecycle hook (the kubelet would call it from the node's network namespace, past the mesh); each
  in a container, an init container or an ephemeral container, and at pod level where the field
  exists there. `kubectl debug --profile=general` (`SYS_PTRACE`) and `--profile=sysadmin`
  (privileged) are therefore refused there. `istio-system` is not enrolled, so istiod, istio-cni
  and ztunnel (the last two add `NET_ADMIN` and `SYS_ADMIN`, istio-cni also `SYS_PTRACE` with
  AppArmor `Unconfined`, and mount `hostPath` volumes; neither is privileged nor host-network) are
  untouched.
- The trust anchor of those refusals is the namespace label `istio.io/dataplane-mode=ambient`, which
  the umbrella sets on both namespaces: removing it takes the namespace out of the mesh and out of
  the refusals at once. That needs namespace-update rights, held by the cluster's administrators,
  who could equally remove the policy; the proof checks that both namespaces still carry it.
- Negative, the residual the mesh does not hold, held only by the cluster's own access control: in
  the enrolled namespaces, what `baseline` admits and only `restricted` would refuse (a container
  running as root, privilege escalation, `baseline`'s own capabilities, volume types other than
  `hostPath`), a `hostPath`-backed PersistentVolume (creating one is a cluster-scoped right), and an
  escape through a kernel or container-runtime flaw; outside them, a host-network or privileged pod in any other namespace
  (`kube-system`'s provider pods among them), whoever may change `istio-system`, and anyone with
  access to the node. A pod admitted before a refusal existed and failing it would have its status
  updates refused; both namespaces were empty when the refusals were added.
- The L7 owner rule of ADR-0009 is not exercised here: no waypoint is installed and the allow matrix
  stays at L4.

**Reopen** when a community Istio release documents SPIRE as supported in ambient mode (the same
upstream check as ADR-0009), or when the client refuses the deviation; the zone file then returns to
`mesh.mode: none` and the derogation is removed until the next decision.

## References

- [ADR-0005](0005-three-cluster-reading-of-the-target-environment.md),
  [ADR-0009](0009-service-mesh-mode-istio-sidecar-with-cilium.md)
- [The IONOS environment](../environments/ionos.md), [Umbrella chart](../umbrella-chart.md),
  [Workload identity](../workload-identity.md)
- `scripts/install-zone/README.md`, `scripts/verify-ambient-mesh/README.md`
