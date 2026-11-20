# IONOS Cloud — CI/CD and visualization

The third cluster. It is meant to run the delivery machinery and the visualization surface, and
holds no demonstration workload: nothing that participates in a zone-to-zone call runs here, so a
failure in the pipeline cannot be mistaken for a failure in the demonstrator.

!!! note "Status"
    The cluster was provided on 23 September 2026. What is installed today is ORCE, the BDD pool and
    the service mesh; stages 1 to 5 below describe the first two and were checked against the
    cluster, except where a stage says otherwise. The service mesh (stage 7) was installed and
    proven on 15 November 2026. The runner, registry access and visualization stages are planned and marked so.

## Before you start

You need:

- a kubeconfig for the IONOS cluster with rights to create namespaces, cluster roles and bindings
  (kept outside the repository, never committed);
- Docker with `linux/amd64` support, Helm v4.3.0 and kubectl;
- Node.js 22 and `npm ci` in this repository, for the acceptance run;
- this repository checked out.

```bash
export KUBECONFIG=/path/to/ionos-admin.kubeconfig
kubectl version -o json | jq -r '.serverVersion.gitVersion'
```

**Verify:** the server reports v1.29 or later (v1.35.6 at the time of writing).

## 1. The cluster as provided

IONOS Managed Kubernetes, one node pool. The provider installs and operates the CNI (Calico), the
IONOS CSI driver with its storage classes, CoreDNS and its own policy validator; none of them is
replaced.

```bash
kubectl get nodes -o wide
kubectl -n kube-system get daemonset calico-node csi-ionoscloud
kubectl get storageclass
```

**Verify:** every node is `Ready`, and both daemonsets report as many ready pods as desired.

The common baseline ([Environments](index.md)) names Cilium with `cni.exclusive=false`, for the
service mesh of the participant zones
([ADR-0009](../adr/0009-service-mesh-mode-istio-sidecar-with-cilium.md)). This cluster keeps its
provider CNI, and its mesh is Istio in **ambient mode on Calico, without SPIRE**
([ADR-0018](../adr/0018-service-mesh-on-the-demonstrator-cluster.md), stage 7). This cluster runs
no SPIRE: upstream ambient mode does not support it, and the cluster hosts tooling, not
demonstration workloads. ZT-24, SRS § 5.1.2 and ZT-60 are declared not met here; what is met on
which cluster is stated in [the mesh and SPIRE on each
cluster](../specifications.md#the-mesh-and-spire-on-each-cluster).

## 2. The ORCE image

ORCE runs the first-party image built from `deployment/docker/orce` (see
[Packaging](../packaging.md)): upstream ORCE with Helm and kubectl pinned, the lifecycle Builder
Node and flow, credentials from the environment, JSON logging, non-root. It is `linux/amd64` only.
The pipeline builds and scans it on every pull request; to build it by hand:

```bash
docker build --platform linux/amd64 -f deployment/docker/orce/Dockerfile -t "$REGISTRY/facis-ztd-orce:$(git rev-parse --short HEAD)" .
docker push "$REGISTRY/facis-ztd-orce:$(git rev-parse --short HEAD)"
```

**Verify:** the push prints the image digest. Everything below references the image by that
digest (`IMAGE=<registry>/facis-ztd-orce@sha256:…`), never by tag.

## 3. ORCE

Installed from the interim manifests in `deployment/orce-minimal/` (see its README) until the ORCE
chart exists.

```bash
kubectl apply -f deployment/orce-minimal/base.yaml

# Credentials: generate them, store only bcrypt hashes (and the read token) in the cluster, and
# keep the plaintext in the team's password manager (see below).
hash() { docker run --rm --platform linux/amd64 --entrypoint node "$IMAGE" \
  -e "console.log(require('/opt/maestro/MBE/node_modules/bcryptjs').hashSync(process.argv[1], 10))" "$1"; }
admin_pass=$(openssl rand -hex 16); http_pass=$(openssl rand -hex 16); read_token=$(openssl rand -hex 32)
kubectl -n ztd-orce create secret generic orce-credentials \
  --from-literal=ORCE_ADMIN_USER=admin --from-literal=ORCE_ADMIN_PASSWORD_HASH="$(hash "$admin_pass")" \
  --from-literal=ORCE_HTTP_USER=bdd --from-literal=ORCE_HTTP_PASSWORD_HASH="$(hash "$http_pass")" \
  --from-literal=ORCE_READ_TOKEN="$read_token"

sed "s|__IMAGE__|$IMAGE|" deployment/orce-minimal/orce.yaml | kubectl apply -f -
```

Before closing the shell, copy `$admin_pass`, `$http_pass` and `$read_token` into the password
manager one at a time through the clipboard (for example `printf %s "$admin_pass" | pbcopy` on
macOS), rather than echoing them to the terminal; they exist nowhere else.

**Verify:**

```bash
kubectl -n ztd-orce rollout status deployment/orce --timeout=5m
kubectl -n ztd-orce get deployment orce -o jsonpath='{.spec.template.spec.containers[0].image}'   # the digest
kubectl -n ztd-orce logs deployment/orce --tail=5          # one JSON object per line
kubectl -n ztd-orce get networkpolicy orce-ingress
```

The rollout completes, the image is the digest you pushed, and the log lines are JSON objects with
`time`, `level`, `type`, `name`, `id` and `msg` ([ORCE logging](../flows.md#orce-logging)); an
image built before JSON logging was added prints prefixed lines instead, and must be replaced. There is
no ingress: ORCE is reached with `kubectl port-forward` until the ORCE chart exposes it over TLS 1.3.

## 4. The BDD pool

The namespaces and least-privilege identities of the cluster acceptance scenarios, bound to ORCE's
ServiceAccount as deployer (the chart's README, `deployment/helm/bdd-pool/README.md`, lists what it
installs):

```bash
helm upgrade --install bdd-pool deployment/helm/bdd-pool --namespace ztd-orce \
  --set deployer.serviceAccount.create=false --set deployer.serviceAccount.name=orce \
  --set observer.serviceAccount.create=false --wait
```

**Verify:**

```bash
kubectl get namespaces -l app.kubernetes.io/name=bdd-pool
kubectl auth can-i create namespaces --as=system:serviceaccount:ztd-orce:orce                          # no
kubectl auth can-i create deployments -n ztd-bdd-tdr-001 --as=system:serviceaccount:ztd-orce:orce      # yes
kubectl auth can-i create deployments -n default --as=system:serviceaccount:ztd-orce:orce              # no
kubectl auth can-i get secrets -n ztd-orce --as=system:serviceaccount:ztd-orce:ztd-bdd-observer        # no
kubectl auth can-i delete pods -n ztd-bdd-tdr-001 --as=system:serviceaccount:ztd-orce:ztd-bdd-observer # no
```

The pool namespaces are listed: `ztd-bdd-tdr-001` … `004`, and `006` for TDR-BDD-06 once the
pool runs this chart version. Each answer is the one in the comment: ORCE deploys only inside the pool, and the observer can neither read ORCE's credentials
nor change anything.

## 5. The acceptance run

The cluster rows (TDR-BDD-01..04 and TDR-BDD-06) run against this cluster with the read-only
observer identity; ORCE does the deploying. In CI this is the `bdd-cluster` job, once
`BDD_CLUSTER_ENABLED` is set and ORCE is reachable from the pipeline ([CI/CD](../ci-cd.md)). By
hand, from an administrator's machine, with the credentials from stage 3:

```bash
# A short-lived observer kubeconfig.
umask 077
kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > ca.crt
kubectl config set-cluster ionos --server="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')" \
  --certificate-authority=ca.crt --embed-certs --kubeconfig=observer.kubeconfig
kubectl config set-credentials observer --kubeconfig=observer.kubeconfig \
  --token="$(kubectl -n ztd-orce create token ztd-bdd-observer --duration=12h)"
kubectl config set-context observer --cluster=ionos --user=observer --kubeconfig=observer.kubeconfig
kubectl config use-context observer --kubeconfig=observer.kubeconfig

kubectl -n ztd-orce port-forward service/orce 18801:1880 &

KUBECONFIG=$PWD/observer.kubeconfig BDD_ORCE_URL=http://127.0.0.1:18801 BDD_TARGET=ionos \
BDD_ORCE_ADMIN_TOKEN="$read_token" BDD_ORCE_HTTP_USER=bdd BDD_ORCE_HTTP_PASS="$http_pass" \
BDD_ORCE_LOGS_CMD="kubectl --kubeconfig=$PWD/observer.kubeconfig -n ztd-orce logs deployment/orce --tail=-1" \
npm run bdd:cluster
```

**Verify:** the run reports every scenario passed; every `scenario.json` under
`bundles/bdd/evidence/` carries the cluster's `kube-system` UID
(`kubectl get namespace kube-system -o jsonpath='{.metadata.uid}'`); and every pool namespace is
back to its baseline (`kubectl -n ztd-bdd-tdr-001 get all` shows nothing). Stop the port-forward and
delete `observer.kubeconfig` and `ca.crt` afterwards; the token expires on its own.

## 6. Admission proof (interim key)

An early admission proof on this cluster: Gatekeeper and the image-verification provider, with the
constraints in [deployment/admission](../../deployment/admission), enforcing only in the namespaces
labelled `facis.ztd/admission-proof=true` (`ztd-adm-001`, `ztd-adm-002`). The images it verifies are
signed with the **interim key** ([docs/contracts/keys/interim-cosign.pub](../contracts/keys/interim-cosign.pub)),
not the client trust chain, so it is not acceptance evidence for the admission requirements.
The fault-injection run marks its evidence that way, in its own words: "interim signing key; not
the client trust chain".

```bash
# Gatekeeper, the provider (by digest, from the release candidate job), the policy and the pool.
BIN=<dir with the pinned Gatekeeper chart, scripts/tools/install.sh gatekeeper-chart> \
PROVIDER_IMAGE=ghcr.io/<owner>/facis-zero-trust-demonstrator/admission-provider@sha256:<digest> \
TRUST_REPOSITORY=ghcr.io/<owner>/facis-zero-trust-demonstrator \
TRUST_KEY=docs/contracts/keys/interim-cosign.pub \
scripts/admission/install.sh
```

**Verify:** the script ends with the two admission namespaces; it has already checked that both
webhooks select only the admission label, that Gatekeeper's response cache is off, and that every
constraint is enforced by every webhook replica.

The acceptance run uses the namespaced tester identity (a kubeconfig built as in stage 5, with
`kubectl -n ztd-adm-001 create token ztd-adm-tester`) and the fixture list the `admission-fixtures`
workflow publishes:

```bash
KUBECONFIG=$PWD/tester.kubeconfig BDD_ADM_FIXTURES=fixtures.txt BDD_TARGET=ionos \
BDD_MODE=cluster GODOG_CUCUMBER_OUT=bundles/bdd/go-cluster-report-ionos.json go test ./internal/bdd
```

**Verify:** ZT-72 passes: the signed pod runs, and the unsigned, untrusted-key, mutable-tag,
missing-SBOM and missing-mock-attestation pods are refused with their reason codes before any pod
exists; `bundles/bdd/evidence/bdd-zt-072/` holds the record.

The fault cases are run by the administrator, with the tester for every admission attempt:

```bash
ADMIN_KUBECONFIG=<administrator> TESTER_KUBECONFIG=$PWD/tester.kubeconfig FIXTURES=fixtures.txt \
EVIDENCE=<dir> BIN=... PROVIDER_IMAGE=... TRUST_REPOSITORY=... TRUST_KEY=... \
scripts/admission/fault-injection.sh
```

It proves, and restores after each step: a non-Linux and an image-index fixture refused (ZT-13
mechanism only; that row stays pending); the provider down and Gatekeeper down each deny in the
admission namespaces while `ztd-orce`, `kube-system` and the lifecycle pool admit; a trusted key
removed while the provider cache is warm denies the next admission once every replica has loaded
the change; break-glass (the webhook removed, then restored by `install.sh`); and the admission
latency from Gatekeeper's own request histogram (p99 below 1.5 s).

**Break-glass:** `kubectl delete validatingwebhookconfiguration gatekeeper-validating-webhook-configuration`,
then `helm uninstall gatekeeper -n gatekeeper-system`. **Teardown:** `kubectl delete -f
deployment/admission/constraints/ -f deployment/admission/templates/`, then `helm uninstall
admission-pool admission gatekeeper -n gatekeeper-system`.

## 7. The service mesh (ambient, no SPIRE)

Istio in ambient mode, installed by `scripts/install-zone/install.sh` on its ambient path from the
zone file `deployment/helm/ztd/zones/ionos.yaml`
([ADR-0018](../adr/0018-service-mesh-on-the-demonstrator-cluster.md)): the umbrella, `istio-base`,
`istiod` (ambient profile, istiod's own CA, trust domain `ionos.trust.invalid`, interim), `istio-cni`
(ambient on, chained behind Calico), `ztunnel`, and `zone-policy` (the mesh-wide STRICT
`PeerAuthentication`, the lane-port policies and the no-sidecar admission policy). Istio comes from
its own pin, 1.31.4. Installed on 2026-11-15 and proven the same day: every check of the proof passed
([evidence](../evidences/ambient-mesh-demonstrator/2026-11-15.md)). The record names the commit it
ran on, on the branch before its rebase onto `main`; the same changes land under another hash.

The cluster facts that shaped it (read-only, 2026-11-14):

- One node, Kubernetes v1.35.6. Calico v3.30.7 managed by IONOS (iptables dataplane on the nft
  backend, IPIP, WireGuard, MTU 1440), its CNI in `/opt/cni/bin` and `/etc/cni/net.d`;
  kube-proxy in iptables mode.
- The provider's admission accepts the Istio CNI agent's and ztunnel's DaemonSets (host
  paths, `NET_ADMIN`, `SYS_ADMIN`, `NET_RAW`, root) at `system-node-critical` (server-side dry runs).
  Gatekeeper enforces only in namespaces labelled `facis.ztd/admission-proof=true`; `istio-system`
  never carries that label.
- The managed API server listens on 15700 behind the `kubernetes` Service (443) and reaches the pods
  through the `konnectivity-agent` pods in `kube-system`. The webhook calls to istiod are therefore
  expected from those pods: inferred from that layout. The proof's webhook check passed on
  2026-11-15 with that opening in place (the only one onto istiod's 15017 from outside
  `istio-system`).

The umbrella renders this zone only under its declared CNI derogation, `cni.derogation:
calico-ambient`: the openings are Kubernetes NetworkPolicies (the webhook source pods to istiod 15017,
ztunnel to istiod 15012, the node's network namespace (SNAT-ed by Istio to 169.254.7.127: the
kubelet's probes, and any host-network pod) on every port into every meshed plane
namespace, the API lane by address on 15700), and the allow-matrix lanes that name ports also name
the HBONE port 15008 ([Umbrella chart](../umbrella-chart.md)). Through 15008 ztunnel would deliver a
connection to any port of the destination pod, so `zone-policy` holds those lanes to their ports at
the mesh layer: one DENY `AuthorizationPolicy` per destination, enforced by ztunnel, refuses every
other port from the lane's source namespace. It also refuses, in the plane namespaces, a pod that
chooses its injection templates, asks for an injected proxy, or carries one, whatever asked for it (a
pod or namespace label among them; `no-sidecar-in-planes`), and, in `ztd-mgmt` and `ztd-data`
(enrolled in the mesh), a pod that opts out of the mesh (`istio.io/dataplane-mode` other than
`ambient`), bypasses ztunnel's inbound capture (`ambient.istio.io/bypass-inbound-capture`), uses
the host network (`hostNetwork`, `hostPort`), or could reach the node's network or its own capture
rules another way, which are the other controls of the Pod Security Standards `baseline` profile:
a privileged container, `hostPID`, `hostIPC`, a `hostPath` volume, an added capability outside
`baseline`'s list (`AUDIT_WRITE`, `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `KILL`, `MKNOD`,
`NET_BIND_SERVICE`, `SETFCAP`, `SETGID`, `SETPCAP`, `SETUID`, `SYS_CHROOT`, in any case, with or
without `CAP_`), seccomp or AppArmor `Unconfined`, a `procMount` other than `Default`, a Windows
`hostProcess`, an SELinux type outside `baseline`'s or an SELinux user or role, a sysctl outside
`baseline`'s safe set, or a host in a probe or a lifecycle hook, in any container, init container or
ephemeral container (and at pod level where the field exists there), whether written at creation,
in an update, through `pods/status` or by `kubectl debug` (so `kubectl debug --profile=general`,
which adds `SYS_PTRACE`, is refused there). A host-network pod, or a privileged `hostPID` pod
through `nsenter`, would reach every ambient pod in plaintext through the 169.254.7.127 opening, a
pod with `NET_ADMIN` could delete its own capture rules, and `SYS_ADMIN`, `SYS_MODULE`,
`DAC_READ_SEARCH` or `SYS_RAWIO` reach the node. These refusals hold while the namespace carries
`istio.io/dataplane-mode=ambient` (the proof checks it). What they leave open, held only by the
cluster's access control, is listed in ADR-0018 (Consequences): what `baseline` admits and only
`restricted` would refuse (root containers, privilege escalation, `baseline`'s own capabilities,
volume types other than `hostPath`), a `hostPath`-backed PersistentVolume and a kernel or runtime
escape in those namespaces, and host-network or privileged pods in any other namespace, changes to
`istio-system` (where istio-cni and ztunnel add `NET_ADMIN` and `SYS_ADMIN` and mount `hostPath`
volumes) and access to the node.

**The local zone copy.** The API endpoint addresses are kept out of the repository; the committed
zone file has `networkPolicy.kubeApi.cidrs: []` and the umbrella refuses it as it stands. Copy it
to `.dev/` (git-ignored, so it is never committed, and the proof's record names it by that
relative path) and add the two addresses as `/32` entries, read from the cluster:

```bash
mkdir -p .dev && cp deployment/helm/ztd/zones/ionos.yaml .dev/ionos.local.yaml
# put each address into networkPolicy.kubeApi.cidrs as <address>/32
kubectl --context cluster-admin@ZeroTrustDemonstrator get endpointslices -n default \
  -l kubernetes.io/service-name=kubernetes \
  -o jsonpath='{.items[*].endpoints[*].addresses[*]}'
```

**Install** (idempotent):

```bash
# the six steps of the ambient path
ZONE_VALUES=.dev/ionos.local.yaml KUBE_CONTEXT=cluster-admin@ZeroTrustDemonstrator \
  scripts/install-zone/install.sh plan
ZONE_VALUES=.dev/ionos.local.yaml KUBE_CONTEXT=cluster-admin@ZeroTrustDemonstrator \
  scripts/install-zone/install.sh install
```

**Verify** with the proof, which places stand-ins in `ztd-mgmt`, `ztd-data` and a throwaway
namespace and removes them on exit (`scripts/verify-ambient-mesh/README.md`):

```bash
ZONE_VALUES=.dev/ionos.local.yaml ZTD_CONFIRM_CLUSTER=cluster-admin@ZeroTrustDemonstrator \
  scripts/verify-ambient-mesh/verify.sh
```

It checks the control plane on every node, the stand-ins' probes under the default deny, their
enrolment by ztunnel, an allowed call between istiod-issued identities in `ionos.trust.invalid`, a
plaintext call refused under STRICT, a lane outside the allow matrix refused, a port outside a lane
that names ports refused, a webhook call that reaches istiod, a plane pod that would carry an
injected proxy refused, and a plane pod that would leave the mesh, use the host network or reach the
node's network another way refused, also through `pods/status` and ephemeral containers, while the
mesh's own pods in `istio-system` are admitted. A passing run writes its dated record under
`docs/evidences/ambient-mesh-demonstrator/`, which is committed; then the ZT-23 row of this cluster in
[Specification changes](../specifications.md#the-mesh-and-spire-on-each-cluster) changes with it.
If the webhook check fails, the webhook source (`controlPlaneWebhooks.fromPods`) is corrected in the
zone file; if the probe check fails, the probe lane is; then install and run the proof again.

**Maintenance outage.** The cluster has one node. When the provider's maintenance replaces it, the
mesh is down until istio-cni and ztunnel start on the new node; the DaemonSets bring them back
without intervention. This is accepted for a tooling cluster.

**Teardown** with the same zone copy: `scripts/install-zone/install.sh uninstall` removes the six
releases in reverse order. To return to the earlier state, the zone file then sets `mesh.mode: none`
and drops the derogation.

## Planned: runner, registry access and visualization

Not installed on this cluster yet. Each gets its stage and its check when it is.

- **Build and signing runner.** The AMD64 Linux runner that builds and signs project images by
  digest, with the key restricted to protected workflows.
- **Registry access.** Pushing images and signatures to the client's registry, and pulling from it
  on the OSC clusters, with a robot account rather than a personal one.
- **Visualization.** The demonstrator UI and the observability interfaces — Prometheus and Jaeger.
  There is no Grafana; the reason is recorded in
  [specification changes](../specifications.md#readings-and-additions).

## Teardown

```bash
kubectl delete -f deployment/orce-minimal/orce.yaml --ignore-not-found
helm uninstall bdd-pool --namespace ztd-orce
kubectl delete -f deployment/orce-minimal/base.yaml --ignore-not-found
```

**Verify:** `kubectl get namespaces | grep ztd-` prints nothing, and
`kubectl get clusterrole,clusterrolebinding | grep ztd-` prints nothing.

## Operations

- **The pipeline is the record.** Every image that reaches a cluster was built by the pipeline and
  is referenced by digest.
- **Credentials never enter the repository.** The administrator kubeconfig, the ORCE credentials
  and the observer tokens live outside it; the cluster stores only hashes and the read token.
- **Key material never leaves the runner**, is never printed into a log, and is never baked into an
  image layer.
