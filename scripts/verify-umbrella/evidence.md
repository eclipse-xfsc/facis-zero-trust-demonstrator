# Umbrella chart evidence (2026-10-08T11:20:32Z)

Commit `0e4ef3c63957e0145c16e18ac9d2c9b299a17d25`, tree dirty: false.

Cluster context `kind-ztd`, chart `deployment/helm/ztd` 0.2.0, zone file `deployment/helm/ztd/ci/values.yaml` (mesh mode sidecar, the installed baseline), excursion fixture `scripts/verify-umbrella/ambient-values.yaml`.

Tools: helm v4.3.0+gbec5b06, kubectl client v1.37.1. The CI chart job pins Helm v4.3.0.

Probe results: `200` means the call went through; `denied(28)` means curl gave up after 5 s because the policy dropped the packets.


## 0. Preconditions

- PASS: the zone file records the server version the cluster runs
  server v1.35.5, recorded v1.35.5
- PASS: Cilium is the CNI
  quay.io/cilium/cilium:v1.20.2@sha256:2939231d0d3e3ebddcd80fffa168b7ddcc78fdf0dc864d1c8c126ff523c54f01
- PASS: cni-exclusive=false (Istio CNI can chain)
  cni-exclusive=false

```
NAME STATUS ROLES AGE VERSION INTERNAL-IP EXTERNAL-IP OS-IMAGE KERNEL-VERSION CONTAINER-RUNTIME
ztd-control-plane Ready control-plane 2d2h v1.35.5 172.18.0.3 <none> Debian GNU/Linux 13 (trixie) 6.8.0-139-generic containerd://2.3.1
ztd-worker Ready <none> 2d2h v1.35.5 172.18.0.4 <none> Debian GNU/Linux 13 (trixie) 6.8.0-139-generic containerd://2.3.1
```


## 1. Clean slate

- PASS: no plane namespace exists before the install

## 2. Install from zero

- PASS: helm upgrade --install from an empty cluster returns 0
  10s

```
Release "ztd" does not exist. Installing it now.
NAME: ztd
DESCRIPTION: Install complete
ztd umbrella chart 0.2.0: release ztd in ztd-system, zone kind.

Plane namespaces:
  - ztd-mgmt  plane=management  istio-injection=enabled
  - ztd-data  plane=data  istio-injection=enabled
  - spire-system  plane=management  istio-injection=enabled
  - istio-system  plane=management  istio-injection=enabled

Network layer: default-deny in both directions in every plane namespace, the DNS bypass, and
5 allow-matrix lanes from the data plane into the management plane.
The post-install verification job read the layout back; the release would have failed otherwise.

Next: the platform components (identity, mesh, admission, ...) install after this release and
plug into the hook-weight scheme described in docs/umbrella-chart.md.
Evidence: scripts/verify-umbrella/verify.sh
```

- PASS: release status is deployed (a failing verification hook would have failed it)
  deployed
- PASS: the post-install verification job passed and was removed by its hook policy
  (a failing job would have failed the release above)

## 3. The layout

The control-plane namespaces of the zone file (`spire-system istio-system`) are management-plane namespaces without the mesh label; the SPIRE and Istio releases that install into them are proven by `scripts/verify-mesh-identity`.


```
NAME STATUS AGE PLANE DATAPLANE-MODE ISTIO-INJECTION
ztd-mgmt Active 11s management enabled
ztd-data Active 11s data enabled
spire-system Active 11s management 
istio-system Active 11s management 
```


```
NAMESPACE NAME POD-SELECTOR AGE
istio-system allow-dns-egress <none> 10s
istio-system allow-intra-plane <none> 10s
istio-system allow-mesh-control-plane-ingress app=istiod 10s
istio-system default-deny <none> 10s
spire-system allow-dns-egress <none> 10s
spire-system allow-intra-plane <none> 10s
spire-system default-deny <none> 10s
ztd-data allow-atls-gateway-to-cmcd-egress app.kubernetes.io/name=atls-gateway 10s
ztd-data allow-atls-gateway-to-tcr-egress app.kubernetes.io/name=atls-gateway 10s
ztd-data allow-backend-to-verification-service-egress app.kubernetes.io/name=backend 10s
ztd-data allow-dns-egress <none> 10s
ztd-data allow-intra-plane <none> 10s
ztd-data allow-mesh-control-plane-egress <none> 10s
ztd-data allow-pdp-adapter-to-tsa-egress app.kubernetes.io/name=pdp-adapter 10s
ztd-data allow-workloads-to-otel-collector-egress <none> 10s
ztd-data default-deny <none> 10s
ztd-mgmt allow-atls-gateway-to-cmcd-ingress app.kubernetes.io/name=cmcd 10s
ztd-mgmt allow-atls-gateway-to-tcr-ingress app.kubernetes.io/name=tcr 10s
ztd-mgmt allow-backend-to-verification-service-ingress app.kubernetes.io/name=verification-service 10s
ztd-mgmt allow-dns-egress <none> 10s
ztd-mgmt allow-intra-plane <none> 10s
ztd-mgmt allow-mesh-control-plane-egress <none> 10s
ztd-mgmt allow-pdp-adapter-to-tsa-ingress app.kubernetes.io/name=tsa-policy-engine 10s
ztd-mgmt allow-workloads-to-otel-collector-ingress app.kubernetes.io/name=otel-collector 10s
ztd-mgmt default-deny <none> 10s
```


```
NAMESPACE NAME AGE VALID
istio-system allow-control-plane-openings 10s True
istio-system allow-kube-api-egress 10s True
spire-system allow-control-plane-openings 10s True
spire-system allow-kube-api-egress 10s True
ztd-mgmt allow-kube-api-egress 10s True
```

- PASS: default-deny present in ztd-mgmt
- PASS: default-deny present in ztd-data
- PASS: default-deny present in spire-system
- PASS: default-deny present in istio-system
- PASS: control-plane namespace spire-system: management plane, no injection label
- PASS: control-plane namespace istio-system: management plane, no injection label
- PASS: sidecar mode (the baseline): istio-injection=enabled on ztd-mgmt
- PASS: sidecar mode (the baseline): istio-injection=enabled on ztd-data
- PASS: sidecar mode: no ambient label on ztd-mgmt
- PASS: sidecar mode: no ambient label on ztd-data
- PASS: sidecar mode: no ambient host-probe exception is rendered

## 4. Install again: idempotent

- PASS: second helm upgrade --install returns 0
- PASS: rendered manifest identical between the two installs
  revision after the second install: 2

## 5. Cross-plane calls: the negative case, and the matrix lanes

Stand-in pods carry the matrix labels; nothing else about them is real. Targets serve HTTP on 8080.

- PASS: management stand-ins Ready
- PASS: data-plane stand-ins Ready
- PASS: unlabelled data-plane pod → openbao (management): DENIED
  → denied(28)
- PASS: unlabelled data-plane pod → tsa-policy-engine (management): DENIED
  → denied(28)
- PASS: pdp-adapter → tsa-policy-engine: ALLOWED (matrix lane pdp-adapter-to-tsa)
  → 200
- PASS: pdp-adapter → openbao: DENIED (a lane is one pair, not a licence)
  → denied(28)
- PASS: data-plane pod → data-plane pod: ALLOWED (intra-plane lane)
  → 200
- PASS: management pod → data plane: DENIED (default deny is both directions)
  → denied(28)
- PASS: DNS bypass: the denied pod still resolves names
  Name:	tsa-policy-engine.ztd-mgmt.svc.cluster.local Address: 10.96.74.130  

## 6. Mesh mode is one label: the excursion to the parked ambient mode, and back

Sidecar is the installed baseline (ADR-0009). The release is switched to ambient with the excursion fixture, which must bring the ambient label and the Cilium host-probe exception while the denial and the lane hold, and then back to sidecar, which must leave neither behind.

- PASS: upgrade to ambient mode returns 0

```
NAME STATUS AGE PLANE DATAPLANE-MODE ISTIO-INJECTION
ztd-mgmt Active 60s management ambient 
ztd-data Active 60s data ambient 
```

- PASS: ambient mode: istio.io/dataplane-mode=ambient on ztd-mgmt
- PASS: ambient mode: istio.io/dataplane-mode=ambient on ztd-data
- PASS: ambient mode: the sidecar label is gone
- PASS: ambient mode: the Cilium host-probe exception is rendered (mode ambient, Cilium)
- PASS: ambient mode: cross-plane call still DENIED
  → denied(28)
- PASS: ambient mode: matrix lane still ALLOWED
  → 200
- PASS: back to sidecar mode returns 0

```
NAME STATUS AGE PLANE DATAPLANE-MODE ISTIO-INJECTION
ztd-mgmt Active 74s management enabled
ztd-data Active 74s data enabled
```

- PASS: sidecar mode restored: istio-injection=enabled on ztd-mgmt
- PASS: sidecar mode restored: istio-injection=enabled on ztd-data
- PASS: sidecar mode restored: the ambient label is gone
- PASS: sidecar mode restored: the ambient host-probe exception is gone
- PASS: sidecar mode restored: cross-plane call still DENIED
  → denied(28)
- PASS: sidecar mode restored: matrix lane still ALLOWED
  → 200

## 7. Guards that refuse a wrong configuration: the lint and render steps of the CI chart gate

The CI job runs `helm lint` and then `helm template`. Schema violations fail both steps; a `fail` call in a template fails the render step only, because lint mode renders `fail` as a no-op by design.

- PASS: no zone file: lint refused by the schema
- PASS: no zone file: render refused by the schema
  at '/zone/storageClass': minLength: got 0, want 1
- PASS: unknown mesh mode: lint refused by the schema
- PASS: unknown mesh mode: render refused
  at '/mesh/mode': value must be one of 'ambient', 'sidecar', 'none'
- PASS: kubeApi lane without cidrs on a zone without Cilium (an ipBlock lane): lint passes, as lint mode ignores the template guard; the render step below is the one that catches it
- PASS: kubeApi lane without cidrs on a zone without Cilium: render refused
  networkPolicy.kubeApi.enabled needs at least one entry in networkPolicy.kubeApi.cidrs; an empty destination would open every address
- PASS: meshed zone without zone.trustDomain: render refused by the schema
  at '/zone/trustDomain': minLength: got 0, want 1
- PASS: sidecar mode on Kubernetes v1.32.0: render refused (native sidecars need 1.33)
  mesh.mode sidecar needs native sidecar containers, which need Kubernetes 1.33 or later; zone.kubernetesVersion is v1.32.0
- PASS: meshed zone without Cilium: render refused, naming the control-plane openings and the derogation
  mesh.mode sidecar needs Cilium (cni.cilium.enabled)

## 8. Teardown leaves no plane namespace behind

- PASS: helm uninstall returns 0
  release "ztd" uninstalled
- PASS: plane namespaces are gone, the control-plane namespaces with them
- PASS: cluster-wide Cilium exception is gone
- PASS: no hook resource left behind (hook-succeeded policy)
  the release namespace `ztd-system` remains, as expected: it was created by --create-namespace and is not owned by the release


## Result

All checks passed.
