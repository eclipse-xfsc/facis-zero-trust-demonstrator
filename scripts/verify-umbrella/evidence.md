# Umbrella chart evidence (2026-10-01T11:04:23Z)

Cluster context `kind-ztd`, chart `deployment/helm/ztd` 0.1.0, zone file `deployment/helm/ztd/ci/values.yaml`.

Tools: helm v4.3.0+gbec5b06, kubectl client v1.34.1. The CI chart job pins Helm v4.3.0.

Probe results: `200` means the call went through; `denied(28)` means curl gave up after 5 s because the policy dropped the packets.


## 0. Preconditions

- PASS: the zone file records the server version the cluster runs
  server v1.35.8, recorded v1.35.8
- PASS: Cilium is the CNI
  quay.io/cilium/cilium:v1.20.2@sha256:2939231d0d3e3ebddcd80fffa168b7ddcc78fdf0dc864d1c8c126ff523c54f01
- PASS: cni-exclusive=false (Istio CNI can chain)
  cni-exclusive=false

```
NAME STATUS ROLES AGE VERSION INTERNAL-IP EXTERNAL-IP OS-IMAGE KERNEL-VERSION CONTAINER-RUNTIME
ztd-control-plane Ready control-plane 11m v1.35.8 172.30.0.2 <none> Debian GNU/Linux 13 (trixie) 6.10.14-linuxkit containerd://2.3.4
ztd-worker Ready <none> 11m v1.35.8 172.30.0.3 <none> Debian GNU/Linux 13 (trixie) 6.10.14-linuxkit containerd://2.3.4
```


## 1. Clean slate

- PASS: no plane namespace exists before the install

## 2. Install from zero

- PASS: helm upgrade --install from an empty cluster returns 0
  4s

```
Release "ztd" does not exist. Installing it now.
NAME: ztd
DESCRIPTION: Install complete
ztd umbrella chart 0.1.0: release ztd in ztd-system, zone kind.

Plane namespaces:
  - ztd-mgmt  plane=management  istio.io/dataplane-mode=ambient
  - ztd-data  plane=data  istio.io/dataplane-mode=ambient

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


```
NAME STATUS AGE PLANE DATAPLANE-MODE ISTIO-INJECTION
ztd-mgmt Active 4s management ambient 
ztd-data Active 4s data ambient 
```


```
NAMESPACE NAME POD-SELECTOR AGE
ztd-data allow-atls-gateway-to-cmcd-egress app.kubernetes.io/name=atls-gateway 4s
ztd-data allow-atls-gateway-to-tcr-egress app.kubernetes.io/name=atls-gateway 4s
ztd-data allow-backend-to-verification-service-egress app.kubernetes.io/name=backend 4s
ztd-data allow-dns-egress <none> 4s
ztd-data allow-intra-plane <none> 4s
ztd-data allow-pdp-adapter-to-tsa-egress app.kubernetes.io/name=pdp-adapter 4s
ztd-data allow-workloads-to-otel-collector-egress <none> 4s
ztd-data default-deny <none> 4s
ztd-mgmt allow-atls-gateway-to-cmcd-ingress app.kubernetes.io/name=cmcd 4s
ztd-mgmt allow-atls-gateway-to-tcr-ingress app.kubernetes.io/name=tcr 4s
ztd-mgmt allow-backend-to-verification-service-ingress app.kubernetes.io/name=verification-service 4s
ztd-mgmt allow-dns-egress <none> 4s
ztd-mgmt allow-intra-plane <none> 4s
ztd-mgmt allow-pdp-adapter-to-tsa-ingress app.kubernetes.io/name=tsa-policy-engine 4s
ztd-mgmt allow-workloads-to-otel-collector-ingress app.kubernetes.io/name=otel-collector 4s
ztd-mgmt default-deny <none> 4s
```

- PASS: default-deny present in ztd-mgmt
- PASS: default-deny present in ztd-data
- PASS: ambient host-probe exception present (mode ambient, Cilium)

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
  Name:	tsa-policy-engine.ztd-mgmt.svc.cluster.local Address: 10.96.210.150  

## 6. Mesh mode is one label

- PASS: upgrade to sidecar mode returns 0

```
NAME STATUS AGE PLANE DATAPLANE-MODE ISTIO-INJECTION
ztd-mgmt Active 36s management enabled
ztd-data Active 36s data enabled
```

- PASS: sidecar mode: istio-injection=enabled on the plane namespaces
- PASS: sidecar mode: the ambient label is gone
- PASS: sidecar mode: the ambient host-probe exception is gone
- PASS: sidecar mode: cross-plane call still DENIED
  → denied(28)
- PASS: sidecar mode: matrix lane still ALLOWED
  → 200
- PASS: back to ambient mode returns 0
- PASS: ambient label restored

## 7. The management plane's API lane under Cilium

Cilium does not select an API server that runs on a node by its address, so with Cilium the lane is a CiliumNetworkPolicy to the kube-apiserver entity and needs no CIDR. Any HTTP code means the call reached the API server; denied(28), a timeout, means the policy dropped it; any other failure is an error.

- PASS: lane off: management pod → API server DENIED
  → denied(28)
- PASS: upgrade with the API lane on and no CIDR returns 0
- PASS: the lane is a CiliumNetworkPolicy to the kube-apiserver entity
- PASS: no address lane is rendered without a CIDR
- PASS: lane on: management pod → API server ALLOWED
  → 200
- PASS: lane on: data-plane pod → API server still DENIED (the lane is management-plane only)
  → denied(28)
- PASS: lane off again returns 0
- PASS: lane off again: management pod → API server DENIED
  → denied(28)

## 8. Guards that refuse a wrong configuration: the lint and render steps of the CI chart gate

The CI job runs `helm lint` and then `helm template`. Schema violations fail both steps; a `fail` call in a template fails the render step only, because lint mode renders `fail` as a no-op by design.

- PASS: no zone file: lint refused by the schema
- PASS: no zone file: render refused by the schema
  at '/zone/storageClass': minLength: got 0, want 1
- PASS: unknown mesh mode: lint refused by the schema
- PASS: unknown mesh mode: render refused
  at '/mesh/mode': value must be one of 'ambient', 'sidecar', 'none'
- PASS: kubeApi lane without cidrs and without Cilium: lint passes, as lint mode ignores the template guard; the render step below is the one that catches it
- PASS: kubeApi lane without cidrs and without Cilium: render refused
  networkPolicy.kubeApi.enabled needs at least one entry in networkPolicy.kubeApi.cidrs; an empty destination would open every address

## 9. Teardown leaves no plane namespace behind

- PASS: helm uninstall returns 0
  release "ztd" uninstalled
- PASS: plane namespaces are gone
- PASS: cluster-wide Cilium exception is gone
- PASS: no hook resource left behind (hook-succeeded policy)
  the release namespace `ztd-system` remains, as expected: it was created by --create-namespace and is not owned by the release


## Result

All checks passed.
