# Plane-separation reachability evidence (2026-11-21T20:28:03Z)

Cluster kind: **kind**, the local cluster from `scripts/dev/kind-cilium-up.sh` with Cilium chained.

Cluster context `kind-ztd-rt`, zone file `deployment/helm/ztd/ci/values.yaml` (trust domain `kind.facis-ztd.local`), the zone already installed (the run installs and uninstalls nothing). Commit `895531dc7261b9e30ea37c7369416421475d9d69`, tree dirty: false. Run id `r9d6f4e5b`.

Layers. **Network layer**: a drop (`denied(28)` or `denied(56)` from curl, or a meshed caller's `503 ... reset reason: connection timeout`) and no new denial line in the destination's proxy, with the drop Hubble recorded for the flow wherever the caller node's Cilium agent offers Hubble (a timeout alone also follows from an address no pod holds any more); a refusal (`denied(7)`, any other `503`) counts only with the drop Hubble recorded for the flow, which is cited whenever the node's Cilium agent offers it. **Mesh layer**: the destination's proxy refused the caller's identity under the mesh default deny (`403 RBAC: access denied` for HTTP) and wrote one denial line with both SPIFFE IDs. **Control channel**: the legitimate caller served over mutual TLS, the destination principal read from the caller's proxy. **n/a**: a destination without a proxy has no mesh layer. **Declared**: istiod's xDS port, open to the meshed plane namespaces under a declared opening (proposed; `docs/specifications.md`), recorded and not counted.


## 0. Preconditions

- PASS: pod-to-pod routing keeps a pod's address between nodes: no native routing with masquerading on and a node's pod range outside ipv4-native-routing-cidr (a pod on another node would reach a pod as remote-node, not as itself)
  routing-mode=tunnel tunnel-protocol=vxlan enable-ipv4-masquerade=true enable-bpf-masquerade=false (absent: Cilium's default): pod addresses are kept between nodes
- PASS: the SPIRE agent runs on at least one node, where the stand-ins are placed
  

```
NAME STATUS ROLES AGE VERSION INTERNAL-IP EXTERNAL-IP OS-IMAGE KERNEL-VERSION CONTAINER-RUNTIME
ztd-rt-control-plane Ready control-plane 27m v1.35.8 <address> <none> Debian GNU/Linux 13 (trixie) 6.10.14-linuxkit containerd://2.3.4
ztd-rt-worker Ready <none> 27m v1.35.8 <address> <none> Debian GNU/Linux 13 (trixie) 6.10.14-linuxkit containerd://2.3.4
ztd-rt-worker2 Ready <none> 27m v1.35.8 <address> <none> Debian GNU/Linux 13 (trixie) 6.10.14-linuxkit containerd://2.3.4
```


## 1. The rows: the rendered umbrella against section 6

- PASS: the umbrella renders with the zone file under test
  level=INFO msg="found symbolic link in path. Contents of linked file included and used" path=<repository>/deployment/helm/ztd/files/admission/constraints resolved=<repository>/deployment/admission/constraints
- PASS: the allowMatrix rows are read from the zone document and the rendered NetworkPolicy pairs
  pdp-adapter-to-tsa atls-gateway-to-cmcd atls-gateway-to-tcr workloads-to-otel-collector backend-to-verification-service
- PASS: section 6's allow matrix is read by heading (scripts/lib/doc-table.sh)
  8 rows
- PASS: the two row sources agree and every row has a probe
  8 rows of section 6 match the 5 allowMatrix rows and the verifier's probes
- PASS: section 6's management plane -> data plane table is read by heading
  1 rows
- PASS: the management plane -> data plane direction: section 6 disposes the management plane -> data plane direction as one DENY row, management-to-data
- PASS: the rendered umbrella: no rule admits a connection from a management-plane namespace (ztd-mgmt, spire-system, istio-system, ztd-otel-node) to a data-plane namespace (ztd-data)
  the expected outcome of every management plane -> data plane probe is a denial at both layers

## 2. Snapshot of the zone's policies

46 policies and the admission policy's spec read (kind, name, UID, resourceVersion); compared at the end.
- PASS: the data-plane namespaces are found by their label ztd.facis.io/plane=data
  ztd-data
- PASS: the cluster's policies: no rule admits a connection from a management-plane namespace (istio-system, spire-system, ztd-mgmt, ztd-otel-node) to a data-plane namespace (ztd-data)

## 3. Destinations: real or stand-in

- row pdp-adapter-to-tsa: no pod matching the row's selector `app.kubernetes.io/name=tsa-policy-engine` under service account `tsa-policy-engine` runs in ztd-mgmt: a **stand-in** from `fixtures/rows/pdp-adapter-to-tsa.yaml`
- row atls-gateway-to-cmcd: no pod matching the row's selector `app.kubernetes.io/name=cmcd` under service account `cmcd` runs in ztd-mgmt: a **stand-in** from `fixtures/rows/atls-gateway-to-cmcd.yaml`
- row atls-gateway-to-tcr: no pod matching the row's selector `app.kubernetes.io/name=tcr` under service account `tcr` runs in ztd-mgmt: a **stand-in** from `fixtures/rows/atls-gateway-to-tcr.yaml`
- row workloads-to-otel-collector: no pod matching the row's selector `app.kubernetes.io/name=otel-collector` under service account `otel-collector` runs in ztd-mgmt: a **stand-in** from `fixtures/rows/workloads-to-otel-collector.yaml`
- row backend-to-verification-service: no pod matching the row's selector `app.kubernetes.io/name=verification-service` under service account `verification-service` runs in ztd-mgmt: a **stand-in** from `fixtures/rows/backend-to-verification-service.yaml`
- TSPA: the zone runs none: a **stand-in** from `fixtures/tspa.yaml`
- data plane ztd-data: runs a meshed Service, probed as **real** from the management plane
- PASS: the stand-in destinations are created
  
- PASS: the stand-in destinations in ztd-mgmt are Ready

## 4. The probe plan

- PASS: the probe plan is built from the zone's namespaces, Services, EndpointSlices and pods
Data-plane namespaces: ztd-data. Management-plane namespaces searched for destinations: istio-system, spire-system, ztd-mgmt, ztd-otel-node.

Destinations of the DENY and catch-all rows (every Service with ready endpoints in those namespaces that no allowMatrix row names):


```
catch-all     istio-system/istiod                            real      no proxy  ports 8080,15010,15012,15014,15017
spire-server  spire-system/spire-controller-manager-webhook  real      no proxy  ports 8080,8081,8082,8083,9443,9988
spire-server  spire-system/spire-server                      real      no proxy  ports 
spire-server  spire-system/spire-server-metrics              real      no proxy  ports 
tspa          ztd-mgmt/tspa                                  stand-in  meshed    ports 8080
```

Management components section 6 names by example and the zone does not run (reported absent): estserver, openbao, argocd, harbor.

- PASS: the management-plane namespaces the management plane -> data plane direction is probed from are found
  istio-system spire-system ztd-mgmt ztd-otel-node; with injection: ztd-data ztd-mgmt
Destinations of the management plane -> data plane direction (every Service with ready endpoints in a data-plane namespace):


```
management-to-data  ztd-data/ztd-connector-gateway  real  meshed  ports 8080
```

- PASS: the management plane -> data plane direction has a destination in the data plane
  1 Service(s)

## 5. Callers and probers

- PASS: the meshed probers (mesh-prober-<i>, one per node with a SPIRE agent, in each probing namespace with injection) are created
  
- PASS: the proxy-less probes of the namespaces without injection are created as written
  namespace: istio-system namespace: spire-system namespace: ztd-otel-node; 
- PASS: as written, each proxy-less probe is refused by the capture rule of proxy-takes-spire-socket
  4 of 4 refused
- PASS: with the capture validation (index 2) lifted, the proxy-less probes (probe-<i>, one per node) are created
- PASS: the admission policy is put back unchanged and refuses the probes again, five times in a row
  refusals held 5 of 5
- PASS: every caller and prober of the run in ztd-data is Ready
- PASS: every caller and prober of the run in istio-system is Ready
- PASS: every caller and prober of the run in spire-system is Ready
- PASS: every caller and prober of the run in ztd-mgmt is Ready
- PASS: every caller and prober of the run in ztd-otel-node is Ready

```
NAME READY STATUS RESTARTS AGE IP NODE NOMINATED NODE READINESS GATES
probe-0 1/1 Running 0 2m41s <address> ztd-rt-worker <none> <none>
probe-1 1/1 Running 0 2m41s <address> ztd-rt-worker2 <none> <none>
NAME READY STATUS RESTARTS AGE IP NODE NOMINATED NODE READINESS GATES
probe-0 1/1 Running 0 2m42s <address> ztd-rt-worker <none> <none>
probe-1 1/1 Running 0 2m41s <address> ztd-rt-worker2 <none> <none>
NAME READY STATUS RESTARTS AGE IP NODE NOMINATED NODE READINESS GATES
atls-gateway-to-cmcd-caller 2/2 Running 0 2m52s <address> ztd-rt-worker <none> <none>
atls-gateway-to-cmcd-impostor 2/2 Running 0 2m52s <address> ztd-rt-worker <none> <none>
atls-gateway-to-cmcd-unlabelled 2/2 Running 0 2m52s <address> ztd-rt-worker <none> <none>
atls-gateway-to-tcr-caller 2/2 Running 0 2m48s <address> ztd-rt-worker <none> <none>
atls-gateway-to-tcr-impostor 2/2 Running 0 2m48s <address> ztd-rt-worker <none> <none>
atls-gateway-to-tcr-unlabelled 2/2 Running 0 2m48s <address> ztd-rt-worker <none> <none>
backend-to-verification-service-caller 2/2 Running 0 2m44s <address> ztd-rt-worker <none> <none>
backend-to-verification-service-impostor 2/2 Running 0 2m44s <address> ztd-rt-worker <none> <none>
backend-to-verification-service-unlabelled 2/2 Running 0 2m44s <address> ztd-rt-worker <none> <none>
mesh-prober-0 2/2 Running 0 2m43s <address> ztd-rt-worker <none> <none>
mesh-prober-1 2/2 Running 0 2m43s <address> ztd-rt-worker2 <none> <none>
pdp-adapter-to-tsa-caller 2/2 Running 0 2m54s <address> ztd-rt-worker <none> <none>
pdp-adapter-to-tsa-impostor 2/2 Running 0 2m54s <address> ztd-rt-worker <none> <none>
pdp-adapter-to-tsa-unlabelled 2/2 Running 0 2m54s <address> ztd-rt-worker <none> <none>
probe-0 1/1 Running 0 2m36s <address> ztd-rt-worker <none> <none>
probe-1 1/1 Running 0 2m36s <address> ztd-rt-worker2 <none> <none>
workloads-to-otel-collector-caller 2/2 Running 0 2m46s <address> ztd-rt-worker <none> <none>
NAME READY STATUS RESTARTS AGE IP NODE NOMINATED NODE READINESS GATES
cmcd 2/2 Running 0 3m14s <address> ztd-rt-worker2 <none> <none>
mesh-prober-0 2/2 Running 0 2m43s <address> ztd-rt-worker <none> <none>
mesh-prober-1 2/2 Running 0 2m42s <address> ztd-rt-worker2 <none> <none>
otel-collector 2/2 Running 0 3m13s <address> ztd-rt-worker2 <none> <none>
probe-0 1/1 Running 0 2m35s <address> ztd-rt-worker <none> <none>
probe-1 1/1 Running 0 2m35s <address> ztd-rt-worker2 <none> <none>
tcr 2/2 Running 0 3m14s <address> ztd-rt-worker2 <none> <none>
tsa-policy-engine 2/2 Running 0 3m15s <address> ztd-rt-worker2 <none> <none>
tspa 2/2 Running 0 3m11s <address> ztd-rt-worker2 <none> <none>
verification-service 2/2 Running 0 3m12s <address> ztd-rt-worker2 <none> <none>
NAME READY STATUS RESTARTS AGE IP NODE NOMINATED NODE READINESS GATES
probe-0 1/1 Running 0 2m41s <address> ztd-rt-worker <none> <none>
probe-1 1/1 Running 0 2m41s <address> ztd-rt-worker2 <none> <none>
```


## 6. The control channels of the management plane

- PASS: control channel: the SPIRE agent of node ztd-rt-worker is attested to the server (and not banned)
  attested agents for the node: 1
- PASS: control channel: the SPIRE agent of node ztd-rt-worker2 is attested to the server (and not banned)
  attested agents for the node: 1
- PASS: control channel: every SPIRE agent is attested
  2 agents; not attested: none
- PASS: control channel: every proxy of the data-plane namespaces holds a configuration SYNCED with istiod (a type istiod never sent is NOT_SENT)
  proxies 16; not SYNCED: none

## 7. ALLOW rows

- PASS: pdp-adapter-to-tsa from ztd-data: legitimate caller (pdp-adapter-to-tsa-caller -> tsa-policy-engine.ztd-mgmt.svc:8080), expected 200 over mTLS, destination principal spiffe://kind.facis-ztd.local/ns/ztd-mgmt/sa/tsa-policy-engine, read 200 tsa-policy-engine-8080; layer control channel
  the caller's proxy counted 1 request(s) to destination_principal spiffe://kind.facis-ztd.local/ns/ztd-mgmt/sa/tsa-policy-engine (istio_requests_total, reporter source)
- PASS: pdp-adapter-to-tsa from ztd-data: impostor (row labels, service account pdp-adapter-to-tsa-impostor) (pdp-adapter-to-tsa-impostor -> tsa-policy-engine.ztd-mgmt.svc:8080), expected 403 RBAC and a denial line with both SPIFFE IDs, read 403 RBAC: access denied; layer mesh
  {"authority":"tsa-policy-engine.ztd-mgmt.svc:8080","code":403,"destination":"spiffe://kind.facis-ztd.local/ns/ztd-mgmt/sa/tsa-policy-engine","detail":"rbac_access_denied_matched_policy[none]","flags":"-","source":"spiffe://kind.facis-ztd.local/ns/ztd-data/sa/pdp-adapter-to-tsa-impostor","termination":null,"time":"2026-11-21T20:31:51.629Z"}
- PASS: pdp-adapter-to-tsa from ztd-data: unlabelled (service account pdp-adapter, no row labels) (pdp-adapter-to-tsa-unlabelled -> tsa-policy-engine.ztd-mgmt.svc:8080), expected dropped, no denial line, read denied(28); layer network
  Hubble drop: Nov 21 20:32:03.441: ztd-data/pdp-adapter-to-tsa-unlabelled:35504 (ID:4866) <> ztd-mgmt/tsa-policy-engine:8080 (ID:29216) Policy denied DROPPED (TCP Flags: SYN); no new denial line of spiffe://kind.facis-ztd.local/ns/ztd-data/sa/pdp-adapter in the destination's proxy
- PASS: atls-gateway-to-cmcd from ztd-data: legitimate caller (atls-gateway-to-cmcd-caller -> cmcd.ztd-mgmt.svc:8080), expected 200 over mTLS, destination principal spiffe://kind.facis-ztd.local/ns/ztd-mgmt/sa/cmcd, read 200 cmcd-8080; layer control channel
  the caller's proxy counted 1 request(s) to destination_principal spiffe://kind.facis-ztd.local/ns/ztd-mgmt/sa/cmcd (istio_requests_total, reporter source)
- PASS: atls-gateway-to-cmcd from ztd-data: impostor (row labels, service account atls-gateway-to-cmcd-impostor) (atls-gateway-to-cmcd-impostor -> cmcd.ztd-mgmt.svc:8080), expected 403 RBAC and a denial line with both SPIFFE IDs, read 403 RBAC: access denied; layer mesh
  {"authority":"cmcd.ztd-mgmt.svc:8080","code":403,"destination":"spiffe://kind.facis-ztd.local/ns/ztd-mgmt/sa/cmcd","detail":"rbac_access_denied_matched_policy[none]","flags":"-","source":"spiffe://kind.facis-ztd.local/ns/ztd-data/sa/atls-gateway-to-cmcd-impostor","termination":null,"time":"2026-11-21T20:32:54.000Z"}
- PASS: atls-gateway-to-cmcd from ztd-data: unlabelled (service account atls-gateway, no row labels) (atls-gateway-to-cmcd-unlabelled -> cmcd.ztd-mgmt.svc:8080), expected dropped, no denial line, read denied(28); layer network
  Hubble drop: Nov 21 20:33:07.857: ztd-data/atls-gateway-to-cmcd-unlabelled:40578 (ID:3989) <> ztd-mgmt/cmcd:8080 (ID:952) Policy denied DROPPED (TCP Flags: SYN); no new denial line of spiffe://kind.facis-ztd.local/ns/ztd-data/sa/atls-gateway in the destination's proxy
- PASS: atls-gateway-to-tcr from ztd-data: legitimate caller (atls-gateway-to-tcr-caller -> tcr.ztd-mgmt.svc:8080), expected 200 over mTLS, destination principal spiffe://kind.facis-ztd.local/ns/ztd-mgmt/sa/tcr, read 200 tcr-8080; layer control channel
  the caller's proxy counted 1 request(s) to destination_principal spiffe://kind.facis-ztd.local/ns/ztd-mgmt/sa/tcr (istio_requests_total, reporter source)
- PASS: atls-gateway-to-tcr from ztd-data: impostor (row labels, service account atls-gateway-to-tcr-impostor) (atls-gateway-to-tcr-impostor -> tcr.ztd-mgmt.svc:8080), expected 403 RBAC and a denial line with both SPIFFE IDs, read 403 RBAC: access denied; layer mesh
  {"authority":"tcr.ztd-mgmt.svc:8080","code":403,"destination":"spiffe://kind.facis-ztd.local/ns/ztd-mgmt/sa/tcr","detail":"rbac_access_denied_matched_policy[none]","flags":"-","source":"spiffe://kind.facis-ztd.local/ns/ztd-data/sa/atls-gateway-to-tcr-impostor","termination":null,"time":"2026-11-21T20:33:44.064Z"}
- PASS: atls-gateway-to-tcr from ztd-data: unlabelled (service account atls-gateway, no row labels) (atls-gateway-to-tcr-unlabelled -> tcr.ztd-mgmt.svc:8080), expected dropped, no denial line, read denied(28); layer network
  Hubble drop: Nov 21 20:33:59.596: ztd-data/atls-gateway-to-tcr-unlabelled:39980 (ID:18947) <> ztd-mgmt/tcr:8080 (ID:63991) Policy denied DROPPED (TCP Flags: SYN); no new denial line of spiffe://kind.facis-ztd.local/ns/ztd-data/sa/atls-gateway in the destination's proxy
- PASS: workloads-to-otel-collector from ztd-data: legitimate caller (workloads-to-otel-collector-caller -> otel-collector.ztd-mgmt.svc:4317), expected 200 over mTLS, destination principal spiffe://kind.facis-ztd.local/ns/ztd-mgmt/sa/otel-collector, read 200 otel-collector-4317; layer control channel
  the caller's proxy counted 1 request(s) to destination_principal spiffe://kind.facis-ztd.local/ns/ztd-mgmt/sa/otel-collector (istio_requests_total, reporter source)
- PASS: workloads-to-otel-collector from ztd-data: legitimate caller (workloads-to-otel-collector-caller -> otel-collector.ztd-mgmt.svc:4318), expected 200 over mTLS, destination principal spiffe://kind.facis-ztd.local/ns/ztd-mgmt/sa/otel-collector, read 200 otel-collector-4318; layer control channel
  the caller's proxy counted 1 request(s) to destination_principal spiffe://kind.facis-ztd.local/ns/ztd-mgmt/sa/otel-collector (istio_requests_total, reporter source)
- N/A: workloads-to-otel-collector from ztd-data: impostor (- -> otel-collector.ztd-mgmt.svc), expected n/a, read not probed; layer mesh
  the row admits every identity of ztd-data, so no identity is an impostor
- N/A: workloads-to-otel-collector from ztd-data: unlabelled (- -> otel-collector.ztd-mgmt.svc), expected n/a, read not probed; layer network
  the row selects every pod of ztd-data, so no pod lacks its labels
- PASS: workloads-to-otel-collector from ztd-data: off the row's ports (workloads-to-otel-collector-caller -> otel-collector.ztd-mgmt.svc:8080), expected dropped (the row admits 4317 and 4318 only), no denial line, read denied(28); layer network
  Hubble drop: Nov 21 20:35:25.484: ztd-data/workloads-to-otel-collector-caller:34188 (ID:2844) <> ztd-mgmt/otel-collector:8080 (ID:4332) Policy denied DROPPED (TCP Flags: SYN); no new denial line of spiffe://kind.facis-ztd.local/ns/ztd-data/sa/workloads-to-otel-collector-caller in the destination's proxy
- PASS: backend-to-verification-service from ztd-data: legitimate caller (backend-to-verification-service-caller -> verification-service.ztd-mgmt.svc:8080), expected 200 over mTLS, destination principal spiffe://kind.facis-ztd.local/ns/ztd-mgmt/sa/verification-service, read 200 verification-service-8080; layer control channel
  the caller's proxy counted 1 request(s) to destination_principal spiffe://kind.facis-ztd.local/ns/ztd-mgmt/sa/verification-service (istio_requests_total, reporter source)
- PASS: backend-to-verification-service from ztd-data: impostor (row labels, service account backend-to-verification-service-impostor) (backend-to-verification-service-impostor -> verification-service.ztd-mgmt.svc:8080), expected 403 RBAC and a denial line with both SPIFFE IDs, read 403 RBAC: access denied; layer mesh
  {"authority":"verification-service.ztd-mgmt.svc:8080","code":403,"destination":"spiffe://kind.facis-ztd.local/ns/ztd-mgmt/sa/verification-service","detail":"rbac_access_denied_matched_policy[none]","flags":"-","source":"spiffe://kind.facis-ztd.local/ns/ztd-data/sa/backend-to-verification-service-impostor","termination":null,"time":"2026-11-21T20:36:09.919Z"}
- PASS: backend-to-verification-service from ztd-data: unlabelled (service account backend, no row labels) (backend-to-verification-service-unlabelled -> verification-service.ztd-mgmt.svc:8080), expected dropped, no denial line, read denied(28); layer network
  Hubble drop: Nov 21 20:36:43.030: ztd-data/backend-to-verification-service-unlabelled:33056 (ID:7127) <> ztd-mgmt/verification-service:8080 (ID:12893) Policy denied DROPPED (TCP Flags: SYN); no new denial line of spiffe://kind.facis-ztd.local/ns/ztd-data/sa/backend in the destination's proxy

## 8. DENY rows and the catch-all row

- PASS: catch-all from ztd-data: TCP, proxy-less (probe-1 -> istio-system/istiod (istiod-84f7f755d9-dxsms):8080), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:37:07.538: ztd-data/probe-1:51302 (ID:24050) <> istio-system/istiod-84f7f755d9-dxsms:8080 (ID:52944) Policy denied DROPPED (TCP Flags: SYN); the destination has no proxy to write a denial line
- PASS: catch-all from ztd-data: TCP, proxy-less (probe-1 -> istio-system/istiod (istiod-84f7f755d9-dxsms):15010), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:37:14.812: ztd-data/probe-1:41112 (ID:24050) <> istio-system/istiod-84f7f755d9-dxsms:15010 (ID:52944) Policy denied DROPPED (TCP Flags: SYN); the destination has no proxy to write a denial line
- DECLARED: catch-all from ztd-data: TCP to istiod's xDS port (probe-1 -> istio-system/istiod (istiod-84f7f755d9-dxsms):15012), expected open, declared opening (proposed): docs/specifications.md, ZT-55 xDS entry, read connected; layer network
  the meshControlPlane opening admits the meshed plane namespaces to 15012; cited, not counted
- PASS: catch-all from ztd-data: TCP, proxy-less (probe-1 -> istio-system/istiod (istiod-84f7f755d9-dxsms):15014), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:37:28.884: ztd-data/probe-1:45512 (ID:24050) <> istio-system/istiod-84f7f755d9-dxsms:15014 (ID:52944) Policy denied DROPPED (TCP Flags: SYN); the destination has no proxy to write a denial line
- PASS: catch-all from ztd-data: TCP, proxy-less (probe-1 -> istio-system/istiod (istiod-84f7f755d9-dxsms):15017), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:37:45.153: ztd-data/probe-1:38326 (ID:24050) <> istio-system/istiod-84f7f755d9-dxsms:15017 (ID:52944) Policy denied DROPPED (TCP Flags: SYN); the destination has no proxy to write a denial line
- N/A: catch-all from ztd-data: mesh layer (- -> istio-system/istiod), expected n/a, read not probed; layer mesh
  mesh: n/a, the destination has no proxy (the SPIRE and Istio control planes are not meshed)
- PASS: spire-server from ztd-data: TCP, proxy-less (probe-0 -> spire-system/spire-controller-manager-webhook (spire-server-0):8080), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:37:55.284: ztd-data/probe-0:39184 (ID:31570) <> spire-system/spire-server-0:8080 (ID:37509) Policy denied DROPPED (TCP Flags: SYN); the destination has no proxy to write a denial line
- PASS: spire-server from ztd-data: TCP, proxy-less (probe-0 -> spire-system/spire-controller-manager-webhook (spire-server-0):8081), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:38:04.940: ztd-data/probe-0:41958 (ID:31570) <> spire-system/spire-server-0:8081 (ID:37509) Policy denied DROPPED (TCP Flags: SYN); the destination has no proxy to write a denial line
- PASS: spire-server from ztd-data: TCP, proxy-less (probe-0 -> spire-system/spire-controller-manager-webhook (spire-server-0):8082), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:38:14.391: ztd-data/probe-0:50896 (ID:31570) <> spire-system/spire-server-0:8082 (ID:37509) Policy denied DROPPED (TCP Flags: SYN); the destination has no proxy to write a denial line
- PASS: spire-server from ztd-data: TCP, proxy-less (probe-0 -> spire-system/spire-controller-manager-webhook (spire-server-0):8083), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:38:22.388: ztd-data/probe-0:60184 (ID:31570) <> spire-system/spire-server-0:8083 (ID:37509) Policy denied DROPPED (TCP Flags: SYN); the destination has no proxy to write a denial line
- PASS: spire-server from ztd-data: TCP, proxy-less (probe-0 -> spire-system/spire-controller-manager-webhook (spire-server-0):9443), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:38:31.637: ztd-data/probe-0:60678 (ID:31570) <> spire-system/spire-server-0:9443 (ID:37509) Policy denied DROPPED (TCP Flags: SYN); the destination has no proxy to write a denial line
- PASS: spire-server from ztd-data: TCP, proxy-less (probe-0 -> spire-system/spire-controller-manager-webhook (spire-server-0):9988), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:38:41.412: ztd-data/probe-0:45670 (ID:31570) <> spire-system/spire-server-0:9988 (ID:37509) Policy denied DROPPED (TCP Flags: SYN); the destination has no proxy to write a denial line
- N/A: spire-server from ztd-data: mesh layer (- -> spire-system/spire-controller-manager-webhook), expected n/a, read not probed; layer mesh
  mesh: n/a, the destination has no proxy (the SPIRE and Istio control planes are not meshed)
- N/A: spire-server from ztd-data: mesh layer (- -> spire-system/spire-server), expected n/a, read not probed; layer mesh
  mesh: n/a, the destination has no proxy (the SPIRE and Istio control planes are not meshed)
- N/A: spire-server from ztd-data: mesh layer (- -> spire-system/spire-server-metrics), expected n/a, read not probed; layer mesh
  mesh: n/a, the destination has no proxy (the SPIRE and Istio control planes are not meshed)
- PASS: tspa from ztd-data: TCP, proxy-less (probe-0 -> ztd-mgmt/tspa (tspa):8080), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:38:51.557: ztd-data/probe-0:35412 (ID:31570) <> ztd-mgmt/tspa:8080 (ID:17492) Policy denied DROPPED (TCP Flags: SYN); no new denial line in the destination's proxy
- PASS: tspa from ztd-data: behind a probe-scoped opening (mesh-prober-0 -> ztd-mgmt/tspa:8080), expected refused by the destination's proxy, a denial line with both SPIFFE IDs, the opening removed, read 403 RBAC: access denied; layer mesh
  {"authority":"tspa.ztd-mgmt.svc:8080","code":403,"destination":"spiffe://kind.facis-ztd.local/ns/ztd-mgmt/sa/tspa","detail":"rbac_access_denied_matched_policy[none]","flags":"-","source":"spiffe://kind.facis-ztd.local/ns/ztd-data/sa/mesh-prober","termination":null,"time":"2026-11-21T20:39:04.405Z"}; opening removed: yes

## 9. Management plane → data plane

Section 6's row `management-to-data`: DENY at both layers by the default deny alone; the rule was checked against the rendered umbrella (section 1) and the cluster's policies (section 2). Probed from: istio-system spire-system ztd-mgmt ztd-otel-node.

- PASS: management-to-data from istio-system: TCP, proxy-less (probe-0 -> ztd-data/ztd-connector-gateway (ztd-connector-gateway-785c9dcc66-p6m25):8080), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:39:14.106: istio-system/probe-0:36890 (ID:19611) <> ztd-data/ztd-connector-gateway-785c9dcc66-p6m25:8080 (ID:63822) Policy denied DROPPED (TCP Flags: SYN); no new denial line in the destination's proxy
- PASS: management-to-data from istio-system: plain text, no identity, behind a probe-scoped opening (probe-0 -> ztd-data/ztd-connector-gateway-785c9dcc66-p6m25:8080), expected reset by the destination's proxy (mutual TLS STRICT), the opening removed, read denied(56); layer mesh
  the network let the request through (Hubble: Nov 21 20:39:27.631: istio-system/probe-0:58068 (ID:19611) -> ztd-data/ztd-connector-gateway-785c9dcc66-p6m25:8080 (ID:63822) to-overlay FORWARDED (TCP Flags: ACK, PSH)) and the destination's proxy reset it: mutual TLS STRICT refuses a caller without a certificate; mutual TLS mode in force: STRICT; opening removed: yes
- PASS: management-to-data from spire-system: TCP, proxy-less (probe-0 -> ztd-data/ztd-connector-gateway (ztd-connector-gateway-785c9dcc66-p6m25):8080), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:39:33.173: spire-system/probe-0:42152 (ID:44323) <> ztd-data/ztd-connector-gateway-785c9dcc66-p6m25:8080 (ID:63822) Policy denied DROPPED (TCP Flags: SYN); no new denial line in the destination's proxy
- PASS: management-to-data from spire-system: plain text, no identity, behind a probe-scoped opening (probe-0 -> ztd-data/ztd-connector-gateway-785c9dcc66-p6m25:8080), expected reset by the destination's proxy (mutual TLS STRICT), the opening removed, read denied(56); layer mesh
  the network let the request through (Hubble: Nov 21 20:40:03.727: spire-system/probe-0:48282 (ID:44323) -> ztd-data/ztd-connector-gateway-785c9dcc66-p6m25:8080 (ID:63822) to-overlay FORWARDED (TCP Flags: ACK, PSH)) and the destination's proxy reset it: mutual TLS STRICT refuses a caller without a certificate; mutual TLS mode in force: STRICT; opening removed: yes
- PASS: management-to-data from ztd-mgmt: TCP, proxy-less (probe-0 -> ztd-data/ztd-connector-gateway (ztd-connector-gateway-785c9dcc66-p6m25):8080), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:40:19.083: ztd-mgmt/probe-0:47444 (ID:10955) <> ztd-data/ztd-connector-gateway-785c9dcc66-p6m25:8080 (ID:63822) Policy denied DROPPED (TCP Flags: SYN); no new denial line in the destination's proxy
- PASS: management-to-data from ztd-mgmt: behind a probe-scoped opening (mesh-prober-0 -> ztd-data/ztd-connector-gateway:8080), expected refused by the destination's proxy, a denial line with both SPIFFE IDs, the opening removed, read 403 RBAC: access denied; layer mesh
  {"authority":"ztd-connector-gateway.ztd-data.svc:8080","code":403,"destination":"spiffe://kind.facis-ztd.local/ns/ztd-data/sa/ztd-connector-gateway","detail":"rbac_access_denied_matched_policy[none]","flags":"-","source":"spiffe://kind.facis-ztd.local/ns/ztd-mgmt/sa/mesh-prober","termination":null,"time":"2026-11-21T20:40:34.869Z"}; opening removed: yes
- PASS: management-to-data from ztd-otel-node: TCP, proxy-less (probe-0 -> ztd-data/ztd-connector-gateway (ztd-connector-gateway-785c9dcc66-p6m25):8080), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:40:42.344: ztd-otel-node/probe-0:53902 (ID:37901) <> ztd-data/ztd-connector-gateway-785c9dcc66-p6m25:8080 (ID:63822) Policy denied DROPPED (TCP Flags: SYN); no new denial line in the destination's proxy
- PASS: management-to-data from ztd-otel-node: plain text, no identity, behind a probe-scoped opening (probe-0 -> ztd-data/ztd-connector-gateway-785c9dcc66-p6m25:8080), expected reset by the destination's proxy (mutual TLS STRICT), the opening removed, read denied(56); layer mesh
  the network let the request through (Hubble: Nov 21 20:40:51.713: ztd-otel-node/probe-0:50482 (ID:37901) -> ztd-data/ztd-connector-gateway-785c9dcc66-p6m25:8080 (ID:63822) to-overlay FORWARDED (TCP Flags: ACK, PSH)) and the destination's proxy reset it: mutual TLS STRICT refuses a caller without a certificate; mutual TLS mode in force: STRICT; opening removed: yes

## 10. Cleanup

- PASS: no fixture, prober or opening of the run remains
  none
- PASS: the zone's policies equal the snapshot taken at the start (NetworkPolicy, CiliumNetworkPolicy, AuthorizationPolicy, the admission policy's spec)
  

## The matrix

| Row | ZT-55 role | Caller's namespace | Legitimate caller | Network layer | Mesh layer | Destination |
|---|---|---|---|---|---|---|
| pdp-adapter-to-tsa | Policy Engine | ztd-data | pdp-adapter-to-tsa-caller (on ztd-rt-worker; destination on ztd-rt-worker2): :8080 200 | unlabelled (service account pdp-adapter, no row labels), tsa-policy-engine.ztd-mgmt.svc:8080 denied(28) | impostor (row labels, service account pdp-adapter-to-tsa-impostor), tsa-policy-engine.ztd-mgmt.svc:8080 403 | stand-in |
| atls-gateway-to-cmcd | Attestation (CMC) | ztd-data | atls-gateway-to-cmcd-caller (on ztd-rt-worker; destination on ztd-rt-worker2): :8080 200 | unlabelled (service account atls-gateway, no row labels), cmcd.ztd-mgmt.svc:8080 denied(28) | impostor (row labels, service account atls-gateway-to-cmcd-impostor), cmcd.ztd-mgmt.svc:8080 403 | stand-in |
| atls-gateway-to-tcr | TRAIN (resolution) | ztd-data | atls-gateway-to-tcr-caller (on ztd-rt-worker; destination on ztd-rt-worker2): :8080 200 | unlabelled (service account atls-gateway, no row labels), tcr.ztd-mgmt.svc:8080 denied(28) | impostor (row labels, service account atls-gateway-to-tcr-impostor), tcr.ztd-mgmt.svc:8080 403 | stand-in |
| workloads-to-otel-collector | Observability stack | ztd-data | workloads-to-otel-collector-caller (on ztd-rt-worker; destination on ztd-rt-worker2): :4317 200; :4318 200 | n/a (otel-collector.ztd-mgmt.svc): the row selects every pod of ztd-data, so no pod lacks its labels; off the row's ports, otel-collector.ztd-mgmt.svc:8080 denied(28) | n/a (otel-collector.ztd-mgmt.svc): the row admits every identity of ztd-data, so no identity is an impostor | stand-in |
| backend-to-verification-service | OCM | ztd-data | backend-to-verification-service-caller (on ztd-rt-worker; destination on ztd-rt-worker2): :8080 200 | unlabelled (service account backend, no row labels), verification-service.ztd-mgmt.svc:8080 denied(28) | impostor (row labels, service account backend-to-verification-service-impostor), verification-service.ztd-mgmt.svc:8080 403 | stand-in |
| catch-all | any management-plane destination not listed above | ztd-data | — | TCP, proxy-less, istio-system/istiod (istiod-84f7f755d9-dxsms):8080 denied(28); TCP, proxy-less, istio-system/istiod (istiod-84f7f755d9-dxsms):15010 denied(28); istio-system/istiod (istiod-84f7f755d9-dxsms):15012 open, declared opening (proposed); TCP, proxy-less, istio-system/istiod (istiod-84f7f755d9-dxsms):15014 denied(28); TCP, proxy-less, istio-system/istiod (istiod-84f7f755d9-dxsms):15017 denied(28) | n/a (istio-system/istiod): mesh: n/a, the destination has no proxy (the SPIRE and Istio control planes are not meshed) | real |
| spire-server | SPIRE control plane | ztd-data | — | TCP, proxy-less, spire-system/spire-controller-manager-webhook (spire-server-0):8080 denied(28); TCP, proxy-less, spire-system/spire-controller-manager-webhook (spire-server-0):8081 denied(28); TCP, proxy-less, spire-system/spire-controller-manager-webhook (spire-server-0):8082 denied(28); TCP, proxy-less, spire-system/spire-controller-manager-webhook (spire-server-0):8083 denied(28); TCP, proxy-less, spire-system/spire-controller-manager-webhook (spire-server-0):9443 denied(28); TCP, proxy-less, spire-system/spire-controller-manager-webhook (spire-server-0):9988 denied(28) | n/a (spire-system/spire-controller-manager-webhook): mesh: n/a, the destination has no proxy (the SPIRE and Istio control planes are not meshed); n/a (spire-system/spire-server): mesh: n/a, the destination has no proxy (the SPIRE and Istio control planes are not meshed); n/a (spire-system/spire-server-metrics): mesh: n/a, the destination has no proxy (the SPIRE and Istio control planes are not meshed) | real |
| tspa | TRAIN (publication) | ztd-data | — | TCP, proxy-less, ztd-mgmt/tspa (tspa):8080 denied(28) | behind a probe-scoped opening, ztd-mgmt/tspa:8080 403 | stand-in |
| management-to-data | any data-plane workload (from the management plane) | istio-system | — | TCP, proxy-less, ztd-data/ztd-connector-gateway (ztd-connector-gateway-785c9dcc66-p6m25):8080 denied(28) | plain text, no identity, behind a probe-scoped opening, ztd-data/ztd-connector-gateway-785c9dcc66-p6m25:8080 denied(56) | real |
| management-to-data | any data-plane workload (from the management plane) | spire-system | — | TCP, proxy-less, ztd-data/ztd-connector-gateway (ztd-connector-gateway-785c9dcc66-p6m25):8080 denied(28) | plain text, no identity, behind a probe-scoped opening, ztd-data/ztd-connector-gateway-785c9dcc66-p6m25:8080 denied(56) | real |
| management-to-data | any data-plane workload (from the management plane) | ztd-mgmt | — | TCP, proxy-less, ztd-data/ztd-connector-gateway (ztd-connector-gateway-785c9dcc66-p6m25):8080 denied(28) | behind a probe-scoped opening, ztd-data/ztd-connector-gateway:8080 403 | real |
| management-to-data | any data-plane workload (from the management plane) | ztd-otel-node | — | TCP, proxy-less, ztd-data/ztd-connector-gateway (ztd-connector-gateway-785c9dcc66-p6m25):8080 denied(28) | plain text, no identity, behind a probe-scoped opening, ztd-data/ztd-connector-gateway-785c9dcc66-p6m25:8080 denied(56) | real |

Per row (`matrix.csv`, decided as the Annex scenario decides it):


```
pdp-adapter-to-tsa green
atls-gateway-to-cmcd green
atls-gateway-to-tcr green
workloads-to-otel-collector green
backend-to-verification-service green
catch-all declared
spire-server green
tspa green
management-to-data green
```


## Result

All checks passed.
