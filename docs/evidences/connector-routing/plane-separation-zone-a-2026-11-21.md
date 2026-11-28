# Plane-separation reachability evidence (2026-11-21T20:44:12Z)

Cluster kind: **participant cluster** `zerotrust-a` (zone `zone-a`), confirmed with `ZTD_CONFIRM_CLUSTER=zerotrust-a`. The trust domain `zone-a.trust.invalid` is **interim**: a zone on an interim name is not acceptance evidence. Every IPv4 and IPv6 address of the cluster is replaced by `<address>` in this record.

Cluster context `zerotrust-a`, zone file `deployment/helm/ztd/zones/zone-a.yaml` (trust domain `zone-a.trust.invalid`), the zone already installed (the run installs and uninstalls nothing). Commit `bb6f42c668357b13b02cc0a2f7909899e475de5e`, tree dirty: false. Run id `r16c3870c`.

Layers. **Network layer**: a drop (`denied(28)` or `denied(56)` from curl, or a meshed caller's `503 ... reset reason: connection timeout`) and no new denial line in the destination's proxy, with the drop Hubble recorded for the flow wherever the caller node's Cilium agent offers Hubble (a timeout alone also follows from an address no pod holds any more); a refusal (`denied(7)`, any other `503`) counts only with the drop Hubble recorded for the flow, which is cited whenever the node's Cilium agent offers it. **Mesh layer**: the destination's proxy refused the caller's identity under the mesh default deny (`403 RBAC: access denied` for HTTP) and wrote one denial line with both SPIFFE IDs. **Control channel**: the legitimate caller served over mutual TLS, the destination principal read from the caller's proxy. **n/a**: a destination without a proxy has no mesh layer. **Declared**: istiod's xDS port, open to the meshed plane namespaces under a declared opening (proposed; `docs/specifications.md`), recorded and not counted.


## 0. Preconditions

- PASS: pod-to-pod routing keeps a pod's address between nodes: no native routing with masquerading on and a node's pod range outside ipv4-native-routing-cidr (a pod on another node would reach a pod as remote-node, not as itself)
  routing-mode=tunnel tunnel-protocol=vxlan enable-ipv4-masquerade=true enable-bpf-masquerade=false: pod addresses are kept between nodes
- PASS: the SPIRE agent runs on at least one node, where the stand-ins are placed
  

```
NAME STATUS ROLES AGE VERSION INTERNAL-IP EXTERNAL-IP OS-IMAGE KERNEL-VERSION CONTAINER-RUNTIME
shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-22p4h Ready worker 43d v1.34.7 <address> <none> Garden Linux 2150.7.0 6.18.38-cloud-amd64 containerd://2.2.6
shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-fztmf Ready worker 43d v1.34.7 <address> <none> Garden Linux 2150.7.0 6.18.38-cloud-amd64 containerd://2.2.6
shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-j82gf Ready worker 43d v1.34.7 <address> <none> Garden Linux 2150.7.0 6.18.38-cloud-amd64 containerd://2.2.6
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

63 policies and the admission policy's spec read (kind, name, UID, resourceVersion); compared at the end.
- PASS: the data-plane namespaces are found by their label ztd.facis.io/plane=data
  ztd-data
- PASS: the cluster's policies: no rule admits a connection from a management-plane namespace (istio-system, spire-system, ztd-mgmt) to a data-plane namespace (ztd-data)

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
Data-plane namespaces: ztd-data. Management-plane namespaces searched for destinations: istio-system, spire-system, ztd-mgmt.

Destinations of the DENY and catch-all rows (every Service with ready endpoints in those namespaces that no allowMatrix row names):


```
catch-all     istio-system/istiod                            real      no proxy  ports 8080,15010,15012,15014,15017
spire-server  spire-system/spire-controller-manager-webhook  real      no proxy  ports 8080,8081,8082,8083,9443,9988
spire-server  spire-system/spire-server                      real      no proxy  ports 
tspa          ztd-mgmt/tspa                                  stand-in  meshed    ports 8080
catch-all     ztd-mgmt/ztd-openbao                           real      meshed    ports 8200,8201,8202
catch-all     ztd-mgmt/ztd-openbao-internal                  real      meshed    ports 
```

Management components section 6 names by example and the zone does not run (reported absent): estserver, argocd, harbor.

- PASS: the management-plane namespaces the management plane -> data plane direction is probed from are found
  istio-system spire-system ztd-mgmt; with injection: ztd-data ztd-mgmt
Destinations of the management plane -> data plane direction (every Service with ready endpoints in a data-plane namespace):


```
management-to-data  ztd-data/ztd-connector-gateway  real  meshed  ports 8080
```

- PASS: the management plane -> data plane direction has a destination in the data plane
  1 Service(s)

## 5. Callers and probers

- PASS: the meshed probers (mesh-prober-<i>, one per node with a SPIRE agent, in each probing namespace with injection) are created
  
- PASS: the proxy-less probes of the namespaces without injection are created as written
  namespace: istio-system namespace: spire-system; 
- PASS: as written, each proxy-less probe is refused by the capture rule of proxy-takes-spire-socket
  6 of 6 refused
- PASS: with the capture validation (index 2) lifted, the proxy-less probes (probe-<i>, one per node) are created
- PASS: the admission policy is put back unchanged and refuses the probes again, five times in a row
  refusals held 5 of 5
- PASS: every caller and prober of the run in ztd-data is Ready
- PASS: every caller and prober of the run in istio-system is Ready
- PASS: every caller and prober of the run in spire-system is Ready
- PASS: every caller and prober of the run in ztd-mgmt is Ready

```
NAME READY STATUS RESTARTS AGE IP NODE NOMINATED NODE READINESS GATES
probe-0 1/1 Running 0 34s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-22p4h <none> <none>
probe-1 1/1 Running 0 34s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-fztmf <none> <none>
probe-2 1/1 Running 0 33s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-j82gf <none> <none>
NAME READY STATUS RESTARTS AGE IP NODE NOMINATED NODE READINESS GATES
probe-0 1/1 Running 0 34s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-22p4h <none> <none>
probe-1 1/1 Running 0 34s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-fztmf <none> <none>
probe-2 1/1 Running 0 33s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-j82gf <none> <none>
NAME READY STATUS RESTARTS AGE IP NODE NOMINATED NODE READINESS GATES
atls-gateway-to-cmcd-caller 2/2 Running 0 57s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-fztmf <none> <none>
atls-gateway-to-cmcd-impostor 2/2 Running 0 57s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-fztmf <none> <none>
atls-gateway-to-cmcd-unlabelled 2/2 Running 0 56s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-fztmf <none> <none>
atls-gateway-to-tcr-caller 2/2 Running 0 52s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-22p4h <none> <none>
atls-gateway-to-tcr-impostor 2/2 Running 0 51s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-22p4h <none> <none>
atls-gateway-to-tcr-unlabelled 2/2 Running 0 50s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-22p4h <none> <none>
backend-to-verification-service-caller 2/2 Running 0 41s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-fztmf <none> <none>
backend-to-verification-service-impostor 2/2 Running 0 40s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-fztmf <none> <none>
backend-to-verification-service-unlabelled 2/2 Running 0 40s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-fztmf <none> <none>
mesh-prober-0 2/2 Running 0 39s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-22p4h <none> <none>
mesh-prober-1 2/2 Running 0 38s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-fztmf <none> <none>
mesh-prober-2 2/2 Running 0 38s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-j82gf <none> <none>
pdp-adapter-to-tsa-caller 2/2 Running 0 63s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-22p4h <none> <none>
pdp-adapter-to-tsa-impostor 2/2 Running 0 62s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-22p4h <none> <none>
pdp-adapter-to-tsa-unlabelled 2/2 Running 0 62s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-22p4h <none> <none>
probe-0 1/1 Running 0 27s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-22p4h <none> <none>
probe-1 1/1 Running 0 27s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-fztmf <none> <none>
probe-2 1/1 Running 0 26s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-j82gf <none> <none>
workloads-to-otel-collector-caller 2/2 Running 0 47s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-22p4h <none> <none>
NAME READY STATUS RESTARTS AGE IP NODE NOMINATED NODE READINESS GATES
cmcd 2/2 Running 0 97s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-22p4h <none> <none>
mesh-prober-0 2/2 Running 0 38s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-22p4h <none> <none>
mesh-prober-1 2/2 Running 0 38s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-fztmf <none> <none>
mesh-prober-2 2/2 Running 0 37s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-j82gf <none> <none>
otel-collector 2/2 Running 0 95s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-j82gf <none> <none>
probe-0 1/1 Running 0 27s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-22p4h <none> <none>
probe-1 1/1 Running 0 26s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-fztmf <none> <none>
probe-2 1/1 Running 0 26s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-j82gf <none> <none>
tcr 2/2 Running 0 96s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-fztmf <none> <none>
tsa-policy-engine 2/2 Running 0 98s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-j82gf <none> <none>
tspa 2/2 Running 0 93s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-fztmf <none> <none>
verification-service 2/2 Running 0 94s <address> shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-22p4h <none> <none>
```


## 6. The control channels of the management plane

- PASS: control channel: the SPIRE agent of node shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-22p4h is attested to the server (and not banned)
  attested agents for the node: 1
- PASS: control channel: the SPIRE agent of node shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-fztmf is attested to the server (and not banned)
  attested agents for the node: 1
- PASS: control channel: the SPIRE agent of node shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-j82gf is attested to the server (and not banned)
  attested agents for the node: 1
- PASS: control channel: every SPIRE agent is attested
  3 agents; not attested: none
- PASS: control channel: every proxy of the data-plane namespaces holds a configuration SYNCED with istiod (a type istiod never sent is NOT_SENT)
  proxies 17; not SYNCED: none

## 7. ALLOW rows

- PASS: pdp-adapter-to-tsa from ztd-data: legitimate caller (pdp-adapter-to-tsa-caller -> tsa-policy-engine.ztd-mgmt.svc:8080), expected 200 over mTLS, destination principal spiffe://zone-a.trust.invalid/ns/ztd-mgmt/sa/tsa-policy-engine, read 200 tsa-policy-engine-8080; layer control channel
  the caller's proxy counted 1 request(s) to destination_principal spiffe://zone-a.trust.invalid/ns/ztd-mgmt/sa/tsa-policy-engine (istio_requests_total, reporter source)
- PASS: pdp-adapter-to-tsa from ztd-data: impostor (row labels, service account pdp-adapter-to-tsa-impostor) (pdp-adapter-to-tsa-impostor -> tsa-policy-engine.ztd-mgmt.svc:8080), expected 403 RBAC and a denial line with both SPIFFE IDs, read 403 RBAC: access denied; layer mesh
  {"authority":"tsa-policy-engine.ztd-mgmt.svc:8080","code":403,"destination":"spiffe://zone-a.trust.invalid/ns/ztd-mgmt/sa/tsa-policy-engine","detail":"rbac_access_denied_matched_policy[none]","flags":"-","source":"spiffe://zone-a.trust.invalid/ns/ztd-data/sa/pdp-adapter-to-tsa-impostor","termination":null,"time":"2026-11-21T20:46:36.049Z"}
- PASS: pdp-adapter-to-tsa from ztd-data: unlabelled (service account pdp-adapter, no row labels) (pdp-adapter-to-tsa-unlabelled -> tsa-policy-engine.ztd-mgmt.svc:8080), expected dropped, no denial line, read denied(28); layer network
  Hubble drop: Nov 21 20:46:47.751: ztd-data/pdp-adapter-to-tsa-unlabelled:56706 (ID:19387) <> ztd-mgmt/tsa-policy-engine:8080 (ID:10752) Policy denied DROPPED (TCP Flags: SYN); no new denial line of spiffe://zone-a.trust.invalid/ns/ztd-data/sa/pdp-adapter in the destination's proxy
- PASS: atls-gateway-to-cmcd from ztd-data: legitimate caller (atls-gateway-to-cmcd-caller -> cmcd.ztd-mgmt.svc:8080), expected 200 over mTLS, destination principal spiffe://zone-a.trust.invalid/ns/ztd-mgmt/sa/cmcd, read 200 cmcd-8080; layer control channel
  the caller's proxy counted 1 request(s) to destination_principal spiffe://zone-a.trust.invalid/ns/ztd-mgmt/sa/cmcd (istio_requests_total, reporter source)
- PASS: atls-gateway-to-cmcd from ztd-data: impostor (row labels, service account atls-gateway-to-cmcd-impostor) (atls-gateway-to-cmcd-impostor -> cmcd.ztd-mgmt.svc:8080), expected 403 RBAC and a denial line with both SPIFFE IDs, read 403 RBAC: access denied; layer mesh
  {"authority":"cmcd.ztd-mgmt.svc:8080","code":403,"destination":"spiffe://zone-a.trust.invalid/ns/ztd-mgmt/sa/cmcd","detail":"rbac_access_denied_matched_policy[none]","flags":"-","source":"spiffe://zone-a.trust.invalid/ns/ztd-data/sa/atls-gateway-to-cmcd-impostor","termination":null,"time":"2026-11-21T20:47:21.042Z"}
- PASS: atls-gateway-to-cmcd from ztd-data: unlabelled (service account atls-gateway, no row labels) (atls-gateway-to-cmcd-unlabelled -> cmcd.ztd-mgmt.svc:8080), expected dropped, no denial line, read denied(28); layer network
  Hubble drop: Nov 21 20:47:32.233: ztd-data/atls-gateway-to-cmcd-unlabelled:47266 (ID:13113) <> ztd-mgmt/cmcd:8080 (ID:11916) Policy denied DROPPED (TCP Flags: SYN); no new denial line of spiffe://zone-a.trust.invalid/ns/ztd-data/sa/atls-gateway in the destination's proxy
- PASS: atls-gateway-to-tcr from ztd-data: legitimate caller (atls-gateway-to-tcr-caller -> tcr.ztd-mgmt.svc:8080), expected 200 over mTLS, destination principal spiffe://zone-a.trust.invalid/ns/ztd-mgmt/sa/tcr, read 200 tcr-8080; layer control channel
  the caller's proxy counted 1 request(s) to destination_principal spiffe://zone-a.trust.invalid/ns/ztd-mgmt/sa/tcr (istio_requests_total, reporter source)
- PASS: atls-gateway-to-tcr from ztd-data: impostor (row labels, service account atls-gateway-to-tcr-impostor) (atls-gateway-to-tcr-impostor -> tcr.ztd-mgmt.svc:8080), expected 403 RBAC and a denial line with both SPIFFE IDs, read 403 RBAC: access denied; layer mesh
  {"authority":"tcr.ztd-mgmt.svc:8080","code":403,"destination":"spiffe://zone-a.trust.invalid/ns/ztd-mgmt/sa/tcr","detail":"rbac_access_denied_matched_policy[none]","flags":"-","source":"spiffe://zone-a.trust.invalid/ns/ztd-data/sa/atls-gateway-to-tcr-impostor","termination":null,"time":"2026-11-21T20:48:03.860Z"}
- PASS: atls-gateway-to-tcr from ztd-data: unlabelled (service account atls-gateway, no row labels) (atls-gateway-to-tcr-unlabelled -> tcr.ztd-mgmt.svc:8080), expected dropped, no denial line, read denied(28); layer network
  Hubble drop: Nov 21 20:48:14.391: ztd-data/atls-gateway-to-tcr-unlabelled:41130 (ID:53290) <> ztd-mgmt/tcr:8080 (ID:16970) Policy denied DROPPED (TCP Flags: SYN); no new denial line of spiffe://zone-a.trust.invalid/ns/ztd-data/sa/atls-gateway in the destination's proxy
- PASS: workloads-to-otel-collector from ztd-data: legitimate caller (workloads-to-otel-collector-caller -> otel-collector.ztd-mgmt.svc:4317), expected 200 over mTLS, destination principal spiffe://zone-a.trust.invalid/ns/ztd-mgmt/sa/otel-collector, read 200 otel-collector-4317; layer control channel
  the caller's proxy counted 1 request(s) to destination_principal spiffe://zone-a.trust.invalid/ns/ztd-mgmt/sa/otel-collector (istio_requests_total, reporter source)
- PASS: workloads-to-otel-collector from ztd-data: legitimate caller (workloads-to-otel-collector-caller -> otel-collector.ztd-mgmt.svc:4318), expected 200 over mTLS, destination principal spiffe://zone-a.trust.invalid/ns/ztd-mgmt/sa/otel-collector, read 200 otel-collector-4318; layer control channel
  the caller's proxy counted 1 request(s) to destination_principal spiffe://zone-a.trust.invalid/ns/ztd-mgmt/sa/otel-collector (istio_requests_total, reporter source)
- N/A: workloads-to-otel-collector from ztd-data: impostor (- -> otel-collector.ztd-mgmt.svc), expected n/a, read not probed; layer mesh
  the row admits every identity of ztd-data, so no identity is an impostor
- N/A: workloads-to-otel-collector from ztd-data: unlabelled (- -> otel-collector.ztd-mgmt.svc), expected n/a, read not probed; layer network
  the row selects every pod of ztd-data, so no pod lacks its labels
- PASS: workloads-to-otel-collector from ztd-data: off the row's ports (workloads-to-otel-collector-caller -> otel-collector.ztd-mgmt.svc:8080), expected dropped (the row admits 4317 and 4318 only), no denial line, read denied(28); layer network
  Hubble drop: Nov 21 20:48:54.322: ztd-data/workloads-to-otel-collector-caller:35820 (ID:1960) <> ztd-mgmt/otel-collector:8080 (ID:1598) Policy denied DROPPED (TCP Flags: SYN); no new denial line of spiffe://zone-a.trust.invalid/ns/ztd-data/sa/workloads-to-otel-collector-caller in the destination's proxy
- PASS: backend-to-verification-service from ztd-data: legitimate caller (backend-to-verification-service-caller -> verification-service.ztd-mgmt.svc:8080), expected 200 over mTLS, destination principal spiffe://zone-a.trust.invalid/ns/ztd-mgmt/sa/verification-service, read 200 verification-service-8080; layer control channel
  the caller's proxy counted 1 request(s) to destination_principal spiffe://zone-a.trust.invalid/ns/ztd-mgmt/sa/verification-service (istio_requests_total, reporter source)
- PASS: backend-to-verification-service from ztd-data: impostor (row labels, service account backend-to-verification-service-impostor) (backend-to-verification-service-impostor -> verification-service.ztd-mgmt.svc:8080), expected 403 RBAC and a denial line with both SPIFFE IDs, read 403 RBAC: access denied; layer mesh
  {"authority":"verification-service.ztd-mgmt.svc:8080","code":403,"destination":"spiffe://zone-a.trust.invalid/ns/ztd-mgmt/sa/verification-service","detail":"rbac_access_denied_matched_policy[none]","flags":"-","source":"spiffe://zone-a.trust.invalid/ns/ztd-data/sa/backend-to-verification-service-impostor","termination":null,"time":"2026-11-21T20:49:26.692Z"}
- PASS: backend-to-verification-service from ztd-data: unlabelled (service account backend, no row labels) (backend-to-verification-service-unlabelled -> verification-service.ztd-mgmt.svc:8080), expected dropped, no denial line, read denied(28); layer network
  Hubble drop: Nov 21 20:49:36.941: ztd-data/backend-to-verification-service-unlabelled:46118 (ID:24013) <> ztd-mgmt/verification-service:8080 (ID:17513) Policy denied DROPPED (TCP Flags: SYN); no new denial line of spiffe://zone-a.trust.invalid/ns/ztd-data/sa/backend in the destination's proxy

## 8. DENY rows and the catch-all row

- PASS: catch-all from ztd-data: TCP, proxy-less (probe-1 -> istio-system/istiod (istiod-7cd6445568-4952v):8080), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:50:05.738: ztd-data/probe-1:50676 (ID:48056) <> istio-system/istiod-7cd6445568-4952v:8080 (ID:17234) Policy denied DROPPED (TCP Flags: SYN); the destination has no proxy to write a denial line
- PASS: catch-all from ztd-data: TCP, proxy-less (probe-1 -> istio-system/istiod (istiod-7cd6445568-4952v):15010), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:50:19.899: ztd-data/probe-1:47850 (ID:48056) <> istio-system/istiod-7cd6445568-4952v:15010 (ID:17234) Policy denied DROPPED (TCP Flags: SYN); the destination has no proxy to write a denial line
- DECLARED: catch-all from ztd-data: TCP to istiod's xDS port (probe-1 -> istio-system/istiod (istiod-7cd6445568-4952v):15012), expected open, declared opening (proposed): docs/specifications.md, ZT-55 xDS entry, read connected; layer network
  the meshControlPlane opening admits the meshed plane namespaces to 15012; cited, not counted
- PASS: catch-all from ztd-data: TCP, proxy-less (probe-1 -> istio-system/istiod (istiod-7cd6445568-4952v):15014), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:50:41.252: ztd-data/probe-1:45448 (ID:48056) <> istio-system/istiod-7cd6445568-4952v:15014 (ID:17234) Policy denied DROPPED (TCP Flags: SYN); the destination has no proxy to write a denial line
- PASS: catch-all from ztd-data: TCP, proxy-less (probe-1 -> istio-system/istiod (istiod-7cd6445568-4952v):15017), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:50:55.974: ztd-data/probe-1:47576 (ID:48056) <> istio-system/istiod-7cd6445568-4952v:15017 (ID:17234) Policy denied DROPPED (TCP Flags: SYN); the destination has no proxy to write a denial line
- N/A: catch-all from ztd-data: mesh layer (- -> istio-system/istiod), expected n/a, read not probed; layer mesh
  mesh: n/a, the destination has no proxy (the SPIRE and Istio control planes are not meshed)
- PASS: spire-server from ztd-data: TCP, proxy-less (probe-1 -> spire-system/spire-controller-manager-webhook (spire-server-0):8080), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:51:11.130: ztd-data/probe-1:59808 (ID:48056) <> spire-system/spire-server-0:8080 (ID:23573) Policy denied DROPPED (TCP Flags: SYN); the destination has no proxy to write a denial line
- PASS: spire-server from ztd-data: TCP, proxy-less (probe-1 -> spire-system/spire-controller-manager-webhook (spire-server-0):8081), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:51:25.550: ztd-data/probe-1:53842 (ID:48056) <> spire-system/spire-server-0:8081 (ID:23573) Policy denied DROPPED (TCP Flags: SYN); the destination has no proxy to write a denial line
- PASS: spire-server from ztd-data: TCP, proxy-less (probe-1 -> spire-system/spire-controller-manager-webhook (spire-server-0):8082), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:51:39.481: ztd-data/probe-1:46102 (ID:48056) <> spire-system/spire-server-0:8082 (ID:23573) Policy denied DROPPED (TCP Flags: SYN); the destination has no proxy to write a denial line
- PASS: spire-server from ztd-data: TCP, proxy-less (probe-1 -> spire-system/spire-controller-manager-webhook (spire-server-0):8083), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:51:54.290: ztd-data/probe-1:37158 (ID:48056) <> spire-system/spire-server-0:8083 (ID:23573) Policy denied DROPPED (TCP Flags: SYN); the destination has no proxy to write a denial line
- PASS: spire-server from ztd-data: TCP, proxy-less (probe-1 -> spire-system/spire-controller-manager-webhook (spire-server-0):9443), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:52:08.498: ztd-data/probe-1:49900 (ID:48056) <> spire-system/spire-server-0:9443 (ID:23573) Policy denied DROPPED (TCP Flags: SYN); the destination has no proxy to write a denial line
- PASS: spire-server from ztd-data: TCP, proxy-less (probe-1 -> spire-system/spire-controller-manager-webhook (spire-server-0):9988), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:52:22.911: ztd-data/probe-1:42644 (ID:48056) <> spire-system/spire-server-0:9988 (ID:23573) Policy denied DROPPED (TCP Flags: SYN); the destination has no proxy to write a denial line
- N/A: spire-server from ztd-data: mesh layer (- -> spire-system/spire-controller-manager-webhook), expected n/a, read not probed; layer mesh
  mesh: n/a, the destination has no proxy (the SPIRE and Istio control planes are not meshed)
- N/A: spire-server from ztd-data: mesh layer (- -> spire-system/spire-server), expected n/a, read not probed; layer mesh
  mesh: n/a, the destination has no proxy (the SPIRE and Istio control planes are not meshed)
- PASS: tspa from ztd-data: TCP, proxy-less (probe-0 -> ztd-mgmt/tspa (tspa):8080), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:52:40.417: ztd-data/probe-0:39712 (ID:41329) <> ztd-mgmt/tspa:8080 (ID:48738) Policy denied DROPPED (TCP Flags: SYN); no new denial line in the destination's proxy
- PASS: tspa from ztd-data: behind a probe-scoped opening (mesh-prober-0 -> ztd-mgmt/tspa:8080), expected refused by the destination's proxy, a denial line with both SPIFFE IDs, the opening removed, read 403 RBAC: access denied; layer mesh
  {"authority":"tspa.ztd-mgmt.svc:8080","code":403,"destination":"spiffe://zone-a.trust.invalid/ns/ztd-mgmt/sa/tspa","detail":"rbac_access_denied_matched_policy[none]","flags":"-","source":"spiffe://zone-a.trust.invalid/ns/ztd-data/sa/mesh-prober","termination":null,"time":"2026-11-21T20:52:58.952Z"}; opening removed: yes
- PASS: catch-all from ztd-data: TCP, proxy-less (probe-0 -> ztd-mgmt/ztd-openbao (ztd-openbao-0):8200), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:53:10.773: ztd-data/probe-0:37234 (ID:41329) <> ztd-mgmt/ztd-openbao-0:8200 (ID:29147) Policy denied DROPPED (TCP Flags: SYN); no new denial line in the destination's proxy
- PASS: catch-all from ztd-data: TCP, proxy-less (probe-0 -> ztd-mgmt/ztd-openbao (ztd-openbao-0):8201), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:53:30.177: ztd-data/probe-0:49876 (ID:41329) <> ztd-mgmt/ztd-openbao-0:8201 (ID:29147) Policy denied DROPPED (TCP Flags: SYN); no new denial line in the destination's proxy
- PASS: catch-all from ztd-data: TCP, proxy-less (probe-0 -> ztd-mgmt/ztd-openbao (ztd-openbao-0):8202), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:53:48.476: ztd-data/probe-0:45980 (ID:41329) <> ztd-mgmt/ztd-openbao-0:8202 (ID:29147) Policy denied DROPPED (TCP Flags: SYN); no new denial line in the destination's proxy
- PASS: catch-all from ztd-data: behind a probe-scoped opening (mesh-prober-0 -> ztd-mgmt/ztd-openbao:8200), expected refused by the destination's proxy, a denial line with both SPIFFE IDs, the opening removed, read 403 RBAC: access denied; layer mesh
  {"authority":"ztd-openbao.ztd-mgmt.svc:8200","code":403,"destination":"spiffe://zone-a.trust.invalid/ns/ztd-mgmt/sa/ztd-openbao","detail":"rbac_access_denied_matched_policy[none]","flags":"-","source":"spiffe://zone-a.trust.invalid/ns/ztd-data/sa/mesh-prober","termination":null,"time":"2026-11-21T20:54:03.640Z"}; opening removed: yes
- PASS: catch-all from ztd-data: behind a probe-scoped opening (mesh-prober-0 -> ztd-mgmt/ztd-openbao:8201), expected refused by the destination's proxy, a denial line with both SPIFFE IDs, the opening removed, read denied(52); layer mesh
  {"authority":null,"code":0,"destination":"spiffe://zone-a.trust.invalid/ns/ztd-mgmt/sa/ztd-openbao","detail":null,"flags":"-","source":"spiffe://zone-a.trust.invalid/ns/ztd-data/sa/mesh-prober","termination":"rbac_access_denied_matched_policy[none]","time":"2026-11-21T20:54:11.963Z"}; opening removed: yes
- catch-all from ztd-data: ztd-mgmt/ztd-openbao-internal:8200 leads to ztd-openbao-0:8200, probed at the mesh layer already through ztd-mgmt/ztd-openbao:8200
- catch-all from ztd-data: ztd-mgmt/ztd-openbao-internal:8201 leads to ztd-openbao-0:8201, probed at the mesh layer already through ztd-mgmt/ztd-openbao:8201
- PASS: catch-all from ztd-data: plain text, no identity, behind a probe-scoped opening (probe-0 -> ztd-mgmt/ztd-openbao-0:8202), expected reset by the destination's proxy (mutual TLS STRICT), the opening removed, read denied(56); layer mesh
  the network let the request through (Hubble: Nov 21 20:54:44.113: ztd-data/probe-0:47340 (ID:41329) -> ztd-mgmt/ztd-openbao-0:8202 (ID:29147) to-overlay FORWARDED (TCP Flags: ACK, PSH)) and the destination's proxy reset it: mutual TLS STRICT refuses a caller without a certificate; mutual TLS mode in force: STRICT; opening removed: yes

## 9. Management plane → data plane

Section 6's row `management-to-data`: DENY at both layers by the default deny alone; the rule was checked against the rendered umbrella (section 1) and the cluster's policies (section 2). Probed from: istio-system spire-system ztd-mgmt.

- PASS: management-to-data from istio-system: TCP, proxy-less (probe-0 -> ztd-data/ztd-connector-gateway (ztd-connector-gateway-55d9978c85-bhs9n):8080), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:54:56.950: istio-system/probe-0:51626 (ID:48897) <> ztd-data/ztd-connector-gateway-55d9978c85-bhs9n:8080 (ID:4779) Policy denied DROPPED (TCP Flags: SYN); no new denial line in the destination's proxy
- PASS: management-to-data from istio-system: plain text, no identity, behind a probe-scoped opening (probe-0 -> ztd-data/ztd-connector-gateway-55d9978c85-bhs9n:8080), expected reset by the destination's proxy (mutual TLS STRICT), the opening removed, read denied(56); layer mesh
  the network let the request through (Hubble: Nov 21 20:55:12.698: istio-system/probe-0:40572 (ID:48897) -> ztd-data/ztd-connector-gateway-55d9978c85-bhs9n:8080 (ID:4779) to-overlay FORWARDED (TCP Flags: ACK, PSH)) and the destination's proxy reset it: mutual TLS STRICT refuses a caller without a certificate; mutual TLS mode in force: STRICT; opening removed: yes
- PASS: management-to-data from spire-system: TCP, proxy-less (probe-0 -> ztd-data/ztd-connector-gateway (ztd-connector-gateway-55d9978c85-bhs9n):8080), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:55:22.305: spire-system/probe-0:42964 (ID:16654) <> ztd-data/ztd-connector-gateway-55d9978c85-bhs9n:8080 (ID:4779) Policy denied DROPPED (TCP Flags: SYN); no new denial line in the destination's proxy
- PASS: management-to-data from spire-system: plain text, no identity, behind a probe-scoped opening (probe-0 -> ztd-data/ztd-connector-gateway-55d9978c85-bhs9n:8080), expected reset by the destination's proxy (mutual TLS STRICT), the opening removed, read denied(56); layer mesh
  the network let the request through (Hubble: Nov 21 20:55:38.873: spire-system/probe-0:37666 (ID:16654) -> ztd-data/ztd-connector-gateway-55d9978c85-bhs9n:8080 (ID:4779) to-overlay FORWARDED (TCP Flags: ACK, PSH)) and the destination's proxy reset it: mutual TLS STRICT refuses a caller without a certificate; mutual TLS mode in force: STRICT; opening removed: yes
- PASS: management-to-data from ztd-mgmt: TCP, proxy-less (probe-0 -> ztd-data/ztd-connector-gateway (ztd-connector-gateway-55d9978c85-bhs9n):8080), expected dropped, read denied(28); layer network
  Hubble drop: Nov 21 20:55:49.762: ztd-mgmt/probe-0:49460 (ID:45863) <> ztd-data/ztd-connector-gateway-55d9978c85-bhs9n:8080 (ID:4779) Policy denied DROPPED (TCP Flags: SYN); no new denial line in the destination's proxy
- PASS: management-to-data from ztd-mgmt: behind a probe-scoped opening (mesh-prober-0 -> ztd-data/ztd-connector-gateway:8080), expected refused by the destination's proxy, a denial line with both SPIFFE IDs, the opening removed, read 403 RBAC: access denied; layer mesh
  {"authority":"ztd-connector-gateway.ztd-data.svc:8080","code":403,"destination":"spiffe://zone-a.trust.invalid/ns/ztd-data/sa/ztd-connector-gateway","detail":"rbac_access_denied_matched_policy[none]","flags":"-","source":"spiffe://zone-a.trust.invalid/ns/ztd-mgmt/sa/mesh-prober","termination":null,"time":"2026-11-21T20:56:03.299Z"}; opening removed: yes

## 10. Cleanup

- PASS: no fixture, prober or opening of the run remains
  none
- PASS: the zone's policies equal the snapshot taken at the start (NetworkPolicy, CiliumNetworkPolicy, AuthorizationPolicy, the admission policy's spec)
  

## The matrix

| Row | ZT-55 role | Caller's namespace | Legitimate caller | Network layer | Mesh layer | Destination |
|---|---|---|---|---|---|---|
| pdp-adapter-to-tsa | Policy Engine | ztd-data | pdp-adapter-to-tsa-caller (on shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-22p4h; destination on shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-j82gf): :8080 200 | unlabelled (service account pdp-adapter, no row labels), tsa-policy-engine.ztd-mgmt.svc:8080 denied(28) | impostor (row labels, service account pdp-adapter-to-tsa-impostor), tsa-policy-engine.ztd-mgmt.svc:8080 403 | stand-in |
| atls-gateway-to-cmcd | Attestation (CMC) | ztd-data | atls-gateway-to-cmcd-caller (on shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-fztmf; destination on shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-22p4h): :8080 200 | unlabelled (service account atls-gateway, no row labels), cmcd.ztd-mgmt.svc:8080 denied(28) | impostor (row labels, service account atls-gateway-to-cmcd-impostor), cmcd.ztd-mgmt.svc:8080 403 | stand-in |
| atls-gateway-to-tcr | TRAIN (resolution) | ztd-data | atls-gateway-to-tcr-caller (on shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-22p4h; destination on shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-fztmf): :8080 200 | unlabelled (service account atls-gateway, no row labels), tcr.ztd-mgmt.svc:8080 denied(28) | impostor (row labels, service account atls-gateway-to-tcr-impostor), tcr.ztd-mgmt.svc:8080 403 | stand-in |
| workloads-to-otel-collector | Observability stack | ztd-data | workloads-to-otel-collector-caller (on shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-22p4h; destination on shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-j82gf): :4317 200; :4318 200 | n/a (otel-collector.ztd-mgmt.svc): the row selects every pod of ztd-data, so no pod lacks its labels; off the row's ports, otel-collector.ztd-mgmt.svc:8080 denied(28) | n/a (otel-collector.ztd-mgmt.svc): the row admits every identity of ztd-data, so no identity is an impostor | stand-in |
| backend-to-verification-service | OCM | ztd-data | backend-to-verification-service-caller (on shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-fztmf; destination on shoot--eco--zerotrust-a-worker-fvsba-z1-785f7-22p4h): :8080 200 | unlabelled (service account backend, no row labels), verification-service.ztd-mgmt.svc:8080 denied(28) | impostor (row labels, service account backend-to-verification-service-impostor), verification-service.ztd-mgmt.svc:8080 403 | stand-in |
| catch-all | any management-plane destination not listed above | ztd-data | — | TCP, proxy-less, istio-system/istiod (istiod-7cd6445568-4952v):8080 denied(28); TCP, proxy-less, istio-system/istiod (istiod-7cd6445568-4952v):15010 denied(28); istio-system/istiod (istiod-7cd6445568-4952v):15012 open, declared opening (proposed); TCP, proxy-less, istio-system/istiod (istiod-7cd6445568-4952v):15014 denied(28); TCP, proxy-less, istio-system/istiod (istiod-7cd6445568-4952v):15017 denied(28); TCP, proxy-less, ztd-mgmt/ztd-openbao (ztd-openbao-0):8200 denied(28); TCP, proxy-less, ztd-mgmt/ztd-openbao (ztd-openbao-0):8201 denied(28); TCP, proxy-less, ztd-mgmt/ztd-openbao (ztd-openbao-0):8202 denied(28) | n/a (istio-system/istiod): mesh: n/a, the destination has no proxy (the SPIRE and Istio control planes are not meshed); behind a probe-scoped opening, ztd-mgmt/ztd-openbao:8200 403; behind a probe-scoped opening, ztd-mgmt/ztd-openbao:8201 denied(52); plain text, no identity, behind a probe-scoped opening, ztd-mgmt/ztd-openbao-0:8202 denied(56) | real |
| spire-server | SPIRE control plane | ztd-data | — | TCP, proxy-less, spire-system/spire-controller-manager-webhook (spire-server-0):8080 denied(28); TCP, proxy-less, spire-system/spire-controller-manager-webhook (spire-server-0):8081 denied(28); TCP, proxy-less, spire-system/spire-controller-manager-webhook (spire-server-0):8082 denied(28); TCP, proxy-less, spire-system/spire-controller-manager-webhook (spire-server-0):8083 denied(28); TCP, proxy-less, spire-system/spire-controller-manager-webhook (spire-server-0):9443 denied(28); TCP, proxy-less, spire-system/spire-controller-manager-webhook (spire-server-0):9988 denied(28) | n/a (spire-system/spire-controller-manager-webhook): mesh: n/a, the destination has no proxy (the SPIRE and Istio control planes are not meshed); n/a (spire-system/spire-server): mesh: n/a, the destination has no proxy (the SPIRE and Istio control planes are not meshed) | real |
| tspa | TRAIN (publication) | ztd-data | — | TCP, proxy-less, ztd-mgmt/tspa (tspa):8080 denied(28) | behind a probe-scoped opening, ztd-mgmt/tspa:8080 403 | stand-in |
| management-to-data | any data-plane workload (from the management plane) | istio-system | — | TCP, proxy-less, ztd-data/ztd-connector-gateway (ztd-connector-gateway-55d9978c85-bhs9n):8080 denied(28) | plain text, no identity, behind a probe-scoped opening, ztd-data/ztd-connector-gateway-55d9978c85-bhs9n:8080 denied(56) | real |
| management-to-data | any data-plane workload (from the management plane) | spire-system | — | TCP, proxy-less, ztd-data/ztd-connector-gateway (ztd-connector-gateway-55d9978c85-bhs9n):8080 denied(28) | plain text, no identity, behind a probe-scoped opening, ztd-data/ztd-connector-gateway-55d9978c85-bhs9n:8080 denied(56) | real |
| management-to-data | any data-plane workload (from the management plane) | ztd-mgmt | — | TCP, proxy-less, ztd-data/ztd-connector-gateway (ztd-connector-gateway-55d9978c85-bhs9n):8080 denied(28) | behind a probe-scoped opening, ztd-data/ztd-connector-gateway:8080 403 | real |

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
