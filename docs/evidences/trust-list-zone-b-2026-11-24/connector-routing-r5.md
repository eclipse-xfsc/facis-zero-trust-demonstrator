# Zero Trust Connector routing (ZT-26) on zerotrust-b, role ingress

Run 20261124T103249Z-21005, started 2026-11-24T10:32:49Z, commit b3cbdcefd816231a61c2f381a2df30e9c4af9b83 (working tree modified).
Zone file: deployment/helm/ztd/zones/zone-b.yaml; route namespace ztd-data; trust domain zone-b.trust.invalid.

## stand-ins

- PASS: the caller (service account backend) and the impostor (route-impostor, same labels) are ready in ztd-data
  

## direct-path

- PASS: the caller's direct https attempt at <address>:443, around the gateway, is dropped by the network layer
  outcome: denied(28); probe window 2026-11-24T10:33:02Z..2026-11-24T10:33:12Z; Hubble: Nov 24 10:33:10.681: ztd-data/route-backend:34536 (ID:61735) <> <address>:443 (world) Policy denied DROPPED (TCP Flags: SYN)
- PASS: the caller cannot reach ztd-m3-b/ztd-protected-resource:8080/http directly (dropped by the network layer)
  outcome: denied(28); probe window 2026-11-24T10:33:39Z..2026-11-24T10:34:03Z; Hubble: Nov 24 10:33:57.113: ztd-data/route-backend:48386 (ID:61735) <> ztd-m3-b/ztd-protected-resource-546b564b6b-rjp7m:8080 (ID:49619) Policy denied DROPPED (TCP Flags: SYN)
- PASS: the caller cannot reach ztd-m3-b/ztd-guard:8080/http directly (dropped by the network layer)
  outcome: denied(28); probe window 2026-11-24T10:34:29Z..2026-11-24T10:34:53Z; Hubble: Nov 24 10:34:47.673: ztd-data/route-backend:54464 (ID:61735) <> ztd-m3-b/ztd-guard-59757bdbc7-m746m:8080 (ID:2680) Policy denied DROPPED (TCP Flags: SYN)
- PASS: the caller cannot reach ztd-m3-b/ztd-participant:8080/http directly (dropped by the network layer)
  outcome: denied(28); probe window 2026-11-24T10:35:20Z..2026-11-24T10:35:44Z; Hubble: Nov 24 10:35:38.841: ztd-data/route-backend:46184 (ID:61735) <> ztd-m3-b/ztd-participant-56785bf4d5-qjfbz:8080 (ID:1588) Policy denied DROPPED (TCP Flags: SYN)
- PASS: the caller cannot reach ztd-m3-b/ztd-connector:8080/http directly (dropped by the network layer)
  outcome: denied(28); probe window 2026-11-24T10:36:11Z..2026-11-24T10:36:36Z; Hubble: Nov 24 10:36:30.009: ztd-data/route-backend:37670 (ID:61735) <> ztd-m3-b/ztd-connector-6dd78f7c67-2sxbf:8080 (ID:34277) Policy denied DROPPED (TCP Flags: SYN)
- PASS: the caller cannot reach ztd-m3-b/ztd-edge:443/https directly (dropped by the network layer)
  outcome: denied(35); probe window 2026-11-24T10:36:48Z..2026-11-24T10:36:52Z; Hubble: Nov 24 10:36:51.705: ztd-data/route-backend:47634 (ID:61735) <> ztd-m3-b/ztd-edge-779c79d6b8-nszxj:8443 (ID:42169) Policy denied DROPPED (TCP Flags: SYN)

## entry

- PASS: the entry ztd-m3-b/ztd-edge forwards every request to one upstream
  8443 {'prefix': '/'} upstream;cluster upstream ztd-participant 8080
- PASS: every port exposed outside the cluster is the entry's or a declared bypass's, and every declared one is exposed
  exposed: ztd-m3-b/ztd-edge:443/TCP ztd-train/train-zone-manager-dns:53/TCP ztd-train/train-zone-manager-dns:53/UDP ztd-train/tspa-public:443/TCP; undeclared: none; declared but absent: none
- PASS: declared entry ztd-train/train-zone-manager-dns: trust.facis.cloud SOA answers NOERROR over UDP and TCP
  UDP NOERROR, TCP NOERROR
- PASS: declared entry ztd-train/train-zone-manager-dns: example.com A answers REFUSED over UDP and TCP
  UDP REFUSED, TCP REFUSED
- PASS: declared entry ztd-train/train-zone-manager-dns is held to its declared scope
  2 assertion(s), all required
- PASS: declared entry ztd-train/tspa-public: a TLS 1.2 handshake is refused
  curl exit 35
- PASS: declared entry ztd-train/tspa-public: GET /.well-known/did.json answers 200
  answered 200
- PASS: declared entry ztd-train/tspa-public: GET the trust list of trust.facis.cloud answers 200 with a JSON or XML body
  answered 200 application/json
- PASS: declared entry ztd-train/tspa-public: GET the VC of trust.facis.cloud's trust list answers 200 with a credential valid now
  answered 200 application/json; valid from 2026-11-24T11:09:20+01:00 until 2026-12-24T11:09:20+01:00
- PASS: declared entry ztd-train/tspa-public: PUT /tspa-service/tspa/v1/trustframework/route-probe (with a body) answers 404/405
  answered 404
- PASS: declared entry ztd-train/tspa-public: DELETE /tspa-service/tspa/v1/trustframework/route-probe answers 404/405
  answered 404
- PASS: declared entry ztd-train/tspa-public: PUT /tspa-service/tspa/v1/init/json/route-probe/trust-list (with a body) answers 404/405
  answered 404
- PASS: declared entry ztd-train/tspa-public: PUT /tspa-service/tspa/v1/init/xml/route-probe/trust-list (with a body) answers 404/405
  answered 404
- PASS: declared entry ztd-train/tspa-public: PUT /tspa-service/tspa/v1/route-probe/trust-list/tsp (with a body) answers 404/405
  answered 404
- PASS: declared entry ztd-train/tspa-public: PATCH /tspa-service/tspa/v1/route-probe/trust-list/tsp/route-probe (with a body) answers 404/405
  answered 404
- PASS: declared entry ztd-train/tspa-public: DELETE /tspa-service/tspa/v1/route-probe/trust-list/tsp/route-probe answers 404/405
  answered 404
- PASS: declared entry ztd-train/tspa-public: DELETE /tspa-service/tspa/v1/route-probe/trust-list answers 404/405
  answered 404
- PASS: declared entry ztd-train/tspa-public: PUT /tspa-service/tspa/v1/route-probe/did (with a body) answers 404/405
  answered 404
- PASS: declared entry ztd-train/tspa-public: DELETE /tspa-service/tspa/v1/route-probe/did answers 404/405
  answered 404
- PASS: declared entry ztd-train/tspa-public: POST /tspa-service/tspa/v1/route-probe/trust-list (with a body) answers 404/405
  answered 404
- PASS: declared entry ztd-train/tspa-public: POST /tspa-service/tspa/v1/route-probe/vc/trust-list (with a body) answers 404/405
  answered 404
- PASS: declared entry ztd-train/tspa-public: POST /.well-known/did.json (with a body) answers 404/405
  answered 405
- PASS: declared entry ztd-train/tspa-public: GET /tspa-service/actuator/health answers 404/405
  answered 404
- PASS: declared entry ztd-train/tspa-public: GET /tspa-service/api/docs answers 404/405
  answered 404
- PASS: declared entry ztd-train/tspa-public is held to its declared scope
  18 assertion(s), all required

## exemptions

- PASS: DNS (declared bypass, name resolution): the caller resolves cluster names through the resolver lane
  names: kubernetes.default.svc.cluster.local
- PASS: observability export (declared bypass, ZT-26): the caller reaches a stand-in with the row's labels and identity on 4318 in ztd-mgmt
  outcome: 200 otlp-http-stand-in

Objects this run created (removed on exit): ztd-data/serviceaccount/backend ztd-data/serviceaccount/route-impostor ztd-data/pod/route-backend ztd-data/pod/route-impostor ztd-mgmt/serviceaccount/otel-collector ztd-mgmt/pod/route-otel-stand-in ztd-mgmt/service/route-otel-stand-in.

Result: 0 failed check(s).
