# Probe: mixed-protocol LoadBalancer on port 53, OSC zone A cluster

Date: 2026-10-14. Cluster: the dedicated OSC cluster of zone A, Kubernetes v1.34.7, Gardener shoot on the
onmetal provider, Cilium with kube-proxy replacement. Purpose: the TRAIN zone manager needs one public
address answering DNS on UDP and TCP 53. Manifest: `lb-probe.yaml`
(namespace `lb-probe`, CoreDNS v1.13.1 from the cluster's mirror serving a synthetic zone
`lbprobe.test`, Service type LoadBalancer with ports 53/UDP and 53/TCP). Everything was deleted at the end.

| Check | Result |
|---|---|
| Service with 53/UDP and 53/TCP accepted by the API server | yes (no admission error) |
| External address assigned | one public IPv4 address, `ipMode: VIP`, within 10 s of creation (events: EnsuringLoadBalancer, EnsuredLoadBalancer 1 s apart) |
| Node ports | one shared node port for both protocols (32272/UDP and 32272/TCP) |
| Query from outside, UDP (A and TXT) | NOERROR, aa flag, ~84 ms |
| Query from outside, TCP (TXT and A) | NOERROR, aa flag, ~85 ms |
| Queries visible in the pod log | yes, 4 of 4 |
| Client source address seen by the pod | node address (10.250.0.x) when the packet landed on a node other than the pod's; the real client address when it landed on the pod's node (externalTrafficPolicy Cluster) |
| Unrelated name | SERVFAIL from the template plugin; expected for this probe, not a path issue |
| Service deleted and recreated from the same manifest | the same address again, after 10 s; one observation, not a reservation guarantee |
| `spec.loadBalancerIP` pinning | not exercised (the address did not change) |
| Gardener shoot-dns-service | CRDs `dnsproviders`/`dnsentries.dns.gardener.cloud` exist; no DNSProvider or DNSEntry configured, so no stable DNS name is available from the cluster without FACIS configuring a provider |
| cert-manager | CRDs present, no issuers |
| Cleanup | namespace `lb-probe` deleted; no LoadBalancer Service left in the cluster; the old VIP no longer answers (timeout) |

What this settles for the zone manager's deployment: its DNS Service can be a plain `type: LoadBalancer`
with both protocols on one port, no annotation needed, and it gets a public address at once.

What stays open: whether the address survives a reinstall is only suggested by one recreation; the
glue records for the delegation should be sent after the real zone manager Service exists, or FACIS
asked whether onmetal offers a reserved VIP for this shoot. With `externalTrafficPolicy: Cluster`
the zone manager's logs will mostly show node addresses, not client addresses.
