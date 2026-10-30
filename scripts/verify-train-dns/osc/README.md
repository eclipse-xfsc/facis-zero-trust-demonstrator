# OSC probes for the TRAIN DNS zone manager

The zone manager has to answer DNS on UDP and TCP 53 behind one public address, and
`docs/train-dns.md` §Operating leaves open whether the target cluster gives that to a Service of
type LoadBalancer. This directory holds the probe that answers it on the dedicated OSC clusters and
the evidence it produced.

| File | What it is |
|---|---|
| `lb-probe.yaml` | A namespace with a minimal CoreDNS serving the synthetic zone `lbprobe.test` and a Service of type LoadBalancer with ports 53/UDP and 53/TCP. Nothing in it is part of the delivered module. |
| `evidence-lb-probe-zone-a.md` | What the probe showed on the OSC zone A cluster on 2026-10-14: address assigned, both protocols answering from outside, address kept across a Service recreation, cleanup confirmed. |

## Running it again

With a kubeconfig for the cluster in `KUBECONFIG`:

```bash
kubectl apply -f scripts/verify-train-dns/osc/lb-probe.yaml
kubectl -n lb-probe rollout status deploy/dns-probe
kubectl -n lb-probe get svc dns-probe -w        # until EXTERNAL-IP is set
IP=$(kubectl -n lb-probe get svc dns-probe -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
dig @"$IP" probe.lbprobe.test TXT +short         # UDP
dig @"$IP" probe.lbprobe.test TXT +tcp +short    # TCP
kubectl -n lb-probe logs deploy/dns-probe | grep lbprobe
kubectl delete ns lb-probe --wait                # releases the load balancer
```

Expected: both `dig` calls print `"zone-a lb probe ok"` and the log shows the queries. The probe
uses the CoreDNS image from the cluster's own mirror so it pulls nothing new onto the nodes.
