# The attested-channel gateway between two zones on kind

Run of 2026-11-25, 13:51 to 14:02 UTC, on a workstation: two kind clusters (`kindest/node` v1.35.8,
one control-plane and one worker each, Cilium 1.20.2 with `cni.exclusive=false`), both installed as
participant zones through `scripts/install-zone` (umbrella, SPIRE, Istio sidecar mode, zone-policy),
each with the attester release `ztd-cmcd` and the gateway release `ztd-atls-gateway` from its zone
file; CMC v0.9.15; images built from the working tree for `linux/arm64`, the platform of these nodes.
Commit `c7f07c0f` (tree clean), the commit that adds the gateway's image, charts, startup check and
this proof; an earlier run of the same day on the uncommitted tree gave the same seventeen verdicts.
Ten and a half minutes from two empty clusters to the verdict.

Reproduce:

```
scripts/verify-atls-gateway/verify.sh --kind --out .dev/verify-atls-gateway
```

## What each step calls

| Step | What it does | Decided from |
|---|---|---|
| provision | renders each zone's reference values and measurement log from `deployment/attestation/<zone>.json`, signs them with `metatool` under a metadata CA created for the run, hands them to the zone as the Secret `cmcd-material` | the files in Git |
| install | `install.sh install ztd spire-crds spire istio-base istiod istio-cni zone-policy`, then the Secrets, then `install.sh install ztd-cmcd ztd-atls-gateway` per zone | the zone file (`cmcd`, `atlsGateway` blocks) |
| startup | waits for `started`/`evidence_verified` from each role | the gateways' decision records (stdout) |
| call | a `curl` from the zone's caller pod to `ztd-atls-gateway-egress:8080`, answered by the peer zone's echo | the HTTP status and body; both ends' `established` records |
| stranger | a pod outside the mesh with a certificate from another CA, `curl -k --cert` at zone B's entry | no application answer; a new `refused` record at the ingress |
| attester | `ztd-cmcd` of zone A scaled to zero, a new call, then scaled back and a new call | the egress's `refused` record; the later call's status |
| tamper | the `rootfs_sha256` of zone A's `zone.json` ConfigMap changed in place, the ingress restarted; then restored and restarted | the pod's exit code and its previous log; zone B's call afterwards |

## Result

| Check | Result |
|---|---|
| zone A, zone B: base releases | PASS |
| zone A, zone B: `ztd-cmcd` and `ztd-atls-gateway` installed from the zone file | PASS |
| four roles: startup check `evidence_verified` before serving | PASS |
| A → B: 200, body `from-zone-a`; both ends one channel, `mutual_attestation`, TLS 1.3 (772), binding `217712666abc9bb5…` at both ends, peer `spiffe://zone-b/gateway` seen by A and `spiffe://zone-a/gateway` seen by B | PASS |
| B → A: 200, body `from-zone-b`; binding `f5ba83443c19b1f5…` at both ends | PASS |
| stranger at B's entry: `curl: (56) … tlsv1 alert unknown ca` (the run on the uncommitted tree saw the connection reset instead; what the client sees depends on when the listener closes); ingress recorded `refused` / `atls: peer certificate identity rejected` | PASS |
| A's attester away: the call ends in a reset (`exit code 56`), egress recorded `refused` / `atls: local attester unavailable` | PASS |
| A's attester back: 200, body `attester-back` | PASS |
| A's ingress with the tampered configuration: exit status 2, `{"role":"ingress","decision":"refused","reason":"evidence_rejected"}`, served nothing | PASS |
| A's ingress restored: B's call answered, 200, body `after-restore` | PASS |

`verdict.txt`: `verdict: all checks passed`, 17 checks.

The records here: `verdict.txt`, `environment.json` (commit, dirty flag, versions, image digests),
`calls.txt` (each call's status and body), `decisions-<zone>-<role>.jsonl` (every decision each role
recorded: the startup outcome, the established channels with their bindings, the refusals) and
`tampered-ingress-a.log` (the refused start). The installer, Cilium, metatool and attester logs and
the plane listings stay in the run directory (`--out`), delivered with the milestone submission.

## Limits

- Two zones on one workstation, over kind's Docker network: the peer is a worker node's address and
  the entry's NodePort. On the zones the peer entry is the zone's load-balancer address and the
  interconnect is the CUG; the releases take both as zone facts.
- The evidence is mock (CMC's software driver over a measurement log rendered from Git); nothing
  measures the running container, and the rootfs digest in `deployment/attestation/<zone>.json` is
  the mock value.
- The peer's measurement is verified against the metadata the attester holds, not against TRAIN: the
  resolver's adapter into `PeerVerifier` is separate work.
- The upstream and the caller are fixtures (an echo and a curl); the Connector's routing is not
  behind the gateway here.
- The two zones share the kind trust domain of `deployment/helm/ztd/ci/values.yaml`; the gateway
  identities are the zone PKI's, not SPIRE's, so the shared domain plays no part in the channel.
- The images were built for the nodes' platform (`linux/arm64`); the release pipeline builds
  `linux/amd64`. The workflow `atls-gateway.yml` runs the same proof on an amd64 runner.
