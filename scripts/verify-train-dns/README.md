# verify-train-dns

Evidence that the trust-framework DNS zone — the zone TRAIN anchors trust in — is live and
verifiable: delegated at its parent, answered authoritatively by every server the delegation
names (UDP and TCP, same serial, and on every server the same NS set as the delegation), carrying
the `_scheme._trust` pointer the content resolver starts from and the URI record at each of its
targets, resolvable through recursive resolvers — pointer and URI through each of them — and in a
coherent DNSSEC state (every server serving the same key-signing key, the DS at the parent being
that key's DS in full, signatures not about to expire, no resolver rejecting the zone as bogus).

```bash
ZONE=trust.example.org scripts/verify-train-dns/verify.sh      # writes evidence.md next to the script
```

Needs `dig` (bind-utils / dnsutils) and `python3`; `delv`, when present and built with crypto,
adds a validation verdict per resolver. Exit status is non-zero if any check failed.

| Variable | Default | Meaning |
|---|---|---|
| `ZONE` | required | the trust-framework zone |
| `RESOLVERS` | `system 1.1.1.1 9.9.9.9` | recursive resolvers to resolve through; `system` is the host's own |
| `WHERE` | `outside the clusters` | where the run happens, for the evidence header (`zone-a`, …) |
| `EXPECT_NS` | not checked | the name servers the delegation must name |
| `SERVERS` | from the delegation | `name=ip …`: query these servers directly, for a zone manager that exists before the delegation does |
| `EXPECT_DS` | not checked | the DS to be published, as the zone manager printed it at first start (several records comma- or newline-separated); each is compared in full — owner, algorithm, digest type, digest — with the DS computed from the key every server serves, signed zone or not, so a key change shows before the DS is live. A bare key tag is accepted, and recorded as the weaker, tag-only check it is |
| `REQUIRE_POINTER` | `1` | `0` records the pointer state without failing — for a zone that is live but has no framework registered yet |
| `MIN_SIG_DAYS` | `7` | signature validity still required when the zone is signed |
| `OUT` | `evidence.md` | where the evidence goes |

**Two states, two runs.** With `REQUIRE_POINTER=0` the evidence proves the zone itself: delegation,
authoritative answers, DNSSEC. Once a framework is registered through TSPA (which writes the
`_scheme._trust` PTR) and its DID is published (the URI record), the default run proves the records
the content resolver follows.

**From a cluster.** Resolution "from all three clusters" is the same script run inside each one,
with `RESOLVERS` set to the cluster resolver so the evidence shows what a workload there sees,
forwarders and all. A throwaway pod in a namespace without the default-deny policy is enough:

```bash
dns=$(kubectl -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}')
kubectl run dnscheck --image=docker.io/library/ubuntu:24.04 --restart=Never -- sleep 900
kubectl wait --for=condition=Ready pod/dnscheck
kubectl cp scripts/verify-train-dns/verify.sh dnscheck:/tmp/verify.sh
kubectl exec dnscheck -- bash -c "apt-get -qq update && apt-get -qq install -y dnsutils python3 >/dev/null;
  ZONE=trust.example.org WHERE=zone-a RESOLVERS=$dns OUT=/tmp/evidence.md bash /tmp/verify.sh; cat /tmp/evidence.md"
kubectl delete pod dnscheck
```

**Before the delegation.** The zone manager can be checked as soon as it runs, by naming its
servers and the DS it printed at first start (the whole line; the digest is shortened here):

```bash
ZONE=trust.example.org SERVERS="ns1.trust.example.org=203.0.113.53 ns2.trust.example.org=203.0.113.53" \
  EXPECT_DS="trust.example.org. 3600 IN DS 54033 13 2 f020…" REQUIRE_POINTER=0 scripts/verify-train-dns/verify.sh
```

**Reading the DNSSEC section.** The zone manager generates its keys at first start and keeps them
in its database; the DS at the parent must be the DS of the key-signing key every server serves, or
every validating resolver refuses the whole zone with SERVFAIL — which the content resolver reports
as an empty result, not an error. The script therefore reads the DNSKEY set from every server,
computes the DS of each key-signing key the way RFC 4034 §5.1.4 defines it (SHA-1, SHA-256 and
SHA-384 over the owner name and the key) and compares DS records in full: a DS with the right key
tag and a wrong digest is refused by resolvers just like a DS of another key. It also reads the SOA
signature's expiry, and distinguishes a bogus zone (SERVFAIL that turns into NOERROR with checking
disabled) from an unreachable one. "No DS" is reported as information: the zone then resolves
unvalidated, which is the state to delegate in until key persistence and re-signing are proven.
With `SERVERS` set the parent is not asked at all, so `EXPECT_DS` is the only DS check there is,
and it fails when no server serves the key it names — an unsigned replacement server included.

**Self-test without a trust-framework zone.** `ZONE=isc.org REQUIRE_POINTER=0` passes every check
on a healthy signed delegation; `ZONE=dnssec-failed.org REQUIRE_POINTER=0` fails on a deliberately
broken one (DS mismatch, bogus at every validating resolver). Neither publishes TRAIN records, so
the pointer checks are only informational there.

**Tests.** `verify_test.sh` runs the inspector against local NSD servers, each serving a variant
of one signed test zone, and checks the verdict of every case: the DS as `ldns-key2ds` writes it
and as `dig` prints it; the right key tag with a wrong digest, owner or algorithm; a bare key tag;
a DS recorded for an unsigned replacement server, alone or next to a signed one; a secondary with
the same serial and another NS set; a resolver that answers the pointer but not the URI at its
target. Then the delegation path, through a signed parent zone and an Unbound resolver anchored on
it: the right DS, a DS with the right key tag and a wrong digest (the resolver refuses the zone), a
stale DS next to the right one, no DS, a DS above an unsigned server, an unexpected NS set. The
servers listen on `127.0.53.1`–`.7` port 53 and the parent's server name goes into `/etc/hosts` for
the run, so it runs as root in a throwaway container, as CI runs it:

```bash
docker run --rm -v "$PWD/scripts/verify-train-dns:/w:ro" ubuntu:24.04 bash -c \
  'apt-get -qq update && apt-get -qq install -y --no-install-recommends nsd ldnsutils unbound dnsutils python3 >/dev/null && bash /w/verify_test.sh'
```

## The zone manager on kind

`kind/` stands the upstream zone manager up on the local kind cluster (`scripts/dev/kind-cilium-up.sh`)
to answer the DNSSEC questions before any client-side step: `zone-manager-up.sh` builds the image
from the upstream Dockerfile at a pinned commit (with the two fixes it needs to start at all, see
`zone-manager-findings.md`), installs the upstream chart with a ReadWriteOnce volume and a fixed
ClusterIP for the DNS service, and prints the DS the zone manager generated. `toolbox.yaml` is the
pod to run the inspector from; `unbound-up.sh "<DS>"` starts a validating resolver anchored on that
DS, which is what the internet's resolvers become once the DS is published at the parent.

```bash
scripts/dev/kind-cilium-up.sh
scripts/verify-train-dns/kind/zone-manager-up.sh                 # prints the DS; keep it
kubectl -n train apply -f scripts/verify-train-dns/kind/toolbox.yaml
scripts/verify-train-dns/kind/unbound-up.sh "<the DS line>"     # prints the resolver's IP
kubectl -n train cp scripts/verify-train-dns/verify.sh dnscheck:/tmp/verify.sh
kubectl -n train exec dnscheck -- env ZONE=trust.ztd.test \
  SERVERS="ns1.trust.ztd.test=10.96.0.53 ns2.trust.ztd.test=10.96.0.53" EXPECT_DS="<the DS line>" \
  RESOLVERS=<resolver IP> WHERE="kind cluster ztd" REQUIRE_POINTER=0 OUT=/tmp/evidence.md bash /tmp/verify.sh
```

What that run showed, and the two experiments on top of it (re-signing by hand, recreating the
volume), is in `zone-manager-findings.md`; the inspector's evidence files from the healthy and the
broken state are next to the kit. They were written on 2026-10-07 by the inspector's first version,
which compared DS key tags only and read the NS set from the first server; the rebuilt volume gave
the zone a new key, so its tag and its digest both changed and the full comparison fails it the
same way (`verify_test.sh` has that case).
