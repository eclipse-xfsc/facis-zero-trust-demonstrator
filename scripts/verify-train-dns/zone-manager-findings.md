# The TRAIN DNS zone manager on kind: what it does with keys and signatures

Findings from running `eclipse-xfsc/train-dns-trust-zone-manager` (commit `a431f14`, the `main`
HEAD on 2026-10-06) on the local kind cluster with `kind/zone-manager-up.sh`, to settle the DNSSEC
questions the zone needs answered before a DS is published at the parent: how long signatures stay
valid, whether anything re-signs the zone, and what happens to the keys when the pod's volume is
recreated. Everything below was observed on 2026-10-07 unless marked as read from source.

## 0. Before anything ran: the image does not build into a working container

The upstream `Dockerfile` starts `FROM python:3.11`. That tag now resolves to Debian 13 (trixie),
whose `python3-ldns` package — the DNSSEC signing library the zone manager uses — is built for the
system Python 3.13 (`_ldns.cpython-313-aarch64-linux-gnu.so`). The image's own interpreter is
Python 3.11, so the first `import ldns` fails with `ModuleNotFoundError: No module named '_ldns'`
and `script.sh` (which runs under `set -e`) exits before the zone exists.

Pinning the base to `python:3.11-bookworm` (Debian 12, system Python 3.11) makes the binding match;
`kind/zone-manager-up.sh` applies that one-line change before building. Whoever deploys the zone
manager for real inherits the same problem unless they take an image built before the tag moved.
Reported upstream as [#39](https://github.com/eclipse-xfsc/train-dns-trust-zone-manager/issues/39).

## 1. What the zone manager does, observed

Stood up with `kind/zone-manager-up.sh` (zone `trust.ztd.test`, DNS service at `10.96.0.53`), queried
from a pod in the cluster (`kind/toolbox.yaml`) and through a validating resolver anchored on the
zone's own DS (`kind/unbound-up.sh`). The inspector's evidence for the healthy state is
`kind/evidence-kind.md`; for the broken state, `kind/evidence-kind-volume-recreated.md`.

| Question | Answer | How it was seen |
|---|---|---|
| Keys | One KSK and one ZSK, ECDSA P-256 (algorithm 13), created by `add-zone` at the first start and stored in `zones.db` on the volume. The private keys are also left in clear in `private_key.tmp` next to it. | `ls /var/lib/zonemgr`, `dig DNSKEY +multi` |
| DS | Printed to the pod log once, by `add-zone`; no API or CLI returns it later. `trust.ztd.test. 3600 IN DS 54033 13 2 f020bc…` at the first start. | pod log |
| Signature validity | 28 days: `RRSIG SOA … 20261104092048 20261007092048` (expiration, inception) for a zone signed at 09:20:48 on 7 Oct. ldns' default; nothing in the zone manager sets it. | `dig +dnssec SOA` |
| Re-signing | Every write re-signs the whole zone (inception and expiration move to "now" and "now + 28 d", SOA serial becomes the Unix time). The nightly job never runs: the crontab is installed for user `zonemgr` but calls `/usr/lib/zonemgr/zonemanager.py`, which does not exist (the entry point is `/usr/local/bin/dns-zone-manager-server`), and no `cron` process is started. `dns-zone-manager-server --database sqlite:////var/lib/zonemgr/zones.db resign` run by hand does the job (the fix is to run exactly that, daily). Reported upstream as [#41](https://github.com/eclipse-xfsc/train-dns-trust-zone-manager/issues/41). | `crontab -l`, `pgrep cron`, `resign` by hand, `dig +dnssec SOA` before and after |
| Denial of existence | NSEC with TTL 3600 (the SOA minimum); the records themselves get TTL 3600 from the CLI and TTL 0 from the API. | `dig +dnssec` for a missing name |
| Pod restart, volume kept | Keys and zone survive (`A zone DB file was found`), but NSD serves nothing — see §2. | `nsd-control zonestatus`, `dig` |
| Volume recreated | New keys: the DS became `… DS 38490 13 2 ca6530…`. A validating resolver still anchored on the first DS answers SERVFAIL (NOERROR with checking disabled) as soon as its cache is empty; the inspector reports the DS mismatch and the bogus state. | `kind/evidence-kind-volume-recreated.md` |
| Validation with a DS | With the right DS as trust anchor, the resolver validates the zone (`ad` flag) and every inspector check passes, pointer included. | `kind/evidence-kind.md` |

Two more things worth knowing before the zone is operated:

- **Negative answers are cached with proof.** After a resolver has been asked for a pointer that
  did not exist yet, it keeps the signed denial for the NSEC TTL (3600 s) and keeps answering
  NXDOMAIN with `ad` after the record is published — the record is at the server, and the
  resolver is right by its own rules. A newly published pointer reaches validating resolvers up
  to an hour late. This is the window any "takes effect within the TTL" statement about trust-list
  changes has to count with, and why the inspector queries the authoritative servers directly as well.
- **`auth.conf` is executed as Python** (`zonedb/api.py`: `exec`). The chart writes the values
  verbatim, so each one must carry its own quotes, and whoever can edit that ConfigMap can run
  code in the zone manager.

## 2. NSD serves no zone after a start — any start

`script.sh` starts NSD at the top, then builds the zone and writes `nsd.conf.d/zonemgr.conf`,
the file that includes the zone list, and then runs `service nsd start` again — a no-op on a
running daemon. NSD therefore never reads the include: `nsd-control zonestatus` lists no zone and
every query gets REFUSED, at the first start and after every pod restart with the volume kept.
The zone appears only when something runs `nsd-control reconfig`, which every write does (through
`reload-nsd.sh`) and nothing else does. On a real cluster that means a node drain, an upgrade or
an OOM restart takes the zone down silently until the next trust-list change.

Observed twice: 0 zones and REFUSED right after the first start and again after a plain
`kubectl delete pod`; 1 zone and NOERROR right after `nsd-control reconfig && nsd-control reload`.
Reported upstream as [#40](https://github.com/eclipse-xfsc/train-dns-trust-zone-manager/issues/40).
`kind/zone-manager-up.sh` patches `script.sh` to run that pair after writing the config, and with
that image both paths serve the zone within five seconds of the pod becoming Ready: a restart with
the volume kept (same KSK, 38490) and a first start on a new volume (new KSK, 61492, DS printed).

## 3. What this settles for the DNS zone ticket

- A DS can be published only once the keys are protected from a volume rebuild (retain the
  volume, back up `zones.db`, and have the DS-change procedure with the parent's operator ready)
  and the daily `resign` runs somewhere that survives restarts. Both are small; neither is in the
  software as shipped.
- The deployment needs the three fixes from this kit (base image, NSD reconfig at start, RWO
  volume on providers without RWX) plus a readiness probe on `nsd-control zonestatus`, so a
  pod that serves no zone is not Ready.
- The inspector's `SERVERS` and `EXPECT_DS` options cover the time between the deployment and the
  delegation, and catch a key change before the DS is live.
