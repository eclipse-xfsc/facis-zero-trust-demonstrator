# TRAIN DNS zone

TRAIN anchors trust in DNS. When the attested channel forms, the verifier does not hold a list of
whom to trust; it holds a domain name, and the content resolver (TCR) turns that name into the
signed trust list by walking a chain of DNS records. The first link of that chain is a DNS zone
that answers for the trust framework. This page is the record of that zone: how it is delegated,
what it serves, what its DNSSEC state is and how re-signing happens, how it is verified, and how a
failure becomes an alert rather than a silent refusal. The verification script and the kit that
produced the observations are in `scripts/verify-train-dns/`.

## The chain the zone starts

```
_scheme._trust.<zone>        PTR  → _scheme._trust.<framework>      (a scheme claim)
_scheme._trust.<framework>   URI  → did:web:…                       (the DID of the trust list)
                             DID document → trust-list VC → trust list → entry for the peer
```

The TCR starts at `_scheme._trust.<zone>` and follows PTR targets and URI records until it holds a
DID; everything after that is HTTPS, described in [TRAIN trust-list publishing](tspa-publish-api.md).
Three components touch the zone:

| Component | Role for the zone | Who runs it |
|---|---|---|
| Zone manager (`train-dns-trust-zone-manager`) | The authoritative DNS server for the zone (NSD) and the API that writes the PTR and URI records, signing the zone on every write | The demonstrator, as part of the XFSC stack |
| TSPA | Publishes the scheme claim and the DID through the zone manager's API when a framework is registered | The demonstrator |
| TCR | Reads the chain for the verifier, with DNSSEC validation on by default | The demonstrator |

Nothing in the chain is reachable from outside the zone manager's own cluster until the parent
domain's DNS points at it. That delegation is the one step the demonstrator cannot perform itself.

## Delegation

A zone exists for the world when two things are true at once: a server answers for it, and the
parent zone names that server. The parent is a domain the client owns; its operator adds the
records, we supply them. The request goes to the client in two messages, because the records
name an address that exists only once the zone manager runs on the dedicated clusters behind a
public address — the shared namespace available today cannot expose port 53. The steps alternate:

1. **First message: three questions.** The zone name — one label under a domain the client
   controls, for example `trust.<domain>`; who operates the parent zone, so the records reach the
   right hands; and whether the parent zone is DNSSEC-signed, because only a signed parent can
   publish the DS record and so validate the chain end to end. The same message says that the DS
   comes as a separate, later step, and why ([DNSSEC](#dnssec)): the client had asked for the DS to
   be part of the delegation, so the change of order is stated, not implied.
2. **Deploy the zone manager** behind a public address on port 53, UDP and TCP, on the dedicated
   clusters.
3. **Second message: the records.** The zone manager publishes two name-server names at the apex
   (`PRIMARY_SERVER_NSD` and `SECONDARY_SERVER_1_NSD` in its configuration), so the parent must
   delegate both; until a real secondary exists, both resolve to the same address:

    ```
    <zone>.        IN NS  ns1.<zone>.
    <zone>.        IN NS  ns2.<zone>.
    ns1.<zone>.    IN A   <public address>     ; glue: the server's name is inside the zone it serves
    ns2.<zone>.    IN A   <public address>
    ```

    The glue records break a circle: to ask `ns1.<zone>` anything, a resolver needs its address, and
    that address lives in the zone `ns1` itself serves. The parent hands out name and address in the
    same referral. A low TTL (300 s) on these four records keeps an address change cheap while the
    deployment settles.
4. **The parent operator publishes the four records** — and no DS record yet.
5. **Verify**, from outside and from each cluster, with `scripts/verify-train-dns/verify.sh`, and
   keep the evidence.
6. **The DS, last.** Once key persistence and the daily re-sign are proven on the deployed instance
   — a closing criterion of the zone manager's deployment — the DS record goes to the parent
   operator as one more record, and the chain validates end to end.

Between steps 2 and 3 the zone can already be checked by naming the servers directly
(`SERVERS=`) and the DS the zone manager printed (`EXPECT_DS=`); see the script's README.

## What the zone serves

Written by the zone manager at first start from its configuration, then by TSPA through the API:

| Record | Written by | TTL | Note |
|---|---|---|---|
| `SOA` | zone manager | 3600 | serial is the Unix time of the last write; refresh 28800, retry 7200, expire 604800, minimum 3600 |
| `NS` ×2 (`ns1`, `ns2`), `A` for `ns1`, `ns2`, `ns3` and for the apex | zone manager, at first start | 3600 | from `TF_DOMAIN_*`, `PRIMARY_SERVER_*`, `SECONDARY_SERVER_*` |
| `_scheme._trust.<zone> PTR` | TSPA (`PUT /trustframework/{fw}`) | 0 | the scheme claim; 3600 when added through the zone manager's CLI |
| `_scheme._trust.<framework> URI` | TSPA (`PUT /{fw}/did`) | 0 | `10 1 "did:…"` |
| `DNSKEY`, `RRSIG`, `NSEC` | zone manager, on every write | 3600 | see below |

Denial of existence uses NSEC (the zone is walkable; it holds nothing secret) with the SOA minimum
of 3600 s, which is also how long a resolver keeps a signed "does not exist" answer — the
[caching window](#caching-windows) that matters most.

## DNSSEC

**Keys.** The zone manager generates one key-signing key (KSK) and one zone-signing key (ZSK),
ECDSA P-256 (algorithm 13), when it creates the zone at its first start, and stores them in its
SQLite database on the pod's volume. It leaves the private keys in clear in `private_key.tmp` next
to the database as well. There is no key rollover command: the keys the zone has are the keys it
will have until the database is lost, and then it silently makes new ones.

**The DS.** The fingerprint of the KSK, the record the parent publishes to make validation
mandatory, is printed to the pod log once, when the zone is created, by the `add-zone` command. No
API or CLI returns it afterwards. Record it from the log at first start
(`scripts/verify-train-dns/kind/zone-manager-up.sh` prints it), or recompute it from the key the
zone serves:

```bash
dig +noall +answer DNSKEY <zone> @<server> | awk '$5==257' | dnssec-dsfromkey -2 -f - <zone>
```

(`dnssec-dsfromkey` is in `bind9-utils`; on kind this reproduced the DS the zone manager had printed.)

**Signatures.** Every write re-signs the whole zone with signatures valid for 28 days from the
moment of the write (ldns' default; nothing in the zone manager changes it). A zone that nobody
writes to for 28 days serves expired signatures, which validating resolvers refuse exactly as they
refuse a wrong key.

**Re-signing.** The zone manager ships a nightly `resign` job that never runs: its crontab calls a
file that does not exist, and no cron daemon is started in the container
([upstream #41](https://github.com/eclipse-xfsc/train-dns-trust-zone-manager/issues/41)). The command itself works and renews the 28 days:

```bash
dns-zone-manager-server --database sqlite:////var/lib/zonemgr/zones.db resign
```

The deployment therefore runs that command on its own schedule — daily, in the zone manager's pod —
and the verification script fails when fewer than `MIN_SIG_DAYS` (7) remain, so a job that stopped
is noticed three weeks before it matters.

**When the DS is published.** A DS at the parent is a commitment: from then on every validating
resolver refuses the whole zone the moment the key or the signatures are wrong, and the TCR reports
that refusal as an empty trust list. Two properties of the zone manager as shipped make the
commitment unkeepable at first: the keys do not survive a rebuilt volume, and nothing re-signs. So
the zone is delegated **without** a DS first. This reverses the order first discussed with the
client, who had asked for the DS to be part of the delegation and welcomed it "if the full chain can
be validated"; the request therefore says in so many words that the DS comes second, and why.
Resolvers meanwhile treat the zone as insecure — they accept its answers unvalidated, as they do for
most of the internet — and the TCR's validation, which stays on, passes it as insecure rather than
bogus. The DS is sent to the parent operator once three things hold on the deployed instance, which
the zone manager's deployment lists among its closing criteria:

- the volume is retained across reinstalls and `zones.db` is backed up, so the keys persist;
- the daily `resign` job runs and the signature expiry is observed to move;
- the procedure for a key change is agreed with the parent operator: remove the DS, wait for its TTL
  to pass, change the keys, publish the new DS. The zone manager cannot double-sign, so a key change
  with a DS in place is an outage of at least the DS TTL.

This is the reading declared in [Specification changes](specifications.md): the zone is signed from
its first start; the anchoring at the parent follows the proof that the signing can be kept up.

## Operating the zone manager

Running the upstream component as shipped was tried on the local kind cluster
(`scripts/verify-train-dns/kind/`, findings in `scripts/verify-train-dns/zone-manager-findings.md`).
Four things the deployment has to carry, in the order they bite:

| Defect as shipped | Effect | What the deployment does |
|---|---|---|
| `FROM python:3.11` now resolves to Debian 13, whose `python3-ldns` is built for Python 3.13 ([upstream #39](https://github.com/eclipse-xfsc/train-dns-trust-zone-manager/issues/39)) | the container exits at `import ldns` | build on `python:3.11-bookworm` |
| NSD starts before the zone's `include` is written, and the second `service nsd start` is a no-op ([upstream #40](https://github.com/eclipse-xfsc/train-dns-trust-zone-manager/issues/40)) | after every start — first or restart — NSD serves no zone: every query is REFUSED until the next write | `nsd-control reconfig && nsd-control reload` after the configuration is written; a readiness probe on `nsd-control zonestatus` so a pod that serves nothing is not Ready |
| The chart's volume claim asks for `ReadWriteMany` | pending forever on block storage | `ReadWriteOnce`; the pod is single-replica by design (one NSD, one database) |
| `auth.conf` is executed as Python (`exec`) | unquoted values are a syntax error at import; whoever edits the ConfigMap runs code in the zone manager | values carry their own quotes; the ConfigMap is management-plane only |

Also to be kept in mind: the DNS service needs TCP and UDP 53 on one public address (a mixed-protocol
LoadBalancer, or a static address); the private keys on the volume are readable by anyone who can
read the volume; and the API's write routes expect an OIDC bearer token whose audience is the
configured `CLIENT_ID` — TSPA's token, in the real deployment.

## Verification

`scripts/verify-train-dns/verify.sh` is the inspector. It walks the chain this page describes and
writes a PASS/FAIL evidence file; its exit status fails a pipeline. What it proves, in order:

1. the delegation at the parent — NS set, glue, DS present or absent;
2. every name server the delegation names answers authoritatively over UDP and TCP, all with the
   same serial, and each with the same NS set inside the zone as the delegation;
3. the `_scheme._trust` pointer on every server, and the URI record at each of its targets;
4. resolution through recursive resolvers, from wherever it runs: the SOA, the pointer, and the URI
   at every target a resolver returns, through that same resolver — one that still caches a
   negative answer for a URI breaks discovery for its clients while the others are right;
5. the DNSSEC state — every server serving the same key-signing key; the DS at the parent and the
   one recorded for publication compared in full (owner, algorithm, digest type, digest) with the
   DS computed from that key, since a right key tag with a wrong digest is refused like any other
   wrong DS; days of signature validity left; and whether any resolver rejects the zone as bogus
   (SERVFAIL that turns into NOERROR with checking disabled).

Run it from outside as it is, and inside each cluster with `RESOLVERS` set to the cluster resolver
(the README has the pod recipe), so the evidence shows what a workload there sees. Before the
delegation, `SERVERS=` names the zone manager directly and `EXPECT_DS=` compares the recorded DS
with the live key, whether the zone is signed or not — which is how a rebuilt volume, or a server
that answers unsigned, shows up as a FAIL before anyone publishes the wrong DS. On kind, against
the upstream zone manager, the healthy state passed every check and the rebuilt-volume state failed
exactly the DS and bogus checks; both evidence files are kept next to the kit. Each failure mode the
inspector claims to catch is also a case in `verify_test.sh`, run in CI against local NSD servers
that break one thing each, behind a signed parent zone and a validating resolver.

## Caching windows

Four windows govern how fast a change at the zone is seen, and they are not the same:

| Change | Seen after | Why |
|---|---|---|
| A new pointer or DID, by a resolver that never asked for it | at once | the records carry TTL 0 (API) |
| A new pointer, by a resolver that asked before it existed | up to 3600 s | the signed denial (NSEC, SOA minimum 3600) is cached and answered from, validly, until it expires |
| A removed pointer | at once for API-written records (TTL 0); up to 3600 s for records written through the CLI | the positive answer is cached for its TTL |
| A DS or key change | DS TTL at the parent plus DNSKEY TTL (3600) | both sides cache |

The second row was observed on kind: the record was at the server, a validating resolver that had
been asked a minute earlier still answered NXDOMAIN with the `ad` flag. It is the reason the
inspector asks the authoritative servers directly as well as the resolvers, and the window any
"takes effect within the TTL" statement about trust-list changes has to include.

## How a failure stays quiet, and the alert that does not let it

The TCR turns every DNS answer that is not NOERROR into an empty result: a lame delegation, an
expired signature, a wrong DS and "nothing is published" all look the same to the verifier, which
then refuses the peer with no indication that DNS was the cause. Fail-closed is the right outcome
(ZT-52); the silence is not, and ZT-52 asks for control-plane failures to be detected and alerted
within 30 seconds.

The alert has two parts, wired into the observability stack when it lands:

- **A resolution probe every 5 s**, from inside each cluster through its resolver: a blackbox DNS
  probe for `_scheme._trust.<zone>` (type PTR, answer must contain a PTR) and for the SOA at each
  authoritative address, each with a 4 s timeout. Two failed probes in a row raise the alert
  (`probe_success == 0` with `for: 5s`, in a rule group evaluated every 5 s), so a single lost UDP
  packet does not. The probe through the resolver catches what the verifier would see; the probes
  at the servers say which link broke.
- **The inspector once a day** as a job in one cluster, with `MIN_SIG_DAYS=7` and `EXPECT_DS` set to
  the published DS; a failed job is the alert. It catches the slow failures a liveness probe cannot:
  signatures running out, a key that no longer matches the DS, a delegation changed at the parent.

The 30 seconds run from the failure to the notification, so every delay on the way counts. Worst
case, for a failure that starts just after a successful probe:

| Step | Worst case | Why |
|---|---|---|
| Until the next probe starts | 5 s | probe interval (the scrape interval of the probe job) |
| Until that probe fails | 4 s | a server that does not answer fails at the timeout; a SERVFAIL or a missing record fails at once |
| Until a rule evaluation reads the failure | 5 s | evaluation interval; the alert is now pending |
| Until it fires | 5 s | `for: 5s`: the next evaluation, which reads the second failed probe |
| Until Alertmanager sends the notification | 5 s | `group_wait: 5s` on the route for this alert |
| **Total** | **24 s** | 6 s left for delivery to the receiver |

Neither setting can be left at its default: Prometheus evaluates rules every minute and Alertmanager
waits 30 s before the first notification of a new group, either of which alone exceeds the budget.

Until the stack exists, the daily inspector run and its evidence file are the record.

## Status

| Done when | Proven where | Still needs |
|---|---|---|
| Delegation completed | — | the first message (the three questions) is written; the records follow the deployment on the dedicated clusters; the parent-zone operator publishes them |
| Records resolve from all three clusters and from outside | on kind: from inside the cluster, direct and through a validating resolver | the delegation, the two OSC clusters |
| DNSSEC status recorded, including re-signing | this page, with the observations in `zone-manager-findings.md` | the daily `resign` job and the volume retention on the real deployment, then the DS |
| A resolution failure raises an alert | the probe and the job are specified; the inspector detects every failure mode seen | the observability stack |
