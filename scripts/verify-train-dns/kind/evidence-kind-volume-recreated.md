# Trust-framework DNS evidence for `trust.ztd.test` (2026-10-07T09:26:55Z)

Run from kind cluster ztd, volume recreated, validator anchored on the first DS; resolvers: `10.244.1.216`; dig 9.18.39-0ubuntu0.24.04.7-Ubuntu.

Authoritative queries are sent without recursion (`+norec`) straight to the servers the delegation names, so an answer there proves the server itself, not a cache.


## 1. Delegation at the parent

- INFO: servers given directly (SERVERS); the delegation at the parent is not looked up
  ns1.trust.ztd.test. ns2.trust.ztd.test.

## 2. Authoritative servers

- PASS: ns1.trust.ztd.test. has an address
  10.96.0.53
- PASS: ns1.trust.ztd.test. (10.96.0.53) answers the SOA authoritatively over udp
  status NOERROR, flags: qr aa, serial 1791365174
- PASS: ns1.trust.ztd.test. (10.96.0.53) answers the SOA authoritatively over tcp
  status NOERROR, flags: qr aa, serial 1791365174
- PASS: ns2.trust.ztd.test. has an address
  10.96.0.53
- PASS: ns2.trust.ztd.test. (10.96.0.53) answers the SOA authoritatively over udp
  status NOERROR, flags: qr aa, serial 1791365174
- PASS: ns2.trust.ztd.test. (10.96.0.53) answers the SOA authoritatively over tcp
  status NOERROR, flags: qr aa, serial 1791365174
- PASS: every authoritative server serves the same SOA serial
  serials: 1791365174 1791365174
- PASS: the NS set inside the zone matches the delegation at the parent
  zone: ns1.trust.ztd.test. ns2.trust.ztd.test.; parent: ns1.trust.ztd.test. ns2.trust.ztd.test.

## 3. TRAIN pointer records

The content resolver starts at `_scheme._trust.trust.ztd.test` (PTR), then reads the URI record at each target, which names the DID of the trust list.

- INFO: ns1.trust.ztd.test. serves the pointer _scheme._trust.trust.ztd.test
  status NXDOMAIN; targets: none
- INFO: ns2.trust.ztd.test. serves the pointer _scheme._trust.trust.ztd.test
  status NXDOMAIN; targets: none

## 4. Resolution through recursive resolvers

What a client where this script runs sees. `ad` in the flags means the resolver validated the answer with DNSSEC.

- **FAIL**: resolver 10.244.1.216 resolves the SOA of trust.ztd.test
  status SERVFAIL, flags: qr rd ra
  delv: resolution failed: failure
- INFO: resolver 10.244.1.216 resolves the pointer _scheme._trust.trust.ztd.test
  status SERVFAIL; targets: none

## 5. DNSSEC state

The zone manager signs the zone with keys it generated at first start; the DS at the parent must match its key-signing key (KSK), and the signatures must not expire before the next re-sign.

- INFO: the zone is signed (DNSKEY read from ns1.trust.ztd.test.); KSK key tag(s): 38490
- **FAIL**: the DS recorded for publication (EXPECT_DS) matches a KSK the zone serves
  DS tags: 54033; KSK tags: 38490
- INFO: no DS at the parent: the signatures are not validated by resolvers (insecure delegation). Publish the DS of the KSK above once key persistence and re-signing are proven.
- PASS: the SOA signature is valid for at least 7 more days
  expires 20261104092614 UTC, 27 day(s) left
- **FAIL**: resolver 10.244.1.216 does not reject the zone as bogus (SERVFAIL that disappears with checking disabled)
  validated: SERVFAIL, checking disabled: NOERROR

## Summary

| Item | State |
|---|---|
| Run from | kind cluster ztd, volume recreated, validator anchored on the first DS |
| Delegation | not looked up; servers given directly |
| Pointer | not published |
| DNSSEC | signed, no DS (insecure delegation), signatures expire 20261104092614 |
| Checks failed | 3 |
