# TRAIN resolution against the real TSPA and name server: evidence

Run of `scripts/verify-train-resolve/verify.sh` on 2026-11-22T11:52:40Z against upstream's TSPA `ecd5fdc` built from its Dockerfile and upstream's zone manager, on kind. The code the run used: `internal/trainresolve` and `cmd/train-resolve-probe` of this checkout (probe built from it), the resolver stand-in `fake_tcr.py` sha256 `f73feffc3d531be0ba654e8f827a88d6bf52dc55a68a5478a670221c51feafd8`. Window measured against: 300 s. Raw records: the `--out` directory (per case: the probe's records, stdout and stderr; the publisher's and reconciler's outputs; the stand-ins' request logs; the kind-up log).

## Summary of the cases

| Case | Expected | Code or outcome | Exit |
|---|---|---|---|
| match | accepted | `accepted` | 0 |
| cache | accepted, second from the cache | `accepted` | 0 |
| mismatch | CHAN-MEASUREMENT-MISMATCH | `CHAN-MEASUREMENT-MISMATCH` | 2 |
| unpublished | CHAN-MEASUREMENT-UNPUBLISHED | `CHAN-MEASUREMENT-UNPUBLISHED` | 2 |
| issuer entry | CHAN-MEASUREMENT-UNPUBLISHED (entry named) | `CHAN-MEASUREMENT-UNPUBLISHED` | 2 |
| unknown zone | CHAN-ZONE-UNKNOWN | `CHAN-ZONE-UNKNOWN` | 2 |
| rolling update, both versions | accepted | `accepted` | 0 |
| after the prune, v1 | CHAN-MEASUREMENT-MISMATCH | `CHAN-MEASUREMENT-MISMATCH` | 2 |
| removal within the window | CHAN-MEASUREMENT-UNPUBLISHED within 300 s | `CHAN-MEASUREMENT-UNPUBLISHED` | 0 |
| zero values | CHAN-MEASUREMENT-UNPUBLISHED (entry named) | `CHAN-MEASUREMENT-UNPUBLISHED` | 2 |
| credential not verified | CHAN-TRUST-UNREACHABLE | `CHAN-TRUST-UNREACHABLE` | 2 |
| resolver answering 502 | CHAN-TRUST-UNREACHABLE | `CHAN-TRUST-UNREACHABLE` | 2 |
| resolver down | CHAN-TRUST-UNREACHABLE | `CHAN-TRUST-UNREACHABLE` | 2 |
| resolver whose TSPA is down | CHAN-TRUST-UNREACHABLE | `CHAN-TRUST-UNREACHABLE` | 2 |

**Verdict: all 45 checks passed.**

## 1. The TSPA, Keycloak, the zone manager and the lanes to them

- PASS: the TSPA answers through the port-forward (GET /api/docs 200)
- PASS: the zone manager's name server answers authoritatively for facis-ztd.local over the forwarded TCP port
  SOA of `facis-ztd.local`: `ns1.facis-ztd.local. zonedb.facis-ztd.local. 1795306613 28800 7200 604800 3600`
## 2. The trust list, the zones' claims in DNS, the gateway's measurement entry

The operator creates the list once; the reconciler applies the repository's file with `--with-zones`, so each zone's claim becomes a real PTR record in the zone manager's name server; the publisher writes the gateway's entry under its own UUID with the lookup key the gateway will present: its identity, `spiffe://zone-b.facis-ztd.local/gateway`. The record is synthetic (the measuring step is not part of this proof); what matters is a real entry in a real list reached through a real PTR.

- PASS: the trust list of facis-ztd.local is created by the operator (PUT init, 201)
- PASS: the repository's trust-list file is applied with the zones' claims (exit 0, applied)
- PASS: dig PTR _scheme._trust.zone-b.facis-ztd.local answers _scheme._trust.facis-ztd.local. (the pointer the gateway derives from the peer's identity is anchored)
- PASS: no PTR record for a zone outside the framework (zone-c.other.test)
- PASS: the reconciler's issuer entries are in the list (issuer-b: 9e031244-fd58-5a57-96b9-9885ca279894)
- PASS: the publisher writes the gateway's entry with v1 (exit 0, published)
- PASS: the entry's lookup key is the gateway's identity
  the gateway's entry: UUID `f1548a40-feea-5748-85eb-6f146cd09cf5`, lookup key `spiffe://zone-b.facis-ztd.local/gateway`, value `8ccdfa6a0862...`; the list holds 3 entries
## 3. The resolver stand-in over the real name server and the real list

`scripts/train-resolve/fake_tcr.py` answers `POST /tcr/v1/resolve` the way upstream's resolver does: the pointer is asked of the zone manager's name server (`dig PTR _scheme._trust.<pointer>`, over the forwarded TCP port), the framework it names gives the DID and the trust-list URIs at the TSPA, the list is read and the entry whose `ServiceTypeIdentifier` equals the issuer is returned. What it leaves out is the real resolver's (signature, hash, DID document, DNSSEC); see its README.

- PASS: the stand-in answers its health
- PASS: asked directly, the stand-in walks the PTR to the framework's DID
- PASS: asked directly, the stand-in returns the gateway's entry from the real list, credential read

```
{"pointers":[{"pointer":"zone-b.facis-ztd.local","dids":["did:web:facis-ztd.local"]}],"endpoint":{"tlUri":"http://127.0.0.1:52452/tspa-service/tspa/v1/facis-ztd.local/trust-list","vcVerified":true,"entry":"f1548a40-feea-5748-85eb-6f146cd09cf5"}}
```

## 4. The peer presenting the published measurement is accepted

- PASS: accepted: exit 0, outcome accepted
- PASS: accepted: the key is the identity, the pointer is the zone domain
- PASS: accepted: one expected value, the publisher's entry, the real list's URI
- PASS: accepted: not from the cache, within the handshake budget (30 ms)

```
{"schema":"train-resolve-probe-record/v1","attempt":1,"identity":"spiffe://zone-b.facis-ztd.local/gateway","key":"spiffe://zone-b.facis-ztd.local/gateway","pointers":["zone-b.facis-ztd.local"],"outcome":"accepted","fromCache":false,"expectedCount":1,"entryUUID":"f1548a40-feea-5748-85eb-6f146cd09cf5","trustList":"http://127.0.0.1:52452/tspa-service/tspa/v1/facis-ztd.local/trust-list","elapsedMs":30,"stats":{"Hits":0,"Misses":1,"Flights":1,"Refusals":0}}
```

## 5. Two verifications in one process: the second is served from the cache

- PASS: cache: both accepted, the second from the cache, one resolution
## 6. A peer presenting another measurement is refused

- PASS: mismatch: exit 2, CHAN-MEASUREMENT-MISMATCH, the expected value was there
  reason: `the peer presented 1 measurement(s) [2344c51c3e5a...], TRAIN expects 1 value(s) [8ccdfa6a0862...]`
## 7. A peer nobody published, in a known zone

- PASS: unpublished: exit 2, CHAN-MEASUREMENT-UNPUBLISHED, no entry
## 8. An issuer's entry is not a measurement

The reconciler's issuer entries share the list. Looked up under an issuer's key, the entry is found, but it carries no TEEM-sha256 value: not published, with the entry named, never accepted.

- PASS: issuer entry: CHAN-MEASUREMENT-UNPUBLISHED with the issuer's entry named
## 9. A peer from a zone without a claim: unknown zone

- PASS: unknown zone: exit 2, CHAN-ZONE-UNKNOWN (no PTR record in the name server)
- PASS: unknown zone: the stand-in reported the pointer's DNS error
## 10. A rolling update: v2 published beside v1, both accepted; pruned to v2, v1 refused

- PASS: the publisher adds v2 beside v1 (exit 0)
- PASS: during the rollout v1 is accepted, two values expected
- PASS: during the rollout v2 is accepted
- PASS: the publisher prunes to v2 (exit 0)
- PASS: after the prune v1 is refused, one value expected
- PASS: after the prune v2 is accepted
## 11. A removal bites within the window: the real cache of 300 s

One probe process keeps verifying v2 every 5 s with the documented TTL. Once it has accepted, the operator deletes the gateway's entry. The refusal must arrive no earlier than the deletion and no later than the first acceptance plus the window plus one interval: that is the window the staleness matrix documents, measured.

- PASS: the probe accepted v2 before the removal
- PASS: the operator deletes the gateway's entry (DELETE 200)
- PASS: the list no longer holds the entry
- PASS: the refusal arrived before the deadline (exit 0)
- PASS: the refusal came within the window plus one interval: 300103 ms after the first acceptance, window 300 s
- PASS: the refusal never came before the deletion (292953 ms after it)
- PASS: no refusal was recorded before the deletion; every verification until then was accepted from the cache
  first acceptance 2026-11-22T11:47:39.015359Z; deletion 2026-11-22T11:47:46.165+00:00; refusal 2026-11-22T11:52:39.118723Z; verifications: 61

```
{"untilCode":"CHAN-MEASUREMENT-UNPUBLISHED","attempts":61,"observed":true,"firstAcceptedAt":"2026-11-22T11:47:39.015359Z","transitionAt":"2026-11-22T11:52:39.118723Z","transitionAfterMs":300103}
```

## 12. An entry without a TEEM-sha256 value: not published

- PASS: the publisher writes the entry again (exit 0)
- PASS: the entry is patched to zero TEEM-sha256 values (PATCH 200)
- PASS: zero values: CHAN-MEASUREMENT-UNPUBLISHED with the entry named
## 13. A resolver that cannot verify the credential, a resolver failing, a resolver down

- PASS: credential not verified by the resolver: CHAN-TRUST-UNREACHABLE
- PASS: credential not verified: the reason says so
- PASS: resolver answering 502: CHAN-TRUST-UNREACHABLE naming the status
- PASS: resolver down: CHAN-TRUST-UNREACHABLE within the handshake budget (0 ms)
- PASS: resolver whose TSPA is down: CHAN-TRUST-UNREACHABLE
## 14. No secret in any record

- PASS: the client secret appears in no record, output or log kept
- PASS: no bearer token appears in any record, output or log kept
