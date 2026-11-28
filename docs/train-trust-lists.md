# TRAIN trust lists: zones and issuers

A verifier that consults TRAIN learns two things from it: which zones claim a trust framework, and
which issuers that framework trusts. The first lives in DNS, as PTR records the TSPA writes through
its zone manager; the second is the trust list, a signed document the TSPA serves and the TCR
fetches. Until now only the pipeline wrote into that list, one measurement entry per attested
component ([TRAIN publication step](train-publish.md)). This page is about the rest of its content,
the issuers and the zones, and how a change to what the system trusts happens: as a file in this
repository, changed by pull request, applied to the TSPA by a step that writes only the difference
and believes nothing it has not read back. It also fixes the window during which a removed issuer
is still trusted, and where the audit trail of every change is.

## The file

One file per trust framework, `deployment/train/trust-lists/<framework>.json`, against the contract
[`train-trust-list.v1`](contracts/train-trust-list.v1.schema.json):

```json
{
  "schemaVersion": 1,
  "framework": "facis-ztd.local",
  "zones": [{ "name": "a", "domain": "zone-a.facis-ztd.local" }],
  "issuers": [
    {
      "id": "issuer-a",
      "name": "Participant credential issuer of zone a",
      "serviceTypeIdentifier": "did:web:issuer-a.facis-ztd.local",
      "credentialTypes": ["ParticipantCredential"],
      "supplyPoint": "https://issuer-a.facis-ztd.local",
      "zone": "a"
    }
  ]
}
```

An issuer becomes one entry of the trust list. Its `serviceTypeIdentifier` is the string a verifier
hands the TCR as `issuer`, which the TCR matches against the entry's `ServiceTypeIdentifier`
(ADR-0011, 4.3): for a credential issuer that is its DID. The entry's UUID is derived from the
framework and the issuer's `id`, so the same issuer is always the same entry, and the entry carries
`{Type: managed-by, Value: train-trust-list/<framework>}` in its identifier list: the mark of what
this file owns. A zone is a DNS name that claims the framework; it changes nothing in the list.

The file on `main` today governs the framework the kind proofs use, with the demonstrator's two
zones and a credential issuer per zone under that name. The client's framework gets its own file
when its name is known ([For the client](#for-the-client)).

## The change: a pull request

Trusting a new issuer, or ceasing to, is an edit to that file. The pull request is the review and
the record: who proposed the change, who approved it, when it merged. Two things help the reviewer:

- the file is validated against the contract on every pull request (the `TRAIN trust lists` job
  runs `validate` on every file under `deployment/train/trust-lists/`, and the contracts job checks
  the schema's fixtures), and
- the change is said in words, not JSON: `reconcile.sh diff --from <main's file> --to <the branch's>`
  prints one line per issuer or zone added, removed or changed, naming the lookup key and, for a
  removal, that verifiers holding a cached copy keep trusting it until the window closes.

Nothing reaches the TSPA from the pull request. The repository's CI cannot see the client's TSPA,
and a pull request from a fork cannot see a secret ([CI/CD](ci-cd.md)); what CI proves is that the
reconciler does the right thing, against a stand-in on every pull request and against upstream's
real TSPA on kind when the step changes.

## The apply: the difference, then the read-back

After the merge an operator, or the orchestration that runs the lifecycle step, runs

```sh
scripts/train-trust-list/reconcile.sh apply --file deployment/train/trust-lists/<framework>.json
```

with the same environment the publisher uses: `TSPA_URL`, and `OIDC_TOKEN_URL` with
`OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` (a confidential client whose service account holds the
realm role `enrolltf`), or `TSPA_TOKEN_FILE`. The framework is the file's. The step:

1. reads the trust list and plans: an issuer with no entry is a `PUT`, one whose entry differs from
   what the file renders is a `PATCH` of the same entry, an entry with the marker whose issuer is no
   longer in the file is a `DELETE`; everything else is left alone;
2. refuses to write anything when an issuer names a lookup key another live entry already holds
   (`conflict`): the TCR returns one entry per key, which one is undefined, so the file is wrong,
   whatever that other entry is; and when the list carries one UUID twice (`duplicate-entry`);
3. writes in that order, each write judged as the TSPA page reads it: a `200` with an empty body is
   a write the TSPA did not run (`write-unconfirmed`), `401`/`403`/`400` are `write-rejected`;
4. reads the list again and plans again: only an empty plan proves the list follows the file. The
   time from the first write to that read-back is recorded.

Entries without the marker are never replaced or deleted, and an entry that sits under one of the
file's UUIDs without the marker stops the apply (`unowned-entry`): the pipeline's measurement
entries keep being the publisher's, and whatever the client's own tooling puts in the list stays.
Deletes run before creates, so an issuer that hands its lookup key to a new `id` (a rename is a
removal and a creation) never shares the key with its old entry. `plan` does
steps 1 and 2 and writes nothing; `verify` does the same and exits non-zero on any difference, so it
can run on a schedule as a drift check. Every run appends one line to `reconciliations.jsonl` and
prints it as `EVENT_JSON=`, the form the lifecycle step relays
([scripts/train-trust-list](../scripts/train-trust-list/README.md) lists the fields and outcomes).

## The window: what a removal does, and when

Removing an issuer from the file and applying it has three moments, and the ticket's question is the
distance between the first and the last:

| Moment | Where | Bound |
|---|---|---|
| the entry is gone from the list the TSPA serves and from the signed VC | TSPA | the read-back: well under a second on kind (under 0.1 s in the last runs of the proof) |
| a verifier that fetches the list now does not find the issuer | TCR | the next fetch: a TCR resolving at that moment gets the new VC |
| a verifier that fetched the list before stops trusting the issuer | TCR/gateway cache | the trust-list TTL, **300 s** ([architecture, staleness matrix](architecture.md#staleness-matrix)); a channel already open keeps its outcome until it is re-established, 15 min at most, so **about 20 min** for an established channel |

So "an update takes effect within the documented TTL" means: the TSPA side is immediate and
proven on every apply; the verifier side is bounded by its own cache, 300 s, and nothing on the
publishing side can shorten it. The DNS side does not move for an issuer change: the chain the TCR
walks (PTR, URI, DID document) names the list, not its entries. For a zone change it does, with the
TTLs the [TRAIN DNS zone](train-dns.md) page records.

What this side proves is that the list the TCR fetches no longer carries the issuer and that the
VC's hash changed. The read half, a verifier that stops trusting an entry within the cache window,
is proven for the measurement entries by the [TRAIN resolution at the handshake](train-resolve.md):
its proof on kind deletes an entry from this list while a verifier with the 300 s cache keeps
verifying, and times the refusal. For the issuer entries the same resolver finds the entry and
refuses it as carrying no measurement; that a credential verifier refuses an issuer's credentials
is still the credential side's proof, once a TCR runs against this list.

## The audit trail

Three records, each answering a different question:

| Question | Record |
|---|---|
| who changed what the system trusts, who approved it, when | the Git history of the file and its pull requests |
| what the TSPA was told, when, from which version of the file, and whether it was proven | `reconciliations.jsonl`: per run the action, the file's path, sha256 and the commit that last touched it (and whether it had uncommitted changes), the plan (ids created, replaced, deleted, unchanged, conflicts), every write with its method, UUID and status, the sha256 of the list read back, the hash inside the signed VC, the seconds to the read-back, the outcome |
| what the list said at a moment | the VC's `credentialSubject.hash` in that line: the TSPA signs the list it serves, and the hash identifies it |

The lines carry no token and no secret; the requests sent and the lists read are kept beside them
under `last/`.

## The zones

A zone claims the framework with one DNS record, `_scheme._trust.<zone domain> PTR
_scheme._trust.<framework>`, the first link of the chain the TCR walks ([TRAIN DNS zone](train-dns.md)).
`apply --with-zones` publishes it for each zone of the file with `PUT /trustframework/<zone domain>`
and the body `{"schemes": ["<framework>"]}`: in the TSPA's API, and in the zone manager's behind it,
the name in the path is the record's owner and the schemes are its targets, so the call goes to the
zone's domain, not to the framework. The zone's domain has to lie inside the DNS zone the manager
serves; a domain outside it is refused by the manager ("domain name not in current zone"), reported
by the TSPA as 500 and by the reconciler as `zones-not-published`. The zones come after the entries'
read-back, so such a run still carries a proven list. Each PTR is then asked from
`TRAIN_DNS_SERVER` (with `TRAIN_DNS_PORT` and `TRAIN_DNS_TCP=1` when the server is reached through a
port-forward, which carries TCP only), and only an answer naming the framework proves the zone.

On kind the proof runs the zone manager beside the TSPA (the kit's `TSPA_ZONE_MANAGER=1`, serving the
framework's DNS zone with the local Keycloak as the issuer the manager's API trusts), so the claims
are published and read back for real, by `dig` and through the manager's API. A zone removed from
the file is not removed from DNS by `apply`: the TSPA's API publishes scheme claims and does not
withdraw one; the DID record of the framework (`PUT /{fw}/did`) is not this step's either.

## What the proofs show

| Proof | Runs | Holds the step to |
|---|---|---|
| `scripts/train-trust-list/reconcile_test.sh` | the `TRAIN trust lists` job of the CI workflow, every pull request; seconds | the contract's refusals; a configuration refused before any call; an issuer renamed under a new id (removal, then creation, the key never shared); an entry under the file's UUID without the marker refused; the change in words; no list; the first apply as PUTs with the marker and stable UUIDs; a second apply that writes nothing; a renamed issuer as a PATCH of the same entry; a removed issuer as a DELETE with the publisher's entry untouched; verify finding drift and apply repairing it; a lookup key another entry holds; a duplicated entry; a wrong secret, a token without the role, a token the TSPA ignores; an unreachable and a broken TSPA; a writer racing the reconciler; the zones with a stubbed `dig`; no secret in any output |
| `scripts/verify-train-trust-list/verify.sh` | `train-publish.yml` on kind, when the step or its inputs change; locally, [`evidence.md`](../scripts/verify-train-trust-list/evidence.md) is the last run | against upstream's real TSPA with upstream's zone manager beside it: the repository's file applied as it is, the publisher's entry written into the same list and never touched, an issuer renamed, an issuer removed with the time to the read-back measured against the 300 s window and the VC's hash changing, verify and the repair of an entry edited by hand, a conflict with the connector's lookup key, a token without the role, the write-without-token quirk re-observed, the zones' claims published and their PTR records read back by `dig` and through the manager's API, a zone outside the DNS zone refused, no secret in any record |

## Status

| Done when | Proven where | Still needs |
|---|---|---|
| An update pull request takes effect within the documented TTL | the TSPA side on kind: the list and the VC follow the file within a second of the write; the verifier side measured on kind by the [TRAIN resolution](train-resolve.md) proof: a removal refused within the 300 s cache, through the resolver stand-in | a real TCR reading this list |
| Removing an entry causes dependent verification to fail | the publishing half: the entry and its lookup key are gone from the list and the VC the TCR fetches; the read half for measurement entries: the gateway's resolver refuses the peer within the window (`verify-train-resolve/evidence.md`) | the same refusal inside a real handshake (the gateway work); a credential verifier refusing an issuer's credentials |
| The change history is auditable | the Git history of the file; `reconciliations.jsonl` with file sha256, commit, plan, writes, list sha256 and VC hash per run | nothing on this side |

After the merge the ticket stays blocked, not done, until the joint proof with the read side and
the client's instance.

## For the client

Nothing here is specific to kind. To govern the client's trust list the following is needed, in the
order it blocks:

1. The framework's name and the TSPA base URL; whether the list exists (the reconciler never creates
   it) and who runs `PUT /init/json/{fw}/trust-list` once.
2. The issuers to trust: for each, its DID (the lookup key verifiers will present), a name, the
   credential types and where its service is reached. They go into
   `deployment/train/trust-lists/<framework>.json` by pull request.
3. An OIDC confidential client for the step whose service account holds the realm role `enrolltf`,
   its token endpoint and credentials as secrets, never in this repository.
4. For the zones: the zone manager reachable from the TSPA, the zone domains inside the DNS zone it
   serves, and a name server that answers for that zone for the PTR read-back (`TRAIN_DNS_SERVER`).
5. Confirmation that the instance runs the TSPA version verified here (commit `ecd5fdc`), or the
   differences in paths and schema.
