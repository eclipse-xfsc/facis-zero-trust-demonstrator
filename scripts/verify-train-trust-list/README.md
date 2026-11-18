# verify-train-trust-list

Proof of the trust-list reconciliation ([`scripts/train-trust-list/reconcile.sh`](../train-trust-list/README.md))
against the real TSPA, on kind: upstream's image built from its Dockerfile at the pinned commit,
upstream's Helm chart and test realm, from the kit under [`scripts/verify-tspa-api`](../verify-tspa-api/README.md).
The reconciler and the publisher run on the host through port-forwards, as the operator will run
them against the client's instance.

```sh
TSPA_REPO=/path/to/train-trust-framework-manager scripts/verify-train-trust-list/verify.sh
```

Needs `kind`, `kubectl`, `helm`, `docker`, `curl`, `jq`, `python3`, `sha256sum` and `dig`. The first
run builds the TSPA image, about fifteen minutes; later runs reuse it. The evidence goes to
`evidence.md` next to the script (`TRAIN_PROOF_EVIDENCE` moves it), the raw records to
`.dev/train-trust-list-proof` (`--out DIR` moves them). The exit status is non-zero when any check failed.

## What one run does

1. The operator creates the trust list once with the kit's payload; a list left by an earlier run is
   removed first.
2. `deployment/train/trust-lists/facis-ztd.local.json`, the repository's file, is planned (nothing
   written) and applied: two `PUT`s, the marker, the UUIDs the file derives, the VC's hash moving;
   applied again: nothing written.
3. The publisher writes the connector's measurement entry into the same list (a synthetic record;
   the measuring step is not this proof's).
4. The file as a pull request would change it: an issuer renamed (one `PATCH`, same UUID, start
   time kept, the connector's entry byte for byte unchanged); an issuer removed (one `DELETE`, its
   lookup key answering nothing, the VC's hash changed, the seconds to the read-back measured
   against the 300 s window); `verify` passing on the current file and reporting drift on the
   previous one; an entry edited by hand found by `verify` and repaired by `apply`; an issuer naming
   the connector's lookup key refused with nothing written.
5. A token whose realm roles lack `enrolltf` (`write-rejected`, 403, nothing changed); a `PATCH`
   without `Authorization` re-observed with curl (200, empty body, nothing stored).
6. `apply --with-zones` on a TSPA with no zone manager: `zones-not-published`, after the issuers were
   reconciled.
7. No secret or token in any record.

## What it does not prove

- The verifier side of the window: no TCR reads this list here. The proof shows the list and the VC
  the TCR fetches no longer carry the issuer; that a verifier refuses it within its 300 s cache is
  the read side's proof, jointly with the handshake verification work.
- The zones' publication: the kit has no zone manager, so the proof shows the refusal, not the PTR.
- The client's TSPA: URL, framework, OIDC client and zone manager are configuration.

`evidence.md` is the last local run.
