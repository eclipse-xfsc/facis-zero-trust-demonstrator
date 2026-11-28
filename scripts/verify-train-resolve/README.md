# TRAIN resolution against the real TSPA and name server

Evidence that the gateway's resolver (`internal/trainresolve`, driven by `cmd/train-resolve-probe`)
accepts a peer only when TRAIN vouches for its measurement, refuses with the registered reason code
otherwise, and sees a removal within the documented window, against real content: the TSPA built
from upstream's source, the zone manager serving the framework's DNS zone, the reconciler's zone
claims as PTR records, the publisher's entry in the real list. The resolver itself is the stand-in
`scripts/train-resolve/fake_tcr.py` over that DNS and that list, since no Trust Content Resolver
runs in this repository ([what it copies and leaves out](../train-resolve/README.md)).

```bash
TSPA_REPO=<clone of eclipse-xfsc/train-trust-framework-manager, with train-shared in shared/> \
  scripts/verify-train-resolve/verify.sh [--out DIR]
```

Needs kind, kubectl, helm, docker, curl, jq, python3, sha256sum, dig and go. The first run builds
the TSPA image (about 15 minutes); `TSPA_SKIP_BUILD=1` reuses it. The run itself takes about ten
minutes, five of them the removal case waiting on the real 300 s window. `TRAIN_RESOLVE_WINDOW`
shortens that window to rehearse the script; the committed evidence is a run with the real one.

The evidence goes to `evidence.md` next to the script (`TRAIN_PROOF_EVIDENCE` moves it); the raw
records to `.dev/train-resolve-proof` (`--out` moves them): per case the probe's record lines,
stdout and stderr, the publisher's and reconciler's outputs, the stand-ins' request logs, the
kind-up log.

## What one run does

1. Builds the probe from the checkout; brings up the TSPA, Keycloak and the zone manager on kind
   with the kit (`scripts/verify-tspa-api/kind-up.sh`, `TSPA_ZONE_MANAGER=1`); port-forwards to the
   TSPA, Keycloak and the name server (DNS over TCP, as a port-forward carries TCP only).
2. Creates the list, applies the repository's trust-list file with `--with-zones` (the zones' PTR
   records), publishes the gateway's entry with the publisher under the lookup key the gateway
   presents: its identity, `spiffe://zone-b.facis-ztd.local/gateway`.
3. Starts the resolver stand-in over the real name server and list, and shows directly that it walks
   the PTR to the framework's DID and returns the gateway's entry.
4. The cases, each a probe run with its record kept: accepted; served from the cache; mismatch; a
   peer nobody published; an issuer's entry (found, no measurement, never accepted); a zone without
   a claim; a rolling update (two values accepted, pruned, the old one refused); the removal within
   the window (a probe verifying every 5 s with the 300 s TTL, the entry deleted by the operator, the
   refusal timed against the first acceptance and the deletion); zero values; a resolver that could
   not verify the credential; a resolver answering 502; a resolver down; a resolver whose TSPA is
   down; no secret in any record.

## What it does not prove

- The real Trust Content Resolver: DID resolution, the credential's signature, DNSSEC. The client's
  instance needs the items listed in `scripts/train-resolve/README.md`.
- The handshake: the peer's identity and measurement are handed to the probe, not extracted from a
  `cmcd`'s verification result. Plugging the verifier behind the attested channel's `PeerVerifier`
  is the gateway's work.
- The measurement: the record is synthetic; the publication proof covers measured records.

## `evidence.md` is the last local run

Committed after a run with the real window; the workflow `train-publish.yml` (job `resolve`) runs
the same script with the TSPA image cached and uploads its evidence as an artefact.
