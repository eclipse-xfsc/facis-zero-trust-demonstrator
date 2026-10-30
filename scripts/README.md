# Scripts

Bash automation — environment bootstrap, evidence collection, reset hooks.

Bash is the language for scripts under `scripts/` per the Technical Development Requirements.

## Attested channel proofs (`atls-probe/`)

Three scripts prove the behaviour of the attested channel (`internal/atls`) between separate
processes and against real `cmcd` attesters. They run everything as plain processes on one machine
— no container, no cluster: two `cmcd` (one per zone, built from the CMC version `go.mod` pins) and
the probe `cmd/atls-probe`.

| Script | Proves | Passes only when |
|---|---|---|
| `atls-probe/prove-mutual-handshake.sh` | Two processes complete a mutually attested handshake and derive the same channel binding | both records show an established channel with verdict `success`, each end saw the expected peer, and both hold the same 32-byte binding |
| `atls-probe/prove-tampered-binding.sh` | A report bound to another TLS session is refused | a relay between client and server forwarded the attestation exchange, both ends refused with `ErrBindingMismatch`, and no application data crossed |
| `atls-probe/prove-session-loss.sh` | Session loss is recorded: server killed, client killed, `cmcd` killed with a channel open and during a handshake, server frozen (half-open) | every scenario ran from an established channel and left its findings, with one reconnect attempt each |

```sh
scripts/atls-probe/prove-mutual-handshake.sh                   # writes docs/evidences/cmc-atls-channel-binding/mutual-handshake/
scripts/atls-probe/prove-tampered-binding.sh
scripts/atls-probe/prove-session-loss.sh                   # about one minute
scripts/atls-probe/prove-mutual-handshake.sh --out /tmp/run    # writes /tmp/run/mutual-handshake/ instead
scripts/atls-probe/prove-mutual-handshake.sh --verify DIR      # runs nothing: checks the records already in DIR
scripts/atls-probe/summary.sh [DIR]              # the verdicts under DIR as a Markdown table
```

They need `go`, `git`, `jq` and bash 5. Each run:

1. builds `cmcd` and the probe into a temporary directory;
2. generates fresh fixtures there, valid for one hour — a CA, a certificate and key, signed
   metadata and a `cmcd` configuration per zone — with the env-gated test
   `TestWriteFixtures` of `internal/atls/atlstest` (`ATLS_FIXTURE_DIR`);
3. starts one `cmcd` per zone on a free port and checks that each produces reports with metadata
   that both verify (`TestCmcdReports`, `ATLS_FIXTURE_CMCD_CHECK`);
4. runs the probe processes and checks the proof on their JSON records;
5. writes the records, the logs, `environment.json` (commit, Go and CMC versions, date, host kind)
   and `verdict.txt` to the evidence folder, and removes the temporary directory with its keys.

The scripts stop every process they started, also when interrupted. In the copied logs the
temporary directory appears as `<work>` and the host name as `<host>`; private keys never leave the
temporary directory.

| Variable | Effect |
|---|---|
| `ATLS_HOST_KIND` | what `environment.json` records the run as: `local` (default), `ci` (default on GitHub Actions) or `target-cluster` |
| `ATLS_CMCD_BIN` | use this `cmcd` binary instead of building one |
| `ATLS_SESSION_LOSS_LIMIT` | seconds a surviving end is given to observe an error in `prove-session-loss.sh` (default 15) |
| `ATLS_KEEP_WORK` | keep the temporary directory, keys included, for inspection |

The evidence in the repository is produced by running the scripts locally and committing the
result. The workflow `.github/workflows/atls-channel-binding.yml` re-runs them with `--out` outside
the checkout to verify that the proofs reproduce; it never writes the committed evidence.

`lib.sh` holds what the three scripts share and is not run on its own.
