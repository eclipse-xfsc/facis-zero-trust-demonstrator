# Token-store failure catalogue

`verify.sh` proves the token store's failure matrix on a throwaway kind cluster: each failure the
store was designed for is induced in turn, the store's answer is recorded next to the reason code
and the behaviour [the token store page](../../docs/token-store.md) documents for it, and recovery
is observed with no statement run against the database. The records are the negative evidence of
the token-storage requirement and feed the acceptance bundles; the script is re-runnable and the
run's output is its artefact.

The store runs as a real deployment runs it: the chart in runtime mode on PostgreSQL and OpenBao
from the pinned images inside the cluster, with the real connector (`services/connector`, built
from the working tree) as the peer zone's issuer, one substitution route registered at that
connector through dynamic client registration, and the fixture outcome signer standing in for the
verifier. The guard is played by the script: it calls `/internal/substitute` and
`/internal/replay-check` as the guard would, with the forwarded-client-certificate header the
sidecar would set, through the API server's pod proxy. There is no mesh and no sidecar: the
deployment prerequisites of the caller check (`SANITIZE_SET`, STRICT mTLS) are the zone's, not
this proof's, and are out of its scope.

## The matrix

Every row is one induced failure. "Expected" is what `docs/token-store.md` says; a row passes only
when the observed answer, reason code, readiness words and audit rows all match it. Recovery is
always the dependency coming back, never a statement against the database; the two rows that need
a state the run cannot reach in time induce it with one `UPDATE` each, marked below, and every
statement the script runs is listed in `statements.txt` so the claim "no manual database surgery
for recovery" can be checked against it.

| # | Induced failure | How it is induced | Expected while induced | Expected after recovery | Records |
|---|---|---|---|---|---|
| 0 | None: the baseline | A first substitution on a cold route acquires the token on demand | 200 with `authorization` and `dpop`; audit `upstream.acquired` | — | `baseline-*` |
| 1 | A caller the routes do not list | A forwarded certificate naming another SPIFFE ID; a request with no certificate | 403 `TOK-CALLER-DENIED` | — | `caller-denied-*` |
| 2 | A target outside the route | A target URI outside the route's `target_prefix`; a method the route does not allow | 403 `TOK-ROUTE-DENIED` | — | `route-denied-*` |
| 3 | A replay storm | 100 concurrent replay checks of one proof, then the same proof once more | exactly one `fresh` (200), the rest 409 `TOK-REPLAY`; a proof outside the window 422 `TOK-PROOF-INVALID` | — | `replay-storm-*` |
| 4 | PostgreSQL unreachable | `postgres` scaled to zero | substitution 503 `TOK-STORE-UNAVAILABLE`; replay check 503 `TOK-STORE-UNAVAILABLE`; `/readyz` 503 with `postgres: unreachable` and `signing_key: unreachable` (the key rows are in the database); `/healthz` 200 | `/readyz` 200; substitution 200; the pod never restarted | `postgres-down-*`, `postgres-back-*` |
| 5 | PostgreSQL crash recovery | `SIGQUIT` to the postmaster in the database pod (PostgreSQL's immediate shutdown: no checkpoint), so the container restarts and the unlogged replay tables come back empty | — | the store stays up and logs once that the replay record may have been lost, naming the window; a proof recorded before the crash is accepted once more inside the window, the documented bounded exposure; the next presentation of it is 409 again | `postgres-crash-*` |
| 6 | OpenBao unreachable | the `openbao` Service's selector pointed at no pod (a partition: the server keeps its state) | `/readyz` 503 with `openbao: unreachable` and `signing_key: unreachable`; substitution 503 `TOK-STORE-UNAVAILABLE`; `/healthz` 200 | `/readyz` 200; substitution 200 with the same key; no restart | `openbao-down-*`, `openbao-back-*` |
| 7 | The issuer down | `connector` scaled to zero, once the live row's renewal is at least 30 s away, so the issuer is gone before the worker claims the row | substitution keeps answering 200 while the token is valid; at `renew_after` the worker's three attempts are audited `upstream.failed` `ACQ-CHALLENGE-FAILED` and the row ends `failed` (`renewal.failed`, same code); substitution is then 409 `TOK-NO-UPSTREAM` and audits one more `ACQ-CHALLENGE-FAILED`. Readiness is recorded, not judged: a passing issuer-separation check is cached for five minutes, so `signing_key` may still read `ok` | substitution 200 with a new `token_id`; audit `upstream.acquired`; the `failed` row left as history | `issuer-down-*`, `issuer-back-*` |
| 8 | Everything expired | **induced**: the live row's `expires_at` and `renew_after` set to the past, with the issuer still down | substitution 409 `TOK-NO-UPSTREAM`, no credential in the body | with the issuer back, substitution 200; the expired row closed by the store itself, `retired` by the activation or `failed` by the worker that claimed it first, never by hand | `expired-*` |
| 9 | A crashed renewer | **induced**: the live row claimed by a worker that does not exist, `claimed_at` six minutes ago | substitution 200 meanwhile (a `renewing` row is still the route's token) | within one cycle the claim is released: row `active`, claim cleared, audit `renewal.released` `REN-CLAIM-STALE` | `stale-claim-*` |

Not in the matrix, and why: the orphan sweep (`ACQ-ORPHAN-DELETED`) needs a value ten minutes old
and a sweep that runs every five, longer than this proof may take, and is covered by the Go tests
of `internal/acquire`; `ACQ-CLAIM-LOST`, `ACQ-KEY-RETIRED` and the activation codes need two
workers or a rotation racing one acquisition, which the Go tests of `internal/renew` and
`internal/acquire` arrange and this script does not. That a caller refusal happens before the body
is read and makes no OpenBao call is asserted by the server's Go tests, not here: this proof sees
the status and the reason code.

## What a run leaves

Every record goes to `--out` (default `.dev/token-store-failures/`, git-ignored):

- `catalogue.txt`: one `PASS` or `FAIL` line per check, in order, and `verdict.txt` with the
  verdict under them.
- `matrix.tsv`: one line per row of the matrix: the row, the request, the status and reason code
  expected, the status and reason code observed.
- the request and response of every call (`*-substitute.json`, `*-replay.json`, `*-readyz.json`),
  except the hundred bodies of the replay storm, which `replay-storm-codes.txt` reduces to their
  status codes,
  the audit rows each row produced (`*-audit.txt`), the `upstream_token` rows before and after
  (`*-rows.txt`), the store's and the connector's records (`store-logs.txt`, `connector-logs.txt`),
  `pod-status.txt` with the store's restart count, `statements.txt` with every statement the
  script ran against the store's database, and `environment.json`.

No credential reaches a record: the canary scan of the key-custody proof is run on every file,
with this run's OpenBao tokens, the store's client secret and the fixture signer's private key
among the needles.

```sh
scripts/verify-token-store-failures/verify.sh                 # about six minutes with the images cached; a first build adds the module download
scripts/verify-token-store-failures/verify.sh --out /tmp/run
KEEP=1 scripts/verify-token-store-failures/verify.sh          # leaves the cluster for inspection
```

It needs `docker`, `helm`, `kind`, `kubectl`, `curl`, `jq`, `openssl` and bash 5, and the pinned
images of `scripts/tools/pins.env`. The workflow `.github/workflows/token-store.yml` runs it as its
own job on every change to the store, uploads the records as an artefact and writes the verdict to
the job summary.
