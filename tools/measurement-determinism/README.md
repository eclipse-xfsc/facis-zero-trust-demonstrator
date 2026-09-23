# Measurement determinism

The reference measurement published for a component has to be a property of the
release, not of the machine that built it: ZT-35 has a peer compare its own
measurement against the published one, and a value that moves with the builder
makes that comparison meaningless.

It does move, unless something stops it. The container measurement is
`sha256(normalised OCI configuration ‖ rootfs hash)`, and the rootfs half is a
hash over a tar stream whose headers carry each file's owner and permission bits
as found on disk. The attestation component normalises that stream only in time —
`ModTime`, `AccessTime` and `ChangeTime` are zeroed, `Uid`, `Gid` and `Mode` are
not, and a file's `security.capability` xattr is folded in as a PAX record
(`measure/rootfs.go`). Git records none of them: it stores content, paths and a
single executable bit, so ownership follows whoever ran the checkout, the
remaining mode bits follow their `umask`, and a file capability set by a build
step is invisible to version control altogether.

Reading a tar stream is also what bounds the problem. Only what a tar header
carries can reach the hash — owner, permission bits, paths, content, that one
xattr — so the operating system around the measurement is invisible to it. That
is why the check varies ownership and permissions rather than Linux
distributions: two hosted runner images check out under the same user with the
same `umask` and agree for reasons that have nothing to do with normalisation.

Measured here, one fixture under three checkouts, with the component's own code
at the pinned revision:

| checkout | template hash, raw | template hash, normalised |
| --- | --- | --- |
| owner `1000`, modes `664`/`775` | `f465397204778180…` | `d4f8da94c5f2374a…` |
| owner `4242`, modes `600`/`700` | `ae5cfbf6939430ff…` | `d4f8da94c5f2374a…` |
| owner `0`, modes `777` | `145a493e6e4688d6…` | `d4f8da94c5f2374a…` |

Same commit, same bytes, three answers — and one answer once the tree is
normalised.

## What is here

| File | What it is |
| --- | --- |
| `bundle/` | The fixture: an OCI bundle, `config.json` plus `rootfs/`, measured and never run |
| `normalise.sh` | Flattens ownership to `0:0`, takes the permission bits from the Git index so the mode reaching the hash is the mode the commit records, and strips the `security.capability` xattr |
| `measure.go` | Prints the three hashes and nothing else — no nonce, no signature, no driver |
| `measure-with-cmc.sh` | Fetches the attestation component at the pinned revision, builds `measure.go` inside it, runs it |
| `proof.sh` | Measures the fixture raw and normalised, printing both as `key=value` |
| `compare.sh` | Decides whether three runs agree, and whether they agree for the right reason |

`measure.go` carries a `//go:build ignore` tag. It imports the attestation
component, which is deliberately not a dependency of this repository's Go module:
the check fetches it at the pinned revision instead, so `go.mod` and the licence
gate are untouched by a tool that only ever runs in CI. The tag keeps
`go build ./...` and the linter from trying to compile it here.

## Running it

`.github/workflows/measurement-determinism.yml` runs the whole thing three times:
on a hosted runner, in a Debian container where the checkout belongs to root
instead of the runner user, and on a hosted runner whose checkout is given another
owner, other permission bits and a file capability. Locally:

```sh
tools/measurement-determinism/proof.sh
```

Setting an owner needs privilege, so `normalise.sh` wants root or passwordless
`sudo`, and it needs `setfattr` from the `attr` package for the xattr. It refuses
in either case rather than report a half-normalised tree as reproducible. Without
them, only the raw measurement is available locally.

## What the check asserts

Two things, because either alone would be hollow:

1. **The normalised measurement is identical on all three checkouts.** This is the
   property ZT-35 needs.
2. **The perturbed checkout's raw measurement differs from the others'.** Without
   it the job would also pass on a workflow that normalised nothing and ran three
   identical machines.

Whether the hosted runner and the container agree *before* normalisation is
reported but not required. That is the other question — whether the measuring
environment matters — and enforcing an answer either way would be asserting
something the check does not establish.

## What it does not cover

The fixture is measured, never built and never run. Once the components are real,
the same normalisation has to reach the image build as well: `COPY` carries the
mode it finds in the build context, so an unnormalised checkout puts the machine
back into the measurement by another route.

The fixture is also a handful of small regular files. It exercises ownership,
permissions and one xattr; it does not exercise symlinks, hard links, sockets or
device nodes, each of which the measurement treats specially.

See [ADR-0011](../../docs/adr/0011-mock-tee-evidence-format-and-provisioning.md),
decision 4.1 and the open items.
