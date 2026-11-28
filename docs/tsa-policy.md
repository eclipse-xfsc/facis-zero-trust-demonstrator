# TSA policy evaluation

The guard's decisions are taken by Rego policy bundles evaluated in the XFSC TSA policy service. The
guard's IF-05 adapter (the policy evaluator) asks the TSA, the TSA evaluates the bundle that is
active, and every decision names the rule that took it and the bundle revision it was taken under.
Bundles are published as signed OCI artefacts, declared active by pull request, verified against a
pinned trust root before they are loaded, and swapped without restarting anything. A rollback is
the pull request that declares the previous bundle again.

## The component

| | |
|---|---|
| Upstream | [eclipse-xfsc/custom-policy-agent](https://github.com/eclipse-xfsc/custom-policy-agent) ("XFSC Policy Service", the TSA policy service), Apache-2.0 |
| Version | v1.1.4, commit `6c2ed6673ef860e79d027f8b41ebaca932e9d686` (5 November 2026); OPA v0.58.0 inside |
| Image | `node-654e3bca7fbeeed18f81d7c7.ps-xaas.io/tsa/policy:1.1.4@sha256:0275b144e1bb03ded111cdd12e185930fc53d4e8a4f65168feb56a6cc8c25862` (multi-arch index, XFSC's Harbor), pinned in `scripts/tools/pins.env` |
| API used | `POST /policy/{repository}/{group}/{name}/{version}/evaluation` (input in the body, the policy's package object back) and `POST /v1/policy/import` (a signed bundle) |
| Chart | [`deployment/helm/tsa-policy`](https://github.com/eclipse-xfsc/facis-zero-trust-demonstrator/tree/main/deployment/helm/tsa-policy); the upstream chart (`tsa/policy:1.1.4-helm`) assumes MongoDB, the XFSC cache, signer and OCM services, runs as root and pins no digest, so it is not used |

It is the only XFSC component that evaluates Rego for the TSA; `rego-policies` holds example
policies and `trusted-info-hub` exports policy data, neither evaluates.

## How it runs

One pod, `tsa-policy-engine`, one replica (the TSA's in-memory storage is per instance):

| Container | Image | Role |
|---|---|---|
| `nats` (native sidecar) | `nats:2.15.3`, pinned | the TSA's change-event client connects to NATS at start-up; loopback only |
| `git` (native sidecar) | `deployment/docker/tsa-git` (Alpine 3.22, `git-daemon` 2.49.1) | the TSA's in-memory storage clones a Git repository at start-up; this serves it an empty one, on loopback |
| `tsa` | the pinned TSA image | evaluates; listens on `127.0.0.1:8081` only, so import, lock, export and admin are unreachable from outside the pod |
| `bundle` | `deployment/docker/tsa-bundle` (`cmd/tsa-bundle serve`) | verifies and activates bundles, serves the trust root to the TSA, and is the pod's only port: it forwards `POST` of the one evaluation path and nothing else |

The TSA starts with no policy, so until a verified bundle is active every evaluation fails, the
evaluator answers 503 `POL-PDP-UNAVAILABLE` and the guard refuses the request. The pod is ready once
the TSA evaluates a verified revision.

```text
guard ── IF-05 /decision ──▶ policy evaluator ── POST …/evaluation ──▶ tsa-policy-engine:8080 (bundle sidecar)
                             (TSA adapter)                                   │ loopback
                                                                             ▼
                                         registry ◀── fetch + verify ── bundle sidecar ── import ──▶ TSA
```

## The IF-05 adapter

`services/policyevaluator/tsa.go`. With `tsa` in its configuration (guard chart value
`tsa.evaluationURL`), the evaluator keeps its `/decision` interface and caller authentication and
takes the decision from the TSA instead of its built-in rules. It sends the IF-05 input unchanged,
reads the `decision` member of the result and acts on it only if it validates against the IF-05
decision schema itself (a copy embedded in the evaluator, kept identical to
`docs/contracts/if05-policy-decision.v1.schema.json` by a test: member presence, `null`, unique
obligations, lengths and the link's URI format included) and names a rule. Anything else — no answer
within `tsa.timeoutMS` (default 500 ms, refused at 1 s or more since the guard's own bound on the
policy call is 1 s), a TSA error, a result without a decision, a decision outside the schema, no
`rule_id` — is 503 `POL-PDP-UNAVAILABLE`. The adapter logs every decision as
one JSON line: `correlation_id`, `allow`, `rule_id`, `bundle_revision`, `reason_code`; and every
failure with its `correlation_id` and the reason.

## The policy

`policies/tsa/facis/guard/1.0/`: `policy.rego` (package `facis.guard`, the TSA's naming convention
`{group}/{name}/{version}`) and `data.json`, the zone's configuration (`data.config`: audience, host,
Participant callers, scope tenants, withdrawn scopes and, for a tenant's guard, `tenant_members`: each
tenant's member SPIFFE IDs; optionally `grpc_methods`, the gRPC methods the guard serves beside the
REST route, and `presentation`, the scopes that need a credential presentation first and the OID4VP
link the caller is answered with). It is the rule set of the built-in evaluator in Rego:
`m3-report-read` and `m3-report-summary` allow with the substitution obligation,
`m3-tenant-membership` denies a caller that is not a member of the tenant the guard's route names
(`target_tenant`), and any target tenant where no members are configured,
`m3-presentation-required` denies a token carrying a presentation scope with
`POL-PRESENTATION-REQUIRED` and the link, `m3-scope-withdrawn`
denies a scope the zone has withdrawn, `m3-default-deny` denies everything else, a gRPC method
the data does not list included. `policy_test.rego`
holds the membership cases of the built-in evaluator's tests, run in OPA at the TSA's version by the
`TSA policy` workflow (`docker run … "$OPA_IMAGE" test policies/tsa/facis/guard/1.0`); it is not
packed into a bundle.
`decision` is the IF-05 decision; its `bundle_revision` is `data.bundle.revision`, which only the
publisher writes.

## Bundles

A bundle is the TSA's own import format, so the TSA imports it unchanged: a zip of
`policy_bundle.zip` (`metadata.json`, `policy.rego`, `data.json`) and `signature.raw`, an ECDSA P-256
signature over the SHA-256 of `policy_bundle.zip`. It is pushed as an OCI artefact with one layer of
type `application/vnd.facis.tsa.bundle.v1+zip`, and the artefact is signed with cosign. Both
signatures use the repository's signing profile and key ([CI/CD](ci-cd.md#image-signing)): cosign,
key-based, no transparency log, today the interim key `docs/contracts/keys/interim-cosign.pub`.

### Publishing

```sh
COSIGN_KEY=env://COSIGN_INTERIM_KEY COSIGN_PASSWORD=... \
  scripts/supplychain/publish-tsa-bundle.sh policies/tsa/facis/guard/1.0 <revision> \
  ghcr.io/eclipse-xfsc/facis-zero-trust-demonstrator/tsa-policy-bundles docs/contracts/keys/interim-cosign.pub [zone-data.json]
```

It packs the directory (with the zone's `data.json` when given) and writes the revision into the
data, signs it with `cosign sign-blob`, checks that signature against the public key, pushes the
artefact under the tag `<revision>`, signs the artefact by digest, and prints the digest reference.
Use a revision that names the source, such as `git-<commit>`; it appears in every decision. A
revision names one bundle for good: the script refuses to publish under a revision whose tag already
exists in the repository (the CI job uses `git-<commit>`, suffixed with the zone data file's name).

### Activating, governed by Git

The active bundle is a value of the zone's `tsa-policy` release:

```yaml
bundle:
  ref: ghcr.io/eclipse-xfsc/facis-zero-trust-demonstrator/tsa-policy-bundles@sha256:…
  revision: git-1a2b3c4d5e6f
```

A policy change is therefore two reviewed changes: the pull request that changes `policies/tsa/`,
and, once the bundle is published, the pull request that declares its reference for the zone.
Syncing the values (the zone's install, or GitOps) changes only the `tsa-policy-bundle` ConfigMap;
the chart puts no checksum of it on the pod, and the chart gate fails if declaring another bundle
would change anything in the pod template. The kubelet refreshes the mounted declaration (within
about a minute), and the sidecar, polling every `bundle.pollSeconds`:

1. does nothing if the declared reference and revision are the active pair;
2. refuses a revision the ledger records under another reference (a revision names one bundle for
   good), and a declaration that failed after import in the last 5 minutes;
3. fetches the declared reference — only a digest reference under `bundle.repository` — and
   verifies its cosign signature by the trust root (the admission verifier's code,
   `internal/cosignverify`), then reads the manifest and its single bundle layer by digest;
4. verifies the bundle (`internal/tsabundle`): exactly the two entries the TSA imports, the bundle
   signature by the trust root, `metadata.json` first and naming the pod-local trust-root URL, the
   configured policy and the declared revision as its version, nothing beside `policy.rego` and
   `data.json` (no `data-config.json`, which would make the TSA fetch data from wherever it names),
   and `data.bundle.revision` equal to the declared revision;
5. only then imports it into the TSA, which checks the bundle signature again with the key it
   fetches from the sidecar (`http://127.0.0.1:8080/trust-root.json`, the trust root as a JWK set);
6. evaluates an empty input under the new revision's key; if the answer names the declared
   revision, it switches the key it forwards evaluations to — the activation, one atomic step — and
   logs `bundle activated` with the reference, the revision and the previous revision.

Each revision is stored in the TSA under its own key, `/policy/policies/facis/guard/<revision>`,
beside the active one; the adapters keep calling the configured path (`…/guard/1.0/evaluation`) and
the sidecar forwards it to the active revision's key. Replacing a policy in place is avoided on
purpose: the TSA (v1.1.4) drops its policy cache through a change notification that is lost when the
import request ends first, so a replaced policy can keep answering indefinitely. The proof on kind
showed it: with in-place replacement a refused candidate kept answering after the previous bundle
had been imported again. With one key per revision a new key has no cache entry, and nothing that
was not switched to is ever forwarded to.

Independently of the declaration — also while it cannot be read, or a fetch is slow — the sidecar
checks every poll that the active revision still answers under its key; after three unanswered
probes in a row (the TSA restarted empty) it imports the active bundle again from its state
directory. Readiness is that check's result.

The sidecar's ledger (`/var/lib/tsa-bundle`, an emptyDir that survives a restart of the sidecar
container) records every revision ever imported with its reference, the declarations that failed
and when, and the bundles of the revisions it keeps. A sidecar that starts without a ledger records
every key the TSA already holds as taken. The TSA has no delete: beyond the active, the previous and
the two most recent other revisions, older keys are locked in the TSA (no longer evaluable) and stay
in the ledger, so their revisions remain taken; a TSA restart frees them, after which only the
active revision is imported again.

The gate passes an answer on only if its decision names the active revision: a policy that answers
the probe correctly but real input under another revision is refused with 503, never forwarded.

Any failure is logged as `bundle refused` with the reason and the revision still active, and the
active revision keeps serving throughout: a bundle refused before import never reaches the TSA, one
refused after import (a correctly signed bundle whose Rego does not answer with its own revision)
stays under its own key and is never forwarded to. Each decision is taken entirely under one
revision, and says which.

### Rolling back

Declare the previous reference and revision again (revert the declaring pull request) and sync. The
previous bundle is verified like any other, imported under its key again and switched to, without a
restart. Bundles are never
deleted from the registry, so every revision ever declared can be restored and audited. Which
revision was active when is in Git (what was declared) and in the sidecar's and evaluator's logs
(what was activated and used).

If the TSA container restarts it comes back empty; the health check notices it within three polls
and imports the active bundle again, and decisions fail closed in between.

### Trust root

`trustRoot` in the chart values, by default the interim key (the chart gate checks the default is
`docs/contracts/keys/interim-cosign.pub`). One key: the TSA verifies with the first key it is served.
Rotation is a new trust root and re-signed bundles; replacing the interim key with the client's key
follows the rest of the signing chain.

The TSA's own import check is not a trust root: it fetches the key from the URL inside the bundle,
from any host. That is why nothing but the sidecar can reach the import endpoint, and why the sidecar
accepts only bundles that name its own loopback URL.

## Proof

`scripts/verify-tsa-policy/verify.sh` runs it on a throwaway kind cluster — the TSA pod from this
chart with the pinned TSA and NATS images, the guard chart's evaluator in TSA mode, a local registry,
bundles published with `publish-tsa-bundle.sh` and an ephemeral key:

1. under v1 an entitled summary request is allowed (`m3-report-summary`, v1);
2. v2, which withdraws the summary scope, is declared: the same request is denied
   (`m3-scope-withdrawn`, v2) and no pod was replaced or restarted;
3. an unsigned bundle, one signed by another key, v2 with its policy altered after signing (with a
   valid artefact signature) and a correctly signed v4 whose Rego answers with revision v2 are each
   refused, and v2 keeps serving;
4. v1 is declared again: allowed under v1, still without a restart;
5. every decision the evaluator answered is in its log with the same `rule_id` and
   `bundle_revision`.

Requests are sent to the evaluator as the guard sends them, with the guard's identity in the
`X-Forwarded-Client-Cert` header its mesh sidecar would set. No mesh, token store or connector is
installed, so the guard's own token path, mTLS and the TSA pod's AuthorizationPolicy are not part of
this proof. `go test ./internal/tsabundle ./services/policyevaluator` covers the refusals one by one
and the adapter's fail-closed answers, including a TSA slower than the bound.

The records of the last run are in [`evidences/tsa-policy/`](evidences/tsa-policy/README.md).

```sh
BIN=<dir with a linux cosign and istio-crds/> scripts/verify-tsa-policy/verify.sh   # writes .dev/tsa-policy-evidence/
```

## Not here yet

- The TSA, NATS and git images must be mirrored (TSA and NATS, unchanged digests) or built (git,
  bundle) and signed by the release pipeline before an admission-labelled namespace admits them; the
  upstream TSA image is built with Go 1.24.2 on Alpine 3.19 and its scan result is not yet known.
- A zone's `data.json` and the first bundle are published and declared in the live rollout.
- One replica: two would each hold their own active revision.
