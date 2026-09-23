# BDD acceptance specifications

Every acceptance requirement is expressed as an executable scenario, tagged with the requirement it
covers, so that traceability from requirement to test is generated rather than maintained by hand.

## Conventions

- Feature text quotes the acceptance wording verbatim, so a scenario can be matched to its
  requirement at a glance.
- Each scenario carries a tag naming its requirement.
- Scenarios run both in CI and against live clusters.
- Negative cases assert against the audit entry that recorded the refusal, not merely against a
  failed response.

## The harness

Two runners, one report. Go scenarios run under [godog](https://github.com/cucumber/godog) and
JavaScript scenarios under [Cucumber.js](https://github.com/cucumber/cucumber-js); both emit the
same legacy cucumber-JSON, so their results merge by concatenation and produce a single
traceability sheet.

| | Runner | Scenarios | Steps | Report |
|---|---|---|---|---|
| Go | godog | `features/go/` | `internal/bdd/` | `bundles/bdd/go-report.json` |
| JavaScript | Cucumber.js | `features/js/` | `features/js/steps/` | `bundles/bdd/js-report.json` |

**Each runner owns its own directory, and a scenario belongs to exactly one.** A runner that
loads the other's scenarios cannot execute their steps; it would report them as undefined and —
unless the suite is strict — still pass, marking those Annex rows covered by scenarios that never
ran. Both runners therefore run strict: an undefined or pending step fails the suite.

```bash
GODOG_CUCUMBER_OUT=bundles/bdd/go-report.json go test ./internal/bdd   # Go scenarios
npm ci && npm run bdd                                                  # JavaScript scenarios
go run ./cmd/bddreport --rows features/annex-rows.txt --out bundles/bdd \
  bundles/bdd/go-report.json bundles/bdd/js-report.json                # merge + sheet
```

Cucumber.js describes its `json` formatter as being in maintenance mode; it is the interchange
format both runners share today, and the documented upgrade path when that changes is the
`message` format. Nothing else in the harness depends on the choice.

### Tags

A scenario carries two tags: the **requirement row** it covers and the **test identifier** from
Annex A.

```gherkin
@ZT-56 @BDD-ZT-056
Scenario: Every workflow is pinned to a commit and scoped to what it needs
```

Only the row tag drives coverage. A tag shaped like a row id that matches no row in
`features/annex-rows.txt` **fails the run** — a typo would otherwise leave the scenario passing
while proving nothing about the row it was meant to cover.

### Running one Annex row

```bash
go test ./internal/bdd -godog.tags=@ZT-56    # Go
npm run bdd:row -- @ZT-17                    # JavaScript
```

### The traceability sheet

`features/annex-rows.txt` holds the 94 Annex A row ids in Annex order and is the denominator: the
sheet reports every row, covered or not, so a gap is visible rather than absent. `cmd/bddreport`
generates `traceability.md` and `traceability.csv` from the tags in the merged report — the sheet
is never edited by hand.

Covered is not proven. Each row also carries a **result** taken from the step and hook results of
every execution that covers it: `passed` only when every execution passed, on every target and for
every Outline example; `failed` when any one failed; `not run` when any was skipped or had no steps.

The pipeline runs all of this on every pull request, writes the sheet into the job summary, and
publishes `bundles/bdd` as the `bdd-evidence` artefact, which is the per-gate evidence bundle.

## Scenario inventory

The scenarios are grouped by the part of the architecture they exercise. Each family carries the
requirements it proves and the negative case it must include — a family with no negative case is
incomplete, because the demonstrator's claim is about what it refuses.

| Family | Requirements | Positive case | Negative case it must include |
|---|---|---|---|
| Workload identity | ZT-24, ZT-57, ZT-59, ZT-60 | A workload attests and receives an SVID whose SPIFFE ID matches its service account | Failed attestation yields no identity **and** no mesh connectivity |
| Mesh enrolment and segmentation | ZT-01, ZT-23, ZT-25, ZT-26, ZT-58, ZT-61, ZT-62 | All service traffic is routed through the mesh; only configured identities may talk | An unaffiliated workload is refused, and the refusal is not IP-based |
| Management/data plane separation | ZT-49, ZT-53, ZT-55 | The management plane is unreachable from the data plane | A data-plane workload attempting a management-plane call is denied at the network layer |
| Admission control | ZT-02, ZT-11, ZT-36, ZT-37, ZT-72 | A correctly signed image is admitted | An unsigned or wrongly signed image is refused, with the reason code in the admission log |
| Supply chain | ZT-10, ZT-13, ZT-38, ZT-54, ZT-71 | Images build on the runner, are signed by digest, and ship an SBOM and a mock attestation | A non-Linux image, or one missing its signature, fails the pipeline |
| Attested channel | ZT-04, ZT-28…ZT-33, ZT-63…ZT-69 | Both ends attest, the verdict is machine-readable, and application traffic follows | A tampered measurement aborts the handshake — and it is **proven** no application traffic passed (ZT-70) |
| Expected measurements and trust lists | ZT-03, ZT-18, ZT-35, ZT-64 | Peer digests resolve through TRAIN and match | A stale or absent trust-list entry refuses the peer |
| Authorization surface | ZT-20, ZT-21, ZT-22, ZT-39, ZT-73, ZT-76 | Dynamic registration, a token derived from a verified presentation, DPoP-bound and substituted upstream | A replayed or unbound DPoP proof is rejected; a wrong scope is denied with an OID4VP link |
| Credential lifecycle | ZT-40, ZT-51 | A credential is issued to the wallet and unlocks the protected resource | A revoked credential flips verification negative and the token store fails closed |
| Policy decision | ZT-06, ZT-20, ZT-41, ZT-75 | The guard permits on a matching policy and returns the resource | No matching policy denies, with the rule and reason recorded |
| Fail-secure behaviour | ZT-47, ZT-52 | Each request is authorised on its own merits | Control-plane unavailability denies rather than admits, and raises an alert |
| Visualization and journey | ZT-05, ZT-08, ZT-09, ZT-43, ZT-44, ZT-78, ZT-81 | The ORCE journey runs end to end and each step is visible | Every refusal above is visible in the UI, not only in a log |
| Documentation and reproduction | ZT-16, ZT-17 | Each cluster is reproduced from the [environment guides](environments/index.md) alone | A step that cannot be reproduced from the documentation fails the check |

## The deployment-lifecycle pack

`features/js/lifecycle.feature` covers TDR-BDD-01..04: deploy, invalid parameters (three
examples), idempotent redeploy and uninstall. Each scenario sends a command to the ORCE lifecycle
workflow ([IF-08](api-docs.md)), reads the final result back from the ORCE context, and decides the
outcome from the cluster with `scripts/bdd/cluster-state.sh` under a read-only identity.

The scenarios are tagged `@cluster`: they need a cluster with ORCE and are never part of a
pull-request run, where the traceability sheet shows their rows as gaps.

### How the cluster decides

Each row has its own namespace from the BDD pool (`ztd-bdd-tdr-001`..`004`), provisioned with ORCE
by the `deployment/helm/bdd-pool` chart. Before a scenario the namespace must hold only its
documented baseline; afterwards it is restored through the same workflow. Every object in it is
classified:

| Class | What | Rule |
|---|---|---|
| Baseline | the pool's own ServiceAccount, root-CA ConfigMap, Roles and RoleBindings | same set, same UIDs, throughout |
| Helm metadata | the release's `helm.sh/release.v1` Secrets | one per history revision, exactly one deployed |
| Expected | every top-level object the release rendered | all present, ready, same UIDs across a redeploy |
| Descendants | ReplicaSets and Pods of an expected Deployment; EndpointSlices and the legacy Endpoints of an expected Service | allow-list only; one active ReplicaSet, the desired Pods, endpoints that match the ready Pods and the resolved ports |
| Events | Event objects | ignored |
| Unexplained | anything else | must be empty — an orphan or duplicate fails the row |

Readiness means the rollout is complete, not that some pods are up. Every check is polled until it
holds or a deadline passes (120 s by default), so asynchronous controllers are waited for; an API
or authorization error fails at once and is never retried into a pass. ORCE and the observer must
report the same `kube-system` UID, so a result can never come from another cluster.

### Running it

Client targets run it **only through CI** (`bdd-cluster` job, one run at a time per target; see
[CI/CD](ci-cd.md)). Against a developer's local cluster — never evidence:

```bash
scripts/dev/kind-up.sh      # kind (Kubernetes 1.35) + BDD pool + identity kubeconfigs in .dev/kind/
scripts/dev/orce-up.sh      # the ORCE image on kind's network, deploying as the pool's deployer;
                            # writes the runner inputs below to .dev/kind/orce.env
set -a && . .dev/kind/orce.env && set +a
npm run bdd:cluster         # about 40 s; evidence in bundles/bdd/evidence/
scripts/dev/orce-down.sh && scripts/dev/kind-down.sh
```

The ORCE image is amd64 only; on an arm64 machine Docker runs it emulated.

| Input | Meaning |
|---|---|
| `KUBECONFIG` | the read-only observer identity |
| `BDD_ORCE_URL` | ORCE base URL |
| `BDD_ORCE_ADMIN_TOKEN` | read-only ORCE admin API bearer token |
| `BDD_ORCE_HTTP_USER`, `BDD_ORCE_HTTP_PASS` | credentials of the ORCE HTTP endpoints |
| `BDD_ORCE_LOGS_CMD` | a command printing the ORCE log (row 02 asserts the structured refusal entry) |
| `BDD_RELEASE_CHART` | the release under test, a chart path in the ORCE image; default the lifecycle fixture |
| `BDD_RELEASE_VALUES` | its valid baseline values; default the fixture's `ci/values.yaml` |
| `BDD_TARGET`, `BDD_RUN_ID` | names the target and the run in the evidence |

A missing input stops the run and is named.

### The release under test

Until the umbrella chart is ready, the pack deploys `features/fixtures/charts/lifecycle-fixture`, a
namespaced chart with no CRDs, and every evidence directory records that it is fixture evidence. A
fixture pass is **not** acceptance of the umbrella release. Before the umbrella chart may replace
the fixture, its cluster-scoped deploy rights and the ownership and removal of the CRDs it ships
(which `helm uninstall` leaves behind) must be designed; it then needs its own run.

### Evidence

Per row, target and example: `bundles/bdd/evidence/bdd-tdr-00n/<target>/<example>/` holds the
commands and acknowledgements, the ORCE context entry of each command (with the masked Helm output,
release revision, chart digest and values hash), every classified inventory, the recorded baseline,
and for row 02 the refusal log entry.

## Traceability

Each scenario's tag is its requirement id, so the requirement-to-test matrix is generated from the
feature files rather than maintained beside them. A requirement with no tagged scenario shows up as
a gap in that matrix; that is the point of generating it.

## Evidence

Each gate produces one indexed evidence bundle, assembled by a single command, with a directory per
requirement row. Bundles are versioned and immutable once a gate has consumed them.
