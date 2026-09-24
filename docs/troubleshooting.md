# Troubleshooting

Symptoms, causes and checks for the demonstrator.

## Reading a refusal

The demonstrator is built so that a refusal explains itself. Before debugging, read the denial: the
guard returns the layer and the rule that produced the decision, and the matching audit entry
carries the same reason code. A refusal with a reason is working as designed — the question is
whether the reason is the one you expected.

## Workload identity and mesh enrolment

| Symptom | Likely cause | Check |
|---|---|---|
| A pod starts but no traffic reaches it | It never received an SVID, so the mesh has no identity to route to | Look for a SPIRE registration entry matching the pod's service account; a missing entry is the answer, not a mesh problem |
| The SVID exists but the SPIFFE ID is wrong | The registration selector matches more, or less, than intended | Compare the SPIFFE ID in the workload's certificate with the selector that produced it |
| Traffic works between two pods that should not be able to talk | L7 enforcement is owned by neither component on that path, or by both | Check which component owns L7 for that path in the mesh configuration — [ADR-0001](adr/0001-service-mesh-mode-istio-ambient-with-cilium.md) requires exactly one |
| The Istio CNI plugin never chains | Cilium claimed the CNI configuration exclusively | Confirm Cilium is installed with `cni.exclusive=false` |

## Admission control rejections

| Symptom | Likely cause | Check |
|---|---|---|
| An image will not start and the event is generic | Gatekeeper refused it but the reason did not reach the event | Read the provider's decision, which carries the reason code; a refusal with no reason code is a defect in the provider |
| A correctly signed image is refused | The verification key does not match the key the image was signed with | Compare the signing key used by the pipeline with the key material the provider was configured with |
| An unsigned image starts | The constraint is not bound to that namespace, or the provider is not reachable | Confirm the constraint's scope, then confirm the provider answers — an unreachable provider must fail closed, not open |

## Token issuance, DPoP proofs and the token store

| Symptom | Likely cause | Check |
|---|---|---|
| Registration succeeds but no token is issued | The presentation did not verify, so there is nothing to derive a token from | Read the verification outcome first; the token failure is downstream of it |
| A token is rejected on use | The DPoP proof is not bound to the key that requested the token, or is being replayed | Compare the proof's key thumbprint with the one recorded at issuance |
| The upstream call carries the caller's own token | Substitution did not happen | Trace the outbound request — the caller's proof must never be forwarded onward |
| Everything fails after a control-plane blip | The token store failed closed, as designed | Confirm the alert was raised; fail-secure is the correct behaviour, silence is not |

## Attested channel handshake failures

| Symptom | Likely cause | Check |
|---|---|---|
| The handshake aborts | The peer's measurement does not match the expected value | Compare the report's measurement with the expected value resolved from TRAIN; a mismatch is a working refusal |
| The handshake aborts and the expected value is absent | The trust-list entry is missing or stale, not the peer | Resolve the peer's digest through TRAIN directly before suspecting the peer |
| The report verifies but the channel is refused | The evidence is not bound to this connection | Confirm the TLS exporter value is present in the report's user data — an unbound report is a replay risk, so refusal is correct |
| Application traffic appears after a failed handshake | A serious defect | This must be impossible and is asserted by an acceptance scenario; treat any instance as a stop-the-line finding |

## Credential verification and trust-list staleness

| Symptom | Likely cause | Check |
|---|---|---|
| A credential that worked yesterday is refused | It was revoked | Check the status list entry before anything else |
| Verification fails for every credential at once | The status list or the trust anchor is unreachable | Check reachability; an unreachable list must deny, and the alert tells you which one it was |
| A peer that should be trusted is not listed | The trust list has not been republished since the peer was added | Compare the published trust list with what the connector resolved, not with what you expect it to contain |

## Deployment lifecycle and the acceptance scenarios

Met while building and running the lifecycle pack (TDR-BDD-01..06) on kind and IONOS.

| Symptom | Likely cause | Check |
|---|---|---|
| A scenario fails before it starts with "the pool namespace is not in its baseline state" | A previous run was interrupted and left a release or objects behind | `kubectl -n <pool namespace> get all,secrets`; uninstall the leftover release through ORCE (an `uninstall` command), not by hand, then rerun |
| `cluster-state.sh` exits 2, "the cluster could not be observed" | The observer kubeconfig is wrong, expired or points at another cluster; API errors are never retried into a pass | `kubectl --kubeconfig <observer> auth whoami`, then `get namespace kube-system` — the UID must be the target's |
| The lifecycle result says `valuesSchemaRejected` for a release you expect to be valid | Its values fail the chart's `values.schema.json`; that is the refusal TDR-BDD-02 relies on | `helm template <chart> -f <values>` locally shows the schema error |
| ORCE starts with the upstream demo flows instead of the lifecycle flow | An old or upstream image: the upstream image sets `FLOWS=flows.json` | The first-party image fixes `flowFile` to `lifecycle.json`; the ORCE log's `Flows file` record must name `/data/lifecycle.json` |
| ORCE refuses to start: "must be set: ORCE does not start without its credentials" | A key of the `orce-credentials` Secret is missing | Compare the Secret's keys with [the ORCE install](environments/ionos.md#3-orce) |
| The ORCE context read returns 401 | The read token is wrong, or it was sent without `Bearer ` | The read token is the `ORCE_READ_TOKEN` of the Secret; it can read, never write |
| No JSON refusal record for a request in the ORCE log (rows 02 and 06) | An image without the JSON log handler, or the log command reads another pod | Every line of `kubectl -n ztd-orce logs deployment/orce` must be one JSON object ([ORCE logging](flows.md#orce-logging)) |
| ORCE is slow to start on an Apple Silicon machine | The image is `linux/amd64` only and runs emulated | Expected locally; allow a few minutes |
| `helm` commands behave differently from the docs | Another Helm major version | The project pins Helm v4.3.0 for chart QA and inside the ORCE image |

## Logs

Records sent through the ORCE logging API are one JSON object per line
([ORCE logging](flows.md#orce-logging)); output outside that API is not. The Go services'
logging convention is set with the observability stack (ZT-27). Correlate by the request identifier
carried across hops rather than by timestamp.
