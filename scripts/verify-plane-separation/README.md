# verify-plane-separation

Executes the plane-separation allow matrix of [`docs/architecture.md` §6](../../docs/architecture.md)
against a zone that is already installed, in both directions between the planes, and attributes every
refusal to the layer that made it. It is the reachability test that ZT-55 asks for ("Management plane components not reachable from data plane
(verified in network test)"), and the Annex scenario `@ZT-55 @BDD-ZT-055` runs it in the cluster mode of
the BDD harness (`internal/bdd/plane_separation_cluster_test.go`).

The script installs, upgrades and uninstalls nothing. It runs against:

- the local kind cluster, after `scripts/dev/kind-cilium-up.sh` and `scripts/install-zone/install.sh`;
- a participant cluster, after `scripts/verify-mesh-identity/verify.sh` with the keep opt-in
  (`ZTD_KEEP_ZONE`), which leaves the zone installed.

## What a run shows

**The rows.** The verifier renders the umbrella with the zone file under test (`helm template`). It
reads the `allowMatrix` rows (selectors, service accounts, ports) and the NetworkPolicy pair each row
renders. It also reads §6's allow matrix with the same heading-based reader as
`scripts/check-plane-separation.sh` (`scripts/lib/doc-table.sh`). The run fails, naming the row, when:

- a row is in one source and not the other;
- the two sources disagree on a verdict;
- a row has no probe (no fixture);
- a DENY row of §6 is one the verifier does not know;
- §6's [management plane → data plane](../../docs/architecture.md#management-plane-data-plane) table
  does not hold the row `management-to-data` as DENY, or holds a row the verifier does not probe;
- the rendered umbrella, or the policies the cluster holds (every release's NetworkPolicies,
  CiliumNetworkPolicies, CiliumClusterwideNetworkPolicies and AuthorizationPolicies; a clusterwide policy
  is read by the namespace terms of its endpoint selectors, so a selector without one covers every
  namespace), hold a rule that admits a connection from a
  management-plane namespace to a data-plane namespace (`plan_reverse_rule`, `plan.sh`). §6 disposes
  that direction as DENY by the default deny alone, so such a rule is an opening it does not dispose.

**Where it probes from.** Every namespace labelled `ztd.facis.io/plane=data`, found by the label, never
from a list. In a data-plane namespace other than a row's own, the row's legitimate caller must be
dropped, because the lane admits its own namespace only. The management plane → data plane direction
is probed from every namespace labelled `ztd.facis.io/plane=management`, `spire-system` and
`istio-system` included. A namespace without injection gets the proxy-less probes only.

**What each row kind is probed with:**

| Row kind | Probe | Passes when | Layer recorded |
|---|---|---|---|
| ALLOW | the legitimate caller (the row's labels and service account), on every port the row admits | `200`, and the caller's proxy counts the request to the destination principal | control channel |
| ALLOW | the impostor (the row's labels, another service account) | `403 RBAC: access denied` and one denial line with both SPIFFE IDs | mesh |
| ALLOW | the unlabelled caller (the row's service account, not its labels) | dropped, and no denial line names it | network |
| ALLOW, export row | the caller, on a collector port other than 4317 and 4318 | dropped, and no denial line names it | network |
| DENY and catch-all | a TCP connection from a proxy-less pod to every port of every endpoint | dropped, and no new denial line in a meshed destination's proxy | network |
| DENY and catch-all, meshed destination | a meshed prober behind a probe-scoped opening, on every port a Service exposes | not served, and the destination's proxy logs a denial line with both SPIFFE IDs | mesh |
| DENY and catch-all, meshed destination, a port no Service exposes | a plain-text request without an identity from a proxy-less probe, to the pod's address behind a probe-scoped opening | reset (`denied(56)` or `denied(52)`) under mutual TLS `STRICT` in force for the port, and, with Hubble, the request seen forwarded to the destination | mesh |
| DENY and catch-all, no proxy | none | recorded `n/a`: "the destination has no proxy" (the SPIRE and Istio control planes, declared in `docs/specifications.md`) | mesh: n/a |
| istiod port 15012 (xDS) | TCP | recorded **open, declared opening (proposed)**: cited, never counted as a denial or as a green channel | declared |
| istiod, any other port | TCP | dropped; a port that answers fails the run, named | network |
| `management-to-data` | a TCP connection from a proxy-less pod of each management-plane namespace to every port of every endpoint of every Service of a data-plane namespace | dropped, and no new denial line in a meshed destination's proxy | network |
| `management-to-data`, meshed destination, from a namespace with injection | the meshed prober behind a probe-scoped opening, on every port a Service exposes (a pod port no Service exposes: in plain text, as above) | not served, and one of the Service's pods logs a denial line with both SPIFFE IDs | mesh |
| `management-to-data`, meshed destination, from a namespace without injection | a plain-text request without an identity to every pod port, behind a probe-scoped opening | reset under mutual TLS `STRICT`, as above | mesh |
| `management-to-data`, no proxy | none | **fails** the run: a data-plane workload without a proxy has no mesh layer, which ZT-55 requires, and the admission policy's capture rule should have kept it out of an injected plane namespace | mesh |

A data-plane namespace that runs no meshed Service gets the stand-in destination
`fixtures/data-target.yaml`, so that both layers are probed in it.

The export row admits every identity of its namespace, so it has no impostor and no unlabelled caller.
The record says so on its own line (`n/a`).

**The catch-all destinations are found, not listed.** They are every Service with ready endpoints in a
namespace labelled `ztd.facis.io/plane=management`, in `spire-system` or in `istio-system`, minus the
destinations of the `allowMatrix` rows. The SPIRE server's pods and TSPA's are filed under their own
rows. The record lists what was found. It also names the management components §6 gives as examples
(estserver, OpenBao, ArgoCD, Harbor) that the zone does not run.

**The probe-scoped opening (mesh layer of a denied destination).** The network layer drops the
connection first, so the mesh never sees it. To show the mesh refusing on its own, the verifier applies
`fixtures/opening.yaml`: one NetworkPolicy pair that admits one meshed prober of this run (selected by
its pod name and the run-unique label), or one proxy-less probe for a plain-text request, to that
destination, on that port only. It then probes, deletes the pair and checks that the pair is gone. Only
a meshed destination gets an opening. The denial log of every pod the Service selects is read, so the
line of whichever replica served the attempt is found. A pod port is
probed once from each namespace: when two Services select the same pods, the second one's ports are
recorded as probed already through the first.

**The control channels**, read from the management side:

- every SPIRE agent is attested to the server and not banned;
- every proxy of the data-plane namespaces holds a configuration SYNCED with istiod. A type istiod
  never sent reads `NOT_SENT`, which is accepted.

A channel that does not hold fails the run, naming the node or the proxy.

## The layer convention

The convention is the one `scripts/verify-mesh-identity` uses, with a stricter network layer: that
script also counts a refusal (`denied(7)`) as a network denial, this one only with a Hubble drop line.

Every outcome class (`denied(<code>)`, `connected`, an HTTP status, `error(<code>)`) is read from curl's
own exit code, which curl writes on its standard output (`-w '%{exitcode}'`), never from the exit status
of `kubectl exec`: on a loaded API server that status has been seen as 0 for a curl that timed out, which
read a probe the network had dropped as served. An attempt whose output carries no exit code observed
nothing, neither a served attempt nor a denial: it is run again, at most three attempts in all, and the
probe's evidence names each such attempt (the exec's exit status and kubectl's first error line). An
attempt that carries an exit code, whatever it is, is never run again. A probe that never carries one is
`error(no exit code)`: it shows nothing about either layer and fails its check.

- **Network layer.** A drop: curl timed out (`denied(28)`) or its connection was reset (`denied(56)`), or
  a meshed caller's proxy gave up connecting (`503 ... reset reason: connection timeout`). When the
  caller node's Cilium agent answers `hubble observe`, a drop counts only with the policy drop Hubble
  recorded for the flow, and fails the probe otherwise: a timeout alone also follows from an address no
  pod holds any more. Without Hubble the drop's class is the evidence. The address of a destination pod
  of the DENY, catch-all and management plane -> data plane probes is read again just before its probe
  (the plan is built earlier): a pod whose address changed is probed at its address now, and a pod gone
  fails its line, named, without a probe. Under Cilium a
  policy denial is a silent drop, so a refusal (`denied(7)`, any other `503`) means the connection reached
  the destination's host: it counts as a network denial only when Hubble recorded a policy drop for the
  flow, and fails the probe otherwise. Every network-layer probe also reads the destination proxy's
  denial log before and after it: a new denial line naming the caller (any new line, for a proxy-less
  probe) means the mesh refused the call, and the probe fails. When the node's Cilium agent answers
  `hubble observe`, the first drop it recorded for the flow since the probe started (read on the node's
  clock) is cited. Otherwise the record says that the outcome's class and the denial log are the
  evidence.
- **Mesh layer.** The destination's proxy refused the caller's identity under the mesh default deny of
  `zone-policy` (`403 RBAC: access denied` for HTTP). It wrote one JSON denial line with the caller's
  SPIFFE ID (`source`), its own (`destination`) and the decision `rbac_access_denied` (in `detail` for an
  HTTP request, in `termination` for a TCP connection).
  A caller without a certificate (a proxy-less probe) is refused before authorization: under mutual TLS
  `STRICT` the destination's proxy resets its plain-text connection, and writes no denial line, because
  the denial log records authorization refusals only. Such a probe passes on the reset, the `STRICT`
  mode in force for the port (`PeerAuthentication`, read with Istio's precedence), and, when Hubble is
  available, the request seen forwarded to the destination, so that the network did not stop it.
- **Served.** An attempt that was answered (`connected`, any HTTP status other than the drop forms above)
  fails a network- or mesh-layer probe, and its evidence says it was served.
- **Control channel.** The legitimate caller was served over mutual TLS. The caller's proxy counted the
  request with the destination principal (`istio_requests_total`, `reporter="source"`).

## Real services and stand-ins

For each row's destination, the verifier first looks for pods that match the row's selector and service
account and that it did not create. It uses such a pod (`real`) through the Service that selects it.
Otherwise it creates the stand-in from `fixtures/rows/<row>.yaml`: agnhost `porter` with exactly the row's
labels and service account, answering on the row's ports. TSPA has its stand-in in `fixtures/tspa.yaml`.

Callers are always stand-ins, so that a probe never execs into a production workload. A row with a real
destination gets no stand-in destination. The run never applies over an object the zone already has,
so its cleanup never deletes one. A ServiceAccount the zone already has is used as found. Any other
object of the same name as a stand-in fails the run, named, and the stand-in is not created.

The proxy-less `probe-<i>` pods opt out of injection, which the capture rule of `zone-policy`'s
admission policy refuses in an injected plane namespace. The verifier therefore creates them with that
one validation lifted, puts it back and checks five refusals in a row, in the same way as
`verify-mesh-identity` (`capture_lift_create`, `scripts/lib/probe.sh`). Each line of the record says
`real` or `stand-in`.

`verify_test.sh` holds every fixture to its rendered row: the destination, the caller, the impostor and
the unlabelled caller each carry exactly the row's labels and service account, or none of them where
that is the point.

## The record

A run writes three files to the run directory and prints that directory as the last line of its output
(`tail -n 1`):

- `evidence.md`: a header (cluster, context, zone file, trust domain, commit, tree state, run id), the
  routing precondition, the rows and their cross-check, the probe plan, every probe with what it read
  and its layer, the control channels, the cleanup, the matrix as one table, and the per-row decision;
- `matrix.csv`: one line per row × caller's namespace × probe;
- `environment.json`: commit, date, context, Kubernetes and Cilium versions, Hubble availability per
  node, tools.

The run directory is `ZTD_EVIDENCE_DIR` when set, and otherwise a new directory per run under
`${XDG_STATE_HOME:-$HOME/.local/state}/ztd/verify-plane-separation/<context>/<UTC start>/`. A directory
inside the repository is refused (exit 125, nothing written) unless git ignores it. The exception is
for the BDD harness, which writes under `bundles/`. On a participant cluster every IPv4 and IPv6
address in the three files is written as `<address>` (`proof_mask`, `scripts/lib/proof.sh`), except the
loopbacks `127.0.0.1` and `::1` and the unspecified `::`.

**The repository holds no record of a run.** A record goes with the task that asked for it. A run
changes nothing in the repository: `git status` after it is what it was before.

`matrix.csv` has these columns, in this order:

| Column | Meaning |
|---|---|
| `row` | the `allowMatrix` row name, `tspa`, `spire-server`, `catch-all` or `management-to-data` |
| `role` | the ZT-55 role §6 gives the row |
| `namespace` | the namespace probed from: a data-plane one, or a management-plane one for `management-to-data` |
| `probe` | what was tried (legitimate caller, impostor, unlabelled, TCP proxy-less, behind a probe-scoped opening, ...) |
| `caller`, `destination`, `port` | the stand-in that called, the destination (Service, or namespace/Service (pod)), the port |
| `expected`, `outcome` | what passes, and what the probe read |
| `layer` | `control channel`, `network` or `mesh` |
| `evidence` | the denial line, the Hubble drop, the request count, or the reason for `n/a` |
| `kind` | `real` or `stand-in` |
| `verdict` | `pass`, `fail`, `declared` (the xDS opening) or `n/a` (no proxy at a management-plane destination; the export row's impostor and unlabelled caller) |

A row is **failed** when any of its lines is `fail`. It is **declared** when one of its lines is
`declared` and none failed, and **green** otherwise. A file without lines decides nothing, and a file
that lacks either direction (no line of `management-to-data`, or no other row) is not held.
`plan_decide` (`plan.sh`) and the Annex scenario both apply this rule, and both are held to the same cases
(`internal/bdd/testdata/plane-matrix/`, run by `verify_test.sh` and `go test ./internal/bdd`).

## Safety and cleanup

- **Before anything is created**, the run refuses (exit 125) while any pod, Service, ServiceAccount or
  NetworkPolicy labelled `app.kubernetes.io/part-of: verify-plane-separation` exists from an earlier
  run.
- **Before anything is created**, it also refuses (exit 125) when the admission policy
  `proxy-takes-spire-socket` cannot be read or holds no capture validation (no validation reads
  `variables.captureDefaults`). A run of this script or of `verify-mesh-identity` that is killed while
  the validation is lifted (SIGKILL, out-of-memory, a reboot: no trap runs) leaves the policy so, and its
  restore file goes with its temporary directory; a later run would otherwise take the lifted policy for
  the zone's. The message names the restore, the `zone-policy` release applied again at its deployed
  revision:

  ```bash
  rev=$(helm --kube-context "$KUBE_CONTEXT" -n istio-system status zone-policy -o json | jq .version)
  helm --kube-context "$KUBE_CONTEXT" -n istio-system rollback zone-policy "$rev" --force-conflicts
  ```

  The lift's patch owns the field `.spec.validations`, so without `--force-conflicts` the rollback, and a
  `helm upgrade` (so `scripts/install-zone/install.sh install`), stops on that field manager's conflict.
  The same holds after **every** run, a completed one included: the restore is a JSON patch too, so
  `kubectl-patch` keeps `.spec.validations` and a later release of the chart that changes a validation
  stops on that conflict until the rollback above takes the field back (`docs/troubleshooting.md`).
- **At the start** it takes a snapshot of every NetworkPolicy, CiliumNetworkPolicy,
  CiliumClusterwideNetworkPolicy and AuthorizationPolicy of the cluster (kind, name, UID,
  resourceVersion), plus the spec of the admission policy whose capture rule it lifts.
- **The lift of the capture validation is a known exposure.** To create its proxy-less probes the run
  removes the capture validation from the whole admission policy `proxy-takes-spire-socket`, not for its
  own pods alone: for about 45 seconds at most (up to 20 dry runs a second apart, then up to 10 creates
  2 s apart), plus the time each API server replica takes to take up the restore, **any pod created in any
  injected plane namespace is admitted without a proxy**, a capture opt-out or another capture annotation.
  The template, socket and proxy rules stay in force. The restore and the five refusals in a row bound
  the window; they do not narrow it. Run the verifier when no deployment is rolling out in the plane
  namespaces, and compare the pods created meanwhile (`kubectl get pods -A
  --sort-by=.metadata.creationTimestamp`) with the run's start if in doubt. `verify-mesh-identity` lifts
  the same validation the same way (`capture_lift_create`, `scripts/lib/probe.sh`).
- **Every pod of the run stops on its own** after two hours (`activeDeadlineSeconds: 7200` in every Pod of
  `fixtures/`, well past a run's length). A caller stand-in carries its row's labels and, where the zone
  has it, the row's real service account, so its SPIFFE identity; a run killed outright (SIGKILL, a
  reboot: no trap runs) would otherwise leave it running with that identity, and the proxy-less probes
  with it. An expired pod is `Failed`, not running; it keeps its label, so the next run still refuses
  until it is deleted (`kubectl delete pods,services,serviceaccounts,networkpolicies -A -l
  app.kubernetes.io/part-of=verify-plane-separation`). A probe-scoped opening left by such a kill has no
  deadline: it admits only a prober of the killed run, and the same refusal names it.
- **At the end, and from an EXIT trap** (an `INT` or `TERM` included), it removes every object carrying
  that label and puts the capture validation back. The run fails when an object remains or when the
  snapshot differs. The trap ignores `INT` and `TERM` from its first line, so a second Ctrl-C does not
  stop the deletions; their wait is bounded (three minutes), and on stderr the trap names every object
  that remains and says when the policies differ from the snapshot.
- **Before any probe**, the routing check of `scripts/lib/probe.sh` stops the run when Cilium would
  masquerade pod traffic between nodes. The run creates nothing then, and the record names the node.

## Exit codes

| Status | Meaning |
|---|---|
| 0 | every check passed; declared openings and `n/a` lines are recorded, not counted |
| 1-124 | the number of failed checks, capped at 124; the record is written |
| 125 | refused or not run: an argument, `CI` set, the context guard, a run directory inside the repository, a leftover object, an admission policy that cannot be read or holds no capture validation; nothing written |
| 130, 143 | interrupted; fixtures and openings removed, no record |

## Running it

It needs `kubectl`, `helm`, `istioctl`, `jq`, `python3` with PyYAML (to read YAML, as the other scripts
under `scripts/` do), `git` and bash 4 or later. `plan.sh`, sourced by `verify.sh`, holds the part that
reads no cluster: the rows, the cross-checks, the rule of the management plane → data plane direction,
the mutual TLS mode in force for a port, the probe plan and the per-row decision. Hubble
is read inside the Cilium agent pods, so nothing more is needed on the host.

On kind:

```bash
scripts/dev/kind-cilium-up.sh
scripts/install-zone/install.sh install
scripts/verify-plane-separation/verify.sh
scripts/verify-plane-separation/verify.sh --help        # usage; touches nothing
scripts/verify-plane-separation/verify_test.sh          # offline cases; no cluster
```

On a participant cluster that `verify-mesh-identity` left installed (zone B: `zerotrust-b` and
`zone-b.yaml`):

```bash
KUBE_CONTEXT=zerotrust-a ZTD_CONFIRM_CLUSTER=zerotrust-a \
  ZONE_VALUES=deployment/helm/ztd/zones/zone-a.yaml scripts/verify-plane-separation/verify.sh
```

The context guard is the one of `verify-mesh-identity` (`scripts/lib/proof.sh`): a kind cluster, or
`zerotrust-a` / `zerotrust-b` with `ZTD_CONFIRM_CLUSTER` typed for the run and the API host, node
provider and node names bound to the context name. Any other context is refused before the cluster is
read.
