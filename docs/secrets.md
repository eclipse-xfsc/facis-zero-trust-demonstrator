# Secrets

How the demonstrator holds credentials and key material, and how it proves none of them leaks into a
log (TDR-BDD-08). Two stores are sanctioned: **Kubernetes Secrets**, and **OpenBao** for X.509 key
material as ZT-11 prescribes ([ADR-0004](adr/0004-openbao-as-x509-key-value-store.md)). Nothing
else holds a credential: not a ConfigMap, not a chart value, not an image, not the repository.

OpenBao is MPL-2.0. It is deployed as a separate, unmodified service and used through its API; the
written licence exception for it (Licence Exception Notice v1.0, follow-up requirement F-07) is
**open** — submitted, not yet decided. See [OSS dependencies](dependencies.md#licence-exceptions).

## OpenBao in the umbrella

The umbrella chart (`deployment/helm/ztd`, [Umbrella chart](umbrella-chart.md)) installs OpenBao as a
dependency when a zone sets `openbao.enabled: true`. It is off by default; the kind zone file
(`ci/values.yaml`) turns it on.

| | |
|---|---|
| Chart | `openbao` 0.28.3 from `https://openbao.github.io/openbao-helm` (locked in `Chart.lock`) |
| Server | OpenBao v2.5.4, the chart's app version, image pinned by digest in `values.yaml` |
| Mode | standalone, one replica, file storage on a volume of the zone's storage class |
| Namespace | the management plane (`ztd-mgmt`) |
| Engines | KV version 2 at `secret/`, transit at `transit/` |
| Not used | the agent injector, the Kubernetes auth method and its cluster-wide auth-delegator binding (they come with the ZT-11 signing flow), high availability |

The chart version and the server version are different numbers: 0.28.3 is the Helm chart, v2.5.4 the
OpenBao it ships. The OpenBao 2.7.0 image in `scripts/tools/pins.env` is a separate pin, used only by
the token-store integration tests.

The server listens without TLS inside the management plane. Transport protection between workloads
is the mesh layer's ([ADR-0001](adr/0001-service-mesh-mode-istio-ambient-with-cilium.md)), and the
plane's default-deny admits only pods of the same plane.

### Bootstrap

A sealed OpenBao is not ready, and with `--wait` Helm runs post-install hooks only once every regular
resource is ready, so no hook could ever unseal it. The bootstrap is therefore a regular Job,
`ztd-openbao-bootstrap-<hash>`, and the release is installed with `--wait --wait-for-jobs`. Its state
lives in the Kubernetes Secret `ztd-openbao-bootstrap` in the management namespace, and every run is
safe to repeat:

| State found | What the Job does |
|---|---|
| not initialised, no Secret | initialises with one key share, stores the unseal key and the root token in the Secret (`state=initialized`) |
| not initialised, Secret present | fails: the store was lost; the Secret is never overwritten |
| initialised, no Secret | fails: it never re-initialises |
| sealed | unseals with the stored key |
| `state=initialized` | enables kv-v2 and transit, creates the fixture transit key `ztd-fixture` and the fixture KV value `secret/ztd-fixture/canary`, the policy `ztd-verify` and a periodic verification token (768 h); checks the token; sets `state=configured` |
| `state=initialized`, continued | for every entry of `openbaoBootstrap.serviceTokens`: enables that entry's two transit engines (`<transitMount>` and `<transitMount>-storage`), writes its policy and issues its periodic token into its own Secret (see [Service tokens](#service-tokens)) |
| `state=configured`, root token still present | issues the service tokens still missing, then revokes the root token if it is still valid and removes it from the Secret |
| `state=configured` | renews the verification token, checks and renews every service token (fails if one is missing or expired), and exits |

After a successful run the Secret holds the unseal key, the verification token and the state; the root
token is revoked. The Job name carries a hash of its script and values: it reruns when the bootstrap
changes, and an unchanged upgrade renders the same manifest. Credentials reach `curl` through header and body files in a memory volume, never on a command line,
and the Job's log names states and HTTP codes only.

The `ztd-verify` policy can read `sys/mounts/*`, read `secret/data/ztd-fixture/*`, use the
`ztd-fixture` transit key, and look up and renew itself. Nothing else.

The Job's Role may create Secrets in the management namespace — Kubernetes RBAC cannot limit `create`
to one name — and may read and patch only `ztd-openbao-bootstrap` and the service-token Secrets it
issues. The entries must be distinct (names, engines, and no engine that is another entry's
`-storage` engine), must not name a reserved or shared engine (`transit`, `secret`, `sys`, `auth`,
`identity`, `cubbyhole`), and need the bundled OpenBao: with `openbaoExternal.address` nothing would
issue them, so the chart refuses the combination.

### Service tokens

A component that signs with OpenBao transit (the OCM wallet's signer is the first) gets its own
engine, policy and token from the bootstrap, declared in the zone file:

```yaml
openbaoBootstrap:
  serviceTokens:
    - name: ocm-wallet          # Secret ztd-openbao-ocm-wallet, policy ztd-svc-ocm-wallet
      transitMount: ocm/zone-a  # the component's own transit engine
      period: 768h              # default
```

For each entry the bootstrap enables two transit engines, `transitMount` and `transitMount-storage`
(left alone when they exist; engines cannot nest, so the second is a sibling), writes the policy
`ztd-svc-<name>` and issues a periodic orphan token with it into the Secret
`ztd-openbao-<name>` (key `openbao-token`) of the management namespace; the component's chart mounts
that Secret and never sees any other token. The policy allows, on the identity engine: listing, reading,
creating and updating keys, signing and verifying; reading the engine's mount configuration and the
mount table (the signer lists both); on the storage engine the same plus encryption and decryption
(the W-Stack's storage service keeps one symmetric key per account there, which must never appear
in the DID document); and looking up and renewing the token itself.
Key export is denied explicitly in both engines, and the per-key configuration in the identity
engine, so the identity key can never be made exportable or deletable (the storage service sets the
configuration of the data keys it creates); nothing outside the two engines (`secret/`, `transit/`,
another component's engine, `sys/`) is reachable. Two components never share an engine: a DID document lists every key of
its engine, so an engine is one identity.

Tokens are periodic orphan tokens without the `default` policy (the policy names `lookup-self`,
`renew-self`, `revoke-self` and `capabilities-self` itself), issued while the root token exists
(`state=initialized`); every later bootstrap run checks that the stored token answers and carries
the policy `ztd-svc-<name>` (a foreign token in the Secret is not accepted), renews it, and fails
rather than replaces it when OpenBao does not answer. A token minted but not stored is revoked
before the Job dies. The Secret also records `policy-sha256`, the hash of the policy text the token
was issued under: when a chart version changes the policy and the root token is gone, the bootstrap
fails with a message naming the recovery instead of renewing a token under the stale policy. On the
identity engine the token may create, read and use keys but never rotate, trim or import them. An entry **added to a zone that is already bootstrapped**
therefore needs the recovery below once: the bootstrap fails with "service token … is missing or
expired and the root token is gone" until a root token is put back. A rebuilt environment needs
nothing: the entries are values, and the first bootstrap issues them all.

**Recovery (new or expired service token, expired verification token).** Generate a root token with
the unseal key (`bao operator generate-root`, inside the OpenBao pod, the key on standard input as
`scripts/secrets/unseal.sh` does), write it to the bootstrap Secret's `root-token` key, and run the
bootstrap again (delete the bootstrap Job and `helm upgrade`, or upgrade with a changed
`openbaoBootstrap`). Then restart the component's pods, which read their token at start.

**Removing an entry.** Deleting an entry from `serviceTokens` does not revoke its token or delete its
policy, engines or Secret (the chart cannot without the root token). Decommission by hand with the
recovery's root token: revoke the token, delete the policy and the Secret, and, only when the
identity is retired for good, disable the two engines. The Job issues what is missing, renews what exists and revokes the root
token again. For the verification token alone the manual route still works: issue a new periodic
token with the `ztd-verify` policy and write it to `verify-token`.

**Network.** The Job reaches the Kubernetes API from the management plane. Under Cilium the chart opens
that lane itself, as a `CiliumNetworkPolicy` to the `kube-apiserver` entity for the Job's pods only, so
OpenBao bootstraps whether or not the zone's `networkPolicy.kubeApi` lane is on. With another CNI that
lane must be open (on kind, `scripts/secrets/kind-api-lane.sh` prints it from the live cluster).

### Verification

The `platform`-band hook `ztd-verify-openbao` runs after every install and upgrade, in the management
namespace, with the verification token from a Secret volume and no Kubernetes API access. It fails
the release unless the server is initialised and unsealed, `secret/` is KV version 2 and `transit/`
is transit; with the bundled server it also reads the fixture value (printing a 12-character hash of
it, never the value), round-trips the fixture transit key and checks that every service token's two
engines exist. It renews the verification token. The hook never holds a service token: each
component renews its own (the wallet chart's daily `<release>-renew` CronJob), and every bootstrap
run checks and renews them too. The Job stays until the next run replaces it, so its log can be collected.

**Token expiry.** If a token expires, the hook fails. Recovery: see [Service tokens](#service-tokens).

### After a restart: manual unseal

OpenBao seals itself whenever its pod restarts and stays not ready until it is unsealed. Unsealing is
a documented manual step, not an automatic one:

```bash
scripts/secrets/unseal.sh            # namespace ztd-mgmt, pod ztd-openbao-0
```

The script reads the key from the Secret and hands it to `bao write sys/unseal key=-` on standard
input, so it never appears on a command line (which the API server's audit log records) or in the
output. The data survives: the secrets baseline restarts the pod, observes it sealed and not ready,
unseals it and finds the same fixture value.

### Teardown

`helm uninstall` deletes the plane namespaces, and with them the OpenBao volume and the bootstrap
Secret. It is a destructive reset: the next install initialises a new, empty store.

### An existing OpenBao

The XFSC ArgoCD deployment, which FACIS names as the reference deployment, already installs OpenBao —
the same chart, 0.28.3, wrapped with selectable auto-unseal backends
([`eclipse-xfsc/deployment`, `INFRA/security/openbao/Chart.yaml`](https://github.com/eclipse-xfsc/deployment/blob/739606691ecff72b3a40404a19fce44d9c22b0ee/INFRA/security/openbao/Chart.yaml)).
There the umbrella uses that instance instead of its own: `openbaoExternal.address` names it and
`openbaoExternal.verifyTokenSecret` names a Secret in the management namespace with a `verify-token`
key. Nothing is installed or initialised; only the verification hook runs (health, unseal state and
the two engines). `openbao.enabled` and `openbaoExternal.address` are exclusive.

## The baseline proof (TDR-BDD-08)

`release.yml` proves the baseline on every candidate, in two jobs of the same run:

**Secrets baseline** (`scripts/secrets/baseline.sh`) installs the umbrella with OpenBao on a disposable
kind cluster, restarts OpenBao and unseals it by hand (`restart.json`), and runs the canary scan
(`scripts/secrets/canary_scan.py`) twice: right after the install, before the restart deletes the first
OpenBao pod and the upgrade replaces the verification hook, and again at the end. `scan.json` holds both
stages and is clean only if both were. Each scan:

- a synthetic credential, the canary, is put in a Kubernetes Secret that a probe pod in the data plane
  consumes as an environment variable and as a file;
- the raw output of every container in every namespace is collected — init containers too, and the
  previous instance of any container that restarted — with every pod spec and every ConfigMap (data
  and decoded binaryData);
- they are searched for the canary (plain and base64), for OpenBao's live credentials read from the
  cluster (the unseal key, the verification token and the fixture value), and for the shapes of
  credentials: PEM private keys, OpenBao tokens and, in ConfigMaps, non-empty password fields and any
  key named like a credential (password, secret, token, API key, private key, credential) that holds
  a value. The root token is revoked and gone by then, so it can only be found by its shape;
- a **negative control** proves the scan finds what it looks for: a pod in its own namespace prints the
  canary, and the scan must detect it there. It is reported apart from the baseline.

A container that never started has no output and is counted as such; any other collection failure
fails the scan, and is reported by operation and exit status only — kubectl's own message can quote
what it was given, and evidence never carries it. The demonstrator has no deployed service that consumes a credential yet, so the probe
stands in for one; the scan covers every container and applies to the services as they land.

**Secrets log audit** runs once the first job has completed. It downloads that job's published log
through the job-level REST endpoint (`scripts/secrets/log_audit.py`, `log-audit.json`) and requires
the canary to be absent and a masking control to be present only masked: the first job registers both
values with `::add-mask::` and prints `ZTD_MASK_CONTROL=<value>` once, which must appear as
`ZTD_MASK_CONTROL=***`. Without the control, a log in which nothing was masked, or the wrong log, could
pass. Both values are derived from the repository, run id and attempt — synthetic, never real
credentials — and the audit refuses evidence from another run or attempt.

The row is decided in the audit job, from both halves for the same run. Evidence publishes counts,
scope, locations and the canary's SHA-256, never a value.

**What masking proves.** A clean published log shows that GitHub's masking removed the registered
values from the published log. It does not show that a component never emitted one; that is what the
scan of the raw container output is for.

## Pipeline credentials

Workflow secrets reach a step through `env`, are masked by GitHub, and are never echoed. A job's
kubeconfig is written with `umask 077` to the runner's temporary directory. See
[CI/CD](ci-cd.md#repository-protection-and-least-privilege) for token scopes.
