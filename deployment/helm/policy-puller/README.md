# policy-puller

The policy package puller of a zone (ZT-12): a CronJob in Argo CD's namespace that, on each run,
resolves the package's channel tag in the registry, verifies the cosign signature of the digest it
names against the trusted public key, refuses a package created before the one the zone already
follows, and writes the verified digest into the parent Application (`ztd-admission`), from whose
values Argo CD renders the children that read the admission policy from the package by digest.
A refusal or an unreachable registry changes nothing: the zone keeps the digest it last verified.
Installed by `scripts/argocd/install.sh` with `POLICY_REPOSITORY`; the design and the operations are
in [deployment/argocd/README.md](../../argocd/README.md#policy-from-the-registry).

## Values

| Key | Default | Meaning |
|---|---|---|
| `image.repository`, `image.digest` | the project's registry, no digest | the puller image, by digest only; the chart refuses a tag |
| `package.repository` | none (required) | the package's repository, `host/path`, the one `policy-publish.yml` pushes to |
| `package.tag` | `main` | the channel tag the workflow moves to each publication |
| `argocd.namespace` | `argocd` | the release namespace the chart accepts: where the Application is |
| `argocd.application` | `ztd-admission` | the parent Application whose values carry the digest |
| `trust.publicKeys` | none (required) | the trusted cosign public keys, PEM |
| `schedule` | every 5 minutes | the CronJob's schedule; runs never overlap and a failed run is not retried |
| `egress.registryPort` | `443` | the port of the lane from the puller to the registry |
| `insecurePlainHTTPRegistry` | empty | a plain-http test registry, `host:port`; never set in a real deployment |
| `registryCredentialsSecret` | empty | a Secret with `username` and `password` for a registry that asks for a credential on pull |

## What a run leaves

On the Application: the annotations `facis.ztd/policy-digest`, `facis.ztd/policy-created` (what a
candidate is ordered against) and `facis.ztd/policy-verified`, and `facis.ztd/policy-refused` with
the last refusal, cleared by the next success. An Event (`PolicyPackageApplied`,
`PolicyPackageRefused`, `PolicyPackageUnavailable`) on each change or failure, as
`kubectl -n argocd describe application ztd-admission` shows them.
