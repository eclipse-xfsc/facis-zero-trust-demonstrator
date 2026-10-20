# token-store

The zone's token store ([services/token-store](../../../services/token-store)). Today the chart
carries the authorization database's schema: a hook Job applies the embedded migrations before
every install and upgrade, so a fresh environment gets the schema automatically and an upgrade
of a current database changes nothing. The service's Deployment joins the chart as the store's
endpoints land; the design is in [docs/token-store.md](../../../docs/token-store.md).

Install into the zone's management plane after the umbrella chart, with the PostgreSQL the store
owns reachable and its connection URL in a Secret of the release namespace. The chart never
carries the credential: the Secret exists before the install and the Jobs read it.

```bash
kubectl -n ztd-mgmt create secret generic token-store-database \
  --from-literal=url='postgres://token_store:...@postgres.ztd-mgmt:5432/tokenstore'
helm upgrade --install token-store deployment/helm/token-store -n ztd-mgmt \
  --set image.digest=sha256:... \
  --set database.existingSecret=token-store-database \
  --wait --wait-for-jobs
```

## Values

| Key | Default | Meaning |
|---|---|---|
| `image.repository` | the project's `token-store` image | Image of the migration Job and, later, the service |
| `image.digest` | none, required | `sha256:` digest; the chart refuses a tag |
| `database.existingSecret` | none, required | Secret in the release namespace holding the connection URL under `database.secretKey` |
| `database.secretKey` | `url` | Key of the connection URL in that Secret |
| `schema.dropOnUninstall` | `false` | Run `migrate down --to 0` on `helm uninstall`, leaving an empty schema; on in `ci/values.yaml` |
| `schema.hookWeight` | `41` | Hook weight of the Jobs, inside the umbrella chart's platform band (40 to 59) |
| `schema.timeout` | `2m` | Deadline of one migration run, lock wait included |
| `schema.backoffLimit` | `2` | Retries of a failed Job pod |
| `resources` | small | Requests and limits of the Job's container |

## How the hooks behave

- **Install and upgrade.** A `pre-install,pre-upgrade` Job runs `token-store migrate up`. The
  migrations are embedded in the image, so the schema applied is the one the deployed build
  expects. Concurrent runs take an advisory lock in turn; a database already at the embedded
  version is left as it is. A failing Job fails the release and stays for inspection; a succeeded
  Job is removed.
- **Rollback.** `helm rollback` runs no schema hook: migrations only add, so an older build runs
  against a newer schema, and its `migrate up` and `migrate status` treat that database as
  current. Reverting a migration is an operator's `migrate down` with the build that applied it;
  an older build refuses to revert what it does not know.
- **Uninstall.** With `schema.dropOnUninstall`, a `pre-delete` Job runs `migrate down --to 0`
  and the schema is empty afterwards, `schema_migrations` included. Off by default. The Secret
  with the connection URL is not the chart's and stays.

## Verify

Without a cluster, the migration runner and the store's queries run against any PostgreSQL:

```bash
TOKEN_STORE_TEST_DATABASE_URL='postgres://postgres:secret@127.0.0.1:5432/postgres?sslmode=disable' \
  go test -count=1 -race ./services/token-store/...
```

The chart's lifecycle, install on an empty database, upgrade as a no-op and uninstall to an empty
schema, is proven on a throwaway kind cluster by `scripts/verify-token-store/verify.sh`, which the
`Token store` workflow runs on every change to the store, the chart or the pinned images.
