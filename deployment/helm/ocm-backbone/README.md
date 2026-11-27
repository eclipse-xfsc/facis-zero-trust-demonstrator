# ocm-backbone

The stores the OCM W-Stack wallet lane of a zone shares: one Cassandra node holding the `ocm`
keyspace the W-Stack services migrate their tables into, and one NATS server for their messaging.
Installed once per zone into the management-plane namespace the [umbrella chart](../ztd/README.md)
laid down, before the first [`ocm-wallet`](../ocm-wallet/README.md) release. The design and the
proof are in [OCM wallet](../../../docs/ocm-wallet.md).

```bash
helm upgrade --install ocm-backbone deployment/helm/ocm-backbone -n ztd-mgmt \
  -f <zone values> --wait --wait-for-jobs
```

## What it installs

| Object | Purpose |
|---|---|
| StatefulSet `ocm-cassandra` (1 replica) and headless Service `ocm-cassandra` | Cassandra 5.0.5 on CQL 9042; the data on claim `data-ocm-cassandra-0`, which the StatefulSet **keeps** on deletion and scale-down, so a `helm uninstall` leaves the credentials where they are and a reinstall binds the same claim |
| Job `ocm-cassandra-keyspace` (post-install and post-upgrade hook, platform band) | `CREATE KEYSPACE IF NOT EXISTS ocm` with replication factor 1, once the node answers; the W-Stack services' own migrations create their tables in it |
| Deployment `ocm-nats` and Service `ocm-nats` | NATS 2.12 on 4222, core NATS only (no JetStream): the W-Stack flows are request/reply and publish/subscribe, durable state is Cassandra's |
| NetworkPolicies | CQL and NATS opened to pods labelled `app.kubernetes.io/part-of: ocm` in the same namespace (a restriction only where the umbrella's intra-plane lane is off); the stores reach nothing but the resolver |
| ServiceAccounts | one per store, no token mounted |

## Values

| Key | Meaning | Default |
|---|---|---|
| `images.cassandra.repository`, `.digest` | Cassandra, by digest only (the chart refuses a tag) | `docker.io/library/cassandra`, empty |
| `images.nats.repository`, `.digest` | NATS, by digest only | `docker.io/library/nats`, empty |
| `cassandra.keyspace` | the keyspace the hook creates; the W-Stack migrations are written for `ocm` | `ocm` |
| `cassandra.clusterName`, `cassandra.numTokens` | the node's cluster name and token count | `ocm`, `16` |
| `cassandra.heap.max`, `cassandra.heap.new` | JVM heap for one node; a zone raises it | `1G`, `200M` |
| `cassandra.storage.className`, `cassandra.storage.size` | the zone's storage class (`zone.storageClass` of the umbrella; required) and the claim's size | empty, `5Gi` |
| `cassandra.startupSeconds` | how long the start may take before liveness counts | `300` |
| `cassandra.resources`, `nats.resources` | requests and limits | see `values.yaml` |
| `hooks.weight` | the keyspace Job's hook weight, inside the platform band 40–59 | `45` |
| `networkPolicy.enabled` | render the two policies | `true` |

The pinned digests the proof installs are in `scripts/tools/pins.env` (`OCM_CASSANDRA_IMAGE`,
`OCM_NATS_IMAGE`); a zone file copies them.

## How it behaves

- **One node, authentication off.** The image's default authenticator admits every connection.
  The data plane is refused by the umbrella's default deny; inside the management plane the
  umbrella's intra-plane lane (on by default) admits every pod of the namespace, and the chart's
  policy restricts the port to the lane's pods only in a zone that turns that lane off.
  Authentication inside the plane is a documented gap.
- **The claim outlives the release.** `helm uninstall ocm-backbone` deletes the node and the
  Service and keeps `data-ocm-cassandra-0`; the next install binds it again. Removing a zone's
  credentials for good means deleting the claim by hand. The zone teardown (`helm uninstall ztd`)
  deletes the namespace and with it the claim.
- **Tenants share the node, not their rows.** The W-Stack keeps the tenant in every row's key; the
  wallets' NATS subjects are prefixed per tenant. On a real zone one wallet runs per cluster.

## Proving it

`scripts/verify-ocm-wallet/verify.sh` installs the backbone and two wallets on a throwaway kind
cluster and checks CQL, the keyspace, the claim, the restarts and the reinstall; the CI workflow
`OCM wallet lane` runs it on every change to the lane.
