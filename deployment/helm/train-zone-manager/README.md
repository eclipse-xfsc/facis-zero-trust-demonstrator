# train-zone-manager

The TRAIN DNS trust zone manager
([eclipse-xfsc/train-dns-trust-zone-manager](https://github.com/eclipse-xfsc/train-dns-trust-zone-manager))
for one trust framework zone: the authoritative name server the verifiers' content resolver starts
from, and the API the trust-framework manager publishes the zone's pointer records through. The
image is the project's own build of the upstream at a pinned commit with its patches
([deployment/docker/train-zone-manager](../../docker/train-zone-manager)); what the zone is and how
it is operated is in [docs/train-dns.md](../../../docs/train-dns.md).

```bash
helm upgrade --install train-zone-manager deployment/helm/train-zone-manager -n ztd-mgmt \
  -f <zone values> --wait --wait-for-jobs
```

Install into the management-plane namespace of a zone the [ztd umbrella](../ztd/README.md) has laid
down: the chart relies on that namespace's default deny and intra-plane lane, and its DS hook on the
plane's egress lane to the Kubernetes API (`networkPolicy.kubeApi` of the umbrella).

## What it installs

| Object | Purpose |
|---|---|
| `Deployment` `train-zone-manager` | one pod, `Recreate`: the `restore` and `address` init containers, the `zone-manager` container (NSD and the API, started by the upstream's own `script.sh`), the `keeper` sidecar |
| `ServiceAccount`, `Role`, `RoleBinding` `train-zone-manager` | read access to the DNS Service, for the `address` step only (projected token, mounted in that container alone) |
| `Service` `train-zone-manager-dns` | UDP and TCP 53 on one address: `LoadBalancer` where the zone has one, `NodePort` on kind |
| `Service` `train-zone-manager-api` | the API on 16001, cluster-internal |
| `PersistentVolumeClaim` `train-zone-manager-data` | the state: database with the keys, zone file, NSD zone list; kept across `helm uninstall` |
| `PersistentVolumeClaim` `train-zone-manager-backup` | the keeper's backups; kept across `helm uninstall` |
| `ConfigMap` `train-zone-manager-zone`, `Secret` `train-zone-manager-auth` | the zone configuration and the API's OIDC settings, values quoted by the chart |
| `NetworkPolicy` and `CiliumNetworkPolicy` `train-zone-manager-dns-ingress` | port 53 from anywhere, including node-translated sources under Cilium; nothing else is opened |
| `Job` `train-zone-manager-record-ds` and its `ServiceAccount`, `Role`, `RoleBinding` | post-install hook: writes the DS of the served key-signing key into `ConfigMap` `train-zone-manager-ds` |

## Values

| Key | Default | Meaning |
|---|---|---|
| `image.repository`, `image.digest` | the project image, no digest | The image by digest; the chart refuses a tag |
| `zone.name` | none, required | The delegated zone, e.g. `trust.example` |
| `zone.address` | `""` | The public address the zone's own records carry (apex A record and glue). Required unless the DNS Service is a `LoadBalancer`, where an empty value means: discover it from the Service before the first start |
| `zone.addressTimeoutSeconds` | `600` | How long the `address` init step waits for the Service's address |
| `zone.servers.{primary,secondary1,secondary2}` | `ns1`, `ns2`, `ns3` | The three name-server labels under the zone the upstream expects |
| `zone.serverAddresses` | `{}` | A secondary's own address when it has one; otherwise `zone.address` |
| `api.issuerUrl`, `api.clientId` | none, required | The OIDC issuer of the trust-framework manager's tokens and the audience they carry |
| `api.allowUnsafeSsl` | `false` | The upstream's switch to skip TLS verification against the issuer |
| `service.dns.type` | `LoadBalancer` | `LoadBalancer`, `NodePort` or `ClusterIP`; `nodePort`, `loadBalancerIP`, `externalTrafficPolicy`, `annotations` as usual |
| `storage.className` | none, required | The zone's storage class (`zone.storageClass` of the umbrella) |
| `storage.size`, `storage.backup.size` | `1Gi` | Claim sizes |
| `storage.backup.enabled`, `storage.backup.keep` | `true`, `14` | The backup volume and how many daily backups the keeper keeps |
| `keeper.resignAt` | `00:05` | Time of day (UTC) the keeper re-signs the zone and takes a backup |
| `dsRecord.enabled`, `dsRecord.configMap` | `true`, `train-zone-manager-ds` | The DS record hook and the ConfigMap it writes |
| `mesh.optOut` | `true` | Keep the pod out of the mesh (sidecar opt-out annotation, ambient opt-out label) |
| `networkPolicy.enabled`, `networkPolicy.cilium` | `true`, `true` | The DNS ingress policies; `cilium` adds the entity-based one |
| `networkPolicy.issuerEgress.cidrs`, `.port` | `[]`, `443` | Egress to the OIDC issuer when it is outside the plane |

## How it behaves

**The address, once.** The upstream writes the zone's own A records (the apex and the glue of its
name servers) into its database at the first start and has no command to change them afterwards. So
the address has to be right before that start. Given in `zone.address` it is used as it is; left
empty with a LoadBalancer Service, the `address` init step waits for the address the Service is
given and fixes it, and the zone manager does not start until it has one. An address that changes
later means a new zone (delete the volumes) and new keys.

**Keys and the DS.** The zone manager creates the zone's key-signing and zone-signing keys at its
first start on an empty state volume and keeps them in its database there. Both claims carry
`helm.sh/resource-policy: keep`, so `helm uninstall` leaves them and the next install finds the same
keys, and the DS the parent zone holds stays right. After every install and upgrade the hook reads
the DS off the served key and writes it into the ConfigMap; that is the record to send to the parent
operator and the `EXPECT_DS` for the inspector. Deleting the state volume means a new key and a new DS,
which is an outage at every validating resolver until the parent's record is changed.

**Backups and restore.** Daily, after the re-sign, the keeper writes a consistent copy of the whole
state directory (SQLite's backup API for the database) into the backup volume and keeps the last
`storage.backup.keep`. At every start the `restore` init container fills an empty state volume from
`latest.tgz`, so a lost state volume comes back with its keys as long as the backup volume exists;
with both gone, the zone manager creates new keys and says so in the init container's log.

**Re-signing.** Signatures last 28 days from the last write and the upstream's nightly job never runs
(its issue #41). The keeper runs `resign` at `keeper.resignAt` every day, in the same pod, because
`resign` rewrites the zone file and tells NSD to reload through `nsd-control`, whose failure the
upstream ignores: from another pod the job would report success while the served signatures stayed
old. The keeper requires the served SOA signature to move and logs a failure otherwise; the
inspector's `MIN_SIG_DAYS` catches a keeper that stopped. NSD takes control over a local socket in
`/run/nsd`, a volume the two containers share: nothing listens on a control port, and the image
ships no control key pair.

**Readiness.** The pod is ready only while NSD answers authoritatively for the zone (`zone-ready`),
so a server that serves nothing, which is what the unpatched upstream does after every start, receives
no traffic from the Service.

**Out of the mesh.** The pod serves DNS to the world, where no client speaks mTLS, and its API is
reached inside the plane by the trust-framework manager, so it opts out of the mesh. Under default
deny it gains exactly one ingress, port 53 from anywhere; the API port is reachable through the
intra-plane lane and refused to the data plane.

**Not hardened yet.** The upstream starts NSD through its init script and keeps the zone manager
process as root, and it leaves the private keys in clear in the state directory next to the database.
Running as a non-root user and protecting the keys are upstream changes, tracked as hardening.

## Operating it

```bash
kubectl -n ztd-mgmt get configmap train-zone-manager-ds -o jsonpath='{.data.ds}'     # the DS
kubectl -n ztd-mgmt exec deploy/train-zone-manager -c keeper -- zone-keeper resign-now
kubectl -n ztd-mgmt exec deploy/train-zone-manager -c keeper -- zone-keeper backup-now
kubectl -n ztd-mgmt exec deploy/train-zone-manager -c keeper -- zone-keeper ds
kubectl -n ztd-mgmt logs deploy/train-zone-manager -c keeper                          # daily runs
```

### Records for the parent

Once the DNS Service has its address `A`, the delegation the parent operator publishes is, with the
default server labels:

```
<zone>.        IN NS  ns1.<zone>.
<zone>.        IN NS  ns2.<zone>.
ns1.<zone>.    IN A   A
ns2.<zone>.    IN A   A
```

and, once key persistence and the daily re-sign are proven on the deployed instance, the DS from the
ConfigMap. The zone's own apex and glue records carry the same address: the one the `address` step
discovered, or `zone.address` when it was given.

### Removing a zone for good

`helm uninstall` keeps both claims. Delete them by hand only after the parent's DS record for this
zone is gone; otherwise the next install creates a key the parent does not know.

## Proving it

`scripts/train-zone-manager/chart_test.sh` installs the chart on a throwaway kind cluster laid out
like a zone (Cilium, the umbrella with its default deny and API lane, a registry for the image by
digest) and runs six cases, each with its negative half: install and readiness, reinstall on kept
volumes, restore from backup, re-sign, ports and planes, the chart gate. The `@chart` regression
feature reads its results.
