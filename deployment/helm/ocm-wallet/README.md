# ocm-wallet

One organisation's OCM W-Stack wallet, one release per tenant: the **signer** with its keys in the
zone's OpenBao transit engine, the **credential storage** and **credential retrieval** services on
the zone's Cassandra and NATS ([`ocm-backbone`](../ocm-backbone/README.md)), and the **edge** that
serves the organisation's `did:web` document over TLS. Installed into the management-plane
namespace the [umbrella chart](../ztd/README.md) laid down, after the backbone. The design, the
identity model and the proof are in [OCM wallet](../../../docs/ocm-wallet.md).

```bash
helm upgrade --install ocm-wallet deployment/helm/ocm-wallet -n ztd-mgmt \
  -f <zone values> --wait --wait-for-jobs
```

## What it installs

| Object | Purpose |
|---|---|
| Job `<release>-key` (post-install and post-upgrade hook, platform band) | creates the tenant's key `tenant.key` in its transit engine with the release's own token once the pods are up (`--wait --wait-for-jobs` returns after it): `ecdsa-p256`, never exportable; a key that exists is checked, not replaced |
| Deployment and Service `<release>-signer` | the W-Stack signer (`crypto-provider-service`) on 8080, with its OpenBao engine (`crypto-provider-hashicorp-vault-plugin`) beside it on 50051; the engine is the only container that holds the token |
| Deployment and Service `<release>-storage` | the credential storage service on 8080; its tables in the backbone's `ocm` keyspace, its store requests on NATS; its keys (one symmetric key per account) in the engine `<transitMount>-storage` the umbrella's bootstrap created beside the tenant's, so the DID document never lists them |
| Deployment and Service `<release>-retrieval` | the credential retrieval service on 8080: OID4VCI on the holder's side, offers from NATS or its API, results stored through the storage subject |
| Deployment, ConfigMap and Service `<release>-edge` | nginx terminating TLS for `tenant.host` on 8443 (Service port 443) and serving exactly `/.well-known/did.json` and `/.well-known/jwks.json` from the signer, with the tenant's identity headers set here and nowhere else; everything else is 404 |
| NetworkPolicies, one per component | the signer to OpenBao and NATS, the services to Cassandra and NATS, the storage service to the engine, the edge to the signer, the edge's TLS port to the world and to the lane's pods, the retrieval service to the issuers it fetches from. Inside the namespace they narrow nothing while the umbrella's intra-plane lane is on (the default); they bind for traffic from outside it and in a zone that turns that lane off |
| CronJob `<release>-renew` | renews the release's own OpenBao token once a day (`tokenRenewal.schedule`), so the wallet does not depend on umbrella upgrades to stay alive |
| PeerAuthentications (with `mesh.enabled`) | STRICT for every workload; the edge's 8443 PERMISSIVE, since the world reaches it without a sidecar |
| ServiceAccounts, one per component | the pods' identities (`spiffe://<trust domain>/ns/<namespace>/sa/<release>-<component>`), no token mounted |

## Values

| Key | Meaning | Default |
|---|---|---|
| `tenant.id` | the organisation's short name: the W-Stack tenant id and the `ztd.facis.io/tenant` label | required |
| `tenant.host` | the DNS name of the DID document: the DID is `did:web:<host>`, served at `https://<host>/.well-known/did.json` | required |
| `tenant.key` | the transit key the document lists | `wallet-<id>` |
| `tenant.transitMount` | the transit engine holding it: the one the umbrella's bootstrap created for this release's service token | `ocm/<id>` |
| `images.<signer\|vaultPlugin\|storage\|retrieval\|edge\|hook>.repository`, `.digest` | every image by digest only | repositories set, digests empty |
| `openbao.address` | the zone's OpenBao | `http://ztd-openbao.ztd-mgmt.svc:8200` |
| `openbao.existingSecret`, `openbao.secretKey` | the Secret the bootstrap wrote for the matching `serviceTokens` entry (`ztd-openbao-<name>`) and its key | required, `openbao-token` |
| `backbone.natsUrl`, `backbone.cassandraHosts`, `backbone.keyspace`, `backbone.credentialsSecret` | the zone's stores; the Secret (`username`, `password`) for a Cassandra with authentication on, empty for the backbone's default | `nats://ocm-nats:4222`, `ocm-cassandra:9042`, `ocm`, empty |
| `messaging.prefix` | the NATS subject prefix: `<prefix>.offering`, `<prefix>.storage`, `<prefix>.signer` | `tenant.id` |
| `edge.service.type`, `.nodePort`, `.loadBalancerIP`, `.externalTrafficPolicy`, `.annotations` | how the world reaches the document: LoadBalancer where the zone has one, NodePort on kind | `ClusterIP` |
| `edge.tls.existingSecret` | the `kubernetes.io/tls` Secret for `tenant.host`; the chart issues no certificate | required |
| `retrieval.trustedCAConfigMap` | a ConfigMap whose `ca.crt` the retrieval service trusts besides the system roots (the zone's CA while certificates are self-issued) | empty |
| `retrieval.country`, `retrieval.region`, `retrieval.disableTLS` | the W-Stack's locality fields; the upstream's development switch, off | `DE`, `EU`, `false` |
| `mesh.enabled` | render the PeerAuthentications | `false` |
| `identity.spireManagedIdentity` | the `spiffe.io/spire-managed-identity` label on every pod | `true` |
| `networkPolicy.enabled`, `.cilium`, `.openbaoSelector`, `.edgeIngress.cidrs`, `.issuerEgress.{cidrs,port,peers}` | the lane's policies; `cilium` adds the node entities a LoadBalancer's traffic arrives from and renders a narrowed `edgeIngress.cidrs` as a CIDR set; `peers` are NetworkPolicyPeer objects; empty `edgeIngress.cidrs` or `openbaoSelector` are refused | `true`, `false`, `{app.kubernetes.io/name: openbao}`, any, none |
| `tokenRenewal.schedule` | when the renewal CronJob runs | `17 3 * * *` |
| `hooks.weight` | the key Job's hook weight, inside the platform band 40–59 | `45` |
| `logLevel`, `resources.*` | logging and sizing | `info`, see `values.yaml` |

The pinned digests the proof installs are in `scripts/tools/pins.env` (`OCM_*_IMAGE`); a zone
file copies them.

## How it behaves

- **The DID document is the engine.** The signer lists every key of the transit engine named in
  the request headers as a verification method, so one engine is one identity. The umbrella's
  bootstrap creates the engine and the token per `serviceTokens` entry
  ([Secrets, service tokens](../../../docs/secrets.md#service-tokens)); the key Job creates the
  key. The document has no `service` section: the W-Stack fills it from a TSA policy the
  demonstrator does not run.
- **Keys never leave OpenBao.** The token's policy denies export and the per-key configuration,
  so the key the Job created cannot be made exportable later; the Job refuses an exportable key
  it finds.
- **Restarts.** Wallet pods and upgrades keep key, DID and credentials. A Cassandra restart keeps
  the credentials. An OpenBao restart seals the store: until `scripts/secrets/unseal.sh` runs the
  document answers without any key (nothing can be verified against it) and the signer cannot
  sign; afterwards the wallet recovers by itself. `helm uninstall` leaves the key in OpenBao and
  the credentials on the backbone's claim; a reinstall from the same values serves the same
  document.
- **A new token or certificate needs a pod restart.** The engine reads its token at start and nginx
  its certificate: after the token is re-issued (Secrets, recovery) or the TLS Secret replaced,
  `kubectl -n ztd-mgmt rollout restart deployment -l app.kubernetes.io/instance=<release>`.
- **TLS and names are the zone's.** The chart serves what it is given: the certificate Secret and,
  on a real zone, the public DNS record for `tenant.host`. The proof stands both in with a test CA
  and a CoreDNS rewrite.

## Proving it

`scripts/verify-ocm-wallet/verify.sh` installs the umbrella with two service tokens, the backbone
and two wallets on a throwaway kind cluster and checks the token boundaries, the documents (id,
one key, the key's RFC 7638 thumbprint against the transit public key), the resolution of the other wallet's DID by a
management-plane pod, a data-plane pod refused by the stores, a stored credential, the restarts (pods, Cassandra, OpenBao) and the reinstall. The CI
workflow `OCM wallet lane` runs it on every change to the lane and publishes the records.
