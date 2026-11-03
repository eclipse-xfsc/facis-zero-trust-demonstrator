# OCM wallet

The wallet is where an organisation keeps the verifiable credentials that prove who it is, and the
place an issuer hands them to. The demonstrator gives each organisation one **OCM W-Stack** wallet,
with its own `did:web` identity, in the management plane of its zone. This page is the design:
what runs, how the identity is served, where the keys and the credentials live, what survives a
restart, and how it is proven. The decision is [ADR-0014](adr/0014-ocm-wstack-packaged-by-the-demonstrator.md);
the charts are `deployment/helm/ocm-backbone` and `deployment/helm/ocm-wallet`, each with its README.

## What runs

The W-Stack is a set of Go services from Eclipse XFSC, run here from their published images by
digest (`scripts/tools/pins.env`), without the Argo CD, operator and gateway machinery of its
reference deployment. Per zone, in `ztd-mgmt`:

| Release | Workloads | Role |
|---|---|---|
| `ocm-backbone` (once) | Cassandra 5 (one node, keyspace `ocm`, claim kept across uninstalls), NATS 2 (core) | the stores the wallets share |
| `ocm-wallet` (one per tenant) | **signer** + its OpenBao **engine** (one pod), **storage**, **retrieval**, **edge** | the organisation's wallet |

- The **signer** (`crypto-provider-service`) builds the DID document and the JWKS from the keys of
  one OpenBao transit engine, signs and verifies credentials and presentations, and answers the
  lane's signing requests on NATS. Its **engine** (`crypto-provider-hashicorp-vault-plugin`) is
  the only container that holds the OpenBao token.
- The **storage** service keeps the organisation's credentials in Cassandra (tables it migrates
  itself into the backbone's keyspace), takes store requests from the wallet's NATS subject, and
  encrypts them per account with keys it keeps in an engine of its own beside the tenant's
  (`ocm/<tenant>-storage`), so the DID document, which lists every key of the tenant's engine,
  never shows them.
- The **retrieval** service is OID4VCI on the holder's side: given a credential offer it fetches
  the issuer's metadata, obtains the token, has the holder proof signed by the signer, asks the
  signer to verify what it receives, and stores it.
- The **edge** (nginx) terminates TLS for the organisation's host name and serves the two
  well-known documents from the signer with the identity headers the W-Stack's gateway would set.

## Identity: one engine, one DID

The organisation's DID is `did:web:<tenant.host>`, resolved at
`https://<tenant.host>/.well-known/did.json`. The signer lists every key of the transit engine
named in the request as a verification method, so **one engine is one identity**: each wallet has
its own engine (`ocm/<tenant>`), created by the zone's OpenBao bootstrap for the wallet's service
token ([Secrets, service tokens](secrets.md#service-tokens)), and one key in it (`wallet-<tenant>`,
P-256, never exportable), created by the chart's key Job as the install's last step. The document's
`verificationMethod[0].publicKeyJwk` is that key; the proof checks its RFC 7638 thumbprint against
the public key read from transit. The document carries no `service` section: the W-Stack fills it
from a TSA policy the demonstrator does not run.

| Tenant | DID (kind proof) | DID (zone, interim) | Engine, key |
|---|---|---|---|
| organisation A (zone A) | `did:web:wallet-a.ztd.test` | `did:web:wallet.<zone A trust domain>` | `ocm/zone-a`, `wallet-zone-a` (data keys in `ocm/zone-a-storage`) |
| organisation B (zone B) | `did:web:wallet-b.ztd.test` | `did:web:wallet.<zone B trust domain>` | `ocm/zone-b`, `wallet-zone-b` (data keys in `ocm/zone-b-storage`) |

The zone hosts are interim until the delegated DNS zone exists; renaming a host is a values change
and a new certificate, the key and the credentials stay. The connector's `did:web` names in the
TRAIN payloads and the admission trust anchor are separate identities and are not touched here.

## Keys and credentials: what survives what

| Event | Keys and DID | Credentials |
|---|---|---|
| wallet pods restart, `helm upgrade` | unchanged (OpenBao) | unchanged (Cassandra) |
| Cassandra pod restarts | unchanged | unchanged (the claim) |
| OpenBao pod restarts | sealed: the document answers **without any key** and the signer cannot sign, until `scripts/secrets/unseal.sh` runs; then unchanged | unchanged |
| `helm uninstall` of wallet and backbone, reinstall from the same values | unchanged (the engine and the key stay in OpenBao) | unchanged (the backbone keeps its claim) |
| `helm uninstall ztd` (zone teardown) | gone with the namespace: a new install is a new key under the same DID | gone with the claim |

Nothing in the lane is created by hand: the engines and tokens come from the zone file's
`openbaoBootstrap.serviceTokens`, the keyspace from the backbone's hook, the key from the wallet's
hook, the tables from the services' migrations.

## Messaging and isolation

The wallets share the zone's NATS and Cassandra. Each wallet's subjects are prefixed with its
tenant (`<tenant>.offering`, `<tenant>.storage`, `<tenant>.signer`), and the W-Stack keeps the
tenant in every Cassandra row key. The chart's NetworkPolicies open, per pod, only what the lane
needs (signer to OpenBao and NATS; storage and retrieval to Cassandra, NATS and the signer; the
edge to the signer and to the world on its TLS port; the retrieval service to the issuers it
fetches from); under the zone's mesh every workload is STRICT except the edge's TLS port. A
wallet's token signs with its own key and is refused the KV store, the shared engine, the other
wallet's key, key export and the per-key configuration. Two qualifications: inside the
management plane the umbrella's intra-plane lane (on by default) admits every pod of the namespace
to every port, so the charts' policies narrow traffic only from outside the namespace and in a zone
that turns that lane off (the proof shows a data-plane pod refused, not a management-plane one);
and Cassandra runs without authentication inside the plane. Both are documented gaps. The W-Stack's
`did-configuration.json` is a signing request with a body, not a document the edge can serve; the
edge exposes `did.json` and `jwks.json`. On a real zone one wallet runs per cluster.

## Installing on a zone

1. In the zone file: a `serviceTokens` entry per wallet (`name`, `transitMount`), the plane's
   storage class, and the wallet's host. On a zone that is already bootstrapped, the recovery in
   [Secrets](secrets.md#service-tokens) issues the new token once.
2. `helm upgrade --install ztd …` (the bootstrap issues the tokens), then `ocm-backbone`, then one
   `ocm-wallet` per tenant, as in [Deployment](deployment.md#components-after-the-umbrella).
3. The zone supplies the wallet's TLS certificate as a `kubernetes.io/tls` Secret and the public
   DNS record of `tenant.host` to the edge's LoadBalancer address; until a certificate issuer
   exists, the zone's own CA, distributed to the peers that resolve the DID (the retrieval
   service's `trustedCAConfigMap`).

## Proving it

`scripts/verify-ocm-wallet/verify.sh` runs the lane on a throwaway kind cluster laid out like a
zone (Cilium, the umbrella with OpenBao and two service tokens, the backbone, two wallets) and
checks the token boundaries, both documents (id, one key, thumbprint against transit, JWKS, 404
elsewhere), the in-cluster resolution of one wallet's DID by a management-plane pod, a data-plane
pod refused by the stores, a
credential stored through the storage subject, the restarts (every pod, Cassandra, OpenBao sealed
and unsealed) and the reinstall from the same values, then the chart gate. The CI workflow
`OCM wallet lane` runs it on every change to the lane and publishes the records (`cases.md`,
`verdict.txt`, the documents, `environment.json`) as the artifact `ocm-wallet-lane`; the proof's
README under `scripts/verify-ocm-wallet/` lists what it stands in for.

## Open points

- **Issuer.** The issuer side of the W-Stack (issuance service, well-known service,
  pre-authorization bridge, a content signer, PostgreSQL, Redis) is the next slice; until it
  lands the proof publishes a fixture credential on the storage subject. Which organisation
  issues in the demonstration, and the credential profile, are to be aligned with the client
  (ZT-46).
- **Revocation.** The W-Stack's status-list service (Token Status List) is not deployed; ZT-51
  stays pending.
- **Images.** Pulled from the client's Harbor by digest, unsigned; the management plane is not
  under admission today. When it is, mirror and sign them into the project's registry.
- **Names and certificates** are interim until the delegated DNS zone and a certificate issuer
  exist; the OSC install of the lane follows the issuer slice.
