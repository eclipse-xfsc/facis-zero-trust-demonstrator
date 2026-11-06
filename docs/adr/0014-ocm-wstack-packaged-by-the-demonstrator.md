# ADR-0014: OCM W-Stack packaged by the demonstrator, one did:web wallet per zone

- **Status:** Accepted for the wallet lane (charts, proof, placement). Open: the client's answer on the
  provided-stack assumption and on the issuer (ZT-46), and the issuer slice itself (see Consequences).
- **Date:** 2026-11-02
- **Deciders:** Delivery team, from the wallet-lane planning of 2026-11-02 (the inventory of the
  four clusters and of the XFSC sources on that day)
- **Requirement basis:** SRS § 2.3.3 (OCM W-Stack SHALL be used for CrBAC, credential issuing and
  credential verification), ZT-40, ZT-46, ZT-55, ZT-53; ZT-11 for the key custody
- **Related:** [ADR-0003](0003-oauth2-authorisation-surface-in-the-go-connector.md) (the connector
  consumes presentations; it does not hold credentials), [ADR-0004](0004-openbao-as-x509-key-value-store.md)
  (OpenBao holds the keys), [ADR-0005](0005-three-cluster-reading-of-the-target-environment.md)
  (the XFSC stack is a zone exit criterion)

## Context

The SRS names the OCM W-Stack as the organisational wallet: the place where an organisation keeps
the verifiable credentials it presents to another organisation's connector (ZT-40) and receives
them from an issuer (ZT-46). The project's assumptions had the W-Stack provided by the client. On
2026-11-02 nothing of it existed on any of the four clusters the project can reach, and the repo
held only the fixtures that stand in for it. The acceptance rows that need a wallet (ZT-40, ZT-46,
ZT-51) cannot move without one.

Two OCM lineages exist under Eclipse XFSC. The older, Aries-based OCM (DIDComm connections, a
ledger-anchored DID, a wallet "agent") has had no code change since May 2025 and no release. The
OCM W-Stack is maintained (releases in October and November 2026), is what the SRS names, and
works differently: Go services configured by environment variables, a `did:web` per tenant whose
document the signer builds from the keys of a transit engine, no connections (an issuer hands the
holder an OID4VCI credential offer), state in Cassandra, messaging over NATS, keys in OpenBao
transit. Its images are published, unsigned and tag-pinned, on the XFSC Harbor, which is the same
host as the registry the client provided to the project. Its reference deployment is an Argo CD
application set with a Kubernetes operator that injects backend credentials, Envoy Gateway,
cert-manager and ExternalDNS, none of which the zones run.

## Decision

1. **The demonstrator packages the W-Stack itself**, as first-party Helm charts that run the
   published XFSC images by digest: `ocm-backbone` (Cassandra and NATS, once per zone) and
   `ocm-wallet` (signer with its OpenBao engine, credential storage, credential retrieval, and an
   edge). No Argo CD, no XFSC operator, no Gateway API: the services take their backends from
   environment variables the chart sets. The client-provided stack remains the stated assumption;
   if one appears, the tenant layer points at it.
2. **One wallet per zone, one release per tenant, in the management plane** (ZT-55), next to the
   zone's OpenBao, on the zone's stores. Two tenants on one backbone are isolated by the row keys
   the W-Stack writes and by per-tenant NATS subjects; on a real zone one tenant runs per cluster.
   Separate namespaces per tenant (ZT-53's stricter reading) stay available through the umbrella's
   extra plane namespaces and are not built now.
3. **`did:web` per tenant, served by the signer behind a first-party edge.** The DID is
   `did:web:<tenant.host>`; the document is what the signer builds from the tenant's transit
   engine, so an engine is one identity and is never shared; the storage service's per-account
   encryption keys live in a second engine beside it (engines cannot nest), out of the document. The edge (nginx) terminates TLS and
   sets the identity headers the W-Stack's gateway would set; it serves the DID document and the
   JWKS and nothing else. The document carries no `service` section: the W-Stack fills it
   from a TSA policy the demonstrator does not run, and the W-Stack's `did-configuration.json` is a
   signing request with a body rather than a servable document, so it is not exposed.
4. **Keys in the zone's OpenBao, under service tokens the umbrella's bootstrap issues.** Each
   wallet gets its own transit engines (identity and storage), a policy limited to them (keys,
   signing, verification, encryption on the storage one; export denied, and the identity key's
   configuration too) and a periodic orphan token in its own Secret, issued
   while the root token still exists (`openbaoBootstrap.serviceTokens`). Kubernetes auth stays
   deferred, as the secrets design records.
5. **Interim names until the delegated DNS zone exists.** The kind proof uses `*.ztd.test` with a
   test CA and a CoreDNS rewrite; a zone names its host from its trust domain and supplies the
   certificate. Renaming a host is a values change and a new certificate; the key and the
   credentials stay.

## Consequences

- The three done-when criteria of the wallet work read, for the W-Stack: the tenant's document
  resolves by its host name over TLS and lists exactly its key, whose thumbprint matches the
  transit key; an issued credential survives every pod, the Cassandra pod and OpenBao restarting
  and an uninstall and reinstall from the same values; the install is Helm with values files only.
- An OpenBao restart seals the store and the wallet answers without keys until the documented
  manual unseal; that is the zone's existing rule, now with one more consumer.
- Inside the management plane the umbrella's intra-plane lane (on by default) admits every pod of
  the namespace to every port; the charts' policies therefore bind for traffic from outside the
  namespace and in a zone that turns that lane off. Cassandra runs without authentication. Both
  are stated in the chart READMEs and the docs page.
- The images are pulled from the client's Harbor by digest and are not signed. The admission
  allow-list (first-party repository, cosign) does not cover them; the management plane is not
  under admission today. When it is, the images are mirrored and signed into the project's
  registry, a values change.
- The wallet's issuer side (issuance service, well-known service, pre-authorization bridge, a
  content signer, PostgreSQL and Redis) is a second slice; until it lands the proof stores a
  fixture credential through the storage subject.

## Triggers to revisit

- The client provides a W-Stack: the tenant layer is pointed at it and the backbone is dropped.
- Admission reaches the management plane: mirror and sign the images.
- Kubernetes auth is adopted for OpenBao: the service tokens become roles.
- The delegated DNS zone and a certificate issuer exist: the hosts move off the interim names and
  the test-CA seam closes.
