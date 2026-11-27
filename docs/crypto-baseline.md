# Cryptographic baseline

ZT-50 requires every algorithm and key length in the demonstrator to follow BSI TR-02102, and
states the strengths it accepts: AES-256 or equivalent for symmetric encryption, RSA-4096 or ECC
P-256/P-384 for asymmetric keys, SHA-256 or stronger for hashes, TLS as in TR-02102-2, and no
MD5, SHA-1 or RSA below 2048 bits anywhere. The strengths are the requirement's own, which are
stricter than the guideline for RSA (TR-02102-1 accepts 3000 bits).

This page is the register of what the repository sets. `scripts/check-crypto-baseline.sh` reads it
and fails when a row names a mechanism outside the list below, when the file a row names no longer
holds the text the row quotes, or when one of the patterns it scans for (below) appears in the Go
code or the deployment configuration. That is all it proves: it cannot tell that a row is missing,
that a quoted setting is in effect, or what an upstream chart or image defaults to. It does not
inspect a running zone. `scripts/verify-crypto-baseline/verify.sh` inspects some of the keys and
certificates the configuration generates, and Annex row ZT-50 stays open until an inspection runs
against a deployed zone.

The scan fails on: an import of `crypto/md5`, `crypto/sha1`, `crypto/des`, `crypto/rc4`,
`crypto/dsa` or `crypto/rsa` in the Go code (the code uses ECDSA only); a Sprig certificate helper
that takes no key in a chart (it makes an RSA-2048 key); and, in the YAML, JSON and template files
of the deployment configuration, `rsa-1024`, `rsa-2048` or `rsa-3072`, a `keySize`, `key_size` or
`key_bits` followed on the same line by a number from 100 to 4095, `RSA-OAEP` (it hashes with
SHA-1; `RSA-OAEP-256` does not), `RSA1_5` (PKCS #1 v1.5 encryption, which TR-02102-1 no longer
recommends), and MD5 or SHA-1 by name. A comment that names one of these fails it too; a size
written any other way, or on the line after its key, is not seen.

## Accepted mechanisms

| Use | Accepted |
|---|---|
| signature | `ECDSA P-256`, `ECDSA P-384`, `RSA-4096` |
| key transport | `RSA-4096` |
| encryption | `AES-256` |
| hash or MAC | `SHA-256`, `SHA-384`, `SHA-512`, `HMAC-SHA-256`, `HMAC-SHA-512`, `HMAC-SHA-512/256` |
| transport | `TLS 1.3` |

## Register

Each row is one place a key is generated or an algorithm is chosen. `Set in` is the file that
decides it and `Setting` is the text in that file that does.

| Component | Purpose | Use | Mechanism | Set in | Setting |
|---|---|---|---|---|---|
| SPIRE server | X.509 CA of the workload identities, JWT signing keys | signature | `ECDSA P-256` | `deployment/helm/values/spire.yaml` | `caKeyType: ec-p256` |
| Service mesh | mutual TLS between workloads | transport | `TLS 1.3` | `deployment/helm/values/istiod.yaml` | `minProtocolVersion: TLSV1_3` |
| Connector | access tokens (JWS) | signature | `ECDSA P-256` | `internal/jose/jose.go` | `const AlgES256 = "ES256"` |
| Connector, Token store | signing and DPoP keys held in OpenBao transit | signature | `ECDSA P-256` | `internal/transit/http.go` | `const keyType = "ecdsa-p256"` |
| Connector | opaque access tokens and registration tokens (secret of 32 bytes or more; the hash is the OAuth2 library's) | hash or MAC | `HMAC-SHA-512/256` | `services/connector/serve.go` | `const minSecret = 32` |
| Guard, Protected Resource | token and DPoP proof verification | signature | `ECDSA P-256` | `internal/tokenverify/keyset.go` | `alg != jose.AlgES256` |
| Participant, Connector registrar | DPoP proof key | signature | `ECDSA P-256` | `internal/dpopproof/processkey.go` | `ecdsa.GenerateKey(elliptic.P256(), rand.Reader)` |
| Admission provider | cosign image signatures it accepts | signature | `ECDSA P-256` | `internal/cosignverify/cosignverify.go` | `key.Curve != elliptic.P256()` |
| Admission provider | its CA and server certificate | signature | `ECDSA P-256` | `deployment/helm/admission/templates/tls.yaml` | `genSignedCertWithKey (index $dns 2) nil $dns (int .Values.tls.validityDays) $genCA (genPrivateKey "ecdsa")` |
| Public ingress (Traefik) | the hosts the controller terminates through a router that names no TLSOption of its own, once the manifest is applied to the cluster as its only `default` TLSOption | transport | `TLS 1.3` | `deployment/ingress/traefik-tls-options.yaml` | `minVersion: VersionTLS13` |
| Admission provider | its HTTPS listener | transport | `TLS 1.3` | `services/admission-provider/provider.go` | `MinVersion:   tls.VersionTLS13` |
| OpenBao | transit key of the secrets baseline proof | encryption | `AES-256` | `deployment/helm/ztd/templates/_openbao.tpl` | `{"type":"aes256-gcm96"}` |
| Keycloak, realm `facis-ztd` | token signatures (RS256) | signature | `RSA-4096` | `deployment/helm/facis-ztd-keycloak/files/realm.json` | `"providerId": "rsa-generated", "subComponents": {}, "config": {"priority": ["100"], "keySize": ["4096"]` |
| Keycloak, realm `facis-ztd` | token encryption key transport (RSA-OAEP-256) | key transport | `RSA-4096` | `deployment/helm/facis-ztd-keycloak/files/realm.json` | `"providerId": "rsa-enc-generated", "subComponents": {}, "config": {"priority": ["100"], "keySize": ["4096"], "algorithm": ["RSA-OAEP-256"]` |
| Keycloak, realm `facis-ztd` | symmetric key (32 bytes) | encryption | `AES-256` | `deployment/helm/facis-ztd-keycloak/files/realm.json` | `"providerId": "aes-generated", "subComponents": {}, "config": {"priority": ["100"], "secretSize": ["32"]` |
| Keycloak, realm `facis-ztd` | access tokens of the runner's login client `ztd-access` (ES256) | signature | `ECDSA P-256` | `deployment/helm/facis-ztd-keycloak/files/realm.json` | `"providerId": "ecdsa-generated", "subComponents": {}, "config": {"priority": ["90"], "ecdsaEllipticCurveKey": ["P-256"]}` |
| Privileged-operations runner | its listener, and its connections to Keycloak | transport | `TLS 1.3` | `cmd/access-runner/main.go` | `TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}` |
| Privileged-operations runner | approvals of privileged operations (grants) | signature | `ECDSA P-256` | `services/accessrunner/grant.go` | `jose.Verify(compact, jose.HeaderPolicy{Typ: GrantType, KidNeeded: true}` |
| Keycloak, realm `facis-ztd` | internal token MAC (HS512, 128-byte secret) | hash or MAC | `HMAC-SHA-512` | `deployment/helm/facis-ztd-keycloak/files/realm.json` | `"algorithm": ["HS512"], "secretSize": ["128"]` |

Keycloak signs with RS256 by default, and not with an elliptic-curve key, because the demonstrator
UI's ORCE flow accepts RS256 tokens only (`flows/demonstrator/identity-on-start.js`). Only the runner's
login client `ztd-access` has its access tokens signed ES256, by the lower-priority P-256 provider.

## What changes on an existing installation

- **Keycloak.** Applying the realm regenerates the two RSA keys of the realm at 4096 bits, and the
  encryption key moves from RSA-OAEP to RSA-OAEP-256. Tokens and sessions issued under the old
  signing key stop verifying once it is gone. The AES and HMAC secrets already have these sizes in
  Keycloak 26.7 and are kept. Only the five providers named here are managed: a key provider added
  by hand under another name is left alone, one added under one of these names is overwritten,
  and one with a higher priority still decides the signing key. The master
  realm is not configured by this chart.
- **Admission provider.** Only a new installation gets the ECDSA certificates. An existing TLS
  Secret is reused as it is, with its RSA-2048 keys, until it is replaced as the chart's README
  describes.
- **SPIRE.** The server keeps the CA it has, and a successor it has already prepared, until they
  rotate out; only a key prepared after the change has the new type. A fresh install starts with it.
- **OpenBao.** The key type is stated when the bootstrap creates the key. A key that already
  exists is not converted or checked.

## Not covered by a baseline mechanism

| Component | What | Why it is listed |
|---|---|---|
| Connector | client secrets are stored as bcrypt hashes (`services/connector/server.go`) | a password hash, which the three strength classes of ZT-50 do not name; TR-02102-1 recommends Argon2id for password hashing |
| Service mesh, ingress, admission provider | TLS 1.3 negotiates `TLS_AES_128_GCM_SHA256` as well as the AES-256 suite | TR-02102-2 accepts the suite; ZT-50's "AES-256 or equivalent" is stricter. No chart restricts the TLS 1.3 suites, and Go does not let a server choose them |

## Not set in this repository

These have cryptography that the register does not pin. They are inspected on the component that
sets them, not here.

| Component | What is not here |
|---|---|
| Public ingress | the certificates of the ORCE and Keycloak hosts come from the cluster's ACME issuer or from a TLS Secret supplied to the chart; their key type is decided there. A TLS handshake with each of the two IONOS hosts on 18 Nov 2026 returned an RSA-2048 certificate; nothing in the repository records or repeats that measurement |
| istiod | its own serving certificate and CA, generated by Istio |
| Gatekeeper | the CA of its webhook and of the client certificate it presents to the admission provider, generated by Gatekeeper |
| Keycloak import job | the encryption of the import tool's remote state (`IMPORT_REMOTESTATE_ENCRYPTIONKEY`), the tool's own |
| ORCE | the bcrypt hashes of its administrator and HTTP passwords, supplied through the environment |
| TRAIN | the DNSSEC keys of the zone manager (ECDSAP256SHA256 in `docs/train-dns.md`) belong to its chart, which is not in this repository yet |
| Attested channel | its key material and cipher suites arrive with the channel |
