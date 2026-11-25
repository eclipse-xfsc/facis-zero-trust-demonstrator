# Trust-list VC from our TSPA image: local evidence

| | |
|---|---|
| Run | 2026-11-21, Docker on the project lead's workstation; no zone touched |
| Commit | `8238a3a2d21baffa6b32e0b5e02eda0cd8c44c4a` |
| TSPA image | built from `deployment/docker/tspa` (upstream `ecd5fdc` + patches 0001–0003), local image id `sha256:2210953f1ee29097cea136df589ebf8233d24427e82d9f8422b337b7cf2bf0ba` |
| Keycloak | upstream's test realm `gxfs-dev-test` at `ecd5fdc`, `quay.io/keycloak/keycloak:26.0.8` by digest |
| Command | `OPENSSL=<OpenSSL 3> scripts/verify-tspa-vc/run.sh` |

**Trust lists published before this change, by the upstream TSPA image (zone B's `ztd-train`
included), were signed with the Ed25519 key published in upstream's source and must not be
trusted.**

## Run

```
PASS  enrolltf token from the test realm
PASS  trust list created
PASS  entry published
PASS  VC validity window 2026-11-21T22:18:52+01:00 .. 2026-12-21T22:18:52+01:00 (P30D)
PASS  VC signed JsonWebSignature2020 by did:web:tspa.local.test#trust-list-1
PASS  the private key is in no stored file, no Tomcat log and not on stdout
PASS  entry replaced (PATCH 200)
PASS  re-publication renews the window (2026-11-21T22:19:30+01:00 .. 2026-12-21T22:19:30+01:00)
verdict: PASS
```

The signing key was generated for the run into a temporary file (mode 600) mounted read-only into
the container, and removed with the run; only its public half is kept, in the DID document.

## The VC the run produced (proof shortened)

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    {
      "trustlisttype": "https://tspa.facis.cloud/ns/trustlist#trustlisttype",
      "trustlistURI": {
        "@id": "https://tspa.facis.cloud/ns/trustlist#trustlistURI",
        "@type": "@id"
      },
      "hash": "https://tspa.facis.cloud/ns/trustlist#hash"
    }
  ],
  "type": [
    "VerifiableCredential"
  ],
  "id": "did:web:tspa.local.test#issuer-lists",
  "issuer": "did:web:tspa.local.test",
  "issuanceDate": "2026-11-21T22:19:30+01:00",
  "expirationDate": "2026-12-21T22:19:30+01:00",
  "credentialSubject": {
    "id": "uuid:2632367287r82729",
    "trustlisttype": "JSON based Trust-lists",
    "trustlistURI": "http://tspa:16003/tspa-service/tspa/v1/facis-ztd.local/trust-list",
    "hash": "QmU6U1bDzJAhxtyCgLd1Y57KRosGrrT2jnT4mRX6iGsio2"
  },
  "proof": {
    "type": "JsonWebSignature2020",
    "created": "2026-11-21T22:19:30Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:web:tspa.local.test#trust-list-1",
    "jws": "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJh…"
  }
}
```

## Checked by the verification service

The VC, the list and the DID document of the run are the fixtures in
`services/verification-service/testdata/tspa/`; `TestAVCSignedByOurTSPAVerifies` accepts the VC inside
its window and refuses it after `expirationDate` and with a subject term changed. Live: not yet run;
it needs our image deployed on zone B and `did:web:tspa.facis.cloud` served.
