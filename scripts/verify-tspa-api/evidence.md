# TSPA local round-trip evidence (2026-09-18T10:03:27-01:00)
## 0. Health

### health

- Request: `GET http://localhost:16003/tspa-service/actuator/health`  (auth: noauth, body: -)
- HTTP status: **503**
- Response (first 800 bytes):

```
{"status":"DOWN","components":{"diskSpace":{"status":"UP","details":{"total":501809635328,"free":134919405568,"threshold":10485760,"path":"/usr/local/tomcat/.","exists":true}},"ping":{"status":"UP"},"zonemanagerHealthCheck":{"status":"DOWN","details":{"Status":"Zonemanager is not healthy","Zonemanager-address":"https://testtrain.trust-scheme.de"}}}}
```
## 1. Token (client_credentials on the compose Keycloak, requested from inside the docker network so iss matches)

Decoded access-token claims relevant to TSPA:

```json
{
  "iss": "http://keycloak:8080/realms/gxfs-dev-test",
  "azp": "xfsctest",
  "preferred_username": "service-account-xfsctest",
  "realm_access": {
    "roles": [
      "enrolltf",
      "offline_access",
      "uma_authorization",
      "default-roles-gxfs-dev-test"
    ]
  },
  "exp": 1789729715
}
```
## 1b. Cleanup from previous runs (ignore result)

### 1b DELETE trust-list (cleanup)

- Request: `DELETE http://localhost:16003/tspa-service/tspa/v1/facis-ztd.local/trust-list`  (auth: auth, body: -)
- HTTP status: **200**
- Response (first 800 bytes):

```
{"message":"Trust list not available in local store.","status":200}
```
## 2. Negative tests before anything exists

### 2a PUT tsp without token

- Request: `PUT http://localhost:16003/tspa-service/tspa/v1/facis-ztd.local/trust-list/tsp`  (auth: noauth, body: tsp-v1.json)
- HTTP status: **200**  (expected 401; upstream quirk gives 200+empty body, see 6b)
- Response (first 800 bytes):

```

```

### 2b PUT tsp with token but no trust list yet

- Request: `PUT http://localhost:16003/tspa-service/tspa/v1/facis-ztd.local/trust-list/tsp`  (auth: auth, body: tsp-v1.json)
- HTTP status: **404**  (expected 404)
- Response (first 800 bytes):

```
{"message":"Trustlist for facis-ztd.local not found in local store at path /tmp/train-tspa/store/trust-lists/","status":404}
```
## 3. Trust framework (calls the external Zone Manager; expected to fail offline)

### 3 PUT trustframework

- Request: `PUT http://localhost:16003/tspa-service/tspa/v1/trustframework/facis-ztd.local`  (auth: auth, body: framework.json)
- HTTP status: **500**  (expected 500 offline)
- Response (first 800 bytes):

```
{"timestamp":"2026-09-18T11:03:36.412+00:00","status":500,"error":"Internal Server Error","path":"/tspa-service/tspa/v1/trustframework/facis-ztd.local"}
```
## 4. Trust list init + first measurement

### 4a PUT init json trust-list

- Request: `PUT http://localhost:16003/tspa-service/tspa/v1/init/json/facis-ztd.local/trust-list`  (auth: auth, body: trustlist-init.json)
- HTTP status: **201**  (expected 201)
- Response (first 800 bytes):

```
{"message":"Trust-list initially created and stored in JSON format","status":201}
```

### 4b PUT tsp v1 (TEEM 1111...)

- Request: `PUT http://localhost:16003/tspa-service/tspa/v1/facis-ztd.local/trust-list/tsp`  (auth: auth, body: tsp-v1.json)
- HTTP status: **201**  (expected 201)
- Response (first 800 bytes):

```
{"MapN":{"message":"TSP published for facis-ztd.local.","status":201}}
```

### 4c GET trust-list

- Request: `GET http://localhost:16003/tspa-service/tspa/v1/facis-ztd.local/trust-list`  (auth: noauth, body: -)
- HTTP status: **200**
- Response (first 800 bytes):

```
{
  "TrustServiceStatusList" : {
    "FrameworkInformation" : {
      "TSLVersionIdentifier" : 1,
      "TSLSequenceNumber" : 1,
      "TSLType" : "http://TRAIN/TrstSvc/TrustedList/TSLType/facis-ztd-local",
      "FrameworkOperatorName" : {
        "Name" : "FACIS ZTD (local round-trip)"
      },
      "FrameworkOperatorAddress" : {
        "PostalAddresses" : {
          "PostalAddress" : [ {
            "StreetAddress" : "n/a",
            "Locality" : "Mindelo",
            "PostalCode" : "2110",
            "CountryName" : "CV"
          } ]
        },
        "ElectronicAddress" : {
          "URI" : "mailto:platform@facis-ztd.local"
        }
      },
      "FrameworkName" : {
        "Name" : "facis-ztd.local"
      },
      "FrameworkInformationURI" : {
        "URI" : "https://fac
```
- Check: measurement 1111... present in trust list: **yes**
- Check: read-back entry has ServiceTypeIdentifier = did:web:connector-b.facis-ztd.local (TCR lookup key): **yes**
## 5. Idempotency

### 5a PUT tsp v1 again (same UUID)

- Request: `PUT http://localhost:16003/tspa-service/tspa/v1/facis-ztd.local/trust-list/tsp`  (auth: auth, body: tsp-v1.json)
- HTTP status: **400**  (expected error)
- Response (first 800 bytes):

```
{"MapN":{"error":"TSP can't publish : TSP with UUID 7d3c1e2a-5b6f-4c8d-9e0f-facis0000zt35 already exists.","status":400}}
```

### 5b PATCH tsp -> v2 (TEEM 2222...)

- Request: `PATCH http://localhost:16003/tspa-service/tspa/v1/facis-ztd.local/trust-list/tsp/7d3c1e2a-5b6f-4c8d-9e0f-facis0000zt35`  (auth: auth, body: tsp-v2.json)
- HTTP status: **200**  (expected 200)
- Response (first 800 bytes):

```
{"MapN":{"message":"TSP update for facis-ztd.local with UUID :7d3c1e2a-5b6f-4c8d-9e0f-facis0000zt35","status":200}}
```

### 5c GET trust-list after PATCH

- Request: `GET http://localhost:16003/tspa-service/tspa/v1/facis-ztd.local/trust-list`  (auth: noauth, body: -)
- HTTP status: **200**
- Response (first 800 bytes):

```
{
  "TrustServiceStatusList" : {
    "FrameworkInformation" : {
      "TSLVersionIdentifier" : 1,
      "TSLSequenceNumber" : 1,
      "TSLType" : "http://TRAIN/TrstSvc/TrustedList/TSLType/facis-ztd-local",
      "FrameworkOperatorName" : {
        "Name" : "FACIS ZTD (local round-trip)"
      },
      "FrameworkOperatorAddress" : {
        "PostalAddresses" : {
          "PostalAddress" : [ {
            "StreetAddress" : "n/a",
            "Locality" : "Mindelo",
            "PostalCode" : "2110",
            "CountryName" : "CV"
          } ]
        },
        "ElectronicAddress" : {
          "URI" : "mailto:platform@facis-ztd.local"
        }
      },
      "FrameworkName" : {
        "Name" : "facis-ztd.local"
      },
      "FrameworkInformationURI" : {
        "URI" : "https://fac
```
- Check: 2222... present: **yes**
- Check: 1111... gone: **yes**
- Check: ServiceTypeIdentifier still = connector DID after PATCH: **yes**

### 5d PATCH with UUID mismatch (url uuid != body uuid)

- Request: `PATCH http://localhost:16003/tspa-service/tspa/v1/facis-ztd.local/trust-list/tsp/00000000-0000-0000-0000-000000000000`  (auth: auth, body: tsp-v2.json)
- HTTP status: **400**  (expected error)
- Response (first 800 bytes):

```
{"error":"TSP update failed, UUID should be 00000000-0000-0000-0000-000000000000 in updated TSP","status":400}
```
## 6. Signed VC (what the TCR would consume)

### 6 GET vc trust-list

- Request: `GET http://localhost:16003/tspa-service/tspa/v1/facis-ztd.local/vc/trust-list`  (auth: noauth, body: -)
- HTTP status: **200**
- Response (first 800 bytes):

```
{
  "@context" : [ "https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/ed25519-2020/v1", "https://w3id.org/security/suites/jws-2020/v1" ],
  "type" : [ "VerifiableCredential" ],
  "id" : "did:web:essif.iao.fraunhofer.de#issuer-lists",
  "issuer" : "did:web:essif.iao.fraunhofer.de",
  "issuanceDate" : "2026-09-18T13:03:36+02:00",
  "expirationDate" : "2025-06-15T18:56:59Z",
  "credentialSubject" : {
    "id" : "uuid:2632367287r82729",
    "trustlisttype" : "JSON based Trust-lists",
    "trustlistURI" : "http://localhost:16003/tspa-service/tspa/v1/facis-ztd.local/trust-list",
    "hash" : "QmW9LdN8aDNypfZoUbVpYy71ib3Cgaqhyfa7HEKRrZb9KG"
  },
  "proof" : {
    "type" : "JsonWebSignature2020",
    "created" : "2026-09-18T12:03:36Z",
    "proofPurpose" : "assertionMethod
```

VC summary:

```json
{
  "issuer": "did:web:essif.iao.fraunhofer.de",
  "type": [
    "VerifiableCredential"
  ],
  "proof.type": "JsonWebSignature2020",
  "proof.verificationMethod": "did:web:essif.iao.fraunhofer.de#test",
  "credentialSubject.keys": [
    "id",
    "trustlisttype",
    "trustlistURI",
    "hash"
  ]
}
```
## 6b. Auth matrix on the write endpoint (list must stay unchanged)

### 6b-1 PUT tsp with a malformed bearer token (Authorization: Bearer not.a.jwt)

- Request: `PUT http://localhost:16003/tspa-service/tspa/v1/facis-ztd.local/trust-list/tsp`  (auth: auth, body: tsp-v1.json)
- HTTP status: **401**  (expected 401)
- Response (first 800 bytes):

```
{"error":"An error occurred while attempting to decode the Jwt: Malformed token","status":401}
```

### 6b-2 PUT tsp with a VALID token whose realm roles lack enrolltf (testuser: enrolltf only as client role)

- Request: `PUT http://localhost:16003/tspa-service/tspa/v1/facis-ztd.local/trust-list/tsp`  (auth: auth, body: tsp-v1.json)
- HTTP status: **403**  (expected 403)
- Response (first 800 bytes):

```

```
- testuser token claims: `realm_access.roles` = ['offline_access', 'uma_authorization', 'default-roles-gxfs-dev-test'] ; `resource_access.xfsctest.roles` = ['enrolltf']
- Check: TSP entries with our UUID before/after the three rejected writes: **1 / 1**
## 7. Delete path (auth + cleanup)

### 7a DELETE tsp without token

- Request: `DELETE http://localhost:16003/tspa-service/tspa/v1/facis-ztd.local/trust-list/tsp/7d3c1e2a-5b6f-4c8d-9e0f-facis0000zt35`  (auth: noauth, body: -)
- HTTP status: **200**  (expected 401; upstream quirk gives 200+empty body)
- Response (first 800 bytes):

```

```

### 7b DELETE tsp with token

- Request: `DELETE http://localhost:16003/tspa-service/tspa/v1/facis-ztd.local/trust-list/tsp/7d3c1e2a-5b6f-4c8d-9e0f-facis0000zt35`  (auth: auth, body: -)
- HTTP status: **200**  (expected 200)
- Response (first 800 bytes):

```
{"MapN":{"message":"TSP removed from facis-ztd.local for UUID: 7d3c1e2a-5b6f-4c8d-9e0f-facis0000zt35","status":200}}
```

### 7c GET trust-list after delete

- Request: `GET http://localhost:16003/tspa-service/tspa/v1/facis-ztd.local/trust-list`  (auth: noauth, body: -)
- HTTP status: **200**
- Response (first 800 bytes):

```
{
  "TrustServiceStatusList" : {
    "FrameworkInformation" : {
      "TSLVersionIdentifier" : 1,
      "TSLSequenceNumber" : 1,
      "TSLType" : "http://TRAIN/TrstSvc/TrustedList/TSLType/facis-ztd-local",
      "FrameworkOperatorName" : {
        "Name" : "FACIS ZTD (local round-trip)"
      },
      "FrameworkOperatorAddress" : {
        "PostalAddresses" : {
          "PostalAddress" : [ {
            "StreetAddress" : "n/a",
            "Locality" : "Mindelo",
            "PostalCode" : "2110",
            "CountryName" : "CV"
          } ]
        },
        "ElectronicAddress" : {
          "URI" : "mailto:platform@facis-ztd.local"
        }
      },
      "FrameworkName" : {
        "Name" : "facis-ztd.local"
      },
      "FrameworkInformationURI" : {
        "URI" : "https://fac
```
- Check: TSP removed: **yes**
