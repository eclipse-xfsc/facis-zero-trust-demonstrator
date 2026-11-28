# TRAIN publication proof against the real TSPA (2026-11-13T12:47:47Z)

Written by `scripts/verify-train-publish/verify.sh`: upstream's TSPA built from its Dockerfile and installed with its chart and test realm on the kind cluster of `scripts/verify-tspa-api/kind-up.sh`, reached through port-forwards from the host, the publisher `scripts/train-publish/publish.sh` run around the rollouts of a stand-in component. Checks: **107**, failed: **0**.

| | |
|---|---|
| date | `2026-11-13T12:47:47Z` |
| repository | `4c48b9f17535ac0a7553670e56620953409aee55` |
| tspa_commit | `ecd5fdc` |
| train_shared_commit | `6a0abe4` |
| cmc_commit | `6754d3c8992133830a3fb0e4c56c860c28e38c1e` |
| kind | `kind v0.33.0 go1.26.7 linux/amd64` |
| node_image | `kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95` |
| keycloak_image | `quay.io/keycloak/keycloak:26.0` |
| tspa_image_id | `sha256:3ce8bfa8978d6b8a8da5b0b12a3a42bb4c4401b524a8c7caa5e691017c319820` |
| stand_in_image | `docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b` |
| go | `go version go1.27.0 linux/amd64` |
| kubectl | `v1.35.6` |
| helm | `v4.3.0+gbec5b06` |

## Summary of the matrix

| row | day | expected outcome | exit | rollout | observed outcome | exit | rollout | publish took | result |
|---|---|---|---|---|---|---|---|---|---|
| first-publication | normal day | `published` | 0 | converged | `published` | 0 | converged | 1s | PASS |
| wrong-secret | day 2 | `token-failed` | 1 | not-started | `token-failed` | 1 | not-started | 0s | PASS |
| token-without-role | day 2 | `write-rejected` | 1 | not-started | `write-rejected` | 1 | not-started | 1s | PASS |
| malformed-token | day 2 | `write-rejected` | 1 | not-started | `write-rejected` | 1 | not-started | 0s | PASS |
| lane-closed-refused | day 5 | `transport-failure` | 1 | not-started | `transport-failure` | 1 | not-started | 1s | PASS |
| lane-closed-blackhole | day 5 | `transport-failure` | 1 | not-started | `transport-failure` | 1 | not-started | 5s | PASS |
| new-version | normal day, days 3 and 4 | `published` | 0 | converged | `published` | 0 | converged | 0s | PASS |
| republish-same | day 3 | `published` | 0 | converged | `published` | 0 | converged | 0s | PASS |

## 1. The TSPA, Keycloak and the lanes to them

- PASS: Keycloak reached through the port-forward issues tokens under the in-cluster name the TSPA validates
  issuer: `http://keycloak:8080/realms/gxfs-dev-test`; the TSPA's `issuer-uri` is `http://keycloak:8080/realms/gxfs-dev-test` (values-kind.yaml)
- PASS: the TSPA answers through the port-forward (GET /api/docs 200)
  `GET /actuator/health` answered 000 after 60s: `no body`
- PASS: the operator's token (service account of xfsctest) carries the realm role enrolltf
  operator token claims: `{"iss": "http://keycloak:8080/realms/gxfs-dev-test", "azp": "xfsctest", "realm_roles": ["enrolltf", "offline_access", "uma_authorization", "default-roles-gxfs-dev-test"]}`
- PASS: testuser's token is valid but its realm roles lack enrolltf
  testuser token claims: `{"iss": "http://keycloak:8080/realms/gxfs-dev-test", "azp": "xfsctest", "realm_roles": ["offline_access", "uma_authorization", "default-roles-gxfs-dev-test"]}`
## 2. The measurement records

Both records were produced by `tools/measurement-determinism/measure-with-cmc.sh` (the attestation component at `6754d3c8992133830a3fb0e4c56c860c28e38c1e`) over the fixture bundle; the second after `APP_MODE=maintenance` became `APP_MODE=serving` in `config.json`. The image is the stand-in's, pinned by digest. The rootfs did not change, so its hash is the same in both; the configuration did, so its hash and the template hash (the TEEM value) differ. The rootfs hash is this machine's (the bundle was not normalised; see tools/measurement-determinism/README.md): what is published is a measurement, which is all the publisher needs.

Record v1 (`records/v1.json`):

```
{
  "component": "connector",
  "zone": "b",
  "serviceTypeIdentifier": "did:web:connector-b.facis-ztd.local",
  "image": "docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b",
  "measurement": {
    "type": "TEEM-sha256",
    "value": "314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582",
    "configSha256": "f1916bc6c252952542fd31775f689d102f23ef3ebf47f8b0d527db868e97c0dc",
    "rootfsSha256": "abc36a3328fe89a0f71a5c25b60e79988e548bda8150cc1eeff643d913699610"
  },
  "source": {
    "commit": "4c48b9f17535ac0a7553670e56620953409aee55",
    "tool": "cmc 6754d3c measure-with-cmc.sh",
    "producedAt": "2026-11-13T12:44:31Z"
  }
}
```

Record v2 (`records/v2.json`):

```
{
  "component": "connector",
  "zone": "b",
  "serviceTypeIdentifier": "did:web:connector-b.facis-ztd.local",
  "image": "docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b",
  "measurement": {
    "type": "TEEM-sha256",
    "value": "210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c",
    "configSha256": "fe0729460cc0a440f44ad9b4732a2ffc60d8c0c0db124ed59215391ff418e7a5",
    "rootfsSha256": "abc36a3328fe89a0f71a5c25b60e79988e548bda8150cc1eeff643d913699610"
  },
  "source": {
    "commit": "4c48b9f17535ac0a7553670e56620953409aee55",
    "tool": "cmc 6754d3c measure-with-cmc.sh",
    "producedAt": "2026-11-13T12:44:31Z"
  }
}
```

- PASS: the two records differ in their TEEM value
- PASS: the two records differ in configSha256
- PASS: the two records share rootfsSha256 (only the configuration changed)
- PASS: the two records name the same image digest
  entry UUID derived from zone `b` and component `connector`: `40888e80-0b00-5523-b9c6-4491d3cf4c55`

## 3. The trust list and the stand-in component

- PASS: the trust list of facis-ztd.local is created once, by the operator (201)
  `PUT /init/json/facis-ztd.local/trust-list` answered 201: `{"status":201,"message":"Trust-list initially created and stored in JSON format"}`
- PASS: no entry for the endpoint before the first publication
Namespace `train-publish-proof`: ConfigMaps `connector-config-v1` and `connector-config-v2` hold the two `config.json` files measured (sha256 `d15d0996698c1ee5f1cf0a43773041efb779871c8eed9d8f991b0618fe82f29a` and `d3905058099fd62619019ca8cc37e0ef1e68448b535a6d0832de1179d626d782`); the Deployment `connector` (`stand-in.yaml`) mounts one of them and runs `docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b`. The rollout from v1 to v2 is the configuration-only change the records describe.


## 4. The rows of matrix.tsv

Each row runs the gate the lifecycle wrapper will run: `publish.sh publish` with the record, then, only when it exits 0, the stand-in's rollout to the record's version and `publish.sh prune` once it has converged. The induction changes the publisher's environment for the publish step alone.

### first-publication — normal day

Induction: none: no entry yet and no pods; the first record (v1). Expected: outcome `published`, exit 0, rollout converged.

- PASS: first-publication: the publisher exits 0
- PASS: first-publication: outcome published
- PASS: first-publication: rollout converged
- PASS: first-publication: the event names the derived UUID
- PASS: first-publication: prune proven (exit 0, outcome pruned)
- PASS: first-publication: exactly one entry for the endpoint, whatever the number of publications
- PASS: first-publication: the entry's ServiceTypeIdentifier is the record's (the TCR's lookup key)
- PASS: first-publication: after prune the TEEM set is the record's value alone
- PASS: first-publication: after prune the image-digest set is the record's digest alone
- PASS: first-publication: the ready pods all run version v1
- PASS: first-publication: every ready pod's imageID is the published digest
  ready pods: `[{"name":"connector-85bdc654c6-nfwkw","uid":"e174a3b7-7ff4-441f-a1b1-394e7a3a110e","version":"v1","imageID":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","created":"2026-11-13T12:44:36Z"}]`
- PASS: first-publication: the config.json in the running pod is the one measured for the record (sha256)
- PASS: first-publication: the trust list carried the value before the first pod of this version existed
  published at `2026-11-13T12:44:36Z`, first pod of v1 created at `2026-11-13T12:44:36Z`, pruned at `2026-11-13T12:44:58Z`
- PASS: first-publication: the first publication is a PUT
- PASS: first-publication: nothing was there before, the record's value after
- PASS: first-publication: the list holds one entry in all

Publish event:

```
{"ts":"2026-11-13T12:44:36Z","action":"publish","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":[],"after":["314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"],"tspa":{"method":"PUT","status":201,"bodySha256":"8ce0fda3f1e3908a765ad51dc7028371306194dd2b5ee8a85d92386d9f6883d4"},"readBack":{"listSha256":"05792631e5c2d95d0c547d31d395f7361c3c6771684667cfb09823062732f6b8","vcHash":"QmNi1tkH9z5tM9MEtMcUW81adbMUceyp7SpN1yzzDA5yVH"},"outcome":"published"}
```

Prune event:

```
{"ts":"2026-11-13T12:44:58Z","action":"prune","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":["314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"],"after":["314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"],"tspa":{"method":"PATCH","status":200,"bodySha256":"9c3d3732ac6f3db0060695568515e265926b8fb8f18fcb97a7997d20ed2f2ce5"},"readBack":{"listSha256":"05792631e5c2d95d0c547d31d395f7361c3c6771684667cfb09823062732f6b8","vcHash":"QmNi1tkH9z5tM9MEtMcUW81adbMUceyp7SpN1yzzDA5yVH"},"outcome":"pruned"}
```

stderr of the publish step:

```
  train-publish: published 314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582 for b/connector (40888e80-0b00-5523-b9c6-4491d3cf4c55): values ["314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"]
```

### wrong-secret — day 2

Induction: OIDC_CLIENT_SECRET wrong; the new record (v2) approved. Expected: outcome `token-failed`, exit 1, rollout not-started.

- PASS: wrong-secret: the publisher exits 1
- PASS: wrong-secret: outcome token-failed
- PASS: wrong-secret: rollout not-started
- PASS: wrong-secret: the event names the derived UUID
- PASS: wrong-secret: the pods are the ones from before (no rollout began)
- PASS: wrong-secret: the trust list is byte for byte what it was
- PASS: wrong-secret: the pods still run v1
- PASS: wrong-secret: no write was attempted

Publish event:

```
{"ts":"2026-11-13T12:44:59Z","action":"publish","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":[],"after":null,"tspa":{"method":null,"status":null,"bodySha256":null},"readBack":{"listSha256":null,"vcHash":null},"outcome":"token-failed"}
```

stderr of the publish step:

```
  train-publish: token endpoint answered 401
  train-publish: outcome: token-failed (nothing proven; a rollout gated on this must not proceed)
```

### token-without-role — day 2

Induction: TSPA_TOKEN_FILE: a valid token whose realm roles lack enrolltf (testuser). Expected: outcome `write-rejected`, exit 1, rollout not-started.

- PASS: token-without-role: the publisher exits 1
- PASS: token-without-role: outcome write-rejected
- PASS: token-without-role: rollout not-started
- PASS: token-without-role: the event names the derived UUID
- PASS: token-without-role: the pods are the ones from before (no rollout began)
- PASS: token-without-role: the trust list is byte for byte what it was
- PASS: token-without-role: the pods still run v1
- PASS: token-without-role: the TSPA refused the write with 403

Publish event:

```
{"ts":"2026-11-13T12:45:00Z","action":"publish","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":["314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"],"after":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c","314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"],"tspa":{"method":"PATCH","status":403,"bodySha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},"readBack":{"listSha256":null,"vcHash":null},"outcome":"write-rejected"}
```

stderr of the publish step:

```
  train-publish: TSPA refused the PATCH with 403: the token lacks the enrolltf realm role, or is invalid
  train-publish: outcome: write-rejected (nothing proven; a rollout gated on this must not proceed)
```

### malformed-token — day 2

Induction: TSPA_TOKEN_FILE: not.a.jwt. Expected: outcome `write-rejected`, exit 1, rollout not-started.

- PASS: malformed-token: the publisher exits 1
- PASS: malformed-token: outcome write-rejected
- PASS: malformed-token: rollout not-started
- PASS: malformed-token: the event names the derived UUID
- PASS: malformed-token: the pods are the ones from before (no rollout began)
- PASS: malformed-token: the trust list is byte for byte what it was
- PASS: malformed-token: the pods still run v1
- PASS: malformed-token: the TSPA refused the write with 401

Publish event:

```
{"ts":"2026-11-13T12:45:00Z","action":"publish","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":["314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"],"after":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c","314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"],"tspa":{"method":"PATCH","status":401,"bodySha256":"cf0d7186f8c99586c91366dc56c59f66bef48e74bd17e4020bbbdb18b13d2426"},"readBack":{"listSha256":null,"vcHash":null},"outcome":"write-rejected"}
```

stderr of the publish step:

```
  train-publish: TSPA refused the PATCH with 401: the token lacks the enrolltf realm role, or is invalid
  train-publish: outcome: write-rejected (nothing proven; a rollout gated on this must not proceed)
```

### lane-closed-refused — day 5

Induction: TSPA_URL: a closed port on localhost. Expected: outcome `transport-failure`, exit 1, rollout not-started.

- PASS: lane-closed-refused: the publisher exits 1
- PASS: lane-closed-refused: outcome transport-failure
- PASS: lane-closed-refused: rollout not-started
- PASS: lane-closed-refused: the event names the derived UUID
- PASS: lane-closed-refused: the pods are the ones from before (no rollout began)
- PASS: lane-closed-refused: the trust list is byte for byte what it was
- PASS: lane-closed-refused: the pods still run v1
- PASS: lane-closed-refused: the publisher gave up within the timeout (1s, limit 40)

Publish event:

```
{"ts":"2026-11-13T12:45:01Z","action":"publish","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":[],"after":null,"tspa":{"method":null,"status":null,"bodySha256":null},"readBack":{"listSha256":null,"vcHash":null},"outcome":"transport-failure"}
```

stderr of the publish step:

```
  train-publish: TSPA unreachable reading the trust list: curl: (7) Failed to connect to 127.0.0.1 port 33541 after 0 ms: Could not connect to server
  train-publish: outcome: transport-failure (nothing proven; a rollout gated on this must not proceed)
```

### lane-closed-blackhole — day 5

Induction: TSPA_URL: a black-holed address, TRAIN_PUBLISH_TIMEOUT=5. Expected: outcome `transport-failure`, exit 1, rollout not-started.

- PASS: lane-closed-blackhole: the publisher exits 1
- PASS: lane-closed-blackhole: outcome transport-failure
- PASS: lane-closed-blackhole: rollout not-started
- PASS: lane-closed-blackhole: the event names the derived UUID
- PASS: lane-closed-blackhole: the pods are the ones from before (no rollout began)
- PASS: lane-closed-blackhole: the trust list is byte for byte what it was
- PASS: lane-closed-blackhole: the pods still run v1
- PASS: lane-closed-blackhole: the publisher gave up within the timeout (5s, limit 5 plus 10 of margin)

Publish event:

```
{"ts":"2026-11-13T12:45:06Z","action":"publish","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":[],"after":null,"tspa":{"method":null,"status":null,"bodySha256":null},"readBack":{"listSha256":null,"vcHash":null},"outcome":"transport-failure"}
```

stderr of the publish step:

```
  train-publish: TSPA unreachable reading the trust list: curl: (28) Connection timed out after 5003 milliseconds
  train-publish: outcome: transport-failure (nothing proven; a rollout gated on this must not proceed)
```

### new-version — normal day, days 3 and 4

Induction: none: the new record (v2) for the same endpoint. Expected: outcome `published`, exit 0, rollout converged.

- PASS: new-version: the publisher exits 0
- PASS: new-version: outcome published
- PASS: new-version: rollout converged
- PASS: new-version: the event names the derived UUID
- PASS: new-version: prune proven (exit 0, outcome pruned)
- PASS: new-version: exactly one entry for the endpoint, whatever the number of publications
- PASS: new-version: the entry's ServiceTypeIdentifier is the record's (the TCR's lookup key)
- PASS: new-version: after prune the TEEM set is the record's value alone
- PASS: new-version: after prune the image-digest set is the record's digest alone
- PASS: new-version: the ready pods all run version v2
- PASS: new-version: every ready pod's imageID is the published digest
  ready pods: `[{"name":"connector-5d56c4bf48-zq5lw","uid":"dd72a096-66de-4580-87c1-afeadc3ca8d5","version":"v2","imageID":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","created":"2026-11-13T12:45:07Z"}]`
- PASS: new-version: the config.json in the running pod is the one measured for the record (sha256)
- PASS: new-version: the trust list carried the value before the first pod of this version existed
  published at `2026-11-13T12:45:07Z`, first pod of v2 created at `2026-11-13T12:45:07Z`, pruned at `2026-11-13T12:45:30Z`
- PASS: new-version: the second publication is a PATCH of the same entry
- PASS: new-version: the publication wrote the union of old and new
- PASS: new-version: both generations ran at once during the rollout (old running: 1, new not ready: 1)
- PASS: new-version: while they did, the entry carried both measurements
- PASS: new-version: and both pods ran the published digest
  during the rollout: TEEM `["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c","314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"]`, digests `["sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b"]`, pod imageIDs `["sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b"]`
- PASS: new-version: the list still holds one entry in all

Publish event:

```
{"ts":"2026-11-13T12:45:07Z","action":"publish","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":["314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"],"after":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c","314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"],"tspa":{"method":"PATCH","status":200,"bodySha256":"9c3d3732ac6f3db0060695568515e265926b8fb8f18fcb97a7997d20ed2f2ce5"},"readBack":{"listSha256":"4f318e4f9bde66246fe9534f2778ea85cb91700a7c4a096cc31e54554b2528a9","vcHash":"QmTfnkAwmWtY8sHmbZyerFqEF35wdczwAWs2qwzxiMojig"},"outcome":"published"}
```

Prune event:

```
{"ts":"2026-11-13T12:45:30Z","action":"prune","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c","314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"],"after":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c"],"tspa":{"method":"PATCH","status":200,"bodySha256":"9c3d3732ac6f3db0060695568515e265926b8fb8f18fcb97a7997d20ed2f2ce5"},"readBack":{"listSha256":"8aa9d955281e4a74f9e021762c55618da2897f9acf220cdada0e655d76e36f40","vcHash":"QmXfwBogKwaTD7ABFsVzDiP7FKvv5To1ApmWGTgzuMaFxj"},"outcome":"pruned"}
```

stderr of the publish step:

```
  train-publish: published 210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c for b/connector (40888e80-0b00-5523-b9c6-4491d3cf4c55): values ["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c","314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"]
```

### republish-same — day 3

Induction: none: the same record (v2) again. Expected: outcome `published`, exit 0, rollout converged.

- PASS: republish-same: the publisher exits 0
- PASS: republish-same: outcome published
- PASS: republish-same: rollout converged
- PASS: republish-same: the event names the derived UUID
- PASS: republish-same: prune proven (exit 0, outcome pruned)
- PASS: republish-same: exactly one entry for the endpoint, whatever the number of publications
- PASS: republish-same: the entry's ServiceTypeIdentifier is the record's (the TCR's lookup key)
- PASS: republish-same: after prune the TEEM set is the record's value alone
- PASS: republish-same: after prune the image-digest set is the record's digest alone
- PASS: republish-same: the ready pods all run version v2
- PASS: republish-same: every ready pod's imageID is the published digest
  ready pods: `[{"name":"connector-5d56c4bf48-zq5lw","uid":"dd72a096-66de-4580-87c1-afeadc3ca8d5","version":"v2","imageID":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","created":"2026-11-13T12:45:07Z"}]`
- PASS: republish-same: the config.json in the running pod is the one measured for the record (sha256)
- PASS: republish-same: the repeated publication is a PATCH, never a second PUT
- PASS: republish-same: the value was there before and is there after, once
- PASS: republish-same: the list still holds one entry in all

Publish event:

```
{"ts":"2026-11-13T12:45:31Z","action":"publish","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c"],"after":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c"],"tspa":{"method":"PATCH","status":200,"bodySha256":"9c3d3732ac6f3db0060695568515e265926b8fb8f18fcb97a7997d20ed2f2ce5"},"readBack":{"listSha256":"8aa9d955281e4a74f9e021762c55618da2897f9acf220cdada0e655d76e36f40","vcHash":"QmXfwBogKwaTD7ABFsVzDiP7FKvv5To1ApmWGTgzuMaFxj"},"outcome":"published"}
```

Prune event:

```
{"ts":"2026-11-13T12:47:46Z","action":"prune","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c"],"after":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c"],"tspa":{"method":"PATCH","status":200,"bodySha256":"9c3d3732ac6f3db0060695568515e265926b8fb8f18fcb97a7997d20ed2f2ce5"},"readBack":{"listSha256":"8aa9d955281e4a74f9e021762c55618da2897f9acf220cdada0e655d76e36f40","vcHash":"QmXfwBogKwaTD7ABFsVzDiP7FKvv5To1ApmWGTgzuMaFxj"},"outcome":"pruned"}
```

stderr of the publish step:

```
  train-publish: published 210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c for b/connector (40888e80-0b00-5523-b9c6-4491d3cf4c55): values ["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c"]
```


## 5. Reading back without writing, and the missing-token quirk

- PASS: verify of the current record: exit 0, outcome verified

```
{"ts":"2026-11-13T12:47:47Z","action":"verify","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c"],"after":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c"],"tspa":{"method":null,"status":null,"bodySha256":null},"readBack":{"listSha256":"8aa9d955281e4a74f9e021762c55618da2897f9acf220cdada0e655d76e36f40","vcHash":"QmXfwBogKwaTD7ABFsVzDiP7FKvv5To1ApmWGTgzuMaFxj"},"outcome":"verified"}
```

- PASS: verify of the pruned record: exit 1, outcome not-published (the old value is gone)

```
{"ts":"2026-11-13T12:47:47Z","action":"verify","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c"],"after":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c"],"tspa":{"method":null,"status":null,"bodySha256":null},"readBack":{"listSha256":"8aa9d955281e4a74f9e021762c55618da2897f9acf220cdada0e655d76e36f40","vcHash":null},"outcome":"not-published"}
```

- PASS: a PATCH without Authorization is answered 200 (the upstream quirk still holds on this build)
- PASS: with an empty body
- PASS: and the list is byte for byte unchanged: the write never ran
  a publisher trusting that 200 would have declared a value published that is not there; publish.sh treats an empty 2xx body as `write-unconfirmed`

## 6. Nothing secret in the records

- PASS: neither the client secret nor a token of this run appears in the records, the logs or the evidence
- PASS: no JWT at all appears in the records, the logs or the evidence

## 7. The publication records (publications.jsonl)

One line per publisher run, in order; the evidence the lifecycle wrapper will relay as `EVENT_JSON`.

```
{"ts":"2026-11-13T12:44:36Z","action":"publish","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":[],"after":["314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"],"tspa":{"method":"PUT","status":201,"bodySha256":"8ce0fda3f1e3908a765ad51dc7028371306194dd2b5ee8a85d92386d9f6883d4"},"readBack":{"listSha256":"05792631e5c2d95d0c547d31d395f7361c3c6771684667cfb09823062732f6b8","vcHash":"QmNi1tkH9z5tM9MEtMcUW81adbMUceyp7SpN1yzzDA5yVH"},"outcome":"published"}
{"ts":"2026-11-13T12:44:58Z","action":"prune","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":["314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"],"after":["314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"],"tspa":{"method":"PATCH","status":200,"bodySha256":"9c3d3732ac6f3db0060695568515e265926b8fb8f18fcb97a7997d20ed2f2ce5"},"readBack":{"listSha256":"05792631e5c2d95d0c547d31d395f7361c3c6771684667cfb09823062732f6b8","vcHash":"QmNi1tkH9z5tM9MEtMcUW81adbMUceyp7SpN1yzzDA5yVH"},"outcome":"pruned"}
{"ts":"2026-11-13T12:44:59Z","action":"publish","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":[],"after":null,"tspa":{"method":null,"status":null,"bodySha256":null},"readBack":{"listSha256":null,"vcHash":null},"outcome":"token-failed"}
{"ts":"2026-11-13T12:45:00Z","action":"publish","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":["314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"],"after":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c","314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"],"tspa":{"method":"PATCH","status":403,"bodySha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},"readBack":{"listSha256":null,"vcHash":null},"outcome":"write-rejected"}
{"ts":"2026-11-13T12:45:00Z","action":"publish","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":["314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"],"after":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c","314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"],"tspa":{"method":"PATCH","status":401,"bodySha256":"cf0d7186f8c99586c91366dc56c59f66bef48e74bd17e4020bbbdb18b13d2426"},"readBack":{"listSha256":null,"vcHash":null},"outcome":"write-rejected"}
{"ts":"2026-11-13T12:45:01Z","action":"publish","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":[],"after":null,"tspa":{"method":null,"status":null,"bodySha256":null},"readBack":{"listSha256":null,"vcHash":null},"outcome":"transport-failure"}
{"ts":"2026-11-13T12:45:06Z","action":"publish","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":[],"after":null,"tspa":{"method":null,"status":null,"bodySha256":null},"readBack":{"listSha256":null,"vcHash":null},"outcome":"transport-failure"}
{"ts":"2026-11-13T12:45:07Z","action":"publish","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":["314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"],"after":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c","314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"],"tspa":{"method":"PATCH","status":200,"bodySha256":"9c3d3732ac6f3db0060695568515e265926b8fb8f18fcb97a7997d20ed2f2ce5"},"readBack":{"listSha256":"4f318e4f9bde66246fe9534f2778ea85cb91700a7c4a096cc31e54554b2528a9","vcHash":"QmTfnkAwmWtY8sHmbZyerFqEF35wdczwAWs2qwzxiMojig"},"outcome":"published"}
{"ts":"2026-11-13T12:45:30Z","action":"prune","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c","314747433ab26d7c9430c41e08aebf4b0ffe1a27f8f999bf4e66682a23f3c582"],"after":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c"],"tspa":{"method":"PATCH","status":200,"bodySha256":"9c3d3732ac6f3db0060695568515e265926b8fb8f18fcb97a7997d20ed2f2ce5"},"readBack":{"listSha256":"8aa9d955281e4a74f9e021762c55618da2897f9acf220cdada0e655d76e36f40","vcHash":"QmXfwBogKwaTD7ABFsVzDiP7FKvv5To1ApmWGTgzuMaFxj"},"outcome":"pruned"}
{"ts":"2026-11-13T12:45:31Z","action":"publish","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c"],"after":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c"],"tspa":{"method":"PATCH","status":200,"bodySha256":"9c3d3732ac6f3db0060695568515e265926b8fb8f18fcb97a7997d20ed2f2ce5"},"readBack":{"listSha256":"8aa9d955281e4a74f9e021762c55618da2897f9acf220cdada0e655d76e36f40","vcHash":"QmXfwBogKwaTD7ABFsVzDiP7FKvv5To1ApmWGTgzuMaFxj"},"outcome":"published"}
{"ts":"2026-11-13T12:47:46Z","action":"prune","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c"],"after":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c"],"tspa":{"method":"PATCH","status":200,"bodySha256":"9c3d3732ac6f3db0060695568515e265926b8fb8f18fcb97a7997d20ed2f2ce5"},"readBack":{"listSha256":"8aa9d955281e4a74f9e021762c55618da2897f9acf220cdada0e655d76e36f40","vcHash":"QmXfwBogKwaTD7ABFsVzDiP7FKvv5To1ApmWGTgzuMaFxj"},"outcome":"pruned"}
{"ts":"2026-11-13T12:47:47Z","action":"verify","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c"],"after":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c"],"tspa":{"method":null,"status":null,"bodySha256":null},"readBack":{"listSha256":"8aa9d955281e4a74f9e021762c55618da2897f9acf220cdada0e655d76e36f40","vcHash":"QmXfwBogKwaTD7ABFsVzDiP7FKvv5To1ApmWGTgzuMaFxj"},"outcome":"verified"}
{"ts":"2026-11-13T12:47:47Z","action":"verify","framework":"facis-ztd.local","uuid":"40888e80-0b00-5523-b9c6-4491d3cf4c55","serviceTypeIdentifier":"did:web:connector-b.facis-ztd.local","image":"docker.io/curlimages/curl@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b","before":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c"],"after":["210a49d4b44827286259e2b85728b9a5d619bc187facc1bb8294a072cb97bb6c"],"tspa":{"method":null,"status":null,"bodySha256":null},"readBack":{"listSha256":"8aa9d955281e4a74f9e021762c55618da2897f9acf220cdada0e655d76e36f40","vcHash":null},"outcome":"not-published"}
```

**Verdict: all 107 checks passed.**
