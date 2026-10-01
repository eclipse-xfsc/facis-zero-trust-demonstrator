# TCR findings (out of scope for the TSPA API verification — recorded, not pursued)

Component: `eclipse-xfsc/train-trust-validator` (Trusted Content Resolver, TRAIN read side), commit `e27b1ed` (2025-05-25),
read and briefly exercised on 2026-09-18 while verifying the TSPA publish API. The verification's criteria are all on the
write side, so nothing here is evidence for that verification. Kept because the two defects below affect any consumer
of the trust lists the pipeline will publish.

## Finding 1 — `resolveDid` fails with a null `getServices()` (candidate upstream issue)

`DIDResolver.resolveDid` (service/src/main/java/eu/xfsc/train/tcr/server/service/DIDResolver.java) calls
`diDoc.getServices().stream()` and, further down, `diDoc.getControllers().stream()` without null checks. A DID
document with no `service` (and no `controller`) section — every `did:key`, and any minimal `did:web` — makes both
`POST /tcr/v1/resolve` and `POST /tcr/v1/validate` answer HTTP 500:

```
{"code":"server_error","message":"Cannot invoke \"java.util.List.stream()\" because the return value of
 \"foundation.identity.did.DIDDocument.getServices()\" is null"}
```

Reproduced with the did:key of TSPA's own signing key (`did:key:z6Mkt2M92kpSrbpYvJUzd75k43vq3Y8YZKvGzsnk1iiSzFn6`)
resolved by `universalresolver/driver-did-key`. Minimal null-safe change that made the endpoints work
(`tcr-null-services.patch`, same folder; the third hunk on `getVerificationMethods` is defensive only):

```diff
-			services = diDoc.getServices().stream();
+			services = (diDoc.getServices() == null ? java.util.List.<Service>of() : diDoc.getServices()).stream();
...
-			origin = diDoc.getControllers().stream().map(uri -> resolveOrigin(uri)).findFirst().orElse(null);
+			origin = (diDoc.getControllers() == null ? java.util.List.<java.net.URI>of() : diDoc.getControllers()).stream().map(uri -> resolveOrigin(uri)).findFirst().orElse(null);
```

Candidate for an upstream issue/PR on `eclipse-xfsc/train-trust-validator`. Not submitted.

## Finding 2 — without libsodium every VC is silently "unverified"

The Ed25519 verifier in `key-formats-java` (`NaClSodiumEd25519Provider`, the only provider registered in
`META-INF/services`) loads libsodium via lazysodium. In a runtime image without the native library the provider
cannot be instantiated; the TCR does not fail the request — it logs a WARN and returns `vcVerified: false` for every
trust list. Installing `libsodium23` fixed it. Whether the upstream runtime image
(`bellsoft/liberica-openjdk-alpine:21`) carries the library was not checked. Operationally: a mis-packaged TCR
reports every published trust list as unverified without any error.

## Exploratory run (context only)

With both fixes applied locally (a local Dockerfile adding libsodium, a compose file joining the TSPA network
with a did:key driver only, TSPA configured to issue the VC under the did:key and to advertise
`request.get.mapping = http://tspa-service:16003/tspa-service/tspa/v1/`), `POST /tcr/v1/validate` returned
`vcVerified: true` and found entries by `ServiceTypeIdentifier` and not by `DigitalId.DID`. The run artefacts
(Dockerfile, compose, validate script, run log) are kept outside this repository as working material. This is
consistent with the code reading in the main document; it is recorded here as context and is not part of
the verification's acceptance evidence.
