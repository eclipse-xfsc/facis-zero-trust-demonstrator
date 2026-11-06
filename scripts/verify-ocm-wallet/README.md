# OCM wallet lane proof

`verify.sh` installs the OCM W-Stack wallet lane on a throwaway kind cluster laid out like a zone
and checks what the lane promises: the umbrella's OpenBao bootstrap issues one service token per
wallet and revokes the root token; `ocm-backbone` brings Cassandra with the `ocm` keyspace and
NATS; two `ocm-wallet` releases, one per tenant, each serve their `did:web` document over TLS by
host name with exactly their own key, whose RFC 7638 thumbprint equals the one computed from the
transit public key with openssl; a management-plane pod resolves the other wallet's DID and a
data-plane pod is refused by the stores; a wallet's token signs with its own key and is refused,
with a 403, everything else; a credential stored through the storage subject is in Cassandra and still is after every pod,
the Cassandra pod and OpenBao restarted (while OpenBao is sealed the document carries no key), and
after an uninstall and a reinstall from the same values; the chart gate passes both charts.

```bash
scripts/tools/install.sh .tools/bin kind kubectl     # once
scripts/verify-ocm-wallet/verify.sh --out .dev/ocm-wallet-evidence
KEEP=1 scripts/verify-ocm-wallet/verify.sh           # leave the cluster behind
```

Needs docker, helm, kind, kubectl, curl, OpenSSL 3, python3, jq and sha256sum; pulls the images pinned in
`scripts/tools/pins.env` (`OCM_*_IMAGE`, `NATS_BOX_IMAGE`), Cilium's chart and the kind node image.
About twenty minutes.

The records in `--out`: `cases.md` (one `PASS`/`FAIL` line per case), `verdict.txt`, the two DID
documents and JWKS, the in-cluster resolution of wallet b, the
credential ids per tenant and account before the restarts (never the stored values), the test CA and `environment.json` (images, versions,
DIDs, thumbprints, the credential id). The CI workflow `OCM wallet lane` runs the script on every
change to the lane and publishes the records as the artifact `ocm-wallet-lane`.

What the proof stands in for, and says so: public DNS (a CoreDNS rewrite inside the cluster and a
port-forward from the host), the certificates (a test CA) and the zone's load balancer. What it
does not prove: the mesh in STRICT mode, the issuer side of OID4VCI (the credential is published on
the storage subject directly), and anything on the OSC clusters.
