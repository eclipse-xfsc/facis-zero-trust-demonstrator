# Mesh identity: SPIRE-issued identities in the sidecar mesh, executed on kind

`evidence.md` and `environment.json` are the executed proof that the zone's mesh identities are
SPIRE's: the end-to-end proof [ADR-0009](../../adr/0009-service-mesh-mode-istio-sidecar-with-cilium.md)
deferred to its own change. They are written by `scripts/verify-mesh-identity/verify.sh` on the
local kind cluster (`scripts/dev/kind-cilium-up.sh`: Kubernetes v1.35.5, Cilium 1.20.2 chained with
`cni.exclusive=false`) and never by hand or by CI: the files in the repository are the output of the
last run, on the commit and host `environment.json` names, with the tree clean.

## What the record proves

The zone is installed from an empty cluster with `scripts/install-zone/install.sh`, as seven
releases in order (the umbrella, SPIRE's `spire-crds` and `spire`, Istio's `base`, `istiod` and
`cni`, and `zone-policy`), and once more to show nothing changes. With stand-in pods it then shows:

- **`svid-over-csi-socket`**: a pod with the identity label gets, over the `csi.spiffe.io` socket,
  the SVID `spiffe://kind.facis-ztd.local/ns/<namespace>/sa/<service account>`, chained to the
  SPIRE server's CA; a pod without the label has no entry and gets no SVID.
- **`mesh-identity-issued-by-spire`**: the certificate the proxy presents in mesh mTLS has
  `O = SPIRE`, the SPIRE CA as issuer and the SVID's URI SAN; the proxy's root bundle (`ROOTCA`) is
  the SPIRE CA; istiod's CA issued nothing; a pod that chooses its injection templates, brings its
  own proxy without the SPIRE socket, or runs Istio's agent under another container name, is
  refused at admission; and a certificate signed with istiod's CA key for an enrolled SPIFFE ID is
  refused by a meshed peer, which accepts that workload's SPIRE SVID; with that SVID the peer's
  proxy completes a TLS 1.3 handshake and refuses one capped at TLS 1.2 (the mesh mTLS minimum of
  ADR 005).
- **`unregistered-workload-cut-off`**: without an entry the proxy has no certificate, the
  application never starts, and the peer refuses the pod under STRICT.
- **`traffic-through-the-proxies`**: the peer sees the caller's SPIFFE ID and both proxies count
  the request as mTLS.
- **`default-deny-with-chained-cni`** and **`control-planes-under-default-deny`**: the Istio CNI
  plugin chained after Cilium, the umbrella's cross-plane denial and matrix lane intact with the
  proxies, both control planes reachable only through their declared openings, and the SPIRE
  agents' metrics bound to each node's loopback.
- **`native-sidecar-version`** and **`install-order-idempotent`**: Kubernetes 1.33 or later with
  the proxy as a native sidecar; the install order from zero, all Ready, idempotent, with every
  SPIRE and Istio image pinned by digest.

It also records the identity-band checks failing a release when a declared registration has no
entry, the render guards, and a teardown that leaves no plane or control-plane namespace, CRD or
webhook behind (the SPIRE CRDs leave through Helm's uninstall of `spire-crds`; the umbrella's
release namespace `ztd-system`, which the installer creates and no release owns, remains). Both
admission webhooks are asked directly, by server-side dry runs, to show the API server reaches them
through the `controlPlaneWebhooks` opening.

## What it does not prove

The client clusters: the OSC zones repeat the run when they exist, on their provider's CNI, and a
CNI other than Cilium needs a declared derogation first. Mesh `AuthorizationPolicy` and the
per-path L7 ownership of the demonstrator workloads belong to their mesh enrolment, after this.

## How to re-run it

See `scripts/verify-mesh-identity/README.md`. Run on a clean tree after the code commit it cites,
then commit the two files; `environment.json` records the commit and `dirty: false`.
