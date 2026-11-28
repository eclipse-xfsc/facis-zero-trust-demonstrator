# ZT-19 as an executable BDD scenario: the connector pair over the attested channel

2026-11-23 14:41 UTC, local processes on one host (Darwin arm64, Go 1.27.0): two `cmcd` v0.9.15
processes built from the pinned CMC module, one per zone, and the two connector gateways. No cluster,
no container, no zone: there is no `kube-system` UID for this run. Commit `3b1c088e` (tree clean),
run id `20261123T144105Z-2174089622`, target `local`.

**Scope decision (Project Leader, Daniel Pires, 2026-11-23):** for M3, ZT-19 is proven on the
component, with real attestation, as recorded here. Deploying the attested gateway on the zone
clusters, with a `cmcd` per zone, is delivered with M4 (bidirectional inter-cluster trust); until
then the zones' inter-zone hop is the Connector routing over verified TLS.

ZT-19 (Upstream / Downstream Proxy Functionality, BDD-ZT-019) is implemented in
`features/annex/annex-a.json` as a `@cluster` row, because its proof owns external processes. The
attested channel itself is the library of `internal/atls` ([Attested channel control](../../attested-channel.md)),
merged into this branch from its two open pull requests with their history. The row adds the piece that
uses it: `internal/connectorgateway` (binary `cmd/connector-gateway`), a gateway with an egress and an
ingress role that forwards opaque byte streams. The egress has one way to its peer, `atls.Dial`; the
ingress has one listener, `atls.Listen`; both require mutual attestation and refuse to start in any
other mode. A stream is closed when the peer's verdict expires.

```bash
PATH=/opt/homebrew/bin:$PATH BDD_MODE=cluster GODOG_CUCUMBER_OUT=bundles/bdd/zt19-local.json \
  go test -count=1 -timeout=10m ./internal/bdd -godog.tags=@ZT-19
```

## What each step calls

The steps (`internal/bdd/attested_gateway_rows_test.go`) run `scripts/verify-attested-gateway/verify.sh`.
It generates fresh keys and metadata for two zones, starts one `cmcd` per zone, checks that each
produces reports the other verifies, and runs `TestGatewayProof` (`internal/connectorgateway`) against
those two attesters. The gateways load their credentials through the loader the binary uses
(`Config.Attestation`).

| Step | What it does | Decided from |
|---|---|---|
| Given | starts the proof and waits until the pair holds a channel, before any application byte is released | the two `established` decisions the gateways recorded: `mutual_attestation`, TLS 1.3, the peer identity each end expected (`spiffe://b/gateway`, `spiffe://a/gateway`), and the same 32-byte channel binding at both ends |
| When | releases the HTTP request over that channel, then the gRPC calls through a second pair | the proof's exit: the upstream asserts what it received, the client what came back |
| Then | reads the proof's `record.json` | passed with the real-`cmcd` proof name; the channel as in Given; TLS bytes seen on the hop between the connectors; the three recorded refusals below |

Call information asserted end to end. HTTP: method, escaped path and query, authority, `Authorization`,
trace header, a repeated header, the body; back: status, body, trailer. gRPC: authority, authorization,
trace metadata, repeated and binary metadata, the deadline, the payload; back: response header and
trailer, an error status with its message, a server stream with its trailer.

The hop between the two connectors runs through a tap that keeps every byte. The proof fails unless
those bytes start with a TLS handshake record and hold none of the request's or response's values in
the clear; the record carries their count (25 693 in this run). The channel binding being equal at both
ends rules out a tap that terminates TLS.

No unprotected path, each decided from the gateway's recorded refusal and its reason, not from a failed
response:

| Case | Recorded decision | Also asserted |
|---|---|---|
| a plaintext peer sends an HTTP request to the ingress | `ingress refused`, `atls: peer does not speak attested TLS 1.3` | the upstream was called once in the whole test: by the attested request |
| a TLS 1.3 peer holding a zone certificate, speaking no attestation, sends an HTTP request to the ingress | `ingress refused`, `atls: handshake timed out` | same |
| the egress is pointed at a TLS 1.3 server holding the peer zone's certificate that never attests | `egress refused`, `atls: handshake timed out` | the request the caller sent never reached that server |

`TestGatewayDeciderRequiresRefusalsAndBinding` (strict mode) holds the decision: a record missing any
one of the five decisions, with differing bindings, without bytes on the hop, or with only a success
flag is refused.

## Result

| Row | Mode | Target | Run | Result |
|---|---|---|---|---|
| ZT-19 | `cluster` | local processes, two `cmcd` v0.9.15 | `20261123T144105Z-2174089622` | passed (Given, When, Then) |

`verdict.txt`: `PASS ZT-19: HTTP and gRPC preserved over the attested channel; plaintext and unattested
TLS refused; no fallback`. Both `cmcd` logs show the `Attest` and `Verify` requests they served. The
cucumber report (`bundles/bdd/zt19-local.json`) and the record
(`bundles/bdd/evidence/bdd-zt-019/local/20261123T144105Z-2174089622/`: `record.json`, `verdict.txt`,
`environment.json`, `gateway-test.log`, both `cmcd` configurations and logs) are git-ignored and delivered
with the milestone submission.

The three channel proofs of the library (`scripts/atls-probe/prove-mutual-handshake.sh`,
`prove-session-loss.sh`, `prove-tampered-binding.sh`) were re-run on the merged branch against their own
`cmcd` processes, with `--out` outside the committed evidence: PASS, PASS, PASS.

## Limits

- The proof runs the two gateways in one test process, from the package the binary is built from. The
  binary `cmd/connector-gateway` itself (flag and JSON configuration, decisions as JSON lines on stdout)
  has no test and no image.
- The deployed Connector gateway (`deployment/helm/connector-gateway`, Envoy with verified TLS between
  the zones, its routing records proven by `scripts/verify-connector-routing/`) is unchanged. No zone and
  no kind cluster runs the attested gateway yet: that needs its image, a `cmcd` per zone with provisioned
  evidence ([Attestation evidence provisioning](../../attestation-provisioning.md)), and a decision on
  how the gateway composes with the Envoy that keeps the per-request routing record.
- A TLS peer with a zone certificate that never attests is refused only when the handshake timeout ends
  (10 s by default, 3 s in the proof); CMC v0.9.15 reads the length prefix of the first message from the
  peer and allocates that many bytes before reading them. The wrapper caps concurrent handshakes at 8.
- The attesters use the software driver with generated keys and metadata (mock evidence), as in the
  library's own proofs.
- The gateway forwards streams and records channel decisions only; it writes no per-request record.
