# Attested channel control

The zones talk to each other only over a mutually attested TLS 1.3 channel (ZT-28 to ZT-35). The
Go package `internal/atls` is the one place that establishes such a channel. It wraps the
Fraunhofer AISEC CMC attested-TLS library and exposes only the demonstrator's own types.

!!! note "v1 — frozen at `d990ca3`, 2026-10-01"
    This page is the contract of interface **IF-07 Attested channel control** in the
    [interface registry](api-docs.md): the Go interface of `internal/atls`, frozen at **v1** at
    commit `d990ca3` on 2026-10-01. The exported identifiers and their signatures are listed in
    `internal/atls/api_v1.txt`, and a test fails when the package differs from that listing.
    [Stability](#stability) states what is frozen and how the interface may change. The freeze
    is ours; the partner sign-off under the interface-freeze process is pending.

## Pinned library

| | |
|---|---|
| Library | `github.com/Fraunhofer-AISEC/cmc`, **v0.9.15** (commit `6754d3c`), unmodified upstream, no `replace` |
| Only importer | `internal/atls` and its sub-packages. A `depguard` rule in CI fails the build for any other importer ([CI/CD](ci-cd.md)) |
| Attester | one `cmcd` per zone, reached over gRPC at `Config.CmcdAddr` |
| Test-only attester | the in-process CMC (`libapi`), reachable only from `internal/atls/atlstest` |
| Handshake messages | JSON; attestation reports as the `cmcd` produces them (CBOR over gRPC) |
| Channel binding | RFC 9266 TLS exporter, label `EXPORTER-Channel-Binding`, 32 bytes. Report nonce = `sha256(exporter ‖ prover's TLS leaf certificate)` |

## Interface

```go
package atls

type Config struct {
    TLS                     *tls.Config    // exactly one static certificate + zone trust anchors
    CmcdAddr                string         // this zone's cmcd, host:port (gRPC)
    Policies                []byte         // optional attestation policies for the verifier
    ExpectedPeerIdentity    string         // URI SAN if it contains "://", DNS SAN otherwise
    HandshakeTimeout        time.Duration  // default 10 s
    ChannelLifetime         time.Duration  // default 15 min
    MaxConcurrentHandshakes int            // default 8
    PeerVerifier            PeerVerifier   // optional veto after attestation
}

const (
    DefaultHandshakeTimeout        = 10 * time.Second
    DefaultChannelLifetime         = 15 * time.Minute
    DefaultMaxConcurrentHandshakes = 8
)

func Dial(ctx context.Context, addr string, cfg Config) (*Conn, error)
func Listen(addr string, cfg Config) (*Listener, error)

func (l *Listener) Accept(ctx context.Context) (*Conn, error) // refusals come back as errors; call again
func (l *Listener) Addr() net.Addr
func (l *Listener) Close() error

type Conn struct{ net.Conn /* … */ }
func (c *Conn) Binding() []byte                    // RFC 9266 exporter, same on both ends
func (c *Conn) Peer() PeerAttestation
func (c *Conn) ConnectionState() tls.ConnectionState
func (c *Conn) Read(b []byte) (int, error)         // io.EOF and timeouts as they are; else ErrChannelLost
func (c *Conn) Write(b []byte) (int, error)        // timeouts as they are; else ErrChannelLost

type PeerAttestation struct {
    Verdict          Verdict        // always VerdictSuccess on a returned connection
    PeerID           string         // hex SHA-256 of the peer's TLS leaf certificate
    Identity         string         // the identity the peer's certificate matched
    Measurements     []Measurement  // verified measurements of the peer's evidence
    AttestedAt       time.Time      // when this end received the verification result
    EvidenceNotAfter time.Time      // validity end of the peer's evidence (zero if none stated)
    ValidUntil       time.Time      // min(AttestedAt + ChannelLifetime, EvidenceNotAfter)
}

type Verdict string
const VerdictSuccess Verdict = "success"

type Measurement struct {
    Evidence string  // evidence type the measurement belongs to
    Name     string  // measured component, when the evidence names it
    Index    int     // register or position
    Digest   string  // hex
    HashAlg  string  // when the evidence states it
}

type PeerVerifier interface {
    VerifyPeer(ctx context.Context, peer PeerAttestation) error
}
type PeerVerifierFunc func(ctx context.Context, peer PeerAttestation) error // adapts a function

type Error struct {
    Kind   error     // the sentinel the error matches
    Reason string    // the cause in words
    Err    error     // the underlying cause, if any
    Peer   net.Addr  // transport address of the peer; nil when no connection existed
}
func (e *Error) Error() string
func (e *Error) Unwrap() []error

var (
    // Refusals: no channel was returned.
    ErrNotAttested, ErrBindingMismatch, ErrEvidenceExpired, ErrIdentityMismatch,
    ErrPlainTLS, ErrPeerAborted, ErrAttestModeMismatch, ErrAttesterUnavailable,
    ErrHandshakeTimeout, ErrPeerRejected, ErrPeerUnreachable, ErrConfig error
    // An established channel failed.
    ErrChannelLost error
)
```

The block above is for reading. The listing that the build checks is `internal/atls/api_v1.txt`.

`*atls.Error` carries every refusal and every lost channel: `Kind` (the sentinel), `Reason`
(words), `Err` (the cause) and `Peer` (the transport address of the peer). Match with
`errors.Is(err, atls.ErrX)`.

`Peer` is set on every refusal `Accept` returns, so a listener can attribute a refusal, and on a
lost channel. A refusal from `Dial` carries it once a connection existed — in practice when the
verdict rules or the `PeerVerifier` refuse the peer; CMC keeps the connection of a handshake it
fails to itself. It is nil when no connection existed: a configuration error from `Dial` or
`Listen`, an unreachable peer, a `Dial` that timed out. It is an address, not an identity, and it
is not part of the error text.

`Peer().Identity` is the identity the peer's certificate matched, which is the configured
`ExpectedPeerIdentity`. A `PeerVerifier` reads the peer's identity from it without access to the
caller's configuration.

## What a returned channel guarantees (fail closed)

`Dial` and `Accept` return a connection only when **all** of the following hold. Any other outcome
closes the connection and returns a refusal.

1. **TLS 1.3 with mutual certificate authentication.** This holds whatever the caller's `tls.Config`
   allows: the wrapper forces TLS 1.3 as the minimum and requires a client certificate. Key exchange
   is limited to NIST curves, with hybrid ML-KEM preferred. Session resumption is off, so every
   channel is attested afresh.
2. **The peer's certificate is trusted and names the expected peer.** Its chain ends at the zone
   trust anchors, it carries `ExpectedPeerIdentity`, and its key is ECDSA P-256/P-384 or RSA with
   at least 4096 bits (ZT-50). The peer is identified by `ExpectedPeerIdentity`, not by the host
   name it was dialled at.
3. **Mutual attestation completed without error.** The attestation mode is always mutual; a peer
   that asks for another mode is refused.
4. **Exactly one attestation result exists for this connection, and its verdict is `success`.** A
   `warn` verdict is a refusal. A missing result means not attested. The result must belong to the
   certificate of this connection's peer.
5. **The peer's evidence is still valid** at the moment the connection is returned.
6. **The `PeerVerifier`, if configured, accepted the peer.** Without a verifier, the decision rests
   on points 1 to 5.

A returned connection has no read or write deadline left over from the handshake.

## Refusals

Each refusal matches exactly one sentinel and states its reason in words. `Decided from` tells how
the wrapper reaches the decision today; it is not part of the freeze.

| Sentinel | Meaning | Decided from |
|---|---|---|
| `ErrNotAttested` | The peer's attestation did not verify as `success`: failed verification, `warn`, no result, a result for another peer, or the peer reported that it could not verify this end | wrapper verdict rules; CMC result; CMC error text |
| `ErrBindingMismatch` | The peer's report is not bound to this TLS session (for example relayed from another session) | CMC result: freshness check failed (error code `Freshness`) |
| `ErrEvidenceExpired` | The peer's evidence is past its validity | CMC result: metadata validity check `Expired`; wrapper check at return time |
| `ErrIdentityMismatch` | The peer's certificate is untrusted, lacks the expected identity or uses a key outside the crypto baseline; or the peer refused this end's certificate | wrapper TLS verification; TLS alert text |
| `ErrPlainTLS` | The peer does not speak attested TLS 1.3: no TLS at all, TLS 1.2 or older, or a malformed first attestation message | TLS error text; CMC error text |
| `ErrPeerAborted` | The peer completed TLS 1.3 with a valid zone certificate and left before the attestation exchange completed. Typically its attester is down. A TLS 1.3 client that holds a zone certificate and never speaks attestation looks the same | CMC error text of the final handshake exchange, with no attestation result on this end |
| `ErrAttestModeMismatch` | The peer requested an attestation mode other than mutual | CMC error text |
| `ErrAttesterUnavailable` | This zone's `cmcd` could not be reached or failed | CMC error text (gRPC / in-process backend) |
| `ErrHandshakeTimeout` | The handshake did not end within the caller's deadline or `HandshakeTimeout`, or no handshake slot became free in time | wrapper deadline; `i/o timeout` from CMC |
| `ErrPeerRejected` | The `PeerVerifier` refused the attested peer. Its error is wrapped and stays inspectable | wrapper |
| `ErrPeerUnreachable` | No TCP connection to the peer. This is a transport failure, not a refusal | dial error text |
| `ErrConfig` | Invalid configuration; no connection was attempted | wrapper validation |

One sentinel is not a refusal. It reports the loss of a channel that was established:

| Sentinel | Meaning | Decided from |
|---|---|---|
| `ErrChannelLost` | A `Read` or `Write` on an established channel failed with an error other than `io.EOF` or a timeout: a connection reset, a broken pipe, a TLS alert, or use of a channel this end closed. The error wraps the cause, so `errors.Is` against the transport error still holds | the error of the TLS connection |

A peer that closes the channel, and a peer whose process is killed, both surface as `io.EOF`,
not as `ErrChannelLost`: see [Errors of an established channel](#errors-of-an-established-channel).

### Peers that do not attest: which sentinel

The negative scenarios of the attested channel map to the sentinels as follows, seen from the
listener:

| The client | Refused with |
|---|---|
| speaks TLS 1.2 or older, or no TLS | `ErrPlainTLS` |
| speaks TLS 1.3 without a zone certificate, or with one that is untrusted or names another identity | `ErrIdentityMismatch` |
| speaks TLS 1.3 with a valid zone certificate and does not complete the attestation exchange | `ErrPeerAborted` |
| speaks TLS 1.3 with a valid zone certificate and sends a malformed first attestation message | `ErrPlainTLS` |
| completes the exchange with a report that does not verify | `ErrNotAttested`, `ErrBindingMismatch` or `ErrEvidenceExpired` |

The classifier checks its sources in this order: the wrapper's own deadline, its identity check,
the typed error codes of this connection's attestation result, then the text of CMC's error. CMC
reports errors as plain text. Every text pattern the classifier relies on is pinned by a test
against the CMC v0.9.15 source. An upgrade that rewords an error therefore fails the build instead
of silently changing a refusal. Text that CMC relays from the peer never counts as a local
attester, TLS or timeout failure. No CMC error type leaves the wrapper; CMC causes are reduced to
their text.

## Lifetime

`ValidUntil` is the earlier of `AttestedAt + ChannelLifetime` and the validity end of the peer's
evidence. TLS 1.3 does not renegotiate, so evidence never refreshes on a live channel. The owner of
the channel must re-establish it before `ValidUntil`. The default lifetime of 15 minutes matches
the channel rotation.

The evidence validity end is the earliest of:

- the `Validity.NotAfter` of the peer's signed metadata (image description, manifests, company
  description);
- the certificates that signed that metadata;
- certificates that signed the evidence itself.

sw-driver evidence is signed with a bare key and has no certificate.

## Concurrency and timeouts

- A listener handshakes each incoming connection in its own goroutine, so one slow peer does not
  delay the others.
- At most `MaxConcurrentHandshakes` handshakes run at once per listener, and at most that many
  across all `Dial` calls of the process. A connection waits for a slot up to the handshake
  timeout and is then refused with `ErrHandshakeTimeout`.
- `Dial` returns within the context deadline or `HandshakeTimeout`, whichever is sooner. If CMC is
  still blocked in the peer exchange at that point, the connection it returns later is closed. Its
  goroutine keeps its handshake slot until CMC gives up, so stalled peers cannot exceed the cap.
- The listener closes a connection whose handshake outlives `HandshakeTimeout`.

## Errors of an established channel

After `Dial` or `Accept` has returned a channel, `Read` and `Write` behave as follows.

| What `Read` or `Write` returns | When | Form |
|---|---|---|
| `io.EOF` | The peer closed the channel, or its process died and its kernel closed the connection | as the connection returns it, not wrapped: `err == io.EOF` holds |
| a timeout error | A deadline the caller set has expired | as the connection returns it, not wrapped: it is a `net.Error` with `Timeout() == true` and matches `os.ErrDeadlineExceeded` |
| `ErrChannelLost` | Any other error: connection reset, broken pipe, TLS alert sent or received, use of a channel this end closed | an `*atls.Error` that wraps the cause; `errors.Is(err, syscall.ECONNRESET)`, `errors.Is(err, net.ErrClosed)` and the like still hold |

Standard-library consumers therefore keep working: `io.Copy`, `io.ReadAll` and `bufio` end on the
raw `io.EOF`, and a heartbeat built on read deadlines sees the raw timeout.

Limits, stated plainly:

- **`ErrChannelLost` does not cover the common crash.** A peer killed with `SIGKILL` surfaces as
  `io.EOF`, exactly as an orderly close does: Go reports an end of stream at a record boundary as
  `io.EOF` whether or not the peer sent its closing alert. The sentinel covers resets, broken
  pipes and TLS alerts. A crash and a close cannot be told apart by the error value.
- **A read deadline leaves the channel usable.** After the timeout the caller can clear or move
  the deadline and go on.
- **A write deadline that expires breaks the channel.** `crypto/tls` leaves the session corrupt
  after a write timed out; every later `Write` fails with the same timeout error. The channel must
  be discarded and a new one opened.

## Stability

The interface is frozen at **v1** (commit `d990ca3`, 2026-10-01).

### What is frozen

- **The exported surface.** Every exported identifier of `internal/atls` and its signature:
  functions, methods, types, struct fields, constants and sentinels, as listed in
  `internal/atls/api_v1.txt`.
- **The sentinel set and the meaning of each sentinel**, as the two tables under
  [Refusals](#refusals) state them, and the rule that a refusal matches exactly one sentinel.
- **The fail-closed guarantees** of
  [What a returned channel guarantees](#what-a-returned-channel-guarantees-fail-closed).
- **The defaults:** handshake timeout 10 s, channel lifetime 15 min, 8 concurrent handshakes.
- **The errors of an established channel**, as the section above states them.

### What is not frozen

- **Error texts.** The text of a sentinel, `Reason`, the text of the cause and the result of
  `Error()` may change. Match with `errors.Is`, never on text.
- **Internals.** Unexported identifiers, the classifier and its text patterns, the `Decided from`
  column, and the test-only packages `internal/atls/atlstest` and `internal/atls/internal/...`.
- **The CMC version.** The pin to v0.9.15 may move; the interface hides it. The limitations
  listed under [Known CMC v0.9.15 limitations](#known-cmc-v0915-limitations) describe that
  version.

### Errors that are not `*atls.Error`

Not every error this package returns is an `*atls.Error`:

| From | Error | Meaning |
|---|---|---|
| `Listen` | the error of package `net`, wrapped | the address could not be opened. An invalid `Config` is an `*atls.Error` matching `ErrConfig` |
| `Accept` | `ctx.Err()` | the caller's context ended before a channel or a refusal was ready |
| `Accept` | `net.ErrClosed` | the listener was closed |
| `Read`, `Write` | `io.EOF` | the peer closed the channel or died |
| `Read`, `Write` | a timeout error | a deadline of the caller expired |

Everything else `Dial`, `Accept`, `Read` and `Write` return is an `*atls.Error` matching exactly
one sentinel.

### Change policy

- **A difference is detected by the build.** `TestExportedAPIFrozen` regenerates the listing of
  the exported API and fails when it differs from `internal/atls/api_v1.txt`, naming each line
  that differs.
- **An additive change** — a new function, method, field, sentinel or constant — updates the
  listing and this document in the same change. It does not need agreement, and it does not
  change the version: the interface stays v1.
- **A removal, a changed signature, a changed default or a changed meaning of a sentinel** needs
  agreement under the interface-freeze process before it is made, and is recorded here with the
  commit and the date.
- **The listing is never updated alone.** A failing guard is resolved by deciding the change and
  updating the listing together with this document, not by regenerating the listing to make the
  test pass.

### Peer identity

`ExpectedPeerIdentity` names the one peer a channel accepts. The rules:

- **Recommended form: a URI SAN `spiffe://<zone trust domain>/<name>`**, for example
  `spiffe://zone-b.example/gateway`. A value that contains `://` is compared with the URI SANs of
  the peer's leaf certificate.
- **A DNS SAN is accepted.** A value without `://` is compared with the DNS SANs, ignoring case.
- **The match is exact.** The whole value must equal one SAN. There are no wildcards: a
  certificate for `*.zone-b.example` does not match `gateway.zone-b.example`.
- **IP SANs and the common name are never used.** Neither is the host name the peer was dialled
  at.
- One channel expects one identity. `Peer().Identity` reports it.

### Liveness is the caller's

- **The wrapper sends no keep-alives and no heartbeats** and sets no deadline on a returned
  channel. A peer that is frozen, or unreachable behind a partition, is invisible until the
  caller's own traffic shows it. The caller detects it with an application heartbeat and a read
  deadline; the read timeout arrives unwrapped and leaves the channel usable.
- **A write deadline that expires makes the channel unusable** (see above). A caller that bounds
  its writes must discard the channel after a write timeout.
- **The wrapper does not close a channel at `ValidUntil`.** It reports the time; the owner of the
  channel re-establishes it before then and closes the old one.
- **Losing this zone's `cmcd` is silent on open channels.** The attester is needed only during a
  handshake, so the loss shows at the next handshake as `ErrAttesterUnavailable`. `cmcd` v0.9.15
  has no health endpoint, and this interface offers no attester check; a check is a possible
  additive change.

### Handshake queue

Handshakes beyond `MaxConcurrentHandshakes` wait for a free slot. The wait and the handshake share
one budget: a connection that has waited and handshaken for `HandshakeTimeout` in total — or, for
`Dial`, until the caller's context ends, if sooner — is refused with `ErrHandshakeTimeout`. There
is no separate queue timeout and no limit on the number of waiting connections.

## Attester selection and builds

Production code sets `CmcdAddr` and attests through the zone's `cmcd`. The in-process CMC cannot be
selected from production code:

- the Config field that selects it is unexported;
- the hook that sets it lives in a package Go's internal-package rule restricts to
  `internal/atls/...`;
- `internal/atls/atlstest` panics outside a test binary, and `depguard` refuses it in non-test
  files.

CMC's default build links every TEE driver, and the SGX driver needs cgo. A binary built with
`CGO_ENABLED=0` must use the build tags `nodefaults,grpc`. They keep only the gRPC attester and
drop the in-process backend and the TEE drivers from the binary.

## Session loss: what each end observes

The session-loss proof (`scripts/atls-probe/prove-session-loss.sh`) runs two probe processes over this
interface, each with the real `cmcd` of its zone, and takes one thing away at a time. Its findings
are in
[reconnect-findings.md](evidences/cmc-atls-channel-binding/session-loss/reconnect-findings.md).
The run recorded there is local (one machine, loopback); a run on the target cluster is pending.

| What happens | What the surviving end gets | Refusal sentinel |
|---|---|---|
| The peer process is killed while the channel is open | The next `Read` returns `io.EOF` within milliseconds | none — `io.EOF`, unwrapped |
| This zone's `cmcd` is killed while the channel is open | Nothing. The channel keeps working; the attester is needed only during a handshake | none |
| A handshake while this zone's `cmcd` is down, or dies during the handshake | The handshake is refused within milliseconds | `ErrAttesterUnavailable` |
| A handshake while the *peer's* `cmcd` is down, or dies during the handshake | The handshake is refused: "the peer left without completing the attestation exchange" | `ErrPeerAborted` |
| The peer process is frozen (half-open channel) | No error within 15 s. Writes keep succeeding, reads wait. Only the missing heartbeats of the application show it. After the peer runs again the channel continues | none |
| A new handshake towards a frozen peer | The handshake is refused after `HandshakeTimeout` | `ErrHandshakeTimeout` |
| A new handshake towards a peer that is down | The handshake is refused at once | `ErrPeerUnreachable` |

In every scenario a new channel could be opened as soon as the missing process was back.

### What v1 decided for each error surface

The session-loss proof showed five error surfaces the draft interface did not express. v1 settles
each one:

| # | Error surface | Decision in v1 | Where |
|---|---|---|---|
| 1 | The loss of an established channel had no sentinel: `Read` and `Write` returned the errors of `crypto/tls` and `net` as they were | **Sentinel added, in part.** `ErrChannelLost` wraps every `Read` and `Write` error except `io.EOF` and timeouts. A killed peer still surfaces as `io.EOF`, like an orderly close; the two cannot be told apart | [Errors of an established channel](#errors-of-an-established-channel) |
| 2 | A half-open channel is not detected: a frozen peer raises no error, and TCP keep-alive does not show it because the kernel of a frozen process still acknowledges | **Left to the caller.** The wrapper sends no heartbeat and sets no deadline. The caller runs an application heartbeat with a read deadline. A network partition, where the peer's kernel is unreachable too, was not part of the run | [Liveness is the caller's](#liveness-is-the-callers) |
| 3 | A peer whose attester is unavailable was reported as `ErrPlainTLS`, which reads as "this peer does not speak attested TLS" | **Sentinel added.** `ErrPeerAborted` names a peer that completed TLS 1.3 with a valid zone certificate and left before the attestation exchange completed. CMC hides the peer's cause (limitation N7), so a peer with a zone certificate that never attests gets the same sentinel. The end whose own `cmcd` is down still gets `ErrAttesterUnavailable` | [Refusals](#refusals) |
| 4 | Losing the local `cmcd` is silent until the next handshake: with a rotation every 15 minutes it is first noticed when the rotation fails, while the old channel stays usable until its `ValidUntil` | **Documented only.** Noticing it earlier is a health check on `cmcd`, which v0.9.15 does not offer and this interface does not add. An attester check is a possible additive change | [Liveness is the caller's](#liveness-is-the-callers) |
| 5 | A refusal returned by `Accept` did not identify the peer | **Field added.** `Error.Peer` carries the transport address of the refused connection on every refusal `Accept` returns | [Interface](#interface) |

## Known CMC v0.9.15 limitations

The wrapper is built around the following behaviour of CMC v0.9.15. Findings marked *tested* are
pinned by regression tests in `internal/atls`, which drive CMC directly. If CMC changes, those tests
fail and the entry must be revisited.

| # | Behaviour | Effect without the wrapper | Mitigation in the wrapper | Residual |
|---|---|---|---|---|
| 1 | The listener sets a 10 s read/write deadline for the handshake and never clears it (*tested*) | Accepted connections fail their first read after 10 s | Deadline cleared after a successful handshake | none |
| 2 | The client bounds only TCP connect and TLS; the attestation phase has no deadline (*tested*) | `Dial` blocks indefinitely against a silent server | `Dial` bounded by context and `HandshakeTimeout` | the abandoned goroutine and socket live until the peer or keep-alive ends them; bounded by the handshake cap |
| 3 | `Accept` runs TLS and attestation inline | One slow client blocks all other accepts | One goroutine per connection | none |
| 4 | The result callback fires inside verification, on failure too, and before `Accept`/`Dial` return; `warn` counts as success; some failure paths produce no callback (*tested*) | Callers may trust a result of a failed handshake, or a `warn` | A result is trusted only after a handshake that returned without error; `warn` and missing results are refusals; one callback per connection | none |
| N1 | When the peer answers with an error, one goroutine per handshake blocks forever (*tested*) | Goroutine growth under repeated failing handshakes | None in the wrapper: the goroutine outlives the handshake, so the handshake cap does not bound it. Mutual TLS limits who can reach this phase to holders of a zone certificate | leaked goroutines accumulate, one per such handshake; upstream fix needed |
| N2 | Resource-exhaustion class issue in the attestation message framing, triggerable by a peer | Memory pressure from a single connection | Mutual TLS gates the phase; the handshake cap bounds concurrency; pod memory limits | not fixable in the wrapper (CMC requires the concrete TLS connection type). Details are withheld until coordinated disclosure with the contracting authority |
| N3 | Channel binding reads only `tls.Config.Certificates[0]` | A dynamic or second certificate breaks the binding | Exactly one static certificate required; certificate callbacks refused (`ErrConfig`) | none |
| N4 | The in-process backend re-initialises process-global TEE drivers on every call; the sw driver also writes state per report | Data races; with two zones in one process, a report can mix one zone's key and the other's signature | In-process backend is test-only. Test fixtures share one sw key across zones and serialise report generation; concurrency tests use the gRPC path | a `cmcd` serving concurrent sw-driver reports races internally. This concerns mock evidence only |
| N5 | On the peer-error path, the response and the handshake-complete message are written concurrently, and their frames can interleave | The peer may fail to parse and stall until its deadline | Wrapper deadlines bound this side | upstream fix needed |
| N6 | Attestation messages carry no type. When one side fails before sending its request, the other side parses its handshake-complete message as the request | The protocol desynchronises until CMC's 10 s deadline | `HandshakeTimeout` bounds the listener side | none beyond the timeout |
| N7 | CMC returns the real handshake error only when the handshake-complete exchange succeeds | A peer that leaves early hides the cause (for example a peer whose attester is down, or a plain-TLS peer) | Complete-stage failure without an attestation result on this side is reported as `ErrPeerAborted`; with a result, as `ErrNotAttested` | the precise cause is lost for peers that leave early |
| N8 | The client does not close the TLS connection when attestation fails (code reading) | Socket held until garbage collection | none possible; the peer closes its end | upstream fix needed |
| N9 | A failed TLS dial dereferences the certificate's parsed leaf without a nil check (code reading) | A certificate without a parsed leaf panics the dialing goroutine | The wrapper always sets the parsed leaf | none |

Findings 1 to 4 and N1 were first established by reading the code; the regression tests confirmed
all five. N4 to N7 were found while testing the wrapper.
