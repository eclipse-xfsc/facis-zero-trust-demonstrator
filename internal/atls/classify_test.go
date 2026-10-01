package atls

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

// pinnedSource maps every text pattern the classifier relies on to the CMC v0.9.15 file that
// produces it, or to "go" for texts produced by the Go standard library (crypto/tls, net) that
// CMC wraps. A CMC upgrade that rewords one of these fails TestPatternsArePinnedInCMC.
var pinnedSource = map[string]string{
	"atls response returned error:":                   "attestedtls/attestation.go",
	"reports failed attestation:":                     "attestedtls/attestation.go",
	"failed to fetch peer cache":                      "attestedtls/attestation.go",
	"could not obtain attestation result":             "attestedtls/grpc.go",
	"failed to obtain AR":                             "attestedtls/grpc.go",
	"failed to initialize CMC":                        "attestedtls/libapi.go",
	"failed to establish connection":                  "attestedtls/grpc.go",
	"mismatching attestation mode":                    "attestedtls/attestation.go",
	"failed to establish tls connection":              "attestedtls/dialer.go",
	"TLS handshake failed":                            "attestedtls/listener.go",
	"failed to receive attestation request":           "attestedtls/attestation.go",
	"failed to send atls handshake request":           "attestedtls/attestation.go",
	"API version mismatch":                            "attestedtls/attestation.go",
	"failed to send handshake complete":               "attestedtls/attestation.go",
	"failed to receive handshake complete":            "attestedtls/attestation.go",
	"message length is zero":                          "attestedtls/backend.go",
	"dial tcp":                                        "go",
	"connection refused":                              "go",
	"no such host":                                    "go",
	"network is unreachable":                          "go",
	"x509:":                                           "go",
	"bad certificate":                                 "go",
	"unknown certificate":                             "go",
	"certificate required":                            "go",
	"certificate unknown":                             "go",
	"expired certificate":                             "go",
	"revoked certificate":                             "go",
	"unsupported certificate":                         "go",
	"didn't provide a certificate":                    "go",
	"protocol version":                                "go",
	"unsupported versions":                            "go",
	"first record does not look like a TLS handshake": "go",
	"i/o timeout":                                     "go",
	"deadline exceeded":                               "go",
}

func cmcDir(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/Fraunhofer-AISEC/cmc").Output()
	if err != nil {
		t.Fatalf("locate CMC module: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// TestPatternsArePinnedInCMC checks that every classifier pattern is pinned, and that each CMC
// pattern still occurs in the CMC source the module builds against.
func TestPatternsArePinnedInCMC(t *testing.T) {
	var all []string
	all = append(all, peerTextMarkers...)
	for _, r := range textRules {
		all = append(all, r.patterns...)
	}
	dir := cmcDir(t)
	if !strings.HasSuffix(dir, "@v0.9.15") {
		t.Fatalf("classifier patterns are pinned against CMC v0.9.15, module resolves to %s", dir)
	}
	for _, p := range all {
		src, ok := pinnedSource[p]
		if !ok {
			t.Errorf("pattern %q is not pinned to a source", p)
			continue
		}
		if src == "go" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, src))
		if err != nil {
			t.Fatalf("read %s: %v", src, err)
		}
		if !strings.Contains(string(data), p) {
			t.Errorf("pattern %q no longer occurs in CMC %s", p, src)
		}
	}
}

// TestResultErrorCodesArePinned pins the numeric CMC error codes the classifier reads. Over gRPC
// the result travels as JSON with numeric codes, so cmcd and wrapper must agree on the values.
func TestResultErrorCodesArePinned(t *testing.T) {
	if ar.Freshness != 83 || ar.Expired != 11 {
		t.Fatalf("CMC error codes moved: Freshness=%d (want 83), Expired=%d (want 11)", ar.Freshness, ar.Expired)
	}
	var r ar.AttestationResult
	if err := json.Unmarshal([]byte(`{"summary":{"status":"fail","errorCodes":[83]},"freshness":{"status":"fail"}}`), &r); err != nil {
		t.Fatal(err)
	}
	if got := fromResult(&r); !errors.Is(got, ErrBindingMismatch) {
		t.Fatalf("JSON result with code 83: got %v", got)
	}
}

// Messages below are what CMC v0.9.15 returns, assembled from its format strings with sample
// addresses. One test per sentinel.

func assertKind(t *testing.T, err error, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
	for _, s := range allSentinels {
		if s != want && errors.Is(err, s) {
			t.Fatalf("%v also matches %v", err, s)
		}
	}
	if strings.TrimSpace(err.Error()) == "" {
		t.Fatal("empty message")
	}
}

var allSentinels = []error{
	ErrNotAttested, ErrBindingMismatch, ErrEvidenceExpired, ErrIdentityMismatch, ErrPlainTLS,
	ErrPeerAborted, ErrAttestModeMismatch, ErrAttesterUnavailable, ErrHandshakeTimeout,
	ErrPeerRejected, ErrPeerUnreachable, ErrConfig, ErrChannelLost,
}

func TestClassifyNotAttested(t *testing.T) {
	for _, msg := range []string{
		// dialer.go + attestation.go: own verification failed (libapi/grpc verifyAR default case).
		"atls handshake failed: 127.0.0.1:1: attestation with peer 127.0.0.1:2 failed: verifier 127.0.0.1:1: failed to attest 127.0.0.1:2: attestation report verification failed",
		// The peer could not verify this end.
		"atls handshake failed: 127.0.0.1:1: peer 127.0.0.1:2 reports failed attestation: verifier 127.0.0.1:2: failed to attest 127.0.0.1:1: attestation report verification failed",
		// The peer's attester is down: its error arrives in the response. Not our attester.
		"atls handshake failed: 127.0.0.1:1: attestation with peer 127.0.0.1:2 failed: atls response returned error: internal error: prover 127.0.0.1:2: could not obtain own AR: failed to obtain AR: rpc error: code = Unavailable",
	} {
		assertKind(t, Classify(errors.New(msg)), ErrNotAttested)
	}
	// The peer hung up after this side had verified it.
	msg := "atls handshake failed: 127.0.0.1:1: failed to receive handshake complete from 127.0.0.1:2: failed to read handshake complete: failed to receive message: no length: EOF"
	assertKind(t, fromTextWith(errors.New(msg), true), ErrNotAttested)
}

func TestClassifyBindingMismatch(t *testing.T) {
	r := &ar.AttestationResult{}
	r.Summary.Fail(ar.Freshness)
	r.Freshness.Status = ar.StatusFail
	assertKind(t, fromResult(r), ErrBindingMismatch)
}

func TestClassifyEvidenceExpired(t *testing.T) {
	r := &ar.AttestationResult{}
	r.Summary.Fail(ar.VerifyMetadata)
	r.Freshness.Status = ar.StatusSuccess
	r.Metadata.ManifestResults = []ar.MetadataResult{{}}
	r.Metadata.ManifestResults[0].ValidityCheck.Fail(ar.Expired)
	assertKind(t, fromResult(r), ErrEvidenceExpired)

	// Not yet valid is not "expired".
	r2 := &ar.AttestationResult{}
	r2.Summary.Fail(ar.VerifyMetadata)
	r2.Freshness.Status = ar.StatusSuccess
	r2.Metadata.ImageDescriptionResult.ValidityCheck.Fail(ar.NotYetValid)
	assertKind(t, fromResult(r2), ErrNotAttested)
}

func TestClassifyIdentityMismatch(t *testing.T) {
	for _, msg := range []string{
		"failed to establish tls connection: tls: failed to verify certificate: x509: certificate signed by unknown authority. 1 certificate chain(s) provided: ",
		"TLS handshake failed: remote error: tls: bad certificate",
		"TLS handshake failed: tls: client didn't provide a certificate",
		"failed to establish tls connection: remote error: tls: certificate required. 1 certificate chain(s) provided: ",
	} {
		assertKind(t, Classify(errors.New(msg)), ErrIdentityMismatch)
	}
}

func TestClassifyPlainTLS(t *testing.T) {
	for _, msg := range []string{
		// listener.go + attestation.go: the peer closed after TLS without an aTLS request.
		"atls handshake failed: 127.0.0.1:1: attestation with peer 127.0.0.1:2 failed: prover 127.0.0.1:1: failed to receive attestation request from 127.0.0.1:2: failed to read response: failed to receive message: no length: EOF",
		// A well-framed message that is not an aTLS request.
		"atls handshake failed: 127.0.0.1:1: attestation with peer 127.0.0.1:2 failed: API version mismatch. Expected AtlsHandshakeRequest version 1.2.0, got ",
		// TLS version negotiation failure.
		"TLS handshake failed: tls: client offered only unsupported versions: [303]",
		"failed to establish tls connection: remote error: tls: protocol version not supported. 1 certificate chain(s) provided: ",
	} {
		assertKind(t, Classify(errors.New(msg)), ErrPlainTLS)
	}
}

// A peer that completed TLS 1.3 and left before the handshake-complete exchange, with no
// attestation result on this side. With a result, the same texts are ErrNotAttested
// (TestClassifyNotAttested).
func TestClassifyPeerAborted(t *testing.T) {
	for _, msg := range []string{
		// listener.go: the peer closed; CMC reports only the failed complete exchange.
		"atls handshake failed: 127.0.0.1:1: failed to send handshake complete to 127.0.0.1:2: failed to send: failed to write payload to 127.0.0.1:2: write tcp 127.0.0.1:1->127.0.0.1:2: write: broken pipe",
		"atls handshake failed: 127.0.0.1:1: failed to receive handshake complete from 127.0.0.1:2: failed to read handshake complete: failed to receive message: no length: EOF",
	} {
		assertKind(t, Classify(errors.New(msg)), ErrPeerAborted)
	}
}

func TestClassifyAttestModeMismatch(t *testing.T) {
	for _, msg := range []string{
		"atls handshake failed: 127.0.0.1:1: attestation with peer 127.0.0.1:2 failed: failed to check attestation mode: mismatching attestation mode, local set to: [mutual], while remote is set to: [client]",
		"atls handshake failed: 127.0.0.1:1: peer 127.0.0.1:2 reports failed attestation: failed to check attestation mode: mismatching attestation mode, local set to: [client], while remote is set to: [mutual]",
	} {
		assertKind(t, Classify(errors.New(msg)), ErrAttestModeMismatch)
	}
}

func TestClassifyAttesterUnavailable(t *testing.T) {
	for _, msg := range []string{
		`atls handshake failed: 127.0.0.1:1: attestation with peer 127.0.0.1:2 failed: failed to fetch peer cache: failed to fetch peer cache: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 127.0.0.1:9: connect: connection refused"`,
		"atls handshake failed: 127.0.0.1:1: attestation with peer 127.0.0.1:2 failed: verifier 127.0.0.1:1: failed to attest 127.0.0.1:2: could not obtain attestation result: rpc error: code = DeadlineExceeded desc = context deadline exceeded",
		"atls handshake failed: 127.0.0.1:1: attestation with peer 127.0.0.1:2 failed: failed to fetch peer cache: failed to initialize CMC: failed to read trusted root CA certificates",
	} {
		assertKind(t, Classify(errors.New(msg)), ErrAttesterUnavailable)
	}
}

func TestClassifyHandshakeTimeout(t *testing.T) {
	msg := "atls handshake failed: 127.0.0.1:1: attestation with peer 127.0.0.1:2 failed: prover 127.0.0.1:1: failed to receive attestation request from 127.0.0.1:2: failed to read response: failed to receive message: no length: read tcp 127.0.0.1:1->127.0.0.1:2: i/o timeout"
	assertKind(t, Classify(errors.New(msg)), ErrHandshakeTimeout)

	// A handshake the wrapper aborted on its own deadline, whatever CMC reported.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assertKind(t, classify(errors.New("use of closed network connection"), newRecorder(nil), true, ctx), ErrHandshakeTimeout)
}

func TestClassifyPeerRejected(t *testing.T) {
	// ErrPeerRejected comes from the wrapper's own PeerVerifier step, never from CMC text.
	cause := errors.New("not on the trust list")
	err := refuse(ErrPeerRejected, "the peer verifier refused the attested peer", cause)
	assertKind(t, err, ErrPeerRejected)
	if !errors.Is(err, cause) {
		t.Fatal("verifier error not inspectable")
	}
}

func TestClassifyPeerUnreachable(t *testing.T) {
	msg := "failed to establish tls connection: dial tcp 127.0.0.1:9: connect: connection refused. 1 certificate chain(s) provided: CN=x"
	assertKind(t, Classify(errors.New(msg)), ErrPeerUnreachable)
}

// TestPeerTextCannotClaimLocalFailure: text the peer sends never turns into a local-attester,
// timeout or TLS classification.
func TestPeerTextCannotClaimLocalFailure(t *testing.T) {
	msg := "atls handshake failed: 127.0.0.1:1: peer 127.0.0.1:2 reports failed attestation: i/o timeout failed to fetch peer cache x509: dial tcp"
	assertKind(t, Classify(errors.New(msg)), ErrNotAttested)
}

// TestNoBareCMCError: the cause of a classified CMC error is plain text.
func TestNoBareCMCError(t *testing.T) {
	type cmcish struct{ error }
	err := Classify(cmcish{errors.New("attestation report verification failed")})
	var c cmcish
	if errors.As(err, &c) {
		t.Fatal("CMC error type leaked through the wrapper error")
	}
}
