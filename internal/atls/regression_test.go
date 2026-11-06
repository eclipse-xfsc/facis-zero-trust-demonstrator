package atls_test

// Regression tests that pin CMC v0.9.15 behaviour the wrapper is built around. They drive CMC's
// attestedtls package directly, through its in-process (libapi) backend, without the wrapper.
// If one of them fails after a CMC upgrade, the finding no longer holds: revisit design.md and
// the wrapper code that neutralises it before changing the test.

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/Fraunhofer-AISEC/cmc/cmc"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls/atlstest"
)

// libapiMu keeps handshakes through CMC's in-process backend of different tests apart: libapi
// re-initialises process-global drivers on every call (finding N4). Tests hold it only while
// CMC is working, not while they wait. Only the in-process backend shares the global driver: the
// stand-in cmcd of every atlstest zone attests with a private sw driver, so handshakes over gRPC
// need no lock (TestStandInCmcdIsolatedFromGlobalDriver).
var libapiMu sync.Mutex

func cmcOptions(z *atlstest.Zone, cb func(*ar.AttestationResult)) []attestedtls.ConnectionOption[attestedtls.CmcConfig] {
	ser, err := ar.NewJsonSerializer()
	if err != nil {
		panic(err)
	}
	opts := []attestedtls.ConnectionOption[attestedtls.CmcConfig]{
		attestedtls.WithCmcApi("libapi"),
		attestedtls.WithLibApiCmcConfig(z.LibAPIConfig()),
		attestedtls.WithAttest(attestedtls.Attest_Mutual),
		attestedtls.WithMtls(true),
		attestedtls.WithSerializer(ser),
	}
	if cb != nil {
		opts = append(opts, attestedtls.WithResultCb(cb))
	}
	return opts
}

func cmcServerTLS(z *atlstest.Zone) *tls.Config {
	c := z.TLSConfig()
	c.MinVersion = tls.VersionTLS13
	c.ClientAuth = tls.RequireAndVerifyClientCert
	return c
}

func cmcClientTLS(z *atlstest.Zone) *tls.Config {
	c := z.TLSConfig()
	c.MinVersion = tls.VersionTLS13
	c.ServerName = "localhost"
	return c
}

type cmcAccepted struct {
	conn *tls.Conn
	err  error
}

// cmcPair runs one CMC-only handshake (CMC Listen/Dial, libapi) and returns both ends' outcome.
func cmcPair(t *testing.T, server, client *atlstest.Zone, serverCb, clientCb func(*ar.AttestationResult)) (*tls.Conn, cmcAccepted, error) {
	t.Helper()
	libapiMu.Lock()
	defer libapiMu.Unlock()
	ln, err := attestedtls.Listen("tcp", "127.0.0.1:0", cmcServerTLS(server), cmcOptions(server, serverCb)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	acc := make(chan cmcAccepted, 1)
	go func() {
		c, err := ln.Accept()
		if c != nil {
			acc <- cmcAccepted{c.(*tls.Conn), err}
			return
		}
		acc <- cmcAccepted{nil, err}
	}()
	c, err := attestedtls.Dial("tcp", ln.Addr().String(), cmcClientTLS(client), cmcOptions(client, clientCb)...)
	if c != nil {
		t.Cleanup(func() { _ = c.Close() })
	}
	a := <-acc
	if a.conn != nil {
		t.Cleanup(func() { _ = a.conn.Close() })
	}
	return c, a, err
}

// Finding 1: CMC's listener sets a 10 s read/write deadline for its handshake
// (attestedtls/listener.go) and never clears it, so an accepted connection fails its first read
// after 10 s. The wrapper clears the deadline after a successful handshake.
func TestCMCFinding1ServerDeadlineNotReset(t *testing.T) {
	skipLibAPIUnderRace(t)
	if testing.Short() {
		t.Skip("waits 11 s")
	}
	t.Parallel()
	f := newFixture(t)
	cli, srv, err := cmcPair(t, f.b, f.a, nil, nil)
	if err != nil || srv.err != nil {
		t.Fatalf("handshake: client %v, server %v", err, srv.err)
	}
	time.Sleep(11 * time.Second)
	go func() { _, _ = cli.Write([]byte("ping")) }()
	buf := make([]byte, 4)
	_, err = srv.conn.Read(buf)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("finding 1 no longer holds: read after 11 s returned %v, want a deadline error", err)
	}
}

// Finding 2: CMC's Dial bounds only TCP connect and TLS (attestedtls/dialer.go); the attestation
// phase has no deadline, so a server that completes TLS and stays silent blocks Dial
// indefinitely. The wrapper bounds Dial by the caller's context and its handshake timeout.
func TestCMCFinding2ClientAttestationPhaseUnbounded(t *testing.T) {
	skipLibAPIUnderRace(t)
	if testing.Short() {
		t.Skip("waits 31 s")
	}
	t.Parallel()
	f := newFixture(t)
	requestRead := make(chan struct{})
	release := make(chan struct{})
	addr := fakeTLSServer(t, f.b, func(c *tls.Conn) {
		recvMsg(t, c) // the client's attestation request; then silence
		close(requestRead)
		<-release
		_ = c.Close()
	})

	libapiMu.Lock()
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		c, err := attestedtls.Dial("tcp", addr, cmcClientTLS(f.a), cmcOptions(f.a, nil)...)
		if c != nil {
			_ = c.Close()
		}
		done <- err
	}()
	select {
	case <-requestRead:
	case <-time.After(10 * time.Second):
	}
	libapiMu.Unlock()

	select {
	case err := <-done:
		t.Fatalf("finding 2 no longer holds: Dial returned after %v: %v", time.Since(start), err)
	case <-time.After(31 * time.Second):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Dial did not return after the server closed")
	}
}

// Finding 4: CMC hands the result to the callback inside its verifier call — on failure too, and
// before Accept/Dial return — and treats a warn verdict as success. The wrapper trusts a result
// only when the handshake returned without error, and refuses warn.
func TestCMCFinding4CallbackOnFailureBeforeReturn(t *testing.T) {
	skipLibAPIUnderRace(t)
	// Zone a's evidence is expired, so the server's verification of a fails.
	f := newFixture(t, atlstest.WithEvidenceValidity(time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)))
	var returned atomic.Bool
	var mu sync.Mutex
	var statuses []ar.Status
	var beforeReturn []bool
	serverCb := func(r *ar.AttestationResult) {
		mu.Lock()
		defer mu.Unlock()
		statuses = append(statuses, r.Summary.Status)
		beforeReturn = append(beforeReturn, !returned.Load())
	}

	libapiMu.Lock()
	ln, err := attestedtls.Listen("tcp", "127.0.0.1:0", cmcServerTLS(f.b), cmcOptions(f.b, serverCb)...)
	if err != nil {
		libapiMu.Unlock()
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	acc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		returned.Store(true)
		if c != nil {
			_ = c.Close()
		}
		acc <- err
	}()
	c, _ := attestedtls.Dial("tcp", ln.Addr().String(), cmcClientTLS(f.a), cmcOptions(f.a, nil)...)
	if c != nil {
		_ = c.Close()
	}
	acceptErr := <-acc
	libapiMu.Unlock()

	if acceptErr == nil {
		t.Fatal("expected CMC to refuse the expired client")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(statuses) != 1 || statuses[0] != ar.StatusFail || !beforeReturn[0] {
		t.Fatalf("finding 4 no longer holds: callback statuses %v, before Accept returned %v", statuses, beforeReturn)
	}
}

func TestCMCFinding4WarnIsSuccess(t *testing.T) {
	skipLibAPIUnderRace(t)
	f := newFixture(t)
	var dialReturned atomic.Bool
	var cbBeforeReturn atomic.Bool
	// The verifier's own result for the server is success; turning it into warn in the callback
	// is exactly what CMC's verifyAR switch then sees (it evaluates the status after the callback).
	clientCb := func(r *ar.AttestationResult) {
		r.Summary.Status = ar.StatusWarn
		cbBeforeReturn.Store(!dialReturned.Load())
	}
	cli, srv, err := cmcPair(t, f.b, f.a, nil, clientCb)
	dialReturned.Store(true)
	if err != nil || cli == nil || srv.err != nil {
		t.Fatalf("finding 4 no longer holds: warn verdict refused by CMC: client %v, server %v", err, srv.err)
	}
	if !cbBeforeReturn.Load() {
		t.Fatal("finding 4 no longer holds: callback did not run before Dial returned")
	}
}

// Finding N1: when the peer's response carries an error, CMC returns early and the goroutine that
// sends the own response blocks forever on an unbuffered channel (attestedtls/attestation.go):
// one leaked goroutine per such handshake. No result callback fires on that path either. The
// wrapper cannot free the goroutine; its handshake cap bounds how many can pile up.
func TestCMCFindingN1GoroutineLeakOnPeerError(t *testing.T) {
	skipLibAPIUnderRace(t)
	f := newFixture(t)
	addr := fakeTLSServer(t, f.b, func(c *tls.Conn) {
		defer func() { _ = c.Close() }()
		sendMsg(t, c, attestedtls.AtlsHandshakeRequest{Version: atlsVersion, Attest: attestedtls.Attest_Mutual})
		recvMsg(t, c) // client's request
		sendMsg(t, c, attestedtls.AtlsHandshakeResponse{Version: atlsVersion, Error: "fake peer refuses to attest"})
		sendMsg(t, c, attestedtls.AtlsHandshakeComplete{Version: atlsVersion, Success: false, Error: "fake peer refuses"})
		// Do not parse what the client sends now: on this path CMC writes its response and its
		// handshake-complete message concurrently and the frames can interleave (finding N5).
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.Copy(io.Discard, c)
	})

	before := leakedSenders()
	const handshakes = 3
	var callbacks atomic.Int32
	for range handshakes {
		libapiMu.Lock()
		c, err := attestedtls.Dial("tcp", addr, cmcClientTLS(f.a),
			cmcOptions(f.a, func(*ar.AttestationResult) { callbacks.Add(1) })...)
		libapiMu.Unlock()
		if c != nil {
			_ = c.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "atls response returned error") {
			t.Fatalf("expected CMC to fail on the peer's error response, got %v", err)
		}
	}
	var leaked int
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if leaked = leakedSenders() - before; leaked >= handshakes {
			break
		}
	}
	if leaked < handshakes {
		t.Fatalf("finding N1 no longer holds: %d handshakes with a peer error leaked %d goroutines", handshakes, leaked)
	}
	if callbacks.Load() != 0 {
		t.Fatalf("expected no result callback on the peer-error path, got %d", callbacks.Load())
	}
}

// Finding N4: CMC's in-process backend calls cmc.NewCmc on every call, which re-initialises the
// process-global sw driver from the calling zone's storage, without a lock. A stand-in cmcd that
// generated reports with that global driver could publish one key in a report's collateral and
// sign its evidence with another while an in-process handshake of another fixture ran, and the
// peer refused the report (the intermittent refusal of the parallel tests). Every atlstest zone
// now attests with a private sw driver: re-initialising CMC with two other fixtures'
// configurations in a loop must not disturb a third fixture's handshakes over gRPC.
func TestStandInCmcdIsolatedFromGlobalDriver(t *testing.T) {
	others := []*fixture{newFixture(t), newFixture(t)}
	f := newFixture(t)

	stop := make(chan struct{})
	var reinit sync.WaitGroup
	var reinits atomic.Int64
	reinit.Add(1)
	go func() {
		defer reinit.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			libapiMu.Lock()
			_, err := cmc.NewCmc(others[i%2].a.LibAPIConfig())
			libapiMu.Unlock()
			if err != nil {
				t.Errorf("re-initialise CMC: %v", err)
				return
			}
			reinits.Add(1)
		}
	}()
	defer func() { close(stop); reinit.Wait() }()

	ln := listen(t, f.b.Config(t, f.a))
	cc := f.a.Config(t, f.b)
	const handshakes = 200
	for i := range handshakes {
		acc := acceptOne(ln, 20*time.Second)
		c, err := dial(t, ln.Addr().String(), cc)
		a := <-acc
		if c != nil {
			_ = c.Close()
		}
		if a.conn != nil {
			_ = a.conn.Close()
		}
		if err != nil || a.err != nil {
			t.Fatalf("handshake %d of %d refused while CMC was re-initialised %d times: dial %v, accept %v",
				i+1, handshakes, reinits.Load(), err, a.err)
		}
	}
	if reinits.Load() == 0 {
		t.Fatal("CMC was never re-initialised during the handshakes")
	}
}

// leakedSenders counts goroutines blocked sending in CMC's handshake response goroutine.
func leakedSenders() int {
	buf := make([]byte, 1<<22)
	buf = buf[:runtime.Stack(buf, true)]
	n := 0
	for _, g := range bytes.Split(buf, []byte("\n\n")) {
		if bytes.Contains(g, []byte("[chan send")) && bytes.Contains(g, []byte("attestedtls.atlsHandshakeStart.func")) {
			n++
		}
	}
	return n
}

// Design D6: which AttestationResult fields carry the evidence validity end. CMC's result has no
// expiry of its own; the signed metadata carries Validity.NotAfter (RFC 3339) and the metadata
// signer certificates carry their validity (time.Time.String() layout). sw evidence is signed
// with a bare key and carries no certificate.
func TestCMCValidityFields(t *testing.T) {
	skipLibAPIUnderRace(t)
	f := newFixture(t)
	var res *ar.AttestationResult
	_, srv, err := cmcPair(t, f.b, f.a, nil, func(r *ar.AttestationResult) { res = r })
	if err != nil || srv.err != nil || res == nil {
		t.Fatalf("handshake: client %v, server %v, result %v", err, srv.err, res != nil)
	}
	want := f.b.EvidenceNotAfter.UTC().Format(time.RFC3339)

	img := res.Metadata.ImageDescriptionResult
	if img.Validity == nil || img.Validity.NotAfter != want {
		t.Fatalf("Metadata.ImageDescriptionResult.Validity.NotAfter = %+v, want %s", img.Validity, want)
	}
	if len(res.Metadata.ManifestResults) != 1 || res.Metadata.ManifestResults[0].Validity == nil ||
		res.Metadata.ManifestResults[0].Validity.NotAfter != want {
		t.Fatalf("Metadata.ManifestResults[].Validity.NotAfter missing or wrong: %+v", res.Metadata.ManifestResults)
	}
	if len(img.SignatureCheck) == 0 || len(img.SignatureCheck[0].Certs) == 0 || len(img.SignatureCheck[0].Certs[0]) == 0 {
		t.Fatal("metadata signature result carries no certificate chain")
	}
	signer := img.SignatureCheck[0].Certs[0][0].Validity.NotAfter
	if _, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", signer); err != nil {
		t.Fatalf("signer certificate NotAfter %q not in time.Time.String() layout: %v", signer, err)
	}
	for _, m := range res.Measurements {
		if len(m.Signature.Certs) != 0 {
			t.Fatalf("%s evidence unexpectedly carries a certificate chain", m.Type)
		}
	}
}
