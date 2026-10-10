package atls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

func selfSigned(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "peer"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// successResult is a verifier result for leaf whose metadata is valid until notAfter.
func successResult(leaf *x509.Certificate, notAfter time.Time) *ar.AttestationResult {
	r := &ar.AttestationResult{Summary: ar.Result{Status: ar.StatusSuccess}}
	r.Prover.PeerId = fingerprint(leaf)
	r.Metadata.ImageDescriptionResult.Validity = &ar.Validity{
		NotBefore: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		NotAfter:  notAfter.UTC().Format(time.RFC3339),
	}
	return r
}

func recorded(results ...*ar.AttestationResult) *recorder {
	rec := newRecorder(nil)
	for _, r := range results {
		rec.callback(r)
	}
	return rec
}

func TestJudgeSuccess(t *testing.T) {
	leaf := selfSigned(t)
	end := time.Now().Add(time.Hour).Truncate(time.Second)
	pa, err := judge(recorded(successResult(leaf, end)), leaf, 15*time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if pa.Verdict != VerdictSuccess || pa.PeerID != fingerprint(leaf) || !pa.EvidenceNotAfter.Equal(end) {
		t.Fatalf("unexpected peer attestation %+v", pa)
	}
}

func TestJudgeWarnIsRefused(t *testing.T) {
	leaf := selfSigned(t)
	r := successResult(leaf, time.Now().Add(time.Hour))
	r.Summary.Status = ar.StatusWarn
	_, err := judge(recorded(r), leaf, time.Minute, time.Now())
	if !errors.Is(err, ErrNotAttested) {
		t.Fatalf("warn: got %v", err)
	}
}

func TestJudgeMissingResultIsRefused(t *testing.T) {
	leaf := selfSigned(t)
	_, err := judge(recorded(), leaf, time.Minute, time.Now())
	if !errors.Is(err, ErrNotAttested) {
		t.Fatalf("missing result: got %v", err)
	}
}

func TestJudgeResultOfAnotherPeerIsRefused(t *testing.T) {
	leaf, other := selfSigned(t), selfSigned(t)
	_, err := judge(recorded(successResult(other, time.Now().Add(time.Hour))), leaf, time.Minute, time.Now())
	if !errors.Is(err, ErrNotAttested) {
		t.Fatalf("foreign result: got %v", err)
	}
}

func TestJudgeTwoResultsAreRefused(t *testing.T) {
	leaf := selfSigned(t)
	r := successResult(leaf, time.Now().Add(time.Hour))
	_, err := judge(recorded(r, r), leaf, time.Minute, time.Now())
	if !errors.Is(err, ErrNotAttested) {
		t.Fatalf("two results: got %v", err)
	}
}

// TestJudgeExpiredEvidence: evidence whose validity ended after CMC checked it, but before the
// wrapper returns the connection, is refused.
func TestJudgeExpiredEvidence(t *testing.T) {
	leaf := selfSigned(t)
	end := time.Now().Add(time.Second).Truncate(time.Second)
	_, err := judge(recorded(successResult(leaf, end)), leaf, time.Minute, end.Add(time.Second))
	if !errors.Is(err, ErrEvidenceExpired) {
		t.Fatalf("expired: got %v", err)
	}
}

func TestValidUntilOrderings(t *testing.T) {
	at := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	life := 15 * time.Minute
	if got := validUntil(at, life, at.Add(time.Hour)); !got.Equal(at.Add(life)) {
		t.Fatalf("lifetime first: got %v", got)
	}
	if got := validUntil(at, life, at.Add(5*time.Minute)); !got.Equal(at.Add(5 * time.Minute)) {
		t.Fatalf("evidence first: got %v", got)
	}
	if got := validUntil(at, life, time.Time{}); !got.Equal(at.Add(life)) {
		t.Fatalf("no evidence end: got %v", got)
	}
}

func TestEvidenceNotAfterTakesEarliest(t *testing.T) {
	leaf := selfSigned(t)
	r := successResult(leaf, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	r.Metadata.ManifestResults = []ar.MetadataResult{{}}
	r.Metadata.ManifestResults[0].Validity = &ar.Validity{NotAfter: "2029-01-01T00:00:00Z"}
	signerEnd := time.Date(2028, 6, 1, 0, 0, 0, 0, time.UTC)
	r.Metadata.ManifestResults[0].SignatureCheck = []ar.SignatureResult{{
		Certs: [][]ar.X509CertExtracted{{{Validity: ar.Validity{NotAfter: signerEnd.String()}}}},
	}}
	if got := evidenceNotAfter(r); !got.Equal(signerEnd) {
		t.Fatalf("got %v, want the signer certificate end %v", got, signerEnd)
	}
}

func TestGateCapsConcurrency(t *testing.T) {
	g := newGate()
	const limit, workers = 3, 20
	var cur, peak atomic.Int64
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := g.acquire(context.Background(), limit); err != nil {
				t.Error(err)
				return
			}
			n := cur.Add(1)
			for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
			}
			time.Sleep(5 * time.Millisecond)
			cur.Add(-1)
			g.release()
		}()
	}
	wg.Wait()
	if peak.Load() > limit || g.peak.Load() > limit {
		t.Fatalf("peak %d / gate peak %d above limit %d", peak.Load(), g.peak.Load(), limit)
	}
}

func TestGateWaitEndsWithContext(t *testing.T) {
	g := newGate()
	if err := g.acquire(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := g.acquire(ctx, 1); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}
