package atls

import (
	"crypto/x509"
	"errors"
	"testing"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

// An end that does not attest its peer refuses a handshake that produced any attestation result,
// even a successful one for the right peer.
func TestUnattestedRefusesAnyResult(t *testing.T) {
	leaf := &x509.Certificate{Raw: []byte("peer leaf")}
	rec := newRecorder(nil)
	res := &ar.AttestationResult{}
	res.Summary.Status = ar.StatusSuccess
	res.Prover.PeerId = fingerprint(leaf)
	rec.callback(res)
	if _, err := unattested(rec, leaf, time.Minute, time.Now()); !errors.Is(err, ErrNotAttested) {
		t.Fatalf("a result on a non-verifying end: %v", err)
	}
	p, err := unattested(newRecorder(nil), leaf, time.Minute, time.Unix(100, 0))
	if err != nil || p.Verdict != VerdictNotAttested || p.PeerID != fingerprint(leaf) || !p.ValidUntil.Equal(time.Unix(160, 0)) || !p.AttestedAt.IsZero() {
		t.Fatalf("no result: %+v, %v", p, err)
	}
}
