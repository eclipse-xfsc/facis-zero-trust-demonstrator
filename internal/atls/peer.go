package atls

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"slices"
	"sync"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

// Verdict is the outcome of the peer's attestation. A returned connection always carries
// VerdictSuccess; any other outcome refuses the channel.
type Verdict string

// VerdictSuccess is the only verdict a returned connection carries.
const VerdictSuccess Verdict = "success"

// Measurement is one verified measurement from the peer's evidence.
type Measurement struct {
	// Evidence is the evidence type the measurement belongs to, for example "SW Result".
	Evidence string
	// Name identifies the measured component when the evidence names it.
	Name string
	// Index is the register or position of the measurement.
	Index int
	// Digest is the measured digest, hex encoded.
	Digest string
	// HashAlg names the digest algorithm when the evidence states it.
	HashAlg string
}

// PeerAttestation is what an established channel knows about its peer.
type PeerAttestation struct {
	// Verdict is always VerdictSuccess on a returned connection.
	Verdict Verdict
	// PeerID is the hex SHA-256 fingerprint of the peer's TLS leaf certificate.
	PeerID string
	// Identity is the identity the peer's certificate matched: the configured
	// Config.ExpectedPeerIdentity, a URI SAN or a DNS SAN.
	Identity string
	// Measurements are the verified measurements of the peer's evidence.
	Measurements []Measurement
	// AttestedAt is when this end received the verification result.
	AttestedAt time.Time
	// EvidenceNotAfter is the validity end of the peer's evidence, zero when the result
	// states none.
	EvidenceNotAfter time.Time
	// ValidUntil is the earlier of AttestedAt plus the channel lifetime and EvidenceNotAfter.
	// The channel must be re-established before this time.
	ValidUntil time.Time
}

// PeerVerifier decides, after a successful attestation, whether the attested peer may connect.
// It is the extension point for trust-list checks. Any error refuses the channel with
// ErrPeerRejected wrapping that error.
type PeerVerifier interface {
	VerifyPeer(ctx context.Context, peer PeerAttestation) error
}

// PeerVerifierFunc adapts a function to PeerVerifier.
type PeerVerifierFunc func(ctx context.Context, peer PeerAttestation) error

// VerifyPeer calls f.
func (f PeerVerifierFunc) VerifyPeer(ctx context.Context, peer PeerAttestation) error {
	return f(ctx, peer)
}

// recorder receives CMC's attestation results for one handshake.
type recorder struct {
	mu       sync.Mutex
	results  []*ar.AttestationResult
	at       time.Time
	first    chan struct{}
	rewrite  func(*ar.AttestationResult) bool
	identity error
}

func newRecorder(rewrite func(*ar.AttestationResult) bool) *recorder {
	return &recorder{first: make(chan struct{}), rewrite: rewrite}
}

// callback is the per-connection CMC result callback.
func (r *recorder) callback(res *ar.AttestationResult) {
	if res == nil {
		return
	}
	if r.rewrite != nil && !r.rewrite(res) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.results = append(r.results, res)
	if len(r.results) == 1 {
		r.at = time.Now()
		close(r.first)
	}
}

func (r *recorder) setIdentityErr(err error) {
	r.mu.Lock()
	r.identity = err
	r.mu.Unlock()
}

func (r *recorder) identityErr() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.identity
}

// snapshot returns the recorded results and the time of the first.
func (r *recorder) snapshot() ([]*ar.AttestationResult, time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.results), r.at
}

// lastFailed returns the last recorded result whose status is not success, or nil.
func (r *recorder) lastFailed() *ar.AttestationResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.results) - 1; i >= 0; i-- {
		if r.results[i].Summary.Status != ar.StatusSuccess {
			return r.results[i]
		}
	}
	return nil
}

// judge applies the fail-closed verdict rules to a handshake that CMC completed without error:
// exactly one result, verdict success, for this peer, evidence still valid.
func judge(rec *recorder, peerLeaf *x509.Certificate, lifetime time.Duration, now time.Time) (PeerAttestation, error) {
	results, at := rec.snapshot()
	if len(results) == 0 {
		return PeerAttestation{}, refuse(ErrNotAttested, "the handshake produced no attestation result for the peer", nil)
	}
	if len(results) > 1 {
		return PeerAttestation{}, refuse(ErrNotAttested,
			fmt.Sprintf("the handshake produced %d attestation results for one peer", len(results)), nil)
	}
	res := results[0]
	if res.Summary.Status != ar.StatusSuccess {
		return PeerAttestation{}, refuse(ErrNotAttested,
			fmt.Sprintf("attestation verdict is %q, only %q is accepted", res.Summary.Status, ar.StatusSuccess), nil)
	}
	if peerLeaf == nil {
		return PeerAttestation{}, refuse(ErrNotAttested, "peer presented no certificate", nil)
	}
	fp := fingerprint(peerLeaf)
	if res.Prover.PeerId != fp {
		return PeerAttestation{}, refuse(ErrNotAttested,
			"the attestation result does not belong to the peer of this connection", nil)
	}
	pa := PeerAttestation{
		Verdict:      VerdictSuccess,
		PeerID:       fp,
		Measurements: measurements(res),
		AttestedAt:   at,
	}
	pa.EvidenceNotAfter = evidenceNotAfter(res)
	pa.ValidUntil = validUntil(at, lifetime, pa.EvidenceNotAfter)
	if !pa.EvidenceNotAfter.IsZero() && !pa.EvidenceNotAfter.After(now) {
		return PeerAttestation{}, refuse(ErrEvidenceExpired,
			fmt.Sprintf("peer evidence expired at %s", pa.EvidenceNotAfter.UTC().Format(time.RFC3339)), nil)
	}
	return pa, nil
}

func fingerprint(leaf *x509.Certificate) string {
	f := sha256.Sum256(leaf.Raw)
	return hex.EncodeToString(f[:])
}

// validUntil is min(attestedAt + lifetime, evidenceEnd); a zero evidenceEnd means none stated.
func validUntil(attestedAt time.Time, lifetime time.Duration, evidenceEnd time.Time) time.Time {
	end := attestedAt.Add(lifetime)
	if !evidenceEnd.IsZero() && evidenceEnd.Before(end) {
		return evidenceEnd
	}
	return end
}

// certTimeLayout is how CMC renders certificate validity (time.Time.String()).
const certTimeLayout = "2006-01-02 15:04:05.999999999 -0700 MST"

// evidenceNotAfter returns the earliest validity end stated in the result: the signed metadata
// (image description, manifests, company description) and the certificates that signed the
// metadata and the evidence. Zero when none is stated.
func evidenceNotAfter(res *ar.AttestationResult) time.Time {
	var end time.Time
	take := func(t time.Time) {
		if !t.IsZero() && (end.IsZero() || t.Before(end)) {
			end = t
		}
	}
	meta := func(m *ar.MetadataResult) {
		if m == nil {
			return
		}
		if m.Validity != nil {
			if t, err := time.Parse(time.RFC3339, m.Validity.NotAfter); err == nil {
				take(t)
			}
		}
		for _, s := range m.SignatureCheck {
			take(certsNotAfter(s))
		}
	}
	meta(&res.Metadata.ImageDescriptionResult)
	for i := range res.Metadata.ManifestResults {
		meta(&res.Metadata.ManifestResults[i])
	}
	meta(res.Metadata.CompanyDescriptionResult)
	for _, m := range res.Measurements {
		take(certsNotAfter(m.Signature))
	}
	return end
}

func certsNotAfter(s ar.SignatureResult) time.Time {
	var end time.Time
	for _, chain := range s.Certs {
		for _, c := range chain {
			t, err := time.Parse(certTimeLayout, c.Validity.NotAfter)
			if err != nil {
				continue
			}
			if end.IsZero() || t.Before(end) {
				end = t
			}
		}
	}
	return end
}

func measurements(res *ar.AttestationResult) []Measurement {
	var out []Measurement
	for _, m := range res.Measurements {
		for _, a := range m.Artifacts {
			if !a.Success {
				continue
			}
			out = append(out, Measurement{
				Evidence: m.Type,
				Name:     a.Name,
				Index:    a.Index,
				Digest:   hex.EncodeToString(a.Digest),
				HashAlg:  a.HashAlg,
			})
		}
	}
	return out
}
