package provision

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// swReport is a JSON report with one sw evidence whose JWS carries payload, plus extra members
// appended to the JWS object.
func swReport(t *testing.T, payload []byte, extra string) []byte {
	t.Helper()
	sig := make([]byte, 64)
	_, _ = rand.Read(sig)
	jws := `{"payload":"` + b64(payload) + `","signatures":[{"protected":"` + b64([]byte(`{"alg":"ES256"}`)) +
		`","signature":"` + b64(sig) + `"}]` + extra + `}`
	return marshalReport(t, []ar.Evidence{{Type: ar.TYPE_EVIDENCE_SW, Data: []byte(jws)}})
}

// marshalReport serializes a report with evs as CMC's prover does (context prepared first).
func marshalReport(t *testing.T, evs []ar.Evidence) []byte {
	t.Helper()
	ser, _ := ar.NewJsonSerializer()
	r := &ar.AttestationReport{Version: ar.GetReportVersion(), Type: ar.TYPE_ATTESTATION_REPORT, Encoding: ar.TYPE_ENCODING_B64, Evidences: evs}
	if _, err := r.PrepareContext(ser, crypto.SHA256); err != nil {
		t.Fatal(err)
	}
	raw, err := ser.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The aggregate is read with the parser CMC's verifier uses: a case-variant "Payload" member,
// which encoding/json would take, is ignored.
func TestSignedAggregateReadsTheVerifiedPayload(t *testing.T) {
	signed, _ := json.Marshal(ar.SwEvidence{Nonce: []byte{1}, Sha256: bytes.Repeat([]byte{0xaa}, 32)})
	unsigned, _ := json.Marshal(ar.SwEvidence{Nonce: []byte{1}, Sha256: bytes.Repeat([]byte{0xbb}, 32)})
	got, err := signedAggregate(swReport(t, signed, `,"Payload":"`+b64(unsigned)+`"`))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{0xaa}, 32)) {
		t.Fatalf("read %x, not the signed payload", got)
	}
}

func TestSignedAggregateNeedsExactlyOneSwEvidence(t *testing.T) {
	payload, _ := json.Marshal(ar.SwEvidence{Sha256: make([]byte, 32)})
	var report ar.AttestationReport
	ser, _ := ar.NewJsonSerializer()
	if err := ser.Unmarshal(swReport(t, payload, ""), &report); err != nil {
		t.Fatal(err)
	}
	two := marshalReport(t, append(report.Evidences, report.Evidences[0]))
	if _, err := signedAggregate(two); err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Errorf("two sw evidences: %v", err)
	}
	if _, err := signedAggregate(marshalReport(t, nil)); err == nil {
		t.Error("no sw evidence was accepted")
	}
}
