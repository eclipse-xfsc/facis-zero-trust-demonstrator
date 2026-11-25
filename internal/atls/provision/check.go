package provision

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/grpcapi"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// ErrNoReport: no attestation report was obtained from cmcd (unreachable, or it failed to
// produce one). Every other error of Check means a report was obtained and rejected.
var ErrNoReport = errors.New("no attestation report from cmcd")

// Evidence is what Check established about a zone's evidence.
type Evidence struct {
	// Aggregate is the measurement value the sw driver signed into the evidence: it differs
	// whenever the measured values differ.
	Aggregate []byte
	// Verified are the template hashes of the verified components, by name.
	Verified map[string][]byte
}

// Check is what a zone's gateway does at startup: it obtains a fresh attestation report from
// the zone's cmcd, verifies it against metadataCAs (the evidence signature, its freshness, the
// signed metadata and the reference values in it), and checks that the verified measured values
// are exactly those of the zone configuration z. It fails when cmcd cannot be reached, the report
// does not verify as success, or its measured values differ from z. ctx bounds the wait for cmcd;
// without a deadline Check waits until cmcd answers.
func Check(ctx context.Context, cmcdAddr string, metadataCAs []*x509.Certificate, z *Zone) (*Evidence, error) {
	want, err := z.Measurements()
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(cmcdAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrNoReport, cmcdAddr, err)
	}
	defer func() { _ = conn.Close() }()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	resp, err := grpcapi.NewCMCServiceClient(conn).Attest(ctx,
		&grpcapi.AttestationRequest{Version: grpcapi.GetVersion(), Nonce: nonce}, grpc.WaitForReady(true))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrNoReport, cmcdAddr, err)
	}

	result := verifier.Verify(resp.Report, nonce, nil, verifier.PolicyEngineSelect_None, false,
		metadataCAs, nil, "", "", false)
	if result.Summary.Status != ar.StatusSuccess {
		return nil, fmt.Errorf("the report verified as %q (error codes %v)", result.Summary.Status, result.Summary.ErrorCodes)
	}
	// Every verified event counts: an event measured twice is two results, and refused.
	verified := map[string][]byte{}
	count := 0
	for _, m := range result.Measurements {
		for _, a := range m.Artifacts {
			if a.Type == "Verified" && a.Success {
				count++
				verified[a.Name] = a.Digest
			}
		}
	}
	if count != len(want) || len(verified) != len(want) {
		return nil, fmt.Errorf("%d events of %d components verified, the configuration has %d components", count, len(verified), len(want))
	}
	for _, m := range want {
		if !bytes.Equal(verified[m.Name], m.TemplateHash) {
			return nil, fmt.Errorf("component %s: verified %x, configured %x", m.Name, verified[m.Name], m.TemplateHash)
		}
	}

	aggregate, err := signedAggregate(resp.Report)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(aggregate, Aggregate(want)) {
		return nil, fmt.Errorf("the evidence signs %x, the configuration gives %x", aggregate, Aggregate(want))
	}
	return &Evidence{Aggregate: aggregate, Verified: verified}, nil
}

// signedAggregate reads the measurement value out of the report's sw evidence. The report has
// been verified, signature included, before this is called. The payload is extracted with CMC's
// own serializer, the parser its verifier used, so the bytes read are the bytes verified.
func signedAggregate(raw []byte) ([]byte, error) {
	s, err := ar.DetectSerialization(raw)
	if err != nil {
		return nil, err
	}
	var report ar.AttestationReport
	if err := s.Unmarshal(raw, &report); err != nil {
		return nil, err
	}
	sw, err := ar.NewJsonSerializer() // sw evidence is always JSON (CMC's swdriver)
	if err != nil {
		return nil, err
	}
	var found []byte
	for _, ev := range report.Evidences {
		if ev.Type != ar.TYPE_EVIDENCE_SW {
			continue
		}
		if found != nil {
			return nil, errors.New("the report carries more than one sw evidence")
		}
		payload, err := sw.GetPayload(ev.Data)
		if err != nil {
			return nil, fmt.Errorf("sw evidence: %w", err)
		}
		var e ar.SwEvidence
		if err := sw.Unmarshal(payload, &e); err != nil {
			return nil, fmt.Errorf("sw evidence payload: %w", err)
		}
		found = e.Sha256
		if found == nil {
			found = []byte{}
		}
	}
	if found == nil {
		return nil, errors.New("the report carries no sw evidence")
	}
	return found, nil
}
