package atlstest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"testing"

	"google.golang.org/grpc"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/grpcapi"
	"github.com/Fraunhofer-AISEC/cmc/prover"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
)

// StartCmcd starts, once per zone, an in-process stand-in for the zone's cmcd and returns its
// gRPC address. It serves the calls the attested-TLS client makes (Attest, Verify, PeerCache)
// the way CMC's cmcd v0.9.15 does (cmcd/grpc.go): CBOR reports, JSON results. It stops when the
// test that created the zone ends.
func (z *Zone) StartCmcd(t testing.TB) string {
	mustTest()
	t.Helper()
	z.cmcdOnce.Do(func() {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("atlstest: cmcd listen: %v", err)
		}
		ser, err := ar.NewCborSerializer()
		if err != nil {
			t.Fatalf("atlstest: cmcd serializer: %v", err)
		}
		s := grpc.NewServer()
		grpcapi.RegisterCMCServiceServer(s, &cmcd{c: z.c, ser: ser})
		go func() { _ = s.Serve(ln) }()
		z.tb.Cleanup(s.Stop)
		z.cmcdAddr = ln.Addr().String()
	})
	return z.cmcdAddr
}

// UnreachableCmcd returns an address on which no cmcd answers.
func UnreachableCmcd(t testing.TB) string {
	mustTest()
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("atlstest: listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

type cmcd struct {
	grpcapi.UnimplementedCMCServiceServer
	c   *cmc.Cmc
	ser ar.Serializer
}

func (s *cmcd) Attest(_ context.Context, req *grpcapi.AttestationRequest) (*grpcapi.AttestationResponse, error) {
	if len(s.c.Drivers) == 0 {
		return nil, errors.New("attest: no drivers configured")
	}
	if err := grpcapi.CheckVersion(req.Version); err != nil {
		return nil, fmt.Errorf("version check failed: %w", err)
	}
	proverMu.Lock()
	report, err := prover.Generate(req.Nonce, req.Cached, s.c.GetMetadata(), s.c.Drivers, s.ser, s.c.HashAlg)
	proverMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation report: %w", err)
	}
	return &grpcapi.AttestationResponse{Version: grpcapi.GetVersion(), Report: report}, nil
}

func (s *cmcd) Verify(_ context.Context, req *grpcapi.VerificationRequest) (*grpcapi.VerificationResponse, error) {
	if err := grpcapi.CheckVersion(req.Version); err != nil {
		return nil, fmt.Errorf("version check failed: %w", err)
	}
	result := verifier.Verify(req.Report, req.Nonce, req.Policies, s.c.PolicyEngineSelect,
		s.c.PolicyOverwrite, s.c.RootCas, s.c.PeerCache, req.Peer, req.PeerAddr, s.c.UseOmsp)
	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal the attestation result")
	}
	return &grpcapi.VerificationResponse{Version: grpcapi.GetVersion(), Result: data}, nil
}

func (s *cmcd) PeerCache(_ context.Context, req *grpcapi.PeerCacheRequest) (*grpcapi.PeerCacheResponse, error) {
	if err := grpcapi.CheckVersion(req.Version); err != nil {
		return nil, fmt.Errorf("version check failed: %w", err)
	}
	return &grpcapi.PeerCacheResponse{Version: grpcapi.GetVersion(), Cache: s.c.PeerCache.GetKeys(req.Peer)}, nil
}
