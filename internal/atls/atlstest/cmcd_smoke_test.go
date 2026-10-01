package atlstest

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/grpcapi"
)

// cmcdCheckEnv lists, comma separated, the addresses of running cmcd processes started from the
// fixtures of TestWriteFixtures. Unset: TestCmcdReports does nothing.
const cmcdCheckEnv = "ATLS_FIXTURE_CMCD_CHECK"

// TestCmcdReports asks every listed cmcd for an attestation report and checks that the report
// carries the zone's signed metadata and that every listed cmcd verifies it with verdict
// success. It waits up to 30 seconds for each cmcd to answer, so it also serves as the
// readiness check of the proof scripts.
func TestCmcdReports(t *testing.T) {
	list := os.Getenv(cmcdCheckEnv)
	if list == "" {
		return
	}
	addrs := strings.Split(list, ",")
	ser, err := ar.NewCborSerializer()
	if err != nil {
		t.Fatal(err)
	}

	clients := map[string]grpcapi.CMCServiceClient{}
	for _, addr := range addrs {
		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatalf("cmcd %s: %v", addr, err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		clients[addr] = grpcapi.NewCMCServiceClient(conn)
	}

	for _, prover := range addrs {
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		resp, err := clients[prover].Attest(ctx,
			&grpcapi.AttestationRequest{Version: grpcapi.GetVersion(), Nonce: nonce},
			grpc.WaitForReady(true))
		cancel()
		if err != nil {
			t.Fatalf("cmcd %s: no attestation report: %v", prover, err)
		}

		var report ar.AttestationReport
		if err := ser.Unmarshal(resp.Report, &report); err != nil {
			t.Fatalf("cmcd %s: report does not parse: %v", prover, err)
		}
		if len(report.Context.Metadata) == 0 {
			t.Fatalf("cmcd %s: the report carries no metadata", prover)
		}
		if len(report.Evidences) == 0 {
			t.Fatalf("cmcd %s: the report carries no evidence", prover)
		}

		for _, verifier := range addrs {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			vresp, err := clients[verifier].Verify(ctx,
				&grpcapi.VerificationRequest{Version: grpcapi.GetVersion(), Nonce: nonce, Report: resp.Report},
				grpc.WaitForReady(true))
			cancel()
			if err != nil {
				t.Fatalf("cmcd %s: verification of the report of %s failed: %v", verifier, prover, err)
			}
			var result ar.AttestationResult
			if err := json.Unmarshal(vresp.Result, &result); err != nil {
				t.Fatalf("cmcd %s: result does not parse: %v", verifier, err)
			}
			if result.Summary.Status != ar.StatusSuccess {
				t.Fatalf("cmcd %s: report of %s verified as %q (error codes %v), want %q\n%s",
					verifier, prover, result.Summary.Status, result.Summary.ErrorCodes, ar.StatusSuccess, vresp.Result)
			}
			t.Logf("cmcd %s: report with %d metadata items and %d evidence(s), verified by cmcd %s: %s",
				prover, len(report.Context.Metadata), len(report.Evidences), verifier, result.Summary.Status)
		}
	}
}
