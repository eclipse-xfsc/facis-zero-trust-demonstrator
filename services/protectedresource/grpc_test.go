package protectedresource

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/tokenverify"
)

// check calls GRPCMethod with a real gRPC client on a Resource configured with verifier.
func check(t *testing.T, verifier tokenverify.RequestVerifier) (*healthpb.HealthCheckResponse, string, error) {
	t.Helper()
	var logs bytes.Buffer
	config := testConfig()
	config.Verifier, config.GRPCAddress = verifier, "127.0.0.1:0"
	server := NewServer(config, slog.New(slog.NewJSONHandler(&logs, nil))).GRPCServer()
	listener, err := net.Listen("tcp", config.GRPCAddress)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(metadata.AppendToOutgoingContext(t.Context(), "x-request-id", "grpc-1"), 5*time.Second)
	defer cancel()
	out, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	return out, logs.String(), err
}

func TestGRPCMethodIsServedToAVerifiedCallerOnly(t *testing.T) {
	out, logs, err := check(t, fakeVerifier{identity: callerIdentity("report:summary")})
	if err != nil || out.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("verified call: %v %v", out, err)
	}
	if !strings.Contains(logs, `"requestId":"grpc-1"`) || !strings.Contains(logs, `"grpcMethod":"`+GRPCMethod+`"`) || !strings.Contains(logs, `"client_id":"client-participant"`) {
		t.Fatalf("no record of the served call: %s", logs)
	}
	_, logs, err = check(t, fakeVerifier{refuse: true})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("refused call: %v", err)
	}
	if !strings.Contains(logs, "protected resource request refused") || strings.Contains(logs, "request completed") {
		t.Fatalf("refusal not recorded as one: %s", logs)
	}
}

func TestGRPCServerNeedsTokenMode(t *testing.T) {
	config := testConfig()
	config.GRPCAddress = "127.0.0.1:0"
	if NewServer(config, nil).GRPCServer() != nil {
		t.Fatal("gRPC served without a verifier")
	}
	t.Setenv("PROTECTED_RESOURCE_GRPC_ADDRESS", ":9090")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("gRPC address accepted in sample mode")
	}
}
