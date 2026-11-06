package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/policy-hook-probe/internal/envoyhook"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/policy-hook-probe/internal/hook"
)

// What the stand-in token store answers every substitution with. The verification reads these
// values back from the upstream to show the caller's credential was replaced.
const (
	upstreamAuthorization = "DPoP fx-upstream-token"
	upstreamProof         = "fx-upstream-proof"
)

type serveOptions struct {
	listen, ops, fixtures, events string
	source, runID, sourceID       string
	publishedBaseURL, peerZone    string
	audience                      string
	decisionTimeout               time.Duration
}

func (o *serveOptions) register(fs *flag.FlagSet) {
	fs.StringVar(&o.listen, "listen", "", "`address` the gRPC services listen on (required)")
	fs.StringVar(&o.ops, "ops", "", "`address` of the plain-HTTP /healthz endpoint (default: none)")
	fs.StringVar(&o.fixtures, "fixtures", "", "`directory` holding the contract fixtures (docs/contracts/fixtures) (required)")
	fs.StringVar(&o.events, "events", "", "`file` the decision events are appended to as JSON lines (default: stderr)")
	fs.StringVar(&o.source, "source", "guard-a", "`name` the decision events carry as their source")
	fs.StringVar(&o.runID, "run-id", "verification", "`run_id` of the decision events")
	fs.StringVar(&o.sourceID, "source-id", "spiffe://zone-a.example/ns/data/sa/backend",
		"caller `SPIFFE-ID` put in the policy input when the transport authenticated none")
	fs.StringVar(&o.publishedBaseURL, "published-base-url", "https://guard-a.example", "`URL` the guard is published at; the upstream proof is minted for it plus the route path")
	fs.StringVar(&o.peerZone, "peer-zone", "zone-b", "`zone` the token store substitutes for")
	fs.StringVar(&o.audience, "audience", "https://guard-b.example", "`audience` the token store substitutes for")
	fs.DurationVar(&o.decisionTimeout, "decision-timeout", 150*time.Millisecond, "bound on one policy decision")
}

func serve(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("policy-hook-probe serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o serveOptions
	o.register(fs)
	if err := fs.Parse(args); err != nil {
		return 1
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(stderr, nil)))
	if o.listen == "" || o.fixtures == "" {
		slog.Error("serve needs --listen and --fixtures")
		return 1
	}
	if err := runServe(ctx, o, stderr); err != nil {
		slog.Error("policy hook stopped", "err", err)
		return 1
	}
	return 0
}

func runServe(ctx context.Context, o serveOptions, stderr io.Writer) error {
	fx, err := hook.LoadFixtures(o.fixtures)
	if err != nil {
		return fmt.Errorf("fixtures: %w", err)
	}
	events := stderr
	if o.events != "" {
		f, err := os.OpenFile(o.events, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		events = f
	}
	guard := hook.New(hook.Config{PublishedBaseURL: o.publishedBaseURL, PeerZone: o.peerZone, Audience: o.audience,
		SourceID: o.sourceID, DecisionTimeout: o.decisionTimeout},
		fx, fx, hook.StaticSubstituter{Authorization: upstreamAuthorization, DPoP: upstreamProof},
		hook.NewLogSink(events, o.source, o.runID))

	srv := grpc.NewServer()
	envoyhook.Register(srv, guard)
	healthpb.RegisterHealthServer(srv, health.NewServer())
	ln, err := net.Listen("tcp", o.listen)
	if err != nil {
		return err
	}
	errc := make(chan error, 2)
	go func() { errc <- srv.Serve(ln) }()

	var ops *http.Server
	if o.ops != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		ops = &http.Server{Addr: o.ops, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := ops.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}
	slog.Info("policy hook listening", "addr", ln.Addr().String(), "ops", o.ops, "source", o.source)

	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	done := make(chan struct{})
	go func() { srv.GracefulStop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		srv.Stop()
	}
	if ops != nil {
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = ops.Shutdown(shutdown)
	}
	return nil
}
