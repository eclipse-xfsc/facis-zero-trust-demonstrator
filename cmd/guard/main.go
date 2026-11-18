package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/envoyhook"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/guard"
	"google.golang.org/grpc"
)

func run() error {
	file := flag.String("config", "/etc/guard/config.json", "public runtime configuration")
	opsAddr := flag.String("ops-addr", ":9090", "address of /healthz, /readyz and /metrics")
	hookAddr := flag.String("hook-addr", "127.0.0.1:50051", "loopback address of the ext_authz hook, for the Envoy of this pod only")
	flag.Parse()
	if host, _, err := net.SplitHostPort(*hookAddr); err != nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("the hook address must be a loopback address")
	}
	f, err := os.Open(*file)
	if err != nil {
		return errors.New("configuration unavailable")
	}
	defer func() { _ = f.Close() }()
	var cfg guard.Config
	dec := json.NewDecoder(io.LimitReader(f, 64*1024))
	dec.DisallowUnknownFields()
	if dec.Decode(&cfg) != nil || dec.Decode(&struct{}{}) != io.EOF {
		return errors.New("configuration invalid")
	}
	runtime, err := guard.New(cfg, hook.NewLogSink(os.Stdout, "ztd-guard", time.Now().UTC().Format(time.RFC3339Nano)))
	if err != nil {
		return err
	}
	// Only the Envoy container in this pod can reach the hook.
	listener, err := net.Listen("tcp", *hookAddr)
	if err != nil {
		return errors.New("listener unavailable")
	}
	server := grpc.NewServer(grpc.MaxRecvMsgSize(64*1024), grpc.MaxSendMsgSize(64*1024))
	envoyhook.RegisterAuthz(server, runtime)
	prober := guard.NewProber(cfg)
	mux := http.NewServeMux()
	// Liveness: the process answers. Readiness: every dependency is up (guard.Prober).
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		down := prober.Down()
		w.Header().Set("Content-Type", "application/json")
		if len(down) > 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ready": len(down) == 0, "down": down})
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		guard.WriteMetrics(w, prober, &runtime.Refused)
	})
	ops := &http.Server{Addr: *opsAddr, Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	probing := make(chan struct{})
	go func() { prober.Run(ctx); close(probing) }()
	failures := make(chan error, 2)
	go func() { failures <- server.Serve(listener) }()
	go func() { failures <- ops.ListenAndServe() }()
	select {
	case <-ctx.Done():
	case <-failures:
		err = errors.New("runtime listener stopped")
	}
	cancel()
	<-probing
	server.Stop()
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_ = ops.Shutdown(shutdown)
	return err
}
func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err := run(); err != nil {
		slog.Error("guard stopped", "reason", err.Error())
		os.Exit(1)
	}
}
