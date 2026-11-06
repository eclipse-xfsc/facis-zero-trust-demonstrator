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
	flag.Parse()
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
	listener, err := net.Listen("tcp", "127.0.0.1:50051")
	if err != nil {
		return errors.New("listener unavailable")
	}
	server := grpc.NewServer(grpc.MaxRecvMsgSize(64*1024), grpc.MaxSendMsgSize(64*1024))
	envoyhook.RegisterAuthz(server, runtime)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	ops := &http.Server{Addr: ":9090", Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	failures := make(chan error, 2)
	go func() { failures <- server.Serve(listener) }()
	go func() { failures <- ops.ListenAndServe() }()
	select {
	case <-ctx.Done():
	case <-failures:
		err = errors.New("runtime listener stopped")
	}
	server.Stop()
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_ = ops.Shutdown(shutdown)
	return err
}
func main() {
	if err := run(); err != nil {
		slog.Error("guard stopped", "reason", err.Error())
		os.Exit(1)
	}
}
