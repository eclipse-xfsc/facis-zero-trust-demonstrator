package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/policyevaluator"
)

func run() error {
	file := flag.String("config", "/etc/policy/config.json", "public deny-default policy configuration")
	flag.Parse()
	f, err := os.Open(*file)
	if err != nil {
		return errors.New("configuration unavailable")
	}
	defer func() { _ = f.Close() }()
	var cfg policyevaluator.Config
	dec := json.NewDecoder(io.LimitReader(f, 64*1024))
	dec.DisallowUnknownFields()
	if dec.Decode(&cfg) != nil || dec.Decode(&struct{}{}) != io.EOF {
		return errors.New("configuration invalid")
	}
	policy, err := policyevaluator.New(cfg)
	if err != nil {
		return errors.New("policy configuration invalid")
	}
	server := &http.Server{Addr: ":8080", Handler: policy, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	failures := make(chan error, 1)
	go func() { failures <- server.ListenAndServe() }()
	select {
	case <-ctx.Done():
	case <-failures:
		err = errors.New("policy listener stopped")
	}
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_ = server.Shutdown(shutdown)
	return err
}
func main() {
	if err := run(); err != nil {
		slog.Error("policy evaluator stopped", "reason", err.Error())
		os.Exit(1)
	}
}
