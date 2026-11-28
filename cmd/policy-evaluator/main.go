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

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
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
	var cfg struct {
		policyevaluator.Config
		// TSA, when set, takes decisions from the XFSC TSA policy service instead of the built-in rules.
		TSA *policyevaluator.TSAConfig `json:"tsa"`
	}
	dec := json.NewDecoder(io.LimitReader(f, 64*1024))
	dec.DisallowUnknownFields()
	if dec.Decode(&cfg) != nil || dec.Decode(&struct{}{}) != io.EOF {
		return errors.New("configuration invalid")
	}
	// Both engines write the IF-01 v2 decision event under the guard's correlation id.
	events := hook.NewLogSinkV2(os.Stdout, cfg.EventSource, "policy-"+time.Now().UTC().Format("20060102T150405.000000000Z"))
	var policy http.Handler
	if cfg.TSA != nil {
		if cfg.EventSource != "policy-a" && cfg.EventSource != "policy-b" {
			return errors.New("policy event_source must be policy-a or policy-b")
		}
		policy, err = policyevaluator.NewTSA(*cfg.TSA, cfg.GuardCallers, slog.New(slog.NewJSONHandler(os.Stdout, nil)), events)
	} else {
		policy, err = policyevaluator.New(cfg.Config, events)
	}
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
