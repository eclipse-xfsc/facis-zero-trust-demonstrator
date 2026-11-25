package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/appevents"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/protectedresource"
)

func main() {
	config, err := protectedresource.LoadConfig()
	if err != nil {
		slog.Error("protected resource configuration rejected", "error", err)
		os.Exit(1)
	}

	source := os.Getenv("IF01_SOURCE")
	if source == "" {
		source = "protected-resource-b"
	}
	config.Events, err = appevents.New(os.Stdout, source)
	if err != nil {
		slog.Error("application event configuration rejected")
		os.Exit(1)
	}

	logger := newLogger(config.LogLevel)
	adapter := protectedresource.NewResourceAdapter(config)
	if err := protectedresource.CheckInterface(context.Background(), config, adapter, logger); err != nil {
		os.Exit(1)
	}
	resource := protectedresource.NewServerWithAdapter(config, logger, adapter)
	server := resource.HTTPServer()

	shutdownSignal, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	shutdownDone := make(chan error, 1)
	go func() {
		<-shutdownSignal.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownDone <- server.Shutdown(ctx)
		close(shutdownDone)
	}()

	logger.Info("protected resource starting", "address", config.Address, "mode", config.ServingMode())
	if grpcServer := resource.GRPCServer(); grpcServer != nil {
		logger.Info("protected resource gRPC starting", "address", config.GRPCAddress, "method", protectedresource.GRPCMethod)
		go func() {
			// Not drained on shutdown: the process exits with the REST server.
			if err := grpcServer.ListenAndServe(); err != nil {
				logger.Error("protected resource gRPC server failed", "error", err)
				os.Exit(1)
			}
		}()
	}
	serveErr := server.ListenAndServe()
	if errors.Is(serveErr, http.ErrServerClosed) {
		if shutdownErr := <-shutdownDone; shutdownErr != nil {
			logger.Error("protected resource shutdown failed", "error", shutdownErr)
		}
		return
	}
	if serveErr != nil {
		logger.Error("protected resource server failed", "error", serveErr)
		os.Exit(1)
	}
}

func newLogger(levelName string) *slog.Logger {
	levels := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: levels[levelName]}))
}
