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

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/participant"
)

func main() {
	config, err := participant.LoadConfig()
	if err != nil {
		slog.Error("participant configuration rejected", "error", err)
		os.Exit(1)
	}

	logger := newLogger(config.LogLevel)
	server := participant.NewServer(config, logger).HTTPServer()

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

	logger.Info("participant starting", "address", config.Address, "mode", config.AdapterMode)
	serveErr := server.ListenAndServe()
	if errors.Is(serveErr, http.ErrServerClosed) {
		if shutdownErr := <-shutdownDone; shutdownErr != nil {
			logger.Error("participant shutdown failed", "error", shutdownErr)
		}
		return
	}
	if serveErr != nil {
		logger.Error("participant server failed", "error", serveErr)
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
