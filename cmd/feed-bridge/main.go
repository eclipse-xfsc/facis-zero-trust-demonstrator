// Command feed-bridge serves the IF-01 feed (/snapshot, /events, /v2/snapshot, /v2/events) from the
// IF-01 lines posted to /ingest and, with --stdin, from standard input (for example the log streams
// of the guard and the policy evaluator). It has no access control of its own: deploy it only
// behind the mesh (deployment/helm/feed-bridge), or bind it to the loopback.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/feedbridge"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8090", "address of the feed API")
	contracts := flag.String("contracts", "docs/contracts", "directory of the IF-01 event schemas")
	stdin := flag.Bool("stdin", false, "also ingest standard input; a read error stops the bridge")
	budget := flag.Int("budget-bytes", feedbridge.DefaultBudget, "bytes of event lines all runs together keep")
	flag.Parse()
	bridge, err := feedbridge.New(*contracts)
	if err != nil {
		slog.Error("feed bridge", "reason", "event schemas unavailable")
		os.Exit(1)
	}
	bridge.Budget = *budget
	server := &http.Server{Addr: *listen, Handler: bridge, ReadHeaderTimeout: 3 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	failed := make(chan error, 1)
	if *stdin {
		go func() {
			accepted, refused, oversized, err := bridge.Consume(os.Stdin)
			slog.Info("feed bridge input ended", "accepted", accepted, "refused", refused, "oversized", oversized)
			if err != nil {
				failed <- errors.New("standard input unreadable")
			}
		}()
	}
	go func() {
		select {
		case <-ctx.Done():
		case err := <-failed:
			slog.Error("feed bridge", "reason", err.Error())
			_ = server.Close()
			os.Exit(1)
		}
		_ = server.Close()
	}()
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("feed bridge", "reason", "listener stopped")
		os.Exit(1)
	}
}
