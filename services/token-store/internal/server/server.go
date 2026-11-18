// Package server is the token store's process: its listeners, its liveness and readiness, and the
// correlation every request's records and outbound calls carry. The store's endpoints join it as
// they land; this build serves the health paths of the contract and nothing else.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/openbao"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/schema"
)

// Server is a running token store. New binds its listeners; Serve runs them until the context
// ends and then drains them.
type Server struct {
	cfg        Config
	log        *slog.Logger
	pool       *pgxpool.Pool
	migrations []schema.Migration
	client     *http.Client
	openBaoURL string
	ready      *readiness
	api, ops   *http.Server
	apiLn      net.Listener
	opsLn      net.Listener
}

// New validates cfg, prepares the connection pool (no connection is opened: a store that starts
// before its database still starts, and readiness says so), loads the embedded migrations once,
// and binds both listeners, so an address in use fails here and not after "listening" was logged.
func New(ctx context.Context, cfg Config, log *slog.Logger) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	migrations, err := schema.Migrations()
	if err != nil {
		return nil, err
	}
	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		// pgx redacts the password of a URL it cannot parse.
		return nil, fmt.Errorf("database URL: %w", err)
	}
	poolCfg.MaxConns = 4
	poolCfg.MinConns = 0
	poolCfg.MaxConnIdleTime = 5 * time.Minute
	poolCfg.HealthCheckPeriod = 30 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("database pool: %w", err)
	}
	s := &Server{
		cfg:        cfg,
		log:        log,
		pool:       pool,
		migrations: migrations,
		client:     openbao.NewClient(),
		openBaoURL: strings.TrimRight(cfg.OpenBaoURL, "/"),
	}
	s.ready = &readiness{timeout: cfg.ReadinessTimeout, postgres: s.checkPostgres, openbao: s.checkOpenBao}

	s.apiLn, err = net.Listen("tcp", cfg.Addr)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("API listener: %w", err)
	}
	s.opsLn, err = net.Listen("tcp", cfg.OpsAddr)
	if err != nil {
		_ = s.apiLn.Close()
		pool.Close()
		return nil, fmt.Errorf("ops listener: %w", err)
	}
	s.api = s.httpServer(s.apiRoutes())
	s.ops = s.httpServer(s.opsRoutes())
	return s, nil
}

// Addr is the API listener's address, as bound.
func (s *Server) Addr() net.Addr { return s.apiLn.Addr() }

// OpsAddr is the ops listener's address, as bound.
func (s *Server) OpsAddr() net.Addr { return s.opsLn.Addr() }

// opsRoutes is what the kubelet probes on the unpublished ops port: the health paths and nothing
// else, ever. The store's endpoints belong to apiRoutes.
func (s *Server) opsRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	return s.correlate(mux)
}

// apiRoutes is the contract on the published port: its health paths now, its endpoints as they
// land. Nothing registered here is reachable on the ops port.
func (s *Server) apiRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	return s.correlate(mux)
}

func (s *Server) httpServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		// A /readyz answer may take the whole readiness budget; the write deadline sits above it.
		WriteTimeout: s.cfg.ReadinessTimeout + 5*time.Second,
		IdleTimeout:  60 * time.Second,
		ErrorLog:     slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
}

// Serve runs both listeners until ctx ends or one of them fails. Asked to stop, it first turns
// readiness red and keeps serving for the drain delay, the time the endpoints controller needs to
// stop routing to the pod, so a caller sent here meanwhile is answered rather than refused; then
// it drains both listeners at once, each within the shutdown timeout, and closes the pool. It
// returns nil after a clean stop.
func (s *Server) Serve(ctx context.Context) error {
	results := make(chan error, 2)
	go func() { results <- s.api.Serve(s.apiLn) }()
	go func() { results <- s.ops.Serve(s.opsLn) }()
	pending := 2
	var cause error
	select {
	case <-ctx.Done():
		s.ready.drain()
		s.log.InfoContext(ctx, "draining", "delay", s.cfg.DrainDelay.String())
		delay := time.NewTimer(s.cfg.DrainDelay)
		select {
		case <-delay.C:
		case err := <-results:
			delay.Stop()
			pending--
			if !errors.Is(err, http.ErrServerClosed) {
				cause = err
			}
		}
	case err := <-results:
		pending--
		if !errors.Is(err, http.ErrServerClosed) {
			cause = err
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
	defer cancel()
	var drains sync.WaitGroup
	var drainErr error
	var drainMu sync.Mutex
	for _, srv := range []*http.Server{s.api, s.ops} {
		drains.Go(func() {
			if err := srv.Shutdown(shutdownCtx); err != nil {
				drainMu.Lock()
				if drainErr == nil {
					drainErr = err
				}
				drainMu.Unlock()
			}
		})
	}
	drains.Wait()
	if drainErr != nil && cause == nil {
		cause = fmt.Errorf("draining: %w", drainErr)
	}
	for ; pending > 0; pending-- {
		select {
		case err := <-results:
			if !errors.Is(err, http.ErrServerClosed) && cause == nil {
				cause = err
			}
		case <-shutdownCtx.Done():
			pending = 0
		}
	}
	s.pool.Close()
	return cause
}
