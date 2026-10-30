// Package server is the token store's process: its listeners, its liveness and readiness, and the
// correlation every request's records and outbound calls carry, and the endpoints of the contract:
// the health paths, the replay check and substitution.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/caller"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/keys"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/renew"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/substitute"

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

	replay      *replay.Postgres
	callers     caller.Authenticator
	routes      caller.Routes       // substitution's router; empty refuses every caller
	substitute  *substitute.Service // nil without an acquisition config
	renewal     *renew.Worker       // nil without an acquisition config
	subTimeout  time.Duration       // the deadline of one substitution; substituteTimeout
	reconnected chan struct{}       // signalled when the pool opens a connection, so the replay epoch is rechecked
	keyStarted  chan struct{}
	issuerCache issuerSeparationCache
	now         func() time.Time
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
	// On-demand acquisitions hold at most two connections each (a route lock and one acquisition
	// statement) and at most substitute.MaxAcquiring run at once; four more stay for the replay
	// check, readiness, lookups and renewal, so cold routes never starve them.
	poolCfg.MaxConns = int32(2*substitute.MaxAcquiring + 4)
	poolCfg.MinConns = 0
	poolCfg.MaxConnIdleTime = 5 * time.Minute
	poolCfg.HealthCheckPeriod = 30 * time.Second
	reconnected := make(chan struct{}, 1)
	poolCfg.AfterConnect = func(context.Context, *pgx.Conn) error {
		select {
		case reconnected <- struct{}{}:
		default:
		}
		return nil
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("database pool: %w", err)
	}
	var routes caller.Routes
	if cfg.Acquisition != nil {
		routes = cfg.Acquisition.Substitution
	}
	callers := cfg.Callers
	if callers == nil {
		if callers, err = caller.NewXFCC(slices.Concat(cfg.ReplayCallers, routes.Callers())); err != nil {
			pool.Close()
			return nil, err
		}
	}
	s := &Server{
		cfg:         cfg,
		log:         log,
		pool:        pool,
		migrations:  migrations,
		client:      openbao.NewClient(),
		openBaoURL:  strings.TrimRight(cfg.OpenBaoURL, "/"),
		replay:      replay.NewPostgres(pool),
		callers:     callers,
		routes:      routes,
		subTimeout:  substituteTimeout,
		reconnected: reconnected,
		now:         time.Now,
		keyStarted:  make(chan struct{}),
	}
	if a := cfg.Acquisition; a != nil {
		// Acquisition, substitution and renewal sign through a signer that never creates a key:
		// a deleted key is reported, never replaced. Only startup (startKeys) may provision one.
		readOnly := keys.ReadOnly{Lister: cfg.OpenBao}
		acquirer := &acquire.Acquirer{DB: pool, Signer: readOnly, Secrets: cfg.OpenBao, KeyName: a.SigningKey,
			Trusted: a.Trusted, Log: log, Prefix: a.KVPrefix}
		s.substitute = &substitute.Service{DB: pool, Signer: readOnly, Secrets: cfg.OpenBao, Routes: *a, Log: log,
			Acquirer: acquirer}
		instance := cfg.Instance
		if instance == "" {
			var b [8]byte
			_, _ = rand.Read(b[:])
			instance = "token-store-" + hex.EncodeToString(b[:])
		}
		s.renewal = &renew.Worker{DB: pool, Acquirer: acquirer, Routes: *a, Instance: instance, Log: log}
	}
	s.ready = &readiness{timeout: cfg.ReadinessTimeout, postgres: s.checkPostgres, openbao: s.checkOpenBao,
		signingKey: s.checkSigningKey}

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

// apiRoutes is the contract on the published port: its health paths and its endpoints as they
// land. Nothing registered here is reachable on the ops port.
func (s *Server) apiRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("POST /internal/replay-check", s.handleReplayCheck)
	mux.HandleFunc("POST /internal/substitute", s.handleSubstitute)
	return s.correlate(mux)
}

func (s *Server) httpServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		// A /readyz answer may take the whole readiness budget, a substitution its own; the write
		// deadline sits above both.
		WriteTimeout: max(s.cfg.ReadinessTimeout, substituteTimeout) + 5*time.Second,
		IdleTimeout:  60 * time.Second,
		ErrorLog:     slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
}

// Serve runs both listeners until ctx ends or one of them fails. Asked to stop, it first turns
// readiness red and keeps serving for the drain delay, the time the endpoints controller needs to
// stop routing to the pod, so a caller sent here meanwhile is answered rather than refused; then
// it drains both listeners at once, each within the shutdown timeout, and closes the pool. It
// returns nil after a clean stop.
//
// With an acquisition config, Serve also resolves the store's signing keys (startKeys): until
// they resolve the store is not ready, and a key that cannot resolve because of its configuration
// stops the service with an error, so the misconfiguration is seen at startup and not at the
// first call.
func (s *Server) Serve(ctx context.Context) error {
	maintainCtx, stopMaintaining := context.WithCancel(context.Background())
	keyStarted := s.keyStarted
	keyFault := make(chan error, 1)
	go func() {
		defer close(keyStarted)
		if s.cfg.Acquisition == nil {
			return
		}
		if err := s.startKeys(maintainCtx); err != nil {
			keyFault <- err
		}
	}()
	defer func() { stopMaintaining(); <-keyStarted }()
	maintained := make(chan struct{})
	go func() { defer close(maintained); s.maintainReplay(maintainCtx) }()
	renewed := make(chan struct{})
	go func() {
		defer close(renewed)
		if s.renewal != nil {
			s.renewal.Run(maintainCtx)
		}
	}()
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
	case err := <-keyFault:
		// The keys cannot resolve as configured. Readiness answered starting until now, so nothing
		// was routed to the pod and there is nothing to drain for; the listeners close and the
		// error is the exit.
		s.ready.drain()
		ref := ""
		var m *misconfigured
		if errors.As(err, &m) {
			ref = m.ref
		}
		s.log.ErrorContext(ctx, msgKeysMisconfigured, "key", s.cfg.Acquisition.SigningKey, "reason", reasonOf(err),
			"key_ref", ref)
		cause = err
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
				// The drain ran out: close what is still open, so no handler keeps a pooled
				// connection and the pool below can close.
				_ = srv.Close()
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
	stopMaintaining()
	<-maintained
	<-renewed
	s.pool.Close()
	return cause
}
