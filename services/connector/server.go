package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider/authelia"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider/pgstore"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/signing"
)

// schemaVersion is the latest migration of the authorization database (owned and applied by the
// token store, services/token-store/internal/schema) that this build needs. A test keeps it equal to
// the newest migration file, so a new migration makes whoever adds it decide whether the connector
// needs it.
const schemaVersion = 4

// D8: a proof is acceptable for lifespan + skew after iat and iat may lie skew ahead, so a lost replay
// record exposes 60 s + 2·30 s.
const (
	proofLifespan    = 60 * time.Second
	proofSkew        = 30 * time.Second
	replayExposure   = proofLifespan + 2*proofSkew
	epochEvery       = 10 * time.Second
	sweepEvery       = time.Minute
	dbOpTimeout      = 2 * time.Second // every upkeep database operation
	requestTimeout   = 5 * time.Second // every API request: bounds its database and transit calls
	signerAttempt    = 5 * time.Second
	maxSignerBackoff = 30 * time.Second
)

// server is a running connector. newServer binds its listeners; serve runs them until the context
// ends and then drains them.
type server struct {
	cfg         config
	log         *slog.Logger
	pool        *pgxpool.Pool
	transit     *transit.Client
	key         transit.KeyVersion
	health      *http.Client
	providerCfg oauth2provider.Config
	replay      *replay.Postgres
	reconnected chan struct{}

	// live is the signer and the route table built on it, published together once the transit key
	// could be read: until then the signer is nil, the API answers 503 everywhere but its health
	// paths, and readiness is red.
	live atomic.Pointer[live]

	registrar       oauth2provider.Client // as seeded, without its hash
	registrarSecret []byte
	stores          oauth2provider.Stores // the PostgreSQL stores, shared by the provider and the registration gate
	registrarState  atomic.Int32          // registrarPending, registrarOK or registrarConflict
	events          *eventSink            // the IF-01 security-state events

	readyState atomic.Int32 // 0 unknown, 1 ready, 2 not ready; only a change is logged
	draining   atomic.Bool

	api, ops     *http.Server
	apiLn, opsLn net.Listener
}

type live struct {
	signer *signing.Transit
	routes http.Handler
}

const (
	registrarPending int32 = iota
	registrarOK
	registrarConflict
)

// newServer reads the secrets, prepares the pool and the transit client (opening no connection, so
// a connector that starts before its dependencies still starts) and binds both listeners.
func newServer(ctx context.Context, cfg config, log *slog.Logger, events *eventSink) (*server, error) {
	tokenSecret, err := readSecret(cfg.tokenSecretFile, "token secret")
	if err != nil {
		return nil, err
	}
	registrationSecret, err := readSecret(cfg.registrationSecretFile, "registration secret")
	if err != nil {
		return nil, err
	}
	if string(tokenSecret) == string(registrationSecret) {
		return nil, errors.New("the token and registration secrets must differ")
	}
	registrarSecret, err := readSecret(cfg.registrarSecretFile, "registrar secret")
	if err != nil {
		return nil, err
	}
	tokenFile := cfg.openBaoTokenFile
	tc, err := transit.New(transit.Config{Addr: cfg.openBaoURL, Token: func(context.Context) (string, error) {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}})
	if err != nil {
		return nil, err
	}
	poolCfg, err := pgxpool.ParseConfig(cfg.databaseURL)
	if err != nil {
		// Not wrapped: pgx's error carries the connection string, masked on a best-effort basis only.
		return nil, errors.New("invalid database configuration")
	}
	poolCfg.MaxConns = 8
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
		return nil, errors.New("invalid database configuration")
	}
	healthTransport := http.DefaultTransport.(*http.Transport).Clone()
	healthTransport.Proxy = nil
	stores := pgstore.New(pool, nil)
	s := &server{
		cfg:     cfg,
		log:     log,
		pool:    pool,
		transit: tc,
		events:  events,
		key:     transit.KeyVersion{Name: cfg.signingKey, Version: cfg.signingKeyVersion},
		health: &http.Client{Transport: healthTransport, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		providerCfg: oauth2provider.Config{
			Secret:              tokenSecret,
			AccessTokenLifespan: cfg.accessTokenLifespan,
			Issuer:              cfg.issuer,
			DPoP: oauth2provider.DPoPConfig{
				Enforce:       cfg.dpopEnforce,
				NonceRequired: cfg.dpopNonce,
				ProofLifespan: proofLifespan,
				ClockSkew:     proofSkew,
			},
			Registration: oauth2provider.RegistrationConfig{
				Secret:      registrationSecret,
				EndpointURL: cfg.registrationEndpoint,
				GrantTypes:  []string{"client_credentials"},
			},
			VerifiedPresentation: cfg.vp,
		},
		replay:      replay.NewPostgres(pool),
		reconnected: reconnected,
		registrar: oauth2provider.Client{
			ID: cfg.registrarID, GrantTypes: []string{"client_credentials"},
			Scopes: cfg.registrarScopes, Audience: cfg.registrarAudiences, DPoPBound: true,
		},
		registrarSecret: registrarSecret,
		stores:          stores,
	}
	if len(cfg.vp.TrustedIssuers) > 0 {
		// Clients may register for the grant; the registrar itself needs only client_credentials.
		s.providerCfg.Registration.GrantTypes = append(s.providerCfg.Registration.GrantTypes, oauth2provider.VerifiedPresentationGrantType)
	}
	if len(cfg.registrarDelegable) > 0 {
		s.providerCfg.Registration.DelegableScopes = map[string][]string{cfg.registrarID: cfg.registrarDelegable}
	}
	s.live.Store(&live{routes: s.apiRoutes(nil, nil)})

	if s.apiLn, err = net.Listen("tcp", cfg.addr); err != nil {
		pool.Close()
		return nil, fmt.Errorf("API listener: %w", err)
	}
	if s.opsLn, err = net.Listen("tcp", cfg.opsAddr); err != nil {
		_ = s.apiLn.Close()
		pool.Close()
		return nil, fmt.Errorf("ops listener: %w", err)
	}
	s.api = s.httpServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.live.Load().routes.ServeHTTP(w, r)
	}))
	s.ops = s.httpServer(s.opsRoutes())
	return s, nil
}

func (s *server) addr() net.Addr    { return s.apiLn.Addr() }
func (s *server) opsAddr() net.Addr { return s.opsLn.Addr() }

// opsRoutes is what the kubelet probes: the health paths and nothing else, ever.
func (s *server) opsRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	return s.correlate(mux)
}

// apiRoutes is the published port. With no provider yet (the signer could not be built) every path
// but the health ones answers 503.
func (s *server) apiRoutes(provider oauth2provider.Provider, signer oauth2provider.TokenSigner) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	if provider == nil {
		mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable"})
		})
		return s.correlate(mux)
	}
	mux.Handle("POST /oauth2/token", provider.TokenHandler())
	mux.Handle("POST /oauth2/register", s.registrationGate(provider.RegistrationHandler()))
	mux.Handle("GET /.well-known/jwks.json", jwksHandler(signer))
	mux.Handle("POST /oauth2/challenge", provider.ChallengeHandler())
	return s.correlate(bounded(mux))
}

// bounded gives every API request a deadline, so its database and transit calls cannot hang.
func bounded(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// jwksHandler publishes the signer's public key as a JWK set (RFC 7517), kid = signer.KeyID().
func jwksHandler(signer oauth2provider.TokenSigner) http.Handler {
	jwk := jose.PublicJWK(signer.Public())
	jwk.Kid = signer.KeyID()
	type key struct {
		jose.JWK
		Use string `json:"use"`
		Alg string `json:"alg"`
	}
	body, _ := json.Marshal(map[string][]key{"keys": {{JWK: jwk, Use: "sig", Alg: jose.AlgES256}}})
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	})
}

func (s *server) httpServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      max(s.cfg.readinessTimeout, requestTimeout) + 5*time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
}

// buildProvider reads the pinned transit key and builds the provider on it, retrying with backoff
// while OpenBao is not there or the key version is missing, so the process never crash-loops on
// a dependency. It returns once the provider serves, or when ctx ends.
func (s *server) buildProvider(ctx context.Context) {
	delay := time.Second
	for {
		err := s.tryProvider(ctx)
		if err == nil {
			return
		}
		s.log.WarnContext(ctx, "signer not ready, retrying", "err", err, "key", s.key.Ref(), "retry_in", delay.String())
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(2*delay, maxSignerBackoff)
	}
}

func (s *server) tryProvider(ctx context.Context) error {
	opCtx, cancel := context.WithTimeout(ctx, signerAttempt)
	defer cancel()
	signer, err := signing.NewTransit(opCtx, s.transit, s.key)
	if err != nil {
		return err
	}
	cfg := s.providerCfg
	cfg.AccessTokenSigner = signer
	provider, err := authelia.New(cfg, s.stores)
	if err != nil {
		return err
	}
	s.live.Store(&live{signer: signer, routes: s.apiRoutes(provider, signer)})
	s.log.InfoContext(ctx, "signer ready", "key", s.key.Ref(), "kid", signer.KeyID())
	return nil
}

// bootstrapRegistrar seeds the registrar (D12) before readiness can turn green, retrying while the
// database is not there. A registrar that exists with other settings is never overwritten: the
// connector stays not ready until an operator resolves it.
func (s *server) bootstrapRegistrar(ctx context.Context) {
	delay := time.Second
	for {
		opCtx, cancel := context.WithTimeout(ctx, signerAttempt)
		same, err := s.seedRegistrar(opCtx)
		cancel()
		switch {
		case err == nil && same:
			s.registrarState.Store(registrarOK)
			s.log.InfoContext(ctx, "registrar ready", "client_id", s.registrar.ID)
			return
		case err == nil:
			s.registrarState.Store(registrarConflict)
			s.log.ErrorContext(ctx, "registrar client exists with other settings; not overwriting it, not becoming ready",
				"client_id", s.registrar.ID)
			return
		case ctx.Err() != nil:
			return
		}
		s.log.WarnContext(ctx, "registrar not seeded, retrying", "err", err, "retry_in", delay.String())
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(2*delay, maxSignerBackoff)
	}
}

// seedRegistrar creates the registrar when it is missing and reports whether the stored one has the
// configured settings. A create that loses a race to another replica fails here and the retry reads
// the winner's row.
func (s *server) seedRegistrar(ctx context.Context) (same bool, err error) {
	stored, err := s.stores.Clients.GetClient(ctx, s.registrar.ID)
	if errors.Is(err, oauth2provider.ErrNotFound) {
		c := s.registrar
		if c.SecretHash, err = bcrypt.GenerateFromPassword(s.registrarSecret, bcrypt.DefaultCost); err != nil {
			return false, err
		}
		if err := s.stores.Clients.CreateClient(ctx, c); err != nil {
			return false, err
		}
		return true, nil
	}
	if err != nil {
		return false, err
	}
	sorted := func(v []string) []string { return slices.Sorted(slices.Values(v)) }
	// Metadata, when present, is what the provider reads instead of the columns below, so a
	// provisioned registrar carries none: a row with any could grant more than the columns say.
	return len(stored.Metadata) == 0 &&
		bcrypt.CompareHashAndPassword(stored.SecretHash, s.registrarSecret) == nil &&
		slices.Equal(sorted(stored.Scopes), sorted(s.registrar.Scopes)) &&
		slices.Equal(sorted(stored.Audience), sorted(s.registrar.Audience)) &&
		slices.Equal(stored.GrantTypes, s.registrar.GrantTypes) && stored.DPoPBound, nil
}

// serve runs both listeners until ctx ends or one fails. Asked to stop, it turns readiness red, keeps
// serving for the drain delay, then drains both listeners within the shutdown timeout, closing
// whatever is still open when that runs out, and closes the pool.
func (s *server) serve(ctx context.Context) error {
	bgCtx, stopBackground := context.WithCancel(context.Background())
	var background sync.WaitGroup
	background.Go(func() { s.buildProvider(bgCtx) })
	background.Go(func() { s.bootstrapRegistrar(bgCtx) })
	background.Go(func() { s.maintain(bgCtx) })
	results := make(chan error, 2)
	go func() { results <- s.api.Serve(s.apiLn) }()
	go func() { results <- s.ops.Serve(s.opsLn) }()
	pending := 2
	var cause error
	select {
	case <-ctx.Done():
		s.draining.Store(true)
		s.log.InfoContext(ctx, "draining", "delay", s.cfg.drainDelay.String())
		delay := time.NewTimer(s.cfg.drainDelay)
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
	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.shutdownTimeout)
	defer cancel()
	var drains sync.WaitGroup
	var drainErr error
	var drainMu sync.Mutex
	for _, srv := range []*http.Server{s.api, s.ops} {
		drains.Go(func() {
			if err := srv.Shutdown(shutdownCtx); err != nil {
				_ = srv.Close() // the drain ran out: force-close, so the pool below can close
				drainMu.Lock()
				drainErr = cmp.Or(drainErr, err)
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
	stopBackground()
	background.Wait()
	s.pool.Close()
	return cause
}

// maintain keeps the replay record honest (D8) and the tables small: the epoch sentinel is checked
// at start, every epochEvery and whenever the pool opened a connection, with a warning when the
// record may have been lost; expired tokens, nonces and proofs are swept every sweepEvery.
func (s *server) maintain(ctx context.Context) {
	op := func(f func(context.Context) error) {
		opCtx, cancel := context.WithTimeout(ctx, dbOpTimeout)
		defer cancel()
		if err := f(opCtx); err != nil && ctx.Err() == nil {
			s.log.DebugContext(ctx, "upkeep failed", "error", err.Error())
		}
	}
	check := func(ctx context.Context) error {
		lost, err := s.replay.CheckEpoch(ctx, time.Now())
		if lost {
			s.log.WarnContext(ctx, "replay record may have been lost (first start, or database crash recovery): "+
				"a DPoP proof may be replayed once within its acceptance window",
				slog.String("window", replayExposure.String()))
		}
		return err
	}
	sweep := func(ctx context.Context) error {
		_, err := pgstore.Sweep(ctx, s.pool, time.Now())
		_, err2 := s.replay.Sweep(ctx, time.Now())
		return errors.Join(err, err2)
	}
	op(check)
	epoch := time.NewTicker(epochEvery)
	defer epoch.Stop()
	sweeps := time.NewTicker(sweepEvery)
	defer sweeps.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-epoch.C:
			op(check)
		case <-s.reconnected:
			op(check)
		case <-sweeps.C:
			op(sweep)
		}
	}
}

// The words of /readyz: fixed, so nothing a dependency says reaches the body.
const (
	checkOK            = "ok"
	checkUnreachable   = "unreachable"
	checkSchemaBehind  = "schema_behind"
	checkUninitialized = "uninitialized"
	checkSealed        = "sealed"
	checkMissing       = "missing"  // the pinned key version does not exist
	checkMismatch      = "mismatch" // it exists but is not the key the signer was built on
	checkPending       = "pending"  // the signer is not built, or the registrar not seeded, yet
	checkConflict      = "conflict" // the registrar exists with other settings
)

type checks struct {
	Postgres   string `json:"postgres"`
	OpenBao    string `json:"openbao"`
	SigningKey string `json:"signing_key"`
	Registrar  string `json:"registrar"`
}

type report struct {
	Ready    bool    `json:"ready"`
	Draining bool    `json:"draining,omitempty"`
	Checks   *checks `json:"checks,omitempty"`
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

// handleReadyz answers 200 only when PostgreSQL is reachable with a current schema, OpenBao is
// initialised and unsealed, the pinned key version resolves to the signer's kid, and the service is
// not stopping. The three checks run at once under the readiness budget.
// ponytail: no coalescing of concurrent evaluations as the token store does; add it if /readyz on
// the published port is ever hammered.
func (s *server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	var rep report
	if s.draining.Load() {
		rep.Draining = true
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), s.cfg.readinessTimeout)
		defer cancel()
		c := &checks{}
		var wg sync.WaitGroup
		for dst, check := range map[*string]func(context.Context) string{
			&c.Postgres: s.checkPostgres, &c.OpenBao: s.checkOpenBao, &c.SigningKey: s.checkSigningKey,
		} {
			wg.Go(func() { *dst = check(ctx) })
		}
		wg.Wait()
		c.Registrar = [...]string{checkPending, checkOK, checkConflict}[s.registrarState.Load()]
		rep = report{Ready: c.Postgres == checkOK && c.OpenBao == checkOK && c.SigningKey == checkOK && c.Registrar == checkOK, Checks: c}
		state := int32(2)
		if rep.Ready {
			state = 1
		}
		if r.Context().Err() == nil && s.readyState.Swap(state) != state {
			if rep.Ready {
				s.log.InfoContext(r.Context(), "ready")
			} else {
				s.log.WarnContext(r.Context(), "not ready", "postgres", c.Postgres, "openbao", c.OpenBao, "signing_key", c.SigningKey, "registrar", c.Registrar)
			}
		}
	}
	status := http.StatusOK
	if !rep.Ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, rep)
}

// checkPostgres reads the newest version the token store's migration runner recorded. The connector
// cannot import that runner (another service's internal package), so it checks the version only;
// checksum drift is the token store's readiness to report.
func (s *server) checkPostgres(ctx context.Context) string {
	var version int
	err := s.pool.QueryRow(ctx, `SELECT coalesce(max(version), 0) FROM schema_migrations`).Scan(&version)
	var pgErr *pgconn.PgError
	switch {
	case errors.As(err, &pgErr) && pgErr.Code == "42P01": // undefined_table: never migrated
		return checkSchemaBehind
	case err != nil:
		s.log.WarnContext(ctx, "database unreachable", "err", err)
		return checkUnreachable
	case version < schemaVersion:
		return checkSchemaBehind
	}
	return checkOK
}

// checkOpenBao asks /v1/sys/health with every state mapped to 200, so the body is OpenBao's own word.
func (s *server) checkOpenBao(ctx context.Context) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(s.cfg.openBaoURL, "/")+"/v1/sys/health?uninitcode=200&sealedcode=200&standbycode=200", nil)
	if err != nil {
		return checkUnreachable
	}
	resp, err := s.health.Do(req)
	if err != nil {
		s.log.WarnContext(ctx, "OpenBao unreachable", "err", err)
		return checkUnreachable
	}
	defer func() { _ = resp.Body.Close() }()
	var state struct{ Initialized, Sealed bool }
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&state) != nil {
		return checkUnreachable
	}
	switch {
	case !state.Initialized:
		return checkUninitialized
	case state.Sealed:
		return checkSealed
	}
	return checkOK
}

// checkSigningKey resolves the pinned key version and compares its thumbprint with the signer's kid
// (D9: only the public key enters the process).
func (s *server) checkSigningKey(ctx context.Context) string {
	pub, err := s.transit.PublicKey(ctx, s.key)
	switch {
	case errors.Is(err, transit.ErrNotFound):
		return checkMissing
	case err != nil:
		return checkUnreachable
	}
	signer := s.live.Load().signer
	if signer == nil {
		return checkPending
	}
	if jkt, err := jose.PublicJWK(pub).Thumbprint(); err != nil || jkt != signer.KeyID() {
		return checkMismatch
	}
	return checkOK
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// correlate gives every request a correlation id, the caller's x-request-id when it is 1 to 128
// visible ASCII characters and a minted one otherwise, echoes it, and ends every request with one
// record: method, path, status, duration. No header, query or body is ever logged.
func (s *server) correlate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := correlationID(r.Header.Get("X-Request-Id"))
		ctx := context.WithValue(r.Context(), correlationKey{}, id)
		w.Header().Set("X-Request-Id", id)
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r.WithContext(ctx))
		s.log.InfoContext(ctx, "request", "method", r.Method, "path", r.URL.Path, "status", sw.status,
			"duration_ms", float64(time.Since(start).Microseconds())/1000)
	})
}

type correlationKey struct{}

// validCorrelationID: what a caller's x-request-id must be to be kept, 1 to 128 visible ASCII
// characters.
func validCorrelationID(id string) bool {
	ok := len(id) >= 1 && len(id) <= 128
	for i := 0; ok && i < len(id); i++ {
		ok = id[i] >= 0x21 && id[i] <= 0x7e
	}
	return ok
}

func correlationID(header string) string {
	if validCorrelationID(header) {
		return header
	}
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// stampHandler adds the request's correlation_id to every record written with its context.
// ponytail: stamps at the record level, so under a WithGroup it lands inside the group; the token
// store's handler handles groups, copy it if the connector ever logs in groups.
type stampHandler struct{ slog.Handler }

func (h stampHandler) Handle(ctx context.Context, r slog.Record) error {
	if id, ok := ctx.Value(correlationKey{}).(string); ok {
		r = r.Clone()
		r.AddAttrs(slog.String("correlation_id", id))
	}
	return h.Handler.Handle(ctx, r)
}

func (h stampHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return stampHandler{h.Handler.WithAttrs(attrs)}
}

func (h stampHandler) WithGroup(name string) slog.Handler {
	return stampHandler{h.Handler.WithGroup(name)}
}
