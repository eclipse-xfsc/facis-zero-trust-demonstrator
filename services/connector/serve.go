package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

// minSecret is the shortest HMAC secret the provider accepts.
const minSecret = 32

// config is the service's configuration surface. Secrets are not in it: only the paths of the
// files that hold them.
type config struct {
	addr, opsAddr          string
	databaseURL            string // a credential; never logged
	openBaoURL             string
	openBaoTokenFile       string
	issuer                 string
	signingKey             string
	signingKeyVersion      int
	registrationEndpoint   string
	tokenSecretFile        string
	registrationSecretFile string
	// The registrar (D12): the client allowed to register others, seeded at start.
	registrarID            string
	registrarSecretFile    string
	registrarScopes        []string
	registrarAudiences     []string // the ceiling of a registrar token's audience
	accessTokenLifespan    time.Duration
	dpopEnforce, dpopNonce bool
	readinessTimeout       time.Duration
	drainDelay             time.Duration
	shutdownTimeout        time.Duration

	// The verified-presentation grant: off unless the issuers file is set, read at start.
	vpIssuersFile, vpScopeMapFile string
	vp                            oauth2provider.VerifiedPresentationConfig
	exclusiveAudiences            []string
	allowAudienceMigration        bool
	registrarDelegable            []string // scopes the registrar may grant beyond its token's
}

type serveOptions struct {
	cfg   config
	level slog.Level
}

// parseServe reads the serve flags. As in the token store, the environment fills what the command
// line did not set, after parsing, so no environment value, the database URL above all, is ever part
// of the usage text the flag package prints on an error.
func parseServe(args []string, env func(string) string, stderr io.Writer) (serveOptions, error) {
	opts := serveOptions{level: slog.LevelInfo}
	c := &opts.cfg
	var registrarScopes, registrarAudiences, registrarDelegable, exclusiveAudiences string
	fs := flag.NewFlagSet("connector serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	strs := []struct {
		name, variable, def, help string
		dst                       *string
	}{
		{"addr", "CONNECTOR_ADDR", ":8080", "API listener address", &c.addr},
		{"ops-addr", "CONNECTOR_OPS_ADDR", ":9090", "ops listener address, /healthz and /readyz", &c.opsAddr},
		{"database-url", "CONNECTOR_DATABASE_URL", "", "PostgreSQL connection URL", &c.databaseURL},
		{"openbao-url", "CONNECTOR_OPENBAO_URL", "", "OpenBao URL, http(s)://host[:port]", &c.openBaoURL},
		{"openbao-token-file", "CONNECTOR_OPENBAO_TOKEN_FILE", "", "file holding the OpenBao token", &c.openBaoTokenFile},
		{"issuer", "CONNECTOR_ISSUER", "", "iss of the access tokens, https://...", &c.issuer},
		{"signing-key", "CONNECTOR_SIGNING_KEY", "", "transit key that signs the access tokens", &c.signingKey},
		{"registration-endpoint", "CONNECTOR_REGISTRATION_ENDPOINT", "", "absolute URL of the registration endpoint", &c.registrationEndpoint},
		{"token-secret-file", "CONNECTOR_TOKEN_SECRET_FILE", "", "file holding the access-token HMAC secret", &c.tokenSecretFile},
		{"registration-secret-file", "CONNECTOR_REGISTRATION_SECRET_FILE", "", "file holding the registration-token HMAC secret", &c.registrationSecretFile},
		{"registrar-id", "CONNECTOR_REGISTRAR_ID", "", "client id of the registrar", &c.registrarID},
		{"registrar-secret-file", "CONNECTOR_REGISTRAR_SECRET_FILE", "", "file holding the registrar's client secret", &c.registrarSecretFile},
		{"registrar-scopes", "CONNECTOR_REGISTRAR_SCOPES", "", "comma-separated scopes of the registrar, connector:client_registration among them", &registrarScopes},
		{"registrar-audiences", "CONNECTOR_REGISTRAR_AUDIENCES", "", "comma-separated audiences of the registrar: the registration endpoint and the resource audiences registered clients may name", &registrarAudiences},
		{"exclusive-audiences", "CONNECTOR_EXCLUSIVE_AUDIENCES", "", "comma-separated mutually exclusive client audiences", &exclusiveAudiences},
		{"registrar-delegable-scopes", "CONNECTOR_REGISTRAR_DELEGABLE_SCOPES", "", "comma-separated scopes the registrar may grant to the clients it registers beyond its token's", &registrarDelegable},
		{"vp-trusted-issuers-file", "CONNECTOR_VP_TRUSTED_ISSUERS_FILE", "", "JSON file of the IF-03 issuers and their keys; enables the verified-presentation grant", &c.vpIssuersFile},
		{"vp-scope-map-file", "CONNECTOR_VP_SCOPE_MAP_FILE", "", "JSON file mapping outcome claims to scopes, required with the issuers file", &c.vpScopeMapFile},
	}
	for _, s := range strs {
		fs.StringVar(s.dst, s.name, s.def, s.help+" ($"+s.variable+")")
	}
	durs := []struct {
		name, variable string
		def            time.Duration
		help           string
		dst            *time.Duration
	}{
		{"access-token-lifespan", "CONNECTOR_ACCESS_TOKEN_LIFESPAN", 300 * time.Second, "access-token lifetime", &c.accessTokenLifespan},
		{"readiness-timeout", "CONNECTOR_READINESS_TIMEOUT", 2 * time.Second, "budget of one /readyz evaluation", &c.readinessTimeout},
		{"drain-delay", "CONNECTOR_DRAIN_DELAY", 5 * time.Second, "time /readyz answers 503 before the listeners close on SIGTERM", &c.drainDelay},
		{"shutdown-timeout", "CONNECTOR_SHUTDOWN_TIMEOUT", 10 * time.Second, "drain of the listeners on SIGTERM", &c.shutdownTimeout},
	}
	for _, d := range durs {
		fs.DurationVar(d.dst, d.name, d.def, d.help+" ($"+d.variable+")")
	}
	bools := []struct {
		name, variable, help string
		dst                  *bool
	}{
		{"allow-audience-migration", "CONNECTOR_ALLOW_AUDIENCE_MIGRATION", "warn instead of failing readiness for existing conflicting clients; grants remain refused", &c.allowAudienceMigration},
		{"dpop-enforce", "CONNECTOR_DPOP_ENFORCE", "require a DPoP proof from every client", &c.dpopEnforce},
		{"dpop-nonce", "CONNECTOR_DPOP_NONCE", "challenge with a server DPoP nonce", &c.dpopNonce},
	}
	for _, b := range bools {
		fs.BoolVar(b.dst, b.name, true, b.help+" ($"+b.variable+")")
	}
	fs.IntVar(&c.signingKeyVersion, "signing-key-version", 0, "pinned version of the signing key ($CONNECTOR_SIGNING_KEY_VERSION)")
	level := fs.String("log-level", "info", "debug, info, warn or error ($CONNECTOR_LOG_LEVEL)")
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if fs.NArg() > 0 {
		return opts, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	fromEnv := func(name, variable string) (string, bool) {
		if set[name] {
			return "", false
		}
		v := env(variable)
		return v, v != ""
	}
	for _, s := range strs {
		if v, ok := fromEnv(s.name, s.variable); ok {
			*s.dst = v
		}
	}
	if v, ok := fromEnv("log-level", "CONNECTOR_LOG_LEVEL"); ok {
		*level = v
	}
	for _, d := range durs {
		if v, ok := fromEnv(d.name, d.variable); ok {
			parsed, err := time.ParseDuration(v)
			if err != nil {
				return opts, fmt.Errorf("%s: %w", d.variable, err)
			}
			*d.dst = parsed
		}
	}
	for _, b := range bools {
		if v, ok := fromEnv(b.name, b.variable); ok {
			parsed, err := strconv.ParseBool(v)
			if err != nil {
				return opts, fmt.Errorf("%s: %w", b.variable, err)
			}
			*b.dst = parsed
		}
	}
	if v, ok := fromEnv("signing-key-version", "CONNECTOR_SIGNING_KEY_VERSION"); ok {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return opts, fmt.Errorf("CONNECTOR_SIGNING_KEY_VERSION: %w", err)
		}
		c.signingKeyVersion = parsed
	}
	if err := opts.level.UnmarshalText([]byte(*level)); err != nil {
		return opts, fmt.Errorf("--log-level: %w", err)
	}
	c.registrarScopes = splitList(registrarScopes)
	c.registrarAudiences = splitList(registrarAudiences)
	c.registrarDelegable = splitList(registrarDelegable)
	c.exclusiveAudiences = splitList(exclusiveAudiences)
	if err := c.validate(); err != nil {
		return opts, err
	}
	var err error
	c.vp, err = loadVP(c.vpIssuersFile, c.vpScopeMapFile)
	return opts, err
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// validate reports the first thing the service cannot run with.
func (c config) validate() error {
	required := []struct{ value, name string }{
		{c.addr, "--addr"}, {c.opsAddr, "--ops-addr"},
		{c.databaseURL, "--database-url or CONNECTOR_DATABASE_URL"},
		{c.openBaoURL, "--openbao-url or CONNECTOR_OPENBAO_URL"},
		{c.openBaoTokenFile, "--openbao-token-file or CONNECTOR_OPENBAO_TOKEN_FILE"},
		{c.issuer, "--issuer or CONNECTOR_ISSUER"},
		{c.signingKey, "--signing-key or CONNECTOR_SIGNING_KEY"},
		{c.registrationEndpoint, "--registration-endpoint or CONNECTOR_REGISTRATION_ENDPOINT"},
		{c.tokenSecretFile, "--token-secret-file or CONNECTOR_TOKEN_SECRET_FILE"},
		{c.registrationSecretFile, "--registration-secret-file or CONNECTOR_REGISTRATION_SECRET_FILE"},
		{c.registrarID, "--registrar-id or CONNECTOR_REGISTRAR_ID"},
		{c.registrarSecretFile, "--registrar-secret-file or CONNECTOR_REGISTRAR_SECRET_FILE"},
	}
	for _, r := range required {
		if r.value == "" {
			return fmt.Errorf("missing: set %s", r.name)
		}
	}
	if c.signingKeyVersion < 1 {
		return errors.New("missing: set --signing-key-version or CONNECTOR_SIGNING_KEY_VERSION to the pinned version, 1 or more")
	}
	if err := validateBaseURL(c.openBaoURL); err != nil {
		return err
	}
	if u, err := url.Parse(c.issuer); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("the issuer must be an https:// URL")
	}
	if u, err := url.Parse(c.registrationEndpoint); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return errors.New("the registration endpoint must be an absolute http(s):// URL")
	}
	if !slices.Contains(c.registrarScopes, oauth2provider.RegistrationScope) {
		return errors.New("--registrar-scopes must include " + oauth2provider.RegistrationScope)
	}
	if !slices.Contains(c.registrarAudiences, c.registrationEndpoint) {
		return errors.New("--registrar-audiences must include the registration endpoint")
	}
	if slices.Contains(c.registrarDelegable, oauth2provider.RegistrationScope) {
		return errors.New("--registrar-delegable-scopes cannot include " + oauth2provider.RegistrationScope)
	}
	if c.accessTokenLifespan <= 0 {
		return errors.New("the access-token lifespan must be longer than 0")
	}
	if c.readinessTimeout <= 0 {
		return errors.New("the readiness timeout must be longer than 0")
	}
	if c.drainDelay < 0 {
		return errors.New("the drain delay cannot be negative")
	}
	if c.shutdownTimeout <= 0 {
		return errors.New("the shutdown timeout must be longer than 0")
	}
	return nil
}

// validateBaseURL accepts http(s)://host[:port], with at most a trailing slash (the token store's rule).
func validateBaseURL(raw string) error {
	const want = "the OpenBao URL must be http(s)://host[:port], nothing more"
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		strings.Trim(u.Path, "/") != "" || u.Opaque != "" || strings.ContainsAny(raw, "?#") {
		return errors.New(want)
	}
	return nil
}

// readSecret reads an HMAC secret from its file. A trailing line break, which a secret mounted from
// a file often carries, is not part of it. Errors name the file, never its content.
func readSecret(path, what string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	b = bytes.TrimRight(b, "\r\n")
	if len(b) < minSecret {
		return nil, fmt.Errorf("%s in %s is shorter than %d bytes", what, path, minSecret)
	}
	return b, nil
}

// serve runs the service until SIGTERM or SIGINT, then drains and exits 0. Its records go to stdout
// as JSON, every one naming the service and the instance, and every one written while a request is
// handled naming that request's correlation id.
func serve(args []string, stdout, stderr io.Writer) int {
	opts, err := parseServe(args, os.Getenv, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		_, _ = fmt.Fprintf(stderr, "connector: %v\n", err)
		return exitUsage
	}
	hostname, _ := os.Hostname()
	log := slog.New(stampHandler{slog.NewJSONHandler(stdout, &slog.HandlerOptions{Level: opts.level})}).
		With("service", "connector", "instance", hostname)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	s, err := newServer(ctx, opts.cfg, log)
	if err != nil {
		log.ErrorContext(ctx, "starting the connector", "err", err)
		return exitFailed
	}
	log.InfoContext(ctx, "connector listening", "addr", s.addr().String(), "ops_addr", s.opsAddr().String())
	if err := s.serve(ctx); err != nil {
		log.ErrorContext(ctx, "connector stopped with an error", "err", err)
		return exitFailed
	}
	log.InfoContext(ctx, "connector stopped")
	return exitOK
}
