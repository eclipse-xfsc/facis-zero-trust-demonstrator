package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/server"
)

type serveOptions struct {
	cfg   server.Config
	level slog.Level
	// acquireConfig and openBaoTokenFile enable substitution (and renewal): the routes file, read at
	// start, and the OpenBao token, read on every call.
	acquireConfig, openBaoTokenFile string
}

// parseServe reads the serve flags. The environment fills what the command line did not set,
// after parsing: a flag always wins, a malformed variable only matters when its flag is absent,
// and no environment value, the connection URL above all, is ever part of the usage text the flag
// package prints on an error. It is separate from the run so the argument handling is tested
// without binding a port.
func parseServe(args []string, env func(string) string, stderr io.Writer) (serveOptions, error) {
	opts := serveOptions{level: slog.LevelInfo}
	fs := flag.NewFlagSet("token-store serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.cfg.Addr, "addr", ":8080", "API listener address ($TOKEN_STORE_ADDR)")
	fs.StringVar(&opts.cfg.OpsAddr, "ops-addr", ":9090", "ops listener address, /healthz and /readyz for the kubelet ($TOKEN_STORE_OPS_ADDR)")
	fs.StringVar(&opts.cfg.DatabaseURL, "database-url", "", "PostgreSQL connection URL ($TOKEN_STORE_DATABASE_URL)")
	fs.StringVar(&opts.cfg.OpenBaoURL, "openbao-url", "", "key-value store URL, http(s)://host[:port] ($TOKEN_STORE_OPENBAO_URL)")
	fs.DurationVar(&opts.cfg.ReadinessTimeout, "readiness-timeout", 2*time.Second, "budget of one /readyz evaluation ($TOKEN_STORE_READINESS_TIMEOUT)")
	fs.DurationVar(&opts.cfg.DrainDelay, "drain-delay", 5*time.Second, "time /readyz answers 503 before the listeners close on SIGTERM ($TOKEN_STORE_DRAIN_DELAY)")
	fs.DurationVar(&opts.cfg.ShutdownTimeout, "shutdown-timeout", 10*time.Second, "drain of the listeners on SIGTERM ($TOKEN_STORE_SHUTDOWN_TIMEOUT)")
	replayCallers := fs.String("replay-callers", "", "comma-separated SPIFFE IDs allowed to call /internal/replay-check ($TOKEN_STORE_REPLAY_CALLERS)")
	level := fs.String("log-level", "info", "debug, info, warn or error ($TOKEN_STORE_LOG_LEVEL)")
	fs.StringVar(&opts.acquireConfig, "acquire-config", "", "routes file, JSON: enables /internal/substitute and renewal ($TOKEN_STORE_ACQUIRE_CONFIG)")
	fs.StringVar(&opts.openBaoTokenFile, "openbao-token-file", "", "file holding the OpenBao token, read on every call ($TOKEN_STORE_OPENBAO_TOKEN_FILE)")
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if fs.NArg() > 0 {
		return opts, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	fromEnv := func(name, variable string, dst *string) {
		if !set[name] {
			if v := env(variable); v != "" {
				*dst = v
			}
		}
	}
	fromEnv("addr", "TOKEN_STORE_ADDR", &opts.cfg.Addr)
	fromEnv("ops-addr", "TOKEN_STORE_OPS_ADDR", &opts.cfg.OpsAddr)
	fromEnv("database-url", "TOKEN_STORE_DATABASE_URL", &opts.cfg.DatabaseURL)
	fromEnv("openbao-url", "TOKEN_STORE_OPENBAO_URL", &opts.cfg.OpenBaoURL)
	fromEnv("log-level", "TOKEN_STORE_LOG_LEVEL", level)
	fromEnv("replay-callers", "TOKEN_STORE_REPLAY_CALLERS", replayCallers)
	fromEnv("acquire-config", "TOKEN_STORE_ACQUIRE_CONFIG", &opts.acquireConfig)
	fromEnv("openbao-token-file", "TOKEN_STORE_OPENBAO_TOKEN_FILE", &opts.openBaoTokenFile)
	for _, id := range strings.Split(*replayCallers, ",") {
		if id = strings.TrimSpace(id); id != "" {
			opts.cfg.ReplayCallers = append(opts.cfg.ReplayCallers, id)
		}
	}
	for _, d := range []struct {
		name, variable string
		dst            *time.Duration
	}{
		{"readiness-timeout", "TOKEN_STORE_READINESS_TIMEOUT", &opts.cfg.ReadinessTimeout},
		{"drain-delay", "TOKEN_STORE_DRAIN_DELAY", &opts.cfg.DrainDelay},
		{"shutdown-timeout", "TOKEN_STORE_SHUTDOWN_TIMEOUT", &opts.cfg.ShutdownTimeout},
	} {
		if set[d.name] {
			continue
		}
		v := env(d.variable)
		if v == "" {
			continue
		}
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return opts, fmt.Errorf("%s: %w", d.variable, err)
		}
		*d.dst = parsed
	}
	if err := opts.level.UnmarshalText([]byte(*level)); err != nil {
		return opts, fmt.Errorf("--log-level: %w", err)
	}
	if opts.cfg.DatabaseURL == "" {
		return opts, errors.New("no database: set --database-url or TOKEN_STORE_DATABASE_URL")
	}
	if opts.cfg.OpenBaoURL == "" {
		return opts, errors.New("no key-value store: set --openbao-url or TOKEN_STORE_OPENBAO_URL")
	}
	if opts.acquireConfig != "" && opts.openBaoTokenFile == "" {
		return opts, errors.New("--acquire-config needs --openbao-token-file or TOKEN_STORE_OPENBAO_TOKEN_FILE")
	}
	if err := opts.cfg.Validate(); err != nil {
		return opts, err
	}
	return opts, nil
}

// loadAcquisition reads the routes file and makes the OpenBao client substitution signs and reads
// with. Errors name the field, never a value.
func (o *serveOptions) loadAcquisition() error {
	if o.acquireConfig == "" {
		return nil
	}
	loaded, err := acquire.LoadConfig(o.acquireConfig)
	if err != nil {
		return err
	}
	tokenFile := o.openBaoTokenFile
	bao, err := transit.New(transit.Config{Addr: o.cfg.OpenBaoURL, Token: func(context.Context) (string, error) {
		b, err := os.ReadFile(tokenFile)
		return strings.TrimSpace(string(b)), err
	}})
	if err != nil {
		return err
	}
	o.cfg.Acquisition, o.cfg.OpenBao = &loaded, bao
	return nil
}

// serve runs the service until SIGTERM or SIGINT, then drains and exits 0. Its records go to
// stdout as JSON, every one naming the service and the instance, and every one written while a
// request is handled naming that request's correlation id. The URLs are never logged.
func serve(args []string, stdout, stderr io.Writer) int {
	opts, err := parseServe(args, os.Getenv, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		_, _ = fmt.Fprintf(stderr, "token-store: %v\n", err)
		return exitUsage
	}
	if err := opts.loadAcquisition(); err != nil {
		_, _ = fmt.Fprintf(stderr, "token-store: %v\n", err)
		return exitUsage
	}
	hostname, _ := os.Hostname()
	opts.cfg.Instance = hostname
	log := slog.New(server.NewHandler(slog.NewJSONHandler(stdout, &slog.HandlerOptions{Level: opts.level}))).
		With("service", "token-store", "instance", hostname)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	s, err := server.New(ctx, opts.cfg, log)
	if err != nil {
		log.ErrorContext(ctx, "starting the token store", "err", err)
		return exitFailed
	}
	log.InfoContext(ctx, "token store listening", "addr", s.Addr().String(), "ops_addr", s.OpsAddr().String())
	if err := s.Serve(ctx); err != nil {
		log.ErrorContext(ctx, "token store stopped with an error", "err", err)
		return exitFailed
	}
	log.InfoContext(ctx, "token store stopped")
	return exitOK
}
