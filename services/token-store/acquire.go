package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/keys"
)

type acquireOptions struct {
	databaseURL, openBaoURL, openBaoTokenFile, configFile, route string
	timeout                                                      time.Duration
}

// parseAcquire reads the flags of acquire (sweep is true for sweep-orphans and the keys commands,
// which take no route). As for serve, the environment fills in after parsing, so no value is ever
// in the usage text.
func parseAcquire(name string, sweep bool, args []string, env func(string) string, stderr io.Writer) (acquireOptions, error) {
	var o acquireOptions
	fs := flag.NewFlagSet("token-store "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	strs := []struct {
		flag, variable, help string
		dst                  *string
	}{
		{"database-url", "TOKEN_STORE_DATABASE_URL", "PostgreSQL connection URL", &o.databaseURL},
		{"openbao-url", "TOKEN_STORE_OPENBAO_URL", "OpenBao URL, http(s)://host[:port]", &o.openBaoURL},
		{"openbao-token-file", "TOKEN_STORE_OPENBAO_TOKEN_FILE", "file holding the OpenBao token, read on every call", &o.openBaoTokenFile},
		{"acquire-config", "TOKEN_STORE_ACQUIRE_CONFIG", "acquisition configuration file (JSON)", &o.configFile},
	}
	for _, s := range strs {
		fs.StringVar(s.dst, s.flag, "", s.help+" ($"+s.variable+")")
	}
	if !sweep {
		fs.StringVar(&o.route, "route", "", "name of the route to acquire a token for")
	}
	fs.DurationVar(&o.timeout, "timeout", time.Minute, "deadline for the whole run")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for _, s := range strs {
		if !set[s.flag] && *s.dst == "" {
			*s.dst = env(s.variable)
		}
		if *s.dst == "" {
			return o, fmt.Errorf("missing: set --%s or %s", s.flag, s.variable)
		}
	}
	if !sweep && o.route == "" {
		return o, errors.New("missing: --route")
	}
	if o.timeout <= 0 {
		return o, errors.New("--timeout must be longer than 0")
	}
	return o, nil
}

// store is what a one-shot command opens: the acquisition configuration, the transit client
// reading the token file on every call, and the connection pool. what names the step that failed,
// for the record; the error itself never carries a URL or a token.
type store struct {
	cfg  acquire.Loaded
	tc   *transit.Client
	pool *pgxpool.Pool
	what string
}

func openStore(ctx context.Context, o acquireOptions) (store, error) {
	var st store
	cfg, err := acquire.LoadConfig(o.configFile)
	if err != nil {
		st.what = "loading the acquisition config"
		return st, err
	}
	tokenFile := o.openBaoTokenFile
	tc, err := transit.New(transit.Config{Addr: o.openBaoURL, Token: func(context.Context) (string, error) {
		b, err := os.ReadFile(tokenFile)
		return strings.TrimSpace(string(b)), err
	}})
	if err != nil {
		st.what = "OpenBao client"
		return st, err
	}
	pool, err := pgxpool.New(ctx, o.databaseURL)
	if err != nil {
		// pgx redacts the password of a URL it cannot parse; the message still stays generic.
		st.what = "invalid database configuration"
		return st, errors.New("the database URL could not be parsed")
	}
	return store{cfg: cfg, tc: tc, pool: pool}, nil
}

// acquireCmd runs acquire --route NAME, or sweep-orphans, once. acquire prints the activated
// token's id and expiry as JSON, never the token.
func acquireCmd(name string, args []string, stdout, stderr io.Writer) int {
	sweep := name == "sweep-orphans"
	o, err := parseAcquire(name, sweep, args, os.Getenv, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		_, _ = fmt.Fprintf(stderr, "token-store: %v\n", err)
		return exitUsage
	}
	log := slog.New(slog.NewJSONHandler(stderr, nil)).With("service", "token-store")
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	st, err := openStore(ctx, o)
	if err != nil {
		log.ErrorContext(ctx, st.what, "err", err)
		return exitFailed
	}
	defer st.pool.Close()
	cfg, tc, pool := st.cfg, st.tc, st.pool
	route, ok := cfg.Routes[o.route]
	if !sweep && !ok {
		log.ErrorContext(ctx, "no such route", "route", o.route)
		return exitUsage
	}
	// As the service, acquire signs through a signer that never creates a key: a missing key is
	// reported (keys ensure registers one), never made on the way to a grant.
	a := &acquire.Acquirer{DB: pool, Signer: keys.ReadOnly{Lister: tc}, Secrets: tc, KeyName: cfg.SigningKey,
		Trusted: cfg.Trusted, Log: log, Prefix: cfg.KVPrefix}

	if sweep {
		n, err := a.SweepOrphans(ctx)
		if err != nil {
			log.ErrorContext(ctx, "orphan sweep failed", "deleted", n, "err", err)
			return exitFailed
		}
		_ = json.NewEncoder(stdout).Encode(map[string]int{"deleted": n})
		return exitOK
	}
	tok, err := a.Acquire(ctx, route)
	if err != nil {
		var e *acquire.Error
		code := ""
		if errors.As(err, &e) {
			code = e.Code
		}
		_ = json.NewEncoder(stdout).Encode(map[string]string{"route": route.Name, "reason_code": code})
		return exitFailed
	}
	_ = json.NewEncoder(stdout).Encode(map[string]any{"route": route.Name, "token_id": tok.ID, "expires_at": tok.ExpiresAt.UTC()})
	return exitOK
}
