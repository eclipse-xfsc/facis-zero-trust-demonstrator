// Command token-store is the zone's token store (docs/contracts/token-store.v1.openapi.yaml): it
// holds the upstream tokens minted to the zone, substitutes them for the guard and detects DPoP
// proof replay for the connector and the guard. This build carries the authorization database's
// schema and applies it, and runs the service: its listeners, its liveness and readiness and the
// correlation of its records; the service's endpoints follow.
//
//	token-store serve                  run the service until SIGTERM
//	token-store migrate up [--to N]    apply the migrations above the current version, up to N (default: all)
//	token-store migrate down --to N    revert to version N; 0 leaves the schema empty
//	token-store migrate status         report the database against the embedded migrations, as JSON
//
// The connection URL comes from --database-url or TOKEN_STORE_DATABASE_URL and is never logged;
// the key-value store's URL from --openbao-url or TOKEN_STORE_OPENBAO_URL. Exit codes: 0 done or
// drained, 1 failed, 2 usage, 3 the database is behind the embedded migrations or an applied one
// drifted (status).
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
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/schema"
)

const (
	exitOK         = 0
	exitFailed     = 1
	exitUsage      = 2
	exitNotCurrent = 3
)

const usage = `usage:
  token-store serve                   run the service until SIGTERM; JSON records on stdout
  token-store migrate up [--to N]     apply the migrations above the current version, up to N (default: all)
  token-store migrate down --to N     revert to version N; 0 leaves the schema empty
  token-store migrate status          report the database against the embedded migrations, as JSON

flags of serve (each defaults to the TOKEN_STORE_* variable of the same name):
  --addr ADDR                   API listener (default :8080)
  --ops-addr ADDR               ops listener, /healthz and /readyz for the kubelet (default :9090)
  --database-url URL            PostgreSQL connection URL
  --openbao-url URL             key-value store URL, http(s)://host[:port]
  --readiness-timeout DURATION  budget of one /readyz evaluation (default 2s)
  --drain-delay DURATION        time /readyz answers 503 before the listeners close on SIGTERM (default 5s)
  --shutdown-timeout DURATION   drain of the listeners on SIGTERM (default 10s)
  --log-level LEVEL             debug, info, warn or error (default info)

flags of every migrate command:
  --database-url URL   PostgreSQL connection URL (default: $TOKEN_STORE_DATABASE_URL)
  --timeout DURATION   deadline for the whole run, lock wait included (default 1m)
`

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "serve":
		return serve(args[1:], stdout, stderr)
	case "migrate":
		return migrate(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(stdout, usage)
		return exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "token-store: unknown command %q\n%s", args[0], usage)
		return exitUsage
	}
}

type migrateOptions struct {
	action      string
	databaseURL string
	to          int
	timeout     time.Duration
}

// parseMigrate reads the migrate subcommand and its flags. It is separate from the run so the
// argument handling is tested without a database.
func parseMigrate(args []string, env func(string) string, stderr io.Writer) (migrateOptions, error) {
	if len(args) == 0 {
		return migrateOptions{}, errors.New("migrate needs one of up, down, status")
	}
	opts := migrateOptions{action: args[0]}
	switch opts.action {
	case "up", "down", "status":
	default:
		return opts, fmt.Errorf("unknown migrate action %q; want up, down or status", opts.action)
	}
	fs := flag.NewFlagSet("token-store migrate "+opts.action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.databaseURL, "database-url", "", "PostgreSQL connection URL ($TOKEN_STORE_DATABASE_URL)")
	fs.IntVar(&opts.to, "to", -1, "target version (up: default latest; down: required, 0 empties the schema)")
	fs.DurationVar(&opts.timeout, "timeout", time.Minute, "deadline for the whole run, lock wait included")
	if err := fs.Parse(args[1:]); err != nil {
		return opts, err
	}
	if fs.NArg() > 0 {
		return opts, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if opts.databaseURL == "" {
		// The environment fills in after parsing, never as the flag's default: the flag package
		// prints defaults in the usage text it writes on an error, and the URL is a credential.
		opts.databaseURL = env("TOKEN_STORE_DATABASE_URL")
	}
	toSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "to" {
			toSet = true
		}
	})
	if toSet && opts.to < 0 {
		return opts, errors.New("--to must be 0 or more")
	}
	if opts.timeout <= 0 {
		return opts, errors.New("--timeout must be longer than 0")
	}
	if opts.databaseURL == "" {
		return opts, errors.New("no database: set --database-url or TOKEN_STORE_DATABASE_URL")
	}
	if opts.action == "down" && opts.to < 0 {
		return opts, errors.New("migrate down needs --to N; 0 empties the schema")
	}
	if opts.action == "up" && opts.to == 0 {
		return opts, errors.New("migrate up --to 0 would apply nothing; use down --to 0 to empty the schema")
	}
	return opts, nil
}

func migrate(args []string, stdout, stderr io.Writer) int {
	opts, err := parseMigrate(args, os.Getenv, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		_, _ = fmt.Fprintf(stderr, "token-store: %v\n", err)
		return exitUsage
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()

	conn, err := pgx.Connect(ctx, opts.databaseURL)
	if err != nil {
		// pgx names the user and database it tried, never the password, and redacts the password
		// of a URL it cannot parse.
		slog.Error("connecting to the database", "err", err)
		return exitFailed
	}
	defer func() { _ = conn.Close(context.Background()) }()
	runner, err := schema.NewRunner(conn)
	if err != nil {
		slog.Error("loading the embedded migrations", "err", err)
		return exitFailed
	}

	switch opts.action {
	case "up":
		applied, err := runner.Up(ctx, max(opts.to, 0))
		for _, m := range applied {
			slog.Info("migration applied", "version", m.Version, "name", m.Name)
		}
		if err != nil {
			slog.Error("migrate up", "err", err)
			return exitFailed
		}
		status, err := runner.Status(ctx)
		if err != nil {
			slog.Error("reading the schema status", "err", err)
			return exitFailed
		}
		slog.Info("schema is current", "version", status.Current, "applied_now", len(applied))
	case "down":
		reverted, err := runner.Down(ctx, opts.to)
		for _, m := range reverted {
			slog.Info("migration reverted", "version", m.Version, "name", m.Name)
		}
		if err != nil {
			slog.Error("migrate down", "err", err)
			return exitFailed
		}
		slog.Info("schema reverted", "version", opts.to, "reverted_now", len(reverted))
	case "status":
		status, err := runner.Status(ctx)
		if err != nil {
			slog.Error("reading the schema status", "err", err)
			return exitFailed
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(status); err != nil {
			return exitFailed
		}
		if !status.IsCurrent() {
			return exitNotCurrent
		}
	}
	return exitOK
}
