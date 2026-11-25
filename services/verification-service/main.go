// Command verification-service is the zone's verification service: it implements the presentation
// API the token store's presentation hook calls (docs/contracts/verification.v1.openapi.yaml). For
// one connector challenge it opens a verification request, judges the SD-JWT VC presentation a
// holder answers it with (internal/presentation: issuer trust, signature, disclosures, holder
// binding, validity, status list) and returns the IF-03 outcome, signed in OpenBao transit.
//
//	verification-service serve       run the service until SIGTERM
//	verification-service trust-set   print the trust-set entry of the outcome key, for the
//	                                 consumers' trusted-issuers file (if03.ParseIssuers' format)
//
// Every flag defaults to the VERIFICATION_SERVICE_* variable of the same name (upper case,
// dashes as underscores). The database URL and the OpenBao token are never logged.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/trustlist"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/meshcaller"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/statuslist"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
)

const usage = `usage:
  verification-service serve       run the service until SIGTERM; JSON records on stdout
  verification-service trust-set   print {"<issuer>": {"keys": [<outcome key JWK>]}} for the consumers

flags (each defaults to VERIFICATION_SERVICE_<NAME>, e.g. --database-url and VERIFICATION_SERVICE_DATABASE_URL):
  --addr ADDR                   API listener (default :8080)
  --ops-addr ADDR               /healthz and /readyz (default :9090)
  --public-url URL              the service's own base URL, for response_uri
  --database-url URL            PostgreSQL: the requests, answered once
  --openbao-url URL             OpenBao, http(s)://host[:port]
  --openbao-token-file PATH     file holding the OpenBao token, read on every call
  --signing-key NAME            transit key that signs the outcomes (created if missing)
  --issuer URI                  iss of the outcomes
  --callers IDS                 comma-separated SPIFFE IDs allowed to call (the token store's)
  --issuer-keys-file PATH       credential issuers and their keys, JSON (if03 trust-set format)
  --trust-list-file PATH        FIXTURE trust source: a TSPA trust list read from a file
  --tcr-url URL                 TRAIN trust source: the TCR's base URL (with --trust-scheme-pointers)
  --trust-scheme-pointers LIST  comma-separated trust framework pointers the TCR resolves
  --trust-refresh DURATION      how often the trust set is rebuilt (default 5m)
  --accepted-vct LIST           comma-separated credential types accepted
  --status-prefixes LIST        comma-separated URL prefixes status lists may be fetched from
`

type options struct {
	addr, opsAddr, publicURL, databaseURL, openBaoURL, openBaoTokenFile, signingKey, issuer string
	callers, acceptedVCT, statusPrefixes, pointers                                          []string
	issuerKeysFile, trustListFile, tcrURL                                                   string
	trustRefresh                                                                            time.Duration
}

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(args []string, env func(string) string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "serve" && args[0] != "trust-set") {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	o, err := parse(args[0], args[1:], env, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "verification-service: %v\n", err)
		return 2
	}
	log := slog.New(slog.NewJSONHandler(stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	kv, err := transit.New(transit.Config{Addr: o.openBaoURL, Token: tokenFile(o.openBaoTokenFile)})
	if err != nil {
		log.Error("openbao", "err", err)
		return 1
	}
	key, err := kv.EnsureKey(ctx, o.signingKey)
	if err != nil {
		log.Error("outcome key not available", "err", err)
		return 1
	}
	kid := fmt.Sprintf("%s-v%d", key.Name, key.Version)
	if args[0] == "trust-set" {
		pub, err := kv.PublicKey(ctx, key)
		if err != nil {
			log.Error("outcome key not read", "err", err)
			return 1
		}
		jwk := jose.PublicJWK(pub)
		jwk.Kid = kid
		_ = json.NewEncoder(stdout).Encode(map[string]any{o.issuer: map[string]any{"keys": []jose.JWK{jwk}}})
		return 0
	}
	return serve(ctx, o, log, kv, key, kid)
}

func serve(ctx context.Context, o options, log *slog.Logger, kv *transit.Client, key transit.KeyVersion, kid string) int {
	pool, err := pgxpool.New(ctx, o.databaseURL)
	if err != nil {
		log.Error("database", "err", err)
		return 1
	}
	defer pool.Close()
	st := store{db: pool}
	if err := st.migrate(ctx); err != nil {
		log.Error("schema not applied", "err", err)
		return 1
	}
	callers, err := meshcaller.NewXFCC(o.callers)
	if err != nil {
		log.Error("callers", "err", err)
		return 2
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 5 * time.Second}
	listed := pinnedList(o.trustListFile)
	if o.tcrURL != "" {
		listed = tcrList(noRedirect, o.tcrURL, o.pointers, &trustlist.Verifier{HTTP: noRedirect, Now: time.Now})
	} else {
		log.Warn("FIXTURE trust source: the pinned trust list is neither signature- nor hash-checked", "file", o.trustListFile)
	}
	s := &server{store: st, callers: callers, issuer: o.issuer, kid: kid, publicURL: o.publicURL, log: log, now: time.Now,
		sign: func(ctx context.Context, in []byte) ([]byte, error) { return kv.Sign(ctx, key, in) }}
	trust := trustConfig{keysFile: o.issuerKeysFile, listed: listed, acceptedVCT: o.acceptedVCT, statusPrefixes: o.statusPrefixes, statusHTTP: noRedirect}
	trust.refresh(ctx, s)
	go func() {
		t := time.NewTicker(o.trustRefresh)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				trust.refresh(ctx, s)
			}
		}
	}()

	ops := http.NewServeMux()
	ops.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	ops.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		c, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if s.policyAt(time.Now()) == nil || pool.Ping(c) != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	api := &http.Server{Addr: o.addr, Handler: s.routes(), ReadHeaderTimeout: 5 * time.Second}
	opsSrv := &http.Server{Addr: o.opsAddr, Handler: ops, ReadHeaderTimeout: 5 * time.Second}
	errs := make(chan error, 2)
	for _, srv := range []*http.Server{api, opsSrv} {
		go func() {
			if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				errs <- err
			}
		}()
	}
	log.Info("serving", "addr", o.addr, "ops_addr", o.opsAddr, "issuer", o.issuer, "kid", kid, "callers", o.callers)
	select {
	case err := <-errs:
		log.Error("listener", "err", err)
		return 1
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = api.Shutdown(shutdown)
	_ = opsSrv.Shutdown(shutdown)
	log.Info("drained")
	return 0
}

func tokenFile(path string) transit.TokenSource {
	return func(context.Context) (string, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", errors.New("openbao token file not readable")
		}
		return strings.TrimSpace(string(b)), nil
	}
}

func parse(cmd string, args []string, env func(string) string, stderr io.Writer) (options, error) {
	var o options
	var callers, vct, prefixes, pointers string
	fs := flag.NewFlagSet("verification-service "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	str := map[string]*string{
		"addr": &o.addr, "ops-addr": &o.opsAddr, "public-url": &o.publicURL, "database-url": &o.databaseURL,
		"openbao-url": &o.openBaoURL, "openbao-token-file": &o.openBaoTokenFile, "signing-key": &o.signingKey,
		"issuer": &o.issuer, "callers": &callers, "issuer-keys-file": &o.issuerKeysFile, "trust-list-file": &o.trustListFile,
		"tcr-url": &o.tcrURL, "trust-scheme-pointers": &pointers, "accepted-vct": &vct, "status-prefixes": &prefixes,
	}
	for name, p := range str {
		fs.StringVar(p, name, "", "") // the usage text above documents them
	}
	refresh := fs.String("trust-refresh", "", "")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	// The environment fills after parsing, never as a flag's default: the URL is a credential and
	// the flag package prints defaults.
	fill := func(name string, p *string) {
		if *p == "" {
			*p = env("VERIFICATION_SERVICE_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")))
		}
	}
	for name, p := range str {
		fill(name, p)
	}
	fill("trust-refresh", refresh)
	o.callers, o.acceptedVCT, o.statusPrefixes, o.pointers = list(callers), list(vct), list(prefixes), list(pointers)
	if o.addr == "" {
		o.addr = ":8080"
	}
	if o.opsAddr == "" {
		o.opsAddr = ":9090"
	}
	o.trustRefresh = 5 * time.Minute
	if *refresh != "" {
		d, err := time.ParseDuration(*refresh)
		if err != nil || d < time.Second {
			return o, errors.New("--trust-refresh must be a duration of at least 1s")
		}
		o.trustRefresh = d
	}
	missing := func(names ...string) error {
		for _, n := range names {
			if p, ok := str[n]; ok && *p == "" {
				return fmt.Errorf("missing --%s", n)
			}
		}
		return nil
	}
	if err := missing("openbao-url", "openbao-token-file", "signing-key", "issuer"); err != nil {
		return o, err
	}
	if cmd == "trust-set" {
		return o, nil
	}
	if err := missing("public-url", "database-url", "callers", "issuer-keys-file", "accepted-vct", "status-prefixes"); err != nil {
		return o, err
	}
	if (o.trustListFile == "") == (o.tcrURL == "") {
		return o, errors.New("set exactly one trust source: --tcr-url (TRAIN) or --trust-list-file (fixture)")
	}
	if o.tcrURL != "" && len(o.pointers) == 0 {
		return o, errors.New("--tcr-url needs --trust-scheme-pointers")
	}
	for _, p := range o.statusPrefixes {
		if err := statuslist.ValidPrefix(p); err != nil {
			return o, err
		}
	}
	return o, nil
}

func list(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
