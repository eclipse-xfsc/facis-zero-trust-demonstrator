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

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire"
)

// keysCmd is the operator's side of the store's signing key: ensure registers the configured
// key's latest version (creating the key in transit if it is missing), rotate moves the store to
// the next version and retires the previous one, status lists the registered versions. These are
// the only commands that hold a transit client allowed to create or rotate; the service and
// acquire sign through a read-only one. Output is JSON on stdout and never carries key material:
// references, thumbprints and states only.
func keysCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "token-store: keys needs one of ensure, rotate, status")
		return exitUsage
	}
	action := args[0]
	switch action {
	case "ensure", "rotate", "status":
	default:
		_, _ = fmt.Fprintf(stderr, "token-store: unknown keys action %q; want ensure, rotate or status\n", action)
		return exitUsage
	}
	o, err := parseAcquire("keys "+action, true, args[1:], os.Getenv, stderr)
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
		// Configuration errors name a field, never a value; the transit and pool errors are generic.
		log.ErrorContext(ctx, st.what, "err", err)
		return exitFailed
	}
	defer st.pool.Close()
	cfg, tc, pool := st.cfg, st.tc, st.pool
	enc := json.NewEncoder(stdout)

	switch action {
	case "ensure":
		key, err := acquire.LoadKey(ctx, pool, tc, cfg.SigningKey)
		if err != nil {
			reason, _ := acquire.Reason(err)
			log.ErrorContext(ctx, "keys ensure failed", "key", cfg.SigningKey, "reason", reason)
			return exitFailed
		}
		_ = enc.Encode(map[string]string{"key": cfg.SigningKey, "key_ref": key.Ref(), "jkt": key.JKT(), "state": "active"})
	case "rotate":
		rot, err := acquire.Rotate(ctx, pool, tc, cfg.SigningKey)
		if err != nil {
			reason, _ := acquire.Reason(err)
			log.ErrorContext(ctx, "keys rotate failed", "key", cfg.SigningKey, "reason", reason)
			return exitFailed
		}
		_ = enc.Encode(rot)
	case "status":
		rows, err := acquire.KeyRows(ctx, pool, cfg.SigningKey)
		if err != nil {
			reason, _ := acquire.Reason(err)
			log.ErrorContext(ctx, "keys status failed", "key", cfg.SigningKey, "reason", reason)
			return exitFailed
		}
		// present says whether transit has the key at all; latest_version and the signing floor
		// (min_signing_version) are transit's, versions are the database's.
		present, latest, floor := true, 0, 0
		switch kv, f, err := tc.KeyStatus(ctx, cfg.SigningKey); {
		case err == nil:
			latest, floor = kv.Version, f
		case errors.Is(err, transit.ErrNotFound):
			present = false
		default:
			reason, _ := acquire.Reason(err)
			log.ErrorContext(ctx, "keys status failed", "key", cfg.SigningKey, "reason", reason)
			return exitFailed
		}
		_ = enc.Encode(map[string]any{"key": cfg.SigningKey, "present": present, "latest_version": latest,
			"min_signing_version": floor, "versions": rows})
	}
	return exitOK
}
