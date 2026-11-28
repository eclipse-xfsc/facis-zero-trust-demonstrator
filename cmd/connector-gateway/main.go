// Command connector-gateway runs one role of the attested-channel gateway
// (internal/connectorgateway): an ingress terminates mutually attested channels from the peer
// zone and forwards each stream to one in-zone target; an egress accepts in-zone streams and
// originates a mutually attested channel to the peer zone's ingress.
//
//	connector-gateway --config /etc/gateway/gateway.json
//
// The configuration is the channel configuration of internal/connectorgateway plus two optional
// fields: an "attestation" block, with which the gateway first obtains a fresh attestation report
// from its zone's cmcd and verifies it against the metadata CA and the zone's attestation
// configuration in Git (internal/atls/provision.Check) before it opens any listener, so a zone
// whose evidence is not the one in Git refuses to serve; and "health", an address on which GET
// /healthz answers 200 once the role serves, and never before: the readiness of the pod. Every
// decision is one JSON line on stdout.
//
// Exit status: 0 after an orderly stop (SIGINT, SIGTERM); 2 when the startup check obtained a
// report and rejected it; 3 when no report could be obtained from cmcd; 1 for a configuration or
// listener error, or when a decision could not be recorded (the role stops: an unrecorded decision
// must not serve).
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls/provision"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorgateway"
)

// fileConfig is the configuration file: the channel configuration and the startup check.
type fileConfig struct {
	connectorgateway.Config
	// StartupCheck is the "attestation" block; absent, the role serves without the check.
	StartupCheck *attestationConfig `json:"attestation,omitempty"`
	// Health is the host:port of the readiness endpoint; empty, none is served.
	Health string `json:"health,omitempty"`
}

// attestationConfig is the startup check of the zone's evidence (docs/attestation-provisioning.md,
// step 5): the zone's attestation configuration as kept in Git and the CA that signed its
// reference metadata. The report is requested from the channel configuration's cmcd.
type attestationConfig struct {
	// Zone is the path of the zone's attestation configuration (deployment/attestation/<zone>.json).
	Zone string `json:"zone"`
	// MetadataCA are PEM files holding the metadata CA certificates.
	MetadataCA []string `json:"metadataCA"`
	// TimeoutSeconds bounds the wait for cmcd; 0 means 30 seconds.
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`
}

// checkFailed marks an error of the startup check that came with a report: the report verified
// as something other than success, or its measured values are not the configured ones.
type checkFailed struct{ error }

func (e checkFailed) Unwrap() error { return e.error }

// checkEvidence is provision.Check; tests replace it to drive the startup decision.
var checkEvidence = provision.Check

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	err := run(ctx, os.Args[1:], os.Stdout, stop)
	if code := exitCode(err); code != 0 {
		fmt.Fprintln(os.Stderr, "connector-gateway:", err)
		os.Exit(code)
	}
}

// exitCode maps an error of run to the process exit status.
func exitCode(err error) int {
	var failed checkFailed
	switch {
	case err == nil:
		return 0
	case errors.Is(err, provision.ErrNoReport):
		return 3
	case errors.As(err, &failed):
		return 2
	}
	return 1
}

// run loads the configuration, performs the startup check when configured, serves the role until
// ctx ends, and records every decision as one JSON line on out. stop ends the run from inside:
// it is called when a decision cannot be recorded, since an unrecorded decision must not serve.
func run(ctx context.Context, args []string, out io.Writer, stop func()) error {
	fs := flag.NewFlagSet("connector-gateway", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", "/etc/gateway/gateway.json", "gateway configuration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("connector-gateway takes no positional argument")
	}
	cfg, err := load(*path)
	if err != nil {
		return err
	}
	att, err := cfg.Attestation()
	if err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	var mu sync.Mutex
	var recordErr error
	record := func(e connectorgateway.Event) {
		mu.Lock()
		defer mu.Unlock()
		if recordErr != nil {
			return
		}
		if err := enc.Encode(e); err != nil {
			recordErr = err
			stop()
		}
	}
	if cfg.StartupCheck != nil {
		if err := startupCheck(ctx, cfg, record); err != nil {
			return err
		}
	}
	g, err := connectorgateway.Start(ctx, cfg.Config, att, record)
	if err != nil {
		return err
	}
	// The readiness endpoint opens last: ready means the check passed and the role listens.
	if cfg.Health != "" {
		ln, err := net.Listen("tcp", cfg.Health)
		if err != nil {
			_ = g.Close()
			return fmt.Errorf("health: %w", err)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/healthz" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
		}), ReadHeaderTimeout: 5 * time.Second}
		go func() { _ = srv.Serve(ln) }()
		defer func() { _ = srv.Close() }()
	}
	<-ctx.Done()
	err = g.Close()
	mu.Lock()
	defer mu.Unlock()
	if recordErr != nil {
		return fmt.Errorf("a decision could not be recorded: %w", recordErr)
	}
	return err
}

// load reads the configuration file; unknown fields are refused.
func load(path string) (*fileConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var cfg fileConfig
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if cfg.Health != "" {
		if _, _, err := net.SplitHostPort(cfg.Health); err != nil {
			return nil, fmt.Errorf("health: %w", err)
		}
	}
	if a := cfg.StartupCheck; a != nil {
		if a.Zone == "" || len(a.MetadataCA) == 0 {
			return nil, errors.New("attestation needs zone and at least one metadataCA")
		}
		if a.TimeoutSeconds < 0 {
			return nil, errors.New("attestation.timeoutSeconds must not be negative")
		}
	}
	return &cfg, nil
}

// startupCheck is step 5 of the evidence provisioning: the zone's own evidence, verified in
// process against the metadata CA and the configuration in Git, before the role serves. Its
// outcome is recorded as a decision: "started" with reason "evidence_verified", or "refused" with
// the reason "evidence_rejected" (a report was obtained and rejected) or "attester_unavailable".
func startupCheck(ctx context.Context, cfg *fileConfig, record connectorgateway.Record) error {
	a := cfg.StartupCheck
	zone, err := provision.Load(a.Zone)
	if err != nil {
		return err
	}
	roots, err := loadCAs(a.MetadataCA)
	if err != nil {
		return err
	}
	timeout := time.Duration(a.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if _, err := checkEvidence(ctx, cfg.Cmcd, roots, zone); err != nil {
		reason := "evidence_rejected"
		if errors.Is(err, provision.ErrNoReport) {
			reason = "attester_unavailable"
		} else {
			err = checkFailed{err}
		}
		record(connectorgateway.Event{Role: cfg.Role, Decision: "refused", Reason: reason})
		return fmt.Errorf("startup check of zone %s: %w", zone.Zone, err)
	}
	record(connectorgateway.Event{Role: cfg.Role, Decision: "started", Reason: "evidence_verified"})
	return nil
}

// loadCAs parses every certificate of the PEM files; at least one is required.
func loadCAs(files []string) ([]*x509.Certificate, error) {
	var roots []*x509.Certificate
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for block, rest := pem.Decode(raw); block != nil; block, rest = pem.Decode(rest) {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			roots = append(roots, cert)
		}
	}
	if len(roots) == 0 {
		return nil, errors.New("no certificate in attestation.metadataCA")
	}
	return roots, nil
}
