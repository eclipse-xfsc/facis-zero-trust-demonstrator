// Command access-runner serves the privileged-operations runner (services/accessrunner).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/accessrunner"
)

// config is the runner's file configuration. Credentials are files it reads, never values here.
type config struct {
	Addr string `json:"addr"`
	// The runner's own certificate: callers send their token and grant over TLS 1.3 only.
	TLSCertFile string             `json:"tls_cert_file"`
	TLSKeyFile  string             `json:"tls_key_file"`
	Trust       accessrunner.Trust `json:"trust"`
	Plane       []string           `json:"plane_namespaces"`
	Callers     struct {
		Issuer   string `json:"issuer"`
		JWKSURL  string `json:"jwks_url"`
		Audience string `json:"audience"`
		Client   string `json:"client"`
	} `json:"callers"`
	Kube struct {
		API       string `json:"api"`
		TokenFile string `json:"token_file"`
		CAFile    string `json:"ca_file"`
		Namespace string `json:"namespace"`
	} `json:"kube"`
	Keycloak struct {
		Base       string `json:"base"`
		Realm      string `json:"realm"`
		ClientID   string `json:"client_id"`
		SecretFile string `json:"secret_file"`
		CAFile     string `json:"ca_file,omitempty"` // when Keycloak's certificate is not from a public CA
	} `json:"keycloak"`
}

func run() error {
	file := flag.String("config", "/etc/access-runner/config.json", "runner configuration")
	flag.Parse()
	f, err := os.Open(*file)
	if err != nil {
		return errors.New("configuration unavailable")
	}
	defer func() { _ = f.Close() }()
	var cfg config
	dec := json.NewDecoder(io.LimitReader(f, 256<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&cfg) != nil {
		return errors.New("configuration invalid")
	}
	if cfg.Addr == "" || cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" || cfg.Trust.Target == "" || len(cfg.Trust.Approvers) == 0 || len(cfg.Plane) == 0 ||
		cfg.Callers.Issuer == "" || cfg.Callers.Audience == "" || cfg.Callers.Client == "" || cfg.Kube.API == "" || cfg.Keycloak.Base == "" {
		return errors.New("configuration incomplete")
	}
	for _, a := range cfg.Trust.Approvers {
		if _, err := a.Key.PublicKey(); err != nil || a.Subject == "" {
			return errors.New("approver key invalid")
		}
	}
	kubeHTTP := &http.Client{Timeout: 10 * time.Second}
	if cfg.Kube.CAFile != "" {
		pool, err := loadPool(cfg.Kube.CAFile)
		if err != nil {
			return errors.New("cluster CA invalid")
		}
		kubeHTTP.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}
	}
	plain := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}}}
	if cfg.Keycloak.CAFile != "" {
		pool, err := loadPool(cfg.Keycloak.CAFile)
		if err != nil {
			return errors.New("the Keycloak CA is invalid")
		}
		plain.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "access-runner")
	s := &accessrunner.Server{
		Trust:    cfg.Trust,
		Callers:  &accessrunner.Callers{Issuer: cfg.Callers.Issuer, JWKSURL: cfg.Callers.JWKSURL, Audience: cfg.Callers.Audience, Client: cfg.Callers.Client, HTTP: plain},
		Kube:     &accessrunner.Kube{API: cfg.Kube.API, TokenFile: cfg.Kube.TokenFile, HTTP: kubeHTTP, Namespace: cfg.Kube.Namespace},
		Keycloak: &accessrunner.Keycloak{Base: cfg.Keycloak.Base, Realm: cfg.Keycloak.Realm, ClientID: cfg.Keycloak.ClientID, SecretFile: cfg.Keycloak.SecretFile, HTTP: plain},
		Plane:    cfg.Plane,
		Log:      log,
	}
	server := &http.Server{Addr: cfg.Addr, Handler: s.Handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	failed := make(chan error, 1)
	go func() { failed <- server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile) }()
	log.Info("access runner listening", "addr", cfg.Addr, "target", cfg.Trust.Target, "policy_version", accessrunner.PolicyVersion())
	select {
	case <-ctx.Done():
	case <-failed:
		err = errors.New("listener stopped")
	}
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_ = server.Shutdown(shutdown)
	return err
}

func loadPool(file string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("no certificate")
	}
	return pool, nil
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err := run(); err != nil {
		slog.Error("access runner stopped", "reason", err.Error())
		os.Exit(1)
	}
}
