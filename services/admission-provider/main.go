// Command admission-provider is the Gatekeeper external-data provider that verifies container
// images before admission: a cosign signature by a trusted key and the two required attestations,
// by digest, from an allowed repository (internal/cosignverify).
//
// It serves ProviderRequests over HTTPS (TLS 1.3, client certificate required and verified against
// Gatekeeper's CA) and its metrics and health endpoints over plain HTTP on a separate port.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/cosignverify"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/ociclient"
)

func main() {
	var (
		addr        = flag.String("addr", ":8443", "HTTPS address for ProviderRequests")
		metricsAddr = flag.String("metrics-addr", ":9090", "HTTP address for /metrics, /healthz and /readyz")
		tlsCert     = flag.String("tls-cert", "/etc/admission-provider/tls/tls.crt", "server certificate (PEM)")
		tlsKey      = flag.String("tls-key", "/etc/admission-provider/tls/tls.key", "server key (PEM)")
		clientCA    = flag.String("client-ca", "/etc/admission-provider/client-ca/ca.crt", "CA that client certificates must chain to (Gatekeeper's)")
		policy      = flag.String("trust-policy", "/etc/admission-provider/trust/policy.json", `trust policy: {"repositories": [...], "publicKeys": "<PEM>"}`)
		timeout     = flag.Duration("request-timeout", time.Second, "deadline for answering one ProviderRequest")
		concurrency = flag.Int("concurrency", 8, "registry verifications in flight at once")
		reload      = flag.Duration("reload-interval", 10*time.Second, "how often TLS and trust files are re-read")
		plainHTTP   = flag.String("insecure-plain-http-registry", "", "a registry host spoken to over http (a local test registry only)")
	)
	flag.Parse()
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err := run(*addr, *metricsAddr, &tlsFiles{certFile: *tlsCert, keyFile: *tlsKey, clientCAFile: *clientCA},
		*policy, *timeout, *concurrency, *reload, *plainHTTP); err != nil {
		slog.Error("admission-provider stopped", "err", err)
		os.Exit(1)
	}
}

func run(addr, metricsAddr string, tf *tlsFiles, policy string, timeout time.Duration, concurrency int, reload time.Duration, plainHTTP string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	var opts ociclient.Options
	if plainHTTP != "" {
		opts.PlainHTTP = []string{plainHTTP}
	}
	// The verifier starts with an empty policy (nothing allowed) until the trust files load.
	v := cosignverify.New(ociclient.New(opts), &cosignverify.Policy{}, concurrency)
	tr := &trust{file: policy, apply: v.SetPolicy}
	if err := tr.load(); err != nil {
		slog.Error("trust policy invalid; answering with a system error until it is fixed", "err", err)
	}
	if err := tf.load(); err != nil {
		return err
	}
	go watch(ctx, reload, "trust policy", tr.load)
	go watch(ctx, reload, "TLS material", tf.load)

	m := newMetrics(&v.Stats)
	ops := http.NewServeMux()
	ops.Handle("GET /metrics", m)
	ops.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	ops.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if tr.err() != nil {
			http.Error(w, "trust policy invalid", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	servers := []*http.Server{
		{Addr: addr, Handler: &handler{verifier: v, trust: tr, timeout: timeout, metrics: m}, TLSConfig: tf.serverConfig(),
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: timeout + 5*time.Second},
		{Addr: metricsAddr, Handler: ops, ReadHeaderTimeout: 5 * time.Second},
	}
	errs := make(chan error, len(servers))
	go func() { errs <- servers[0].ListenAndServeTLS("", "") }()
	go func() { errs <- servers[1].ListenAndServe() }()
	slog.Info("admission-provider listening", "addr", addr, "metrics", metricsAddr)

	var err error
	select {
	case err = <-errs:
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutdown)
	}
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}
