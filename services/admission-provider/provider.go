package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/cosignverify"
)

// Gatekeeper external data, externaldata.gatekeeper.sh/v1beta1.
const apiVersion = "externaldata.gatekeeper.sh/v1beta1"

type providerRequest struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Request    struct {
		Keys []string `json:"keys"`
	} `json:"request"`
}

type item struct {
	Key   string `json:"key"`
	Value any    `json:"value,omitempty"`
	Error string `json:"error,omitempty"`
}

type providerResponse struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Response   struct {
		Idempotent  bool   `json:"idempotent"`
		Items       []item `json:"items"`
		SystemError string `json:"systemError,omitempty"`
	} `json:"response"`
}

const (
	maxRequestBytes = 1 << 20
	maxKeys         = 100
	verifiedValue   = "verified"
)

type verifier interface {
	VerifyImage(ctx context.Context, image string) cosignverify.Result
}

// handler answers ProviderRequests. Each key is an image reference; its item carries "verified" or
// an error "<ADM code>: <detail>". A request that cannot be answered at all gets a systemError,
// which the constraints treat as a denial, like any item error or missing item.
type handler struct {
	verifier verifier
	trust    *trust
	timeout  time.Duration
	metrics  *metrics
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() { h.metrics.observe(time.Since(start)) }()

	var resp providerResponse
	resp.APIVersion, resp.Kind = apiVersion, "ProviderResponse"
	resp.Response.Items = []item{}
	fail := func(status int, msg string) {
		h.metrics.systemErrors.Add(1)
		resp.Response.SystemError = cosignverify.CodeProviderDown + ": " + msg
		writeJSON(w, status, resp)
	}

	if r.Method != http.MethodPost {
		fail(http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req providerRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes)).Decode(&req); err != nil {
		fail(http.StatusBadRequest, "malformed request")
		return
	}
	if req.APIVersion != apiVersion || req.Kind != "ProviderRequest" {
		fail(http.StatusBadRequest, "not a "+apiVersion+" ProviderRequest")
		return
	}
	if len(req.Request.Keys) > maxKeys {
		fail(http.StatusBadRequest, fmt.Sprintf("more than %d keys", maxKeys))
		return
	}
	if err := h.trust.err(); err != nil {
		fail(http.StatusOK, "trust policy unavailable: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	items := make([]item, len(req.Request.Keys))
	var wg sync.WaitGroup
	for i, key := range req.Request.Keys {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := h.verifier.VerifyImage(ctx, key)
			if res.Code == cosignverify.CodeProviderDown && ctx.Err() != nil {
				res.Detail = "verification did not finish within " + h.timeout.String()
			}
			h.metrics.verdict(res.Code)
			items[i] = item{Key: key}
			if res.OK() {
				items[i].Value = verifiedValue
			} else {
				items[i].Error = res.Code + ": " + res.Detail
			}
		}()
	}
	wg.Wait()
	resp.Response.Idempotent = true
	resp.Response.Items = items
	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// trust is the trust policy, read from one JSON file: {"repositories": ["host/path", ...],
// "publicKeys": "<PEM>"}. One file, read at once, so an update can never be seen half applied (the
// repositories of one revision with the keys of another). Its revision is the hash of the file, so
// any edit empties the verifier's cache. An unreadable or invalid edit does not fall back to the
// previous policy: the provider answers with a system error until the file is valid again.
type trust struct {
	file  string
	apply func(*cosignverify.Policy)

	mu       sync.Mutex
	revision string
	loadErr  error
}

func (t *trust) err() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.loadErr
}

func (t *trust) load() error {
	b, err := os.ReadFile(t.file)
	var policy *cosignverify.Policy
	if err == nil {
		policy, err = parsePolicy(b)
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if err != nil {
		t.loadErr, t.revision = err, ""
		return err
	}
	if policy.Revision != t.revision {
		t.apply(policy)
		t.revision = policy.Revision
		slog.Info("trust policy loaded", "revision", policy.Revision, "repositories", len(policy.Repositories), "keys", len(policy.Keys))
	}
	t.loadErr = nil
	return nil
}

func parsePolicy(b []byte) (*cosignverify.Policy, error) {
	var doc struct {
		Repositories []string `json:"repositories"`
		PublicKeys   string   `json:"publicKeys"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("trust policy: %w", err)
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("trust policy: content after the policy object")
	}
	var prefixes []string
	for _, r := range doc.Repositories {
		if r = strings.TrimSpace(r); r != "" {
			prefixes = append(prefixes, r)
		}
	}
	if len(prefixes) == 0 {
		return nil, errors.New("trust policy: no allowed repository")
	}
	keys, err := cosignverify.ParsePublicKeys([]byte(doc.PublicKeys))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return &cosignverify.Policy{Repositories: prefixes, Keys: keys, Revision: hex.EncodeToString(sum[:])[:16]}, nil
}

// tlsFiles serves TLS 1.3 only and requires a client certificate chaining to the client CA
// (Gatekeeper's). The server key pair and the client CA are re-read from their files, so a rotated
// secret takes effect without a restart. A failed reload keeps the last good material and is
// logged; the files are mounted from Secrets, which the kubelet replaces atomically.
type tlsFiles struct {
	certFile, keyFile, clientCAFile string
	current                         atomic.Pointer[tls.Config]
	loaded                          [][]byte
}

func (f *tlsFiles) load() error {
	var contents [][]byte
	for _, name := range []string{f.certFile, f.keyFile, f.clientCAFile} {
		b, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		contents = append(contents, b)
	}
	if f.current.Load() != nil && slices.EqualFunc(contents, f.loaded, bytes.Equal) {
		return nil
	}
	cert, err := tls.X509KeyPair(contents[0], contents[1])
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(contents[2]) {
		return fmt.Errorf("%s: no certificate", f.clientCAFile)
	}
	f.current.Store(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	})
	f.loaded = contents
	slog.Info("TLS material loaded")
	return nil
}

// serverConfig hands each connection the current material.
func (f *tlsFiles) serverConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return f.current.Load(), nil
		},
	}
}

// watch re-reads the files every interval until ctx ends.
//
// ponytail: polling instead of an inotify library; a Secret update reaches the pod within the
// kubelet sync period anyway, so a 10 s poll adds little to the rotation delay.
func watch(ctx context.Context, interval time.Duration, name string, load func() error) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := load(); err != nil {
				slog.Error("reload failed", "what", name, "err", err)
			}
		}
	}
}

// metrics is the Prometheus text exposition of the provider's counters, written by hand.
//
// ponytail: no client library for five series; move to prometheus/client_golang if the set grows.
type metrics struct {
	stats        *cosignverify.Stats
	systemErrors atomic.Int64

	mu       sync.Mutex
	verdicts map[string]int64
	buckets  []float64
	counts   []int64 // per bucket, made cumulative when rendered
	sum      float64
	count    int64
}

func newMetrics(stats *cosignverify.Stats) *metrics {
	b := []float64{0.05, 0.1, 0.25, 0.5, 1, 1.5, 2}
	return &metrics{stats: stats, verdicts: map[string]int64{}, buckets: b, counts: make([]int64, len(b))}
}

func (m *metrics) observe(d time.Duration) {
	s := d.Seconds()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, le := range m.buckets {
		if s <= le {
			m.counts[i]++
			break
		}
	}
	m.sum += s
	m.count++
}

func (m *metrics) verdict(code string) {
	if code == "" {
		code = "allowed"
	}
	m.mu.Lock()
	m.verdicts[code]++
	m.mu.Unlock()
}

func (m *metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	m.mu.Lock()
	defer m.mu.Unlock()
	var b strings.Builder
	counter := func(name, help string, v int64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
	}
	counter("ztd_admission_cache_hits_total", "Verifications answered from the cache.", m.stats.Hits.Load())
	counter("ztd_admission_cache_misses_total", "Verifications not answered from the cache.", m.stats.Misses.Load())
	counter("ztd_admission_system_errors_total", "Requests answered with a system error.", m.systemErrors.Load())
	b.WriteString("# HELP ztd_admission_verdicts_total Image verdicts by reason code.\n# TYPE ztd_admission_verdicts_total counter\n")
	for _, code := range slices.Sorted(maps.Keys(m.verdicts)) {
		fmt.Fprintf(&b, "ztd_admission_verdicts_total{code=%q} %d\n", code, m.verdicts[code])
	}
	b.WriteString("# HELP ztd_admission_request_duration_seconds Time to answer a ProviderRequest.\n# TYPE ztd_admission_request_duration_seconds histogram\n")
	var cumulative int64
	for i, le := range m.buckets {
		cumulative += m.counts[i]
		fmt.Fprintf(&b, "ztd_admission_request_duration_seconds_bucket{le=\"%g\"} %d\n", le, cumulative)
	}
	fmt.Fprintf(&b, "ztd_admission_request_duration_seconds_bucket{le=\"+Inf\"} %d\n", m.count)
	fmt.Fprintf(&b, "ztd_admission_request_duration_seconds_sum %g\nztd_admission_request_duration_seconds_count %d\n", m.sum, m.count)
	_, _ = io.WriteString(w, b.String())
}
