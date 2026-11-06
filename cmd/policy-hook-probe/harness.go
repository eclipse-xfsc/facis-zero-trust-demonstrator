package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/policy-hook-probe/internal/hook"
)

// The bootstraps, by the name the proofs and the evidence use.
const (
	filterBaseline = "baseline"
	filterExtAuthz = "ext-authz"
	filterExtProc  = "ext-proc"
)

type proveOptions struct {
	out, image, fixtures, templates string
	timeout, margin                 time.Duration
	requests, warmup                int
	concurrency                     string
}

func (o *proveOptions) register(fs *flag.FlagSet) {
	fs.StringVar(&o.out, "out", "", "`directory` the records are written to (required)")
	fs.StringVar(&o.image, "envoy-image", "", "Envoy image `reference`, pinned by digest (required)")
	fs.StringVar(&o.fixtures, "fixtures", "", "`directory` holding the contract fixtures (required)")
	fs.StringVar(&o.templates, "templates", "", "`directory` holding the Envoy bootstrap templates (required)")
	fs.DurationVar(&o.timeout, "timeout", 250*time.Millisecond, "bound Envoy puts on one hook call")
	fs.DurationVar(&o.margin, "margin", time.Second, "slack the fail-closed proof allows beyond the timeout")
	fs.IntVar(&o.requests, "requests", 2000, "requests per latency run")
	fs.IntVar(&o.warmup, "warmup", 200, "requests sent before a latency run is measured")
	fs.StringVar(&o.concurrency, "concurrency", "1,8", "comma-separated concurrencies of the latency runs")
}

func prove(ctx context.Context, args []string, stderr io.Writer) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		_, _ = fmt.Fprint(stderr, usage)
		return 1
	}
	proof := args[0]
	fs := flag.NewFlagSet("policy-hook-probe prove "+proof, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o proveOptions
	o.register(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return 1
	}
	for name, v := range map[string]string{"--out": o.out, "--envoy-image": o.image, "--fixtures": o.fixtures, "--templates": o.templates} {
		if v == "" {
			_, _ = fmt.Fprintf(stderr, "policy-hook-probe: prove needs %s\n", name)
			return 1
		}
	}
	names := []string{proof}
	if proof == "all" {
		names = proofOrder
	}
	h, err := newHarness(o, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "policy-hook-probe: %v\n", err)
		return 1
	}
	defer h.close()
	steps := h.proofs()
	for _, name := range names {
		if _, ok := steps[name]; !ok {
			_, _ = fmt.Fprintf(stderr, "policy-hook-probe: unknown proof %q\n%s", name, usage)
			return 1
		}
	}
	if err := h.start(ctx); err != nil {
		_, _ = fmt.Fprintf(stderr, "policy-hook-probe: %v\n", err)
		return 1
	}
	for _, name := range names {
		h.logf("proof: %s", name)
		if err := steps[name](ctx); err != nil {
			_, _ = fmt.Fprintf(stderr, "policy-hook-probe: %s: %v\n", name, err)
			return 1
		}
	}
	return 0
}

// harness holds what the proofs run against: the echo upstream in this process, the hook as a
// child process, and Envoy in a container. Logs go to a temporary directory; the records to out.
type harness struct {
	o      proveOptions
	stderr io.Writer
	fx     *hook.Fixtures
	work   string
	// bind is what the host processes bind to; fromEnvoy is how the container reaches them.
	bind, fromEnvoy string
	hostNetwork     bool
	hookPort        int
	listenPort      int
	adminPort       int
	upstreamPort    int
	client          *http.Client
	adapter         *adapter
	envoy           *envoyInstance
	cancel          context.CancelFunc
}

func newHarness(o proveOptions, stderr io.Writer) (*harness, error) {
	fx, err := hook.LoadFixtures(o.fixtures)
	if err != nil {
		return nil, fmt.Errorf("fixtures: %w", err)
	}
	if err := os.MkdirAll(o.out, 0o755); err != nil {
		return nil, err
	}
	work, err := os.MkdirTemp("", "policy-hook-probe.")
	if err != nil {
		return nil, err
	}
	h := &harness{o: o, stderr: stderr, fx: fx, work: work}
	if runtime.GOOS == "linux" {
		h.bind, h.fromEnvoy, h.hostNetwork = "127.0.0.1", "127.0.0.1", true
	} else {
		h.bind, h.fromEnvoy = "0.0.0.0", "host.docker.internal"
	}
	for _, p := range []*int{&h.hookPort, &h.listenPort, &h.adminPort, &h.upstreamPort} {
		if *p, err = freePort(h.bind); err != nil {
			return nil, err
		}
	}
	h.client = &http.Client{
		Transport: &http.Transport{MaxIdleConns: 256, MaxIdleConnsPerHost: 256, IdleConnTimeout: time.Minute},
		Timeout:   o.timeout + o.margin + 10*time.Second,
	}
	return h, nil
}

func (h *harness) logf(format string, args ...any) {
	_, _ = fmt.Fprintf(h.stderr, "%s policy-hook-probe: %s\n",
		time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), fmt.Sprintf(format, args...))
}

// start brings up the upstream and the hook; each proof then picks its Envoy bootstrap.
func (h *harness) start(ctx context.Context) error {
	ctx, h.cancel = context.WithCancel(ctx)
	addr, err := serveEcho(ctx, net.JoinHostPort(h.bind, strconv.Itoa(h.upstreamPort)))
	if err != nil {
		return fmt.Errorf("echo upstream: %w", err)
	}
	h.logf("echo upstream on %s", addr)
	h.adapter, err = startAdapter(ctx, adapterOptions{
		listen:   net.JoinHostPort(h.bind, strconv.Itoa(h.hookPort)),
		fixtures: h.o.fixtures,
		events:   h.eventsPath(),
		log:      filepath.Join(h.work, "adapter.log"),
	})
	if err != nil {
		return err
	}
	h.logf("policy hook (pid %d) on %s", h.adapter.cmd.Process.Pid, h.adapter.listen)
	return nil
}

func (h *harness) eventsPath() string { return filepath.Join(h.work, "events.log") }

// useEnvoy runs Envoy with the named bootstrap, replacing a running one.
func (h *harness) useEnvoy(ctx context.Context, filter string) error {
	h.stopEnvoy()
	cfg, err := h.render(filter)
	if err != nil {
		return err
	}
	inst, err := startEnvoyContainer(ctx, h.o.image, fmt.Sprintf("policy-hook-%s-%d", filter, os.Getpid()), cfg, h.hostNetwork, []int{h.listenPort, h.adminPort})
	if err != nil {
		return err
	}
	h.envoy = inst
	readyCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := inst.waitReady(readyCtx, h.adminURL()); err != nil {
		return err
	}
	h.logf("envoy (%s) listening on %s", filter, h.guardURL())
	return nil
}

func (h *harness) stopEnvoy() {
	if h.envoy != nil {
		h.envoy.stop()
		h.envoy = nil
	}
}

func (h *harness) render(filter string) (string, error) {
	return renderBootstrap(filepath.Join(h.o.templates, filter+".yaml.tmpl"), bootstrapData{
		BindAddress: h.bind, ListenPort: h.listenPort, AdminPort: h.adminPort,
		UpstreamHost: h.fromEnvoy, UpstreamPort: h.upstreamPort, HookHost: h.fromEnvoy, HookPort: h.hookPort,
		Timeout: envoyDuration(h.o.timeout),
	})
}

func (h *harness) guardURL() string { return "http://127.0.0.1:" + strconv.Itoa(h.listenPort) }
func (h *harness) adminURL() string { return "http://127.0.0.1:" + strconv.Itoa(h.adminPort) }

func (h *harness) close() {
	h.stopEnvoy()
	if h.adapter != nil {
		h.adapter.kill()
	}
	if h.cancel != nil {
		h.cancel()
	}
	_ = os.RemoveAll(h.work)
}

// response is what one request through Envoy returned, with what the upstream saw when it was
// forwarded.
type response struct {
	Status     int           `json:"status"`
	Headers    http.Header   `json:"headers"`
	Body       string        `json:"body"`
	Refusal    *hook.Refusal `json:"refusal,omitempty"`
	Upstream   *echoRecord   `json:"upstream,omitempty"`
	DurationMs float64       `json:"duration_ms"`
}

// send sends one request to Envoy's listener and reads the answer.
func (h *harness) send(ctx context.Context, path string, headers http.Header) (response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.guardURL()+path, nil)
	if err != nil {
		return response{}, err
	}
	for k, v := range headers {
		req.Header[k] = v
	}
	start := time.Now()
	resp, err := h.client.Do(req)
	if err != nil {
		return response{DurationMs: millis(time.Since(start))}, err
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	out := response{Status: resp.StatusCode, Headers: resp.Header, Body: string(body), DurationMs: millis(time.Since(start))}
	if err != nil {
		return out, err
	}
	if resp.StatusCode == http.StatusOK {
		var rec echoRecord
		if json.Unmarshal(body, &rec) == nil {
			out.Upstream = &rec
		}
	} else {
		var r hook.Refusal
		if json.Unmarshal(body, &r) == nil && r.ReasonCode != "" {
			out.Refusal = &r
		}
	}
	return out, nil
}

// callerHeaders are what the proofs send as the caller: the credential of the case, a proof of
// its own, and every header the guard must strip or carry.
func callerHeaders(authorization string) http.Header {
	hdr := http.Header{
		"DPoP":             {"caller-proof"},
		"X-Facis-Evil":     {"set-by-the-caller"},
		"X-Forwarded-For":  {"203.0.113.9"},
		"X-Forwarded-Host": {"evil.example"},
		"Forwarded":        {"for=203.0.113.9"},
		"Traceparent":      {"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
		"X-Request-Id":     {"chosen-by-the-caller"},
	}
	if authorization != "" {
		hdr.Set("Authorization", authorization)
	}
	return hdr
}

// allowedRequest is the entitled request the load proofs send.
func (h *harness) allowedRequest() (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, h.guardURL()+"/api/data", nil)
	if err != nil {
		return nil, err
	}
	req.Header = callerHeaders("DPoP " + hook.FixtureTokenRead)
	return req, nil
}

// writeJSON writes a record into the output folder.
func (h *harness) writeJSON(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(h.o.out, name), append(b, '\n'), 0o644)
}

func (h *harness) writeText(name, s string) error {
	return os.WriteFile(filepath.Join(h.o.out, name), []byte(s), 0o644)
}

// freePort finds a TCP port nothing listens on at bind.
func freePort(bind string) (int, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(bind, "0"))
	if err != nil {
		return 0, err
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// --- the echo upstream ----------------------------------------------------------------------

// echoRecord is what the upstream saw.
type echoRecord struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Host    string              `json:"host"`
	Headers map[string][]string `json:"headers"`
}

// echoHandler answers every request with a record of what reached it, so the headers the guard
// forwarded can be read back.
func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := echoRecord{Method: r.Method, Path: r.URL.RequestURI(), Host: r.Host, Headers: map[string][]string{}}
		for k, v := range r.Header {
			rec.Headers[http.CanonicalHeaderKey(k)] = append([]string(nil), v...)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rec)
	})
}

// serveEcho listens on addr and serves the echo handler until ctx ends; it returns the bound address.
func serveEcho(ctx context.Context, addr string) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	srv := &http.Server{Handler: echoHandler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	return ln.Addr().String(), nil
}

// --- the hook as a child process ------------------------------------------------------------

type adapterOptions struct {
	listen, fixtures, events, log string
}

// adapter is the hook running as a child process of this one.
type adapter struct {
	opts   adapterOptions
	cmd    *exec.Cmd
	listen string
	done   chan struct{}
}

func startAdapter(ctx context.Context, o adapterOptions) (*adapter, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	logFile, err := os.OpenFile(o.log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, "serve", "--listen", o.listen, "--fixtures", o.fixtures, "--events", o.events)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("start the policy hook: %w", err)
	}
	a := &adapter{opts: o, cmd: cmd, listen: o.listen, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		_ = logFile.Close()
		close(a.done)
	}()
	if err := waitPort(ctx, o.listen, 30*time.Second); err != nil {
		a.kill()
		return nil, fmt.Errorf("the policy hook did not start listening: %w", err)
	}
	return a, nil
}

// kill ends the process as a crash would, and waits until it is gone.
func (a *adapter) kill() {
	if a.cmd.Process == nil {
		return
	}
	_ = a.cmd.Process.Signal(syscall.SIGCONT)
	_ = a.cmd.Process.Kill()
	select {
	case <-a.done:
	case <-time.After(10 * time.Second):
	}
}

// freeze stops the process without ending it: its connections stay open and it answers nothing.
func (a *adapter) freeze() error { return a.cmd.Process.Signal(syscall.SIGSTOP) }

// restart runs a new process in place of the ended one, on the same address.
func (a *adapter) restart(ctx context.Context) (*adapter, error) {
	a.kill()
	return startAdapter(ctx, a.opts)
}

func waitPort(ctx context.Context, addr string, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("timeout")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// lineDiff is a line diff of a against b: "-" lines only in a, "+" lines only in b, aligned on
// a longest common subsequence. Empty when the texts are equal.
func lineDiff(nameA, a, nameB, b string) string {
	if a == b {
		return ""
	}
	la := strings.Split(strings.TrimSuffix(a, "\n"), "\n")
	lb := strings.Split(strings.TrimSuffix(b, "\n"), "\n")
	lcs := make([][]int, len(la)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(lb)+1)
	}
	for i := len(la) - 1; i >= 0; i-- {
		for j := len(lb) - 1; j >= 0; j-- {
			if la[i] == lb[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var out strings.Builder
	fmt.Fprintf(&out, "--- %s\n+++ %s\n", nameA, nameB)
	i, j := 0, 0
	for i < len(la) && j < len(lb) {
		switch {
		case la[i] == lb[j]:
			fmt.Fprintf(&out, " %s\n", la[i])
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			fmt.Fprintf(&out, "-%s\n", la[i])
			i++
		default:
			fmt.Fprintf(&out, "+%s\n", lb[j])
			j++
		}
	}
	for ; i < len(la); i++ {
		fmt.Fprintf(&out, "-%s\n", la[i])
	}
	for ; j < len(lb); j++ {
		fmt.Fprintf(&out, "+%s\n", lb[j])
	}
	return out.String()
}
