package server

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/testsupport"
)

// A URL whose password must never appear in a record, and a port nothing listens on.
const unreachableDatabase = "postgres://u:hunter2@127.0.0.1:1/x?sslmode=disable&connect_timeout=1"

func localConfig(databaseURL, openBaoURL string) Config {
	return Config{
		Addr:             "127.0.0.1:0",
		OpsAddr:          "127.0.0.1:0",
		DatabaseURL:      databaseURL,
		OpenBaoURL:       openBaoURL,
		ReadinessTimeout: 2 * time.Second,
		ShutdownTimeout:  3 * time.Second,
	}
}

// startServer runs s until the test ends or stop is called, and returns stop, which waits for
// Serve to return and hands back its error.
func startServer(t *testing.T, s *Server) func() error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	var result error
	var once bool
	stop := func() error {
		if !once {
			once = true
			cancel()
			select {
			case result = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("Serve did not return after the context ended")
			}
		}
		return result
	}
	t.Cleanup(func() { _ = stop() })
	return stop
}

func get(t *testing.T, url string, headers map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func TestConfigValidate(t *testing.T) {
	good := localConfig("postgres://u:p@db/x", "http://bao:8200")
	if err := good.Validate(); err != nil {
		t.Fatalf("a good config is refused: %v", err)
	}
	cases := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"no API address", func(c *Config) { c.Addr = "" }, "API listener"},
		{"no ops address", func(c *Config) { c.OpsAddr = "" }, "ops listener"},
		{"no database", func(c *Config) { c.DatabaseURL = "" }, "no database"},
		{"no key-value store", func(c *Config) { c.OpenBaoURL = "" }, "no key-value store"},
		{"key-value store without a scheme", func(c *Config) { c.OpenBaoURL = "bao:8200" }, "http(s)://host"},
		{"key-value store with a path", func(c *Config) { c.OpenBaoURL = "http://bao:8200/v1" }, "http(s)://host"},
		{"key-value store with a query", func(c *Config) { c.OpenBaoURL = "http://bao:8200/?x=1" }, "http(s)://host"},
		{"key-value store with a bare question mark", func(c *Config) { c.OpenBaoURL = "http://bao:8200?" }, "http(s)://host"},
		{"key-value store with a bare fragment", func(c *Config) { c.OpenBaoURL = "http://bao:8200#" }, "http(s)://host"},
		{"key-value store with a user", func(c *Config) { c.OpenBaoURL = "http://root@bao:8200" }, "http(s)://host"},
		{"key-value store over ftp", func(c *Config) { c.OpenBaoURL = "ftp://bao" }, "http(s)://host"},
		{"zero readiness budget", func(c *Config) { c.ReadinessTimeout = 0 }, "readiness timeout"},
		{"negative drain delay", func(c *Config) { c.DrainDelay = -time.Second }, "drain delay"},
		{"negative shutdown", func(c *Config) { c.ShutdownTimeout = -1 }, "shutdown timeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := good
			tc.mut(&c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want one containing %q", err, tc.want)
			}
		})
	}
	trailing := good
	trailing.OpenBaoURL = "https://bao:8200/"
	if err := trailing.Validate(); err != nil {
		t.Errorf("a trailing slash is refused: %v", err)
	}
}

// The store starts with neither dependency there: it listens, says it is alive, says it is not
// ready, names no credential, and drains cleanly.
func TestServerStartsWithoutItsDependencies(t *testing.T) {
	var buf testsupport.Buffer
	s, err := New(context.Background(), localConfig(unreachableDatabase, "http://127.0.0.1:1"), testLogger(&buf))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	stop := startServer(t, s)

	ops := "http://" + s.OpsAddr().String()
	api := "http://" + s.Addr().String()
	for _, base := range []string{ops, api} {
		if resp, _ := get(t, base+"/healthz", nil); resp.StatusCode != http.StatusOK {
			t.Errorf("%s/healthz: %d", base, resp.StatusCode)
		}
		resp, body := get(t, base+"/readyz", map[string]string{"X-Request-Id": "probe-1"})
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("%s/readyz: %d, want 503", base, resp.StatusCode)
		}
		var rep report
		if err := json.Unmarshal([]byte(body), &rep); err != nil {
			t.Fatalf("readyz body: %v", err)
		}
		if rep.Ready || rep.Checks.Postgres != checkUnreachable || rep.Checks.OpenBao != checkUnreachable {
			t.Errorf("%s/readyz: %+v", base, rep)
		}
		if resp.Header.Get("X-Request-Id") != "probe-1" {
			t.Errorf("x-request-id not echoed: %q", resp.Header.Get("X-Request-Id"))
		}
	}
	if resp, _ := get(t, ops+"/nothing", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown path: %d", resp.StatusCode)
	}
	if err := stop(); err != nil {
		t.Errorf("Serve returned %v after a clean stop", err)
	}

	logs := buf.String()
	if strings.Contains(logs, "hunter2") {
		t.Errorf("the password reached the records:\n%s", logs)
	}
	if !strings.Contains(logs, `"correlation_id":"probe-1"`) {
		t.Errorf("no record carries the probe's correlation id:\n%s", logs)
	}
	for _, r := range requestRecords(t, &buf) {
		if r["correlation_id"] == nil {
			t.Errorf("a completion record has no correlation_id: %v", r)
		}
	}
}

// Asked to stop, the store answers 503 with draining set while both listeners stay open for the
// drain delay, and only then closes them.
func TestServerDrainsBeforeClosing(t *testing.T) {
	var buf testsupport.Buffer
	cfg := localConfig(unreachableDatabase, "http://127.0.0.1:1")
	// A short budget, so even a host that drops rather than refuses the dial answers a probe
	// quickly, and the loop below gets several attempts inside the drain delay.
	cfg.ReadinessTimeout = 200 * time.Millisecond
	cfg.DrainDelay = 800 * time.Millisecond
	s, err := New(context.Background(), cfg, testLogger(&buf))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	ops := "http://" + s.OpsAddr().String()
	api := "http://" + s.Addr().String()
	if resp, _ := get(t, ops+"/healthz", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz before the stop: %d", resp.StatusCode)
	}

	stopped := time.Now()
	cancel()
	var rep report
	for !rep.Draining && time.Since(stopped) < cfg.DrainDelay/2 {
		resp, body := get(t, ops+"/readyz", nil)
		if err := json.Unmarshal([]byte(body), &rep); err != nil {
			t.Fatalf("readyz body during the drain: %v", err)
		}
		if rep.Draining && resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("readyz during the drain: %d", resp.StatusCode)
		}
	}
	if !rep.Draining || rep.Ready {
		t.Errorf("readyz during the drain did not say draining: %+v", rep)
	}
	if resp, _ := get(t, api+"/healthz", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("the API listener closed before the drain delay: %d", resp.StatusCode)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned %v", err)
		}
		if elapsed := time.Since(stopped); elapsed < cfg.DrainDelay {
			t.Errorf("Serve returned after %v, before the %v drain delay", elapsed, cfg.DrainDelay)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return")
	}
	if !strings.Contains(buf.String(), `"msg":"draining"`) {
		t.Errorf("the drain was not recorded:\n%s", buf.String())
	}
}

func TestNewRefusesAnAddressInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	cfg := localConfig(unreachableDatabase, "http://127.0.0.1:1")
	cfg.OpsAddr = ln.Addr().String()
	var buf testsupport.Buffer
	if _, err := New(context.Background(), cfg, testLogger(&buf)); err == nil {
		t.Fatal("an address in use was accepted")
	}
}
