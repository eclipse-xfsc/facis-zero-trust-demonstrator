package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/testsupport"
)

func serveEnv(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

const (
	testDatabase = "postgres://u:hunter2@127.0.0.1:1/x?sslmode=disable&connect_timeout=1"
	testOpenBao  = "http://127.0.0.1:1"
)

func TestParseServe(t *testing.T) {
	both := serveEnv(map[string]string{"TOKEN_STORE_DATABASE_URL": testDatabase, "TOKEN_STORE_OPENBAO_URL": testOpenBao})
	cases := []struct {
		name    string
		args    []string
		env     func(string) string
		wantErr string
		check   func(t *testing.T, o serveOptions)
	}{
		{name: "defaults", args: nil, env: both, check: func(t *testing.T, o serveOptions) {
			if o.cfg.Addr != ":8080" || o.cfg.OpsAddr != ":9090" || o.cfg.ReadinessTimeout != 2*time.Second || o.cfg.DrainDelay != 5*time.Second || o.cfg.ShutdownTimeout != 10*time.Second || o.level.String() != "INFO" {
				t.Errorf("defaults: %+v level %s", o.cfg, o.level)
			}
		}},
		{name: "a flag beats a malformed environment duration", args: []string{"--readiness-timeout", "1s", "--drain-delay", "0"}, env: serveEnv(map[string]string{
			"TOKEN_STORE_DATABASE_URL": testDatabase, "TOKEN_STORE_OPENBAO_URL": testOpenBao,
			"TOKEN_STORE_READINESS_TIMEOUT": "soon", "TOKEN_STORE_DRAIN_DELAY": "later",
		}), check: func(t *testing.T, o serveOptions) {
			if o.cfg.ReadinessTimeout != time.Second || o.cfg.DrainDelay != 0 {
				t.Errorf("flags over a malformed environment: %+v", o.cfg)
			}
		}},
		{name: "environment fills every flag", args: nil, env: serveEnv(map[string]string{
			"TOKEN_STORE_ADDR": ":1", "TOKEN_STORE_OPS_ADDR": ":2", "TOKEN_STORE_DATABASE_URL": testDatabase,
			"TOKEN_STORE_OPENBAO_URL": "https://bao", "TOKEN_STORE_READINESS_TIMEOUT": "750ms",
			"TOKEN_STORE_SHUTDOWN_TIMEOUT": "3s", "TOKEN_STORE_LOG_LEVEL": "debug",
		}), check: func(t *testing.T, o serveOptions) {
			if o.cfg.Addr != ":1" || o.cfg.OpsAddr != ":2" || o.cfg.OpenBaoURL != "https://bao" || o.cfg.ReadinessTimeout != 750*time.Millisecond || o.cfg.ShutdownTimeout != 3*time.Second || o.level.String() != "DEBUG" {
				t.Errorf("from the environment: %+v level %s", o.cfg, o.level)
			}
		}},
		{name: "flag beats environment", args: []string{"--addr", ":7", "--readiness-timeout", "1s", "--log-level", "warn"}, env: serveEnv(map[string]string{
			"TOKEN_STORE_ADDR": ":1", "TOKEN_STORE_READINESS_TIMEOUT": "9s", "TOKEN_STORE_LOG_LEVEL": "debug",
			"TOKEN_STORE_DATABASE_URL": testDatabase, "TOKEN_STORE_OPENBAO_URL": testOpenBao,
		}), check: func(t *testing.T, o serveOptions) {
			if o.cfg.Addr != ":7" || o.cfg.ReadinessTimeout != time.Second || o.level.String() != "WARN" {
				t.Errorf("flags: %+v level %s", o.cfg, o.level)
			}
		}},
		{name: "routes file needs the OpenBao token", args: []string{"--acquire-config", "/etc/routes.json"}, env: both, wantErr: "--openbao-token-file"},
		{name: "routes file and token from the environment", args: nil, env: serveEnv(map[string]string{
			"TOKEN_STORE_DATABASE_URL": testDatabase, "TOKEN_STORE_OPENBAO_URL": testOpenBao,
			"TOKEN_STORE_ACQUIRE_CONFIG": "/etc/routes.json", "TOKEN_STORE_OPENBAO_TOKEN_FILE": "/run/bao-token",
		}), check: func(t *testing.T, o serveOptions) {
			if o.acquireConfig != "/etc/routes.json" || o.openBaoTokenFile != "/run/bao-token" {
				t.Errorf("routes file %q, token file %q", o.acquireConfig, o.openBaoTokenFile)
			}
		}},
		{name: "no database", args: nil, env: serveEnv(map[string]string{"TOKEN_STORE_OPENBAO_URL": testOpenBao}), wantErr: "no database"},
		{name: "no key-value store", args: nil, env: serveEnv(map[string]string{"TOKEN_STORE_DATABASE_URL": testDatabase}), wantErr: "no key-value store"},
		{name: "key-value store without a scheme", args: []string{"--openbao-url", "bao:8200"}, env: both, wantErr: "http(s)://host"},
		{name: "key-value store with a path", args: []string{"--openbao-url", "http://bao:8200/v1"}, env: both, wantErr: "http(s)://host"},
		{name: "zero readiness budget", args: []string{"--readiness-timeout", "0"}, env: both, wantErr: "longer than 0"},
		{name: "zero shutdown", args: []string{"--shutdown-timeout", "0s"}, env: both, wantErr: "longer than 0"},
		{name: "negative drain delay", args: []string{"--drain-delay", "-1s"}, env: both, wantErr: "drain delay"},
		{name: "help", args: []string{"-h"}, env: both, wantErr: "help requested"},
		{name: "bad level", args: []string{"--log-level", "loud"}, env: both, wantErr: "--log-level"},
		{name: "bad duration in the environment", args: nil, env: serveEnv(map[string]string{
			"TOKEN_STORE_DATABASE_URL": testDatabase, "TOKEN_STORE_OPENBAO_URL": testOpenBao, "TOKEN_STORE_READINESS_TIMEOUT": "soon",
		}), wantErr: "TOKEN_STORE_READINESS_TIMEOUT"},
		{name: "stray argument", args: []string{"extra"}, env: both, wantErr: "unexpected argument"},
		{name: "unknown flag", args: []string{"--port", "1"}, env: both, wantErr: "flag provided but not defined"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var errOut bytes.Buffer
			got, err := parseServe(tc.args, tc.env, &errOut)
			// Every case has the password in its environment; none may print it, the usage text
			// the flag package writes on an error included.
			if strings.Contains(errOut.String(), "hunter2") {
				t.Errorf("the connection URL reached the usage text:\n%s", errOut.String())
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, got)
		})
	}
}

func TestServeRefusesAnAddressInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	var out, errOut testsupport.Buffer
	code := run([]string{"serve", "--addr", ln.Addr().String(), "--ops-addr", "127.0.0.1:0",
		"--database-url", testDatabase, "--openbao-url", testOpenBao}, &out, &errOut)
	if code != exitFailed {
		t.Fatalf("exit %d, want %d\n%s%s", code, exitFailed, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "starting the token store") {
		t.Errorf("the failure was not recorded:\n%s", out.String())
	}
	if strings.Contains(out.String()+errOut.String(), "hunter2") {
		t.Errorf("the password reached the output")
	}
}

// serve end to end: it listens on both addresses, says it is alive and not ready while nothing
// is there, carries the caller's id, and exits 0 on SIGTERM. The password is nowhere.
func TestServeStopsOnSIGTERM(t *testing.T) {
	var out, errOut testsupport.Buffer
	exit := make(chan int, 1)
	go func() {
		exit <- run([]string{"serve", "--addr", "127.0.0.1:0", "--ops-addr", "127.0.0.1:0",
			"--database-url", testDatabase, "--openbao-url", testOpenBao, "--drain-delay", "200ms", "--shutdown-timeout", "2s"}, &out, &errOut)
	}()

	var opsAddr string
	deadline := time.Now().Add(10 * time.Second)
	for opsAddr == "" && time.Now().Before(deadline) {
		for _, line := range strings.Split(out.String(), "\n") {
			var rec struct {
				Msg     string `json:"msg"`
				OpsAddr string `json:"ops_addr"`
			}
			if json.Unmarshal([]byte(line), &rec) == nil && rec.Msg == "token store listening" {
				opsAddr = rec.OpsAddr
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if opsAddr == "" {
		t.Fatalf("the store never reported listening:\n%s%s", out.String(), errOut.String())
	}

	resp, err := http.Get("http://" + opsAddr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz %d", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://"+opsAddr+"/readyz", nil)
	req.Header.Set("X-Request-Id", "cli-probe")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), `"unreachable"`) {
		t.Errorf("readyz %d %s", resp.StatusCode, body)
	}

	// The signal is for the running serve, whose handler is installed; had serve already returned,
	// the process would have no handler and the signal would end the test binary instead.
	select {
	case code := <-exit:
		t.Fatalf("serve exited with %d before the signal:\n%s%s", code, out.String(), errOut.String())
	default:
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-exit:
		if code != exitOK {
			t.Errorf("exit %d after SIGTERM, want %d\n%s", code, exitOK, out.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not exit after SIGTERM")
	}
	logs := out.String()
	if strings.Contains(logs+errOut.String(), "hunter2") {
		t.Errorf("the password reached the output:\n%s", logs)
	}
	for _, want := range []string{`"correlation_id":"cli-probe"`, `"service":"token-store"`, `"instance":`, `"msg":"draining"`, `"msg":"token store stopped"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("records lack %s:\n%s", want, logs)
		}
	}
}
