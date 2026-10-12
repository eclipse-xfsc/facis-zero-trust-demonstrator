package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/policy-hook-probe/internal/contractpath"
)

func TestUsageAndModes(t *testing.T) {
	var stderr bytes.Buffer
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{nil, 1, "usage:"},
		{[]string{"help"}, 0, "usage:"},
		{[]string{"bogus"}, 1, "unknown mode"},
		{[]string{"prove"}, 1, "usage:"},
		{[]string{"prove", "fail-closed", "--out", t.TempDir()}, 1, "needs"},
		{[]string{"prove", "nope", "--out", t.TempDir(), "--envoy-image", "x", "--fixtures", contractpath.Fixtures(t), "--templates", "t"}, 1, "unknown proof"},
		{[]string{"serve"}, 1, "needs --listen"},
	} {
		stderr.Reset()
		if code := run(tc.args, &stderr); code != tc.code || !strings.Contains(stderr.String(), tc.want) {
			t.Errorf("%v: code %d, %q", tc.args, code, stderr.String())
		}
	}
}

// TestEnvoyAPIIsImportedOnlyByEnvoyhook keeps the Envoy types inside the one package that
// translates the guard's outcome into them.
func TestEnvoyAPIIsImportedOnlyByEnvoyhook(t *testing.T) {
	const allowed = "github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/policy-hook-probe/internal/envoyhook"
	list := exec.Command("go", "list", "-json=ImportPath,Imports", "./...")
	list.Dir = contractpath.Root(t)
	out, err := list.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	var checked, found int
	for decoder := json.NewDecoder(bytes.NewReader(out)); ; {
		var p struct {
			ImportPath string
			Imports    []string
		}
		if err = decoder.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		checked++
		if p.ImportPath == allowed {
			found++
			continue
		}
		for _, imported := range p.Imports {
			if strings.HasPrefix(imported, "github.com/envoyproxy/go-control-plane/") || strings.HasPrefix(imported, "github.com/cncf/xds/") {
				t.Errorf("%s imports %s; only %s may", p.ImportPath, imported, allowed)
			}
		}
	}
	if checked == 0 || found != 1 {
		t.Fatalf("%d packages checked, envoyhook found %d times", checked, found)
	}
}

var testData = bootstrapData{BindAddress: "127.0.0.1", ListenPort: 10001, AdminPort: 10002,
	UpstreamHost: "127.0.0.1", UpstreamPort: 10003, HookHost: "127.0.0.1", HookPort: 10004, Timeout: "0.25s"}

func render(t *testing.T, name string) string {
	t.Helper()
	cfg, err := renderBootstrap(filepath.Join(contractpath.Templates(t), name+".yaml.tmpl"), testData)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestBootstrapsDifferOnlyInTheFilterBlock(t *testing.T) {
	authz, proc, base := render(t, filterExtAuthz), render(t, filterExtProc), render(t, filterBaseline)
	for _, want := range []string{"port_value: 10001", "port_value: 10004", "timeout: 0.25s", "POL-PDP-UNAVAILABLE", "failure_mode_allow: false"} {
		if !strings.Contains(authz, want) {
			t.Errorf("rendered bootstrap lacks %q", want)
		}
	}
	for _, pair := range [][2]string{{authz, proc}, {authz, base}, {proc, base}} {
		if same, err := identicalOutsideFilterBlock(pair[0], pair[1]); err != nil || !same {
			t.Errorf("bootstraps differ outside the filter block (%v)", err)
		}
	}
	_, block, _, err := splitFilterBlock(authz)
	if err != nil || !strings.Contains(block, "ext_authz") || strings.Contains(block, "ext_proc") {
		t.Errorf("ext-authz block: %q (%v)", block, err)
	}
	if _, _, _, err := splitFilterBlock(markerEnd + "\n" + markerBegin); err == nil {
		t.Error("markers out of order were accepted")
	}
	if envoyDuration(250*time.Millisecond) != "0.25s" || envoyDuration(2*time.Second) != "2s" {
		t.Error("duration format")
	}
}

func TestPercentilesAndLoad(t *testing.T) {
	var d []time.Duration
	for i := 100; i >= 1; i-- {
		d = append(d, time.Duration(i)*time.Millisecond)
	}
	p50, p95, p99, maxD := percentiles(d)
	if p50 != 50*time.Millisecond || p95 != 95*time.Millisecond || p99 != 99*time.Millisecond || maxD != 100*time.Millisecond {
		t.Errorf("p50 %v p95 %v p99 %v max %v", p50, p95, p99, maxD)
	}
	if p50, _, _, _ := percentiles(nil); p50 != 0 {
		t.Errorf("empty: %v", p50)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/deny" {
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()
	var calls atomic.Int32
	res := runLoad(t.Context(), srv.Client(), func() (*http.Request, error) {
		path := "/"
		if calls.Add(1)%5 == 0 {
			path = "/deny"
		}
		return http.NewRequest(http.MethodGet, srv.URL+path, nil)
	}, 20, 4)
	if res.Errors != 0 || res.Statuses[http.StatusOK] != 16 || res.Statuses[http.StatusForbidden] != 4 || res.MaxMs < res.P99Ms {
		t.Errorf("result %+v", res)
	}
}

func TestEchoAndDiff(t *testing.T) {
	srv := httptest.NewServer(echoHandler())
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/x?y=1", nil)
	req.Header.Set("X-Facis-Evil", "1")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var rec echoRecord
	_ = json.NewDecoder(resp.Body).Decode(&rec)
	_ = resp.Body.Close()
	if rec.Path != "/x?y=1" || rec.Headers["X-Facis-Evil"][0] != "1" {
		t.Errorf("echo record %+v", rec)
	}
	if d := lineDiff("a", "x\ny\n", "b", "x\ny\n"); d != "" {
		t.Errorf("equal texts differ: %q", d)
	}
	d := lineDiff("a", "x\ny\nz\n", "b", "x\nq\nz\n")
	for _, want := range []string{"--- a", "+++ b", " x", "-y", "+q", " z"} {
		if !strings.Contains(d, want+"\n") {
			t.Errorf("diff lacks %q:\n%s", want, d)
		}
	}
}
