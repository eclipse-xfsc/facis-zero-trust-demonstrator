package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	osexec "os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectortest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03/if03fixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/meshcaller"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/pgtest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/envoyhook"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/policyevaluator"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire/acquiretest"
	"go.yaml.in/yaml/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// testHTTP bounds every call the test makes to the guard and to Prometheus.
var testHTTP = &http.Client{Timeout: 3 * time.Second}

// front is a dependency's network edge in this test. It forwards to the real dependency, adding the
// guard's mesh identity as the trusted sidecar would, until it is cut; cut, it closes every
// connection without an answer, as an unreachable service does. cutPath cuts one path only.
type front struct {
	url     string
	cut     atomic.Bool
	cutPath atomic.Value // string
}

func newFront(t *testing.T, target, identity string) *front {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	f := &front{}
	f.cutPath.Store("")
	proxy := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(u)
		r.Out.Header.Del("X-Forwarded-Client-Cert")
		if identity != "" {
			r.Out.Header.Set("X-Forwarded-Client-Cert", "URI="+identity)
		}
	}, Transport: &http.Transport{}}
	proxy.ErrorLog = slog.NewLogLogger(slog.NewTextHandler(io.Discard, nil), slog.LevelError)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.cut.Load() || r.URL.Path == f.cutPath.Load().(string) {
			if conn, _, err := http.NewResponseController(w).Hijack(); err == nil {
				_ = conn.Close()
			}
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	f.url = server.URL
	return f
}

// guardProcess is a running cmd/guard.
type guardProcess struct {
	cmd    *osexec.Cmd
	ops    string // where the test reaches its ops endpoints
	hook   *grpc.ClientConn
	logs   *syncLog
	exited chan struct{}
}

// syncLog collects a process's output.
type syncLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func newSyncLog() *syncLog { return &syncLog{} }

func (l *syncLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *syncLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func startGuard(t *testing.T, binary string, cfg map[string]any, opsBind string) *guardProcess {
	t.Helper()
	raw, _ := json.Marshal(cfg)
	file := filepath.Join(t.TempDir(), "guard.json")
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(opsBind, ":0") {
		opsBind = strings.TrimSuffix(opsBind, "0") + strings.TrimPrefix(freeLoopback(t), "127.0.0.1:")
	}
	hookAddr := freeLoopback(t)
	logs := newSyncLog()
	cmd := osexec.Command(binary, "-config", file, "-ops-addr", opsBind, "-hook-addr", hookAddr)
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	g := &guardProcess{cmd: cmd, ops: "http://127.0.0.1:" + opsBind[strings.LastIndexByte(opsBind, ':')+1:], logs: logs, exited: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(g.exited) }()
	t.Cleanup(g.stop)
	conn, err := grpc.NewClient(hookAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	g.hook = conn
	waitFor(t, 10*time.Second, "the guard answers on its ops port", func() bool {
		resp, err := testHTTP.Get(g.ops + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
		}
		return err == nil && resp.StatusCode == http.StatusOK
	})
	return g
}

func (g *guardProcess) stop() {
	_ = g.cmd.Process.Kill()
	<-g.exited
}

// ready returns the guard's readiness answer: the status and the dependencies it reports down.
func (g *guardProcess) ready(t *testing.T) (int, []string) {
	t.Helper()
	resp, err := testHTTP.Get(g.ops + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct{ Down []string }
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body.Down
}

func freeLoopback(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().String()
}

// waitFor polls cond until it holds; a success seen after the deadline is a failure too.
func waitFor(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		ok := cond()
		if time.Now().After(deadline) {
			t.Fatalf("not within %s: %s", within, what)
		}
		if ok {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// prometheus is a Prometheus from the pinned image, loaded with the guard chart's rule file.
type prometheus struct{ api string }

type alert struct {
	Labels map[string]string
	State  string
}

func (p *prometheus) alerts(t *testing.T) []alert {
	t.Helper()
	resp, err := testHTTP.Get(p.api + "/api/v1/alerts")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Prometheus alerts: %d", resp.StatusCode)
	}
	var body struct{ Data struct{ Alerts []alert } }
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body.Data.Alerts
}

// state is the state of the alert name for the instance (and, when given, the dependency), or "".
func (p *prometheus) state(t *testing.T, name, instance, dependency string) string {
	t.Helper()
	for _, a := range p.alerts(t) {
		if a.Labels["alertname"] == name && a.Labels["instance"] == instance && (dependency == "" || a.Labels["dependency"] == dependency) {
			return a.State
		}
	}
	return ""
}

// anyFor lists the pending or firing alerts of the instance.
func (p *prometheus) anyFor(t *testing.T, instance string) []string {
	t.Helper()
	var out []string
	for _, a := range p.alerts(t) {
		if a.Labels["instance"] == instance {
			out = append(out, a.Labels["alertname"]+"/"+a.Labels["dependency"]+":"+a.State)
		}
	}
	return out
}

// query returns the value of an instant query with one result, or "" when it has none.
func (p *prometheus) query(t *testing.T, q string) string {
	t.Helper()
	resp, err := testHTTP.Get(p.api + "/api/v1/query?query=" + url.QueryEscape(q))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Data struct {
			Result []struct{ Value []any }
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || len(body.Data.Result) != 1 || len(body.Data.Result[0].Value) != 2 {
		return ""
	}
	return fmt.Sprint(body.Data.Result[0].Value[1])
}

// startPrometheus runs Prometheus scraping targets as job ztd-guard every 5 s (1 s timeout), with the
// rules of deployment/helm/guard/alerts/guard-rules.yaml evaluated every 5 s.
func startPrometheus(t *testing.T, image string, hostNetwork bool, targets []string) *prometheus {
	t.Helper()
	dir := t.TempDir()
	rules, err := os.ReadFile(filepath.Join(repoRoot(t), "deployment/helm/guard/alerts/guard-rules.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	config, _ := yaml.Marshal(map[string]any{
		"global":         map[string]any{"scrape_interval": "5s", "scrape_timeout": "1s", "evaluation_interval": "5s"},
		"rule_files":     []string{"/etc/prometheus/rules/guard-rules.yaml"},
		"scrape_configs": []any{map[string]any{"job_name": "ztd-guard", "static_configs": []any{map[string]any{"targets": targets, "labels": map[string]string{"cluster": "failclosed", "namespace": "ztd-test"}}}}},
	})
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules", "guard-rules.yaml"), rules, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "prometheus.yml"), config, 0o644); err != nil {
		t.Fatal(err)
	}
	mount := []string{"-v", dir + "/prometheus.yml:/etc/prometheus/prometheus.yml:ro", "-v", dir + "/rules:/etc/prometheus/rules:ro"}
	for _, check := range [][]string{{"check", "config", "/etc/prometheus/prometheus.yml"}, {"check", "rules", "/etc/prometheus/rules/guard-rules.yaml"}} {
		args := append(append([]string{"run", "--rm"}, mount...), append([]string{"--entrypoint", "promtool", image}, check...)...)
		if out, err := osexec.Command("docker", args...).CombinedOutput(); err != nil {
			t.Fatalf("promtool %v: %v\n%s", check, err, out)
		}
	}
	port := freeLoopback(t)[len("127.0.0.1:"):]
	name := fmt.Sprintf("ztd-guard-alerts-%d", os.Getpid())
	args := append([]string{"run", "-d", "--rm", "--name", name}, mount...)
	if hostNetwork {
		args = append(args, "--network", "host")
	} else {
		args = append(args, "-p", "127.0.0.1:"+port+":"+port)
	}
	args = append(args, image, "--config.file=/etc/prometheus/prometheus.yml", "--storage.tsdb.path=/prometheus", "--web.listen-address=:"+port)
	if out, err := osexec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = osexec.Command("docker", "rm", "-f", name).Run() })
	p := &prometheus{api: "http://127.0.0.1:" + port}
	waitFor(t, 60*time.Second, "Prometheus is ready with the guard's rules", func() bool {
		resp, err := testHTTP.Get(p.api + "/api/v1/rules")
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		return strings.Contains(string(raw), `"ZtdGuardDependencyDown"`) && strings.Contains(string(raw), `"health":"ok"`)
	})
	return p
}

func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := osexec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// TestGuardFailsClosedPerDependency makes each of the guard's dependencies unreachable in turn,
// with the real connector, policy evaluator, token store, PostgreSQL and OpenBao behind them and the
// real cmd/guard in front: an otherwise valid request is refused for that dependency, the guard
// reports it down, and the chart's alert rule fires in a Prometheus scraping the guard within 30 s
// of the outage; restored, the request is served again and the alert resolves. It also shows what
// stays allowed: a guard that already holds the connector's keys keeps verifying with them while
// the connector is unreachable, and a guard that never had them refuses.
func TestGuardFailsClosedPerDependency(t *testing.T) {
	addr, token := os.Getenv("TRANSIT_TEST_ADDR"), os.Getenv("TRANSIT_TEST_TOKEN")
	image := os.Getenv("PROMETHEUS_IMAGE")
	if addr == "" || token == "" || os.Getenv(pgtest.DatabaseEnv) == "" || image == "" {
		t.Skip("PostgreSQL, OpenBao and PROMETHEUS_IMAGE are needed")
	}
	const issuer = "https://connector.guard.test"
	const aud = "https://resource.facis.invalid"
	const inbound = "https://guard.facis.invalid"
	const published = "https://resource.guard.test"
	const participantID = "spiffe://zone-b.test/ns/example/sa/ztd-participant"
	const guardPrincipal = "spiffe://zone-b.test/ns/example/sa/ztd-guard"
	const vpIssuer = "https://fixture.guard.test"
	const vpKid = "fixture-1"
	fixtureKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := connectortest.Start(t, pgtest.MigratedURL(t, "guard_failclosed"), addr, token, connectortest.Options{
		Issuer: issuer, VPIssuer: vpIssuer, VPKid: vpKid, VPKey: &fixtureKey.PublicKey, Audiences: []string{inbound, aud},
		ScopeMap:            []connectortest.Scope{{Role: "reader", Scopes: []string{"report:read"}}, {Role: "viewer", Scopes: []string{"report:summary"}}},
		AccessTokenLifespan: 15 * time.Minute,
	})
	bao, err := transit.New(transit.Config{Addr: addr, Token: func(context.Context) (string, error) { return token, nil }})
	if err != nil {
		t.Fatal(err)
	}
	loaded := acquire.Loaded{SigningKey: "guard-failclosed-" + acquiretest.RandHex(6), KVPrefix: "ztd/failclosed-test/" + acquiretest.RandHex(8),
		Trusted: if03.Issuers{vpIssuer: {vpKid: &fixtureKey.PublicKey}}, Routes: map[string]acquire.Route{}}
	scopes := map[string]string{"report:read": "read", "report:summary": "summary"}
	for scope, tenant := range scopes {
		clientID, secret := c.Register(t, "store "+tenant, scope, aud)
		file := filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(file, []byte(secret), 0o600); err != nil {
			t.Fatal(err)
		}
		role := map[string]string{"read": "reader", "summary": "viewer"}[tenant]
		loaded.Routes[tenant] = acquire.Route{Name: tenant, PeerZone: "zone-b", Audience: aud, Tenant: tenant, ConnectorURL: c.Base, ClientID: clientID, ClientSecretFile: file,
			Outcomes: if03fixture.Fixture{Issuer: vpIssuer, Kid: vpKid, Key: fixtureKey, Claims: if03.Claims{Role: role}}}
		loaded.Substitution = append(loaded.Substitution, meshcaller.Route{Callers: []string{guardPrincipal}, PeerZone: "zone-b", Audience: aud, Tenant: tenant, Methods: []string{"POST"}, TargetPrefix: published + "/demo"})
	}
	dsn := testDatabaseURL(t)
	migrate(t, dsn)
	cfg := localConfig(dsn, addr)
	cfg.Acquisition = &loaded
	cfg.OpenBao = bao
	cfg.ReplayCallers = []string{guardPrincipal}
	store, err := New(t.Context(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	startServer(t, store)
	policy, err := policyevaluator.New(policyevaluator.Config{Revision: "failclosed-1", Audience: inbound, Host: "resource.guard.test", GuardCallers: []string{guardPrincipal}, ParticipantCallers: []string{participantID}, ScopeTenants: scopes})
	if err != nil {
		t.Fatal(err)
	}
	policyServer := httptest.NewServer(policy)
	t.Cleanup(policyServer.Close)

	policyFront := newFront(t, policyServer.URL, guardPrincipal)
	storeFront := newFront(t, "http://"+store.Addr().String(), guardPrincipal)
	keysFront := newFront(t, c.Base, "")

	binary := filepath.Join(t.TempDir(), "guard")
	if out, err := osexec.Command("go", "build", "-o", binary, "github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/guard").CombinedOutput(); err != nil {
		t.Fatalf("building cmd/guard: %v\n%s", err, out)
	}
	guardConfig := map[string]any{"issuer": issuer, "jwks_url": keysFront.url + "/.well-known/jwks.json", "inbound_audience": inbound,
		"upstream_audience": aud, "published_base_url": published, "peer_zone": "zone-b", "policy_url": policyFront.url,
		"store_url": storeFront.url, "allowed_callers": []string{participantID}, "scope_tenants": scopes}

	// Where Prometheus, in a container, reaches the guard: the host's network on Linux, the host's
	// name elsewhere.
	hostNetwork := runtime.GOOS == "linux"
	bind, fromContainer := "0.0.0.0", "host.docker.internal"
	if hostNetwork {
		bind, fromContainer = "127.0.0.1", "127.0.0.1"
	}
	opsPort := freeLoopback(t)[len("127.0.0.1:"):]
	g := startGuard(t, binary, guardConfig, bind+":"+opsPort)
	guardInstance := fromContainer + ":" + opsPort

	// A second target that reports two of the three dependencies: the rule for missing series must
	// fire for it and for nothing else.
	partial, err := net.Listen("tcp", bind+":0")
	if err != nil {
		t.Fatal(err)
	}
	var partialEmpty atomic.Bool
	partialServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if partialEmpty.Load() {
			_, _ = io.WriteString(w, "# no dependency series\n")
			return
		}
		_, _ = io.WriteString(w, "ztd_guard_dependency_up{dependency=\"policy_engine\"} 1\nztd_guard_dependency_up{dependency=\"key_set\"} 1\n")
	})}
	go func() { _ = partialServer.Serve(partial) }()
	t.Cleanup(func() { _ = partialServer.Close() })
	partialInstance := fmt.Sprintf("%s:%d", fromContainer, partial.Addr().(*net.TCPAddr).Port)

	prom := startPrometheus(t, image, hostNetwork, []string{guardInstance, partialInstance})

	// A Participant with a token for the guard; every request carries a fresh proof.
	participantClient, participantSecret := c.Register(t, "participant reader", "report:read", inbound)
	cc := &connectorclient.Client{BaseURL: c.Base, ClientID: participantClient, ClientSecret: participantSecret}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer := guardTestKey{key}
	challenge, err := cc.Challenge(t.Context(), inbound)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := if03fixture.Fixture{Issuer: vpIssuer, Kid: vpKid, Key: fixtureKey, Claims: if03.Claims{Role: "reader"}}.Outcome(t.Context(), challenge)
	if err != nil {
		t.Fatal(err)
	}
	granted, err := cc.Grant(t.Context(), signer, outcome, challenge.Value, inbound)
	if err != nil {
		t.Fatal(err)
	}
	ask := func(t *testing.T, gp *guardProcess) envoyhook.Answer {
		t.Helper()
		proof, err := dpopproof.Build(t.Context(), signer, dpopproof.Claims{HTM: "POST", HTU: published + "/demo", ATH: connectorclient.ATH(granted.AccessToken)})
		if err != nil {
			t.Fatal(err)
		}
		header := http.Header{}
		header.Set("Authorization", "DPoP "+granted.AccessToken)
		header.Set("DPoP", proof)
		header.Set("X-Forwarded-Client-Cert", "URI="+participantID)
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		answer, err := envoyhook.Check(ctx, gp.hook, hook.Request{Method: "POST", Path: "/demo", Host: "resource.guard.test", Headers: header})
		if err != nil {
			t.Fatalf("the hook did not answer: %v", err)
		}
		return answer
	}
	reason := func(a envoyhook.Answer) string {
		var body struct {
			ReasonCode string `json:"reason_code"`
		}
		_ = json.Unmarshal([]byte(a.Body), &body)
		return body.ReasonCode
	}
	wantServed := func(t *testing.T, gp *guardProcess) {
		t.Helper()
		a := ask(t, gp)
		if !a.Allowed || !strings.HasPrefix(a.Headers.Get("Authorization"), "DPoP ") || a.Headers.Get("Authorization") == "DPoP "+granted.AccessToken {
			t.Fatalf("a valid request was not served with a substituted token: allowed=%v %d %q\n%s", a.Allowed, a.Status, reason(a), gp.logs.String())
		}
	}
	wantRefused := func(t *testing.T, gp *guardProcess, code string) {
		t.Helper()
		a := ask(t, gp)
		if a.Allowed || a.Status != http.StatusServiceUnavailable || reason(a) != code || a.Headers.Get("Authorization") != "" || a.Headers.Get("DPoP") != "" {
			t.Fatalf("want a 503 %s refusal without a substituted token, got allowed=%v %d %q", code, a.Allowed, a.Status, reason(a))
		}
	}
	// healthy waits until the guard is ready, Prometheus reads three dependencies up, and no alert of
	// the guard is pending or firing; then a request is served.
	healthy := func(t *testing.T) {
		t.Helper()
		waitFor(t, 45*time.Second, "the guard is ready and quiet", func() bool {
			status, _ := g.ready(t)
			return status == http.StatusOK &&
				prom.query(t, fmt.Sprintf(`sum(ztd_guard_dependency_up{instance=%q})`, guardInstance)) == "3" &&
				prom.query(t, fmt.Sprintf(`up{instance=%q}`, guardInstance)) == "1" &&
				len(prom.anyFor(t, guardInstance)) == 0
		})
		wantServed(t, g)
	}
	// alerted waits, from the outage at since, for the dependency's alert to fire for the guard.
	alerted := func(t *testing.T, since time.Time, dependency string) {
		t.Helper()
		for {
			firing := prom.state(t, "ZtdGuardDependencyDown", guardInstance, dependency) == "firing"
			if time.Since(since) > 30*time.Second {
				t.Fatalf("no firing alert for %s within 30 s of the outage; alerts: %v", dependency, prom.anyFor(t, guardInstance))
			}
			if firing {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		t.Logf("%s: alert firing %.1f s after the outage", dependency, time.Since(since).Seconds())
		if status, down := g.ready(t); status != http.StatusServiceUnavailable || !strings.Contains(strings.Join(down, ","), dependency) {
			t.Fatalf("readiness during the outage: %d %v", status, down)
		}
	}

	healthy(t)
	waitFor(t, 45*time.Second, "the missing-series alert fires for the partial target", func() bool {
		return prom.state(t, "ZtdGuardDependencySeriesMissing", partialInstance, "") == "firing"
	})
	if alerts := prom.anyFor(t, guardInstance); len(alerts) != 0 {
		t.Fatalf("the complete guard has alerts: %v", alerts)
	}
	// From two series to none and back, the alert stays one alert and keeps firing.
	partialEmpty.Store(true)
	for until := time.Now().Add(15 * time.Second); time.Now().Before(until); time.Sleep(500 * time.Millisecond) {
		if state := prom.state(t, "ZtdGuardDependencySeriesMissing", partialInstance, ""); state != "firing" {
			t.Fatalf("the missing-series alert went %q when the target reported no series", state)
		}
	}
	partialEmpty.Store(false)

	t.Run("policy engine unreachable", func(t *testing.T) {
		outage := time.Now()
		policyFront.cut.Store(true)
		defer policyFront.cut.Store(false)
		wantRefused(t, g, hook.ReasonPDPUnavailable)
		alerted(t, outage, "policy_engine")
		policyFront.cut.Store(false)
		healthy(t)
	})

	t.Run("token store unreachable", func(t *testing.T) {
		outage := time.Now()
		storeFront.cut.Store(true)
		defer storeFront.cut.Store(false)
		// The replay check is its first call, before the policy is asked.
		wantRefused(t, g, "replay_unavailable")
		alerted(t, outage, "token_store")
		storeFront.cut.Store(false)
		healthy(t)
	})

	t.Run("token store unreachable for substitution only", func(t *testing.T) {
		storeFront.cutPath.Store("/internal/substitute")
		defer storeFront.cutPath.Store("")
		wantRefused(t, g, hook.ReasonTokenStoreUnavailable)
		storeFront.cutPath.Store("")
		healthy(t)
	})

	t.Run("connector key set unreachable", func(t *testing.T) {
		outage := time.Now()
		keysFront.cut.Store(true)
		defer keysFront.cut.Store(false)
		// The guard holds the keys it fetched: it keeps verifying with them (docs/fail-closed.md).
		wantServed(t, g)
		alerted(t, outage, "key_set")

		// A guard that never had the keys refuses, and reports only the key set down.
		cold := startGuard(t, binary, guardConfig, "127.0.0.1:0")
		waitFor(t, 15*time.Second, "the cold guard reports the key set, and only it, down", func() bool {
			status, down := cold.ready(t)
			return status == http.StatusServiceUnavailable && strings.Join(down, ",") == "key_set"
		})
		wantRefused(t, cold, "key_set_unavailable")

		restored := time.Now()
		keysFront.cut.Store(false)
		waitFor(t, 15*time.Second, "the cold guard becomes ready", func() bool {
			status, _ := cold.ready(t)
			return status == http.StatusOK
		})
		// Its verifier fetches the key set again only on a request, and at most every 30 s after
		// the last attempt (tokenverify MinRefresh): until then every request is still refused
		// for the key set.
		waitFor(t, 45*time.Second, "the cold guard serves once it has the keys", func() bool {
			a := ask(t, cold)
			if !a.Allowed && reason(a) != "key_set_unavailable" {
				t.Fatalf("while recovering the cold guard refused with %q", reason(a))
			}
			return a.Allowed
		})
		t.Logf("the cold guard served %.1f s after the key set returned", time.Since(restored).Seconds())
		wantServed(t, cold)
		cold.stop()
		healthy(t)
	})

	t.Run("guard metrics unreachable", func(t *testing.T) {
		outage := time.Now()
		g.stop()
		for {
			firing := prom.state(t, "ZtdGuardScrapeFailing", guardInstance, "") == "firing"
			if time.Since(outage) > 30*time.Second {
				t.Fatalf("no firing scrape alert within 30 s of the guard stopping; alerts: %v", prom.anyFor(t, guardInstance))
			}
			if firing {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		t.Logf("scrape: alert firing %.1f s after the guard stopped", time.Since(outage).Seconds())
	})
}
