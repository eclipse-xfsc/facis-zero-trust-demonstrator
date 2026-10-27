package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

func serveEnv(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

const testDatabase = "postgres://u:hunter2@127.0.0.1:1/x?sslmode=disable&connect_timeout=1"

// required is a complete environment; each case removes or overrides what it tests.
func required(over map[string]string) func(string) string {
	env := map[string]string{
		"CONNECTOR_DATABASE_URL":             testDatabase,
		"CONNECTOR_OPENBAO_URL":              "http://127.0.0.1:1",
		"CONNECTOR_OPENBAO_TOKEN_FILE":       "/run/bao-token",
		"CONNECTOR_ISSUER":                   "https://connector.example",
		"CONNECTOR_SIGNING_KEY":              "connector-at",
		"CONNECTOR_SIGNING_KEY_VERSION":      "1",
		"CONNECTOR_REGISTRATION_ENDPOINT":    "https://connector.example/oauth2/register",
		"CONNECTOR_TOKEN_SECRET_FILE":        "/run/token-secret",
		"CONNECTOR_REGISTRATION_SECRET_FILE": "/run/registration-secret",
		"CONNECTOR_REGISTRAR_ID":             "registrar",
		"CONNECTOR_REGISTRAR_SECRET_FILE":    "/run/registrar-secret",
		"CONNECTOR_REGISTRAR_SCOPES":         "connector:client_registration, resource.read",
		"CONNECTOR_REGISTRAR_AUDIENCES":      "https://connector.example/oauth2/register,https://resource.example",
	}
	for k, v := range over {
		if v == "" {
			delete(env, k)
		} else {
			env[k] = v
		}
	}
	return serveEnv(env)
}

func TestParseServe(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		env     func(string) string
		wantErr string
		check   func(t *testing.T, c config)
	}{
		{name: "defaults", env: required(nil), check: func(t *testing.T, c config) {
			if c.addr != ":8080" || c.opsAddr != ":9090" || c.accessTokenLifespan != 300*time.Second || !c.dpopEnforce || !c.dpopNonce ||
				c.readinessTimeout != 2*time.Second || c.drainDelay != 5*time.Second || c.shutdownTimeout != 10*time.Second || c.signingKeyVersion != 1 {
				t.Errorf("defaults: %+v", c)
			}
		}},
		{name: "environment fills every flag", env: required(map[string]string{
			"CONNECTOR_ADDR": ":1", "CONNECTOR_OPS_ADDR": ":2", "CONNECTOR_SIGNING_KEY_VERSION": "7",
			"CONNECTOR_ACCESS_TOKEN_LIFESPAN": "1m", "CONNECTOR_DPOP_ENFORCE": "false", "CONNECTOR_DPOP_NONCE": "0",
			"CONNECTOR_READINESS_TIMEOUT": "750ms", "CONNECTOR_DRAIN_DELAY": "0s", "CONNECTOR_SHUTDOWN_TIMEOUT": "3s", "CONNECTOR_LOG_LEVEL": "debug",
		}), check: func(t *testing.T, c config) {
			if c.addr != ":1" || c.opsAddr != ":2" || c.signingKeyVersion != 7 || c.accessTokenLifespan != time.Minute || c.dpopEnforce || c.dpopNonce ||
				c.readinessTimeout != 750*time.Millisecond || c.drainDelay != 0 || c.shutdownTimeout != 3*time.Second ||
				c.openBaoTokenFile != "/run/bao-token" || c.tokenSecretFile != "/run/token-secret" || c.registrarID != "registrar" ||
				strings.Join(c.registrarScopes, " ") != "connector:client_registration resource.read" || len(c.registrarAudiences) != 2 {
				t.Errorf("from the environment: %+v", c)
			}
		}},
		{name: "flag beats environment", args: []string{"--addr", ":7", "--signing-key-version", "3", "--dpop-nonce=false", "--readiness-timeout", "1s"},
			env: required(map[string]string{"CONNECTOR_ADDR": ":1", "CONNECTOR_DPOP_NONCE": "true", "CONNECTOR_READINESS_TIMEOUT": "soon"}),
			check: func(t *testing.T, c config) {
				if c.addr != ":7" || c.signingKeyVersion != 3 || c.dpopNonce || c.readinessTimeout != time.Second {
					t.Errorf("flags: %+v", c)
				}
			}},
		{name: "no database", env: required(map[string]string{"CONNECTOR_DATABASE_URL": ""}), wantErr: "--database-url"},
		{name: "no OpenBao", env: required(map[string]string{"CONNECTOR_OPENBAO_URL": ""}), wantErr: "--openbao-url"},
		{name: "no OpenBao token file", env: required(map[string]string{"CONNECTOR_OPENBAO_TOKEN_FILE": ""}), wantErr: "--openbao-token-file"},
		{name: "no issuer", env: required(map[string]string{"CONNECTOR_ISSUER": ""}), wantErr: "--issuer"},
		{name: "no signing key", env: required(map[string]string{"CONNECTOR_SIGNING_KEY": ""}), wantErr: "--signing-key"},
		{name: "no key version", env: required(map[string]string{"CONNECTOR_SIGNING_KEY_VERSION": ""}), wantErr: "--signing-key-version"},
		{name: "no registration endpoint", env: required(map[string]string{"CONNECTOR_REGISTRATION_ENDPOINT": ""}), wantErr: "--registration-endpoint"},
		{name: "no token secret file", env: required(map[string]string{"CONNECTOR_TOKEN_SECRET_FILE": ""}), wantErr: "--token-secret-file"},
		{name: "no registration secret file", env: required(map[string]string{"CONNECTOR_REGISTRATION_SECRET_FILE": ""}), wantErr: "--registration-secret-file"},
		{name: "no registrar", env: required(map[string]string{"CONNECTOR_REGISTRAR_ID": ""}), wantErr: "--registrar-id"},
		{name: "no registrar secret file", env: required(map[string]string{"CONNECTOR_REGISTRAR_SECRET_FILE": ""}), wantErr: "--registrar-secret-file"},
		{name: "registrar without the registration scope", args: []string{"--registrar-scopes", "resource.read"}, env: required(nil), wantErr: "connector:client_registration"},
		{name: "registrar without the registration endpoint", args: []string{"--registrar-audiences", "https://resource.example"}, env: required(nil), wantErr: "registration endpoint"},
		{name: "issuer over http", args: []string{"--issuer", "http://connector.example"}, env: required(nil), wantErr: "https://"},
		{name: "relative registration endpoint", args: []string{"--registration-endpoint", "/oauth2/register"}, env: required(nil), wantErr: "absolute"},
		{name: "OpenBao with a path", args: []string{"--openbao-url", "http://bao:8200/v1"}, env: required(nil), wantErr: "http(s)://host"},
		{name: "zero lifespan", args: []string{"--access-token-lifespan", "0"}, env: required(nil), wantErr: "lifespan"},
		{name: "negative drain delay", args: []string{"--drain-delay", "-1s"}, env: required(nil), wantErr: "drain delay"},
		{name: "bad bool in the environment", env: required(map[string]string{"CONNECTOR_DPOP_ENFORCE": "maybe"}), wantErr: "CONNECTOR_DPOP_ENFORCE"},
		{name: "bad version in the environment", env: required(map[string]string{"CONNECTOR_SIGNING_KEY_VERSION": "v1"}), wantErr: "CONNECTOR_SIGNING_KEY_VERSION"},
		{name: "bad level", args: []string{"--log-level", "loud"}, env: required(nil), wantErr: "--log-level"},
		{name: "help", args: []string{"-h"}, env: required(nil), wantErr: "help requested"},
		{name: "stray argument", args: []string{"extra"}, env: required(nil), wantErr: "unexpected argument"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var errOut bytes.Buffer
			got, err := parseServe(tc.args, tc.env, &errOut)
			if strings.Contains(errOut.String(), "hunter2") {
				t.Errorf("the database URL reached the usage text:\n%s", errOut.String())
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
			tc.check(t, got.cfg)
		})
	}
}

// schemaVersion follows the token store's migrations: a new migration fails this test until someone
// decides whether the connector needs it.
func TestSchemaVersionIsTheNewestMigration(t *testing.T) {
	files, err := filepath.Glob("../token-store/internal/schema/migrations/*.up.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("no migrations: %v", err)
	}
	if len(files) != schemaVersion {
		t.Errorf("schemaVersion is %d, the token store has %d migrations", schemaVersion, len(files))
	}
}

// syncBuffer collects records written from other goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// writeFile writes content to a new file under the test's directory and returns its path.
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const (
	canaryTokenSecret        = "canary-token-secret-0123456789abcdef\n"
	canaryRegistrationSecret = "canary-registration-secret-0123456789"
	canaryRegistrarSecret    = "canary-registrar-secret-0123456789abcd"
	registrationEndpoint     = "https://connector.example/oauth2/register"
	resourceAudience         = "https://resource.example"
)

// noCanary fails for every canary found in logs, naming its label, never its value.
func noCanary(t *testing.T, logs string, canaries map[string]string) {
	t.Helper()
	for label, value := range canaries {
		if value != "" && strings.Contains(logs, value) {
			t.Errorf("canary %q reached the output", label)
		}
	}
}

// baseArgs are the serve arguments every run shares; later arguments override them.
func baseArgs(t *testing.T, database, openbao string) []string {
	return []string{"serve", "--addr", "127.0.0.1:0", "--ops-addr", "127.0.0.1:0",
		"--database-url", database, "--openbao-url", openbao,
		"--openbao-token-file", writeFile(t, "bao-token", "dev-token-not-used\n"),
		"--issuer", "https://connector.example", "--signing-key", "connector-at", "--signing-key-version", "1",
		"--registration-endpoint", "https://connector.example/oauth2/register",
		"--token-secret-file", writeFile(t, "token-secret", canaryTokenSecret),
		"--registration-secret-file", writeFile(t, "registration-secret", canaryRegistrationSecret),
		"--registrar-id", "registrar", "--registrar-secret-file", writeFile(t, "registrar-secret", canaryRegistrarSecret),
		"--registrar-scopes", "connector:client_registration,resource.read",
		"--registrar-audiences", registrationEndpoint + "," + resourceAudience,
		"--drain-delay", "300ms", "--shutdown-timeout", "2s"}
}

func TestServeRefusesMissingOrShortSecrets(t *testing.T) {
	for name, override := range map[string][]string{
		"missing token secret":        {"--token-secret-file", filepath.Join(t.TempDir(), "absent")},
		"short registration secret":   {"--registration-secret-file", writeFile(t, "short", "only-31-bytes-long-0123456789ab\n")},
		"the same secret for both":    {"--registration-secret-file", writeFile(t, "same", canaryTokenSecret)},
		"short token secret, no line": {"--token-secret-file", writeFile(t, "short", "x")},
		"short registrar secret":      {"--registrar-secret-file", writeFile(t, "short", "registrar\n")},
		"missing registrar secret":    {"--registrar-secret-file", filepath.Join(t.TempDir(), "absent")},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errOut syncBuffer
			code := run(append(baseArgs(t, testDatabase, "http://127.0.0.1:1"), override...), &out, &errOut)
			if code != exitFailed {
				t.Fatalf("exit %d, want %d\n%s%s", code, exitFailed, out.String(), errOut.String())
			}
			logs := out.String() + errOut.String()
			if !strings.Contains(logs, "starting the connector") {
				t.Errorf("the refusal was not recorded:\n%s", logs)
			}
			noCanary(t, logs, map[string]string{"database password": "hunter2", "token secret": strings.TrimSpace(canaryTokenSecret),
				"registration secret": canaryRegistrationSecret, "registrar secret": canaryRegistrarSecret, "short secret": "only-31-bytes"})
		})
	}
}

// running is a serve started by start.
type running struct {
	addr, opsAddr string
	out, errOut   *syncBuffer
	exit          chan int
	sawDraining   bool // /readyz answered draining after the signal
}

// start runs serve in the background and waits for it to report its listeners.
func start(t *testing.T, args []string) *running {
	t.Helper()
	r := &running{out: &syncBuffer{}, errOut: &syncBuffer{}, exit: make(chan int, 1)}
	go func() { r.exit <- run(args, r.out, r.errOut) }()
	deadline := time.Now().Add(10 * time.Second)
	for r.opsAddr == "" && time.Now().Before(deadline) {
		for _, line := range strings.Split(r.out.String(), "\n") {
			var raw struct {
				Msg     string `json:"msg"`
				Addr    string `json:"addr"`
				OpsAddr string `json:"ops_addr"`
			}
			if json.Unmarshal([]byte(line), &raw) == nil && raw.Msg == "connector listening" {
				r.addr, r.opsAddr = raw.Addr, raw.OpsAddr
			}
		}
		select {
		case code := <-r.exit:
			t.Fatalf("serve exited with %d:\n%s%s", code, r.out.String(), r.errOut.String())
		case <-time.After(20 * time.Millisecond):
		}
	}
	if r.opsAddr == "" {
		t.Fatalf("serve never reported listening:\n%s%s", r.out.String(), r.errOut.String())
	}
	return r
}

// stop sends SIGTERM to the running serve and returns its exit code. The signal is for serve's own
// handler; it is sent only while serve runs.
func (r *running) stop(t *testing.T) int {
	t.Helper()
	select {
	case code := <-r.exit:
		t.Fatalf("serve exited with %d before the signal:\n%s", code, r.out.String())
	default:
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	// The listeners stay open for the drain delay while readiness already says draining.
	for range 20 {
		if code, _, body := get(t, "http://"+r.opsAddr+"/readyz"); code == http.StatusServiceUnavailable && strings.Contains(body, `"draining":true`) {
			r.sawDraining = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case code := <-r.exit:
		return code
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not exit after SIGTERM")
		return -1
	}
}

func get(t *testing.T, url string, header ...string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(body)
}

// With nothing there the connector still starts, stays alive and not ready, serves no token, and
// stops on SIGTERM: readiness turns to draining at once, then the process exits 0.
func TestServeStartsWithoutDependenciesAndDrains(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	openbao := "http://" + ln.Addr().String()
	_ = ln.Close() // nothing listens there now

	r := start(t, baseArgs(t, testDatabase, openbao))
	if code, _, _ := get(t, "http://"+r.opsAddr+"/healthz"); code != http.StatusOK {
		t.Errorf("healthz %d", code)
	}
	code, hdr, body := get(t, "http://"+r.opsAddr+"/readyz", "X-Request-Id", "cli-probe")
	if code != http.StatusServiceUnavailable || !strings.Contains(body, `"postgres":"unreachable"`) ||
		!strings.Contains(body, `"openbao":"unreachable"`) || hdr.Get("X-Request-Id") != "cli-probe" {
		t.Errorf("readyz %d %s", code, body)
	}
	if code, _, _ := get(t, "http://"+r.addr+"/.well-known/jwks.json"); code != http.StatusServiceUnavailable {
		t.Errorf("jwks before the signer: %d, want 503", code)
	}
	if code := r.stop(t); code != exitOK || !r.sawDraining {
		t.Errorf("exit %d after SIGTERM, readiness drained: %v\n%s", code, r.sawDraining, r.out.String())
	}
	logs := r.out.String() + r.errOut.String()
	if strings.Contains(logs, "hunter2") {
		t.Errorf("the database password reached the output:\n%s", logs)
	}
	for _, want := range []string{`"correlation_id":"cli-probe"`, `"service":"connector"`, `"msg":"signer not ready, retrying"`,
		`"msg":"draining"`, `"msg":"connector stopped"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("records lack %s:\n%s", want, logs)
		}
	}
}

// A database URL pgx cannot parse is refused with a fixed message: pgx's own error carries the
// connection string, masked on a best-effort basis only. Each password below defeats that masking
// in part (an "@" inside it, spaces around "=").
func TestServeNeverPrintsAnUnparsableDatabaseURL(t *testing.T) {
	for name, c := range map[string]struct{ dsn, password string }{
		"invalid URL":       {"postgres://u:pw@canary-url-tail@[::1/x", "canary-url-tail"},
		"invalid option":    {"postgres://u:pw@canary-opt-tail@127.0.0.1:1/x?sslmode=bogus", "canary-opt-tail"},
		"keyword/value DSN": {"host=127.0.0.1 user=u password = canary-kv-pw sslmode=bogus", "canary-kv-pw"},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errOut syncBuffer
			code := run(append(baseArgs(t, testDatabase, "http://127.0.0.1:1"), "--database-url", c.dsn), &out, &errOut)
			if code != exitFailed {
				t.Fatalf("exit %d, want %d", code, exitFailed)
			}
			logs := out.String() + errOut.String()
			if !strings.Contains(logs, "invalid database configuration") {
				t.Errorf("the refusal was not recorded")
			}
			noCanary(t, logs, map[string]string{"database URL": c.dsn, "database password": c.password})
		})
	}
}

// testJWK is the public JWK of a fresh P-256 key with kid as its kid, as a JSON object.
func testJWK(t *testing.T, kid string) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.PublicJWK(&key.PublicKey)
	jwk.Kid = kid
	b, _ := json.Marshal(jwk)
	return key, string(b)
}

const (
	vpIssuer = "https://verifier.example"
	vpScope  = "resource.vp"
)

// The verified-presentation flags: off when unset; the files parsed strictly, every refusal naming
// the flag and nothing of the file.
func TestParseServeVerifiedPresentation(t *testing.T) {
	_, k1 := testJWK(t, "canary-kid-1")
	_, k2 := testJWK(t, "canary-kid-2")
	_, dup := testJWK(t, "canary-kid-1")
	issuers := writeFile(t, "issuers.json", `{"`+vpIssuer+`":{"keys":[`+k1+`]},"https://other.example":{"keys":[`+k2+`]}}`)
	scopeMap := writeFile(t, "scopes.json", `[{"role":"canary-role","entitlement":"e","scopes":["`+vpScope+`"]},{"role":"canary-role","scopes":["b","c"]}]`)
	vpArgs := func(issuersFile, mapFile string) []string {
		return []string{"--vp-trusted-issuers-file", issuersFile, "--vp-scope-map-file", mapFile}
	}
	issuersWith := func(content string) []string { return vpArgs(writeFile(t, "issuers.json", content), scopeMap) }
	mapWith := func(content string) []string { return vpArgs(issuers, writeFile(t, "scopes.json", content)) }
	private := strings.TrimSuffix(k1, "}") + `,"d":"AAAA"}`
	p384 := strings.Replace(k1, `"P-256"`, `"P-384"`, 1)
	noKid := strings.Replace(k1, `"kid":"canary-kid-1"`, `"use":"sig"`, 1)

	t.Run("off when unset", func(t *testing.T) {
		got, err := parseServe(nil, required(nil), io.Discard)
		if err != nil || got.cfg.vp.TrustedIssuers != nil || got.cfg.vp.Scopes != nil || got.cfg.registrarDelegable != nil {
			t.Fatalf("%+v, %v", got.cfg.vp, err)
		}
	})
	t.Run("from the environment", func(t *testing.T) {
		got, err := parseServe(nil, required(map[string]string{"CONNECTOR_VP_TRUSTED_ISSUERS_FILE": issuers,
			"CONNECTOR_VP_SCOPE_MAP_FILE": scopeMap, "CONNECTOR_REGISTRAR_DELEGABLE_SCOPES": vpScope + ", b"}), io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		vp := got.cfg.vp
		if len(vp.TrustedIssuers) != 2 || vp.TrustedIssuers[vpIssuer]["canary-kid-1"] == nil || vp.TrustedIssuers["https://other.example"]["canary-kid-2"] == nil {
			t.Errorf("issuers: %v", vp.TrustedIssuers)
		}
		if len(vp.Scopes) != 2 || vp.Scopes[0].Entitlement != "e" || vp.Scopes[1].Entitlement != "" || strings.Join(vp.Scopes[1].Scopes, " ") != "b c" {
			t.Errorf("scopes: %+v", vp.Scopes)
		}
		if strings.Join(got.cfg.registrarDelegable, " ") != vpScope+" b" {
			t.Errorf("delegable: %v", got.cfg.registrarDelegable)
		}
	})

	for _, tc := range []struct {
		name, wantErr string
		args          []string
	}{
		{"issuers without a map", "--vp-scope-map-file", []string{"--vp-trusted-issuers-file", issuers}},
		{"map without issuers", "--vp-scope-map-file", []string{"--vp-scope-map-file", scopeMap}},
		{"missing issuers file", "--vp-trusted-issuers-file", vpArgs(filepath.Join(t.TempDir(), "absent"), scopeMap)},
		{"private key member", "--vp-trusted-issuers-file", issuersWith(`{"` + vpIssuer + `":{"keys":[` + private + `]}}`)},
		{"wrong curve", "--vp-trusted-issuers-file", issuersWith(`{"` + vpIssuer + `":{"keys":[` + p384 + `]}}`)},
		{"no kid", "--vp-trusted-issuers-file", issuersWith(`{"` + vpIssuer + `":{"keys":[` + noKid + `]}}`)},
		{"duplicate kid across issuers", "--vp-trusted-issuers-file", issuersWith(`{"` + vpIssuer + `":{"keys":[` + k1 + `]},"https://o.example":{"keys":[` + dup + `]}}`)},
		{"unknown issuer member", "--vp-trusted-issuers-file", issuersWith(`{"` + vpIssuer + `":{"keys":[` + k1 + `],"canary-extra":1}}`)},
		{"duplicate issuer", "--vp-trusted-issuers-file", issuersWith(`{"` + vpIssuer + `":{"keys":[` + k1 + `]},"` + vpIssuer + `":{"keys":[` + k2 + `]}}`)},
		{"no keys", "--vp-trusted-issuers-file", issuersWith(`{"` + vpIssuer + `":{"keys":[]}}`)},
		{"issuer not a URI", "--vp-trusted-issuers-file", issuersWith(`{"canary-issuer":{"keys":[` + k1 + `]}}`)},
		{"empty issuers", "--vp-trusted-issuers-file", issuersWith(`{}`)},
		{"unknown map member", "--vp-scope-map-file", mapWith(`[{"role":"canary-role","scopes":["a"],"canary-extra":true}]`)},
		{"case-folded map member", "--vp-scope-map-file", mapWith(`[{"Role":"canary-role","scopes":["a"]}]`)},
		{"duplicate map member", "--vp-scope-map-file", mapWith(`[{"role":"canary-role","role":"x","scopes":["a"]}]`)},
		{"no role", "--vp-scope-map-file", mapWith(`[{"scopes":["a"]}]`)},
		{"no scopes", "--vp-scope-map-file", mapWith(`[{"role":"canary-role","scopes":[]}]`)},
		{"registration scope mapped", "--vp-scope-map-file", mapWith(`[{"role":"canary-role","scopes":["connector:client_registration"]}]`)},
		{"pair mapped twice", "--vp-scope-map-file", mapWith(`[{"role":"canary-role","scopes":["a"]},{"role":"canary-role","scopes":["b"]}]`)},
		{"map not an array", "--vp-scope-map-file", mapWith(`{"role":"canary-role","scopes":["a"]}`)},
		{"registration scope delegated", "--registrar-delegable-scopes", []string{"--registrar-delegable-scopes", "a,connector:client_registration"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseServe(tc.args, required(nil), io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one naming %s", err, tc.wantErr)
			}
			if strings.Contains(err.Error(), "canary") || strings.Contains(err.Error(), "AAAA") {
				t.Errorf("the error repeats the file: %v", err)
			}
		})
	}
}
