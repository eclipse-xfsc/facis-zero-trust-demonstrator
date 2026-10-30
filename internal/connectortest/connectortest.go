// Package connectortest runs a Connector for integration tests: the real connector binary
// (services/connector), built once per test binary and started as a subprocess on a migrated
// database of its own, with a transit signing key, the registrar, the trusted-issuers file and the
// scope map. Clients are registered through the registrar's DCR with delegated verified-presentation
// scopes, as a deployment registers them. A test binary that uses it calls Cleanup from its TestMain.
package connectortest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
)

const vpGrantType = "urn:facis:params:oauth:grant-type:verified-presentation"

var (
	buildOnce    sync.Once
	connectorBin string
	buildErr     error
)

func connectorBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		_, self, _, _ := runtime.Caller(0)
		dir, err := os.MkdirTemp("", "connector-bin")
		if err != nil {
			buildErr = err
			return
		}
		connectorBin = filepath.Join(dir, "connector")
		cmd := exec.Command("go", "build", "-o", connectorBin, "./services/connector")
		cmd.Dir = filepath.Join(filepath.Dir(self), "..", "..")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = errors.New(string(out))
		}
	})
	if buildErr != nil {
		t.Fatalf("building the connector: %v", buildErr)
	}
	return connectorBin
}

// Cleanup removes the built connector binary.
func Cleanup() {
	if connectorBin != "" {
		_ = os.RemoveAll(filepath.Dir(connectorBin))
	}
}

// Connector is a running connector.
type Connector struct {
	Base string
	// Stop stops the connector (SIGTERM, then wait); later calls do nothing.
	Stop func()

	registrarSecret string
	endpoint        string
}

// Options configure the connector's verified-presentation grant.
type Options struct {
	Issuer    string           // iss of its access tokens
	VPIssuer  string           // the one trusted IF-03 issuer
	VPKid     string           // its key id
	VPKey     *ecdsa.PublicKey // its key
	ScopeMap  []Scope          // claims to scopes
	Audiences []string         // resource audiences clients may register
}

// Scope is one entry of the scope map.
type Scope struct {
	Role        string   `json:"role"`
	Entitlement string   `json:"entitlement,omitempty"`
	Scopes      []string `json:"scopes"`
}

// FreeAddr is a loopback address nothing listens on at the moment.
func FreeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

// WriteFile writes content to a file of the test's own and returns its path.
func WriteFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// RandHex is n random bytes, hex-encoded.
func RandHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Start runs the connector on dsn (migrated by pgtest). Every scope of the map is delegable by the
// registrar, which may name every audience of o.
func Start(t *testing.T, dsn, baoAddr, baoToken string, o Options) *Connector {
	t.Helper()
	ctx := t.Context()
	// pgtest applies the files directly; record them as the token store's runner would, as the
	// connector's own tests do, so the binary's schema check is satisfied.
	files, _ := filepath.Glob(filepath.Join(migrationsDir(), "*.up.sql"))
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `CREATE TABLE schema_migrations (version integer PRIMARY KEY, name text NOT NULL,
		checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now());
		INSERT INTO schema_migrations (version, name, checksum) SELECT v, 'm', '' FROM generate_series(1, `+strconv.Itoa(len(files))+`) v`); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close(ctx)

	kv, err := transit.New(transit.Config{Addr: baoAddr, Token: func(context.Context) (string, error) { return baoToken, nil }})
	if err != nil {
		t.Fatal(err)
	}
	key, err := kv.EnsureKey(ctx, "acq-b-"+RandHex(6))
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.PublicJWK(o.VPKey)
	jwk.Kid = o.VPKid
	jwkJSON, _ := json.Marshal(jwk)
	scopeMap, _ := json.Marshal(o.ScopeMap)
	var delegable []string
	for _, e := range o.ScopeMap {
		delegable = append(delegable, e.Scopes...)
	}

	apiAddr, opsAddr := FreeAddr(t), FreeAddr(t)
	base := "http://" + apiAddr
	endpoint := base + "/oauth2/register"
	registrarSecret := RandHex(24)
	cmd := exec.Command(connectorBinary(t), "serve", "--addr", apiAddr, "--ops-addr", opsAddr,
		"--database-url", dsn, "--openbao-url", baoAddr, "--openbao-token-file", WriteFile(t, "bao-token", baoToken+"\n"),
		"--issuer", o.Issuer, "--signing-key", key.Name, "--signing-key-version", strconv.Itoa(key.Version),
		"--registration-endpoint", endpoint,
		"--token-secret-file", WriteFile(t, "token-secret", RandHex(24)),
		"--registration-secret-file", WriteFile(t, "registration-secret", RandHex(24)),
		"--registrar-id", "registrar", "--registrar-secret-file", WriteFile(t, "registrar-secret", registrarSecret),
		"--registrar-scopes", "connector:client_registration", "--registrar-audiences", strings.Join(append([]string{endpoint}, o.Audiences...), ","),
		"--registrar-delegable-scopes", strings.Join(delegable, ","),
		"--vp-trusted-issuers-file", WriteFile(t, "issuers.json", `{"`+o.VPIssuer+`":{"keys":[`+string(jwkJSON)+`]}}`),
		"--vp-scope-map-file", WriteFile(t, "scopes.json", string(scopeMap)),
		"--zone", "b", "--drain-delay", "0s", "--shutdown-timeout", "2s")
	out := &buffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			_ = cmd.Wait()
		})
	}
	t.Cleanup(stop)
	for i := 0; ; i++ {
		resp, err := http.Get("http://" + opsAddr + "/readyz")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if strings.Contains(string(body), `"ready":true`) {
				break
			}
		}
		if i == 150 {
			t.Fatalf("connector never ready:\n%s", out.String())
		}
		time.Sleep(100 * time.Millisecond)
	}

	return &Connector{Base: base, Stop: stop, registrarSecret: registrarSecret, endpoint: endpoint}
}

// Register registers a confidential client for the verified-presentation grant, DPoP-bound, with
// scope (space-separated) and audiences, through the registrar's DCR as a deployment does
// (connectorclient, the client side `connector register` runs), and returns its credentials.
func (c *Connector) Register(t *testing.T, name, scope string, audiences ...string) (clientID, clientSecret string) {
	t.Helper()
	key, err := dpopproof.NewProcessKey()
	if err != nil {
		t.Fatal(err)
	}
	registrar := &connectorclient.Client{BaseURL: c.Base, ClientID: "registrar", ClientSecret: c.registrarSecret}
	issued, err := registrar.ClientCredentialsToken(t.Context(), key, connectorclient.RegistrationScope, append([]string{c.endpoint}, audiences...))
	if err != nil {
		t.Fatalf("registrar token: %v", err)
	}
	creds, err := registrar.Register(t.Context(), key, c.endpoint, issued.AccessToken, connectorclient.Registration{
		ClientName: name, GrantTypes: []string{vpGrantType}, Scope: scope, Audience: audiences,
	})
	if err != nil {
		t.Fatalf("registration: %v", err)
	}
	return creds.ClientID, creds.ClientSecret
}

func migrationsDir() string {
	_, self, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(self), "..", "..", "services", "token-store", "internal", "schema", "migrations")
}

// buffer collects the connector's output from its own goroutines.
type buffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *buffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
