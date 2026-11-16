package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/pgtest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire"
)

// keysEnv is what the keys and acquire commands need on the command line: a migrated database, a
// real OpenBao (TRANSIT_TEST_ADDR, TRANSIT_TEST_TOKEN) and an acquisition config naming a fresh
// key and, for acquire, one route to a connector nothing listens on.
type keysEnv struct {
	t     *testing.T
	name  string
	args  []string
	dbURL string
	tc    *transit.Client
}

func newKeysEnv(t *testing.T, withRoute bool) *keysEnv {
	t.Helper()
	addr, token := os.Getenv("TRANSIT_TEST_ADDR"), os.Getenv("TRANSIT_TEST_TOKEN")
	if addr == "" || token == "" {
		t.Skip("TRANSIT_TEST_ADDR and TRANSIT_TEST_TOKEN not set")
	}
	if os.Getenv(pgtest.DatabaseEnv) == "" {
		t.Skipf("%s not set", pgtest.DatabaseEnv)
	}
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	privDER, _ := x509.MarshalECPrivateKey(priv)
	pubFile := write("issuer.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	privFile := write("issuer.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}))
	secretFile := write("client-secret", []byte("not-a-real-secret-0123456789\n"))
	var b [6]byte
	_, _ = rand.Read(b[:])
	name := "cli-" + hex.EncodeToString(b[:])
	cfg := map[string]any{
		"signing_key":     name,
		"trusted_issuers": []any{map[string]any{"issuer": "https://verifier.test.invalid", "kid": "k1", "public_key_file": pubFile}},
		"routes":          []any{},
	}
	if withRoute {
		cfg["routes"] = []any{map[string]any{
			"name": "dead", "peer_zone": "zone-b", "audience": "https://resource.test.invalid",
			"connector_url": "http://127.0.0.1:1", "client_id": "store", "client_secret_file": secretFile,
			"fixture_outcomes": map[string]any{"issuer": "https://verifier.test.invalid", "kid": "k1",
				"private_key_file": privFile, "role": "reader"},
		}}
	}
	raw, _ := json.Marshal(cfg)
	cfgFile := write("acquisition.json", raw)
	tokenFile := write("openbao-token", []byte(token+"\n"))
	tc, err := transit.New(transit.Config{Addr: addr, Token: func(context.Context) (string, error) { return token, nil }})
	if err != nil {
		t.Fatal(err)
	}
	dbURL := pgtest.MigratedURL(t, "cli_keys")
	return &keysEnv{t: t, name: name, dbURL: dbURL, tc: tc, args: []string{
		"--database-url", dbURL, "--openbao-url", addr, "--openbao-token-file", tokenFile, "--acquire-config", cfgFile}}
}

// run runs one command and decodes its JSON output; stderr is returned for the record checks.
func (e *keysEnv) run(cmd ...string) (code int, out map[string]any, stderr string) {
	e.t.Helper()
	var stdout, errOut bytes.Buffer
	code = run(append(cmd, e.args...), &stdout, &errOut)
	if stdout.Len() > 0 {
		if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
			e.t.Fatalf("output is not JSON: %v\n%s", err, stdout.String())
		}
	}
	return code, out, errOut.String()
}

func (e *keysEnv) rows() []struct{ ref, state string } {
	e.t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, e.dbURL)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	rows, err := conn.Query(ctx, `SELECT key_ref, state FROM signing_key WHERE split_part(key_ref, ':', 2) = $1 ORDER BY created_at`, e.name)
	if err != nil {
		e.t.Fatal(err)
	}
	type row = struct{ ref, state string }
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		err := r.Scan(&x.ref, &x.state)
		return x, err
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return out
}

// ensure registers the key's first version with its thumbprint; rotate activates the second,
// retires the first and raises transit's signing floor above it; status reports both; no output
// carries key material.
func TestKeysEnsureRotateAndStatus(t *testing.T) {
	e := newKeysEnv(t, false)
	v1 := transit.KeyVersion{Name: e.name, Version: 1}
	v2 := transit.KeyVersion{Name: e.name, Version: 2}
	var records strings.Builder

	code, out, stderr := e.run("keys", "ensure")
	records.WriteString(stderr)
	if code != exitOK || out["key_ref"] != v1.Ref() || out["state"] != "active" || len(out["jkt"].(string)) != 43 {
		t.Fatalf("ensure: exit %d %v\n%s", code, out, stderr)
	}
	if rows := e.rows(); len(rows) != 1 || rows[0].state != "active" {
		t.Fatalf("after ensure: %+v", rows)
	}
	code, out, stderr = e.run("keys", "status")
	records.WriteString(stderr)
	if code != exitOK || out["present"] != true || out["latest_version"] != float64(1) || out["min_signing_version"] != float64(0) || len(out["versions"].([]any)) != 1 {
		t.Fatalf("status: exit %d %v", code, out)
	}

	code, out, stderr = e.run("keys", "rotate")
	records.WriteString(stderr)
	if code != exitOK || out["active"] != v2.Ref() || out["min_signing_version"] != float64(2) || out["adopted"] != false {
		t.Fatalf("rotate: exit %d %v\n%s", code, out, stderr)
	}
	if retired, _ := out["retired"].([]any); len(retired) != 1 || retired[0] != v1.Ref() {
		t.Fatalf("rotate retired %v", out["retired"])
	}
	if rows := e.rows(); len(rows) != 2 || rows[0].state != "retired" || rows[1].state != "active" || rows[1].ref != v2.Ref() {
		t.Fatalf("after rotate: %+v", rows)
	}
	ctx := context.Background()
	var se *transit.StatusError
	if _, err := e.tc.Sign(ctx, v1, []byte("eyJhbGciOiJFUzI1NiJ9.e30")); !errors.As(err, &se) || se.Status < 400 {
		t.Fatalf("transit still signs with the retired version: %v", err)
	}
	if _, err := e.tc.Sign(ctx, v2, []byte("eyJhbGciOiJFUzI1NiJ9.e30")); err != nil {
		t.Fatalf("transit does not sign with the active version: %v", err)
	}
	code, out, stderr = e.run("keys", "status")
	records.WriteString(stderr)
	if code != exitOK || out["latest_version"] != float64(2) || out["min_signing_version"] != float64(2) || len(out["versions"].([]any)) != 2 {
		t.Fatalf("status after rotate: exit %d %v", code, out)
	}
	// A floor above the registered version (a rotation that did not finish): ensure says retired
	// rather than all clear, and rotate repairs by adopting the version transit is at.
	v3 := transit.KeyVersion{Name: e.name, Version: 3}
	if _, err := e.tc.Rotate(ctx, e.name); err != nil {
		t.Fatal(err)
	}
	if err := e.tc.SetMinSigningVersion(ctx, e.name, 3); err != nil {
		t.Fatal(err)
	}
	code, out, stderr = e.run("keys", "ensure")
	records.WriteString(stderr)
	if code != exitFailed || out != nil || !strings.Contains(stderr, `"reason":"retired"`) {
		t.Fatalf("ensure below the floor: exit %d %v\n%s", code, out, stderr)
	}
	code, out, stderr = e.run("keys", "rotate")
	records.WriteString(stderr)
	if code != exitOK || out["active"] != v3.Ref() || out["adopted"] != true {
		t.Fatalf("rotate repairing the floor: exit %d %v\n%s", code, out, stderr)
	}
	for _, needle := range []string{"-----", "BEGIN ", "PRIVATE"} {
		if strings.Contains(records.String(), needle) {
			t.Fatalf("key material in the records:\n%s", records.String())
		}
	}
}

// acquire signs through a read-only signer: with the key not yet registered it fails in the store
// before any peer contact, and the key is not created on the way.
func TestAcquireCommandDoesNotCreateTheKey(t *testing.T) {
	e := newKeysEnv(t, true)
	code, out, _ := e.run("acquire", "--route", "dead")
	if code != exitFailed || out["reason_code"] != acquire.CodeStore {
		t.Fatalf("acquire without a key: exit %d %v", code, out)
	}
	if _, err := e.tc.LatestKey(context.Background(), e.name); !errors.Is(err, transit.ErrNotFound) {
		t.Fatalf("acquire created the key: %v", err)
	}
	if rows := e.rows(); len(rows) != 0 {
		t.Fatalf("acquire registered a row: %+v", rows)
	}
}

// status on a key transit does not have says so, rather than a version of 0 that reads as present.
func TestKeysStatusReportsAnAbsentKey(t *testing.T) {
	e := newKeysEnv(t, false)
	code, out, _ := e.run("keys", "status")
	if code != exitOK || out["present"] != false || out["latest_version"] != float64(0) || len(out["versions"].([]any)) != 0 {
		t.Fatalf("status of an absent key: exit %d %v", code, out)
	}
	code, out, _ = e.run("keys", "rotate")
	if code != exitFailed || out != nil {
		t.Fatalf("rotate of an absent key: exit %d %v; want a failure and no key created", code, out)
	}
	if _, err := e.tc.LatestKey(context.Background(), e.name); !errors.Is(err, transit.ErrNotFound) {
		t.Fatalf("rotate created the key: %v", err)
	}
}
