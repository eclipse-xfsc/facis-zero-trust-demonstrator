package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// stubCalls is what the stub connector saw.
type stubCalls struct {
	mu                   sync.Mutex
	tokenScope, tokenAud string
	registrationBody     []byte
	beforeCreated        func() // runs just before a 201
}

// stubConnector answers the registrar's token request and the registration as the connector
// does, from a script: mode "ok" registers, "refuse" refuses the metadata, "down" answers 500,
// "unread" answers a 201 without the secret, "not found" answers the registration with a plain 404.
func stubConnector(t *testing.T, mode string) (*httptest.Server, *stubCalls) {
	t.Helper()
	const token = "connector_at_x.SIGNATURE"
	calls := &stubCalls{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode == "down" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		switch r.URL.Path {
		case "/oauth2/token":
			user, pass, ok := r.BasicAuth()
			if !ok || user != "registrar" || !strings.HasPrefix(pass, "registrar-secret") || r.Header.Get("DPoP") == "" ||
				r.FormValue("grant_type") != "client_credentials" || !strings.Contains(r.FormValue("scope"), "connector:client_registration") ||
				!strings.Contains(r.FormValue("audience"), "/oauth2/register") || r.Header.Get("X-Request-Id") != "req-cli" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client","reason":"invalid_client"}`))
				return
			}
			calls.mu.Lock()
			calls.tokenScope, calls.tokenAud = r.FormValue("scope"), r.FormValue("audience")
			calls.mu.Unlock()
			_, _ = w.Write([]byte(`{"access_token":"` + token + `","token_type":"DPoP","expires_in":300}`))
		case "/oauth2/register":
			body, _ := io.ReadAll(r.Body)
			calls.mu.Lock()
			calls.registrationBody = body
			calls.mu.Unlock()
			var m map[string]any
			if r.Header.Get("Authorization") != "DPoP "+token || r.Header.Get("DPoP") == "" || json.Unmarshal(body, &m) != nil ||
				r.Header.Get("X-Request-Id") != "req-cli" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_token","reason":"invalid_token"}`))
				return
			}
			switch {
			case mode == "not found":
				http.NotFound(w, r)
				return
			case mode == "refuse" || m["dpop_bound_access_tokens"] != true:
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_client_metadata","error_description":"` + ruleText[ruleDPoPBound] + `","reason":"registration_rejected"}`))
				return
			case mode == "unread":
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"client_id":"` + strings.Repeat("c", 64) + `"}`))
				return
			}
			if calls.beforeCreated != nil {
				calls.beforeCreated()
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"client_id":"` + strings.Repeat("c", 64) + `","client_secret":"` + strings.Repeat("s", 32) +
				`","registration_access_token":"canary-rat","client_name":"` + m["client_name"].(string) + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, calls
}

func registerArgs(t *testing.T, srv *httptest.Server, out string, extra ...string) []string {
	t.Helper()
	return append([]string{"register", "--connector", srv.URL, "--registrar-id", "registrar",
		"--registrar-secret-file", writeFile(t, "registrar-secret", "registrar-secret-0123456789abcdefghij\n"),
		"--client-name", "cli participant", "--scope", "resource.read,resource.write", "--audience", "https://resource.example",
		"--out", out, "--request-id", "req-cli"}, extra...)
}

// clearRegisterEnv keeps the command's environment fallback out of the way of a test's flags.
func clearRegisterEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{"CONNECTOR_URL", "CONNECTOR_REGISTRATION_ENDPOINT", "CONNECTOR_REGISTRAR_ID", "CONNECTOR_REGISTRAR_SECRET_FILE", "CONNECTOR_REGISTRAR_DELEGABLE_SCOPES"} {
		t.Setenv(v, "")
	}
}

func TestRegisterCommand(t *testing.T) {
	clearRegisterEnv(t)
	t.Run("registers and writes the credentials file", func(t *testing.T) {
		srv, calls := stubConnector(t, "ok")
		out := filepath.Join(t.TempDir(), "credentials.json")
		var stdout, stderr bytes.Buffer
		if code := run(registerArgs(t, srv, out), &stdout, &stderr); code != exitOK {
			t.Fatalf("exit %d\n%s%s", code, stdout.String(), stderr.String())
		}
		info, err := os.Stat(out)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("credentials file: %v %v", err, info)
		}
		content, _ := os.ReadFile(out)
		want := `{"client_id":"` + strings.Repeat("c", 64) + `","client_secret":"` + strings.Repeat("s", 32) + `"}` + "\n"
		if string(content) != want {
			t.Errorf("credentials file:\n%s", content)
		}
		if !strings.HasPrefix(stdout.String(), "registered client_id="+strings.Repeat("c", 64)+" credentials=") || stderr.Len() != 0 {
			t.Errorf("output:\n%s%s", stdout.String(), stderr.String())
		}
		for _, canary := range []string{strings.Repeat("s", 32), "canary-rat", "registrar-secret-0123", "SIGNATURE"} {
			if strings.Contains(stdout.String()+stderr.String(), canary) {
				t.Errorf("%q reached the output", canary)
			}
		}
		if calls.tokenScope != "connector:client_registration resource.read resource.write" ||
			calls.tokenAud != srv.URL+"/oauth2/register https://resource.example" {
			t.Errorf("registrar token asked for %q / %q", calls.tokenScope, calls.tokenAud)
		}
		if left, _ := filepath.Glob(filepath.Join(filepath.Dir(out), ".*.tmp")); len(left) != 0 {
			t.Errorf("temporary files left: %v", left)
		}
	})
	t.Run("a refusal exits 1 and leaves no file", func(t *testing.T) {
		srv, _ := stubConnector(t, "refuse")
		out := filepath.Join(t.TempDir(), "credentials.json")
		var stdout, stderr bytes.Buffer
		if code := run(registerArgs(t, srv, out), &stdout, &stderr); code != exitRefused {
			t.Fatalf("exit %d\n%s%s", code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stderr.String(), "registration refused: registration_rejected (400): "+ruleText[ruleDPoPBound]) || stdout.Len() != 0 {
			t.Errorf("output:\n%s%s", stdout.String(), stderr.String())
		}
		if entries, _ := os.ReadDir(filepath.Dir(out)); len(entries) != 0 {
			t.Errorf("a refused registration left files: %v", entries)
		}
	})
	t.Run("a refused registrar token exits 1", func(t *testing.T) {
		srv, _ := stubConnector(t, "ok")
		out := filepath.Join(t.TempDir(), "credentials.json")
		args := registerArgs(t, srv, out)
		args[6] = writeFile(t, "wrong-secret", "not-the-registrar-secret-0123456789")
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != exitRefused || !strings.Contains(stderr.String(), "registrar token refused: invalid_client (401)") {
			t.Errorf("exit %d\n%s", code, stderr.String())
		}
	})
	t.Run("the metadata file is sent as is and shapes the token", func(t *testing.T) {
		srv, calls := stubConnector(t, "ok")
		out := filepath.Join(t.TempDir(), "credentials.json")
		doc := `{"client_name":"from file","grant_types":["client_credentials"],"token_endpoint_auth_method":"client_secret_basic","scope":"report:read","dpop_bound_access_tokens":true,"audience":["https://file.example"]}`
		var stdout, stderr bytes.Buffer
		code := run([]string{"register", "--connector", srv.URL, "--registrar-id", "registrar",
			"--registrar-secret-file", writeFile(t, "registrar-secret", "registrar-secret-0123456789abcdefghij"),
			"--metadata-file", writeFile(t, "metadata.json", doc), "--out", out, "--request-id", "req-cli"}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("exit %d\n%s%s", code, stdout.String(), stderr.String())
		}
		if string(calls.registrationBody) != doc {
			t.Errorf("sent %s", calls.registrationBody)
		}
		if calls.tokenScope != "connector:client_registration report:read" || calls.tokenAud != srv.URL+"/oauth2/register https://file.example" {
			t.Errorf("registrar token asked for %q / %q", calls.tokenScope, calls.tokenAud)
		}
	})
	t.Run("a 201 without the credentials exits 4", func(t *testing.T) {
		srv, _ := stubConnector(t, "unread")
		out := filepath.Join(t.TempDir(), "credentials.json")
		var stdout, stderr bytes.Buffer
		if code := run(registerArgs(t, srv, out), &stdout, &stderr); code != exitNotWritten || !strings.Contains(stderr.String(), "delete its oauth2_client row") {
			t.Errorf("exit %d\n%s", code, stderr.String())
		}
	})
	t.Run("a target that appears during the run exits 4 and is not overwritten", func(t *testing.T) {
		srv, calls := stubConnector(t, "ok")
		out := filepath.Join(t.TempDir(), "credentials.json")
		calls.beforeCreated = func() { _ = os.WriteFile(out, []byte("someone else's"), 0o600) }
		var stdout, stderr bytes.Buffer
		if code := run(registerArgs(t, srv, out), &stdout, &stderr); code != exitNotWritten || !strings.Contains(stderr.String(), "registered client "+strings.Repeat("c", 64)) {
			t.Errorf("exit %d\n%s", code, stderr.String())
		}
		if content, _ := os.ReadFile(out); string(content) != "someone else's" {
			t.Errorf("target overwritten: %s", content)
		}
		if strings.Contains(stderr.String(), strings.Repeat("s", 32)) {
			t.Error("the secret reached the output")
		}
	})
	t.Run("a server error exits 3 and warns the client may exist", func(t *testing.T) {
		srv, _ := stubConnector(t, "down")
		out := filepath.Join(t.TempDir(), "credentials.json")
		var stdout, stderr bytes.Buffer
		if code := run(registerArgs(t, srv, out), &stdout, &stderr); code != exitUnreachable || !strings.Contains(stderr.String(), "server error from the peer (500)") {
			t.Errorf("exit %d\n%s", code, stderr.String())
		}
		if entries, _ := os.ReadDir(filepath.Dir(out)); len(entries) != 0 {
			t.Errorf("a failed registration left files: %v", entries)
		}
	})
	t.Run("an answer no IF-02 call gives exits 3, not refused", func(t *testing.T) {
		srv, _ := stubConnector(t, "not found")
		out := filepath.Join(t.TempDir(), "credentials.json")
		var stdout, stderr bytes.Buffer
		code := run(registerArgs(t, srv, out), &stdout, &stderr)
		if code != exitUnreachable || !strings.Contains(stderr.String(), "unexpected answer from the peer (404)") || !strings.Contains(stderr.String(), "may have been registered") {
			t.Errorf("exit %d\n%s", code, stderr.String())
		}
	})
	t.Run("an existing credentials file is refused before any call", func(t *testing.T) {
		srv, calls := stubConnector(t, "ok")
		out := writeFile(t, "credentials.json", "{}")
		var stdout, stderr bytes.Buffer
		if code := run(registerArgs(t, srv, out), &stdout, &stderr); code != exitUsage || !strings.Contains(stderr.String(), "credentials file") {
			t.Errorf("exit %d\n%s", code, stderr.String())
		}
		if content, _ := os.ReadFile(out); string(content) != "{}" || calls.tokenScope != "" {
			t.Errorf("the existing file was touched or a call was made: %s %q", content, calls.tokenScope)
		}
	})
	t.Run("help exits 0", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"register", "-h"}, &stdout, &stderr); code != exitOK {
			t.Errorf("exit %d", code)
		}
	})
	t.Run("usage errors exit 2 and name what is wrong", func(t *testing.T) {
		secret := writeFile(t, "registrar-secret", "registrar-secret-0123456789abcdefghij")
		base := []string{"register", "--connector", "http://x", "--registrar-id", "r", "--registrar-secret-file", secret, "--out", filepath.Join(t.TempDir(), "o")}
		good := append(append([]string{}, base...), "--client-name", "n", "--scope", "s", "--audience", "https://a")
		with := func(args []string, extra ...string) []string { return append(append([]string{}, args...), extra...) }
		for name, tc := range map[string]struct {
			args []string
			want string
		}{
			"no connector":            {[]string{"register", "--registrar-id", "r", "--registrar-secret-file", "/x", "--out", "/y"}, "--connector"},
			"bad connector":           {[]string{"register", "--connector", "ftp://x", "--registrar-id", "r", "--registrar-secret-file", "/x", "--out", "/y"}, "--connector"},
			"bad endpoint":            {with(good, "--registration-endpoint", "https://x/register?a=1"), "--registration-endpoint"},
			"no registrar":            {[]string{"register", "--connector", "http://x", "--registrar-secret-file", "/x", "--out", "/y"}, "--registrar-id"},
			"no registrar secret":     {[]string{"register", "--connector", "http://x", "--registrar-id", "r", "--out", "/y"}, "--registrar-secret-file"},
			"no out":                  {[]string{"register", "--connector", "http://x", "--registrar-id", "r", "--registrar-secret-file", "/x"}, "--out"},
			"no metadata":             {base, "--client-name, --scope and --audience"},
			"relative audience":       {with(base, "--client-name", "n", "--scope", "s", "--audience", "/api"), "--audience"},
			"repeated audience":       {with(base, "--client-name", "n", "--scope", "s", "--audience", "https://a,https://a"), "--audience"},
			"registration scope":      {with(base, "--client-name", "n", "--scope", "s,connector:client_registration", "--audience", "https://a"), "--scope"},
			"repeated scope":          {with(base, "--client-name", "n", "--scope", "s s", "--audience", "https://a"), "--scope"},
			"scope with a tab":        {with(base, "--client-name", "n", "--scope", "a\tb", "--audience", "https://a"), "--scope"},
			"padded client name":      {with(base, "--client-name", " n", "--scope", "s", "--audience", "https://a"), "--client-name"},
			"no grant types":          {with(good, "--grant-types", ","), "--grant-types"},
			"metadata and flags":      {with(base, "--metadata-file", "/m.json", "--scope", "s"), "--metadata-file"},
			"request id with a space": {with(good, "--request-id", "has space"), "--request-id"},
			"zero timeout":            {with(good, "--timeout", "0s"), "--timeout"},
			"missing registrar secret file": {[]string{"register", "--connector", "http://x", "--registrar-id", "r", "--registrar-secret-file", "/does/not/exist",
				"--out", "/y", "--client-name", "n", "--scope", "s", "--audience", "https://a"}, "registrar secret"},
			"metadata file not an object": {with(base, "--metadata-file", writeFile(t, "m.json", "[1]")), "not one JSON object"},
			"stray argument":              {[]string{"register", "extra"}, "unexpected argument"},
		} {
			t.Run(name, func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				if code := run(tc.args, &stdout, &stderr); code != exitUsage || !strings.Contains(stderr.String(), tc.want) {
					t.Errorf("exit %d, want %d naming %q\n%s", code, exitUsage, tc.want, stderr.String())
				}
			})
		}
	})
}

// The environment fills what the command line left unset; a flag wins over it.
func TestParseRegisterEnvironment(t *testing.T) {
	env := map[string]string{"CONNECTOR_URL": "http://env.example", "CONNECTOR_REGISTRAR_ID": "env-registrar",
		"CONNECTOR_REGISTRAR_SECRET_FILE": "/env/secret", "CONNECTOR_REGISTRATION_ENDPOINT": "http://env.example/custom/register"}
	o, err := parseRegister([]string{"--registrar-id", "flag-registrar", "--client-name", "n", "--scope", "s", "--audience", "https://a", "--out", "/o"},
		func(k string) string { return env[k] }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if o.connector != "http://env.example" || o.registrarID != "flag-registrar" || o.registrarFile != "/env/secret" || o.endpoint != "http://env.example/custom/register" {
		t.Errorf("%+v", o)
	}
}

// The registrar's token asks for the registration scope and the client's scopes, never a delegable
// one, which no token can carry.
func TestRegistrarTokenScope(t *testing.T) {
	for _, tc := range []struct {
		scope     string
		delegable []string
		want      string
	}{
		{"resource.read", nil, "connector:client_registration resource.read"},
		{"resource.vp", []string{"resource.vp"}, "connector:client_registration"},
		{"resource.read resource.vp", []string{"resource.vp", "other"}, "connector:client_registration resource.read"},
		{"", nil, "connector:client_registration"},
		{"a  a\tb", nil, "connector:client_registration a b"},
	} {
		if got := registrarTokenScope(tc.scope, tc.delegable); got != tc.want {
			t.Errorf("%q minus %v: %q, want %q", tc.scope, tc.delegable, got, tc.want)
		}
	}
}
