package connectorclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
)

// registrarStub is a connector's token and registration endpoints as a registrar sees them: the
// first token call demands a nonce, then issues; the registration answers per mode.
func registrarStub(t *testing.T, mode string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var tokenCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			n := tokenCalls.Add(1)
			user, pass, _ := r.BasicAuth()
			if user != "registrar" || pass != "s3cret" || r.FormValue("grant_type") != "client_credentials" || r.Header.Get("DPoP") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client","reason":"invalid_client"}`))
				return
			}
			if n == 1 {
				w.Header().Set("DPoP-Nonce", "nonce-1")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"use_dpop_nonce","reason":"dpop_use_nonce"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"at.one.two","token_type":"DPoP"}`))
		case "/oauth2/register":
			body, _ := io.ReadAll(r.Body)
			var m map[string]any
			if r.Header.Get("Authorization") != "DPoP at.one.two" || r.Header.Get("DPoP") == "" || json.Unmarshal(body, &m) != nil {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_token","reason":"invalid_token"}`))
				return
			}
			switch mode {
			case "refuse":
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_client_metadata","error_description":"ab\u0007\u001bcd` + strings.Repeat("x", 300) + `","reason":"registration_rejected"}`))
			case "unknown reason":
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"weird","error_description":"not for you","reason":"something_else"}`))
			case "redirect":
				w.Header().Set("Location", "https://elsewhere.example/")
				w.WriteHeader(http.StatusFound)
			case "not found":
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("404 page not found"))
			case "server error":
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"server_error","reason":"server_error"}`))
			case "malformed":
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"client_id":"id"}`))
			default:
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"client_id":"id-1","client_secret":"secret-1","registration_access_token":"rat","client_name":"` + m["client_name"].(string) + `"}`))
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &tokenCalls
}

func TestRegistrarTokenAndRegistration(t *testing.T) {
	srv, tokenCalls := registrarStub(t, "ok")
	key, err := dpopproof.NewProcessKey()
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{BaseURL: srv.URL, ClientID: "registrar", ClientSecret: "s3cret", RequestID: "req-1"}
	issued, err := c.ClientCredentialsToken(context.Background(), key, RegistrationScope, []string{srv.URL + "/oauth2/register", "https://r.example"})
	if err != nil || issued.AccessToken != "at.one.two" || tokenCalls.Load() != 2 {
		t.Fatalf("token: %+v %v after %d calls", issued, err, tokenCalls.Load())
	}
	creds, err := c.Register(context.Background(), key, srv.URL+"/oauth2/register", issued.AccessToken,
		Registration{ClientName: "backend", Scope: "resource.read", Audience: []string{"https://r.example"}})
	if err != nil || creds.ClientID != "id-1" || creds.ClientSecret != "secret-1" {
		t.Fatalf("register: %+v %v", creds, err)
	}
}

func TestRegistrationRefusals(t *testing.T) {
	key, err := dpopproof.NewProcessKey()
	if err != nil {
		t.Fatal(err)
	}
	for mode, want := range map[string]struct {
		kind        Kind
		reason      string
		description string
		status      int
		unreachable bool
	}{
		// The description keeps its printable runes only, bounded: the control characters go.
		"refuse":         {KindRefused, ReasonRegistrationRejected, "abcd" + strings.Repeat("x", maxDescription-4), 400, false},
		"unknown reason": {KindLost, "", "", 400, false},
		"redirect":       {KindLost, "", "", 302, false},
		"not found":      {KindLost, "", "", 404, false},
		"server error":   {KindLost, "", "", 500, true},
		"malformed":      {KindUnread, "", "", 201, false},
	} {
		t.Run(mode, func(t *testing.T) {
			srv, _ := registrarStub(t, mode)
			c := &Client{BaseURL: srv.URL, ClientID: "registrar", ClientSecret: "s3cret"}
			issued, err := c.ClientCredentialsToken(context.Background(), key, RegistrationScope, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Register(context.Background(), key, srv.URL+"/oauth2/register", issued.AccessToken, Registration{ClientName: "b", Scope: "s", Audience: []string{"https://r.example"}})
			var e *Error
			if !errors.As(err, &e) || e.Kind != want.kind || e.Reason != want.reason || e.Description != want.description ||
				e.Status != want.status || e.Unreachable != want.unreachable {
				t.Errorf("%+v", e)
			}
			if e != nil && strings.Contains(e.Error(), "not for you") {
				t.Errorf("the peer's text reached the error")
			}
		})
	}
	// A refused registrar token.
	srv, _ := registrarStub(t, "ok")
	c := &Client{BaseURL: srv.URL, ClientID: "registrar", ClientSecret: "wrong"}
	_, err = c.ClientCredentialsToken(context.Background(), key, RegistrationScope, nil)
	var e *Error
	if !errors.As(err, &e) || e.Kind != KindRefused || e.Reason != "invalid_client" || e.Status != http.StatusUnauthorized {
		t.Errorf("refused token: %+v", e)
	}
}

func TestWriteCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := WriteCredentials(path, Credentials{ClientID: "id", ClientSecret: "secret"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v %v", err, info)
	}
	content, _ := os.ReadFile(path)
	if string(content) != "{\"client_id\":\"id\",\"client_secret\":\"secret\"}\n" {
		t.Errorf("content: %s", content)
	}
	if err := WriteCredentials(path, Credentials{ClientID: "other", ClientSecret: "x"}); err == nil {
		t.Error("an existing file was overwritten")
	}
	if content, _ := os.ReadFile(path); !strings.Contains(string(content), `"id"`) {
		t.Errorf("the first credentials were lost: %s", content)
	}
}

// A credentials file appears only complete: nothing at the target until the credentials are in it,
// a run that stops in between leaves the target free for the next one, and a target that appeared
// meanwhile is never overwritten.
func TestCredentialsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.json")
	f, err := ReserveCredentials(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the target exists before the credentials: %v", err)
	}
	// A run that stopped here (killed): the next one can still reserve the target.
	again, err := ReserveCredentials(path)
	if err != nil {
		t.Fatalf("a stopped run blocked the next: %v", err)
	}
	again.Abandon()
	if err := os.WriteFile(path, []byte("someone else's"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.Write(Credentials{ClientID: "id", ClientSecret: "secret"}); err == nil {
		t.Error("a target that appeared meanwhile was overwritten")
	}
	if content, _ := os.ReadFile(path); string(content) != "someone else's" {
		t.Errorf("target: %s", content)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".credentials.json.*.tmp")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
	if _, err := ReserveCredentials(filepath.Join(dir, "missing", "credentials.json")); err == nil {
		t.Error("a missing directory was accepted")
	}
	if _, err := ReserveCredentials(path); !errors.Is(err, fs.ErrExist) {
		t.Errorf("an existing target: %v", err)
	}
}
