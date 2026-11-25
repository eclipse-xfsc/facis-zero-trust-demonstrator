package protectedresource

import (
	"bytes"
	"context"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cloudStandIn is a TLS server in the cloud API's place; it returns its base URL and its CA file.
func cloudStandIn(t *testing.T, handler http.HandlerFunc) (string, string) {
	t.Helper()
	upstream := httptest.NewTLSServer(handler)
	t.Cleanup(upstream.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return upstream.URL + "/cloudapi/v6", ca
}

// cloudTestConfig loads the cloud adapter's configuration from the environment, as the binary does.
func cloudTestConfig(t *testing.T, apiURL, caFile string) Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("cloud-test-canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROTECTED_RESOURCE_MODE", "sample")
	t.Setenv("PROTECTED_RESOURCE_ADAPTER_MODE", "cloud-api")
	t.Setenv("PROTECTED_RESOURCE_CLOUD_TOKEN_FILE", path)
	t.Setenv("PROTECTED_RESOURCE_CLOUD_API_URL", apiURL)
	t.Setenv("PROTECTED_RESOURCE_CLOUD_CA_FILE", caFile)
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestCloudDock(t *testing.T) {
	for _, tc := range []struct {
		name         string
		status       int
		body, reason string
	}{
		{"success", 200, `{"id":"datacenters","type":"collection","items":[{"id":"1","type":"datacenter","metadata":{"secret":"cloud-test-canary"},"properties":{"name":"cloud-test-canary"}}],"offset":0,"limit":100}`, ReasonReportReturned},
		{"empty", 200, `{"type":"collection","items":[]}`, ReasonReportReturned},
		{"unauthorized", 401, "cloud-test-canary", "CLOUD_ACCESS_DENIED"},
		{"forbidden", 403, "cloud-test-canary", "CLOUD_ACCESS_DENIED"},
		{"unavailable", 503, "cloud-test-canary", "CLOUD_UPSTREAM_UNAVAILABLE"},
		{"redirect", 302, "cloud-test-canary", "CLOUD_UPSTREAM_UNAVAILABLE"},
		{"malformed", 200, "cloud-test-canary", "CLOUD_RESPONSE_INVALID"},
		{"wrong interface", 200, `{"type":"collection","items":[{"type":"server"}]}`, "CLOUD_RESPONSE_INVALID"},
		{"missing items", 200, `{"type":"collection"}`, "CLOUD_RESPONSE_INVALID"},
		{"oversized", 200, strings.Repeat("x", 1048577), "CLOUD_RESPONSE_INVALID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			apiURL, ca := cloudStandIn(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "GET" || r.URL.RequestURI() != "/cloudapi/v6/datacenters?depth=0&limit=100" || r.Header.Get("Authorization") != "Bearer cloud-test-canary" {
					t.Error("incorrect upstream contract")
				}
				w.Header().Set("Location", "https://unexpected.invalid/")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})
			cfg := cloudTestConfig(t, apiURL, ca)
			cfg.Verifier = fakeVerifier{identity: callerIdentity(ScopeReportRead)}
			var logs bytes.Buffer
			server := NewServer(cfg, slog.New(slog.NewJSONHandler(&logs, nil)))
			response := serveWithCredentials(server.Handler(), `{"resource":"sample-report","action":"read"}`)
			if !strings.Contains(response.Body.String(), tc.reason) || !strings.Contains(logs.String(), `"reasonCode":"`+tc.reason+`","adapter":"cloud-api"`) {
				t.Fatalf("missing result or recorded event %s: %s", tc.reason, logs.String())
			}
			if success := tc.reason == ReasonReportReturned; success != strings.Contains(response.Body.String(), `"id":"CLOUD-DATACENTERS"`) {
				t.Fatalf("cloud report present = %v, want %v", !success, success)
			}
			if calls != 1 {
				t.Fatalf("calls=%d (redirect must not be followed)", calls)
			}
			if strings.Contains(response.Body.String()+logs.String(), "cloud-test-canary") {
				t.Fatal("credential or provider data leaked")
			}
		})
	}
}

func TestCloudScopeBoundary(t *testing.T) {
	cfg := cloudTestConfig(t, "", "")
	for _, scope := range []string{"other:write", ScopeReportSummary} {
		cfg.Verifier = fakeVerifier{identity: callerIdentity(scope)}
		var logs bytes.Buffer
		// A nil adapter makes any unauthorized upstream invocation fail the test.
		server := NewServerWithAdapter(cfg, slog.New(slog.NewJSONHandler(&logs, nil)), nil)
		response := serveWithCredentials(server.Handler(), `{"resource":"sample-report","action":"read"}`)
		if response.Code != 403 || !strings.Contains(logs.String(), ReasonScopeInsufficient) {
			t.Fatal("scope refusal not recorded")
		}
	}
}

func TestCloudCredentialAndCancellation(t *testing.T) {
	cfg := cloudTestConfig(t, "", "")
	if cfg.CloudAPIURL != defaultCloudAPIURL || cfg.CloudRootCAs != nil {
		t.Fatalf("defaults: %q", cfg.CloudAPIURL)
	}
	adapter := NewResourceAdapter(cfg)
	if err := os.Remove(cfg.CloudTokenFile); err != nil {
		t.Fatal(err)
	}
	result, err := adapter.Request(context.Background(), ResourceRequest{Resource: "sample-report", Action: "read"})
	if err != nil || result.ReasonCode != "CLOUD_CREDENTIAL_INVALID" {
		t.Fatal("missing mounted credential did not fail closed")
	}
	if _, err := LoadConfig(); err == nil || err.Error() != "CLOUD_CREDENTIAL_INVALID" {
		t.Fatal("invalid configuration accepted")
	}
	for _, token := range []string{"", "embedded\nnewline", "bad\x00token", strings.Repeat("x", 16385)} {
		if err := os.WriteFile(cfg.CloudTokenFile, []byte(token), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(); err == nil {
			t.Fatal("invalid credential accepted")
		}
	}
	if err := os.WriteFile(cfg.CloudTokenFile, []byte("cloud-test-canary"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err = adapter.Request(ctx, ResourceRequest{Resource: "sample-report", Action: "read"})
	if err != nil || result.ReasonCode != "CLOUD_REQUEST_FAILED" {
		t.Fatal("cancelled request did not fail closed")
	}
}

// Settings that cannot name a usable API are refused when the configuration is loaded.
func TestCloudSettingsRejected(t *testing.T) {
	cloudTestConfig(t, "", "")
	notPEM := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, setting := range [][2]string{
		{"PROTECTED_RESOURCE_CLOUD_API_URL", "http://api.example/cloudapi/v6"},
		{"PROTECTED_RESOURCE_CLOUD_API_URL", "https://user:secret@api.example/cloudapi/v6"},
		{"PROTECTED_RESOURCE_CLOUD_API_URL", "https://api.example/cloudapi/v6?depth=5"},
		{"PROTECTED_RESOURCE_CLOUD_API_URL", "/cloudapi/v6"},
		{"PROTECTED_RESOURCE_CLOUD_CA_FILE", notPEM},
		{"PROTECTED_RESOURCE_CLOUD_CA_FILE", notPEM + ".absent"},
	} {
		t.Run(setting[1], func(t *testing.T) {
			t.Setenv(setting[0], setting[1])
			if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), setting[0]) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("accepted or misreported: %v", err)
			}
		})
	}
}

// The configuration-time check: an API that does not answer as the documented interface is refused
// before the Resource serves, with a recorded reason and one read-only call.
func TestCloudInterfaceCheck(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		cause  string
	}{
		{"documented interface", 200, `{"id":"datacenters","type":"collection","items":[{"id":"1","type":"datacenter"}]}`, ""},
		{"another collection", 200, `{"type":"collection","items":[{"type":"server"}]}`, "CLOUD_RESPONSE_INVALID"},
		{"not the API", 200, `<html>cloud-test-canary</html>`, "CLOUD_RESPONSE_INVALID"},
		{"no such operation", 404, `{}`, "CLOUD_UPSTREAM_UNAVAILABLE"},
		{"credential refused", 401, `{}`, "CLOUD_ACCESS_DENIED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			apiURL, ca := cloudStandIn(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})
			cfg := cloudTestConfig(t, apiURL, ca)
			var logs bytes.Buffer
			err := CheckInterface(context.Background(), cfg, NewResourceAdapter(cfg), slog.New(slog.NewJSONHandler(&logs, nil)))
			if tc.cause == "" {
				if err != nil || logs.Len() != 0 {
					t.Fatalf("conforming API refused: %v %s", err, logs.String())
				}
			} else if err == nil || err.Error() != ReasonInterfaceRejected+": "+tc.cause ||
				!strings.Contains(logs.String(), `"reasonCode":"`+ReasonInterfaceRejected+`","cause":"`+tc.cause+`"`) {
				t.Fatalf("refusal %v, record %s", err, logs.String())
			}
			if calls != 1 || strings.Contains(logs.String(), "cloud-test-canary") {
				t.Fatalf("calls=%d, or a leak: %s", calls, logs.String())
			}
		})
	}
	// An API whose certificate the configured roots do not vouch for is refused as well.
	apiURL, _ := cloudStandIn(t, func(http.ResponseWriter, *http.Request) { t.Error("an untrusted API was called") })
	cfg := cloudTestConfig(t, apiURL, "")
	if err := CheckInterface(context.Background(), cfg, NewResourceAdapter(cfg), slog.New(slog.DiscardHandler)); err == nil || err.Error() != ReasonInterfaceRejected+": CLOUD_REQUEST_FAILED" {
		t.Fatalf("untrusted API: %v", err)
	}
	// The sample adapters have no remote interface to check.
	t.Setenv("PROTECTED_RESOURCE_ADAPTER_MODE", "sample")
	sample, err := LoadConfig()
	if err != nil || CheckInterface(context.Background(), sample, NewResourceAdapter(sample), slog.New(slog.DiscardHandler)) != nil {
		t.Fatal("sample adapter refused")
	}
}
