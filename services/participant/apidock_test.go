package participant_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectortest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03/if03fixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/pgtest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/protectedresource"
)

// The API dock (docs/api-dock.md): the journey of TestTokenPathEndToEnd with the supplied mocks
// replaced. The real connector binary runs once for the whole test; the Resource is built from the
// environment as cmd/protected-resource builds it, first with the supplied sample adapter and then
// with the cloud-api adapter docked on the same public URL, and a second participant backend, written
// against the Connector's documented interface only, takes the supplied Participant's place.
//
// TestAPIDockJourney docks a local stand-in that answers as the provider documents its list operation.
// TestAPIDockLive docks the provider itself and runs only when API_DOCK_LIVE_TOKEN_FILE names a token
// file. Both write their record to API_DOCK_RECORD when it is set.

const (
	cloudReportID = "CLOUD-DATACENTERS"
	seedReportID  = "FACIS-SAMPLE-REPORT-001"
)

// cloudStandIn answers the provider's documented list operation (GET /datacenters, Bearer token,
// a collection of datacenter items) and refuses anything else. It returns its base URL, CA file and
// call counter.
func cloudStandIn(t *testing.T, token, itemType string) (string, string, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Header.Get("Authorization") != "Bearer "+token:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"httpStatus":401,"messages":[{"errorCode":"315","message":"Unauthorized"}]}`)
		case r.Method != http.MethodGet || r.URL.Path != "/cloudapi/v6/datacenters":
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"httpStatus":404,"messages":[{"errorCode":"309","message":"Resource does not exist"}]}`)
		default:
			href := "https://" + r.Host + "/cloudapi/v6/datacenters"
			item := func(id, name string) map[string]any {
				return map[string]any{"id": id, "type": itemType, "href": href + "/" + id,
					"metadata":   map[string]any{"etag": "stand-in", "state": "AVAILABLE"},
					"properties": map[string]any{"name": name, "location": "de/txl", "version": 1}}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "datacenters", "type": "collection", "href": href,
				"items":  []any{item("15f67991-0f51-4efc-a8ad-ef1fb31a480c", "stand-in one"), item("25f67991-0f51-4efc-a8ad-ef1fb31a480d", "stand-in two")},
				"offset": 0, "limit": 100, "_links": map[string]any{"self": href + "?depth=0&limit=100"}})
		}
	}))
	t.Cleanup(srv.Close)
	ca := writeFile(t, "cloud-ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	return srv.URL + "/cloudapi/v6", ca, calls
}

func digest(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:8])
}

func TestAPIDockJourney(t *testing.T) {
	token := "stand-in-" + connectortest.RandHex(12)
	apiURL, ca, calls := cloudStandIn(t, token, "datacenter")
	apiDock(t, "local stand-in", apiURL, ca, writeFile(t, "cloud-token", []byte(token+"\n")), calls)
}

func TestAPIDockLive(t *testing.T) {
	tokenFile := os.Getenv("API_DOCK_LIVE_TOKEN_FILE")
	if _, err := os.Stat(tokenFile); tokenFile == "" || err != nil {
		t.Skip("API_DOCK_LIVE_TOKEN_FILE names no token file; the live provider is not called")
	}
	apiDock(t, "live provider", "", "", tokenFile, nil)
}

func apiDock(t *testing.T, upstream, apiURL, caFile, tokenFile string, standInCalls *atomic.Int32) {
	addr, baoToken := os.Getenv("TRANSIT_TEST_ADDR"), os.Getenv("TRANSIT_TEST_TOKEN")
	if addr == "" || baoToken == "" {
		t.Skip("TRANSIT_TEST_ADDR and TRANSIT_TEST_TOKEN not set")
	}
	dsn := pgtest.MigratedURL(t, "dock")
	var lines []string
	record := func(format string, args ...any) {
		lines = append(lines, fmt.Sprintf(format, args...))
		t.Log(lines[len(lines)-1])
	}

	// The Zero Trust core of the journey: one Connector process, its trust and scope settings fixed here.
	verifier, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(verifier)
	verifierKeyFile := writeFile(t, "verifier.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	c := connectortest.Start(t, dsn, addr, baoToken, connectortest.Options{
		Issuer: cIssuer, VPIssuer: vpIssuer, VPKid: vpKid, VPKey: &verifier.PublicKey, Audiences: []string{resourceAud},
		ScopeMap: []connectortest.Scope{{Role: "report-reader", Scopes: []string{protectedresource.ScopeReportRead}}},
	})
	jwks := func() string {
		_, _, raw := getJSON(t, http.MethodGet, c.Base+"/.well-known/jwks.json", "")
		return digest(raw)
	}

	// The Resource's public URL stays; what answers behind it is swapped.
	var docked atomic.Value
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		docked.Load().(http.Handler).ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	trust := map[string]string{
		"PROTECTED_RESOURCE_MODE": "token", "PROTECTED_RESOURCE_TOKEN_ISSUER": cIssuer,
		"PROTECTED_RESOURCE_JWKS_URL": c.Base + "/.well-known/jwks.json", "PROTECTED_RESOURCE_AUDIENCE": resourceAud,
		"PROTECTED_RESOURCE_PUBLIC_BASE_URL": front.URL,
	}
	for k, v := range trust {
		t.Setenv(k, v)
	}
	trustDigest := func() string {
		var parts []string
		for _, k := range []string{"PROTECTED_RESOURCE_MODE", "PROTECTED_RESOURCE_TOKEN_ISSUER", "PROTECTED_RESOURCE_JWKS_URL",
			"PROTECTED_RESOURCE_AUDIENCE", "PROTECTED_RESOURCE_PUBLIC_BASE_URL"} {
			parts = append(parts, k+"="+os.Getenv(k))
		}
		return digest(parts...)
	}
	resourceLogs := &syncBuffer{}
	// dock builds the Resource as cmd/protected-resource does: configuration, adapter, the
	// configuration-time interface check, then the server. Only the adapter settings differ.
	dock := func(adapter map[string]string) (http.Handler, error) {
		for k, v := range adapter {
			t.Setenv(k, v)
		}
		cfg, err := protectedresource.LoadConfig()
		if err != nil {
			return nil, err
		}
		logger := slog.New(slog.NewJSONHandler(resourceLogs, nil))
		impl := protectedresource.NewResourceAdapter(cfg)
		if err := protectedresource.CheckInterface(t.Context(), cfg, impl, logger); err != nil {
			return nil, err
		}
		return protectedresource.NewServerWithAdapter(cfg, logger, impl).Handler(), nil
	}
	cloud := map[string]string{"PROTECTED_RESOURCE_ADAPTER_MODE": "cloud-api", "PROTECTED_RESOURCE_CLOUD_TOKEN_FILE": tokenFile,
		"PROTECTED_RESOURCE_CLOUD_API_URL": apiURL, "PROTECTED_RESOURCE_CLOUD_CA_FILE": caFile}

	// Baseline: the supplied Participant and the supplied Resource mock.
	mock, err := dock(map[string]string{"PROTECTED_RESOURCE_ADAPTER_MODE": "sample"})
	if err != nil {
		t.Fatalf("supplied resource: %v", err)
	}
	docked.Store(mock)
	readerID, readerSecret := c.Register(t, "participant reader", protectedresource.ScopeReportRead, resourceAud)
	supplied := startParticipant(t, c.Base, credentials(t, readerID, readerSecret), verifierKeyFile, "report-reader", front.URL)
	var bodies []string
	waitReady(t, supplied, &bodies)
	demo := `{"resource":"sample-report","action":"read","requestId":"dock-check","correlationId":"dock-run"}`
	// call makes the supplied Participant's protected call and returns the report it relays.
	call := func(wantID string) string {
		t.Helper()
		status, got, raw := getJSON(t, http.MethodPost, supplied.url+"/demo", demo)
		bodies = append(bodies, raw)
		safe, _ := got["safeData"].(map[string]any)
		report, _ := safe["report"].(map[string]any)
		if status != http.StatusOK || got["reasonCode"] != "RESOURCE_REPORT_RETURNED" || report["id"] != wantID {
			t.Fatalf("journey: %d %s\nparticipant logs:\n%s\nresource logs:\n%s", status, raw, supplied.logs.String(), resourceLogs.String())
		}
		content, _ := report["content"].(string)
		return content
	}
	call(seedReportID)
	record("baseline: supplied participant -> Connector token -> supplied resource mock -> 200 RESOURCE_REPORT_RETURNED report %s", seedReportID)
	jwksBefore, trustBefore := jwks(), trustDigest()

	// The protected-resource dock: the cloud API takes the mock's place behind the same URL. The
	// Participant is not restarted and presents the token it already holds.
	replacement, err := dock(cloud)
	if err != nil {
		t.Fatalf("docking the cloud API: %v\n%s", err, resourceLogs.String())
	}
	docked.Store(replacement)
	record("resource dock: cloud-api adapter on the %s accepted by the configuration-time interface check", upstream)
	content := call(cloudReportID)
	if !strings.Contains(resourceLogs.String(), `"reasonCode":"RESOURCE_REPORT_RETURNED","adapter":"cloud-api","client_id":"`+readerID+`"`) {
		t.Fatalf("the resource did not record the cloud-backed answer:\n%s", resourceLogs.String())
	}
	record("journey: supplied participant -> Connector token -> docked resource (%s) -> 200 RESOURCE_REPORT_RETURNED report %s: %s", upstream, cloudReportID, content)

	// The participant-backend dock: a second backend, not services/participant, registered through the
	// Connector's DCR and using only its documented interface: challenge, verified-presentation grant,
	// DPoP-bound token, proof per call.
	otherID, otherSecret := c.Register(t, "replacement participant backend", protectedresource.ScopeReportRead, resourceAud)
	key, err := dpopproof.NewProcessKey()
	if err != nil {
		t.Fatal(err)
	}
	cc := &connectorclient.Client{BaseURL: c.Base, ClientID: otherID, ClientSecret: otherSecret}
	ch, err := cc.Challenge(t.Context(), resourceAud)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := if03fixture.Fixture{Issuer: vpIssuer, Kid: vpKid, Key: verifier, Claims: if03.Claims{Role: "report-reader"}}.Outcome(t.Context(), ch)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := cc.Grant(t.Context(), key, outcome, ch.Value, resourceAud)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := dpopproof.Build(t.Context(), key, dpopproof.Claims{HTM: http.MethodPost, HTU: front.URL + "/demo", ATH: connectorclient.ATH(issued.AccessToken)})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/demo", strings.NewReader(demo))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "DPoP "+issued.AccessToken)
	req.Header.Set("DPoP", proof)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	bodies = append(bodies, string(raw))
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"id":"`+cloudReportID+`"`) ||
		!strings.Contains(resourceLogs.String(), `"reasonCode":"RESOURCE_REPORT_RETURNED","adapter":"cloud-api","client_id":"`+otherID+`"`) {
		t.Fatalf("replacement participant: %d %s\n%s", resp.StatusCode, raw, resourceLogs.String())
	}
	record("participant dock: replacement participant backend registered through DCR -> verified-presentation token -> docked resource (%s) -> 200 RESOURCE_REPORT_RETURNED report %s", upstream, cloudReportID)

	// The core did not change: the same Connector process and keys, the same trust settings at the Resource.
	if after := jwks(); after != jwksBefore || trustDigest() != trustBefore {
		t.Fatalf("the core changed across the dock: JWKS %s -> %s", jwksBefore, after)
	}
	record("core unchanged: one Connector process, JWKS digest %s and resource trust settings digest %s before and after the dock", jwksBefore, trustBefore)

	if standInCalls != nil {
		// One call for the interface check, one per protected call: nothing was answered by the mock.
		if n := standInCalls.Load(); n != 3 {
			t.Fatalf("%d calls reached the stand-in; want 3", n)
		}
		// An API that does not satisfy the documented interface is refused at configuration time: the
		// Resource is not built, and the refusal is in its log.
		token, _ := os.ReadFile(tokenFile)
		wrongURL, wrongCA, wrongCalls := cloudStandIn(t, strings.TrimSpace(string(token)), "server")
		_, err := dock(map[string]string{"PROTECTED_RESOURCE_CLOUD_API_URL": wrongURL, "PROTECTED_RESOURCE_CLOUD_CA_FILE": wrongCA})
		if err == nil || err.Error() != "CLOUD_INTERFACE_REJECTED: CLOUD_RESPONSE_INVALID" || wrongCalls.Load() != 1 ||
			!strings.Contains(resourceLogs.String(), `"msg":"protected resource configuration rejected","adapter":"cloud-api","reasonCode":"CLOUD_INTERFACE_REJECTED","cause":"CLOUD_RESPONSE_INVALID"`) {
			t.Fatalf("non-conforming API: %v\n%s", err, resourceLogs.String())
		}
		record("rejected at configuration time: an API answering another interface -> CLOUD_INTERFACE_REJECTED cause CLOUD_RESPONSE_INVALID, recorded, resource not started")
		if _, err := dock(map[string]string{"PROTECTED_RESOURCE_ADAPTER_MODE": "unknown-api"}); err == nil {
			t.Fatal("an unknown adapter was accepted")
		}
		record("rejected at configuration time: an adapter name the resource does not know")
	}

	// Canary: neither the provider token nor a Connector credential in any log, body or record.
	providerToken, _ := os.ReadFile(tokenFile)
	for _, s := range []string{supplied.logs.String(), resourceLogs.String(), strings.Join(bodies, "\n"), strings.Join(lines, "\n")} {
		for _, secret := range []string{strings.TrimSpace(string(providerToken)), readerSecret, otherSecret, issued.AccessToken, proof, outcome} {
			if strings.Contains(s, secret) {
				t.Fatal("a credential leaked into a log, body or record")
			}
		}
	}
	if path := os.Getenv("API_DOCK_RECORD"); path != "" {
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
