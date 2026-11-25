package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectortest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03/if03fixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/meshcaller"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/pgtest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/tokenverify"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/guard"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/policyevaluator"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire/acquiretest"
)

// tenantCase is one row of the two-tenant record (ZT-53).
type tenantCase struct {
	Case          string      `json:"case"`
	Status        int         `json:"status"`
	ReasonCode    string      `json:"reason_code,omitempty"`
	RuleID        string      `json:"rule_id,omitempty"`
	CorrelationID string      `json:"correlation_id,omitempty"`
	GuardEvent    *hook.Event `json:"guard_event,omitempty"`
	PolicyEvent   *hook.Event `json:"policy_event,omitempty"`
}

// TestTwoTenantsWithRealConnectorStorePolicyPostgresAndOpenBao: two tenants, each with its own
// guard (target tenant from its configuration), policy (its own members), upstream routes and
// upstream client credentials, on one real connector, token store, PostgreSQL and OpenBao. Each
// tenant's member is served on its own routes with scope separation kept; the other tenant's
// member, through the same guard, is denied by policy (m3-tenant-membership) with the tenant on
// both events; and the other tenant's guard cannot obtain this tenant's upstream credential from
// the store. Every case runs in both directions.
func TestTwoTenantsWithRealConnectorStorePolicyPostgresAndOpenBao(t *testing.T) {
	addr, token := os.Getenv("TRANSIT_TEST_ADDR"), os.Getenv("TRANSIT_TEST_TOKEN")
	if addr == "" || token == "" || os.Getenv(pgtest.DatabaseEnv) == "" {
		t.Skip("real Postgres/OpenBao inputs unavailable")
	}
	const issuer = "https://connector.tenants.test"
	const aud = "https://resource.facis.invalid"
	const inbound = "https://guard.facis.invalid"
	const vpIssuer = "https://fixture.tenants.test"
	const vpKid = "fixture-1"
	tenants := []string{"tenant-a", "tenant-b"}
	id := func(tenant, sa string) string { return "spiffe://zone-a.test/ns/" + tenant + "/sa/" + sa }
	host := func(tenant string) string { return "ztd-guard." + tenant + ".test" }
	fixtureKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := connectortest.Start(t, pgtest.MigratedURL(t, "tenant_issuer"), addr, token, connectortest.Options{
		Issuer: issuer, VPIssuer: vpIssuer, VPKid: vpKid, VPKey: &fixtureKey.PublicKey, Audiences: []string{inbound, aud},
		ScopeMap: []connectortest.Scope{{Role: "reader", Scopes: []string{"report:read"}}, {Role: "viewer", Scopes: []string{"report:summary"}}},
	})
	bao, err := transit.New(transit.Config{Addr: addr, Token: func(context.Context) (string, error) { return token, nil }})
	if err != nil {
		t.Fatal(err)
	}
	prefix := "ztd/m3-tenants/" + acquiretest.RandHex(8)
	loaded := acquire.Loaded{SigningKey: "tenant-store-" + acquiretest.RandHex(6), KVPrefix: prefix,
		Trusted: if03.Issuers{vpIssuer: {vpKid: &fixtureKey.PublicKey}}, Routes: map[string]acquire.Route{}}
	// Each tenant's upstream routes, with an upstream client of its own: its credentials.
	scopeRoutes := map[string]map[string]string{}
	for _, tenant := range tenants {
		scopeRoutes[tenant] = map[string]string{"report:read": tenant + "-read", "report:summary": tenant + "-summary"}
		for scope, route := range scopeRoutes[tenant] {
			clientID, secret := c.Register(t, "store "+route, scope, aud)
			file := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(file, []byte(secret), 0o600); err != nil {
				t.Fatal(err)
			}
			role := map[string]string{"report:read": "reader", "report:summary": "viewer"}[scope]
			loaded.Routes[route] = acquire.Route{Name: route, PeerZone: "zone-b", Audience: aud, Tenant: route, ConnectorURL: c.Base, ClientID: clientID, ClientSecretFile: file,
				Outcomes: if03fixture.Fixture{Issuer: vpIssuer, Kid: vpKid, Key: fixtureKey, Claims: if03.Claims{Role: role}}}
			loaded.Substitution = append(loaded.Substitution, meshcaller.Route{Callers: []string{id(tenant, "ztd-guard")}, PeerZone: "zone-b", Audience: aud, Tenant: route, Methods: []string{"POST"}, TargetPrefix: "https://" + host(tenant) + "/demo"})
		}
	}
	dsn := testDatabaseURL(t)
	migrate(t, dsn)
	cfg := localConfig(dsn, addr)
	cfg.Acquisition = &loaded
	cfg.OpenBao = bao
	cfg.ReplayCallers = []string{id("tenant-a", "ztd-guard"), id("tenant-b", "ztd-guard")}
	store, err := New(t.Context(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	startServer(t, store)
	participants := []string{id("tenant-a", "ztd-participant"), id("tenant-b", "ztd-participant")}
	v2 := compileV2(t)
	type tenantSide struct {
		guard           *guard.Runtime
		guardEvents     *eventLog
		policyEvents    *eventLog
		storeAsGuard    string
		published, host string
	}
	sides := map[string]*tenantSide{}
	for _, tenant := range tenants {
		s := &tenantSide{guardEvents: &eventLog{}, policyEvents: &eventLog{}, published: "https://" + host(tenant), host: host(tenant)}
		storeFront := guardTestProxy(t, "http://"+store.Addr().String(), id(tenant, "ztd-guard"))
		s.storeAsGuard = storeFront.URL
		policy, err := policyevaluator.New(policyevaluator.Config{Revision: tenant + "-1", Audience: inbound, Host: s.host, GuardCallers: []string{id(tenant, "ztd-guard")},
			ParticipantCallers: participants, ScopeTenants: scopeRoutes[tenant], EventSource: "policy-a", TenantMembers: map[string][]string{tenant: {id(tenant, "ztd-participant")}}},
			hook.NewLogSinkV2(s.policyEvents, "policy-a", tenant))
		if err != nil {
			t.Fatal(err)
		}
		policyServer := httptest.NewServer(policy)
		t.Cleanup(policyServer.Close)
		policyFront := guardTestProxy(t, policyServer.URL, id(tenant, "ztd-guard"))
		s.guard, err = guard.New(guard.Config{Issuer: issuer, JWKSURL: c.Base + "/.well-known/jwks.json", InboundAudience: inbound, UpstreamAudience: aud, PublishedBaseURL: s.published,
			PeerZone: "zone-b", PolicyURL: policyFront.URL, StoreURL: storeFront.URL, AllowedCallers: participants, ScopeTenants: scopeRoutes[tenant], EventSource: "guard-a", TargetTenant: tenant},
			hook.NewLogSinkV2(s.guardEvents, "guard-a", tenant))
		if err != nil {
			t.Fatal(err)
		}
		sides[tenant] = s
	}
	type member struct {
		granted connectorclient.TokenResponse
		signer  guardTestKey
		spiffe  string
	}
	login := func(t *testing.T, tenant, scope, role string) member {
		clientID, secret := c.Register(t, tenant+" "+role, scope, inbound)
		cc := &connectorclient.Client{BaseURL: c.Base, ClientID: clientID, ClientSecret: secret}
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		challenge, err := cc.Challenge(t.Context(), inbound)
		if err != nil {
			t.Fatal(err)
		}
		outcome, err := if03fixture.Fixture{Issuer: vpIssuer, Kid: vpKid, Key: fixtureKey, Claims: if03.Claims{Role: role}}.Outcome(t.Context(), challenge)
		if err != nil {
			t.Fatal(err)
		}
		granted, err := cc.Grant(t.Context(), guardTestKey{key}, outcome, challenge.Value, inbound)
		if err != nil {
			t.Fatal(err)
		}
		return member{granted, guardTestKey{key}, id(tenant, "ztd-participant")}
	}
	call := func(t *testing.T, m member, s *tenantSide) hook.Outcome {
		proof, err := dpopproof.Build(t.Context(), m.signer, dpopproof.Claims{HTM: "POST", HTU: s.published + "/demo", ATH: connectorclient.ATH(m.granted.AccessToken)})
		if err != nil {
			t.Fatal(err)
		}
		header := http.Header{}
		header.Set("Authorization", "DPoP "+m.granted.AccessToken)
		header.Set("DPoP", proof)
		header.Set("X-Forwarded-Client-Cert", "URI="+m.spiffe)
		return s.guard.Evaluate(t.Context(), hook.Request{Method: "POST", Path: "/demo", Host: s.host, Headers: header})
	}
	var rows []tenantCase
	for _, own := range tenants {
		other := tenants[0]
		if own == other {
			other = tenants[1]
		}
		s := sides[own]
		resource, err := tokenverify.New(tokenverify.Config{Issuer: issuer, JWKSURL: c.Base + "/.well-known/jwks.json", Audience: aud, PublicBaseURL: s.published, Replay: replay.NewMemory()})
		if err != nil {
			t.Fatal(err)
		}
		t.Run(own, func(t *testing.T) {
			// The tenant's own member, both scopes: served, and the forwarded credential is the
			// tenant's upstream token of exactly that scope.
			for _, entry := range []struct{ scope, role string }{{"report:read", "reader"}, {"report:summary", "viewer"}} {
				out := call(t, login(t, own, entry.scope, entry.role), s)
				if !out.Allowed || out.RuleID != "m3-"+map[string]string{"report:read": "report-read", "report:summary": "report-summary"}[entry.scope] {
					t.Fatalf("%s member (%s) refused: %d %s %s", own, entry.scope, out.Status, out.ReasonCode, out.RuleID)
				}
				forwarded, _ := http.NewRequest(http.MethodPost, s.published+"/demo", nil)
				for _, h := range out.SetHeaders {
					forwarded.Header.Set(h.Name, h.Value)
				}
				verified, err := resource.Verify(forwarded)
				if err != nil || !slices.Contains(verified.Scopes, entry.scope) || (entry.scope == "report:summary" && slices.Contains(verified.Scopes, "report:read")) {
					t.Fatalf("%s %s: forwarded credential wrong: %v %v", own, entry.scope, err, verified.Scopes)
				}
				ge, pe := s.guardEvents.find(t, out.CorrelationID), s.policyEvents.find(t, out.CorrelationID)
				if ge == nil || pe == nil || ge.Payload.Tenant != own || pe.Payload.Tenant != own || ge.Payload.State != "allowed" {
					t.Fatalf("%s allowed events: %+v %+v", own, ge, pe)
				}
				checkV2(t, v2, ge)
				checkV2(t, v2, pe)
				rows = append(rows, tenantCase{Case: own + " member, " + entry.scope + ", through the " + own + " guard", Status: 200, RuleID: out.RuleID, CorrelationID: out.CorrelationID, GuardEvent: ge, PolicyEvent: pe})
			}
			// The other tenant's member through this tenant's guard: authenticated, entitled to the
			// scope, and denied by policy because it is not a member of this tenant.
			for _, entry := range []struct{ scope, role string }{{"report:read", "reader"}, {"report:summary", "viewer"}} {
				out := call(t, login(t, other, entry.scope, entry.role), s)
				ge, pe := s.guardEvents.find(t, out.CorrelationID), s.policyEvents.find(t, out.CorrelationID)
				if out.Allowed || out.Status != 403 || out.ReasonCode != hook.ReasonRuleDeny || out.RuleID != policyevaluator.RuleTenantMembership ||
					ge == nil || pe == nil || ge.Payload.Tenant != own || pe.Payload.Tenant != own || pe.Payload.RuleID != policyevaluator.RuleTenantMembership ||
					pe.Payload.CallerSPIFFEID != id(other, "ztd-participant") || pe.Payload.BundleRevision != own+"-1" {
					t.Fatalf("%s member through the %s guard: %+v guard %+v policy %+v", other, own, out, ge, pe)
				}
				checkV2(t, v2, ge)
				checkV2(t, v2, pe)
				rows = append(rows, tenantCase{Case: other + " member, " + entry.scope + ", through the " + own + " guard", Status: out.Status, ReasonCode: out.ReasonCode, RuleID: out.RuleID, CorrelationID: out.CorrelationID, GuardEvent: ge, PolicyEvent: pe})
			}
			// Credentials: the other tenant's guard asks the store for this tenant's upstream token.
			for _, route := range scopeRoutes[own] {
				body, _ := json.Marshal(hook.SubstituteRequest{PeerZone: "zone-b", Audience: aud, Tenant: &route, Method: "POST", TargetURI: s.published + "/demo", CorrelationID: "tenant-cross-" + route})
				resp, err := http.Post(sides[other].storeAsGuard+"/internal/substitute", "application/json", bytes.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				var refusal struct {
					ReasonCode string `json:"reason_code"`
				}
				_ = json.NewDecoder(resp.Body).Decode(&refusal)
				_ = resp.Body.Close()
				if resp.StatusCode != 403 || (refusal.ReasonCode != hook.ReasonTokenCallerDenied && refusal.ReasonCode != hook.ReasonTokenRouteDenied) {
					t.Fatalf("%s guard obtained or was not refused %s's route %s: %d %s", other, own, route, resp.StatusCode, refusal.ReasonCode)
				}
				rows = append(rows, tenantCase{Case: other + " guard asks the store for " + own + "'s upstream route " + route, Status: resp.StatusCode, ReasonCode: refusal.ReasonCode})
			}
		})
	}
	if dir := os.Getenv("TENANTS_OUT"); dir != "" {
		out, _ := json.MarshalIndent(rows, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, "tenants.json"), append(out, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := bao.List(t.Context(), prefix)
	if err != nil {
		t.Fatal("test KV list failed")
	}
	for _, entry := range entries {
		if err := bao.Delete(t.Context(), prefix+"/"+entry); err != nil {
			t.Fatal("test KV cleanup failed")
		}
	}
}
