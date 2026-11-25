package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectortest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03/if03fixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/meshcaller"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/pgtest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/contractpath"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/tokenverify"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/guard"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/policyevaluator"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire/acquiretest"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type guardTestKey struct{ key *ecdsa.PrivateKey }

func (k guardTestKey) JWK() jose.JWK { return jose.PublicJWK(&k.key.PublicKey) }
func (k guardTestKey) Sign(_ context.Context, in []byte) ([]byte, error) {
	sum := sha256.Sum256(in)
	r, s, err := ecdsa.Sign(rand.Reader, k.key, sum[:])
	if err != nil {
		return nil, err
	}
	return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...), nil
}

// This adapter models only the trusted sidecar header boundary locally. It is not mesh evidence.
// Connector, policy evaluator, token store, Postgres, OpenBao and token/proof verification are real.
func guardTestProxy(t *testing.T, target, identity string) *httptest.Server {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(u)
		r.Out.Header.Del("X-Forwarded-Client-Cert")
		r.Out.Header.Set("X-Forwarded-Client-Cert", "URI="+identity)
	}}
	proxy.ErrorLog = slog.NewLogLogger(slog.NewTextHandler(io.Discard, nil), slog.LevelError)
	front := httptest.NewServer(proxy)
	t.Cleanup(front.Close)
	return front
}

// eventLog collects one component's IF-01 v2 lines, safe for concurrent writers.
type eventLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *eventLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

// find returns the event of correlation id in this log, or nil.
func (l *eventLog) find(t *testing.T, id string) *hook.Event {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	e, err := hook.ReadEvent(bytes.NewReader(l.buf.Bytes()), id)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// catalogueCase is one row of the guard's negative-case catalogue as the evidence records it.
type catalogueCase struct {
	Case          string           `json:"case"`
	Status        int              `json:"status"`
	ReasonCode    string           `json:"reason_code"`
	RuleID        string           `json:"rule_id,omitempty"`
	OID4VPLink    string           `json:"oid4vp_link,omitempty"`
	CorrelationID string           `json:"correlation_id"`
	GuardEvent    *hook.Event      `json:"guard_event"`
	PolicyEvent   *hook.Event      `json:"policy_event,omitempty"`
	Forwarded     *json.RawMessage `json:"forwarded_request_id,omitempty"`
}

func TestGuardWithRealConnectorStorePolicyPostgresAndOpenBao(t *testing.T) {
	addr, token := os.Getenv("TRANSIT_TEST_ADDR"), os.Getenv("TRANSIT_TEST_TOKEN")
	if addr == "" || token == "" || os.Getenv(pgtest.DatabaseEnv) == "" {
		t.Skip("real Postgres/OpenBao inputs unavailable")
	}
	const issuer = "https://connector.guard.test"
	const aud = "https://resource.facis.invalid"
	const inbound = "https://guard.facis.invalid"
	const published = "https://resource.guard.test"
	const participantID = "spiffe://zone-b.test/ns/example/sa/ztd-participant"
	const guardPrincipal = "spiffe://zone-b.test/ns/example/sa/ztd-guard"
	const vpIssuer = "https://fixture.guard.test"
	const vpKid = "fixture-1"
	const oid4vpLink = "openid4vp://authorize?client_id=verifier.guard.test&request_uri=https%3A%2F%2Fverifier.guard.test%2Frequest"
	// Short enough that the expired-token case needs no forged token (the catalogue waits it out),
	// long enough that the store's renewer (every 15 s, at 75 % of the lifetime) keeps the
	// upstream route's token valid in between.
	const lifespan = 90 * time.Second
	fixtureKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := connectortest.Start(t, pgtest.MigratedURL(t, "guard_issuer"), addr, token, connectortest.Options{
		Issuer: issuer, VPIssuer: vpIssuer, VPKid: vpKid, VPKey: &fixtureKey.PublicKey, Audiences: []string{inbound, aud}, AccessTokenLifespan: lifespan,
		ScopeMap: []connectortest.Scope{{Role: "reader", Scopes: []string{"report:read"}}, {Role: "viewer", Scopes: []string{"report:summary"}}, {Role: "unrelated", Scopes: []string{"other:read"}}, {Role: "full", Scopes: []string{"report:full"}}},
	})
	bao, err := transit.New(transit.Config{Addr: addr, Token: func(context.Context) (string, error) { return token, nil }})
	if err != nil {
		t.Fatal(err)
	}
	prefix := "ztd/m3-test/" + acquiretest.RandHex(8)
	loaded := acquire.Loaded{SigningKey: "guard-store-" + acquiretest.RandHex(6), KVPrefix: prefix,
		Trusted: if03.Issuers{vpIssuer: {vpKid: &fixtureKey.PublicKey}}, Routes: map[string]acquire.Route{}}
	scopes := map[string]string{"report:read": "read", "report:summary": "summary"}
	for scope, tenant := range scopes {
		clientID, secret := c.Register(t, "store "+tenant, scope, aud)
		file := filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(file, []byte(secret), 0o600); err != nil {
			t.Fatal(err)
		}
		role := "reader"
		if tenant == "summary" {
			role = "viewer"
		}
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
	storeFront := guardTestProxy(t, "http://"+store.Addr().String(), guardPrincipal)
	// A participant the policy blocks by rule although its token is valid: the policy-only denial.
	blockedID, blockedSecret := c.Register(t, "participant blocked", "report:summary", inbound)
	guardEvents, policyEvents := &eventLog{}, &eventLog{}
	policy, err := policyevaluator.New(policyevaluator.Config{Revision: "integration-1", Audience: inbound, Host: "resource.guard.test", GuardCallers: []string{guardPrincipal}, ParticipantCallers: []string{participantID}, ScopeTenants: scopes,
		EventSource: "policy-b", BlockedClients: []string{blockedID}, Presentation: &policyevaluator.Presentation{Scopes: []string{"report:full"}, OID4VPLink: oid4vpLink}},
		hook.NewLogSinkV2(policyEvents, "policy-b", "catalogue"))
	if err != nil {
		t.Fatal(err)
	}
	policyServer := httptest.NewServer(policy)
	t.Cleanup(policyServer.Close)
	policyFront := guardTestProxy(t, policyServer.URL, guardPrincipal)
	runtime, err := guard.New(guard.Config{Issuer: issuer, JWKSURL: c.Base + "/.well-known/jwks.json", InboundAudience: inbound, UpstreamAudience: aud, PublishedBaseURL: published, PeerZone: "zone-b", PolicyURL: policyFront.URL, StoreURL: storeFront.URL, AllowedCallers: []string{participantID}, ScopeTenants: scopes, EventSource: "guard-b"},
		hook.NewLogSinkV2(guardEvents, "guard-b", "catalogue"))
	if err != nil {
		t.Fatal(err)
	}
	resource, err := tokenverify.New(tokenverify.Config{Issuer: issuer, JWKSURL: c.Base + "/.well-known/jwks.json", Audience: aud, PublicBaseURL: published, Replay: replay.NewMemory()})
	if err != nil {
		t.Fatal(err)
	}
	type participant struct {
		granted connectorclient.TokenResponse
		signer  guardTestKey
	}
	login := func(t *testing.T, id, secret, role string) participant {
		cc := &connectorclient.Client{BaseURL: c.Base, ClientID: id, ClientSecret: secret}
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
		if _, err := cc.Challenge(t.Context(), aud); err == nil {
			t.Fatal("Participant obtained a Resource-audience challenge")
		}
		return participant{granted, guardTestKey{key}}
	}
	request := func(t *testing.T, p participant, signer guardTestKey) hook.Request {
		proof, err := dpopproof.Build(t.Context(), signer, dpopproof.Claims{HTM: "POST", HTU: published + "/demo", ATH: connectorclient.ATH(p.granted.AccessToken)})
		if err != nil {
			t.Fatal(err)
		}
		header := http.Header{}
		header.Set("Authorization", "DPoP "+p.granted.AccessToken)
		header.Set("DPoP", proof)
		header.Set("X-Forwarded-Client-Cert", "URI="+participantID)
		return hook.Request{Method: "POST", Path: "/demo", Host: "resource.guard.test", Headers: header}
	}
	makeRequest := func(t *testing.T, p participant) hook.Request { return request(t, p, p.signer) }

	var last hook.Request
	var viewer participant
	for _, entry := range []struct{ role, scope string }{{"reader", "report:read"}, {"viewer", "report:summary"}} {
		t.Run(entry.role, func(t *testing.T) {
			id, secret := c.Register(t, "participant "+entry.role, entry.scope, inbound)
			p := login(t, id, secret, entry.role)
			// The very same valid proof/token must fail at the Resource before any
			// mesh control is involved, then succeed through the guard after substitution.
			req := makeRequest(t, p)
			direct, _ := http.NewRequest(http.MethodPost, published+"/demo", nil)
			direct.Header = req.Headers.Clone()
			if _, err := resource.Verify(direct); !errors.Is(err, tokenverify.ErrAudience) {
				t.Fatal("Resource did not reject Participant token for audience mismatch")
			}
			answer := runtime.Evaluate(t.Context(), req)
			if !answer.Allowed {
				t.Fatalf("guard refused: status=%d reason=%s", answer.Status, answer.ReasonCode)
			}
			forwarded, _ := http.NewRequest(http.MethodPost, published+"/demo", nil)
			for _, h := range answer.SetHeaders {
				forwarded.Header.Set(h.Name, h.Value)
			}
			verified, err := resource.Verify(forwarded)
			if err != nil {
				t.Fatal("resource refused substituted token/proof")
			}
			if !slices.Contains(verified.Scopes, entry.scope) || (entry.role == "viewer" && slices.Contains(verified.Scopes, "report:read")) {
				t.Fatal("substitution changed privilege")
			}
			if forwarded.Header.Get("Authorization") == req.Headers.Get("Authorization") {
				t.Fatal("token was not substituted")
			}
			fresh := makeRequest(t, p)
			if again := runtime.Evaluate(t.Context(), fresh); !again.Allowed {
				t.Fatalf("fresh proof refused: %d %s", again.Status, again.ReasonCode)
			}
			if entry.role == "viewer" {
				viewer = p
			}
			last = makeRequest(t, p)
		})
	}

	// The negative-case catalogue: each case's status, registry code and its own decision
	// event, found by the correlation id the caller received; for a case policy decided, the
	// policy's event under the same id.
	v2 := compileV2(t)
	var rows []catalogueCase
	record := func(t *testing.T, name string, out hook.Outcome, status int, code, rule string, policyDecided bool) catalogueCase {
		t.Helper()
		if out.Allowed || out.Status != status || out.ReasonCode != code || (rule != "" && out.RuleID != rule) {
			t.Fatalf("%s: got allowed=%v status=%d reason=%s rule=%s, want %d %s %s", name, out.Allowed, out.Status, out.ReasonCode, out.RuleID, status, code, rule)
		}
		row := catalogueCase{Case: name, Status: out.Status, ReasonCode: out.ReasonCode, RuleID: out.RuleID, CorrelationID: out.CorrelationID}
		var body hook.Refusal
		if json.Unmarshal(out.Body, &body) != nil || body.ReasonCode != code {
			t.Fatalf("%s: refusal body does not carry the reason code", name)
		}
		row.OID4VPLink = body.OID4VPLink
		row.GuardEvent = guardEvents.find(t, out.CorrelationID)
		if row.GuardEvent == nil || row.GuardEvent.Payload.State != "denied" || row.GuardEvent.Payload.ReasonCode != code || row.GuardEvent.Version != 2 {
			t.Fatalf("%s: no matching guard decision event: %+v", name, row.GuardEvent)
		}
		checkV2(t, v2, row.GuardEvent)
		row.PolicyEvent = policyEvents.find(t, out.CorrelationID)
		if policyDecided != (row.PolicyEvent != nil) {
			t.Fatalf("%s: policy event present=%v, want %v", name, row.PolicyEvent != nil, policyDecided)
		}
		if policyDecided {
			if row.PolicyEvent.Payload.RuleID != row.GuardEvent.Payload.RuleID || row.PolicyEvent.Payload.BundleRevision != "integration-1" || row.GuardEvent.Payload.BundleRevision != "integration-1" {
				t.Fatalf("%s: guard and policy events disagree on rule or revision", name)
			}
			checkV2(t, v2, row.PolicyEvent)
		} else if row.GuardEvent.Payload.BundleRevision != hook.NotEvaluated || row.GuardEvent.Payload.RuleID == "" {
			t.Fatalf("%s: a refusal before policy must record the bundle as not evaluated", name)
		}
		rows = append(rows, row)
		return row
	}
	t.Run("catalogue", func(t *testing.T) {
		// The allowed request first: one correlation id across guard, policy and the forwarded
		// request the resource logs (x-request-id).
		ok := runtime.Evaluate(t.Context(), makeRequest(t, viewer))
		var requestID string
		for _, h := range ok.SetHeaders {
			if h.Name == hook.HeaderRequestID {
				requestID = h.Value
			}
		}
		ge, pe := guardEvents.find(t, ok.CorrelationID), policyEvents.find(t, ok.CorrelationID)
		if !ok.Allowed || requestID != ok.CorrelationID || ge == nil || pe == nil || ge.Payload.State != "allowed" || pe.Payload.RuleID != "m3-report-summary" || ge.Payload.TokenSubject == hook.NotEvaluated {
			t.Fatalf("allowed request not traceable: %+v %+v %+v", ok, ge, pe)
		}
		checkV2(t, v2, ge)
		checkV2(t, v2, pe)
		forwardedID := json.RawMessage(strconv.Quote(requestID))
		rows = append(rows, catalogueCase{Case: "allowed (control)", Status: 200, CorrelationID: ok.CorrelationID, RuleID: ok.RuleID, GuardEvent: ge, PolicyEvent: pe, Forwarded: &forwardedID})

		noToken := makeRequest(t, viewer)
		noToken.Headers.Del("Authorization")
		noToken.Headers.Del("DPoP")
		record(t, "no token", runtime.Evaluate(t.Context(), noToken), 401, "TOK-MISSING", "", false)

		// TDR-BDD-05: an actual Keycloak viewer token is never machine authorization.
		// The local proof writes it mode 0600 outside the evidence tree, then deletes it.
		if path := os.Getenv("KEYCLOAK_GUARD_TOKEN_FILE"); path != "" {
			raw, err := os.ReadFile(path)
			if err != nil || len(raw) == 0 {
				t.Fatal("Keycloak viewer token file unavailable")
			}
			kc := makeRequest(t, viewer)
			kc.Headers.Set("Authorization", "DPoP "+string(raw))
			row := record(t, "Keycloak viewer token", runtime.Evaluate(t.Context(), kc), 401, "TOK-INVALID", "", false)
			if row.GuardEvent.Payload.Detail != "signature_invalid" {
				t.Fatal("Keycloak token refusal did not record the untrusted signing key")
			}
		}

		missing := makeRequest(t, viewer)
		missing.Headers.Del("DPoP")
		record(t, "missing proof", runtime.Evaluate(t.Context(), missing), 401, "TOK-PROOF-INVALID", "", false)

		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		record(t, "proof signed by the wrong key", runtime.Evaluate(t.Context(), request(t, viewer, guardTestKey{other})), 401, "TOK-JKT-MISMATCH", "", false)

		unrelatedID, unrelatedSecret := c.Register(t, "participant unrelated", "other:read", inbound)
		record(t, "insufficient scope", runtime.Evaluate(t.Context(), makeRequest(t, login(t, unrelatedID, unrelatedSecret, "unrelated"))), 403, hook.ReasonRuleDeny, policyevaluator.RuleScopeRequired, true)

		record(t, "policy-only denial", runtime.Evaluate(t.Context(), makeRequest(t, login(t, blockedID, blockedSecret, "viewer"))), 403, hook.ReasonRuleDeny, policyevaluator.RuleClientBlocked, true)

		fullID, fullSecret := c.Register(t, "participant full", "report:full", inbound)
		row := record(t, "presentation required", runtime.Evaluate(t.Context(), makeRequest(t, login(t, fullID, fullSecret, "full"))), 401, hook.ReasonPresentationRequired, policyevaluator.RulePresentationRequired, true)
		if row.OID4VPLink != oid4vpLink {
			t.Fatal("presentation denial without the OID4VP link")
		}

		// An upstream token at the guard: the wrong audience.
		upstream := http.Header{}
		for _, h := range ok.SetHeaders {
			upstream.Set(h.Name, h.Value)
		}
		upstream.Set("X-Forwarded-Client-Cert", "URI="+participantID)
		wrong := record(t, "wrong audience", runtime.Evaluate(t.Context(), hook.Request{Method: "POST", Path: "/demo", Host: "resource.guard.test", Headers: upstream}), 401, "TOK-INVALID", "", false)
		if wrong.GuardEvent.Payload.Detail != "audience_mismatch" {
			t.Fatal("wrong audience not distinguishable in the event detail")
		}

		replayed := makeRequest(t, viewer)
		if first := runtime.Evaluate(t.Context(), replayed); !first.Allowed {
			t.Fatalf("first use refused: %d %s", first.Status, first.ReasonCode)
		}
		record(t, "replayed proof", runtime.Evaluate(t.Context(), replayed), 401, "TOK-REPLAY", "", false)

		spoof := makeRequest(t, viewer)
		spoof.Headers.Set("X-Forwarded-Client-Cert", "URI=spiffe://wrong.test/ns/x/sa/y")
		record(t, "wrong mesh caller", runtime.Evaluate(t.Context(), spoof), 403, "MESH-PAIR-DENIED", "", false)

		policyFront.Close()
		record(t, "policy engine down", runtime.Evaluate(t.Context(), last), 503, hook.ReasonPDPUnavailable, "", false)

		storeFront.Close()
		record(t, "token store down", runtime.Evaluate(t.Context(), makeRequest(t, viewer)), 503, "TOK-STORE-UNAVAILABLE", "", false)

		// The token's lifetime plus the verifier's clock skew, then the same caller again.
		time.Sleep(lifespan + 31*time.Second)
		record(t, "expired token", runtime.Evaluate(t.Context(), makeRequest(t, viewer)), 401, "TOK-EXPIRED", "", false)

		seen := map[string]string{}
		for _, r := range rows[1:] {
			key := r.ReasonCode + "/" + r.RuleID + "/" + r.GuardEvent.Payload.Detail
			if prev, dup := seen[key]; dup {
				t.Fatalf("cases %q and %q are indistinguishable", prev, r.Case)
			}
			seen[key] = r.Case
		}
		if dir := os.Getenv("GUARD_CATALOGUE_OUT"); dir != "" {
			out, _ := json.MarshalIndent(rows, "", "  ")
			if err := os.WriteFile(filepath.Join(dir, "catalogue.json"), append(out, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	})
	// Cleanup only test-owned KV entries; no bearer material is emitted on failure.
	entries, err := bao.List(t.Context(), prefix)
	if err != nil {
		t.Fatal("test KV list failed")
	}
	for _, entry := range entries {
		if strings.Contains(entry, "/") {
			t.Fatal("unexpected nested test key")
		}
		if err := bao.Delete(t.Context(), prefix+"/"+entry); err != nil {
			t.Fatal("test KV cleanup failed")
		}
	}
}

func compileV2(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	sch, err := c.Compile(filepath.Join(contractpath.Contracts(t), "if01-event.v2.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	return sch
}

func checkV2(t *testing.T, sch *jsonschema.Schema, e *hook.Event) {
	t.Helper()
	raw, _ := json.Marshal(e)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(doc); err != nil {
		t.Fatalf("event does not validate against IF-01 v2: %v\n%s", err, raw)
	}
}
