package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider/memstore"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider/pgstore"
)

const vp = oauth2provider.VerifiedPresentationGrantType

// goodMetadata is a registration the policy accepts; each case below changes one thing.
func goodMetadata(change func(m map[string]any)) []byte {
	m := map[string]any{
		"client_name": "participant backend", "grant_types": []string{"client_credentials"},
		"token_endpoint_auth_method": "client_secret_basic", "scope": "resource.read",
		"dpop_bound_access_tokens": true, "audience": []string{"https://resource.example"},
	}
	if change != nil {
		change(m)
	}
	b, _ := json.Marshal(m)
	return b
}

func TestRegistrationPolicy(t *testing.T) {
	offered := []string{"client_credentials", vp}
	cases := []struct {
		name string
		body []byte
		rule string
	}{
		{"accepted", goodMetadata(nil), ""},
		{"verified-presentation client, as the test harness registers", goodMetadata(func(m map[string]any) {
			m["grant_types"] = []string{vp}
			m["scope"] = "resource.vp"
		}), ""},
		{"both grants", goodMetadata(func(m map[string]any) { m["grant_types"] = []string{"client_credentials", vp} }), ""},
		{"auth method absent", goodMetadata(func(m map[string]any) { delete(m, "token_endpoint_auth_method") }), ""},
		{"client_name of 128 two-byte characters", goodMetadata(func(m map[string]any) { m["client_name"] = strings.Repeat("é", maxClientName) }), ""},
		{"not JSON", []byte("client_name=x"), ruleBody},
		{"an array", []byte(`[{"client_name":"x"}]`), ruleBody},
		{"duplicate member", []byte(`{"client_name":"a","client_name":"b","grant_types":["client_credentials"],"scope":"s","dpop_bound_access_tokens":true,"audience":["https://r.example"]}`), ruleBody},
		{"data after the object", append(goodMetadata(nil), []byte(" {}")...), ruleBody},
		{"redirect_uris", goodMetadata(func(m map[string]any) { m["redirect_uris"] = []string{"https://x.example/cb"} }), ruleMembers},
		{"software_statement", goodMetadata(func(m map[string]any) { m["software_statement"] = "eyJ" }), ruleMembers},
		{"no client_name", goodMetadata(func(m map[string]any) { delete(m, "client_name") }), ruleClientName},
		{"blank client_name", goodMetadata(func(m map[string]any) { m["client_name"] = "   " }), ruleClientName},
		{"client_name with a control character", goodMetadata(func(m map[string]any) { m["client_name"] = "a\x01b" }), ruleClientName},
		{"client_name with a line break around it", goodMetadata(func(m map[string]any) { m["client_name"] = "\nname\n" }), ruleClientName},
		{"client_name padded with spaces", goodMetadata(func(m map[string]any) { m["client_name"] = "name" + strings.Repeat(" ", 5000) }), ruleClientName},
		{"client_name of 129 characters", goodMetadata(func(m map[string]any) { m["client_name"] = strings.Repeat("é", maxClientName+1) }), ruleClientName},
		{"client_name not a string", goodMetadata(func(m map[string]any) { m["client_name"] = 7 }), ruleClientName},
		{"public client", goodMetadata(func(m map[string]any) { m["token_endpoint_auth_method"] = "none" }), ruleAuthMethod},
		{"post auth method", goodMetadata(func(m map[string]any) { m["token_endpoint_auth_method"] = "client_secret_post" }), ruleAuthMethod},
		{"no DPoP binding", goodMetadata(func(m map[string]any) { m["dpop_bound_access_tokens"] = false }), ruleDPoPBound},
		{"DPoP binding absent", goodMetadata(func(m map[string]any) { delete(m, "dpop_bound_access_tokens") }), ruleDPoPBound},
		{"DPoP binding as a string", goodMetadata(func(m map[string]any) { m["dpop_bound_access_tokens"] = "true" }), ruleDPoPBound},
		{"no grant_types", goodMetadata(func(m map[string]any) { delete(m, "grant_types") }), ruleGrantTypes},
		{"empty grant_types", goodMetadata(func(m map[string]any) { m["grant_types"] = []string{} }), ruleGrantTypes},
		{"password grant", goodMetadata(func(m map[string]any) { m["grant_types"] = []string{"password"} }), ruleGrantTypes},
		{"repeated grant", goodMetadata(func(m map[string]any) { m["grant_types"] = []string{"client_credentials", "client_credentials"} }), ruleGrantTypes},
		{"no scope", goodMetadata(func(m map[string]any) { delete(m, "scope") }), ruleScope},
		{"empty scope", goodMetadata(func(m map[string]any) { m["scope"] = "" }), ruleScope},
		{"scope of one space", goodMetadata(func(m map[string]any) { m["scope"] = " " }), ruleScope},
		{"scope of one tab", goodMetadata(func(m map[string]any) { m["scope"] = "\t" }), ruleScope},
		{"scopes separated by a tab", goodMetadata(func(m map[string]any) { m["scope"] = "a\ta" }), ruleScope},
		{"scope with a line break", goodMetadata(func(m map[string]any) { m["scope"] = "a\n" }), ruleScope},
		{"scope with a non-breaking space", goodMetadata(func(m map[string]any) { m["scope"] = "a\u00a0b" }), ruleScope},
		{"scope with a quote", goodMetadata(func(m map[string]any) { m["scope"] = `a"b` }), ruleScope},
		{"double space in scope", goodMetadata(func(m map[string]any) { m["scope"] = "a  b" }), ruleScope},
		{"repeated scope", goodMetadata(func(m map[string]any) { m["scope"] = "a a" }), ruleScope},
		{"the registration scope", goodMetadata(func(m map[string]any) { m["scope"] = "a connector:client_registration" }), ruleScope},
		{"no audience", goodMetadata(func(m map[string]any) { delete(m, "audience") }), ruleAudience},
		{"empty audience", goodMetadata(func(m map[string]any) { m["audience"] = []string{} }), ruleAudience},
		{"relative audience", goodMetadata(func(m map[string]any) { m["audience"] = []string{"/api"} }), ruleAudience},
		{"audience with userinfo", goodMetadata(func(m map[string]any) { m["audience"] = []string{"https://u@r.example"} }), ruleAudience},
		{"audience with a fragment", goodMetadata(func(m map[string]any) { m["audience"] = []string{"https://r.example/#x"} }), ruleAudience},
		{"audience with a query", goodMetadata(func(m map[string]any) { m["audience"] = []string{"https://r.example/?x=1"} }), ruleAudience},
		{"audience with an empty query", goodMetadata(func(m map[string]any) { m["audience"] = []string{"https://r.example/?"} }), ruleAudience},
		{"repeated audience", goodMetadata(func(m map[string]any) { m["audience"] = []string{"https://r.example", "https://r.example"} }), ruleAudience},
		{"audience as a string", goodMetadata(func(m map[string]any) { m["audience"] = "https://r.example" }), ruleAudience},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := registrationPolicy(tc.body, offered); got != tc.rule {
				t.Errorf("rule %q, want %q", got, tc.rule)
			}
		})
	}
	// A grant the deployment does not offer in registration.
	if got, _ := registrationPolicy(goodMetadata(func(m map[string]any) { m["grant_types"] = []string{vp} }), []string{"client_credentials"}); got != ruleGrantTypes {
		t.Errorf("grant not offered: rule %q, want %q", got, ruleGrantTypes)
	}
	// The name comes back for the audit detail once it is valid, whatever rule fails later.
	if _, name := registrationPolicy(goodMetadata(func(m map[string]any) { m["scope"] = "" }), offered); name != "participant backend" {
		t.Errorf("client name %q", name)
	}
	if _, name := registrationPolicy(goodMetadata(func(m map[string]any) { m["client_name"] = "\nx" }), offered); name != "" {
		t.Errorf("an invalid client name came back: %q", name)
	}
	for rule, text := range ruleText {
		if text == "" || !strings.HasSuffix(text, ".") {
			t.Errorf("rule %s has no description", rule)
		}
	}
}

func TestRegistryCode(t *testing.T) {
	cases := []struct {
		reason string
		status int
		auth   bool
		want   string
	}{
		{"registration_rejected", 400, true, "TOK-REGISTRATION-REJECTED"},
		{"invalid_token", 401, true, "TOK-INVALID"},
		{"invalid_token", 401, false, "TOK-MISSING"},
		{"insufficient_scope", 403, true, "TOK-SCOPE"},
		{"invalid_client", 401, true, "TOK-CLIENT-INVALID"},
		{"invalid_request", 400, true, "TOK-REQUEST-INVALID"},
		{"server_error", 500, true, "TOK-SERVER-ERROR"},
		{"dpop_invalid_proof", 401, true, "TOK-PROOF-INVALID"},
		{"dpop_replayed", 401, true, "TOK-REPLAY"},
		{"dpop_use_nonce", 401, true, "TOK-NONCE"},
		{"dpop_jkt_mismatch", 401, true, "TOK-JKT-MISMATCH"},
		{"dpop_invalid_ath", 401, true, "TOK-ATH-MISMATCH"},
		{"", 400, true, "TOK-REQUEST-INVALID"},
		{"something_new", 503, true, "TOK-SERVER-ERROR"},
	}
	for _, tc := range cases {
		if got := registryCode(tc.reason, tc.status, tc.auth); got != tc.want {
			t.Errorf("%q/%d/%v: %s, want %s", tc.reason, tc.status, tc.auth, got, tc.want)
		}
	}
}

func TestTokenSignature(t *testing.T) {
	cases := map[string]string{
		"DPoP connector_at_abc.SIG":           "SIG",
		"Bearer connector_at_abc.SIG":         "SIG",
		"dpop header.payload.SIGNATURE":       "SIGNATURE",
		"DPoP  spaced.token ":                 "token",
		"Basic dXNlcjpwYXNz":                  "",
		"DPoP one-part":                       "",
		"DPoP a.b.c.d":                        "",
		"DPoP with space.in it":               "",
		"":                                    "",
		"DPoP a." + strings.Repeat("b", 8000): strings.Repeat("b", 8000), // no bound of its own, as the library
	}
	for header, want := range cases {
		if got := tokenSignature(header); got != want {
			t.Errorf("%q: %q, want %q", header, got, want)
		}
	}
}

// auditLog records what the gate audits.
type auditLog struct {
	mu     sync.Mutex
	events []pgstore.AuditEvent
	fail   bool
}

func (a *auditLog) record(_ context.Context, e pgstore.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return context.DeadlineExceeded
	}
	a.events = append(a.events, e)
	return nil
}

func (a *auditLog) kinds() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, e := range a.events {
		out = append(out, e.Kind)
	}
	return out
}

// libraryStub stands in for the library's handler: it registers the client in the stores it was
// given, through the request's context (the gate's transaction), or answers a scripted refusal.
func libraryStub(stores oauth2provider.Stores, refusal func(w http.ResponseWriter) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if refusal != nil && refusal(w) {
			return
		}
		body, _ := json.Marshal(map[string]any{"client_name": "x", "scope": "resource.read"})
		client := oauth2provider.Client{ID: "new-client", SecretHash: []byte("hash"), GrantTypes: []string{"client_credentials"},
			Scopes: []string{"resource.read"}, Audience: []string{"https://resource.example"}, DPoPBound: true, Metadata: body}
		if err := stores.Clients.CreateClient(r.Context(), client); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Length", "999") // must not be relayed
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"client_id":"new-client","client_secret":"the-secret","registration_access_token":"the-rat"}`))
	})
}

// refusing answers like the library refusing for reason, with a challenge header.
func refusing(status int, reason string) func(http.ResponseWriter) bool {
	return func(w http.ResponseWriter) bool {
		w.Header().Set("WWW-Authenticate", `DPoP error="`+reason+`"`)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":"` + reason + `","reason":"` + reason + `"}`))
		return true
	}
}

// registrarAuth is the Authorization of a request carrying the registrar's token, which newGate
// puts in the store under the signature "sig".
var registrarAuth = []string{"Authorization", "DPoP a.b.sig"}

func newGate(t *testing.T, stores oauth2provider.Stores, next http.Handler, audit *auditLog, events *bytes.Buffer) (*registrationGate, *syncBuffer) {
	t.Helper()
	for sig, rec := range map[string]oauth2provider.TokenRecord{
		"sig":      {ClientID: "ztd-registrar", GrantedScopes: []string{oauth2provider.RegistrationScope}, ExpiresAt: time.Now().Add(time.Minute)},
		"expired":  {ClientID: "ztd-registrar", GrantedScopes: []string{oauth2provider.RegistrationScope}, ExpiresAt: time.Now().Add(-time.Second)},
		"unscoped": {ClientID: "participant", GrantedScopes: []string{"resource.read"}, ExpiresAt: time.Now().Add(time.Minute)},
	} {
		if err := stores.AccessTokens.CreateToken(context.Background(), sig, rec); err != nil {
			t.Fatal(err)
		}
	}
	var logs syncBuffer
	return &registrationGate{
		next: next, stores: stores, offered: []string{"client_credentials", vp},
		log:    slog.New(stampHandler{slog.NewJSONHandler(&logs, nil)}),
		events: newEventSink(events, "b"),
		audit:  audit.record,
		slots:  make(chan struct{}, maxConcurrentRegistrations),
	}, &logs
}

func post(t *testing.T, h http.Handler, body []byte, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	req = req.WithContext(context.WithValue(req.Context(), correlationKey{}, "corr-1"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func detailOf(t *testing.T, e pgstore.AuditEvent) string {
	t.Helper()
	b, _ := json.Marshal(e.Detail)
	return string(b)
}

// An accepted registration: the library's 201 is relayed (headers but the length), the client and
// its audit row are committed together, one IF-01 registered event follows.
func TestGateRelaysAnAcceptedRegistration(t *testing.T) {
	stores := memstore.New(time.Now)
	audit := &auditLog{}
	var events bytes.Buffer
	g, logs := newGate(t, stores, libraryStub(stores, nil), audit, &events)

	rec := post(t, g, goodMetadata(nil), registrarAuth...)
	if rec.Code != http.StatusCreated || rec.Header().Get("Content-Length") != strconv.Itoa(rec.Body.Len()) || rec.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(rec.Body.String(), `"client_secret":"the-secret"`) {
		t.Fatalf("relayed answer: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	if _, err := stores.Clients.GetClient(context.Background(), "new-client"); err != nil {
		t.Errorf("the client was not committed: %v", err)
	}
	if kinds := audit.kinds(); len(kinds) != 1 || kinds[0] != "registration.accepted" {
		t.Fatalf("audit %v", kinds)
	}
	e := audit.events[0]
	detail := detailOf(t, e)
	if e.ClientID != "new-client" || e.CorrelationID != "corr-1" || e.ReasonCode != "" ||
		!strings.Contains(detail, `"client_name":"participant backend"`) || !strings.Contains(detail, `"dpop_bound":true`) ||
		!strings.Contains(detail, `"registrar":"ztd-registrar"`) {
		t.Errorf("accepted row: %+v %s", e, detail)
	}
	if strings.Contains(detail, "the-secret") || strings.Contains(detail, "the-rat") {
		t.Errorf("a secret reached the audit detail")
	}
	if ev := events.String(); !strings.Contains(ev, `"kind":"token_event"`) || !strings.Contains(ev, `"state":"registered"`) ||
		!strings.Contains(ev, `"detail":"client_id=new-client"`) || !strings.Contains(ev, `"correlation_id":"corr-1"`) {
		t.Errorf("event: %s", ev)
	}
	if l := logs.String(); strings.Contains(l, "the-secret") || strings.Contains(l, "the-rat") || !strings.Contains(l, `"outcome":"accepted"`) {
		t.Errorf("records: %s", l)
	}
	if len(g.slots) != 0 {
		t.Errorf("a registration slot was not given back")
	}
}

// A policy violation from a known token is refused before the library runs: no client, the
// library's shape, a refused audit row naming the rule and the registrar, one IF-01 refused event
// with the rule and the registry code, and the answer out before the row is written.
func TestGateRefusesAPolicyViolationBeforeTheLibrary(t *testing.T) {
	stores := memstore.New(time.Now)
	var events bytes.Buffer
	called := false
	var flushedFirst bool
	var rec *httptest.ResponseRecorder
	audit := &auditLog{}
	g, _ := newGate(t, stores, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }), audit, &events)
	g.audit = func(ctx context.Context, e pgstore.AuditEvent) error {
		flushedFirst = rec.Flushed
		return audit.record(ctx, e)
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader(goodMetadata(func(m map[string]any) { m["dpop_bound_access_tokens"] = false })))
	req.Header.Set(registrarAuth[0], registrarAuth[1])
	req = req.WithContext(context.WithValue(req.Context(), correlationKey{}, "corr-1"))
	rec = httptest.NewRecorder()
	g.ServeHTTP(rec, req)

	if called {
		t.Fatal("the library ran for a request the policy refused")
	}
	var answer map[string]string
	if rec.Code != http.StatusBadRequest || json.Unmarshal(rec.Body.Bytes(), &answer) != nil ||
		answer["error"] != "invalid_client_metadata" || answer["reason"] != "registration_rejected" || answer["error_description"] != ruleText[ruleDPoPBound] ||
		rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" ||
		rec.Header().Get("Content-Length") != strconv.Itoa(rec.Body.Len()) {
		t.Fatalf("refusal: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	if !flushedFirst {
		t.Error("the audit row was written before the answer left")
	}
	if kinds := audit.kinds(); len(kinds) != 1 || kinds[0] != "registration.refused" {
		t.Fatalf("audit %v", kinds)
	}
	e := audit.events[0]
	detail := detailOf(t, e)
	if e.ReasonCode != "TOK-REGISTRATION-REJECTED" || e.CorrelationID != "corr-1" || e.ClientID != "ztd-registrar" ||
		!strings.Contains(detail, `"rule":"`+ruleDPoPBound+`"`) || !strings.Contains(detail, `"client_name":"participant backend"`) {
		t.Errorf("refused row: %+v %s", e, detail)
	}
	if ev := events.String(); !strings.Contains(ev, `"state":"refused"`) || !strings.Contains(ev, `"reason_code":"TOK-REGISTRATION-REJECTED"`) ||
		!strings.Contains(ev, `"rule_id":"`+ruleDPoPBound+`"`) {
		t.Errorf("event: %s", ev)
	}

	// Over the body bound, and exactly at it: refused for size, then judged on its content.
	big := post(t, g, bytes.Repeat([]byte("x"), maxRegistrationBody+1), registrarAuth...)
	if big.Code != http.StatusBadRequest || !strings.Contains(big.Body.String(), ruleText[ruleBodySize]) {
		t.Errorf("oversized body: %d %s", big.Code, big.Body.String())
	}
	if last := audit.events[len(audit.events)-1]; !strings.Contains(detailOf(t, last), `"rule":"`+ruleBodySize+`"`) {
		t.Errorf("oversized row: %s", detailOf(t, last))
	}
	atBound := post(t, g, bytes.Repeat([]byte("x"), maxRegistrationBody), registrarAuth...)
	if !strings.Contains(atBound.Body.String(), ruleText[ruleBody]) {
		t.Errorf("a body at the bound was refused for its size: %s", atBound.Body.String())
	}
	// A refusal whose row cannot be written is still answered.
	audit.fail = true
	if again := post(t, g, goodMetadata(func(m map[string]any) { m["scope"] = "" }), registrarAuth...); again.Code != http.StatusBadRequest {
		t.Errorf("a refusal without its audit row: %d", again.Code)
	}
}

// A request whose token the store does not know goes to the library unjudged, outside any
// transaction: the library's refusal is relayed and audited; the policy gives no verdict.
func TestGateLeavesUnauthenticatedRequestsToTheLibrary(t *testing.T) {
	stores := memstore.New(time.Now)
	audit := &auditLog{}
	var events bytes.Buffer
	var sawTx bool
	g, _ := newGate(t, stores, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A nested BeginTx fails inside a transaction; outside one it opens one, closed at once.
		if txCtx, err := stores.Transactions.BeginTx(r.Context()); err != nil {
			sawTx = true
		} else {
			_ = stores.Transactions.Rollback(txCtx)
		}
		refusing(http.StatusUnauthorized, "invalid_token")(w)
	}), audit, &events)
	violating := goodMetadata(func(m map[string]any) { m["dpop_bound_access_tokens"] = false })
	// No token, an unknown one, a token without the registration scope.
	for _, auth := range [][]string{nil, {"Authorization", "Bearer connector_at_forged.unknown"}, {"Authorization", "DPoP a.unscoped"}} {
		rec := post(t, g, violating, auth...)
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" || !strings.Contains(rec.Body.String(), `"reason":"invalid_token"`) {
			t.Fatalf("%v: relayed refusal: %d %v %s", auth, rec.Code, rec.Header(), rec.Body.String())
		}
	}
	if sawTx {
		t.Error("an unauthenticated request ran inside a transaction")
	}
	if len(audit.events) != 3 || audit.events[0].ReasonCode != "TOK-MISSING" || audit.events[1].ReasonCode != "TOK-INVALID" {
		t.Errorf("audit: %+v", audit.events)
	}
	for _, e := range audit.events {
		if e.ClientID != "" || strings.Contains(detailOf(t, e), ruleDPoPBound) {
			t.Errorf("an unjudged request was attributed or judged: %+v", e)
		}
	}
	if strings.Contains(events.String(), "registration_rejected") || strings.Contains(events.String(), "TOK-REGISTRATION-REJECTED") {
		t.Errorf("the policy judged an unauthenticated request: %s", events.String())
	}
}

// A registrar token past its stored expiry is still judged: the library's clock may hold it valid
// a little longer (to the end of a signed token's exp second), so leaving it unjudged could let
// the library register what the policy never saw. The library refuses it if it has expired.
func TestGateJudgesAnExpiredRegistrarToken(t *testing.T) {
	stores := memstore.New(time.Now)
	audit := &auditLog{}
	called := false
	g, _ := newGate(t, stores, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }), audit, &bytes.Buffer{})
	rec := post(t, g, goodMetadata(func(m map[string]any) { m["dpop_bound_access_tokens"] = false }), "Authorization", "DPoP a.expired")
	if called || rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), ruleText[ruleDPoPBound]) ||
		len(audit.events) != 1 || audit.events[0].ClientID != "ztd-registrar" {
		t.Errorf("an expired registrar token went unjudged: called %v, %d %s %+v", called, rec.Code, rec.Body.String(), audit.events)
	}
}

// The library's refusal of an authenticated request is relayed unchanged and audited with its
// reason mapped and the registrar named; the nonce handshake is relayed and not audited.
func TestGateRelaysAndAuditsTheLibrarysRefusal(t *testing.T) {
	stores := memstore.New(time.Now)
	audit := &auditLog{}
	var events bytes.Buffer
	g, _ := newGate(t, stores, libraryStub(stores, refusing(http.StatusForbidden, "insufficient_scope")), audit, &events)
	rec := post(t, g, goodMetadata(nil), registrarAuth...)
	if rec.Code != http.StatusForbidden || rec.Header().Get("WWW-Authenticate") == "" || !strings.Contains(rec.Body.String(), `"reason":"insufficient_scope"`) {
		t.Fatalf("relayed refusal: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	if len(audit.events) != 1 || audit.events[0].ReasonCode != "TOK-SCOPE" || audit.events[0].ClientID != "ztd-registrar" ||
		!strings.Contains(detailOf(t, audit.events[0]), `"rule":"`+ruleLibrary+`"`) {
		t.Errorf("audit: %+v", audit.events)
	}
	if _, err := stores.Clients.GetClient(context.Background(), "new-client"); err == nil {
		t.Error("a refused registration left a client")
	}
	if len(g.slots) != 0 {
		t.Error("a registration slot was not given back")
	}

	// The library's ceiling: a registration beyond the registrar's token.
	g, _ = newGate(t, stores, libraryStub(stores, refusing(http.StatusBadRequest, "registration_rejected")), audit, &events)
	if rec = post(t, g, goodMetadata(nil), registrarAuth...); rec.Code != http.StatusBadRequest || audit.events[1].ReasonCode != "TOK-REGISTRATION-REJECTED" {
		t.Errorf("ceiling refusal: %d %+v", rec.Code, audit.events)
	}

	g, _ = newGate(t, stores, libraryStub(stores, refusing(http.StatusUnauthorized, "dpop_use_nonce")), audit, &events)
	rec = post(t, g, goodMetadata(nil), registrarAuth...)
	if rec.Code != http.StatusUnauthorized || len(audit.events) != 2 {
		t.Errorf("the nonce handshake was audited: %d %+v", rec.Code, audit.events)
	}
	if strings.Count(events.String(), "\n") != 2 {
		t.Errorf("events: %s", events.String())
	}
}

// When the accepted row cannot be written, the registration is rolled back and the caller gets no
// credential: a 500 in the error shape, nothing in the store, no registered event.
func TestGateRollsBackWhenTheAuditRowFails(t *testing.T) {
	stores := memstore.New(time.Now)
	audit := &auditLog{fail: true}
	var events bytes.Buffer
	g, _ := newGate(t, stores, libraryStub(stores, nil), audit, &events)
	rec := post(t, g, goodMetadata(nil), registrarAuth...)
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "the-secret") || !strings.Contains(rec.Body.String(), `"reason":"server_error"`) {
		t.Fatalf("answer: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := stores.Clients.GetClient(context.Background(), "new-client"); err == nil {
		t.Error("the client survived a failed audit write")
	}
	if strings.Contains(events.String(), `"registered"`) {
		t.Errorf("a registered event followed a rollback: %s", events.String())
	}
}

// failingCommit commits, then reports failure: the outcome a lost acknowledgement leaves.
type failingCommit struct{ oauth2provider.Transactor }

func (f failingCommit) Commit(ctx context.Context) error {
	_ = f.Transactor.Commit(ctx)
	return errors.New("connection lost during commit")
}

// failingLookup cannot answer a token lookup.
type failingLookup struct{ oauth2provider.TokenStore }

func (failingLookup) GetToken(context.Context, string) (oauth2provider.TokenRecord, error) {
	return oauth2provider.TokenRecord{}, errors.New("database unreachable")
}

// The connector's own failures: each answers 500 without a credential and is audited.
func TestGateFailures(t *testing.T) {
	t.Run("the 201 names no client", func(t *testing.T) {
		stores := memstore.New(time.Now)
		audit := &auditLog{}
		g, _ := newGate(t, stores, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"client_secret":"the-secret"}`))
		}), audit, &bytes.Buffer{})
		rec := post(t, g, goodMetadata(nil), registrarAuth...)
		if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "the-secret") ||
			len(audit.events) != 1 || !strings.Contains(detailOf(t, audit.events[0]), `"rule":"`+ruleStored+`"`) {
			t.Errorf("%d %s %+v", rec.Code, rec.Body.String(), audit.events)
		}
	})
	t.Run("the commit outcome is unknown", func(t *testing.T) {
		stores := memstore.New(time.Now)
		stores.Transactions = failingCommit{stores.Transactions}
		audit := &auditLog{}
		var events bytes.Buffer
		g, _ := newGate(t, stores, libraryStub(stores, nil), audit, &events)
		rec := post(t, g, goodMetadata(nil), registrarAuth...)
		if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "the-secret") {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		kinds := audit.kinds()
		if len(kinds) != 2 || kinds[0] != "registration.accepted" || kinds[1] != "registration.uncertain" || audit.events[1].ClientID != "new-client" {
			t.Errorf("audit %v %+v", kinds, audit.events)
		}
		if ev := events.String(); !strings.Contains(ev, `"state":"uncertain"`) || strings.Contains(ev, `"state":"refused"`) {
			t.Errorf("events: %s", ev)
		}
	})
	t.Run("the library accepts an unknown token", func(t *testing.T) {
		stores := memstore.New(time.Now)
		audit := &auditLog{}
		g, _ := newGate(t, stores, libraryStub(stores, nil), audit, &bytes.Buffer{})
		rec := post(t, g, goodMetadata(nil), "Authorization", "Bearer unknown.token")
		if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "the-secret") ||
			len(audit.events) != 1 || audit.events[0].Kind != "registration.uncertain" {
			t.Errorf("%d %s %+v", rec.Code, rec.Body.String(), audit.events)
		}
	})
	t.Run("the token lookup fails", func(t *testing.T) {
		stores := memstore.New(time.Now)
		audit := &auditLog{}
		g, _ := newGate(t, stores, libraryStub(stores, nil), audit, &bytes.Buffer{})
		g.stores.AccessTokens = failingLookup{stores.AccessTokens}
		rec := post(t, g, goodMetadata(nil), registrarAuth...)
		if rec.Code != http.StatusInternalServerError || len(audit.events) != 1 || !strings.Contains(detailOf(t, audit.events[0]), `"rule":"`+ruleLookup+`"`) {
			t.Errorf("%d %+v", rec.Code, audit.events)
		}
	})
	t.Run("no registration slot within the deadline", func(t *testing.T) {
		stores := memstore.New(time.Now)
		audit := &auditLog{}
		g, _ := newGate(t, stores, libraryStub(stores, nil), audit, &bytes.Buffer{})
		for range maxConcurrentRegistrations {
			g.slots <- struct{}{}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		req := httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader(goodMetadata(nil))).WithContext(ctx)
		req.Header.Set(registrarAuth[0], registrarAuth[1])
		rec := httptest.NewRecorder()
		g.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError || len(audit.events) != 1 || !strings.Contains(detailOf(t, audit.events[0]), `"rule":"`+ruleBusy+`"`) {
			t.Errorf("%d %+v", rec.Code, audit.events)
		}
		if _, err := stores.Clients.GetClient(context.Background(), "new-client"); err == nil {
			t.Error("a registration ran without a slot")
		}
	})
	t.Run("the body cannot be read", func(t *testing.T) {
		stores := memstore.New(time.Now)
		audit := &auditLog{}
		g, _ := newGate(t, stores, libraryStub(stores, nil), audit, &bytes.Buffer{})
		req := httptest.NewRequest(http.MethodPost, "/oauth2/register", iotest.ErrReader(errors.New("client gone")))
		req.Header.Set(registrarAuth[0], registrarAuth[1])
		rec := httptest.NewRecorder()
		g.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"reason":"invalid_request"`) || len(audit.events) != 1 ||
			audit.events[0].ReasonCode != "TOK-REQUEST-INVALID" || !strings.Contains(detailOf(t, audit.events[0]), `"rule":"`+ruleRead+`"`) {
			t.Errorf("%d %s %+v", rec.Code, rec.Body.String(), audit.events)
		}
	})
}

// memstore undoes a client creation on rollback, restoring a client it overwrote.
func TestMemstoreRollbackRestoresAnOverwrittenClient(t *testing.T) {
	stores := memstore.New(time.Now)
	ctx := context.Background()
	original := oauth2provider.Client{ID: "c", Scopes: []string{"original"}}
	if err := stores.Clients.CreateClient(ctx, original); err != nil {
		t.Fatal(err)
	}
	txCtx, err := stores.Transactions.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = stores.Clients.CreateClient(txCtx, oauth2provider.Client{ID: "c", Scopes: []string{"overwritten"}})
	_ = stores.Clients.CreateClient(txCtx, oauth2provider.Client{ID: "new"})
	if err := stores.Transactions.Rollback(txCtx); err != nil {
		t.Fatal(err)
	}
	if got, err := stores.Clients.GetClient(ctx, "c"); err != nil || len(got.Scopes) != 1 || got.Scopes[0] != "original" {
		t.Errorf("after rollback: %+v %v", got, err)
	}
	if _, err := stores.Clients.GetClient(ctx, "new"); err == nil {
		t.Error("a rolled-back creation survived")
	}
}

// Through a real server and the request middleware, a refusal reaches the caller complete while its
// audit row is still being written.
func TestGateAnswersBeforeTheAuditRow(t *testing.T) {
	stores := memstore.New(time.Now)
	audit := &auditLog{}
	g, _ := newGate(t, stores, libraryStub(stores, nil), audit, &bytes.Buffer{})
	release := make(chan struct{})
	g.audit = func(ctx context.Context, e pgstore.AuditEvent) error {
		<-release
		return audit.record(ctx, e)
	}
	s := &server{log: slog.New(slog.NewJSONHandler(io.Discard, nil))}
	srv := httptest.NewServer(s.correlate(bounded(g)))
	defer srv.Close()
	defer close(release)

	req, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(goodMetadata(func(m map[string]any) { m["scope"] = "" })))
	req.Header.Set(registrarAuth[0], registrarAuth[1])
	done := make(chan string, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- err.Error()
			return
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		done <- string(body)
	}()
	select {
	case body := <-done:
		if !strings.Contains(body, ruleText[ruleScope]) {
			t.Errorf("answer: %s", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the refusal did not reach the caller before its audit row was written")
	}
}
