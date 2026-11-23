package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider/pgstore"
)

// maxRegistrationBody bounds a registration request; client metadata is a few hundred bytes.
const maxRegistrationBody = 64 << 10

// auditTimeout bounds the audit row of a refusal, written after the answer, outside any transaction.
const auditTimeout = 2 * time.Second

// The registration policy: what this connector requires of client metadata beyond the library's
// ceiling (a registration cannot exceed the registrar's token in scope, audience and grant types).
// The library leaves open what these rules close: a client without a secret, without a name,
// without DPoP binding, with members outside IF-02, or in a lenient document. The rules judge the
// raw values the library stores, never a cleaned copy of them. Each rule has one fixed description;
// a refusal carries it in the library's own shape, 400 invalid_client_metadata with the reason
// registration_rejected, so a client sees one shape whoever refused.
const (
	ruleBodySize   = "dcr.body_size"
	ruleBody       = "dcr.body"
	ruleMembers    = "dcr.members"
	ruleClientName = "dcr.client_name"
	ruleAuthMethod = "dcr.auth_method"
	ruleDPoPBound  = "dcr.dpop_bound"
	ruleGrantTypes = "dcr.grant_types"
	ruleScope      = "dcr.scope"
	ruleAudience   = "dcr.audience"
	// The audit names of the outcomes that are not policy rules: a refusal the library made, a body
	// that could not be read, and the connector's own failures (the token lookup, a registration
	// slot, the transaction, the stored client, the audit row). A failed commit is uncertain, not
	// refused.
	ruleLibrary = "library"
	ruleRead    = "read"
	ruleLookup  = "lookup"
	ruleBusy    = "busy"
	ruleBegin   = "begin"
	ruleStored  = "stored"
	ruleAudit   = "audit"
)

var ruleText = map[string]string{
	ruleBodySize:   "The client metadata is larger than 64 KiB.",
	ruleBody:       "The client metadata must be one JSON object without duplicate members.",
	ruleMembers:    "The client metadata may contain only client_name, grant_types, token_endpoint_auth_method, scope, dpop_bound_access_tokens and audience.",
	ruleClientName: "client_name is required: 1 to 128 printable characters, without leading or trailing spaces.",
	ruleAuthMethod: "token_endpoint_auth_method must be client_secret_basic.",
	ruleDPoPBound:  "dpop_bound_access_tokens must be true: this connector issues DPoP-bound tokens only.",
	ruleGrantTypes: "grant_types is required: client_credentials and/or the verified-presentation grant, each once.",
	ruleScope:      "scope is required: one or more distinct scope tokens separated by single spaces, never connector:client_registration.",
	ruleAudience:   "audience is required: one or more distinct absolute http(s) URLs without credentials, query or fragment.",
}

var allowedMembers = map[string]bool{"client_name": true, "grant_types": true, "token_endpoint_auth_method": true,
	"scope": true, "dpop_bound_access_tokens": true, "audience": true}

var knownGrantTypes = []string{"client_credentials", oauth2provider.VerifiedPresentationGrantType}

// maxClientName bounds client_name, in characters.
const maxClientName = 128

// registrationPolicy applies the rules to a registration request's body and names the first rule
// it breaks, or nothing, with the client_name when that one is valid (for the audit detail).
// offered are the grant types the deployment admits in registration.
func registrationPolicy(body []byte, offered []string) (rule, clientName string) {
	members, err := jose.ParseObject(body)
	if err != nil {
		return ruleBody, ""
	}
	for name := range members {
		if !allowedMembers[name] {
			return ruleMembers, ""
		}
	}
	name, present, ok := jose.String(members, "client_name")
	if !present || !ok || !validClientName(name) {
		return ruleClientName, ""
	}
	if _, present := members["token_endpoint_auth_method"]; present {
		if method, _, ok := jose.String(members, "token_endpoint_auth_method"); !ok || method != "client_secret_basic" {
			return ruleAuthMethod, name
		}
	}
	if raw, present := members["dpop_bound_access_tokens"]; !present || string(bytes.TrimSpace(raw)) != "true" {
		return ruleDPoPBound, name
	}
	var grants []string
	if raw, present := members["grant_types"]; !present || json.Unmarshal(raw, &grants) != nil || len(grants) == 0 || !distinct(grants) {
		return ruleGrantTypes, name
	}
	for _, g := range grants {
		if !slices.Contains(knownGrantTypes, g) || !slices.Contains(offered, g) {
			return ruleGrantTypes, name
		}
	}
	scope, present, ok := jose.String(members, "scope")
	if !present || !ok || !validScopes(scope) {
		return ruleScope, name
	}
	var audience []string
	if raw, present := members["audience"]; !present || json.Unmarshal(raw, &audience) != nil || len(audience) == 0 || !distinct(audience) {
		return ruleAudience, name
	}
	for _, a := range audience {
		if !absoluteHTTPURL(a) {
			return ruleAudience, name
		}
	}
	return "", name
}

// validClientName: 1 to 128 printable characters, as stored: no leading or trailing space.
func validClientName(name string) bool {
	return name != "" && name == strings.TrimSpace(name) && utf8.RuneCountInString(name) <= maxClientName && printableOnly(name)
}

// validScopes: one or more distinct RFC 6749 scope tokens (section 3.3) separated by single spaces,
// never the registration scope. The library splits on any whitespace; a scope token holds none, so
// both readings of an accepted value are the same list.
func validScopes(scope string) bool {
	scopes := strings.Split(scope, " ")
	for _, s := range scopes {
		if !scopeToken(s) {
			return false
		}
	}
	return distinct(scopes) && !slices.Contains(scopes, oauth2provider.RegistrationScope)
}

// scopeToken is one RFC 6749 scope-token: %x21 / %x23-5B / %x5D-7E, one or more.
func scopeToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

func printableOnly(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func distinct(values []string) bool {
	seen := map[string]bool{}
	for _, v := range values {
		if seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}

// absoluteHTTPURL: an absolute http(s) URL with a host and nothing a resource could not be
// configured to match: no credentials, query, fragment or whitespace.
func absoluteHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil &&
		u.Opaque == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && !strings.ContainsAny(raw, " \t\r\n#?")
}

// registryCode maps a refusal's reason to the registry code (docs/api-docs.md, reason codes): the
// audit row's and the IF-01 event's reason_code.
func registryCode(reason string, status int, authorizationPresent bool) string {
	switch reason {
	case "registration_rejected":
		return "TOK-REGISTRATION-REJECTED"
	case "invalid_token":
		if !authorizationPresent {
			return "TOK-MISSING"
		}
		return "TOK-INVALID"
	case "insufficient_scope":
		return "TOK-SCOPE"
	case "invalid_client":
		return "TOK-CLIENT-INVALID"
	case "invalid_request":
		return "TOK-REQUEST-INVALID"
	case "server_error":
		return "TOK-SERVER-ERROR"
	case "dpop_invalid_proof":
		return "TOK-PROOF-INVALID"
	case "dpop_replayed":
		return "TOK-REPLAY"
	case "dpop_use_nonce":
		return "TOK-NONCE"
	case "dpop_jkt_mismatch":
		return "TOK-JKT-MISMATCH"
	case "dpop_invalid_ath":
		return "TOK-ATH-MISMATCH"
	}
	if status >= 500 {
		return "TOK-SERVER-ERROR"
	}
	return "TOK-REQUEST-INVALID"
}

// tokenSignature is the store key of a bearer token: the signature part the token store keeps
// (the second of an opaque token's two parts, the third of a signed token's three). Empty when the
// header carries no such token.
func tokenSignature(authorization string) string {
	scheme, token, found := strings.Cut(authorization, " ")
	if !found || (!strings.EqualFold(scheme, "DPoP") && !strings.EqualFold(scheme, "Bearer")) {
		return ""
	}
	// No length bound of its own: the library applies none, and the header is bounded by the server.
	token = strings.TrimSpace(token)
	if len(token) == 0 {
		return ""
	}
	for i := 0; i < len(token); i++ {
		if token[i] < 0x21 || token[i] > 0x7e {
			return ""
		}
	}
	parts := strings.Split(token, ".")
	switch len(parts) {
	case 2:
		return parts[1]
	case 3:
		return parts[2]
	}
	return ""
}

// maxConcurrentRegistrations bounds the registrations holding a transaction at once. Each holds
// one pool connection for its whole run while the library's nonce and replay checks take another, so
// without a bound a burst of registrations would hold the pool and stall the token endpoint.
const maxConcurrentRegistrations = 2

// registrationGate wraps the library's registration handler. First the caller: a request whose
// token the store does not know goes to the library as it is, which refuses it (401), with no
// transaction and no policy verdict. For a known token: the body bound and the policy, refused
// without touching the library; then, in one of a few registration slots, one transaction around
// the library, so an accepted registration and its audit row commit together and no credential
// leaves without its entry. Every outcome but the DPoP nonce handshake is a decision and leaves an
// audit row and an IF-01 token_event; a refusal is answered first and audited after.
type registrationGate struct {
	next    http.Handler
	stores  oauth2provider.Stores
	offered []string
	log     *slog.Logger
	events  *eventSink
	audit   func(ctx context.Context, e pgstore.AuditEvent) error
	slots   chan struct{}
}

func (s *server) registrationGate(next http.Handler) http.Handler {
	pool := s.pool
	return &registrationGate{
		next: next, stores: s.stores, offered: s.providerCfg.Registration.GrantTypes, log: s.log, events: s.events,
		audit: func(ctx context.Context, e pgstore.AuditEvent) error { return pgstore.Audit(ctx, pool, e) },
		slots: make(chan struct{}, maxConcurrentRegistrations),
	}
}

func (g *registrationGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	registrar, err := g.registrarOf(ctx, r)
	if err != nil {
		g.log.ErrorContext(ctx, "registration token lookup failed", "err", err)
		g.serverError(ctx, w, r, ruleLookup, "", "")
		return
	}
	if registrar == "" {
		g.unauthenticated(ctx, w, r)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRegistrationBody+1))
	if err != nil {
		writeRefusal(w, http.StatusBadRequest, "invalid_request", "The request body could not be read.", string(oauth2provider.CodeInvalidRequest))
		g.auditRefusal(ctx, w, r, ruleRead, string(oauth2provider.CodeInvalidRequest), http.StatusBadRequest, registrar, "")
		return
	}
	if len(body) > maxRegistrationBody {
		g.refuse(ctx, w, r, ruleBodySize, registrar, "")
		return
	}
	rule, clientName := registrationPolicy(body, g.offered)
	if rule != "" {
		g.refuse(ctx, w, r, rule, registrar, clientName)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	select {
	case g.slots <- struct{}{}:
	case <-ctx.Done():
		g.serverError(ctx, w, r, ruleBusy, registrar, clientName)
		return
	}
	release := sync.OnceFunc(func() { <-g.slots })
	defer release()

	txCtx, err := g.stores.Transactions.BeginTx(ctx)
	if err != nil {
		release()
		g.serverError(ctx, w, r, ruleBegin, registrar, clientName)
		return
	}
	open := true
	rollback := func() {
		if open {
			_ = g.stores.Transactions.Rollback(txCtx)
			open = false
		}
		release()
	}
	defer rollback()

	rec := &recorder{header: http.Header{}, status: http.StatusOK}
	g.next.ServeHTTP(rec, r.WithContext(txCtx))
	if rec.status != http.StatusCreated {
		// The library refused, or asked for a nonce: nothing was created. Give the connection back,
		// relay its answer as is, then audit.
		rollback()
		g.relay(ctx, w, r, rec, registrar, clientName)
		return
	}
	clientID := clientIDOf(rec.body.Bytes())
	stored, err := g.stores.Clients.GetClient(txCtx, clientID)
	if clientID == "" || err != nil || stored.ID != clientID {
		rollback()
		g.serverError(ctx, w, r, ruleStored, registrar, clientName)
		return
	}
	detail := map[string]any{"registrar": registrar, "client_name": clientName, "grant_types": stored.GrantTypes,
		"scopes": stored.Scopes, "audience": stored.Audience, "dpop_bound": stored.DPoPBound}
	if err := g.audit(txCtx, pgstore.AuditEvent{Kind: "registration.accepted", CorrelationID: correlationOf(ctx), ClientID: clientID, Detail: detail}); err != nil {
		g.log.ErrorContext(ctx, "audit row not written; registration rolled back", "err", err)
		rollback()
		g.serverError(ctx, w, r, ruleAudit, registrar, clientName)
		return
	}
	err = g.stores.Transactions.Commit(txCtx)
	open = false
	release()
	if err != nil {
		g.uncertain(ctx, w, clientID, registrar, clientName, err)
		return
	}
	rec.flush(w)
	g.events.tokenEvent(ctx, eventPayload{State: "registered", Detail: "client_id=" + clientID})
	g.log.InfoContext(ctx, "registration", "outcome", "accepted", "client_id", clientID, "registrar", registrar)
}

// unauthenticated hands a request whose token the store does not know to the library, which refuses
// it for the token (the conformance suite pins that a missing or unknown token is answered 401), and
// audits that refusal. The library's answer is relayed only when it is a refusal: should it ever
// accept such a request, the credentials are withheld and the outcome is recorded as uncertain.
func (g *registrationGate) unauthenticated(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	rec := &recorder{header: http.Header{}, status: http.StatusOK}
	g.next.ServeHTTP(rec, r)
	if rec.status == http.StatusCreated {
		g.uncertain(ctx, w, clientIDOf(rec.body.Bytes()), "", "", errors.New("registered without a token the store knows"))
		return
	}
	g.relay(ctx, w, r, rec, "", "")
}

// relay passes the library's refusal on unchanged and audits it, unless it is the nonce handshake.
func (g *registrationGate) relay(ctx context.Context, w http.ResponseWriter, r *http.Request, rec *recorder, registrar, clientName string) {
	reason := reasonOf(rec.body.Bytes())
	rec.flush(w)
	if reason == string(oauth2provider.CodeDPoPUseNonce) {
		return
	}
	g.auditRefusal(ctx, w, r, ruleLibrary, reason, rec.status, registrar, clientName)
}

// refuse answers a policy violation in the library's shape and audits it.
func (g *registrationGate) refuse(ctx context.Context, w http.ResponseWriter, r *http.Request, rule, registrar, clientName string) {
	writeRefusal(w, http.StatusBadRequest, "invalid_client_metadata", ruleText[rule], string(oauth2provider.CodeRegistrationRejected))
	g.auditRefusal(ctx, w, r, rule, string(oauth2provider.CodeRegistrationRejected), http.StatusBadRequest, registrar, clientName)
}

// serverError answers a failure of the connector's own and audits it.
func (g *registrationGate) serverError(ctx context.Context, w http.ResponseWriter, r *http.Request, rule, registrar, clientName string) {
	writeRefusal(w, http.StatusInternalServerError, "server_error", "", string(oauth2provider.CodeServerError))
	g.auditRefusal(ctx, w, r, rule, string(oauth2provider.CodeServerError), http.StatusInternalServerError, registrar, clientName)
}

// auditRefusal records a refusal after its answer has left: the row best effort, outside any
// transaction, under its own deadline; the event; and one record.
func (g *registrationGate) auditRefusal(ctx context.Context, w http.ResponseWriter, r *http.Request, rule, reason string, status int, registrar, clientName string) {
	_ = http.NewResponseController(w).Flush()
	code := registryCode(reason, status, r.Header.Get("Authorization") != "")
	detail := map[string]any{"rule": rule, "reason": reason, "status": status}
	if clientName != "" {
		detail["client_name"] = clientName
	}
	g.writeAudit(ctx, pgstore.AuditEvent{Kind: "registration.refused", CorrelationID: correlationOf(ctx), ClientID: registrar, ReasonCode: code, Detail: detail})
	payload := eventPayload{State: "refused", ReasonCode: code, Detail: reason}
	if text, own := ruleText[rule]; own {
		payload.RuleID, payload.Detail = rule, text
	} else if reason == string(oauth2provider.CodeServerError) {
		payload.Detail = reason + " (" + rule + ")"
	}
	g.events.tokenEvent(ctx, payload)
	g.log.InfoContext(ctx, "registration", "outcome", "refused", "rule", rule, "reason_code", code, "status", status, "registrar", registrar)
}

// uncertain answers a registration whose outcome is unknown: the commit failed without saying
// whether it happened, or the library accepted what it should have refused. The credentials are
// withheld; the client may exist, inert, with a secret nobody received, until an operator deletes it.
func (g *registrationGate) uncertain(ctx context.Context, w http.ResponseWriter, clientID, registrar, clientName string, cause error) {
	g.log.ErrorContext(ctx, "registration outcome unknown; credentials withheld, the client may exist without them", "err", cause, "client_id", clientID)
	writeRefusal(w, http.StatusInternalServerError, "server_error", "", string(oauth2provider.CodeServerError))
	_ = http.NewResponseController(w).Flush()
	detail := map[string]any{"registrar": registrar, "client_name": clientName}
	g.writeAudit(ctx, pgstore.AuditEvent{Kind: "registration.uncertain", CorrelationID: correlationOf(ctx), ClientID: clientID, ReasonCode: "TOK-SERVER-ERROR", Detail: detail})
	g.events.tokenEvent(ctx, eventPayload{State: "uncertain", ReasonCode: "TOK-SERVER-ERROR", Detail: "client_id=" + clientID + ": outcome unknown, credentials withheld"})
}

// writeAudit writes a row outside the request's transaction and deadline, bounded by auditTimeout.
func (g *registrationGate) writeAudit(ctx context.Context, e pgstore.AuditEvent) {
	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
	defer cancel()
	if err := g.audit(detached, e); err != nil {
		g.log.ErrorContext(ctx, "audit row not written", "err", err, "kind", e.Kind)
	}
}

// registrarOf names the client whose token the request carries, when the store holds that token
// granted the registration scope: empty for no token, a malformed or unknown one, or one without
// the scope, all of which the library refuses on its own; an error only when the store could not
// answer. It decides whether the request is judged; the library still authorises it. Expiry is
// deliberately not checked here: the library's clock differs (a signed token stays valid to the
// end of its exp second), and an expired token that is judged is still refused by the library,
// inside the transaction.
func (g *registrationGate) registrarOf(ctx context.Context, r *http.Request) (string, error) {
	sig := tokenSignature(r.Header.Get("Authorization"))
	if sig == "" {
		return "", nil
	}
	rec, err := g.stores.AccessTokens.GetToken(ctx, sig)
	if errors.Is(err, oauth2provider.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !slices.Contains(rec.GrantedScopes, oauth2provider.RegistrationScope) {
		return "", nil
	}
	return rec.ClientID, nil
}

func correlationOf(ctx context.Context) string {
	id, _ := ctx.Value(correlationKey{}).(string)
	return id
}

// writeRefusal writes an IF-02 error body with the connector's reason, with its length, so a flush
// completes the answer.
func writeRefusal(w http.ResponseWriter, status int, oauthError, description, reason string) {
	answer := map[string]string{"error": oauthError, oauth2provider.ReasonField: reason}
	if description != "" {
		answer["error_description"] = description
	}
	body, _ := json.Marshal(answer)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// clientIDOf reads client_id, and nothing else, from a registration answer.
func clientIDOf(body []byte) string {
	members, err := jose.ParseObject(body)
	if err != nil {
		return ""
	}
	id, _, ok := jose.String(members, "client_id")
	if !ok {
		return ""
	}
	return id
}

// reasonOf reads the reason of a refusal the library wrote.
func reasonOf(body []byte) string {
	var answer struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(body, &answer)
	return answer.Reason
}

// recorder holds the library's answer until the gate decides whether to relay it.
type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *recorder) Header() http.Header         { return r.header }
func (r *recorder) WriteHeader(status int)      { r.status = status }
func (r *recorder) Write(p []byte) (int, error) { return r.body.Write(p) }

// flush relays the recorded answer: its headers, its status, its body, with the length of the body
// it actually relays (never one the handler declared), so a flush completes the answer.
func (r *recorder) flush(w http.ResponseWriter) {
	for name, values := range r.header {
		if name == "Content-Length" {
			continue
		}
		w.Header()[name] = values
	}
	w.Header().Set("Content-Length", strconv.Itoa(r.body.Len()))
	w.WriteHeader(r.status)
	_, _ = w.Write(r.body.Bytes())
}
