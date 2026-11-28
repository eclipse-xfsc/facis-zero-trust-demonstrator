// Package policyevaluator serves a deny-default IF-05 rule set for the M3 resource.
//
// Decide is the rule source: one input in, one decision out carrying the rule id that decided and
// the bundle revision. ServeHTTP authenticates the guard, calls Decide and writes the IF-01 v2
// decision event; a different rule source (for example policy bundles) replaces Decide only.
package policyevaluator

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/meshcaller"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
)

// Rule ids, one per reason a decision can have.
const (
	RuleDefaultDeny          = "m3-default-deny"
	RuleScopeRequired        = "m3-scope-required"
	RuleClientBlocked        = "m3-client-blocked"
	RulePresentationRequired = "m3-presentation-required"
	RuleTenantRoute          = "m3-tenant-route"
	RuleTenantMembership     = "m3-tenant-membership"
)

type Config struct {
	Revision           string            `json:"revision"`
	Audience           string            `json:"audience"`
	Host               string            `json:"host"`
	GuardCallers       []string          `json:"guard_callers"`
	ParticipantCallers []string          `json:"participant_callers"`
	ScopeTenants       map[string]string `json:"scope_tenants"`
	// EventSource names this evaluator on the IF-01 feed: policy-a or policy-b.
	EventSource string `json:"event_source"`
	// BlockedClients are clients denied by rule whatever their token says.
	BlockedClients []string `json:"blocked_clients,omitempty"`
	// Presentation, when set, denies a token carrying one of its scopes until the caller presents
	// a credential, answering with the OID4VP link.
	Presentation *Presentation `json:"presentation,omitempty"`
	// TenantMembers, when set, names the callers that are members of each tenant: a request is
	// allowed only for a member of the target tenant the guard's route names. Configured, a request
	// without a target tenant is denied; unconfigured, so is one with a target tenant.
	TenantMembers map[string][]string `json:"tenant_members,omitempty"`
	// GRPCMethods are the gRPC methods the rule set covers besides the REST route, as full method
	// paths; the guard is configured with the same list.
	GRPCMethods []string `json:"grpc_methods,omitempty"`
}

// tenantName is a tenant as the contracts name it: a Kubernetes namespace name.
var tenantName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

type Presentation struct {
	Scopes     []string `json:"scopes"`
	OID4VPLink string   `json:"oid4vp_link"`
}

// routed reports whether the request is for a route the rule set covers: the REST route, or a
// configured gRPC method whose service the guard named. The decision that follows is the same.
func (p *Policy) routed(r hook.RequestInfo) bool {
	if r.Method != http.MethodPost {
		return false
	}
	if r.GRPCService == "" {
		return r.Path == "/demo"
	}
	return slices.Contains(p.cfg.GRPCMethods, r.Path) && strings.HasPrefix(r.Path, "/"+r.GRPCService+"/")
}

type Policy struct {
	cfg     Config
	callers *meshcaller.XFCC
	events  hook.EventSink
}

// New returns the evaluator. events may be nil.
func New(cfg Config, events hook.EventSink) (*Policy, error) {
	if cfg.Revision == "" || cfg.Audience == "" || cfg.Host == "" || len(cfg.GuardCallers) == 0 || len(cfg.ParticipantCallers) == 0 || cfg.ScopeTenants["report:read"] == "" || cfg.ScopeTenants["report:summary"] == "" || cfg.ScopeTenants["report:read"] == cfg.ScopeTenants["report:summary"] {
		return nil, errors.New("policy configuration incomplete")
	}
	if cfg.EventSource != "policy-a" && cfg.EventSource != "policy-b" {
		return nil, errors.New("policy event_source must be policy-a or policy-b")
	}
	if p := cfg.Presentation; p != nil {
		link, err := url.Parse(p.OID4VPLink)
		if len(p.Scopes) == 0 || err != nil || (link.Scheme != "https" && link.Scheme != "openid4vp") || len(p.OID4VPLink) > 2048 {
			return nil, errors.New("policy presentation needs scopes and an https or openid4vp link")
		}
		for _, s := range p.Scopes {
			if _, ok := cfg.ScopeTenants[s]; ok || s == "" {
				return nil, errors.New("a presentation scope cannot also select a tenant")
			}
		}
	}
	for tenant, members := range cfg.TenantMembers {
		if !tenantName.MatchString(tenant) || len(members) == 0 || slices.ContainsFunc(members, func(m string) bool { return !slices.Contains(cfg.ParticipantCallers, m) }) {
			return nil, errors.New("policy tenant_members needs namespace-named tenants whose members are participant callers")
		}
	}
	auth, err := meshcaller.NewXFCC(cfg.GuardCallers)
	if err != nil {
		return nil, err
	}
	if _, err = meshcaller.NewXFCC(cfg.ParticipantCallers); err != nil {
		return nil, err
	}
	return &Policy{cfg: cfg, callers: auth, events: events}, nil
}

func (p *Policy) deny(rule string) hook.Decision {
	return hook.Decision{Allow: false, ReasonCode: hook.ReasonRuleDeny, RuleID: rule, BundleRevision: p.cfg.Revision, DenyBody: &hook.DenyBody{Error: "access_denied"}}
}

// Decide answers one input. The checks run from the request's shape to the caller's entitlement,
// so insufficient scope (RuleScopeRequired) is never reported for a request a rule refuses anyway.
func (p *Policy) Decide(in hook.Input) hook.Decision {
	if !slices.Contains(p.cfg.ParticipantCallers, in.Source.SPIFFEID) || !p.routed(in.Request) || in.Request.Host != p.cfg.Host || !in.Token.Present || !in.Token.ProofValid || in.Token.Aud != p.cfg.Audience || in.Token.Sub == "" || in.Token.ClientID == "" || in.Token.JKT == "" {
		return p.deny(RuleDefaultDeny)
	}
	// Membership of the target tenant is decided here, from this policy's configuration: the guard
	// names the tenant of its route, never which callers belong to it.
	if (in.TargetTenant != "" || len(p.cfg.TenantMembers) > 0) && !slices.Contains(p.cfg.TenantMembers[in.TargetTenant], in.Source.SPIFFEID) {
		return p.deny(RuleTenantMembership)
	}
	if slices.Contains(p.cfg.BlockedClients, in.Token.ClientID) {
		return p.deny(RuleClientBlocked)
	}
	scopes := strings.Fields(in.Token.Scope)
	if pr := p.cfg.Presentation; pr != nil && slices.ContainsFunc(scopes, func(s string) bool { return slices.Contains(pr.Scopes, s) }) {
		return hook.Decision{Allow: false, ReasonCode: hook.ReasonPresentationRequired, RuleID: RulePresentationRequired, BundleRevision: p.cfg.Revision,
			DenyBody: &hook.DenyBody{Error: "presentation_required", OID4VPLink: pr.OID4VPLink}}
	}
	// A summary identity must select a summary-only acquisition route, never a full-report token.
	for _, scope := range []string{"report:read", "report:summary"} {
		if slices.Contains(scopes, scope) {
			if in.Tenant == nil || *in.Tenant != p.cfg.ScopeTenants[scope] {
				return p.deny(RuleTenantRoute)
			}
			return hook.Decision{Allow: true, RuleID: "m3-" + strings.ReplaceAll(scope, ":", "-"), BundleRevision: p.cfg.Revision, Obligations: []string{hook.ObligationSubstituteUpstreamToken}}
		}
	}
	return p.deny(RuleScopeRequired)
}

func (p *Policy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.URL.Path != "/decision" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if _, err := p.callers.Authenticate(r); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	var in hook.Input
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil || dec.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	decision := p.Decide(in)
	p.record(in, decision)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(decision)
}

// record writes the decision event under the guard's correlation id.
func (p *Policy) record(in hook.Input, d hook.Decision) { recordDecision(p.events, p.cfg.Host, in, d) }

// recordDecision writes one IF-01 v2 decision event for an answered input, whichever engine
// decided: the rule id and the bundle revision of the decision, or not_evaluated when the engine
// gave none (an unavailable engine). host is the authority the resource is named with; an empty
// host takes the input's own when it is well formed. Caller-controlled strings are bounded or
// replaced so the event always satisfies its schema.
func recordDecision(events hook.EventSink, host string, in hook.Input, d hook.Decision) {
	if events == nil {
		return
	}
	e := hook.EventPayload{State: "allowed", RuleID: d.RuleID, BundleRevision: d.BundleRevision, CallerSPIFFEID: bounded(in.Source.SPIFFEID, "spiffe://")}
	if tenantName.MatchString(in.TargetTenant) {
		e.Tenant = in.TargetTenant
	}
	if !d.Allow {
		e.State, e.ReasonCode = "denied", d.ReasonCode
	}
	if in.Token.Present {
		e.TokenSubject = bounded(in.Token.Sub, "")
	}
	if host == "" && len(in.Request.Host) <= 253 && in.Request.Host != "" && strings.IndexFunc(in.Request.Host, func(c rune) bool { return c <= ' ' || c > '~' || c == '/' }) < 0 {
		host = in.Request.Host
	}
	e.Resource = "UNKNOWN " + host + "/"
	if slices.Contains([]string{http.MethodPost, http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch}, in.Request.Method) && in.Request.Host == host && (in.Request.Path == "/demo" || in.Request.GRPCService != "" && grpcMethod.MatchString(in.Request.Path)) {
		e.Resource = in.Request.Method + " " + host + in.Request.Path
	}
	if host == "" {
		e.Resource = "UNKNOWN /"
	}
	id := in.CorrelationID
	if len(id) > 128 || strings.IndexFunc(id, func(c rune) bool { return c <= ' ' || c > '~' }) >= 0 {
		id = ""
	}
	events.Emit(id, e)
}

// grpcMethod is a full gRPC method path, the form the guard accepts in its configuration.
var grpcMethod = regexp.MustCompile(`^/[A-Za-z_][A-Za-z0-9_.]*/[A-Za-z_][A-Za-z0-9_]*$`)

// spiffeID is the v2 event schema's pattern for caller_spiffe_id.
var spiffeID = regexp.MustCompile(`^spiffe://[a-z0-9._-]+(/[A-Za-z0-9._~%!$&'()*+,;=:@-]+)+$`)

func bounded(v, prefix string) string {
	if prefix != "" && !spiffeID.MatchString(v) {
		return ""
	}
	if v == "" || len(v) > 256 || strings.IndexFunc(v, func(c rune) bool { return c <= ' ' || c > '~' }) >= 0 || v == hook.NotEvaluated {
		return ""
	}
	return v
}
