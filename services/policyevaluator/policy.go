// Package policyevaluator serves a deny-default IF-05 rule set for the M3 resource.
package policyevaluator

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/meshcaller"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
)

type Config struct {
	Revision           string            `json:"revision"`
	Audience           string            `json:"audience"`
	Host               string            `json:"host"`
	GuardCallers       []string          `json:"guard_callers"`
	ParticipantCallers []string          `json:"participant_callers"`
	ScopeTenants       map[string]string `json:"scope_tenants"`
}

type Policy struct {
	cfg     Config
	callers *meshcaller.XFCC
}

func New(cfg Config) (*Policy, error) {
	if cfg.Revision == "" || cfg.Audience == "" || cfg.Host == "" || len(cfg.GuardCallers) == 0 || len(cfg.ParticipantCallers) == 0 || cfg.ScopeTenants["report:read"] == "" || cfg.ScopeTenants["report:summary"] == "" || cfg.ScopeTenants["report:read"] == cfg.ScopeTenants["report:summary"] {
		return nil, errors.New("policy configuration incomplete")
	}
	auth, err := meshcaller.NewXFCC(cfg.GuardCallers)
	if err != nil {
		return nil, err
	}
	if _, err = meshcaller.NewXFCC(cfg.ParticipantCallers); err != nil {
		return nil, err
	}
	return &Policy{cfg: cfg, callers: auth}, nil
}

func (p *Policy) Decide(in hook.Input) hook.Decision {
	deny := hook.Decision{Allow: false, ReasonCode: hook.ReasonRuleDeny, RuleID: "m3-default-deny", BundleRevision: p.cfg.Revision, DenyBody: &hook.DenyBody{Error: "access_denied"}}
	if !slices.Contains(p.cfg.ParticipantCallers, in.Source.SPIFFEID) || in.Request.Method != http.MethodPost || in.Request.Path != "/demo" || in.Request.Host != p.cfg.Host || !in.Token.Present || !in.Token.ProofValid || in.Token.Aud != p.cfg.Audience || in.Token.Sub == "" || in.Token.ClientID == "" || in.Token.JKT == "" || in.Tenant == nil {
		return deny
	}
	// A summary identity must select a summary-only acquisition route, never a full-report token.
	for _, scope := range []string{"report:read", "report:summary"} {
		if slices.Contains(strings.Fields(in.Token.Scope), scope) {
			if *in.Tenant != p.cfg.ScopeTenants[scope] {
				return deny
			}
			return hook.Decision{Allow: true, RuleID: "m3-" + strings.ReplaceAll(scope, ":", "-"), BundleRevision: p.cfg.Revision, Obligations: []string{hook.ObligationSubstituteUpstreamToken}}
		}
	}
	return deny
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
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(p.Decide(in))
}
