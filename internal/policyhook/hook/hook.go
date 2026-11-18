// Package hook is the transport-neutral core of the guard's policy hook as it is verified: the
// policy input and decision as the policy interface defines them
// (docs/contracts/if05-*.v1.schema.json), and the evaluation that turns one request into one
// outcome — the request headers an allowed request is forwarded with, or the status, headers and
// body a refused request is answered with. The two Envoy filters the guard can be built on,
// ext_authz and ext_proc, are thin translations of the same Outcome (package envoyhook).
//
// This is verification code: the guard's deployable adapter is a later task and may take or
// leave it.
package hook

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ObligationSubstituteUpstreamToken is the one obligation an allow may carry: the guard replaces
// the caller's credential with the token store's values before forwarding, or refuses.
const ObligationSubstituteUpstreamToken = "substitute_upstream_token"

// Input is what the guard sends to the policy engine for one request. The token has already been
// authenticated by the guard; ProofValid records that result, it is never computed by policy.
type Input struct {
	CorrelationID string      `json:"correlation_id"`
	Source        Source      `json:"source"`
	Request       RequestInfo `json:"request"`
	Token         Token       `json:"token"`
	// Tenant is serialised as null when there is none; the member is always present.
	Tenant *string `json:"tenant"`
}

// Source is the workload the request comes from.
type Source struct {
	SPIFFEID  string `json:"spiffe_id"`
	Namespace string `json:"namespace,omitempty"`
}

// RequestInfo is the part of the request policy decides on.
type RequestInfo struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	Host        string `json:"host"`
	GRPCService string `json:"grpc_service,omitempty"`
}

// Token is the authenticated caller token. When Present is false no other member is sent.
type Token struct {
	Present    bool
	Sub        string
	ClientID   string
	JKT        string
	Scope      string
	Aud        string
	ProofValid bool
}

type tokenJSON struct {
	Present    bool   `json:"present"`
	Sub        string `json:"sub,omitempty"`
	ClientID   string `json:"client_id"`
	JKT        string `json:"jkt"`
	Scope      string `json:"scope"`
	Aud        string `json:"aud"`
	ProofValid bool   `json:"proof_valid"`
}

// MarshalJSON writes only {"present": false} for an absent token and every member the policy
// interface requires for a present one.
func (t Token) MarshalJSON() ([]byte, error) {
	if !t.Present {
		return []byte(`{"present":false}`), nil
	}
	return json.Marshal(tokenJSON{true, t.Sub, t.ClientID, t.JKT, t.Scope, t.Aud, t.ProofValid})
}

// UnmarshalJSON is the inverse of MarshalJSON.
func (t *Token) UnmarshalJSON(b []byte) error {
	var raw tokenJSON
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*t = Token(raw)
	return nil
}

// Decision is the policy engine's answer.
type Decision struct {
	Allow          bool      `json:"allow"`
	ReasonCode     string    `json:"reason_code,omitempty"`
	RuleID         string    `json:"rule_id,omitempty"`
	BundleRevision string    `json:"bundle_revision"`
	Obligations    []string  `json:"obligations,omitempty"`
	DenyBody       *DenyBody `json:"deny_body,omitempty"`
}

// DenyBody is what a refused caller is told.
type DenyBody struct {
	Error      string `json:"error"`
	OID4VPLink string `json:"oid4vp_link,omitempty"`
}

// Reason codes the hook answers with: the policy layer's, and the token layer's it passes on
// when a substitution is refused.
const (
	ReasonRuleDeny              = "POL-RULE-DENY"
	ReasonPresentationRequired  = "POL-PRESENTATION-REQUIRED"
	ReasonPDPUnavailable        = "POL-PDP-UNAVAILABLE"
	ReasonBundleStale           = "POL-BUNDLE-STALE"
	ReasonTokenNoUpstream       = "TOK-NO-UPSTREAM"
	ReasonTokenStoreUnavailable = "TOK-STORE-UNAVAILABLE"
	ReasonTokenCallerDenied     = "TOK-CALLER-DENIED"
	ReasonTokenRouteDenied      = "TOK-ROUTE-DENIED"
)

// statusByCode is the HTTP status the reason-code registry (docs/contracts/reason-codes.json)
// gives each code the hook can answer with: the family default unless the code overrides it. A
// test keeps it equal to the registry.
var statusByCode = map[string]int{
	ReasonRuleDeny:              403,
	ReasonPresentationRequired:  401,
	ReasonPDPUnavailable:        503,
	ReasonBundleStale:           503,
	ReasonTokenNoUpstream:       409,
	ReasonTokenStoreUnavailable: 503,
	ReasonTokenCallerDenied:     403,
	ReasonTokenRouteDenied:      403,
}

// KnownCodes lists the reason codes the hook can answer with.
func KnownCodes() []string {
	out := make([]string, 0, len(statusByCode))
	for code := range statusByCode {
		out = append(out, code)
	}
	return out
}

// StatusFor is the HTTP status a refusal with the given reason code carries: the registry's,
// else the family default (403 for the policy layer, 401 for the token layer).
func StatusFor(code string) int {
	if s, ok := statusByCode[code]; ok {
		return s
	}
	if strings.HasPrefix(code, "TOK-") {
		return 401
	}
	return 403
}

var reasonCodePattern = regexp.MustCompile(`^POL(-[A-Z0-9]+)+$`)

// Validate applies the rules the decision schema states, so a decision that would not validate
// against the contract is never acted on.
func (d Decision) Validate() error {
	if d.BundleRevision == "" {
		return errors.New("bundle_revision is required")
	}
	if d.Allow {
		if d.ReasonCode != "" || d.DenyBody != nil {
			return errors.New("an allow carries neither reason_code nor deny_body")
		}
		for _, o := range d.Obligations {
			if o != ObligationSubstituteUpstreamToken {
				return fmt.Errorf("unknown obligation %q", o)
			}
		}
		return nil
	}
	switch {
	case d.ReasonCode == "" || d.DenyBody == nil:
		return errors.New("a denial requires reason_code and deny_body")
	case !reasonCodePattern.MatchString(d.ReasonCode):
		return fmt.Errorf("reason_code %q is not a policy code", d.ReasonCode)
	case len(d.Obligations) > 0:
		return errors.New("a denial carries no obligations")
	case d.DenyBody.Error == "":
		return errors.New("deny_body.error is required")
	case d.ReasonCode == ReasonRuleDeny && d.RuleID == "":
		return errors.New("a rule denial names its rule_id")
	case d.ReasonCode == ReasonPresentationRequired && d.DenyBody.OID4VPLink == "":
		return errors.New("a presentation-required denial carries deny_body.oid4vp_link")
	}
	return nil
}

// Substitutes reports whether the allow carries the substitution obligation.
func (d Decision) Substitutes() bool {
	for _, o := range d.Obligations {
		if o == ObligationSubstituteUpstreamToken {
			return true
		}
	}
	return false
}

// Header is one header to set or send.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Outcome is what the guard does with one request: forward it with SetHeaders applied and
// RemoveHeaders dropped, or answer it with Status, SetHeaders and Body.
type Outcome struct {
	Allowed       bool     `json:"allowed"`
	CorrelationID string   `json:"correlation_id"`
	Status        int      `json:"status,omitempty"`
	ReasonCode    string   `json:"reason_code,omitempty"`
	RuleID        string   `json:"rule_id,omitempty"`
	SetHeaders    []Header `json:"set_headers,omitempty"`
	RemoveHeaders []string `json:"remove_headers,omitempty"`
	Body          []byte   `json:"body,omitempty"`
}

// Refusal is what the caller receives in the body of a refused request: the deny body of the
// decision plus the reason code, and the rule for a rule denial.
type Refusal struct {
	Error      string `json:"error"`
	ReasonCode string `json:"reason_code"`
	RuleID     string `json:"rule_id,omitempty"`
	OID4VPLink string `json:"oid4vp_link,omitempty"`
}

// Response headers of a refusal and request headers of a forwarded request.
const (
	HeaderReasonCode = "x-facis-reason-code"
	HeaderRequestID  = "x-request-id"
	ContentTypeJSON  = "application/json"
)

// IsFacisHeader reports whether name is in the namespace only the guard may set.
func IsFacisHeader(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "x-facis-")
}
