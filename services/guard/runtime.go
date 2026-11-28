package guard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/meshcaller"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/tokenverify"
)

const (
	proofLifespan = 60 * time.Second
	proofSkew     = 30 * time.Second
)

// Config contains public wiring only. Mesh callers are checked via a SANITIZE_SET sidecar.
type Config struct {
	ScopeTenants     map[string]string `json:"scope_tenants"`
	Issuer           string            `json:"issuer"`
	JWKSURL          string            `json:"jwks_url"`
	InboundAudience  string            `json:"inbound_audience"`
	UpstreamAudience string            `json:"upstream_audience"`
	PublishedBaseURL string            `json:"published_base_url"`
	PeerZone         string            `json:"peer_zone"`
	PolicyURL        string            `json:"policy_url"`
	StoreURL         string            `json:"store_url"`
	AllowedCallers   []string          `json:"allowed_callers"`
	// EventSource names this guard on the IF-01 feed: guard-a or guard-b.
	EventSource string `json:"event_source"`
	// TargetTenant, when set, is the tenant this guard's route belongs to: sent to policy with every
	// request and recorded on every decision event. It comes from here only, never from the request.
	TargetTenant string `json:"target_tenant,omitempty"`
	// GRPCMethods are the gRPC methods guarded besides the REST route, as full method paths
	// ("/package.Service/Method"). Empty means the guard serves the REST route only.
	GRPCMethods []string `json:"grpc_methods,omitempty"`
}

// grpcMethod is a full gRPC method path: the service, with its package, and the method.
var grpcMethod = regexp.MustCompile(`^/[A-Za-z_][A-Za-z0-9_.]*/[A-Za-z_][A-Za-z0-9_]*$`)

// restPath is the one REST route of the protected resource.
const restPath = "/demo"

// route reports whether the request is for a guarded route, and the gRPC service when it is a
// gRPC call. A gRPC call is a POST to a configured method path with a gRPC content type; a path
// the configuration does not name is no route, whatever its content type.
func (r *Runtime) route(in hook.Request) (grpcService string, ok bool) {
	if in.Method != http.MethodPost {
		return "", false
	}
	if in.Path == restPath {
		return "", true
	}
	contentType := in.Headers.Get("Content-Type")
	if !slices.Contains(r.cfg.GRPCMethods, in.Path) || (contentType != "application/grpc" && !strings.HasPrefix(contentType, "application/grpc+")) {
		return "", false
	}
	return in.Path[1:strings.LastIndexByte(in.Path, '/')], true
}

// tenantName is a tenant as the contracts name it: a Kubernetes namespace name.
var tenantName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

type Runtime struct {
	cfg      Config
	verifier interface {
		Verify(*http.Request) (tokenverify.Identity, error)
	}
	callers *meshcaller.XFCC
	clients *Clients
	events  hook.EventSink
}

func New(cfg Config, events hook.EventSink) (*Runtime, error) {
	if strings.TrimSpace(cfg.InboundAudience) == "" || strings.TrimSpace(cfg.UpstreamAudience) == "" || strings.IndexFunc(cfg.InboundAudience+cfg.UpstreamAudience, unicode.IsSpace) >= 0 || cfg.InboundAudience == cfg.UpstreamAudience {
		return nil, errors.New("guard requires distinct nonempty inbound and upstream audiences")
	}
	for _, raw := range []string{cfg.PublishedBaseURL, cfg.PolicyURL, cfg.StoreURL} {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return nil, errors.New("guard requires configured base URLs")
		}
	}
	if cfg.EventSource != "guard-a" && cfg.EventSource != "guard-b" {
		return nil, errors.New("guard requires event_source guard-a or guard-b")
	}
	if cfg.TargetTenant != "" && !tenantName.MatchString(cfg.TargetTenant) {
		return nil, errors.New("guard target_tenant must be a namespace name")
	}
	if cfg.PeerZone == "" || len(cfg.AllowedCallers) == 0 || cfg.ScopeTenants["report:read"] == "" || cfg.ScopeTenants["report:summary"] == "" || cfg.ScopeTenants["report:read"] == cfg.ScopeTenants["report:summary"] {
		return nil, errors.New("guard requires peer zone and allowed mesh callers")
	}
	for _, method := range cfg.GRPCMethods {
		if !grpcMethod.MatchString(method) {
			return nil, errors.New("guard gRPC methods must be full method paths, /package.Service/Method")
		}
	}
	cfg.PublishedBaseURL = strings.TrimRight(cfg.PublishedBaseURL, "/")
	cfg.PolicyURL = strings.TrimRight(cfg.PolicyURL, "/")
	cfg.StoreURL = strings.TrimRight(cfg.StoreURL, "/")
	callers, err := meshcaller.NewXFCC(cfg.AllowedCallers)
	if err != nil {
		return nil, errors.New("guard caller configuration invalid")
	}
	clients := NewClients(cfg.PolicyURL, cfg.StoreURL)
	verifier, err := tokenverify.New(tokenverify.Config{Issuer: cfg.Issuer, JWKSURL: cfg.JWKSURL, Audience: cfg.InboundAudience,
		PublicBaseURL: cfg.PublishedBaseURL, Replay: clients, Proof: dpopproof.Policy{Lifespan: proofLifespan, Skew: proofSkew}})
	if err != nil {
		return nil, errors.New("guard verifier configuration invalid")
	}
	return &Runtime{cfg: cfg, verifier: verifier, callers: callers, clients: clients, events: events}, nil
}

// resource is the v2 event's resource: the method and the configured target, never the caller's
// Host, bounded and without whitespace.
func resource(method, base, path string) string {
	method = strings.ToUpper(method)
	if len(method) < 3 || len(method) > 7 || strings.IndexFunc(method, func(c rune) bool { return c < 'A' || c > 'Z' }) >= 0 {
		method = "UNKNOWN"
	}
	target := base + path
	if len(target) > 512 || strings.IndexFunc(target, unicode.IsSpace) >= 0 {
		target = base + "/"
	}
	return method + " " + target
}

// verifiedClaims is constructed only after the cryptographic verifier succeeds for this request.
type verifiedClaims struct{ token hook.Token }

func (v verifiedClaims) Authenticate(string, string) hook.Token { return v.token }

// registry maps the guard's own refusals (before policy) to the reason-code registry
// (docs/contracts/reason-codes.json) and the status the registry gives the code. The runtime
// code stays in the decision event's detail, so two causes under one code remain distinguishable.
var registry = map[string]struct {
	code   string
	status int
}{
	"route_denied":         {hook.ReasonRuleDeny, http.StatusForbidden},
	"host_denied":          {hook.ReasonRuleDeny, http.StatusForbidden},
	"mesh_caller_denied":   {"MESH-PAIR-DENIED", http.StatusForbidden},
	"token_absent":         {"TOK-MISSING", http.StatusUnauthorized},
	"token_malformed":      {"TOK-INVALID", http.StatusUnauthorized},
	"signature_invalid":    {"TOK-INVALID", http.StatusUnauthorized},
	"issuer_mismatch":      {"TOK-INVALID", http.StatusUnauthorized},
	"audience_mismatch":    {"TOK-INVALID", http.StatusUnauthorized},
	"token_expired":        {"TOK-EXPIRED", http.StatusUnauthorized},
	"proof_absent":         {"TOK-PROOF-INVALID", http.StatusUnauthorized},
	"proof_invalid":        {"TOK-PROOF-INVALID", http.StatusUnauthorized},
	"key_binding_mismatch": {"TOK-JKT-MISMATCH", http.StatusUnauthorized},
	"proof_replayed":       {"TOK-REPLAY", http.StatusUnauthorized},
	"scope_insufficient":   {"TOK-SCOPE", http.StatusForbidden},
	"request_invalid":      {"TOK-REQUEST-INVALID", http.StatusBadRequest},
	"replay_unavailable":   {hook.ReasonTokenStoreUnavailable, http.StatusServiceUnavailable},
	"key_set_unavailable":  {"TOK-KEYSET-UNAVAILABLE", http.StatusServiceUnavailable},
	"unclassified":         {"TOK-SERVER-ERROR", http.StatusInternalServerError},
}

// guardRule names the guard's own route allow-list when it refuses a route or host.
const guardRule = "guard-route-allowlist"

func (r *Runtime) refuse(runtimeCode string, seen hook.EventPayload) hook.Outcome {
	entry, ok := registry[runtimeCode]
	if !ok {
		entry = registry["unclassified"]
	}
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	id := hex.EncodeToString(raw[:])
	refusal := hook.Refusal{Error: "request_refused", ReasonCode: entry.code}
	if entry.code == hook.ReasonRuleDeny {
		refusal.RuleID = guardRule
	}
	if r.events != nil {
		seen.State, seen.ReasonCode, seen.RuleID, seen.Detail = "denied", entry.code, refusal.RuleID, runtimeCode
		r.events.Emit(id, seen)
	}
	body, _ := json.Marshal(refusal)
	return hook.Outcome{CorrelationID: id, Status: entry.status, ReasonCode: entry.code, RuleID: refusal.RuleID, Body: body,
		SetHeaders: []hook.Header{{Name: "content-type", Value: "application/json"}, {Name: hook.HeaderReasonCode, Value: entry.code}, {Name: hook.HeaderRequestID, Value: id}}}
}

// Evaluate validates the incoming proof before policy or substitution, so replay cannot be hidden
// by a freshly minted upstream proof. Every dependency failure is a refusal.
func (r *Runtime) Evaluate(ctx context.Context, in hook.Request) hook.Outcome {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	path, _, _ := strings.Cut(in.Path, "?")
	seen := hook.EventPayload{Resource: resource(in.Method, r.cfg.PublishedBaseURL, path), Tenant: r.cfg.TargetTenant}
	grpcService, routed := r.route(in)
	if !routed {
		return r.refuse("route_denied", seen)
	}
	in.GRPCService = grpcService
	target, _ := url.Parse(r.cfg.PublishedBaseURL)
	if !strings.EqualFold(in.Host, target.Host) {
		return r.refuse("host_denied", seen)
	}
	// The proof's target is the published base URL and the route's own path, REST or gRPC.
	req, err := http.NewRequestWithContext(ctx, in.Method, r.cfg.PublishedBaseURL+in.Path, nil)
	if err != nil {
		return r.refuse("route_denied", seen)
	}
	req.Header = in.Headers.Clone()
	peer, err := r.callers.Authenticate(req)
	if err != nil {
		return r.refuse("mesh_caller_denied", seen)
	}
	seen.CallerSPIFFEID = peer.SPIFFEID
	id, err := r.verifier.Verify(req)
	if err != nil {
		return r.refuse(tokenverify.ReasonCode(err), seen)
	}
	in.Scheme = target.Scheme
	in.Host = target.Host // canonical configured authority for the policy input
	in.PeerID = peer.SPIFFEID
	claims := verifiedClaims{hook.Token{Present: true, Sub: id.Subject, ClientID: id.ClientID, JKT: id.JKT,
		Scope: strings.Join(id.Scopes, " "), Aud: r.cfg.InboundAudience, ProofValid: true}}
	var tenant *string
	for _, scope := range []string{"report:read", "report:summary"} {
		if slices.Contains(id.Scopes, scope) {
			value := r.cfg.ScopeTenants[scope]
			tenant = &value
			break
		}
	}
	g := hook.New(hook.Config{PublishedBaseURL: r.cfg.PublishedBaseURL, PeerZone: r.cfg.PeerZone,
		Audience: r.cfg.UpstreamAudience, Tenant: tenant, TargetTenant: r.cfg.TargetTenant, DecisionTimeout: 6 * time.Second}, r.clients, claims, r.clients, r.events)
	out := g.Evaluate(ctx, in)
	if out.Allowed {
		out.RemoveHeaders = append(out.RemoveHeaders, "x-forwarded-client-cert")
	}
	return out
}
