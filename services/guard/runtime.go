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

type Runtime struct {
	cfg      Config
	verifier interface {
		Verify(*http.Request) (tokenverify.Identity, error)
	}
	callers *meshcaller.XFCC
	clients *Clients
	events  hook.EventSink
	// Refused counts every refusal, once, by its reason code.
	Refused Refusals
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

// verifiedClaims is constructed only after the cryptographic verifier succeeds for this request.
type verifiedClaims struct{ token hook.Token }

func (v verifiedClaims) Authenticate(string, string) hook.Token { return v.token }

func (r *Runtime) refuse(reason string, status int) hook.Outcome {
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	id := hex.EncodeToString(raw[:])
	if r.events != nil {
		r.events.Emit(id, hook.EventPayload{State: "denied", ReasonCode: reason})
	}
	body, _ := json.Marshal(map[string]string{"error": "request_refused", "reason_code": reason})
	return hook.Outcome{CorrelationID: id, Status: status, ReasonCode: reason, Body: body,
		SetHeaders: []hook.Header{{Name: "content-type", Value: "application/json"}, {Name: hook.HeaderRequestID, Value: id}}}
}

// Evaluate decides one request and counts it when it is refused.
func (r *Runtime) Evaluate(ctx context.Context, in hook.Request) hook.Outcome {
	out := r.evaluate(ctx, in)
	if !out.Allowed {
		r.Refused.add(out.ReasonCode)
	}
	return out
}

// evaluate validates the incoming proof before policy or substitution, so replay cannot be hidden
// by a freshly minted upstream proof. Every dependency failure is a refusal.
func (r *Runtime) evaluate(ctx context.Context, in hook.Request) hook.Outcome {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	grpcService, routed := r.route(in)
	if !routed {
		return r.refuse("route_denied", http.StatusForbidden)
	}
	in.GRPCService = grpcService
	target, _ := url.Parse(r.cfg.PublishedBaseURL)
	if !strings.EqualFold(in.Host, target.Host) {
		return r.refuse("host_denied", http.StatusForbidden)
	}
	// The proof's target is the published base URL and the route's own path, REST or gRPC.
	req, err := http.NewRequestWithContext(ctx, in.Method, r.cfg.PublishedBaseURL+in.Path, nil)
	if err != nil {
		return r.refuse("route_denied", http.StatusForbidden)
	}
	req.Header = in.Headers.Clone()
	peer, err := r.callers.Authenticate(req)
	if err != nil {
		return r.refuse("mesh_caller_denied", http.StatusForbidden)
	}
	id, err := r.verifier.Verify(req)
	if err != nil {
		status := http.StatusUnauthorized
		if errors.Is(err, tokenverify.ErrKeySetUnavailable) || tokenverify.ReasonCode(err) == "replay_unavailable" {
			status = http.StatusServiceUnavailable
		}
		return r.refuse(tokenverify.ReasonCode(err), status)
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
		Audience: r.cfg.UpstreamAudience, Tenant: tenant, DecisionTimeout: 6 * time.Second}, r.clients, claims, r.clients, r.events)
	out := g.Evaluate(ctx, in)
	if out.Allowed {
		out.RemoveHeaders = append(out.RemoveHeaders, "x-forwarded-client-cert")
	}
	return out
}
