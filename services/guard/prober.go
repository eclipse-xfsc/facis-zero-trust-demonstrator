package guard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/tokenverify"
)

// The guard's dependencies, as the prober names them in its readiness answer and its metrics.
const (
	DependencyPolicyEngine = "policy_engine"
	DependencyKeySet       = "key_set"
	DependencyTokenStore   = "token_store"
)

// Dependencies lists them in a fixed order.
var Dependencies = []string{DependencyPolicyEngine, DependencyKeySet, DependencyTokenStore}

const (
	// probeInterval is how often each dependency is checked, probeTimeout how long one check may
	// take, and probeMaxAge how old the last success may be for the dependency to count as up. A
	// prober that stops checking is therefore reported down within probeMaxAge.
	probeInterval = 5 * time.Second
	probeTimeout  = 2 * time.Second
	probeMaxAge   = 8 * time.Second
)

// probeSource is the source of the policy probe's input: no participant, so the rule set must deny.
const probeSource = "spiffe://probe.invalid/ns/ztd-guard/sa/dependency-probe"

// Prober checks the guard's dependencies, each on the path the guard itself uses and without a side
// effect: the policy engine answers a request it must deny with a valid denial, the connector's key
// set holds a key the verifier would use, the token store answers ready. It reports; it never
// decides a request: every request is still refused at request time when a dependency fails it.
type Prober struct {
	cfg    Config
	client *http.Client
	post   func(ctx context.Context, target string, input, output any) (int, error)
	now    func() time.Time

	mu    sync.Mutex
	state map[string]probeState
}

type probeState struct {
	ok          bool      // the last check succeeded
	lastSuccess time.Time // zero until one has
}

// NewProber builds the prober from the guard's configuration; New has validated it.
func NewProber(cfg Config) *Prober {
	cfg.PolicyURL = strings.TrimRight(cfg.PolicyURL, "/")
	cfg.StoreURL = strings.TrimRight(cfg.StoreURL, "/")
	clients := NewClients(cfg.PolicyURL, cfg.StoreURL)
	clients.HTTP.Timeout = probeTimeout
	return &Prober{cfg: cfg, client: clients.HTTP, post: clients.post, now: time.Now, state: map[string]probeState{}}
}

// Run checks every dependency at once and then every probeInterval, each on its own schedule, until
// ctx ends.
func (p *Prober) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, dependency := range Dependencies {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(probeInterval)
			defer ticker.Stop()
			for {
				p.Check(ctx, dependency)
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	}
	wg.Wait()
}

// Check runs one check of one dependency and records its result.
func (p *Prober) Check(ctx context.Context, dependency string) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	var err error
	switch dependency {
	case DependencyPolicyEngine:
		err = p.checkPolicy(ctx)
	case DependencyKeySet:
		err = p.checkKeySet(ctx)
	case DependencyTokenStore:
		err = p.checkStore(ctx)
	default:
		err = errors.New("unknown dependency")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.state[dependency]
	s.ok = err == nil
	if s.ok {
		s.lastSuccess = p.now()
	}
	p.state[dependency] = s
}

func (p *Prober) checkPolicy(ctx context.Context) error {
	in := hook.Input{CorrelationID: "dependency-probe", Source: hook.Source{SPIFFEID: probeSource},
		Request: hook.RequestInfo{Method: http.MethodPost, Path: restPath, Host: "dependency-probe.invalid"}}
	var out hook.Decision
	status, err := p.post(ctx, p.cfg.PolicyURL+"/decision", in, &out)
	if err != nil || status != http.StatusOK || out.Validate() != nil || out.Allow || out.ReasonCode != hook.ReasonRuleDeny {
		return errors.New("policy engine did not deny the probe")
	}
	return nil
}

func (p *Prober) checkKeySet(ctx context.Context) error {
	return p.get(ctx, p.cfg.JWKSURL, tokenverify.CheckKeySet)
}

func (p *Prober) checkStore(ctx context.Context) error {
	return p.get(ctx, p.cfg.StoreURL+"/readyz", func([]byte) error { return nil })
}

// get fetches target, which must answer 200 within 1 MiB, and checks the body.
func (p *Prober) get(ctx context.Context, target string, check func([]byte) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil || resp.StatusCode != http.StatusOK || len(body) > 1<<20 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return check(body)
}

// Up reports, for every dependency, whether it is up now: its last check succeeded and that success
// is at most probeMaxAge old. A dependency never checked is down.
func (p *Prober) Up() map[string]bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	up := make(map[string]bool, len(Dependencies))
	for _, dependency := range Dependencies {
		s := p.state[dependency]
		up[dependency] = s.ok && !s.lastSuccess.IsZero() && now.Sub(s.lastSuccess) <= probeMaxAge
	}
	return up
}

// Down lists the dependencies that are not up, in the fixed order.
func (p *Prober) Down() []string {
	up := p.Up()
	var down []string
	for _, dependency := range Dependencies {
		if !up[dependency] {
			down = append(down, dependency)
		}
	}
	return down
}

// Refusals counts the guard's refusals by reason code. A code outside the known set is counted as
// "other", so the label set stays bounded.
type Refusals struct {
	mu     sync.Mutex
	counts map[string]int64
}

func (r *Refusals) add(code string) {
	if !knownRefusalCodes[code] {
		code = "other"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.counts == nil {
		r.counts = map[string]int64{}
	}
	r.counts[code]++
}

// knownRefusalCodes are the codes a refusal can carry: the guard's own, the verifier's and the
// hook's registry.
var knownRefusalCodes = func() map[string]bool {
	known := map[string]bool{}
	for _, code := range []string{"route_denied", "host_denied", "mesh_caller_denied",
		"token_absent", "proof_absent", "token_malformed", "signature_invalid", "token_expired",
		"issuer_mismatch", "audience_mismatch", "scope_insufficient", "key_binding_mismatch",
		"proof_invalid", "proof_replayed", "key_set_unavailable", "request_invalid",
		"replay_unavailable", "unclassified"} {
		known[code] = true
	}
	for _, code := range hook.KnownCodes() {
		known[code] = true
	}
	return known
}()

// WriteMetrics writes the Prometheus text exposition of the dependency states and the refusals.
// Every dependency's series is always present, 0 until it has been checked up.
func WriteMetrics(w io.Writer, prober *Prober, refusals *Refusals) {
	up := prober.Up()
	var b strings.Builder
	b.WriteString("# HELP ztd_guard_dependency_up Whether the guard's last check of the dependency succeeded, at most 8 s ago.\n# TYPE ztd_guard_dependency_up gauge\n")
	for _, dependency := range Dependencies {
		value := 0
		if up[dependency] {
			value = 1
		}
		fmt.Fprintf(&b, "ztd_guard_dependency_up{dependency=%q} %d\n", dependency, value)
	}
	b.WriteString("# HELP ztd_guard_refusals_total Requests the guard refused, by reason code.\n# TYPE ztd_guard_refusals_total counter\n")
	refusals.mu.Lock()
	codes := make([]string, 0, len(refusals.counts))
	for code := range refusals.counts {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	for _, code := range codes {
		fmt.Fprintf(&b, "ztd_guard_refusals_total{reason_code=%q} %d\n", code, refusals.counts[code])
	}
	refusals.mu.Unlock()
	_, _ = io.WriteString(w, b.String())
}
