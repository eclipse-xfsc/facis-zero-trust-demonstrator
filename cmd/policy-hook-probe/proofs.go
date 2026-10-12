package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/policy-hook-probe/internal/hook"
)

// proofOrder is the order "prove all" runs the proofs in: the fail-closed proof kills the hook,
// so it comes last.
var proofOrder = []string{"header-mutation", "deny-response", "filter-parity", "latency", "fail-closed"}

func (h *harness) proofs() map[string]func(context.Context) error {
	return map[string]func(context.Context) error{
		"header-mutation": h.proveHeaderMutation,
		"deny-response":   h.proveDenyResponse,
		"filter-parity":   h.proveFilterParity,
		"latency":         h.proveLatency,
		"fail-closed":     h.proveFailClosed,
	}
}

// --- header mutation ------------------------------------------------------------------------

// headerMutationRecord is one allowed request as the caller sent it and as the upstream saw it.
type headerMutationRecord struct {
	RequestSent   map[string][]string `json:"request_sent"`
	Status        int                 `json:"status"`
	Refusal       *hook.Refusal       `json:"refusal,omitempty"`
	Upstream      *echoRecord         `json:"upstream"`
	Expected      map[string]string   `json:"expected"`
	DecisionEvent *hook.Event         `json:"decision_event"`
	Checks        map[string]bool     `json:"checks"`
}

func (h *harness) proveHeaderMutation(ctx context.Context) error {
	if err := h.useEnvoy(ctx, filterExtAuthz); err != nil {
		return err
	}
	sent := callerHeaders("DPoP " + hook.FixtureTokenRead)
	resp, err := h.send(ctx, "/api/data?q=1", sent)
	if err != nil {
		return err
	}
	rec := headerMutationRecord{RequestSent: sent, Status: resp.Status, Refusal: resp.Refusal, Upstream: resp.Upstream,
		Expected: map[string]string{"authorization": upstreamAuthorization, "dpop": upstreamProof}, Checks: map[string]bool{}}
	rec.Checks["forwarded"] = resp.Status == http.StatusOK && resp.Upstream != nil
	if resp.Upstream == nil {
		return h.writeJSON("upstream-seen.json", rec)
	}
	seen := resp.Upstream.Headers
	get := func(name string) string {
		if v := seen[http.CanonicalHeaderKey(name)]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	absent := func(name string) bool { _, ok := seen[http.CanonicalHeaderKey(name)]; return !ok }
	requestID := get("X-Request-Id")
	rec.Checks["authorization_substituted"] = get("Authorization") == upstreamAuthorization
	rec.Checks["dpop_substituted"] = get("DPoP") == upstreamProof
	rec.Checks["caller_credential_not_forwarded"] = get("DPoP") != sent.Get("DPoP") && get("Authorization") != sent.Get("Authorization")
	rec.Checks["facis_headers_removed"] = true
	for name := range seen {
		if hook.IsFacisHeader(name) {
			rec.Checks["facis_headers_removed"] = false
		}
	}
	rec.Checks["forwarded_headers_removed"] = absent("X-Forwarded-For") && absent("X-Forwarded-Host") && absent("Forwarded") && absent("X-Forwarded-Proto")
	rec.Checks["traceparent_propagated"] = get("Traceparent") == sent.Get("Traceparent")
	rec.Checks["request_id_replaced"] = requestID != "" && requestID != sent.Get("X-Request-Id")
	f, err := os.Open(h.eventsPath())
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if rec.DecisionEvent, err = hook.ReadEvent(f, requestID); err != nil {
		return err
	}
	e := rec.DecisionEvent
	rec.Checks["request_id_is_correlation_id"] = e != nil && e.CorrelationID == requestID && e.Kind == "decision" && e.Payload.State == "allowed"
	return h.writeJSON("upstream-seen.json", rec)
}

// --- deny response --------------------------------------------------------------------------

// denyRecord is one refused request: what the decision fixture says and what the caller got.
type denyRecord struct {
	Case           string          `json:"case"`
	Decision       hook.Decision   `json:"decision"`
	ExpectedStatus int             `json:"expected_status"`
	Status         int             `json:"status"`
	ContentType    string          `json:"content_type"`
	ReasonHeader   string          `json:"reason_header"`
	RequestID      string          `json:"request_id"`
	Body           *hook.Refusal   `json:"body"`
	Checks         map[string]bool `json:"checks"`
}

func (h *harness) proveDenyResponse(ctx context.Context) error {
	if err := h.useEnvoy(ctx, filterExtAuthz); err != nil {
		return err
	}
	var records []denyRecord
	for _, c := range h.fx.Cases() {
		if c.Decision.Allow {
			continue
		}
		resp, err := h.send(ctx, "/api/data", callerHeaders(c.Authorization))
		if err != nil {
			return err
		}
		rec := denyRecord{Case: c.Name, Decision: c.Decision, ExpectedStatus: hook.StatusFor(c.Decision.ReasonCode), Status: resp.Status,
			ContentType: resp.Headers.Get("Content-Type"), ReasonHeader: resp.Headers.Get(hook.HeaderReasonCode),
			RequestID: resp.Headers.Get(hook.HeaderRequestID), Body: resp.Refusal, Checks: map[string]bool{}}
		b := resp.Refusal
		rec.Checks["status"] = rec.Status == rec.ExpectedStatus
		rec.Checks["content_type_json"] = rec.ContentType == hook.ContentTypeJSON
		rec.Checks["reason_header"] = rec.ReasonHeader == c.Decision.ReasonCode
		rec.Checks["request_id_present"] = rec.RequestID != ""
		rec.Checks["body"] = b != nil && b.ReasonCode == c.Decision.ReasonCode && b.Error == c.Decision.DenyBody.Error &&
			b.RuleID == c.Decision.RuleID && b.OID4VPLink == c.Decision.DenyBody.OID4VPLink
		records = append(records, rec)
	}
	return h.writeJSON("responses.json", map[string]any{"cases": records})
}

// --- filter parity --------------------------------------------------------------------------

// decisionRecord is one case as the caller and the upstream saw it, with what differs per
// request or per Envoy (dates, server, request ids, Envoy's own headers) normalised away.
type decisionRecord struct {
	Case            string            `json:"case"`
	Status          int               `json:"status"`
	Headers         map[string]string `json:"headers"`
	Body            *hook.Refusal     `json:"body,omitempty"`
	UpstreamHeaders map[string]string `json:"upstream_headers,omitempty"`
}

func (h *harness) proveFilterParity(ctx context.Context) error {
	cases := h.fx.Cases()
	rendered := map[string]string{}
	decisions := map[string][]decisionRecord{}
	for _, filter := range []string{filterExtAuthz, filterExtProc} {
		if err := h.useEnvoy(ctx, filter); err != nil {
			return err
		}
		cfg, err := h.render(filter)
		if err != nil {
			return err
		}
		rendered[filter] = cfg
		if err := h.writeText("envoy-"+filter+".yaml", cfg); err != nil {
			return err
		}
		for _, c := range cases {
			resp, err := h.send(ctx, "/api/data", callerHeaders(c.Authorization))
			if err != nil {
				return err
			}
			rec := decisionRecord{Case: c.Name, Status: resp.Status, Headers: normalise(resp.Headers), Body: resp.Refusal}
			if resp.Upstream != nil {
				rec.UpstreamHeaders = normalise(resp.Upstream.Headers)
			}
			decisions[filter] = append(decisions[filter], rec)
		}
		if err := h.writeJSON("decisions-"+filter+".json", decisions[filter]); err != nil {
			return err
		}
	}
	a, _ := json.MarshalIndent(decisions[filterExtAuthz], "", "  ")
	b, _ := json.MarshalIndent(decisions[filterExtProc], "", "  ")
	diff := lineDiff("decisions-ext-authz.json", string(a), "decisions-ext-proc.json", string(b))
	_, blockA, _, err := splitFilterBlock(rendered[filterExtAuthz])
	if err != nil {
		return err
	}
	_, blockB, _, err := splitFilterBlock(rendered[filterExtProc])
	if err != nil {
		return err
	}
	if err := h.writeText("filter-switch.diff", lineDiff("envoy-ext-authz.yaml (filter block)", blockA, "envoy-ext-proc.yaml (filter block)", blockB)); err != nil {
		return err
	}
	outside, err := identicalOutsideFilterBlock(rendered[filterExtAuthz], rendered[filterExtProc])
	if err != nil {
		return err
	}
	return h.writeJSON("parity.json", map[string]any{
		"cases": len(cases), "decisions_identical": diff == "", "decisions_diff": diff, "configs_identical_outside_filter": outside,
	})
}

// normalise lower-cases header names, joins values, drops what Envoy varies per response and
// per instance, and keeps only the presence of the per-request id.
func normalise(h map[string][]string) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		name := strings.ToLower(k)
		switch {
		case name == "date", name == "server", strings.HasPrefix(name, "x-envoy-"):
		case name == hook.HeaderRequestID:
			out[name] = "<present>"
		default:
			out[name] = strings.Join(v, ", ")
		}
	}
	return out
}

// --- latency --------------------------------------------------------------------------------

type latencyRun struct {
	Filter string `json:"filter"`
	loadResult
}

type latencyAdded struct {
	Filter      string  `json:"filter"`
	Concurrency int     `json:"concurrency"`
	P50Ms       float64 `json:"p50_ms"`
	P95Ms       float64 `json:"p95_ms"`
	P99Ms       float64 `json:"p99_ms"`
}

// latencyRecord is the measurement of the three bootstraps; Added is each hook bootstrap minus
// the no-hook one at the same concurrency.
type latencyRecord struct {
	Requests  int            `json:"requests"`
	Warmup    int            `json:"warmup"`
	TimeoutMs float64        `json:"timeout_ms"`
	Runs      []latencyRun   `json:"runs"`
	Added     []latencyAdded `json:"added"`
	AllOK     bool           `json:"all_ok"`
}

func (h *harness) proveLatency(ctx context.Context) error {
	var concurrencies []int
	for s := range strings.SplitSeq(h.o.concurrency, ",") {
		c, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || c < 1 {
			return fmt.Errorf("--concurrency: %q is not a positive integer", s)
		}
		concurrencies = append(concurrencies, c)
	}
	rec := latencyRecord{Requests: h.o.requests, Warmup: h.o.warmup, TimeoutMs: millis(h.o.timeout), AllOK: true}
	baseline := map[int]loadResult{}
	for _, filter := range []string{filterBaseline, filterExtAuthz, filterExtProc} {
		if err := h.useEnvoy(ctx, filter); err != nil {
			return err
		}
		runLoad(ctx, h.client, h.allowedRequest, h.o.warmup, 8)
		for _, c := range concurrencies {
			h.logf("latency: %s, concurrency %d, %d requests", filter, c, h.o.requests)
			res := runLoad(ctx, h.client, h.allowedRequest, h.o.requests, c)
			if res.Errors > 0 || len(res.Statuses) != 1 || res.Statuses[http.StatusOK] != h.o.requests {
				rec.AllOK = false
			}
			rec.Runs = append(rec.Runs, latencyRun{Filter: filter, loadResult: res})
			if filter == filterBaseline {
				baseline[c] = res
				continue
			}
			b := baseline[c]
			rec.Added = append(rec.Added, latencyAdded{Filter: filter, Concurrency: c,
				P50Ms: round3(res.P50Ms - b.P50Ms), P95Ms: round3(res.P95Ms - b.P95Ms), P99Ms: round3(res.P99Ms - b.P99Ms)})
		}
	}
	return h.writeJSON("latency.json", rec)
}

func round3(f float64) float64 { return float64(int64(f*1000+0.5*sign(f))) / 1000 }

func sign(f float64) float64 {
	if f < 0 {
		return -1
	}
	return 1
}

// --- fail closed ----------------------------------------------------------------------------

type burstResponse struct {
	Worker      int     `json:"worker"`
	StartedMs   float64 `json:"started_ms"`
	DurationMs  float64 `json:"duration_ms"`
	AfterStrike bool    `json:"after_strike"`
	Status      int     `json:"status"`
	ReasonCode  string  `json:"reason_code,omitempty"`
	Error       string  `json:"error,omitempty"`
}

// burstRecord is what happened to a stream of requests while the hook died or froze under them:
// the aggregates, the responses around the strike, and every anomaly — a request after the strike
// not refused as it must be, or one that outlived the bound.
type burstRecord struct {
	// Mode is "killed" (the process ended, its connections reset) or "frozen" (the process
	// stopped answering with its connections open, so only the timeout ends a call).
	Mode                   string          `json:"mode"`
	Workers                int             `json:"workers"`
	WindowMs               float64         `json:"window_ms"`
	TimeoutMs              float64         `json:"timeout_ms"`
	MarginMs               float64         `json:"margin_ms"`
	StruckAtMs             float64         `json:"struck_at_ms"`
	Sent                   int             `json:"sent"`
	Completed              int             `json:"completed"`
	Errors                 int             `json:"errors"`
	BeforeStrike           int             `json:"before_strike"`
	BeforeStrikeStatuses   map[int]int     `json:"before_strike_statuses"`
	AfterStrike            int             `json:"after_strike"`
	AfterStrikeUnavailable int             `json:"after_strike_unavailable"`
	AfterStrikeStatuses    map[int]int     `json:"after_strike_statuses"`
	AfterStrikeMinMs       float64         `json:"after_strike_min_ms"`
	AfterStrikeMedianMs    float64         `json:"after_strike_median_ms"`
	AfterStrikeP99Ms       float64         `json:"after_strike_p99_ms"`
	MaxDurationMs          float64         `json:"max_duration_ms"`
	AllCompleted           bool            `json:"all_completed"`
	AllWithinBound         bool            `json:"all_within_bound"`
	AllAfterStrikeRefused  bool            `json:"all_after_strike_refused"`
	Samples                []burstResponse `json:"samples"`
	Anomalies              []burstResponse `json:"anomalies"`
}

// recoveryRecord is what happened once the hook was running again.
type recoveryRecord struct {
	Attempts int `json:"attempts"`
	// Statuses counts every answer; AfterRecoveryStatuses those after the first success, which
	// must all be 200.
	Statuses              map[int]int `json:"statuses"`
	AfterRecoveryStatuses map[int]int `json:"after_recovery_statuses"`
	FirstSuccessAfterMs   float64     `json:"first_success_after_ms"`
	Recovered             bool        `json:"recovered"`
}

func (h *harness) proveFailClosed(ctx context.Context) error {
	if err := h.useEnvoy(ctx, filterExtAuthz); err != nil {
		return err
	}
	runLoad(ctx, h.client, h.allowedRequest, 20, 1)
	killed := h.burst(ctx, "killed", func() { h.adapter.kill() })
	if err := h.writeJSON("killed.json", killed); err != nil {
		return err
	}
	var err error
	if h.adapter, err = h.adapter.restart(ctx); err != nil {
		return err
	}
	afterKill := h.recover(ctx)
	frozen := h.burst(ctx, "frozen", func() { _ = h.adapter.freeze() })
	if err := h.writeJSON("frozen.json", frozen); err != nil {
		return err
	}
	if h.adapter, err = h.adapter.restart(ctx); err != nil {
		return err
	}
	afterFreeze := h.recover(ctx)
	return h.writeJSON("recovery.json", map[string]recoveryRecord{"after_kill": afterKill, "after_freeze": afterFreeze})
}

// burst keeps 16 workers sending allowed requests back to back for a window, strikes the hook a
// quarter of the way in, and records what happened.
func (h *harness) burst(ctx context.Context, mode string, strike func()) burstRecord {
	const workers = 16
	window := 4 * (h.o.timeout + 250*time.Millisecond)
	rec := burstRecord{Mode: mode, Workers: workers, WindowMs: millis(window), TimeoutMs: millis(h.o.timeout), MarginMs: millis(h.o.margin),
		BeforeStrikeStatuses: map[int]int{}, AfterStrikeStatuses: map[int]int{}, Samples: []burstResponse{}, Anomalies: []burstResponse{}}
	var (
		mu        sync.Mutex
		wg        sync.WaitGroup
		struckAt  time.Time
		responses []burstResponse
		completed = make(chan struct{})
		start     = time.Now()
	)
	for w := range workers {
		wg.Go(func() {
			for time.Since(start) < window {
				t := time.Now()
				resp, err := h.send(ctx, "/api/data", callerHeaders("DPoP "+hook.FixtureTokenRead))
				r := burstResponse{Worker: w, StartedMs: millis(t.Sub(start)), DurationMs: millis(time.Since(t)), Status: resp.Status}
				if err != nil {
					r.Error = err.Error()
				}
				if resp.Refusal != nil {
					r.ReasonCode = resp.Refusal.ReasonCode
				}
				mu.Lock()
				r.AfterStrike = !struckAt.IsZero() && t.After(struckAt)
				responses = append(responses, r)
				mu.Unlock()
			}
		})
	}
	go func() {
		time.Sleep(window / 4)
		mu.Lock()
		struckAt = time.Now()
		mu.Unlock()
		strike()
	}()
	go func() { wg.Wait(); close(completed) }()
	select {
	case <-completed:
		rec.AllCompleted = true
	case <-time.After(window + h.o.timeout + h.o.margin + 10*time.Second):
	}
	mu.Lock()
	defer mu.Unlock()
	rec.StruckAtMs = millis(struckAt.Sub(start))
	rec.Sent = len(responses)
	rec.AllWithinBound, rec.AllAfterStrikeRefused = true, true
	bound := millis(h.o.timeout + h.o.margin)
	sort.Slice(responses, func(i, j int) bool { return responses[i].StartedMs < responses[j].StartedMs })
	var after []time.Duration
	for _, r := range responses {
		if r.Error != "" {
			rec.Errors++
		} else {
			rec.Completed++
		}
		rec.MaxDurationMs = max(rec.MaxDurationMs, r.DurationMs)
		anomaly := r.DurationMs > bound
		if anomaly {
			rec.AllWithinBound = false
		}
		if !r.AfterStrike {
			rec.BeforeStrike++
			rec.BeforeStrikeStatuses[r.Status]++
		} else {
			rec.AfterStrike++
			rec.AfterStrikeStatuses[r.Status]++
			after = append(after, time.Duration(r.DurationMs*float64(time.Millisecond)))
			if r.Error == "" && r.Status == http.StatusServiceUnavailable && r.ReasonCode == hook.ReasonPDPUnavailable {
				rec.AfterStrikeUnavailable++
			} else {
				rec.AllAfterStrikeRefused = false
				anomaly = true
			}
		}
		if anomaly {
			rec.Anomalies = append(rec.Anomalies, r)
		}
	}
	if rec.AfterStrike == 0 {
		rec.AllAfterStrikeRefused = false
	}
	p50, _, p99, _ := percentiles(after)
	rec.AfterStrikeMedianMs, rec.AfterStrikeP99Ms = millis(p50), millis(p99)
	if len(after) > 0 {
		sort.Slice(after, func(i, j int) bool { return after[i] < after[j] })
		rec.AfterStrikeMinMs = millis(after[0])
	}
	first := sort.Search(len(responses), func(i int) bool { return responses[i].AfterStrike })
	rec.Samples = append(rec.Samples, responses[max(0, first-20):first]...)
	rec.Samples = append(rec.Samples, responses[first:min(len(responses), first+20)]...)
	return rec
}

// recover sends allowed requests until one succeeds, then a few more, and records the statuses.
func (h *harness) recover(ctx context.Context) recoveryRecord {
	rec := recoveryRecord{Statuses: map[int]int{}, AfterRecoveryStatuses: map[int]int{}}
	start := time.Now()
	for time.Since(start) < 10*time.Second && rec.AfterRecoveryStatuses[http.StatusOK] < 20 {
		resp, err := h.send(ctx, "/api/data", callerHeaders("DPoP "+hook.FixtureTokenRead))
		rec.Attempts++
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		rec.Statuses[resp.Status]++
		if rec.Recovered {
			rec.AfterRecoveryStatuses[resp.Status]++
		} else if resp.Status == http.StatusOK {
			rec.Recovered = true
			rec.FirstSuccessAfterMs = millis(time.Since(start))
			rec.AfterRecoveryStatuses[resp.Status]++
		}
	}
	return rec
}
