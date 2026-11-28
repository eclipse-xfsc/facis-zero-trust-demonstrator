package policyevaluator

import (
	"bytes"
	"encoding/json"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTSAAdapterPassesValidDecisionsAndFailsClosed(t *testing.T) {
	const guard = "spiffe://zone-b.test/ns/m3/sa/ztd-guard"
	type reply struct {
		answer string
		delay  time.Duration
	}
	var current atomic.Pointer[reply]
	tsa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" || r.URL.Path != "/policy/policies/facis/guard/1.0/evaluation" {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		rep := current.Load()
		time.Sleep(rep.delay)
		_, _ = io.WriteString(w, rep.answer)
	}))
	defer tsa.Close()
	var logs, events bytes.Buffer
	adapter, err := NewTSA(TSAConfig{EvaluationURL: tsa.URL + "/policy/policies/facis/guard/1.0/evaluation", TimeoutMS: 200},
		[]string{guard}, slog.New(slog.NewJSONHandler(&logs, nil)), hook.NewLogSinkV2(&events, "policy-b", "tsa-test"))
	if err != nil {
		t.Fatal(err)
	}
	input := `{"correlation_id":"c-1","source":{"spiffe_id":"spiffe://zone-b.test/ns/m3/sa/p"},"request":{"method":"POST","path":"/demo","host":"h"},"token":{"present":false},"tenant":null}`
	call := func(caller string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/decision", strings.NewReader(input))
		req.Header.Set("X-Forwarded-Client-Cert", "URI="+caller)
		rec := httptest.NewRecorder()
		adapter.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	allow := `{"decision":{"allow":true,"rule_id":"m3-report-summary","bundle_revision":"v1","obligations":["substitute_upstream_token"]},"selected":"report:summary"}`
	deny := `{"decision":{"allow":false,"reason_code":"POL-RULE-DENY","rule_id":"m3-scope-withdrawn","bundle_revision":"v2","deny_body":{"error":"access_denied"}}}`
	for name, c := range map[string]struct {
		answer string
		delay  time.Duration
		status int
	}{
		"allow":                {allow, 0, http.StatusOK},
		"deny":                 {deny, 0, http.StatusOK},
		"no rule":              {`{"decision":{"allow":true,"bundle_revision":"v1","obligations":["substitute_upstream_token"]}}`, 0, http.StatusServiceUnavailable},
		"no revision":          {`{"decision":{"allow":false,"reason_code":"POL-RULE-DENY","rule_id":"r","deny_body":{"error":"x"}}}`, 0, http.StatusServiceUnavailable},
		"outside contract":     {`{"decision":{"allow":true,"rule_id":"r","bundle_revision":"v1","extra":1}}`, 0, http.StatusServiceUnavailable},
		"no decision":          {`{"request_ok":true}`, 0, http.StatusServiceUnavailable},
		"null reason":          {`{"decision":{"allow":true,"rule_id":"r","bundle_revision":"v1","obligations":["substitute_upstream_token"],"reason_code":null}}`, 0, http.StatusServiceUnavailable},
		"null deny body":       {`{"decision":{"allow":true,"rule_id":"r","bundle_revision":"v1","obligations":["substitute_upstream_token"],"deny_body":null}}`, 0, http.StatusServiceUnavailable},
		"duplicate obligation": {`{"decision":{"allow":true,"rule_id":"r","bundle_revision":"v1","obligations":["substitute_upstream_token","substitute_upstream_token"]}}`, 0, http.StatusServiceUnavailable},
		"oversized rule":       {`{"decision":{"allow":true,"rule_id":"` + strings.Repeat("r", 257) + `","bundle_revision":"v1","obligations":["substitute_upstream_token"]}}`, 0, http.StatusServiceUnavailable},
		"null revision":        {`{"decision":{"allow":true,"rule_id":"r","bundle_revision":null,"obligations":["substitute_upstream_token"]}}`, 0, http.StatusServiceUnavailable},
		"bad link":             {`{"decision":{"allow":false,"reason_code":"POL-PRESENTATION-REQUIRED","rule_id":"r","bundle_revision":"v1","deny_body":{"error":"x","oid4vp_link":"not a uri"}}}`, 0, http.StatusServiceUnavailable},
		"presentation":         {`{"decision":{"allow":false,"reason_code":"POL-PRESENTATION-REQUIRED","rule_id":"r","bundle_revision":"v1","deny_body":{"error":"presentation_required","oid4vp_link":"https://zone-a.example/present?challenge=x"}}}`, 0, http.StatusOK},
		"error result":         {`{"id":"x","kind":0,"message":"policy not found"}`, 0, http.StatusServiceUnavailable},
		"slower than bound":    {allow, 400 * time.Millisecond, http.StatusServiceUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			current.Store(&reply{c.answer, c.delay})
			logs.Reset()
			events.Reset()
			start := time.Now()
			status, body := call(guard)
			if status != c.status {
				t.Fatalf("status %d (%s), want %d", status, body, c.status)
			}
			if time.Since(start) > 350*time.Millisecond {
				t.Fatalf("answered after %v, beyond the bound", time.Since(start))
			}
			var entry map[string]any
			if err := json.Unmarshal(logs.Bytes(), &entry); err != nil || entry["correlation_id"] != "c-1" {
				t.Fatalf("decision not logged: %s", logs.String())
			}
			if c.status == http.StatusOK && (entry["rule_id"] == "" || entry["rule_id"] == nil || entry["bundle_revision"] == nil) {
				t.Fatalf("decision log lacks rule or revision: %s", logs.String())
			}
			if c.status != http.StatusOK && !strings.Contains(body, "POL-PDP-UNAVAILABLE") {
				t.Fatalf("failure body %s", body)
			}
			// The IF-01 v2 decision event: the TSA's rule and revision, or not_evaluated when it failed.
			ev := checkV2Event(t, events.Bytes())
			if ev.CorrelationID != "c-1" || ev.Source != "policy-b" {
				t.Fatalf("event %+v", ev)
			}
			if c.status == http.StatusOK {
				var answer hook.Decision
				_ = json.Unmarshal([]byte(body), &answer)
				if ev.Payload.RuleID != answer.RuleID || ev.Payload.BundleRevision != answer.BundleRevision || (ev.Payload.State == "allowed") != answer.Allow {
					t.Fatalf("event %+v does not carry the decision %+v", ev.Payload, answer)
				}
			} else if ev.Payload.State != "denied" || ev.Payload.ReasonCode != hook.ReasonPDPUnavailable || ev.Payload.RuleID != hook.NotEvaluated || ev.Payload.BundleRevision != hook.NotEvaluated {
				t.Fatalf("failure event %+v", ev.Payload)
			}
		})
	}
	current.Store(&reply{allow, 0})
	if status, _ := call("spiffe://zone-b.test/ns/m3/sa/intruder"); status != http.StatusForbidden {
		t.Fatalf("unlisted caller: %d", status)
	}
	if _, err := NewTSA(TSAConfig{EvaluationURL: tsa.URL, TimeoutMS: 1000}, []string{guard}, slog.Default(), nil); err == nil {
		t.Fatal("a timeout at the guard's bound accepted")
	}
}

func TestDecisionSchemaIsTheContract(t *testing.T) {
	published, err := os.ReadFile("../../docs/contracts/if05-policy-decision.v1.schema.json")
	if err != nil || !bytes.Equal(published, decisionSchemaJSON) {
		t.Fatal("services/policyevaluator/if05-policy-decision.v1.schema.json differs from the contract")
	}
}
