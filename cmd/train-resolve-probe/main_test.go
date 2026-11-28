package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	teemA = "783431065396a0483425b016f6925a321dee6c2146c5ab7244833aa888ebb60c"
	keyB  = "spiffe://zone-b.facis-ztd.local/gateway"
)

// resolver is a Trust Content Resolver stand-in that answers with the entry it is told to hold,
// for any issuer; nil means a verified list without an entry.
type resolver struct {
	mu     sync.Mutex
	values []string
	absent bool
	calls  int
	srv    *httptest.Server
}

func newResolver(t *testing.T, values ...string) *resolver {
	r := &resolver{values: values}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Issuer string `json:"issuer"`
		}
		_ = json.NewDecoder(req.Body).Decode(&body)
		r.mu.Lock()
		r.calls++
		values, absent := r.values, r.absent
		r.mu.Unlock()
		ep := map[string]any{"vcUri": "vc", "tlUri": "tl", "vcVerified": true}
		if !absent {
			certs := []map[string]string{}
			for _, v := range values {
				certs = append(certs, map[string]string{"Type": "TEEM-sha256", "Value": v})
			}
			ep["trustList"] = map[string]any{
				"UUID":           "u1",
				"TSPInformation": map[string]any{"TSPCertificationList": map[string]any{"TSPCertification": certs}},
				"TSPServices":    map[string]any{"TSPService": []map[string]any{{"ServiceTypeIdentifier": body.Issuer}}},
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"trustSchemePointers": []map[string]any{{"pointer": "zone-b.facis-ztd.local", "dids": []string{"did:web:x"}}},
			"resolvedResults":     []map[string]any{{"did": "did:web:x", "resolvedDoc": map[string]any{"endpoints": []any{ep}}}},
		})
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *resolver) set(absent bool, values ...string) {
	r.mu.Lock()
	r.values, r.absent = values, absent
	r.mu.Unlock()
}

func records(t *testing.T, out string) []map[string]any {
	t.Helper()
	var recs []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("not a JSON line: %q", line)
		}
		recs = append(recs, m)
	}
	return recs
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"-tcr", "http://127.0.0.1:1"},
		{"-identity", keyB},
		{"-tcr", "http://127.0.0.1:1", "-identity", keyB, "extra"},
		{"-tcr", "http://127.0.0.1:1", "-identity", keyB, "-repeat", "0"},
		{"-tcr", "not a url", "-identity", keyB},
		{"-tcr", "http://127.0.0.1:1/path", "-identity", keyB},
		{"-tcr", "http://127.0.0.1:1", "-identity", keyB, "-ca", filepath.Join(t.TempDir(), "missing.pem")},
		{"-tcr", "http://127.0.0.1:1", "-identity", keyB, "-nope"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 1 {
			t.Errorf("%v: exit %d, want 1 (stderr %q)", args, code, stderr.String())
		}
	}
}

func TestAcceptedThenServedFromTheCache(t *testing.T) {
	r := newResolver(t, teemA)
	var stdout, stderr bytes.Buffer
	rec := filepath.Join(t.TempDir(), "records.jsonl")
	code := run([]string{"-tcr", r.srv.URL, "-identity", keyB, "-digest", teemA, "-repeat", "2", "-interval", "0", "-record", rec}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	recs := records(t, stdout.String())
	if len(recs) != 2 {
		t.Fatalf("%d records", len(recs))
	}
	first, second := recs[0], recs[1]
	if first["outcome"] != "accepted" || first["fromCache"] != false || first["key"] != keyB || first["entryUUID"] != "u1" || first["expectedCount"] != float64(1) {
		t.Fatalf("first = %v", first)
	}
	if ptrs, _ := first["pointers"].([]any); len(ptrs) != 1 || ptrs[0] != "zone-b.facis-ztd.local" {
		t.Fatalf("pointers = %v", first["pointers"])
	}
	if second["fromCache"] != true || r.calls != 1 {
		t.Fatalf("second = %v, resolver asked %d times", second, r.calls)
	}
	file, err := os.ReadFile(rec)
	if err != nil || len(records(t, string(file))) != 2 {
		t.Fatalf("record file: %v, %d lines", err, len(records(t, string(file))))
	}
}

func TestRefusedCarriesTheCode(t *testing.T) {
	r := newResolver(t, teemA)
	var stdout, stderr bytes.Buffer
	other := strings.Repeat("0842477b", 8)
	code := run([]string{"-tcr", r.srv.URL, "-identity", keyB, "-digest", other}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d", code)
	}
	rec := records(t, stdout.String())[0]
	if rec["outcome"] != "refused" || rec["code"] != "CHAN-MEASUREMENT-MISMATCH" || rec["expectedCount"] != float64(1) || !strings.Contains(rec["reason"].(string), other[:12]) {
		t.Fatalf("record = %v", rec)
	}
	stdout.Reset()
	if code := run([]string{"-tcr", r.srv.URL, "-identity", keyB}, &stdout, &stderr); code != 2 {
		t.Fatalf("no digest: exit %d", code)
	}
	if rec := records(t, stdout.String())[0]; rec["code"] != "CHAN-MEASUREMENT-MISMATCH" || !strings.Contains(rec["reason"].(string), "no well-formed") {
		t.Fatalf("record = %v", rec)
	}
	stdout.Reset()
	r.set(true)
	if code := run([]string{"-tcr", r.srv.URL, "-identity", keyB, "-digest", teemA}, &stdout, &stderr); code != 2 {
		t.Fatalf("absent: exit %d", code)
	}
	if rec := records(t, stdout.String())[0]; rec["code"] != "CHAN-MEASUREMENT-UNPUBLISHED" || rec["expectedCount"] != float64(0) {
		t.Fatalf("record = %v", rec)
	}
	stdout.Reset()
	r.srv.Close()
	if code := run([]string{"-tcr", r.srv.URL, "-identity", keyB, "-digest", teemA, "-resolve-timeout", "2s"}, &stdout, &stderr); code != 2 {
		t.Fatalf("down: exit %d", code)
	}
	if rec := records(t, stdout.String())[0]; rec["code"] != "CHAN-TRUST-UNREACHABLE" || rec["entryUUID"] != nil {
		t.Fatalf("record = %v", rec)
	}
}

func TestPointersForADNSSAN(t *testing.T) {
	r := newResolver(t, teemA)
	var stdout, stderr bytes.Buffer
	code := run([]string{"-tcr", r.srv.URL, "-identity", "gateway.zone-b.facis-ztd.local", "-digest", teemA, "-pointer", "zone-b.facis-ztd.local"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if rec := records(t, stdout.String())[0]; rec["key"] != "gateway.zone-b.facis-ztd.local" {
		t.Fatalf("record = %v", rec)
	}
	stdout.Reset()
	if code := run([]string{"-tcr", r.srv.URL, "-identity", "gateway.zone-b.facis-ztd.local", "-digest", teemA}, &stdout, &stderr); code != 2 {
		t.Fatalf("a DNS SAN without a pointer must be refused: exit %d", code)
	}
	if rec := records(t, stdout.String())[0]; rec["code"] != "CHAN-ZONE-UNKNOWN" {
		t.Fatalf("record = %v", rec)
	}
}

func TestUntilCodeRecordsTheTransition(t *testing.T) {
	r := newResolver(t, teemA)
	var stdout, stderr bytes.Buffer
	// The value disappears from TRAIN after the first resolution; with a short TTL the probe sees it.
	go func() {
		for {
			r.mu.Lock()
			n := r.calls
			r.mu.Unlock()
			if n >= 1 {
				r.set(true)
				return
			}
		}
	}()
	code := run([]string{"-tcr", r.srv.URL, "-identity", keyB, "-digest", teemA, "-until-code", "CHAN-MEASUREMENT-UNPUBLISHED", "-ttl", "300ms", "-interval", "50ms", "-deadline", "10s"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	recs := records(t, stdout.String())
	last := recs[len(recs)-1]
	if last["schema"] != "train-resolve-probe-transition/v1" || last["observed"] != true || last["firstAcceptedAt"] == nil || last["transitionAfterMs"].(float64) < 250 {
		t.Fatalf("transition = %v", last)
	}
	if recs[0]["outcome"] != "accepted" || recs[len(recs)-2]["code"] != "CHAN-MEASUREMENT-UNPUBLISHED" {
		t.Fatalf("records = %v", recs)
	}
	stdout.Reset()
	if code := run([]string{"-tcr", r.srv.URL, "-identity", keyB, "-digest", teemA, "-until-code", "CHAN-MEASUREMENT-MISMATCH", "-interval", "20ms", "-deadline", "100ms"}, &stdout, &stderr); code != 2 {
		t.Fatalf("a code never observed: exit %d", code)
	}
	recs = records(t, stdout.String())
	if last := recs[len(recs)-1]; last["observed"] != false {
		t.Fatalf("transition = %v", last)
	}
}
