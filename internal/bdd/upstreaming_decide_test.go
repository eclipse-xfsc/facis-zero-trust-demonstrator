package bdd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDecideUpstreaming holds the decision of ZT-73 to the record: it passes on a record shaped like a
// zone run's, and each record the row rests on, when missing or contrary, fails it.
func TestDecideUpstreaming(t *testing.T) {
	const participant = "spiffe://zone.test/ns/ztd/sa/ztd-participant"
	record := map[string]string{
		"state.json":                         `{"mode":"token","state":"ready","history":[{"state":"idle"},{"state":"presenting"},{"state":"acquiring_token"},{"state":"ready"}]}`,
		"guarded-status.txt":                 "200\n",
		"guarded-response.json":              `{"requestId":"req-1","outcome":"success","reasonCode":"RESOURCE_REPORT_RETURNED","safeData":{"report":{"id":"REPORT-001"}}}`,
		"guarded-guard-record.jsonl":         `{"kind":"decision","correlation_id":"aa","payload":{"state":"allowed","rule_id":"m3-report-read"}}` + "\n",
		"guarded-resource-record.jsonl":      `{"requestId":"req-1","outcome":"success","client_id":"ztd-store"}` + "\n",
		"expected-store-client.txt":          "ztd-store\n",
		"guarded-stats-guard-before.txt":     "http.inbound_0.0.0.0_8080;.rbac.allowed: 46\nhttp.inbound_0.0.0.0_8080;.rbac.denied: 0\n",
		"guarded-stats-guard-after.txt":      "http.inbound_0.0.0.0_8080;.rbac.allowed: 47\nhttp.inbound_0.0.0.0_8080;.rbac.denied: 0\n",
		"guarded-stats-resource-before.txt":  "http.inbound_0.0.0.0_8080;.rbac.allowed: 46\n",
		"guarded-stats-resource-after.txt":   "http.inbound_0.0.0.0_8080;.rbac.allowed: 47\n",
		"tokenless-response.txt":             "HTTP/1.1 401 Unauthorized\r\ncontent-type: application/json\r\nx-request-id: bb\r\n\r\n" + `{"error":"request_refused","reason_code":"TOK-MISSING"}`,
		"tokenless-guard-record.jsonl":       `{"kind":"decision","correlation_id":"bb","payload":{"state":"denied","reason_code":"TOK-MISSING"}}` + "\n",
		"meshed-response.txt":                "HTTP/1.1 403 Forbidden\r\ncontent-type: text/plain\r\n\r\nRBAC: access denied",
		"meshed-receiver-log.txt":            `{"code":403,"detail":"rbac_access_denied_matched_policy[none]","source":"` + participant + `","destination":"spiffe://zone.test/ns/ztd/sa/ztd-protected-resource"}` + "\n",
		"resource-app-log-during-probes.txt": "",
	}
	decide := func(t *testing.T, name, content string, remove bool) error {
		dir := t.TempDir()
		for file, text := range record {
			if file == name {
				if remove {
					continue
				}
				text = content
			}
			if err := os.WriteFile(filepath.Join(dir, file), []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		_, err := decideUpstreaming(dir)
		return err
	}
	if err := decide(t, "", "", false); err != nil {
		t.Fatalf("a complete record is not held: %v", err)
	}
	// A guard older than the reason-code registry names the missing token by its runtime code; the
	// response and the event must name the same one.
	old := strings.ReplaceAll(record["tokenless-response.txt"], "TOK-MISSING", "token_absent")
	if err := decide(t, "tokenless-response.txt", old, false); err == nil {
		t.Error("a response and an event that name different codes are held")
	}
	// The Participant's own token reaching the resource is not the store's substitution.
	ownToken := `{"requestId":"req-1","outcome":"success","client_id":"ztd-participant"}` + "\n"
	if err := decide(t, "guarded-resource-record.jsonl", ownToken, false); err == nil {
		t.Error("a resource record for the Participant's own client is held as the store's substitution")
	}
	for file := range record {
		if err := decide(t, file, "", true); err == nil {
			t.Errorf("a record without %s is held", file)
		}
	}
	for file, contrary := range map[string]string{
		"state.json":                         `{"mode":"sample","state":"ready","history":[{"state":"ready"}]}`,
		"guarded-status.txt":                 "403\n",
		"guarded-response.json":              `{"requestId":"req-1","outcome":"success","reasonCode":"X","safeData":{}}`,
		"guarded-guard-record.jsonl":         `{"kind":"decision","correlation_id":"aa","payload":{"state":"denied","reason_code":"POL-RULE-DENY"}}`,
		"guarded-resource-record.jsonl":      `{"requestId":"another","outcome":"success","client_id":"ztd-store"}`,
		"guarded-stats-resource-after.txt":   "http.inbound_0.0.0.0_8080;.rbac.allowed: 46\n",
		"tokenless-response.txt":             "HTTP/1.1 200 OK\r\nx-request-id: bb\r\n\r\n" + `{"safeData":{"report":{"id":"REPORT-001"}}}`,
		"tokenless-guard-record.jsonl":       `{"kind":"decision","correlation_id":"cc","payload":{"state":"denied","reason_code":"TOK-MISSING"}}`,
		"meshed-response.txt":                "HTTP/1.1 200 OK\r\n\r\n" + `{"safeData":{"report":{"id":"REPORT-001"}}}`,
		"meshed-receiver-log.txt":            `{"code":403,"detail":"rbac_access_denied_matched_policy[none]","source":"","destination":""}`,
		"resource-app-log-during-probes.txt": `{"msg":"protected resource request completed"}` + "\n",
	} {
		if err := decide(t, file, contrary, false); err == nil {
			t.Errorf("a record with a contrary %s is held", file)
		}
	}
}
