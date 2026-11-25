package bdd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDecideParticipantMock holds the decision of ZT-74 to the record: it passes on a record shaped
// like a kind run's, and each record the row rests on, when missing or contrary, fails it.
func TestDecideParticipantMock(t *testing.T) {
	const (
		sa    = "spiffe://cluster.local/ns/ztd-m3/sa/"
		run   = "participant-b-0a1b2c"
		step  = `{"version":2,"run_id":"` + run + `","source":"participant-b","kind":"step","correlation_id":"`
		guard = `{"version":2,"run_id":"guard-1","source":"guard-b","kind":"decision","correlation_id":"`
		hop   = `","security":"mutual_tls","response_code":"200","requests":2}` + "\n"
	)
	record := map[string]string{
		"run.json":     `{"served_id":"aa11","refused_id":"bb22","participant_run_id":"` + run + `","participant_identity":"` + sa + `ztd-participant","connector_url":"http://ztd-connector:8080","guard_url":"http://ztd-guard:8080","client_id":"client-1"}`,
		"config.json":  `{"PARTICIPANT_ADAPTER_MODE":"token","PARTICIPANT_CONNECTOR_URL":"http://ztd-connector:8080","PARTICIPANT_RESOURCE_URL":"http://ztd-guard:8080"}`,
		"state.json":   `{"mode":"token","state":"ready","history":[{"state":"registering"},{"state":"registered"},{"state":"presenting"},{"state":"acquiring_token"},{"state":"ready"}]}`,
		"served.http":  "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n" + `{"correlationId":"aa11","mode":"token","outcome":"success","reasonCode":"RESOURCE_SUMMARY_RETURNED","safeData":{"action":"read","resource":"sample-report","summary":{"id":"REPORT-001"}}}`,
		"refused.http": "HTTP/1.1 503 Service Unavailable\r\ncontent-type: application/json\r\n\r\n" + `{"correlationId":"bb22","mode":"token","outcome":"unavailable","reasonCode":"TOKEN_RESOURCE_UNAVAILABLE","safeData":{}}`,
		"resource.log": `{"msg":"protected resource request completed","requestId":"aa11"}` + "\n",
		"hops.jsonl": `{"source":"` + sa + `ztd-participant","destination":"` + sa + `ztd-connector` + hop +
			`{"source":"` + sa + `ztd-participant","destination":"` + sa + `ztd-guard` + hop +
			`{"source":"` + sa + `ztd-guard","destination":"` + sa + `ztd-protected-resource` + hop,
		"feed.jsonl": step + run + `","payload":{"state":"registered","reason_code":"APP-STEP-COMPLETED","detail":"registration"}}` + "\n" +
			step + run + `","payload":{"state":"presenting","reason_code":"APP-STEP-STARTED","detail":"status"}}` + "\n" +
			step + run + `","payload":{"state":"acquiring_token","reason_code":"APP-STEP-STARTED","detail":"status"}}` + "\n" +
			step + run + `","payload":{"state":"ready","reason_code":"APP-STEP-COMPLETED","detail":"status"}}` + "\n" +
			step + `aa11","payload":{"state":"success","reason_code":"APP-RESOURCE-SUMMARY-RETURNED","detail":"request"}}` + "\n" +
			step + `bb22","payload":{"state":"unavailable","reason_code":"APP-TOKEN-RESOURCE-UNAVAILABLE","detail":"request"}}` + "\n" +
			`{"version":2,"run_id":"resource-1","source":"protected-resource-b","kind":"step","correlation_id":"aa11","payload":{"state":"success","detail":"access role=viewer"}}` + "\n" +
			guard + `g1","payload":{"state":"allowed","rule_id":"m3-report-summary","token_subject":"client-1","caller_spiffe_id":"` + sa + `ztd-participant"}}` + "\n" +
			guard + `g2","payload":{"state":"denied","reason_code":"POL-PDP-UNAVAILABLE","token_subject":"client-1","caller_spiffe_id":"` + sa + `ztd-participant"}}` + "\n",
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
		_, err := decideParticipantMock(dir)
		return err
	}
	if err := decide(t, "", "", false); err != nil {
		t.Fatalf("a complete record is not held: %v", err)
	}
	for file := range record {
		if err := decide(t, file, "", true); err == nil {
			t.Errorf("a record without %s is held", file)
		}
	}
	feed := record["feed.jsonl"]
	for name, contrary := range map[string][2]string{
		"sample mode":                        {"config.json", strings.Replace(record["config.json"], "token", "sample", 1)},
		"another resource endpoint":          {"config.json", strings.Replace(record["config.json"], "ztd-guard", "ztd-protected-resource", 1)},
		"never ready":                        {"state.json", `{"mode":"token","state":"failed_token","history":[{"state":"registering"},{"state":"failed_token"}]}`},
		"served without the resource's data": {"served.http", strings.Replace(record["served.http"], `,"summary":{"id":"REPORT-001"}`, "", 1)},
		"request not served":                 {"served.http", "HTTP/1.1 403 Forbidden\r\n\r\n" + `{"correlationId":"aa11","mode":"token","outcome":"denied","safeData":{}}`},
		"refused request answered":           {"refused.http", strings.Replace(record["served.http"], "aa11", "bb22", 1)},
		"refused request at the resource":    {"resource.log", record["resource.log"] + `{"requestId":"bb22"}`},
		"plain-text hop":                     {"hops.jsonl", strings.Replace(record["hops.jsonl"], "mutual_tls", "none", 1)},
		"guard reached by another identity":  {"hops.jsonl", strings.Replace(record["hops.jsonl"], "ztd-participant\",\"destination\":\""+sa+"ztd-guard", "intruder\",\"destination\":\""+sa+"ztd-guard", 1)},
		"no registration event":              {"feed.jsonl", strings.Replace(feed, `"detail":"registration"`, `"detail":"status"`, 1)},
		"no ready event":                     {"feed.jsonl", strings.Replace(feed, `"state":"ready"`, `"state":"failed_token"`, 1)},
		"request event under another id":     {"feed.jsonl", strings.Replace(feed, step+"aa11", step+"cc33", 1)},
		"events of another run":              {"feed.jsonl", strings.ReplaceAll(feed, `"run_id":"`+run, `"run_id":"participant-b-other`)},
		"guard decision for another caller":  {"feed.jsonl", strings.Replace(feed, `"client-1","caller_spiffe_id":"`+sa+"ztd-participant", `"client-1","caller_spiffe_id":"`+sa+"intruder", 1)},
		"guard decision for another client":  {"feed.jsonl", strings.Replace(feed, `"token_subject":"client-1"`, `"token_subject":"client-2"`, 1)},
		"a third guard decision":             {"feed.jsonl", feed + guard + `g3","payload":{"state":"allowed","token_subject":"client-1","caller_spiffe_id":"` + sa + `ztd-participant"}}` + "\n"},
		"no access event of the resource":    {"feed.jsonl", strings.Replace(feed, `"protected-resource-b","kind":"step","correlation_id":"aa11"`, `"protected-resource-b","kind":"step","correlation_id":"zz"`, 1)},
		"refused id on another event":        {"feed.jsonl", feed + guard + `bb22","payload":{"state":"allowed","token_subject":"other"}}` + "\n"},
		"refusal not on the feed":            {"feed.jsonl", strings.Replace(feed, "APP-TOKEN-RESOURCE-UNAVAILABLE", "APP-TOKEN-FORBIDDEN", 1)},
		"no guard denial":                    {"feed.jsonl", strings.Replace(feed, "POL-PDP-UNAVAILABLE", "POL-RULE-DENY", 1)},
	} {
		if err := decide(t, contrary[0], contrary[1], false); err == nil {
			t.Errorf("%s: the row was decided as held", name)
		}
	}
}
