package feedbridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/contractpath"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func bridge(t *testing.T) *Bridge {
	b, err := New(contractpath.Contracts(t))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// schemas compiles the feed's message and snapshot schemas of both versions.
func schemas(t *testing.T) map[string]*jsonschema.Schema {
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	dir := contractpath.Contracts(t)
	for _, name := range []string{"if01-event.v1", "if01-event.v2"} {
		raw, err := os.ReadFile(filepath.Join(dir, name+".schema.json"))
		if err != nil {
			t.Fatal(err)
		}
		doc, _ := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err := c.AddResource("https://github.com/eclipse-xfsc/facis-zero-trust-demonstrator/docs/contracts/"+name+".schema.json", doc); err != nil {
			t.Fatal(err)
		}
	}
	out := map[string]*jsonschema.Schema{}
	for _, name := range []string{"if01-event.v1", "if01-event.v2", "if01-snapshot.v1", "if01-snapshot.v2"} {
		sch, err := c.Compile(filepath.Join(dir, name+".schema.json"))
		if err != nil {
			t.Fatal(err)
		}
		out[name] = sch
	}
	return out
}

func valid(t *testing.T, sch *jsonschema.Schema, doc []byte) bool {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	return err == nil && sch.Validate(v) == nil
}

// lines writes n decision events of one run through the real v2 sink.
func lines(source, run string, n int) [][]byte {
	var buf bytes.Buffer
	sink := hook.NewLogSinkV2(&buf, source, run)
	for i := 0; i < n; i++ {
		sink.Emit("corr-"+string(rune('a'+i%26)), hook.EventPayload{State: "denied", ReasonCode: "TOK-MISSING", Resource: "POST https://guard.test/demo"})
	}
	return bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
}

func events(t *testing.T, srv *httptest.Server, path string) (int, [][]byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out [][]byte
	scan := bufio.NewScanner(resp.Body)
	scan.Buffer(make([]byte, 64*1024), 128*1024)
	for scan.Scan() {
		if data, ok := strings.CutPrefix(scan.Text(), "data: "); ok {
			out = append(out, []byte(data))
		}
	}
	return resp.StatusCode, out
}

func get(t *testing.T, srv *httptest.Server, path string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body bytes.Buffer
	_, _ = body.ReadFrom(resp.Body)
	return resp.StatusCode, body.Bytes()
}

// TestEachVersionServesOnlyWhatItsContractAccepts: the same run read through v1 and v2. Every v1
// message and snapshot validates against v1 (a policy source left out, v2 members removed); v2 keeps
// the producer's lines and every source.
func TestEachVersionServesOnlyWhatItsContractAccepts(t *testing.T) {
	sch := schemas(t)
	b := bridge(t)
	guard := lines("guard-b", "run-1", 4)
	v1 := []byte(`{"run_id":"run-1","seq":5,"ts":"2026-11-21T12:00:00Z","source":"guard-b","kind":"decision","correlation_id":"c","payload":{"state":"allowed"}}`)
	for _, l := range [][]byte{guard[0], guard[1], guard[1], guard[3], v1, []byte("plain text"), []byte(`{"run_id":"run-1","seq":9,"payload":{}}`)} {
		_ = b.Ingest(l)
	}
	for _, l := range lines("policy-b", "run-p", 2) {
		if err := b.Ingest(l); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(b)
	defer srv.Close()

	_, got1 := events(t, srv, "/events?run_id=run-1&from_seq=0")
	_, got2 := events(t, srv, "/v2/events?run_id=run-1&from_seq=0")
	if len(got1) != 6 || len(got2) != 6 {
		t.Fatalf("v1 %d, v2 %d messages", len(got1), len(got2))
	}
	for i := range got1 {
		if !valid(t, sch["if01-event.v1"], got1[i]) {
			t.Fatalf("v1 message %d does not validate: %s", i, got1[i])
		}
		if !valid(t, sch["if01-event.v1"], got2[i]) && !valid(t, sch["if01-event.v2"], got2[i]) {
			t.Fatalf("v2 message %d validates against neither version: %s", i, got2[i])
		}
	}
	if !bytes.Contains(got2[0], []byte(`"version":2`)) || bytes.Contains(got1[0], []byte(`"version"`)) || !bytes.Contains(got1[2], []byte(`"kind":"gap"`)) {
		t.Fatalf("v1 %s / v2 %s", got1[0], got2[0])
	}
	// The policy evaluator's run: no message and no panel on v1, both on v2.
	if _, p1 := events(t, srv, "/events?run_id=run-p&from_seq=0"); len(p1) != 0 {
		t.Fatalf("v1 streamed a policy source: %s", p1[0])
	}
	if _, p2 := events(t, srv, "/v2/events?run_id=run-p&from_seq=0"); len(p2) != 2 {
		t.Fatalf("v2 policy messages: %d", len(p2))
	}
	for _, c := range []struct{ path, schema, want string }{
		{"/snapshot?run_id=run-1", "if01-snapshot.v1", `"as_of_seq":5`},
		{"/snapshot?run_id=run-p", "if01-snapshot.v1", `"panels":{}`},
		{"/v2/snapshot?run_id=run-p", "if01-snapshot.v2", `"policy-b"`},
	} {
		status, body := get(t, srv, c.path)
		if status != http.StatusOK || !valid(t, sch[c.schema], body) || !strings.Contains(string(body), c.want) {
			t.Fatalf("%s: %d %s", c.path, status, body)
		}
	}
	if status, _ := get(t, srv, "/snapshot?run_id=unknown"); status != http.StatusNotFound {
		t.Fatalf("unknown run answered %d", status)
	}
}

func TestEachRunKeepsTheLastThousandAndSignalsTheLoss(t *testing.T) {
	b := bridge(t)
	for _, l := range lines("guard-b", "run-1", Buffer+5) {
		if err := b.Ingest(l); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(b)
	defer srv.Close()
	_, got := events(t, srv, "/v2/events?run_id=run-1&from_seq=0")
	if len(got) != Buffer+1 || !bytes.Contains(got[0], []byte(`"kind":"gap"`)) || !bytes.Contains(got[1], []byte(`"seq":5`)) {
		t.Fatalf("%d events, first %s", len(got), got[0])
	}
}

// TestTheBudgetEvictsTheLeastRecentRunsAndAnswers410: many runs within a small budget keep the
// memory bounded; a dropped run is answered 410, an unknown one 404, a fresh one is served.
func TestTheBudgetEvictsTheLeastRecentRunsAndAnswers410(t *testing.T) {
	b := bridge(t)
	b.Budget = 64 << 10
	for i := 0; i < 200; i++ {
		for _, l := range lines("guard-b", "run-"+strings.Repeat("x", i%3)+string(rune('A'+i%26))+string(rune('a'+i/26)), 20) {
			if err := b.Ingest(l); err != nil {
				t.Fatal(err)
			}
		}
		if b.bytes > b.Budget {
			t.Fatalf("after run %d the bridge holds %d bytes, over its %d budget", i, b.bytes, b.Budget)
		}
	}
	srv := httptest.NewServer(b)
	defer srv.Close()
	if status, _ := get(t, srv, "/v2/snapshot?run_id=run-Aa"); status != http.StatusGone {
		t.Fatalf("the oldest run answered %d, want 410", status)
	}
	if status, _ := events(t, srv, "/events?run_id=run-Aa&from_seq=0"); status != http.StatusGone {
		t.Fatalf("the oldest run's stream answered %d, want 410", status)
	}
	if status, _ := get(t, srv, "/v2/snapshot?run_id=never"); status != http.StatusNotFound {
		t.Fatalf("an unknown run answered %d, want 404", status)
	}
	last := "run-" + strings.Repeat("x", 199%3) + string(rune('A'+199%26)) + string(rune('a'+199/26))
	if status, _ := get(t, srv, "/v2/snapshot?run_id="+last); status != http.StatusOK {
		t.Fatalf("the newest run answered %d", status)
	}
}

// TestConsumeDrainsOversizedLinesAndContinues: a line over MaxLine is counted, never buffered, and
// the lines after it are still taken, from a reader and through /ingest.
func TestConsumeDrainsOversizedLinesAndContinues(t *testing.T) {
	good := lines("guard-b", "run-1", 2)
	input := string(good[0]) + "\n" + strings.Repeat("y", MaxLine*3) + "\nnot json\n" + string(good[1]) + "\n"
	b := bridge(t)
	accepted, refused, oversized, err := b.Consume(strings.NewReader(input))
	if err != nil || accepted != 2 || refused != 1 || oversized != 1 {
		t.Fatalf("accepted %d refused %d oversized %d err %v", accepted, refused, oversized, err)
	}
	b = bridge(t)
	srv := httptest.NewServer(b)
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/ingest", "application/x-ndjson", strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	var counts map[string]int
	_ = json.NewDecoder(resp.Body).Decode(&counts)
	_ = resp.Body.Close()
	if counts["accepted"] != 2 || counts["refused"] != 1 || counts["oversized"] != 1 {
		t.Fatalf("ingest counts %v", counts)
	}
	if _, got := events(t, srv, "/v2/events?run_id=run-1&from_seq=0"); len(got) != 2 {
		t.Fatalf("%d events after ingest", len(got))
	}
}

// TestArchivedEvidenceValidatesInBothVersions replays the archived kind run's lines through the
// bridge and validates every v1 and v2 snapshot and message against its contract.
func TestArchivedEvidenceValidatesInBothVersions(t *testing.T) {
	sch := schemas(t)
	dir := filepath.Join(contractpath.Root(t), "docs/evidences/guard-catalogue-kind-2026-11-22/events")
	b := bridge(t)
	runs := map[string]bool{}
	for _, name := range []string{"guard-events.jsonl", "policy-events.jsonl"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range bytes.Split(raw, []byte("\n")) {
			var m meta
			if json.Unmarshal(line, &m) == nil && m.RunID != "" && b.Ingest(line) == nil {
				runs[m.RunID] = true
			}
		}
	}
	if len(runs) < 2 {
		t.Fatalf("%d runs in the archive", len(runs))
	}
	srv := httptest.NewServer(b)
	defer srv.Close()
	for run := range runs {
		for _, v := range []struct{ prefix, snap, event string }{{"", "if01-snapshot.v1", "if01-event.v1"}, {"/v2", "if01-snapshot.v2", ""}} {
			status, body := get(t, srv, v.prefix+"/snapshot?run_id="+run)
			if status != http.StatusOK || !valid(t, sch[v.snap], body) {
				t.Fatalf("%s snapshot of %s: %d %s", v.snap, run, status, body)
			}
			_, msgs := events(t, srv, v.prefix+"/events?run_id="+run+"&from_seq=0")
			for _, m := range msgs {
				ok := valid(t, sch["if01-event.v1"], m) || (v.event == "" && valid(t, sch["if01-event.v2"], m))
				if !ok {
					t.Fatalf("%s message of %s does not validate: %s", v.prefix, run, m)
				}
			}
		}
	}
}
