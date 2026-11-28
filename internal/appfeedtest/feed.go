// Package appfeedtest exercises the real IF-01 ingest, snapshot and SSE handlers without sockets.
package appfeedtest

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

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/feedbridge"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// stopAfterFlush disconnects after the bridge has sent its buffered events, like an SSE client.
type stopAfterFlush struct {
	*httptest.ResponseRecorder
	cancel context.CancelFunc
}

func (w stopAfterFlush) Flush() { w.ResponseRecorder.Flush(); w.cancel() }

// RoundTrip returns only events read back from SSE, not the producer's original records.
// Every input line must pass the contract and be served exactly once, in sequence, without gaps.
func RoundTrip(t *testing.T, contracts string, logs ...string) []hook.Event {
	t.Helper()
	bridge, err := feedbridge.New(contracts)
	if err != nil {
		t.Fatal(err)
	}
	registryRaw, err := os.ReadFile(filepath.Join(contracts, "reason-codes.json"))
	if err != nil {
		t.Fatal(err)
	}
	registryCompiler := jsonschema.NewCompiler()
	registrySchema, err := registryCompiler.Compile(filepath.Join(contracts, "reason-codes.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	registryDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(registryRaw))
	if err != nil {
		t.Fatal(err)
	}
	if err := registrySchema.Validate(registryDoc); err != nil {
		t.Fatal(err)
	}
	var registry struct {
		Families map[string]struct{ Codes map[string]json.RawMessage }
	}
	if err := json.Unmarshal(registryRaw, &registry); err != nil {
		t.Fatal(err)
	}
	runs := map[string][]hook.Event{}
	raw := strings.Join(logs, "")
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		var event hook.Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if event.Version != 2 || event.Kind != "step" || event.CorrelationID == "" {
			t.Fatalf("invalid application event: %s", line)
		}
		if _, ok := registry.Families["APP"].Codes[event.Payload.ReasonCode]; !ok {
			t.Fatalf("unregistered application reason %s", event.Payload.ReasonCode)
		}
		runs[event.RunID] = append(runs[event.RunID], event)
	}
	response := httptest.NewRecorder()
	bridge.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/ingest", strings.NewReader(raw)))
	var ingest struct{ Accepted, Refused, Oversized int }
	err = json.Unmarshal(response.Body.Bytes(), &ingest)
	total := 0
	for _, events := range runs {
		total += len(events)
	}
	if err != nil || response.Code != 200 || ingest.Accepted != total || ingest.Refused != 0 || ingest.Oversized != 0 {
		t.Fatalf("ingest: %+v %v", ingest, err)
	}
	var result []hook.Event
	for run, expected := range runs {
		for _, version := range []string{"", "/v2"} {
			response = httptest.NewRecorder()
			bridge.ServeHTTP(response, httptest.NewRequest(http.MethodGet, version+"/snapshot?run_id="+run, nil))
			snapshot := response.Body.Bytes()
			if response.Code != 200 {
				t.Fatalf("snapshot: %d", response.Code)
			}
			name := "if01-snapshot.v2.schema.json"
			if version == "" {
				name = "if01-snapshot.v1.schema.json"
				if !bytes.Contains(snapshot, []byte(`"panels":{}`)) {
					t.Fatal("v1 exposed a v2-only source")
				}
			}
			compiler := jsonschema.NewCompiler()
			for _, eventSchema := range []string{"if01-event.v1.schema.json", "if01-event.v2.schema.json"} {
				raw, err := os.ReadFile(filepath.Join(contracts, eventSchema))
				if err != nil {
					t.Fatal(err)
				}
				doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
				if err != nil {
					t.Fatal(err)
				}
				if err := compiler.AddResource("https://github.com/eclipse-xfsc/facis-zero-trust-demonstrator/docs/contracts/"+eventSchema, doc); err != nil {
					t.Fatal(err)
				}
			}
			schema, err := compiler.Compile(filepath.Join(contracts, name))
			if err != nil {
				t.Fatal(err)
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(snapshot))
			if err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(doc); err != nil {
				t.Fatal(err)
			}
			if version == "/v2" && !bytes.Contains(snapshot, []byte(`"`+expected[0].Source+`"`)) {
				t.Fatal("snapshot missing source panel")
			}
		}
		response = httptest.NewRecorder()
		ctx, cancel := context.WithCancel(context.Background())
		bridge.ServeHTTP(stopAfterFlush{response, cancel}, httptest.NewRequest(http.MethodGet, "/v2/events?run_id="+run+"&from_seq=0", nil).WithContext(ctx))
		cancel()
		if response.Code != 200 {
			t.Fatalf("SSE: %d", response.Code)
		}
		scan := bufio.NewScanner(response.Body)
		n := 0
		for scan.Scan() {
			line := scan.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			var got hook.Event
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &got); err != nil {
				t.Fatal(err)
			}
			if n >= len(expected) || got != expected[n] || got.Seq != uint64(n) {
				t.Fatalf("SSE event %d differs from producer or sequence", n)
			}
			result = append(result, got)
			n++
		}
		if n != len(expected) || scan.Err() != nil {
			t.Fatalf("SSE served %d of %d events: %v", n, len(expected), scan.Err())
		}
	}
	return result
}
