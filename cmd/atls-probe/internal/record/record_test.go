package record

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// A record is replaced atomically: a reader never sees a partial file, and no temporary file
// stays behind.
func TestSaveIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "record.json")
	f := New(path, "server", "listener", NewEnvironment("abc123", false))
	f.NextSession()
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := int64(0); ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			f.UpdateSession(0, func(s *Session) { s.Heartbeats.Sent = i })
			if err := f.Save(); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for range 300 {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var r Record
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatalf("partial record read: %v\n%s", err, raw)
		}
		if r.Schema != Schema || r.Mode != "server" || r.Environment.Commit != "abc123" {
			t.Fatalf("record: %+v", r)
		}
	}
	close(stop)
	wg.Wait()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "record.json" {
		t.Fatalf("left behind: %v", entries)
	}
}

// The first session is the record itself; later ones are listed after it.
func TestSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	f := New(path, "server", "listener", Environment{})
	for want := range 3 {
		if got := f.NextSession(); got != want {
			t.Fatalf("session %d reserved as %d", want, got)
		}
	}
	f.UpdateSession(0, func(s *Session) { s.Outcome = OutcomeEstablished; s.Binding = "aa" })
	f.UpdateSession(2, func(s *Session) {
		s.Outcome = OutcomeRefused
		s.Refusal = &Refusal{Sentinel: "ErrBindingMismatch", Message: "m"}
	})
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["outcome"] != OutcomeEstablished || m["binding"] != "aa" {
		t.Fatalf("first session is not the record's own: %s", raw)
	}
	further := m["further_sessions"].([]any)
	if len(further) != 2 {
		t.Fatalf("further sessions: %v", further)
	}
	last := further[1].(map[string]any)
	if last["outcome"] != OutcomeRefused || last["refusal"].(map[string]any)["sentinel"] != "ErrBindingMismatch" {
		t.Fatalf("third session: %v", last)
	}
	if _, has := last["binding"]; has {
		t.Fatal("a refused session holds a binding")
	}
	if strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("key material in the record")
	}
}

func TestEnvironment(t *testing.T) {
	env := NewEnvironment("deadbeef", true)
	if env.Commit != "deadbeef" || !env.Dirty || env.GoVersion == "" || env.Platform == "" {
		t.Fatalf("%+v", env)
	}
	if env := NewEnvironment("", false); env.Commit == "" || env.CMCVersion == "" {
		t.Fatalf("%+v", env)
	}
}
