package appevents_test

import (
	"bytes"
	"sync"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/appevents"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/appfeedtest"
)

func TestConcurrentEventsKeepUniqueOrderedRuns(t *testing.T) {
	for _, source := range []string{"participant-a", "participant-b", "protected-resource-a", "protected-resource-b"} {
		var lines bytes.Buffer
		sink, err := appevents.New(&lines, source)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for range 20 {
			wg.Go(func() { sink.Emit("correlation", "denied", "TOKEN_FORBIDDEN", "request") })
		}
		wg.Wait()
		events := appfeedtest.RoundTrip(t, "../../docs/contracts", lines.String())
		if len(events) != 20 {
			t.Fatal("lost an event")
		}
		var other bytes.Buffer
		restarted, err := appevents.New(&other, source)
		if err != nil {
			t.Fatal(err)
		}
		restarted.Emit("", "idle", "RESET", "status")
		next := appfeedtest.RoundTrip(t, "../../docs/contracts", other.String())
		if events[0].RunID == next[0].RunID {
			t.Fatal("restart reused a run id")
		}
	}
	if _, err := appevents.New(&bytes.Buffer{}, "unknown"); err == nil {
		t.Fatal("unknown source accepted")
	}
}
