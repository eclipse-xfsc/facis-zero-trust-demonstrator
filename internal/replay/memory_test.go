package replay

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemory(t *testing.T) {
	now := time.Now()
	m := NewMemory()
	m.now = func() time.Time { return now }
	use := Use{JKT: "k", Method: "POST", URI: "https://r.test/demo", JTI: "j", NotAfter: now.Add(time.Minute)}

	var fresh atomic.Int32
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, err := m.TryUse(t.Context(), use); err != nil {
				t.Error(err)
			} else if ok {
				fresh.Add(1)
			}
		}()
	}
	wg.Wait()
	if fresh.Load() != 1 {
		t.Fatalf("%d fresh uses of one proof", fresh.Load())
	}
	other := use
	other.URI = "https://r.test/other"
	if ok, _ := m.TryUse(t.Context(), other); !ok {
		t.Fatal("a proof for another URI counted as seen")
	}
	if _, err := m.TryUse(t.Context(), Use{JKT: "k"}); err == nil {
		t.Fatal("incomplete use accepted")
	}

	// Past NotAfter and the next sweep, the record goes.
	now = now.Add(2 * time.Minute)
	if ok, _ := m.TryUse(t.Context(), Use{JKT: "k", Method: "GET", URI: "u", JTI: "x", NotAfter: now.Add(time.Minute)}); !ok {
		t.Fatal("new use refused")
	}
	if _, kept := m.seen[proofKey{"k", "POST", "https://r.test/demo", "j"}]; kept || len(m.seen) != 1 {
		t.Fatalf("expired records not swept: %d left", len(m.seen))
	}
}
