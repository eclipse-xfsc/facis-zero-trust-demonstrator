package replay

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Memory is a Store held in the process, for a protected resource that keeps its own replay record.
// A proof is bound to one resource by htu, so no other process needs to see the record; it is lost on
// restart, which exposes at most one proof window (Window) of proofs presented before the restart.
// Records are kept until their NotAfter and swept on use.
type Memory struct {
	mu        sync.Mutex
	seen      map[proofKey]time.Time // NotAfter per proof
	nextSweep time.Time
	now       func() time.Time
}

type proofKey struct{ jkt, method, uri, jti string }

var _ Store = (*Memory)(nil)

// NewMemory returns an empty in-process Store.
func NewMemory() *Memory { return &Memory{seen: map[proofKey]time.Time{}, now: time.Now} }

// TryUse records the use; one already recorded is a replay. As with Postgres, an expired record that
// was not swept yet still counts as seen.
func (m *Memory) TryUse(_ context.Context, use Use) (bool, error) {
	if use.JKT == "" || use.Method == "" || use.URI == "" || use.JTI == "" || use.NotAfter.IsZero() {
		return false, fmt.Errorf("replay: incomplete use")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if now := m.now(); now.After(m.nextSweep) {
		// ponytail: a full scan at most once a minute; the record holds about one proof window.
		for k, notAfter := range m.seen {
			if notAfter.Before(now) {
				delete(m.seen, k)
			}
		}
		m.nextSweep = now.Add(time.Minute)
	}
	key := proofKey{use.JKT, use.Method, use.URI, use.JTI}
	if _, dup := m.seen[key]; dup {
		return false, nil
	}
	m.seen[key] = use.NotAfter
	return true, nil
}
