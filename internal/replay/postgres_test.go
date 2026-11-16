package replay

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/pgtest"
)

func newStore(t *testing.T) (*Postgres, *pgxpool.Pool) {
	t.Helper()
	pool, err := pgxpool.New(t.Context(), pgtest.MigratedURL(t, "replay"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return NewPostgres(pool), pool
}

func use(jti string) Use {
	return Use{JKT: "jkt", Method: "POST", URI: "https://b.example/token", JTI: jti, NotAfter: time.Now().Add(time.Minute)}
}

func TestPostgres_SeenProofIsRefused(t *testing.T) {
	s, _ := newStore(t)
	ctx := t.Context()

	if fresh, err := s.TryUse(ctx, use("a")); err != nil || !fresh {
		t.Fatalf("first use: %v, %v", fresh, err)
	}
	if fresh, err := s.TryUse(ctx, use("a")); err != nil || fresh {
		t.Fatalf("second use: %v, %v", fresh, err)
	}

	// Any part of the key makes another proof.
	other := use("a")
	other.URI = "https://b.example/other"
	if fresh, _ := s.TryUse(ctx, other); !fresh {
		t.Error("the same jti on another URI was refused")
	}
}

// Of any number of concurrent uses of one proof, exactly one is fresh.
func TestPostgres_OneOfAHundredConcurrentUsesIsFresh(t *testing.T) {
	s, _ := newStore(t)
	var fresh, failed atomic.Int32
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			ok, err := s.TryUse(context.Background(), use("raced"))
			if err != nil {
				failed.Add(1)
			}
			if ok {
				fresh.Add(1)
			}
		})
	}
	wg.Wait()
	if fresh.Load() != 1 || failed.Load() != 0 {
		t.Fatalf("%d fresh, %d errors; want 1 and 0", fresh.Load(), failed.Load())
	}
}

func TestPostgres_IncompleteUseIsAnError(t *testing.T) {
	s, _ := newStore(t)
	for name, u := range map[string]Use{
		"no jkt":       {Method: "POST", URI: "u", JTI: "j", NotAfter: time.Now()},
		"no jti":       {JKT: "k", Method: "POST", URI: "u", NotAfter: time.Now()},
		"no not_after": {JKT: "k", Method: "POST", URI: "u", JTI: "j"},
	} {
		if _, err := s.TryUse(t.Context(), u); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPostgres_SweepRemovesOnlyExpiredRecords(t *testing.T) {
	s, _ := newStore(t)
	ctx := t.Context()
	old := use("old")
	old.NotAfter = time.Now().Add(-time.Second)
	for _, u := range []Use{old, use("live")} {
		if _, err := s.TryUse(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := s.Sweep(ctx, time.Now()); err != nil || n != 1 {
		t.Fatalf("swept %d, %v", n, err)
	}
	if fresh, _ := s.TryUse(ctx, use("live")); fresh {
		t.Error("a live record was swept")
	}
}

// The sentinel is missing on a new database and after the unlogged tables were reset, and present
// otherwise. Emptying both tables stands in for crash recovery here; the real crash is exercised by
// hand (docs/token-store.md).
func TestPostgres_EpochReportsLostReplayState(t *testing.T) {
	s, pool := newStore(t)
	ctx := t.Context()

	if lost, err := s.CheckEpoch(ctx, time.Now()); err != nil || !lost {
		t.Fatalf("new database: lost=%v, %v; want true", lost, err)
	}
	if lost, _ := s.CheckEpoch(ctx, time.Now()); lost {
		t.Fatal("a second check reported loss")
	}

	if _, err := pool.Exec(ctx, `TRUNCATE replay_epoch, proof_jti`); err != nil {
		t.Fatal(err)
	}
	if lost, _ := s.CheckEpoch(ctx, time.Now()); !lost {
		t.Fatal("reset tables were not reported")
	}
}
