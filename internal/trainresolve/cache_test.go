package trainresolve

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

var peerA = Peer{Identity: "spiffe://zone-a.example/gateway", Digests: []Digest{{teemA, "SHA-256"}}}

func newTestVerifier(src Source) (*Verifier, *clock) {
	v := New(src, nil)
	c := newClock()
	v.now = c.now
	return v, c
}

func TestCacheServesWithinTTLAndRefetchesAtTTL(t *testing.T) {
	src := answering(teemA)
	v, c := newTestVerifier(src)
	for i := 0; i < 3; i++ {
		if err := v.Verify(ctxBg, peerA); err != nil {
			t.Fatal(err)
		}
	}
	if src.count() != 1 || v.Stats.Hits.Load() != 2 || v.Stats.Misses.Load() != 1 || v.Stats.Flights.Load() != 1 {
		t.Fatalf("calls %d hits %d misses %d flights %d", src.count(), v.Stats.Hits.Load(), v.Stats.Misses.Load(), v.Stats.Flights.Load())
	}
	c.advance(v.TTL - time.Second)
	if err := v.Verify(ctxBg, peerA); err != nil || src.count() != 1 {
		t.Fatalf("just before the TTL: err %v calls %d", err, src.count())
	}
	c.advance(time.Second)
	if err := v.Verify(ctxBg, peerA); err != nil || src.count() != 2 {
		t.Fatalf("at the TTL: err %v calls %d", err, src.count())
	}
}

func TestAChangeInTRAINTakesEffectAtTheTTL(t *testing.T) {
	var mu sync.Mutex
	values := []string{teemA}
	src := &fakeSource{fn: func(_ context.Context, l Lookup) (Expected, error) {
		mu.Lock()
		defer mu.Unlock()
		return Expected{Key: l.Key, Values: append([]string(nil), values...)}, nil
	}}
	v, c := newTestVerifier(src)
	if err := v.Verify(ctxBg, peerA); err != nil {
		t.Fatal(err)
	}
	// The value is removed in TRAIN: within the window the cache still accepts, at the TTL it refuses.
	mu.Lock()
	values = nil
	mu.Unlock()
	c.advance(v.TTL / 2)
	if err := v.Verify(ctxBg, peerA); err != nil {
		t.Fatalf("within the window the cached resolution must still be served: %v", err)
	}
	c.advance(v.TTL / 2)
	if err := v.Verify(ctxBg, peerA); !errors.Is(err, ErrUnpublished) {
		t.Fatalf("at the TTL the removal must bite: %v", err)
	}
	// The value is published again: the absence was cached for the same window.
	mu.Lock()
	values = []string{teemA}
	mu.Unlock()
	if err := v.Verify(ctxBg, peerA); !errors.Is(err, ErrUnpublished) || src.count() != 2 {
		t.Fatalf("an absence is a resolution and is cached: err %v calls %d", err, src.count())
	}
	c.advance(v.TTL)
	if err := v.Verify(ctxBg, peerA); err != nil || src.count() != 3 {
		t.Fatalf("after the window the publication is seen: err %v calls %d", err, src.count())
	}
}

func TestAFailureIsNeverCached(t *testing.T) {
	var mu sync.Mutex
	fail := true
	src := &fakeSource{fn: func(_ context.Context, l Lookup) (Expected, error) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return Expected{}, refuse(ErrUnreachable, "resolver answered 502", nil)
		}
		return Expected{Key: l.Key, Values: []string{teemA}}, nil
	}}
	v, _ := newTestVerifier(src)
	if err := v.Verify(ctxBg, peerA); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v", err)
	}
	if err := v.Verify(ctxBg, peerA); !errors.Is(err, ErrUnreachable) || src.count() != 2 {
		t.Fatalf("a failure must be asked again: err %v calls %d", err, src.count())
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	if err := v.Verify(ctxBg, peerA); err != nil || src.count() != 3 {
		t.Fatalf("err %v calls %d", err, src.count())
	}
}

// blockingSource holds every resolution until release is closed, or until the context ends.
type blockingSource struct {
	fakeSource
	release chan struct{}
	started chan struct{}
}

func newBlockingSource(values ...string) *blockingSource {
	b := &blockingSource{release: make(chan struct{}), started: make(chan struct{}, 1024)}
	b.fn = func(ctx context.Context, l Lookup) (Expected, error) {
		b.started <- struct{}{}
		select {
		case <-b.release:
			return Expected{Key: l.Key, Values: values}, nil
		case <-ctx.Done():
			return Expected{}, ctx.Err()
		}
	}
	return b
}

func TestConcurrentVerifiesShareOneResolution(t *testing.T) {
	src := newBlockingSource(teemA)
	v, _ := newTestVerifier(src)
	const n = 50
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() { errs <- v.Verify(ctxBg, peerA) }()
	}
	<-src.started
	close(src.release)
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if src.count() != 1 || v.Stats.Flights.Load() != 1 {
		t.Fatalf("calls %d flights %d", src.count(), v.Stats.Flights.Load())
	}
}

func TestACallerWhoseDeadlineEndsFirstIsRefusedAndTheNextOneIsServedFromTheCache(t *testing.T) {
	src := newBlockingSource(teemA)
	v, _ := newTestVerifier(src)
	ctx, cancel := context.WithTimeout(ctxBg, 50*time.Millisecond)
	defer cancel()
	err := v.Verify(ctx, peerA)
	if !errors.Is(err, ErrUnreachable) || !errors.Is(err, context.DeadlineExceeded) || CodeOf(err) != CodeTrustUnreachable {
		t.Fatalf("err = %v", err)
	}
	close(src.release)
	// The detached resolution completes and is cached.
	deadline := time.Now().Add(2 * time.Second)
	for {
		v.mu.Lock()
		n := len(v.inflight)
		v.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the resolution did not complete after the caller left")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := v.Verify(ctxBg, peerA); err != nil || src.count() != 1 {
		t.Fatalf("the next attempt should be served from the cache: err %v calls %d", err, src.count())
	}
}

func TestAHangingSourceIsRefusedAtTheResolveTimeoutAndNotCached(t *testing.T) {
	src := newBlockingSource(teemA) // never released: only the context ends it
	v, _ := newTestVerifier(src)
	v.ResolveTimeout = 50 * time.Millisecond
	start := time.Now()
	err := v.Verify(ctxBg, peerA)
	if !errors.Is(err, ErrUnreachable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("the resolve timeout did not bound the resolution")
	}
	if err := v.Verify(ctxBg, peerA); !errors.Is(err, ErrUnreachable) || src.count() != 2 {
		t.Fatalf("a timeout must not be cached: err %v calls %d", err, src.count())
	}
}

func TestTooManyResolutionsInProgressRefuses(t *testing.T) {
	src := newBlockingSource(teemA)
	v, _ := newTestVerifier(src)
	ctx, cancel := context.WithCancel(ctxBg)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < maxInflight; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = v.Verify(ctx, Peer{Identity: fmt.Sprintf("spiffe://zone-%d.example/gateway", i), Digests: peerA.Digests})
		}(i)
	}
	for i := 0; i < maxInflight; i++ {
		<-src.started
	}
	err := v.Verify(ctxBg, Peer{Identity: "spiffe://one-more.example/gateway", Digests: peerA.Digests})
	if !errors.Is(err, ErrUnreachable) || err.Error() != "trainresolve: trust resolution failed: too many resolutions in progress" {
		t.Fatalf("err = %v", err)
	}
	cancel()
	close(src.release)
	wg.Wait()
}

func TestTheCacheIsBounded(t *testing.T) {
	v, c := newTestVerifier(answering(teemA))
	for i := 0; i < maxCacheEntries; i++ {
		v.store(fmt.Sprintf("key-%d", i), Expected{})
	}
	c.advance(v.TTL) // every entry is now expired
	v.store("fresh", Expected{})
	if n := len(v.cache); n != 1 {
		t.Fatalf("after the sweep %d entries remain, want 1", n)
	}
	for i := 0; i < maxCacheEntries-1; i++ {
		v.store(fmt.Sprintf("live-%d", i), Expected{})
	}
	v.store("one-more", Expected{}) // nothing expired: the cache is emptied first
	if n := len(v.cache); n != 1 {
		t.Fatalf("at the bound with nothing expired %d entries remain, want 1", n)
	}
}

func TestLookupsWithOtherPointersAreOtherResolutions(t *testing.T) {
	src := answering(teemA)
	v, _ := newTestVerifier(src)
	a := New(src, WithPointers("zone-a.example"))
	a.now = v.now
	if err := v.Verify(ctxBg, peerA); err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(ctxBg, Peer{Identity: peerA.Identity, Digests: peerA.Digests}); err != nil {
		t.Fatal(err)
	}
	if cacheKey(Lookup{Key: "k", Pointers: []string{"b", "a"}}) != cacheKey(Lookup{Key: "k", Pointers: []string{"a", "b"}}) {
		t.Fatal("the order of the pointers must not matter")
	}
	if cacheKey(Lookup{Key: "k", Pointers: []string{"a"}}) == cacheKey(Lookup{Key: "k", Pointers: []string{"b"}}) {
		t.Fatal("other pointers are another resolution")
	}
}
