package trainresolve

import (
	"context"
	"sort"
	"strings"
	"time"
)

// cached is one resolution the verifier may still serve.
type cached struct {
	exp     Expected
	expires time.Time
}

// flight is one resolution in progress; every request for the same Lookup waits on it.
type flight struct {
	done chan struct{}
	exp  Expected
	err  error
}

// maxInflight bounds the resolutions running at once across distinct keys. The channel caps
// handshakes per listener; several listeners and dialers may share one verifier.
const maxInflight = 64

// maxCacheEntries bounds the cache: at the bound the expired entries are swept and, if that frees
// nothing, the cache is emptied. A zone talks to a handful of peers; this is a safety bound, not a
// tuning parameter.
const maxCacheEntries = 1024

// cacheKey tells lookups apart by key and by the pointers they start from, so that the same key
// asked through another zone is a different resolution.
func cacheKey(l Lookup) string {
	pointers := append([]string(nil), l.Pointers...)
	sort.Strings(pointers)
	return l.Key + "\x00" + strings.Join(pointers, ",")
}

// resolve answers from the cache, else joins or starts a resolution at the source. The resolution
// runs detached from ctx, bounded by ResolveTimeout, and is shared by every concurrent request for
// the same Lookup. A request whose ctx ends first is refused as ErrUnreachable (fail closed), but
// the resolution completes and is cached, so the peer's next attempt is answered from the cache: a
// cold resolution slower than the handshake budget cannot refuse a peer forever. A failed
// resolution is never cached.
func (v *Verifier) resolve(ctx context.Context, l Lookup) (Expected, bool, error) {
	key := cacheKey(l)
	if exp, ok := v.lookup(key); ok {
		v.Stats.Hits.Add(1)
		return exp, true, nil
	}
	f, exp, ok := v.start(key, l)
	if ok {
		v.Stats.Hits.Add(1) // a flight for this key finished between the lookup and the start
		return exp, true, nil
	}
	v.Stats.Misses.Add(1)
	if f == nil {
		return Expected{}, false, refuse(ErrUnreachable, "too many resolutions in progress", nil)
	}
	select {
	case <-f.done:
		if f.err != nil {
			return Expected{}, false, f.err
		}
		return f.exp, false, nil
	case <-ctx.Done():
		return Expected{}, false, refuse(ErrUnreachable, "the resolution was still in progress when the caller's deadline ended; it completes and is cached for the next attempt", ctx.Err())
	}
}

// start returns the cached resolution for key if one appeared since the lookup (a flight can finish
// in between), else joins the resolution in progress, else starts one; the flight is nil when too
// many are running. Cache and flights are read under one lock, so a finished flight is never missed.
func (v *Verifier) start(key string, l Lookup) (*flight, Expected, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if c, ok := v.cache[key]; ok && v.now().Before(c.expires) {
		return nil, c.exp, true
	}
	if f, ok := v.inflight[key]; ok {
		return f, Expected{}, false
	}
	if len(v.inflight) >= maxInflight {
		return nil, Expected{}, false
	}
	f := &flight{done: make(chan struct{})}
	v.inflight[key] = f
	v.Stats.Flights.Add(1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), v.ResolveTimeout)
		defer cancel()
		exp, err := v.src.Resolve(ctx, l)
		if err != nil {
			f.err = asRefusal(err)
		} else {
			exp = normalise(exp, l, v.now())
			f.exp = exp
			v.store(key, exp)
		}
		v.mu.Lock()
		delete(v.inflight, key)
		v.mu.Unlock()
		close(f.done)
	}()
	return f, Expected{}, false
}

// normalise fills what a Source may leave out and puts Values in the shape the comparison expects:
// deduplicated, sorted. Values that do not follow the grammar are left as they are; a Source is
// expected to have refused them, and a value that cannot equal a well-formed digest refuses by
// comparison anyway.
func normalise(exp Expected, l Lookup, now time.Time) Expected {
	if exp.Key == "" {
		exp.Key = l.Key
	}
	if len(exp.Pointers) == 0 {
		exp.Pointers = append([]string(nil), l.Pointers...)
	}
	if exp.ResolvedAt.IsZero() {
		exp.ResolvedAt = now
	}
	set := map[string]bool{}
	for _, val := range exp.Values {
		set[val] = true
	}
	values := make([]string, 0, len(set))
	for val := range set {
		values = append(values, val)
	}
	sort.Strings(values)
	exp.Values = values
	return exp
}

// lookup serves a resolution still within its TTL. The counting is resolve's, once it knows
// whether the verification was served from the cache or had to wait for a resolution.
func (v *Verifier) lookup(key string) (Expected, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	c, ok := v.cache[key]
	if !ok || !v.now().Before(c.expires) {
		return Expected{}, false
	}
	return c.exp, true
}

// store caches a resolution for TTL. Only resolutions get here: a failure is not knowledge about
// the peer and is never cached. An absence (no entry, no values) is a resolution too, and is cached
// for the same TTL, so that a peer nobody published does not reach TRAIN on every handshake; it
// becomes visible as soon as the window ends, like a change of value.
func (v *Verifier) store(key string, exp Expected) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.cache) >= maxCacheEntries {
		now := v.now()
		for k, c := range v.cache {
			if !now.Before(c.expires) {
				delete(v.cache, k)
			}
		}
		if len(v.cache) >= maxCacheEntries {
			v.cache = map[string]cached{}
		}
	}
	v.cache[key] = cached{exp: exp, expires: v.now().Add(v.TTL)}
}
