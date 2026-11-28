package trainresolve

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSource answers with fn and counts its calls.
type fakeSource struct {
	mu    sync.Mutex
	calls int
	fn    func(ctx context.Context, l Lookup) (Expected, error)
}

func (s *fakeSource) Resolve(ctx context.Context, l Lookup) (Expected, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return s.fn(ctx, l)
}

func (s *fakeSource) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func answering(values ...string) *fakeSource {
	return &fakeSource{fn: func(_ context.Context, l Lookup) (Expected, error) {
		return Expected{Key: l.Key, Values: values, EntryUUID: "entry-1"}, nil
	}}
}

// Three well-formed TEEM-sha256 values, in ascending order teemC < teemB < teemA.
const teemA = "783431065396a0483425b016f6925a321dee6c2146c5ab7244833aa888ebb60c"

var (
	teemB = strings.Repeat("210a7c3e", 8)
	teemC = strings.Repeat("0842477b", 8)
)

var ctxBg = context.Background()

func TestDefaultKey(t *testing.T) {
	cases := []struct {
		name, identity string
		wantKey        string
		wantPointer    string
		wantErr        bool
	}{
		{"spiffe id", "spiffe://zone-b.facis-ztd.local/gateway", "spiffe://zone-b.facis-ztd.local/gateway", "zone-b.facis-ztd.local", false},
		{"https uri with port and path", "https://gateway.zone-a.example:8443/x", "https://gateway.zone-a.example:8443/x", "gateway.zone-a.example", false},
		{"host case is folded, the key is not", "spiffe://Zone-B.Example/Gateway", "spiffe://Zone-B.Example/Gateway", "zone-b.example", false},
		{"dns san", "gateway.zone-b.example", "", "", true},
		{"empty", "", "", "", true},
		{"uri without host", "spiffe:///gateway", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, err := DefaultKey(tc.identity)
			if tc.wantErr {
				if !errors.Is(err, ErrZoneUnknown) {
					t.Fatalf("err = %v, want ErrZoneUnknown", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if l.Key != tc.wantKey || len(l.Pointers) != 1 || l.Pointers[0] != tc.wantPointer {
				t.Fatalf("got %+v, want key %q pointer %q", l, tc.wantKey, tc.wantPointer)
			}
		})
	}
}

func TestWithPointers(t *testing.T) {
	key := WithPointers("zone-a.example", "", "zone-b.example")
	l, err := key("gateway.zone-b.example")
	if err != nil {
		t.Fatal(err)
	}
	if l.Key != "gateway.zone-b.example" || strings.Join(l.Pointers, ",") != "zone-a.example,zone-b.example" {
		t.Fatalf("got %+v", l)
	}
	l.Pointers[0] = "changed"
	if l2, _ := key("x"); l2.Pointers[0] != "zone-a.example" {
		t.Fatal("the fixed pointers must not be shared with the caller")
	}
	if _, err := key(""); !errors.Is(err, ErrZoneUnknown) {
		t.Fatalf("empty identity: err = %v", err)
	}
	if _, err := WithPointers()("gateway"); !errors.Is(err, ErrZoneUnknown) {
		t.Fatalf("no pointers: err = %v", err)
	}
}

func TestPresentedDigests(t *testing.T) {
	upper := strings.ToUpper(teemA)
	got, seen := presentedDigests([]Digest{
		{teemB, "SHA-256"},
		{teemA, "sha256"},
		{teemA, "sha-256"}, // duplicate under another spelling
		{teemC, "SHA_256"},
		{teemA, "SHA-384"}, // another algorithm
		{teemA, ""},        // no algorithm stated
		{upper, "SHA-256"}, // uppercase: refused, not normalised
		{teemA[:63], "SHA-256"},
		{teemA + "0", "SHA-256"},
		{"sha256:" + teemA, "SHA-256"},
	})
	if seen != 10 {
		t.Fatalf("seen = %d", seen)
	}
	if strings.Join(got, " ") != strings.Join([]string{teemC, teemB, teemA}, " ") {
		t.Fatalf("presented = %v", got)
	}
}

func TestIsTEEMValue(t *testing.T) {
	for s, want := range map[string]bool{teemA: true, strings.ToUpper(teemA): false, teemA[:63]: false, teemA + "a": false, "sha256:" + teemA[7:]: false, "": false} {
		if IsTEEMValue(s) != want {
			t.Errorf("IsTEEMValue(%q) = %v, want %v", s, !want, want)
		}
	}
}

func TestVerifyFailsClosedInOrder(t *testing.T) {
	good := Peer{Identity: "spiffe://zone-b.example/gateway", Digests: []Digest{{teemA, "SHA-256"}}}

	t.Run("no identity: zone unknown, no network", func(t *testing.T) {
		src := answering(teemA)
		err := New(src, nil).Verify(ctxBg, Peer{Digests: good.Digests})
		if !errors.Is(err, ErrZoneUnknown) || CodeOf(err) != CodeZoneUnknown || src.count() != 0 {
			t.Fatalf("err = %v, calls = %d", err, src.count())
		}
	})
	t.Run("dns san with the default key: zone unknown, no network", func(t *testing.T) {
		src := answering(teemA)
		err := New(src, nil).Verify(ctxBg, Peer{Identity: "gateway.zone-b.example", Digests: good.Digests})
		if !errors.Is(err, ErrZoneUnknown) || src.count() != 0 {
			t.Fatalf("err = %v, calls = %d", err, src.count())
		}
	})
	t.Run("key function returning a plain error: zone unknown", func(t *testing.T) {
		src := answering(teemA)
		v := New(src, func(string) (Lookup, error) { return Lookup{}, errors.New("boom") })
		err := v.Verify(ctxBg, good)
		if !errors.Is(err, ErrZoneUnknown) || src.count() != 0 {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("key function returning an empty lookup: zone unknown", func(t *testing.T) {
		src := answering(teemA)
		v := New(src, func(id string) (Lookup, error) { return Lookup{Key: id}, nil })
		if err := v.Verify(ctxBg, good); !errors.Is(err, ErrZoneUnknown) || src.count() != 0 {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no usable digest: mismatch, no network", func(t *testing.T) {
		src := answering(teemA)
		err := New(src, nil).Verify(ctxBg, Peer{Identity: good.Identity, Digests: []Digest{{strings.ToUpper(teemA), "SHA-256"}, {teemA, "SHA-384"}}})
		if !errors.Is(err, ErrMismatch) || CodeOf(err) != CodeMeasurementMismatch || src.count() != 0 {
			t.Fatalf("err = %v, calls = %d", err, src.count())
		}
		if !strings.Contains(err.Error(), "2 measurement(s) seen") {
			t.Fatalf("reason does not count what was seen: %v", err)
		}
	})
	t.Run("source: zone unknown passes through", func(t *testing.T) {
		src := &fakeSource{fn: func(context.Context, Lookup) (Expected, error) {
			return Expected{}, refuse(ErrZoneUnknown, "no trust list behind the pointer", nil)
		}}
		err := New(src, nil).Verify(ctxBg, good)
		if !errors.Is(err, ErrZoneUnknown) || CodeOf(err) != CodeZoneUnknown {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("source: a plain error is unreachable", func(t *testing.T) {
		cause := errors.New("connection refused")
		src := &fakeSource{fn: func(context.Context, Lookup) (Expected, error) { return Expected{}, cause }}
		err := New(src, nil).Verify(ctxBg, good)
		if !errors.Is(err, ErrUnreachable) || !errors.Is(err, cause) || CodeOf(err) != CodeTrustUnreachable {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no value published: unpublished", func(t *testing.T) {
		src := &fakeSource{fn: func(_ context.Context, l Lookup) (Expected, error) {
			return Expected{Key: l.Key, EntryUUID: "entry-9"}, nil
		}}
		err := New(src, nil).Verify(ctxBg, good)
		if !errors.Is(err, ErrUnpublished) || CodeOf(err) != CodeMeasurementUnpublished {
			t.Fatalf("err = %v", err)
		}
		if !strings.Contains(err.Error(), "entry-9") || !strings.Contains(err.Error(), good.Identity) {
			t.Fatalf("reason names neither the entry nor the key: %v", err)
		}
	})
	t.Run("value differs: mismatch", func(t *testing.T) {
		err := New(answering(teemB), nil).Verify(ctxBg, good)
		if !errors.Is(err, ErrMismatch) {
			t.Fatalf("err = %v", err)
		}
		if !strings.Contains(err.Error(), teemA[:12]) || !strings.Contains(err.Error(), teemB[:12]) || strings.Contains(err.Error(), teemA) {
			t.Fatalf("reason should abbreviate both sides: %v", err)
		}
	})
	t.Run("set semantics: the second published value matches", func(t *testing.T) {
		if err := New(answering(teemB, teemA), nil).Verify(ctxBg, good); err != nil {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("set semantics: the second presented digest matches", func(t *testing.T) {
		v := New(answering(teemC), nil)
		if err := v.Verify(ctxBg, Peer{Identity: good.Identity, Digests: []Digest{{teemA, "SHA-256"}, {teemC, "SHA-256"}}}); err != nil {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("refusals are counted, acceptances are not", func(t *testing.T) {
		v := New(answering(teemA), nil)
		_ = v.Verify(ctxBg, good)
		_ = v.Verify(ctxBg, Peer{Identity: good.Identity, Digests: []Digest{{teemB, "SHA-256"}}})
		_ = v.Verify(ctxBg, Peer{})
		if n := v.Stats.Refusals.Load(); n != 2 {
			t.Fatalf("refusals = %d", n)
		}
	})
}

func TestVerifyPassesTheLookupToTheSource(t *testing.T) {
	var got Lookup
	src := &fakeSource{fn: func(_ context.Context, l Lookup) (Expected, error) {
		got = l
		return Expected{Values: []string{teemA}}, nil
	}}
	v := New(src, WithPointers("zone-a.example"))
	if err := v.Verify(ctxBg, Peer{Identity: "gateway.zone-a.example", Digests: []Digest{{teemA, "SHA-256"}}}); err != nil {
		t.Fatal(err)
	}
	if got.Key != "gateway.zone-a.example" || strings.Join(got.Pointers, ",") != "zone-a.example" {
		t.Fatalf("lookup = %+v", got)
	}
}

func TestResolveFillsTheExpected(t *testing.T) {
	src := &fakeSource{fn: func(context.Context, Lookup) (Expected, error) {
		return Expected{Values: []string{teemB, teemA, teemB}}, nil
	}}
	v := New(src, nil)
	exp, fromCache, err := v.Resolve(ctxBg, "spiffe://zone-b.example/gateway")
	if err != nil || fromCache {
		t.Fatalf("err = %v, fromCache = %v", err, fromCache)
	}
	if exp.Key != "spiffe://zone-b.example/gateway" || strings.Join(exp.Pointers, ",") != "zone-b.example" || exp.ResolvedAt.IsZero() {
		t.Fatalf("expected not filled: %+v", exp)
	}
	if strings.Join(exp.Values, " ") != teemB+" "+teemA {
		t.Fatalf("values not deduplicated and sorted: %v", exp.Values)
	}
	if _, fromCache, _ = v.Resolve(ctxBg, "spiffe://zone-b.example/gateway"); !fromCache {
		t.Fatal("second resolution should come from the cache")
	}
	if _, _, err := v.Resolve(ctxBg, ""); !errors.Is(err, ErrZoneUnknown) {
		t.Fatalf("err = %v", err)
	}
}

func TestCheckReportsTheOutcome(t *testing.T) {
	src := answering(teemB, teemA)
	v := New(src, nil)
	peer := Peer{Identity: "spiffe://zone-b.example/gateway", Digests: []Digest{{teemA, "SHA-256"}, {teemA, "sha256"}, {"zz", "SHA-256"}}}
	out, err := v.Check(ctxBg, peer)
	if err != nil {
		t.Fatal(err)
	}
	if out.FromCache || out.Expected.EntryUUID != "entry-1" || strings.Join(out.Expected.Values, " ") != teemB+" "+teemA || strings.Join(out.Presented, " ") != teemA {
		t.Fatalf("outcome = %+v", out)
	}
	out, err = v.Check(ctxBg, Peer{Identity: peer.Identity, Digests: []Digest{{teemC, "SHA-256"}}})
	if !errors.Is(err, ErrMismatch) || !out.FromCache || len(out.Expected.Values) != 2 {
		t.Fatalf("mismatch outcome = %+v, err %v", out, err)
	}
	out, err = v.Check(ctxBg, Peer{Identity: peer.Identity})
	if !errors.Is(err, ErrMismatch) || out.Expected.Key != "" || src.count() != 1 {
		t.Fatalf("a peer without a digest is refused before TRAIN: %+v, err %v, calls %d", out, err, src.count())
	}
	out, err = v.Check(ctxBg, Peer{Digests: peer.Digests})
	if !errors.Is(err, ErrZoneUnknown) || out.Presented != nil {
		t.Fatalf("a peer without an identity is refused first: %+v, err %v", out, err)
	}
}

func TestNewPanicsWithoutASource(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New(nil, nil) should panic")
		}
	}()
	New(nil, nil)
}

func TestErrors(t *testing.T) {
	cause := errors.New("dial tcp: connection refused")
	e := refuse(ErrUnreachable, "the resolver did not answer", cause)
	if !errors.Is(e, ErrUnreachable) || !errors.Is(e, cause) || errors.Is(e, ErrMismatch) {
		t.Fatal("errors.Is must match the sentinel and the cause only")
	}
	if got := e.Error(); got != "trainresolve: trust resolution failed: the resolver did not answer: dial tcp: connection refused" {
		t.Fatalf("text = %q", got)
	}
	if CodeOf(e) != CodeTrustUnreachable || CodeOf(nil) != "" || CodeOf(errors.New("other")) != "" {
		t.Fatal("CodeOf")
	}
	var wrapped error = &wrapper{e}
	if CodeOf(wrapped) != CodeTrustUnreachable || !errors.Is(wrapped, ErrUnreachable) {
		t.Fatal("a wrapped refusal must still be found")
	}
	for kind, code := range map[error]string{ErrMismatch: CodeMeasurementMismatch, ErrUnpublished: CodeMeasurementUnpublished, ErrZoneUnknown: CodeZoneUnknown, ErrUnreachable: CodeTrustUnreachable} {
		if r := refuse(kind, "", nil); r.Code != code || len(r.Unwrap()) != 1 {
			t.Errorf("%v: code %q, unwrap %d", kind, r.Code, len(r.Unwrap()))
		}
	}
	if asRefusal(e) != e {
		t.Fatal("asRefusal must keep a refusal as it is")
	}
	if r := asRefusal(cause); r.Kind != ErrUnreachable || !errors.Is(r, cause) {
		t.Fatalf("asRefusal(plain) = %v", r)
	}
}

type wrapper struct{ err error }

func (w *wrapper) Error() string { return "wrapped: " + w.err.Error() }
func (w *wrapper) Unwrap() error { return w.err }

// clock is a fake time source for the cache tests.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}
