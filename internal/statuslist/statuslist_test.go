package statuslist_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt/sdjwtfixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/statuslist"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/statuslist/statuslistfixture"
)

const (
	issuer = "https://issuer.zone-a.example"
	kid    = "issuer-1"
	uri    = "https://status.zone-a.example/lists/1.jwt"
)

var (
	now       = time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	issuerKey = sdjwtfixture.TestIssuerKey()
	otherKey  = sdjwtfixture.TestOtherIssuerKey()
)

func trust() if03.Issuers { return if03.Issuers{issuer: {kid: &issuerKey.PublicKey}} }

// trustTwo trusts a second issuer as well: its lists are good for its own credentials only.
func trustTwo() if03.Issuers {
	return if03.Issuers{issuer: {kid: &issuerKey.PublicKey}, "https://other.example": {"other-1": &otherKey.PublicKey}}
}

func options() statuslistfixture.Options {
	return statuslistfixture.Options{Key: issuerKey, Kid: kid, Issuer: issuer, Subject: uri, Bits: 1, Size: 1024,
		Set: map[int]statuslist.Status{42: statuslist.Invalid}, IssuedAt: now.Add(-time.Minute)}
}

func sign(t *testing.T, o statuslistfixture.Options) string {
	t.Helper()
	tok, err := statuslistfixture.Sign(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestParse_Entries(t *testing.T) {
	l, err := statuslist.Parse(sign(t, options()), trust(), issuer, uri, now)
	if err != nil {
		t.Fatal(err)
	}
	if l.Len() != 1024 || l.Bits != 1 || l.Issuer != issuer || l.Subject != uri {
		t.Errorf("list: %+v", l)
	}
	for idx, want := range map[int]statuslist.Status{0: statuslist.Valid, 41: statuslist.Valid, 42: statuslist.Invalid, 43: statuslist.Valid, 1023: statuslist.Valid} {
		got, err := l.At(idx)
		if err != nil || got != want {
			t.Errorf("At(%d) = %v, %v; want %v", idx, got, err, want)
		}
	}
	if _, err := l.At(1024); !errors.Is(err, statuslist.ErrUnavailable) {
		t.Errorf("out of range: %v", err)
	}
	if _, err := l.At(-1); !errors.Is(err, statuslist.ErrUnavailable) {
		t.Errorf("negative: %v", err)
	}

	o := options()
	o.Bits, o.Size, o.Set = 2, 100, map[int]statuslist.Status{7: statuslist.Suspended, 8: statuslist.Invalid, 99: 3}
	l, err = statuslist.Parse(sign(t, o), trust(), issuer, uri, now)
	if err != nil {
		t.Fatal(err)
	}
	for idx, want := range map[int]statuslist.Status{6: 0, 7: statuslist.Suspended, 8: statuslist.Invalid, 99: 3} {
		if got, _ := l.At(idx); got != want {
			t.Errorf("2-bit At(%d) = %v, want %v", idx, got, want)
		}
	}
	if l.Len() != 100 {
		t.Errorf("2-bit len %d", l.Len())
	}
}

func TestParse_Refusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		tok  func() string
		uri  string
		at   time.Time
		want error
	}{
		{"unknown kid", func() string { o := options(); o.Kid = "issuer-9"; return sign(t, o) }, uri, now, statuslist.ErrUnavailable},
		{"wrong key", func() string { o := options(); o.Key = otherKey; return sign(t, o) }, uri, now, statuslist.ErrUnavailable},
		{"iss is not the key owner", func() string { o := options(); o.Issuer = "https://other.example"; return sign(t, o) }, uri, now, statuslist.ErrUnavailable},
		{"signed by another trusted issuer", func() string {
			o := options()
			o.Key, o.Kid, o.Issuer = otherKey, "other-1", "https://other.example"
			return sign(t, o)
		}, uri, now, statuslist.ErrUnavailable},
		{"sub is another list", func() string { return sign(t, options()) }, "https://status.zone-a.example/lists/2.jwt", now, statuslist.ErrUnavailable},
		{"expired", func() string { o := options(); o.ExpiresAt = now.Add(-time.Second); return sign(t, o) }, uri, now, statuslist.ErrUnavailable},
		{"not a JWT", func() string { return "nope" }, uri, now, statuslist.ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := statuslist.Parse(tc.tok(), trustTwo(), issuer, tc.uri, tc.at); !errors.Is(err, tc.want) {
				t.Errorf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// signRaw signs an arbitrary status-list payload with the trusted key, for malformed-payload cases.
func signRaw(t *testing.T, payload string) string {
	t.Helper()
	tok, err := jose.Sign(context.Background(), jose.Header{Typ: statuslist.Typ, Kid: kid}, []byte(payload), func(_ context.Context, in []byte) ([]byte, error) {
		return sdjwtfixture.SignES256(issuerKey, in)
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestParse_MalformedPayloads(t *testing.T) {
	good, err := statuslist.Parse(sign(t, options()), trust(), issuer, uri, now)
	if err != nil {
		t.Fatal(err)
	}
	_ = good
	lst := func() string {
		tok := sign(t, options())
		payload, _ := jose.DecodeB64(strings.Split(tok, ".")[1])
		m, _ := jose.ParseObject(payload)
		sl, _ := jose.ParseObject(m["status_list"])
		v, _, _ := jose.String(sl, "lst")
		return v
	}()
	base := func(statusList, extra string) string {
		return `{"iss":"` + issuer + `","sub":"` + uri + `","iat":1757419200` + extra + `,"status_list":` + statusList + `}`
	}
	for _, tc := range []struct{ name, payload string }{
		{"status_list extra member", base(`{"bits":1,"lst":"`+lst+`","foo":1}`, "")},
		{"aggregation_uri not a string", base(`{"bits":1,"lst":"`+lst+`","aggregation_uri":1}`, "")},
		{"bits null", base(`{"bits":null,"lst":"`+lst+`"}`, "")},
		{"bits 3", base(`{"bits":3,"lst":"`+lst+`"}`, "")},
		{"bits as float", base(`{"bits":1.0,"lst":"`+lst+`"}`, "")},
		{"lst missing", base(`{"bits":1}`, "")},
		{"ttl null", base(`{"bits":1,"lst":"`+lst+`"}`, `,"ttl":null`)},
		{"ttl zero", base(`{"bits":1,"lst":"`+lst+`"}`, `,"ttl":0`)},
		{"ttl a year and a day", base(`{"bits":1,"lst":"`+lst+`"}`, `,"ttl":31708801`)},
		{"exp null", base(`{"bits":1,"lst":"`+lst+`"}`, `,"exp":null`)},
		{"exp negative", base(`{"bits":1,"lst":"`+lst+`"}`, `,"exp":-1`)},
		{"iat missing", `{"iss":"` + issuer + `","sub":"` + uri + `","status_list":{"bits":1,"lst":"` + lst + `"}}`},
		{"sub empty", `{"iss":"` + issuer + `","sub":"","iat":1,"status_list":{"bits":1,"lst":"` + lst + `"}}`},
		{"not an object", `[]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := statuslist.Parse(signRaw(t, tc.payload), trust(), issuer, uri, now)
			if !errors.Is(err, statuslist.ErrMalformed) {
				t.Errorf("got %v", err)
			}
		})
	}
	t.Run("aggregation_uri is allowed", func(t *testing.T) {
		if _, err := statuslist.Parse(signRaw(t, base(`{"bits":1,"lst":"`+lst+`","aggregation_uri":"https://status.zone-a.example/all"}`, "")), trust(), issuer, uri, now); err != nil {
			t.Errorf("got %v", err)
		}
	})
}

func TestClient(t *testing.T) {
	var serves atomic.Int32
	var current atomic.Value
	current.Store(sign(t, options()))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serves.Add(1)
		if r.Header.Get("Accept") != statuslist.MediaType {
			t.Errorf("accept header %q", r.Header.Get("Accept"))
		}
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/lists/1.jwt", http.StatusFound)
		case "/missing":
			http.NotFound(w, r)
		case "/huge":
			w.Header().Set("Content-Type", statuslist.MediaType)
			_, _ = w.Write([]byte(strings.Repeat("a", statuslist.MaxTokenSize+1)))
		default:
			w.Header().Set("Content-Type", statuslist.MediaType)
			_, _ = w.Write([]byte(current.Load().(string)))
		}
	}))
	defer srv.Close()
	listURI := srv.URL + "/lists/1.jwt"
	clock := now
	c := &statuslist.Client{HTTP: srv.Client(), Trusted: trust(), AllowedPrefixes: []string{srv.URL + "/"}, CacheTTL: 60 * time.Second,
		Now: func() time.Time { return clock }}
	ctx := context.Background()

	t.Run("sub must match the fetched uri", func(t *testing.T) {
		if _, err := c.Status(ctx, issuer, listURI, 42); !errors.Is(err, statuslist.ErrUnavailable) {
			t.Errorf("got %v", err)
		}
	})
	o := options()
	o.Subject = listURI
	current.Store(sign(t, o))
	serves.Store(0)
	t.Run("fetch, then cache", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			s, err := c.Status(ctx, issuer, listURI, 42)
			if err != nil || s != statuslist.Invalid {
				t.Fatalf("got %v, %v", s, err)
			}
		}
		if s, _ := c.Status(ctx, issuer, listURI, 41); s != statuslist.Valid {
			t.Error("entry 41 is not valid")
		}
		if serves.Load() != 1 {
			t.Errorf("served %d times", serves.Load())
		}
	})
	t.Run("cache expires with the TTL", func(t *testing.T) {
		clock = clock.Add(61 * time.Second)
		if _, err := c.Status(ctx, issuer, listURI, 42); err != nil {
			t.Fatal(err)
		}
		if serves.Load() != 2 {
			t.Errorf("served %d times", serves.Load())
		}
	})
	t.Run("the token's ttl shortens the cache", func(t *testing.T) {
		o := options()
		o.Subject, o.TTL = listURI, 5*time.Second
		current.Store(sign(t, o))
		clock = clock.Add(61 * time.Second)
		serves.Store(0)
		_, _ = c.Status(ctx, issuer, listURI, 1)
		clock = clock.Add(4 * time.Second)
		_, _ = c.Status(ctx, issuer, listURI, 1)
		if serves.Load() != 1 {
			t.Errorf("served %d times within the ttl", serves.Load())
		}
		clock = clock.Add(2 * time.Second)
		_, _ = c.Status(ctx, issuer, listURI, 1)
		if serves.Load() != 2 {
			t.Errorf("served %d times after the ttl", serves.Load())
		}
	})
	t.Run("stale cache is never relied on", func(t *testing.T) {
		clock = clock.Add(61 * time.Second)
		current.Store("broken")
		if _, err := c.Status(ctx, issuer, listURI, 42); !errors.Is(err, statuslist.ErrUnavailable) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("a cached list is not believed for another issuer", func(t *testing.T) {
		o := options()
		o.Subject = listURI
		current.Store(sign(t, o))
		clock = clock.Add(61 * time.Second)
		if _, err := c.Status(ctx, issuer, listURI, 42); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Status(ctx, "https://other.example", listURI, 42); !errors.Is(err, statuslist.ErrUnavailable) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("server down with a stale entry", func(t *testing.T) {
		down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			o := options()
			o.Subject = listURI
			_, _ = w.Write([]byte(sign(t, o)))
		}))
		downURI := down.URL + "/lists/1.jwt"
		o := options()
		o.Subject = downURI
		downTok := sign(t, o)
		down.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(downTok)) })
		at := now
		dc := &statuslist.Client{HTTP: down.Client(), Trusted: trust(), AllowedPrefixes: []string{down.URL + "/"}, CacheTTL: time.Minute, Timeout: time.Second,
			Now: func() time.Time { return at }}
		if s, err := dc.Status(ctx, issuer, downURI, 42); err != nil || s != statuslist.Invalid {
			t.Fatalf("got %v, %v", s, err)
		}
		down.Close()
		at = at.Add(30 * time.Second)
		if s, err := dc.Status(ctx, issuer, downURI, 42); err != nil || s != statuslist.Invalid {
			t.Fatalf("within the cache window: %v, %v", s, err)
		}
		at = at.Add(31 * time.Second)
		if _, err := dc.Status(ctx, issuer, downURI, 42); !errors.Is(err, statuslist.ErrUnavailable) {
			t.Errorf("after the window with the server gone: %v", err)
		}
	})
	t.Run("prefix not allowed", func(t *testing.T) {
		other := &statuslist.Client{HTTP: srv.Client(), Trusted: trust(), AllowedPrefixes: []string{"https://status.zone-a.example/"}}
		if _, err := other.Status(ctx, issuer, listURI, 42); !errors.Is(err, statuslist.ErrUnavailable) {
			t.Errorf("got %v", err)
		}
	})
	fresh := func() *statuslist.Client {
		return &statuslist.Client{HTTP: srv.Client(), Trusted: trust(), AllowedPrefixes: []string{srv.URL + "/"}, Now: func() time.Time { return now }}
	}
	t.Run("redirect refused", func(t *testing.T) {
		if _, err := fresh().Status(ctx, issuer, srv.URL+"/redirect", 42); !errors.Is(err, statuslist.ErrUnavailable) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("not found", func(t *testing.T) {
		if _, err := fresh().Status(ctx, issuer, srv.URL+"/missing", 42); !errors.Is(err, statuslist.ErrUnavailable) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("body too large", func(t *testing.T) {
		if _, err := fresh().Status(ctx, issuer, srv.URL+"/huge", 42); !errors.Is(err, statuslist.ErrUnavailable) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("server gone", func(t *testing.T) {
		gone := httptest.NewServer(http.NotFoundHandler())
		gone.Close()
		c := &statuslist.Client{Trusted: trust(), AllowedPrefixes: []string{gone.URL}, Timeout: time.Second}
		if _, err := c.Status(ctx, issuer, gone.URL+"/lists/1.jwt", 42); !errors.Is(err, statuslist.ErrUnavailable) {
			t.Errorf("got %v", err)
		}
	})
}

func TestValidPrefix(t *testing.T) {
	for _, p := range []string{"https://status.zone-a.example/", "https://status.zone-a.example/lists/", "http://127.0.0.1:8080/", "https://[::1]:8443/x/"} {
		if err := statuslist.ValidPrefix(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	for _, p := range []string{"", "status.zone-a.example/", "https://status.zone-a.example", "ftp://status.zone-a.example/", "https://user@status.zone-a.example/",
		"https://status.zone-a.example/?x=1", "https://status.zone-a.example/#f", "https://status.zone-a.example/a/../", "https://status.zone-a.example/a/%2e%2e/",
		"https://status.zone-a.example/./", "https:///lists/", "mailto:a@b"} {
		if err := statuslist.ValidPrefix(p); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
}

// TestClient_PrefixMatchesHostNotString: the prefix is matched on the parsed scheme, host and path,
// so a host that merely starts with the same characters, or a userinfo trick, never matches.
func TestClient_PrefixMatchesHostNotString(t *testing.T) {
	var hosts []string
	c := &statuslist.Client{Trusted: trust(), AllowedPrefixes: []string{"https://status.zone-a.example", "https://status.zone-a.example/lists/", "", "nonsense"},
		HTTP: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			hosts = append(hosts, r.URL.Host)
			return &http.Response{StatusCode: http.StatusNotFound, Body: http.NoBody, Request: r}, nil
		})}}
	ctx := context.Background()
	for _, uri := range []string{
		"https://status.zone-a.example.evil.net/lists/1.jwt",
		"https://status.zone-a.example@evil.example/lists/1.jwt",
		"https://status.zone-a.example/other/1.jwt",
		"https://status.zone-a.example:8443/lists/1.jwt",
		"http://status.zone-a.example/lists/1.jwt",
		"https://status.zone-a.example/lists/../secret/1.jwt",
		"https://status.zone-a.example/lists/..",
		"https://status.zone-a.example/lists/%2e%2e/secret/1.jwt",
		"https://status.zone-a.example/lists/.%2e/secret/1.jwt",
		"https://status.zone-a.example/lists/..%2fsecret/1.jwt",
		"https://status.zone-a.example/lists/./1.jwt",
		"https://status.zone-a.example/lists/..;/secret/1.jwt",
		"https://status.zone-a.example/lists/%2e%2e;x/secret/1.jwt",
		"https://status.zone-a.example/lists/%2e/1.jwt",
		"https://status.zone-a.example",
		"not a uri",
	} {
		if _, err := c.Status(ctx, issuer, uri, 1); !errors.Is(err, statuslist.ErrUnavailable) {
			t.Errorf("%s: %v", uri, err)
		}
	}
	if len(hosts) != 0 {
		t.Fatalf("fetched from %v", hosts)
	}
	for _, uri := range []string{"https://status.zone-a.example/lists/1.jwt", "HTTPS://STATUS.zone-a.example/lists/sub/2.jwt"} {
		_, _ = c.Status(ctx, issuer, uri, 1)
	}
	if len(hosts) != 2 {
		t.Errorf("allowed URIs fetched %d times", len(hosts))
	}
}

func TestClient_SingleFlightAndEviction(t *testing.T) {
	var serves atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serves.Add(1)
		time.Sleep(5 * time.Millisecond)
		o := options()
		o.Subject = "http://" + r.Host + r.URL.Path
		_, _ = w.Write([]byte(sign(t, o)))
	}))
	defer srv.Close()
	c := &statuslist.Client{HTTP: srv.Client(), Trusted: trust(), AllowedPrefixes: []string{srv.URL + "/"}}
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s, err := c.Status(ctx, issuer, srv.URL+"/lists/1.jwt", 42); err != nil || s != statuslist.Invalid {
				t.Errorf("got %v, %v", s, err)
			}
		}()
	}
	wg.Wait()
	if serves.Load() != 1 {
		t.Errorf("50 concurrent misses fetched %d times", serves.Load())
	}
	// Many distinct lists: the cache stays bounded and every answer is still right.
	for i := 0; i < 300; i++ {
		if s, err := c.Status(ctx, issuer, fmt.Sprintf("%s/lists/%d.jwt", srv.URL, i), 42); err != nil || s != statuslist.Invalid {
			t.Fatalf("list %d: %v, %v", i, s, err)
		}
	}
	if n := c.Cached(); n == 0 || n > 256 {
		t.Errorf("%d lists cached", n)
	}
}

// TestClient_FlightSurvivesPanicAndCancellation: a transport that panics does not strand the
// flight (later callers are answered, not hung), and a leader that gives up does not fail a
// follower whose own context is live.
func TestClient_FlightSurvivesPanicAndCancellation(t *testing.T) {
	var calls atomic.Int32
	c := &statuslist.Client{Trusted: trust(), AllowedPrefixes: []string{"https://s.example/"}, Timeout: time.Second,
		HTTP: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			if calls.Add(1) == 1 {
				panic("transport broke")
			}
			return &http.Response{StatusCode: http.StatusNotFound, Body: http.NoBody, Request: r}, nil
		})}}
	func() {
		defer func() { _ = recover() }()
		_, _ = c.Status(context.Background(), issuer, "https://s.example/1.jwt", 1)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.Status(ctx, issuer, "https://s.example/1.jwt", 1); !errors.Is(err, statuslist.ErrUnavailable) || ctx.Err() != nil {
		t.Fatalf("after a panicking flight: %v (ctx %v)", err, ctx.Err())
	}

	started := make(chan struct{})
	release := make(chan struct{})
	slow := &statuslist.Client{Trusted: trust(), AllowedPrefixes: []string{"https://s.example/"}, Timeout: 5 * time.Second,
		HTTP: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			close(started)
			<-release
			o := options()
			o.Subject = "https://s.example/2.jwt"
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(sign(t, o))), Request: r}, nil
		})}}
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, err := slow.Status(leaderCtx, issuer, "https://s.example/2.jwt", 42)
		leaderDone <- err
	}()
	<-started
	followerDone := make(chan error, 1)
	go func() {
		_, err := slow.Status(context.Background(), issuer, "https://s.example/2.jwt", 42)
		followerDone <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancelLeader()
	close(release)
	if err := <-followerDone; err != nil {
		t.Errorf("follower with a live context: %v", err)
	}
	if err := <-leaderDone; err != nil {
		t.Errorf("the leader's fetch is detached from its context: %v", err)
	}
}

func TestZeroListAndErrors(t *testing.T) {
	var l statuslist.List
	if l.Len() != 0 {
		t.Error("zero list has entries")
	}
	if _, err := l.At(0); !errors.Is(err, statuslist.ErrUnavailable) {
		t.Errorf("zero list At: %v", err)
	}
	if !errors.Is(statuslist.ErrMalformed, statuslist.ErrUnavailable) {
		t.Error("a malformed list is not reported as unavailable")
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
