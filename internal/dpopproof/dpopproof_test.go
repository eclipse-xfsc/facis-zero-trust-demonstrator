package dpopproof

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
)

type testKey struct{ k *ecdsa.PrivateKey }

func newTestKey(t testing.TB) testKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{k}
}

func (k testKey) JWK() jose.JWK { return jose.PublicJWK(&k.k.PublicKey) }

func (k testKey) Sign(_ context.Context, in []byte) ([]byte, error) {
	d := sha256.Sum256(in)
	r, s, err := ecdsa.Sign(rand.Reader, k.k, d[:])
	if err != nil {
		return nil, err
	}
	return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...), nil
}

func (k testKey) jkt(t testing.TB) string {
	j, err := k.JWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	return j
}

// memStore is an in-memory replay.Store.
type memStore struct {
	mu   sync.Mutex
	seen map[replay.Use]bool
	last replay.Use
}

func newStore() *memStore { return &memStore{seen: map[replay.Use]bool{}} }

func (s *memStore) TryUse(_ context.Context, u replay.Use) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = u
	key := u
	key.NotAfter = time.Time{}
	if s.seen[key] {
		return false, nil
	}
	s.seen[key] = true
	return true, nil
}

type failingStore struct{}

func (failingStore) TryUse(context.Context, replay.Use) (bool, error) {
	return true, errors.New("database unreachable")
}

const uri = "https://api.example.com/resource"

var (
	policy = Policy{Lifespan: 60 * time.Second, Skew: 5 * time.Second}
	now    = time.Unix(1_800_000_000, 0)
)

func build(t testing.TB, k testKey, c Claims) string {
	t.Helper()
	p, err := Build(context.Background(), k, c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBuildVerify_ValidProofPasses(t *testing.T) {
	k := newTestKey(t)
	store := newStore()
	p := build(t, k, Claims{HTM: "GET", HTU: uri, IAT: now, ATH: ath("tok"), Nonce: "n1"})
	v, err := Verify(context.Background(), p, Expect{Method: "GET", URI: uri, AccessToken: "tok", JKT: k.jkt(t), Nonce: "n1"}, policy, now, store)
	if err != nil {
		t.Fatal(err)
	}
	if v.JKT != k.jkt(t) || v.Claims.HTU != uri || !v.Claims.IAT.Equal(now) || v.Claims.JTI == "" {
		t.Errorf("verified = %+v", v)
	}
	if want := now.Add(policy.Lifespan + policy.Skew); !v.NotAfter.Equal(want) || !store.last.NotAfter.Equal(want) {
		t.Errorf("NotAfter = %v, store %v, want %v", v.NotAfter, store.last.NotAfter, want)
	}
	if store.last.JKT != v.JKT || store.last.Method != "GET" || store.last.URI != uri || store.last.JTI != v.Claims.JTI {
		t.Errorf("replay use = %+v", store.last)
	}
}

func TestBuild_HeaderAndClaimsAreTheRFC9449Shape(t *testing.T) {
	k := newTestKey(t)
	p := build(t, k, Claims{HTM: "POST", HTU: uri, IAT: now})
	parts := strings.Split(p, ".")
	h, _ := base64.RawURLEncoding.DecodeString(parts[0])
	c, _ := base64.RawURLEncoding.DecodeString(parts[1])
	j := k.JWK()
	if want := `{"alg":"ES256","typ":"dpop+jwt","jwk":{"kty":"EC","crv":"P-256","x":"` + j.X + `","y":"` + j.Y + `"}}`; string(h) != want {
		t.Errorf("header = %s", h)
	}
	if !strings.HasSuffix(string(c), `"htm":"POST","htu":"`+uri+`","iat":1800000000}`) || strings.Contains(string(c), "ath") || strings.Contains(string(c), "nonce") {
		t.Errorf("claims = %s", c)
	}
	jtis := map[string]bool{}
	for range 50 {
		v, err := Verify(context.Background(), build(t, k, Claims{HTM: "GET", HTU: uri, IAT: now}), Expect{Method: "GET", URI: uri}, policy, now, newStore())
		if err != nil {
			t.Fatal(err)
		}
		if raw, err := base64.RawURLEncoding.DecodeString(v.Claims.JTI); err != nil || len(raw) != 16 || jtis[v.Claims.JTI] {
			t.Fatalf("generated jti %q is not a fresh 128-bit base64url value", v.Claims.JTI)
		}
		jtis[v.Claims.JTI] = true
	}
}

func TestVerify_AcceptsProofFromRepoTestMinter(t *testing.T) {
	k := newTestKey(t)
	p := mintLikeDpoptest(t, k.k, minterProof{Method: "POST", URL: uri, IssuedAt: now, AccessToken: "tok", Nonce: "n"})
	v, err := Verify(context.Background(), p, Expect{Method: "POST", URI: uri, AccessToken: "tok", Nonce: "n", JKT: minterThumbprint(k.k)}, policy, now, newStore())
	if err != nil {
		t.Fatal(err)
	}
	if v.JKT != minterThumbprint(k.k) {
		t.Errorf("jkt = %s, minter says %s", v.JKT, minterThumbprint(k.k))
	}
}

func TestVerify_IATWindow(t *testing.T) {
	k := newTestKey(t)
	for _, tc := range []struct {
		name   string
		iat    time.Time
		accept bool
	}{
		{"now", now, true},
		{"in the future within skew", now.Add(policy.Skew), true},
		{"in the future beyond skew", now.Add(policy.Skew + time.Second), false},
		{"at the end of lifespan plus skew", now.Add(-policy.Lifespan - policy.Skew), true},
		{"expired", now.Add(-policy.Lifespan - policy.Skew - time.Second), false},
		{"long expired", now.Add(-24 * time.Hour), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := build(t, k, Claims{HTM: "GET", HTU: uri, IAT: tc.iat})
			_, err := Verify(context.Background(), p, Expect{Method: "GET", URI: uri}, policy, now, newStore())
			if tc.accept != (err == nil) || (err != nil && !errors.Is(err, ErrInvalid)) {
				t.Errorf("err = %v, accept want %v", err, tc.accept)
			}
		})
	}
}

func TestVerify_HTMMustEqualMethodExactly(t *testing.T) {
	k := newTestKey(t)
	for _, htm := range []string{"POST", "get", "GET ", ""} {
		p := build(t, k, Claims{HTM: htm, HTU: uri, IAT: now})
		if _, err := Verify(context.Background(), p, Expect{Method: "GET", URI: uri}, policy, now, newStore()); err == nil {
			t.Errorf("htm %q accepted for GET", htm)
		}
	}
}

func TestVerify_HTUComparedAfterNormalisation(t *testing.T) {
	k := newTestKey(t)
	for _, tc := range []struct {
		name, htu, want string
		accept          bool
	}{
		{"exact", uri, uri, true},
		{"uppercase scheme and host", "HTTPS://API.Example.COM/resource", uri, true},
		{"default https port", "https://api.example.com:443/resource", uri, true},
		{"default http port", "http://api.example.com:80/resource", "http://api.example.com/resource", true},
		{"query ignored", uri + "?a=1", uri, true},
		{"fragment ignored", uri + "#frag", uri, true},
		{"configured URI with port, proof without", "https://api.example.com/resource", "https://api.example.com:443/resource", true},
		{"empty path is root", "https://api.example.com", "https://api.example.com/", true},
		{"escaped unreserved decoded", "https://api.example.com/%7euser", "https://api.example.com/~user", true},
		{"escaped unreserved letters decoded", "https://api.example.com/%72esource", uri, true},
		{"hex case of an escape is irrelevant", "https://api.example.com/a%2fb", "https://api.example.com/a%2Fb", true},
		{"escaped slash is not a slash", "https://api.example.com/a%2Fb", "https://api.example.com/a/b", false},
		{"dot-dot segment removed", "https://api.example.com/a/../resource", uri, true},
		{"dot segment removed", "https://api.example.com/./resource", uri, true},
		{"escaped dot-dot segment removed", "https://api.example.com/a/%2E%2E/resource", uri, true},
		{"dot-dot above root stays at root", "https://api.example.com/../../resource", uri, true},
		{"repeated slash kept", "https://api.example.com//resource", uri, false},
		{"bad escape", "https://api.example.com/%zz", uri, false},
		{"other path", "https://api.example.com/other", uri, false},
		{"trailing slash differs", uri + "/", uri, false},
		{"path case differs", "https://api.example.com/Resource", uri, false},
		{"other host", "https://evil.example/resource", uri, false},
		{"other port", "https://api.example.com:8443/resource", uri, false},
		{"http for https", "http://api.example.com/resource", uri, false},
		{"https port 80 is not default", "https://api.example.com:80/resource", "https://api.example.com/resource", false},
		{"userinfo", "https://user@api.example.com/resource", uri, false},
		{"relative", "/resource", uri, false},
		{"other scheme", "ftp://api.example.com/resource", uri, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := build(t, k, Claims{HTM: "GET", HTU: tc.htu, IAT: now})
			_, err := Verify(context.Background(), p, Expect{Method: "GET", URI: tc.want}, policy, now, newStore())
			if tc.accept != (err == nil) {
				t.Errorf("err = %v, accept want %v", err, tc.accept)
			}
		})
	}
}

func ath(token string) string {
	d := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(d[:])
}

func TestVerify_ATHBindsTheAccessToken(t *testing.T) {
	k := newTestKey(t)
	for _, tc := range []struct {
		name, ath, token string
		accept           bool
	}{
		{"matches", ath("tok"), "tok", true},
		{"missing when a token is expected", "", "tok", false},
		{"hash of another token", ath("other"), "tok", false},
		{"raw token instead of hash", "tok", "tok", false},
		{"present when no token is expected", ath("tok"), "", false},
		{"absent when no token is expected", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := build(t, k, Claims{HTM: "GET", HTU: uri, IAT: now, ATH: tc.ath})
			_, err := Verify(context.Background(), p, Expect{Method: "GET", URI: uri, AccessToken: tc.token}, policy, now, newStore())
			if tc.accept != (err == nil) || (err != nil && !errors.Is(err, ErrMismatch)) {
				t.Errorf("err = %v, accept want %v", err, tc.accept)
			}
		})
	}
}

func TestVerify_NonceMustMatchWhenExpected(t *testing.T) {
	k := newTestKey(t)
	for _, tc := range []struct {
		name, nonce, want string
		accept            bool
	}{
		{"matches", "n1", "n1", true},
		{"wrong", "n2", "n1", false},
		{"missing", "", "n1", false},
		{"not expected", "n1", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := build(t, k, Claims{HTM: "GET", HTU: uri, IAT: now, Nonce: tc.nonce})
			_, err := Verify(context.Background(), p, Expect{Method: "GET", URI: uri, Nonce: tc.want}, policy, now, newStore())
			if tc.accept != (err == nil) {
				t.Errorf("err = %v, accept want %v", err, tc.accept)
			}
		})
	}
}

func TestVerify_ProofKeyMustBeTheBoundKey(t *testing.T) {
	k, other := newTestKey(t), newTestKey(t)
	p := build(t, k, Claims{HTM: "GET", HTU: uri, IAT: now})
	_, err := Verify(context.Background(), p, Expect{Method: "GET", URI: uri, JKT: other.jkt(t)}, policy, now, newStore())
	if !errors.Is(err, ErrKeyMismatch) || !errors.Is(err, ErrMismatch) {
		t.Errorf("err = %v, want ErrKeyMismatch (an ErrMismatch)", err)
	}
}

func TestVerify_ReplayedProofIsRefused(t *testing.T) {
	k := newTestKey(t)
	store := newStore()
	p := build(t, k, Claims{HTM: "GET", HTU: uri, IAT: now})
	want := Expect{Method: "GET", URI: uri}
	if _, err := Verify(context.Background(), p, want, policy, now, store); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), p, want, policy, now.Add(time.Second), store); !errors.Is(err, ErrReplayed) {
		t.Errorf("second use: err = %v, want ErrReplayed", err)
	}
	// The same jti on a URI spelled differently is the same use.
	p2 := build(t, k, Claims{JTI: "fixed", HTM: "GET", HTU: uri, IAT: now})
	p3 := build(t, k, Claims{JTI: "fixed", HTM: "GET", HTU: "HTTPS://api.example.com:443/resource?x", IAT: now})
	if _, err := Verify(context.Background(), p2, want, policy, now, store); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), p3, want, policy, now, store); !errors.Is(err, ErrReplayed) {
		t.Errorf("same jti, URI spelled differently: err = %v, want ErrReplayed", err)
	}
}

func TestVerify_ConcurrentReplayHasExactlyOneWinner(t *testing.T) {
	k := newTestKey(t)
	store := newStore()
	p := build(t, k, Claims{HTM: "GET", HTU: uri, IAT: now})
	var ok, replayed atomic.Int32
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			_, err := Verify(context.Background(), p, Expect{Method: "GET", URI: uri}, policy, now, store)
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, ErrReplayed):
				replayed.Add(1)
			default:
				t.Errorf("err = %v", err)
			}
		})
	}
	wg.Wait()
	if ok.Load() != 1 || replayed.Load() != 99 {
		t.Errorf("successes = %d, replays = %d, want 1 and 99", ok.Load(), replayed.Load())
	}
}

func TestVerify_ReplayStoreErrorFailsClosed(t *testing.T) {
	k := newTestKey(t)
	p := build(t, k, Claims{HTM: "GET", HTU: uri, IAT: now})
	_, err := Verify(context.Background(), p, Expect{Method: "GET", URI: uri}, policy, now, failingStore{})
	if err == nil || errors.Is(err, ErrReplayed) {
		t.Errorf("err = %v, want a store failure", err)
	}
	if _, err := Verify(context.Background(), p, Expect{Method: "GET", URI: uri}, policy, now, nil); err == nil {
		t.Error("nil store accepted")
	}
}

func TestVerify_RefusesMalformedProofs(t *testing.T) {
	k := newTestKey(t)
	sign := func(header, claims string) string {
		in := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(claims))
		sig, _ := k.Sign(context.Background(), []byte(in))
		return in + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	j := k.JWK()
	hdr := `{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"` + j.X + `","y":"` + j.Y + `"}}`
	good := `"htm":"GET","htu":"` + uri + `","iat":1800000000`
	for name, p := range map[string]string{
		"typ jwt":            sign(strings.Replace(hdr, "dpop+jwt", "jwt", 1), `{"jti":"a",`+good+`}`),
		"no jwk":             sign(`{"typ":"dpop+jwt","alg":"ES256"}`, `{"jti":"a",`+good+`}`),
		"kid instead of jwk": sign(`{"typ":"dpop+jwt","alg":"ES256","kid":"k"}`, `{"jti":"a",`+good+`}`),
		"no jti":             sign(hdr, `{`+good+`}`),
		"empty jti":          sign(hdr, `{"jti":"",`+good+`}`),
		"jti too long":       sign(hdr, `{"jti":"`+strings.Repeat("a", 257)+`",`+good+`}`),
		"jti not a string":   sign(hdr, `{"jti":1,`+good+`}`),
		"no htm":             sign(hdr, `{"jti":"a","htu":"`+uri+`","iat":1800000000}`),
		"no htu":             sign(hdr, `{"jti":"a","htm":"GET","iat":1800000000}`),
		"no iat":             sign(hdr, `{"jti":"a","htm":"GET","htu":"`+uri+`"}`),
		"iat a string":       sign(hdr, `{"jti":"a","htm":"GET","htu":"`+uri+`","iat":"1800000000"}`),
		"iat fractional":     sign(hdr, `{"jti":"a","htm":"GET","htu":"`+uri+`","iat":1800000000.5}`),
		"duplicate htu":      sign(hdr, `{"jti":"a",`+good+`,"htu":"https://evil.example/"}`),
		"claims not object":  sign(hdr, `["jti"]`),
		"oversized":          sign(hdr, `{"jti":"a",`+good+`,"pad":"`+strings.Repeat("x", 8<<10)+`"}`),
		"garbage":            "not.a.proof",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(context.Background(), p, Expect{Method: "GET", URI: uri}, policy, now, newStore())
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("err = %v, want ErrInvalid", err)
			}
		})
	}
	t.Run("whitespace in claims is fine", func(t *testing.T) {
		p := sign(hdr, `{ "jti" : "a" , "htm" : "GET" , "htu" : "`+uri+`" , "iat" : 1800000000 }`)
		if _, err := Verify(context.Background(), p, Expect{Method: "GET", URI: uri}, policy, now, newStore()); err != nil {
			t.Errorf("err = %v", err)
		}
	})
}

func TestVerify_ReplayIdentityUsesTheNormalisedURI(t *testing.T) {
	k := newTestKey(t)
	store := newStore()
	want := Expect{Method: "GET", URI: "https://api.example.com/~user/resource"}
	first := build(t, k, Claims{JTI: "same", HTM: "GET", HTU: "https://api.example.com/%7euser/x/../resource", IAT: now})
	if _, err := Verify(context.Background(), first, want, policy, now, store); err != nil {
		t.Fatal(err)
	}
	if store.last.URI != "https://api.example.com/~user/resource" {
		t.Errorf("replay URI = %q", store.last.URI)
	}
	second := build(t, k, Claims{JTI: "same", HTM: "GET", HTU: "https://API.example.com:443/~user/resource", IAT: now})
	if _, err := Verify(context.Background(), second, want, policy, now, store); !errors.Is(err, ErrReplayed) {
		t.Errorf("same target spelled differently: err = %v, want ErrReplayed", err)
	}
}

func TestNormalizePath_RFC3986(t *testing.T) {
	for in, want := range map[string]string{
		"":                    "/",
		"/":                   "/",
		"/a/b/../c":           "/a/c",
		"/a/b/..":             "/a/",
		"/a/./b/.":            "/a/b/",
		"/a/b/c/./../../g":    "/a/g",
		"/mid/content=5/../6": "/mid/6",
		"//a//b/":             "//a//b/",
		"/a%2fb%3a":           "/a%2Fb%3A",
		"/%7E%7e%2D%2e%5F":    "/~~-._",
		"/%25":                "/%25",
	} {
		if got, err := normalizePath(in); err != nil || got != want {
			t.Errorf("normalizePath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

type canaryStore struct{ err error }

func (s canaryStore) TryUse(context.Context, replay.Use) (bool, error) { return false, s.err }

// Canary: a refusal never carries the proof, a claim value, a member name, a parser message or the
// replay store's error; only the category (and a context cancellation or deadline) survives.
func TestErrors_NeverCarryInputOrStoreText(t *testing.T) {
	k := newTestKey(t)
	sign := func(claims string) string {
		j := k.JWK()
		hdr := `{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"` + j.X + `","y":"` + j.Y + `"}}`
		in := base64.RawURLEncoding.EncodeToString([]byte(hdr)) + "." + base64.RawURLEncoding.EncodeToString([]byte(claims))
		sig, _ := k.Sign(context.Background(), []byte(in))
		return in + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	want := Expect{Method: "GET", URI: uri, AccessToken: "CANARY-TOKEN", Nonce: "CANARY-NONCE-WANT"}
	for _, tc := range []struct {
		name  string
		proof string
		store replay.Store
		cat   error
	}{
		{"malformed htu", sign(`{"jti":"a","htm":"GET","htu":"https://api.example/CANARY%zz","iat":1800000000}`), newStore(), ErrInvalid},
		{"htu mismatch", sign(`{"jti":"a","htm":"GET","htu":"https://CANARY.example/","iat":1800000000}`), newStore(), ErrMismatch},
		{"htm mismatch", sign(`{"jti":"a","htm":"CANARY-METHOD","htu":"` + uri + `","iat":1800000000}`), newStore(), ErrMismatch},
		{"overflowing iat", sign(`{"jti":"a","htm":"GET","htu":"` + uri + `","iat":1e31337999}`), newStore(), ErrInvalid},
		{"duplicate claim", sign(`{"jti":"a","CANARY_DUP":1,"CANARY_DUP":2,"htm":"GET","htu":"` + uri + `","iat":1800000000}`), newStore(), ErrInvalid},
		{"claim of the wrong type", sign(`{"jti":{"CANARY":1},"htm":"GET","htu":"` + uri + `","iat":1800000000}`), newStore(), ErrInvalid},
		{"wrong ath and nonce", build(t, k, Claims{HTM: "GET", HTU: uri, IAT: now, ATH: "CANARY-ATH", Nonce: "CANARY-NONCE"}), newStore(), ErrMismatch},
		{"store error", build(t, k, Claims{HTM: "GET", HTU: uri, IAT: now, ATH: ath("CANARY-TOKEN"), Nonce: "CANARY-NONCE-WANT"}), canaryStore{errors.New("CANARY-STORE-DSN")}, errReplayCheck},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Verify(context.Background(), tc.proof, want, policy, now, tc.store)
			if !errors.Is(err, tc.cat) {
				t.Fatalf("err = %v, want %v", err, tc.cat)
			}
			msg := err.Error()
			if strings.Contains(msg, "CANARY") || strings.Contains(msg, "31337") || strings.Contains(msg, tc.proof) || strings.Contains(msg, strings.Split(tc.proof, ".")[1]) {
				t.Errorf("error carries input: %q", msg)
			}
		})
	}
	t.Run("store cancellation stays recognisable", func(t *testing.T) {
		p := build(t, k, Claims{HTM: "GET", HTU: uri, IAT: now})
		_, err := Verify(context.Background(), p, Expect{Method: "GET", URI: uri}, policy, now, canaryStore{fmt.Errorf("CANARY: %w", context.Canceled)})
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrReplayed) || strings.Contains(err.Error(), "CANARY") {
			t.Errorf("err = %v", err)
		}
	})
}
