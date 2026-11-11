package tokenverify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
)

const (
	issuer   = "https://connector.example"
	audience = "https://api.example"
	baseURL  = "https://api.example.com"
	path     = "/v1/data"
)

// --- keys -----------------------------------------------------------------------------------------

type ecKey struct{ k *ecdsa.PrivateKey }

func newECKey(t testing.TB) ecKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ecKey{k}
}

func (k ecKey) JWK() jose.JWK { return jose.PublicJWK(&k.k.PublicKey) }

func (k ecKey) Sign(_ context.Context, in []byte) ([]byte, error) {
	d := sha256.Sum256(in)
	r, s, err := ecdsa.Sign(rand.Reader, k.k, d[:])
	if err != nil {
		return nil, err
	}
	return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...), nil
}

func (k ecKey) jkt(t testing.TB) string {
	s, err := k.JWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// --- fakes ----------------------------------------------------------------------------------------

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type memStore struct {
	mu   sync.Mutex
	seen map[string]bool
	down bool
}

func (s *memStore) TryUse(_ context.Context, u replay.Use) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return false, errors.New("replay store down")
	}
	k := u.JKT + "|" + u.Method + "|" + u.URI + "|" + u.JTI
	if s.seen[k] {
		return false, nil
	}
	s.seen[k] = true
	return true, nil
}

// jwksServer serves the issuer keys it is given and counts fetches.
type jwksServer struct {
	*httptest.Server
	mu      sync.Mutex
	keys    map[string]ecKey
	body    string // when set, served verbatim
	fail    bool
	delay   time.Duration
	onFetch func() // runs while the request is being served, e.g. to move the clock
	fetches atomic.Int32
}

func newJWKSServer(t *testing.T) *jwksServer {
	s := &jwksServer{keys: map[string]ecKey{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.fetches.Add(1)
		s.mu.Lock()
		fail, delay, body, onFetch := s.fail, s.delay, s.body, s.onFetch
		var set []jose.JWK
		for kid, k := range s.keys {
			j := k.JWK()
			j.Kid = kid
			set = append(set, j)
		}
		s.mu.Unlock()
		time.Sleep(delay)
		if onFetch != nil {
			onFetch()
		}
		if fail {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		if body != "" {
			_, _ = w.Write([]byte(body))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": set})
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *jwksServer) set(f func(s *jwksServer)) { s.mu.Lock(); defer s.mu.Unlock(); f(s) }

// --- fixture --------------------------------------------------------------------------------------

type fixture struct {
	t      *testing.T
	jwks   *jwksServer
	issuer ecKey
	client ecKey
	clock  *clock
	store  *memStore
	v      *Verifier
}

func newFixture(t *testing.T, edit ...func(*Config)) *fixture {
	f := &fixture{t: t, jwks: newJWKSServer(t), issuer: newECKey(t), client: newECKey(t),
		clock: &clock{t: time.Unix(1_800_000_000, 0)}, store: &memStore{seen: map[string]bool{}}}
	f.jwks.keys["k1"] = f.issuer
	cfg := Config{
		Issuer: issuer, JWKSURL: f.jwks.URL, Audience: audience, PublicBaseURL: baseURL,
		Scopes: []string{"read"}, Proof: dpopproof.Policy{Lifespan: time.Minute, Skew: 5 * time.Second},
		Replay: f.store, Now: f.clock.Now,
	}
	for _, e := range edit {
		e(&cfg)
	}
	v, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.v = v
	return f
}

func (f *fixture) claims() map[string]any {
	now := f.clock.Now()
	return map[string]any{
		"iss": issuer, "sub": "client-a", "aud": audience, "client_id": "client-a",
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "jti": "tok-" + randID(f.t),
		"scope": "read write", "cnf": map[string]any{"jkt": f.client.jkt(f.t)},
	}
}

func (f *fixture) sign(key ecKey, h jose.Header, claims map[string]any) string {
	payload, err := json.Marshal(claims)
	if err != nil {
		f.t.Fatal(err)
	}
	tok, err := jose.Sign(context.Background(), h, payload, key.Sign)
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

func (f *fixture) token(edit func(map[string]any)) string {
	c := f.claims()
	if edit != nil {
		edit(c)
	}
	return f.sign(f.issuer, jose.Header{Typ: "at+jwt", Kid: "k1"}, c)
}

func (f *fixture) proof(key ecKey, method, htu, token string) string {
	c := dpopproof.Claims{HTM: method, HTU: htu, IAT: f.clock.Now()}
	if token != "" {
		d := sha256.Sum256([]byte(token))
		c.ATH = b64url(d[:])
	}
	p, err := dpopproof.Build(context.Background(), key, c)
	if err != nil {
		f.t.Fatal(err)
	}
	return p
}

// request is a request as a reverse proxy delivers it: an internal Host, the public URL nowhere.
func request(method, token, proof string) *http.Request {
	r := httptest.NewRequest(method, "http://10.0.0.7:8080"+path+"?q=1", nil)
	if token != "" {
		r.Header.Set("Authorization", "DPoP "+token)
	}
	if proof != "" {
		r.Header.Set("DPoP", proof)
	}
	return r
}

func (f *fixture) valid() (*http.Request, string, string) {
	tok := f.token(nil)
	p := f.proof(f.client, http.MethodGet, baseURL+path, tok)
	return request(http.MethodGet, tok, p), tok, p
}

// --- tests ----------------------------------------------------------------------------------------

func TestVerify_ValidRequestYieldsIdentityFromValidatedClaims(t *testing.T) {
	f := newFixture(t)
	r, _, _ := f.valid()
	id, err := f.v.Verify(r)
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "client-a" || id.ClientID != "client-a" || id.JKT != f.client.jkt(t) ||
		strings.Join(id.Scopes, " ") != "read write" || !strings.HasPrefix(id.TokenID, "tok-") ||
		!id.Expires.Equal(f.clock.Now().Add(5*time.Minute)) {
		t.Errorf("identity = %+v", id)
	}
}

func TestVerify_TokenClaimsAreEnforced(t *testing.T) {
	skew := 5 * time.Second
	for _, tc := range []struct {
		name string
		edit func(c map[string]any, now time.Time)
		want error // nil means accepted
	}{
		{"expired", func(c map[string]any, now time.Time) { c["exp"] = now.Add(-skew - time.Second).Unix() }, ErrExpired},
		{"expired within leeway", func(c map[string]any, now time.Time) { c["exp"] = now.Add(-skew + time.Second).Unix() }, nil},
		{"nbf in the future", func(c map[string]any, now time.Time) { c["nbf"] = now.Add(time.Minute).Unix() }, ErrExpired},
		{"nbf within leeway", func(c map[string]any, now time.Time) { c["nbf"] = now.Add(skew).Unix() }, nil},
		{"iat in the future", func(c map[string]any, now time.Time) { c["iat"] = now.Add(time.Minute).Unix() }, ErrExpired},
		{"exp missing", func(c map[string]any, _ time.Time) { delete(c, "exp") }, ErrMalformed},
		{"exp a string", func(c map[string]any, _ time.Time) { c["exp"] = "never" }, ErrMalformed},
		{"iat missing", func(c map[string]any, _ time.Time) { delete(c, "iat") }, ErrMalformed},
		{"wrong issuer", func(c map[string]any, _ time.Time) { c["iss"] = "https://evil.example" }, ErrIssuer},
		{"issuer missing", func(c map[string]any, _ time.Time) { delete(c, "iss") }, ErrIssuer},
		{"wrong audience", func(c map[string]any, _ time.Time) { c["aud"] = "https://other.example" }, ErrAudience},
		{"audience array containing ours", func(c map[string]any, _ time.Time) { c["aud"] = []string{"x", audience} }, nil},
		{"audience array without ours", func(c map[string]any, _ time.Time) { c["aud"] = []string{"x", "y"} }, ErrAudience},
		{"audience missing", func(c map[string]any, _ time.Time) { delete(c, "aud") }, ErrAudience},
		{"sub missing", func(c map[string]any, _ time.Time) { delete(c, "sub") }, ErrMalformed},
		{"sub empty", func(c map[string]any, _ time.Time) { c["sub"] = "" }, ErrMalformed},
		{"sub not a string", func(c map[string]any, _ time.Time) { c["sub"] = 7 }, ErrMalformed},
		{"client_id missing", func(c map[string]any, _ time.Time) { delete(c, "client_id") }, ErrMalformed},
		{"jti missing", func(c map[string]any, _ time.Time) { delete(c, "jti") }, ErrMalformed},
		{"cnf missing", func(c map[string]any, _ time.Time) { delete(c, "cnf") }, ErrMalformed},
		{"cnf.jkt empty", func(c map[string]any, _ time.Time) { c["cnf"] = map[string]any{"jkt": ""} }, ErrMalformed},
		{"scope not a string", func(c map[string]any, _ time.Time) { c["scope"] = []string{"read"} }, ErrMalformed},
		{"scope missing", func(c map[string]any, _ time.Time) { delete(c, "scope") }, ErrScope},
		{"scope empty", func(c map[string]any, _ time.Time) { c["scope"] = "" }, ErrMalformed},
		{"scope with double space", func(c map[string]any, _ time.Time) { c["scope"] = "read  write" }, ErrMalformed},
		{"scope with leading space", func(c map[string]any, _ time.Time) { c["scope"] = " read" }, ErrMalformed},
		{"scope with tab", func(c map[string]any, _ time.Time) { c["scope"] = "read\twrite" }, ErrMalformed},
		{"scope with newline", func(c map[string]any, _ time.Time) { c["scope"] = "read\nwrite" }, ErrMalformed},
		{"scope with double quote", func(c map[string]any, _ time.Time) { c["scope"] = `read "x"` }, ErrMalformed},
		{"scope with backslash", func(c map[string]any, _ time.Time) { c["scope"] = `read a\b` }, ErrMalformed},
		{"scope with non-ASCII", func(c map[string]any, _ time.Time) { c["scope"] = "read wrïte" }, ErrMalformed},
		{"scope with all allowed characters", func(c map[string]any, _ time.Time) { c["scope"] = "read !#[]~:/" }, nil},
		{"audience array with null", func(c map[string]any, _ time.Time) { c["aud"] = []any{nil, audience} }, ErrMalformed},
		{"audience array with number", func(c map[string]any, _ time.Time) { c["aud"] = []any{1, audience} }, ErrMalformed},
		{"audience array empty", func(c map[string]any, _ time.Time) { c["aud"] = []any{} }, ErrMalformed},
		{"audience an object", func(c map[string]any, _ time.Time) { c["aud"] = map[string]any{"a": audience} }, ErrMalformed},
		{"insufficient scope", func(c map[string]any, _ time.Time) { c["scope"] = "write readonly" }, ErrScope},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tok := f.token(func(c map[string]any) { tc.edit(c, f.clock.Now()) })
			_, err := f.v.Verify(request(http.MethodGet, tok, f.proof(f.client, http.MethodGet, baseURL+path, tok)))
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerify_TokenSignatureAndHeaderAreEnforced(t *testing.T) {
	f := newFixture(t)
	other := newECKey(t)
	for _, tc := range []struct {
		name string
		tok  string
		want error
	}{
		{"signed by an untrusted key", f.sign(other, jose.Header{Typ: "at+jwt", Kid: "k1"}, f.claims()), ErrSignature},
		{"typ JWT", f.sign(f.issuer, jose.Header{Typ: "JWT", Kid: "k1"}, f.claims()), ErrSignature},
		{"no kid", f.sign(f.issuer, jose.Header{Typ: "at+jwt"}, f.claims()), ErrSignature},
		{"not a JWS", "abc.def", ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.v.Verify(request(http.MethodGet, tc.tok, f.proof(f.client, http.MethodGet, baseURL+path, tc.tok)))
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerify_ProofKeyMustBeTheTokensCnfJKT(t *testing.T) {
	f := newFixture(t)
	tok := f.token(nil)
	_, err := f.v.Verify(request(http.MethodGet, tok, f.proof(newECKey(t), http.MethodGet, baseURL+path, tok)))
	if !errors.Is(err, ErrKeyMismatch) {
		t.Errorf("err = %v, want ErrKeyMismatch", err)
	}
}

func TestVerify_ProofMustAccompanyTheToken(t *testing.T) {
	f := newFixture(t)
	tok := f.token(nil)
	if _, err := f.v.Verify(request(http.MethodGet, tok, "")); !errors.Is(err, ErrNoProof) {
		t.Errorf("no proof: err = %v, want ErrNoProof", err)
	}
	r := request(http.MethodGet, tok, f.proof(f.client, http.MethodGet, baseURL+path, tok))
	r.Header.Add("DPoP", f.proof(f.client, http.MethodGet, baseURL+path, tok))
	if _, err := f.v.Verify(r); !errors.Is(err, ErrProof) {
		t.Errorf("two proofs: err = %v, want ErrProof", err)
	}
	other := f.token(nil)
	if _, err := f.v.Verify(request(http.MethodGet, tok, f.proof(f.client, http.MethodGet, baseURL+path, other))); !errors.Is(err, ErrProof) {
		t.Errorf("proof for another token: err = %v, want ErrProof", err)
	}
	if _, err := f.v.Verify(request(http.MethodGet, tok, f.proof(f.client, http.MethodPost, baseURL+path, tok))); !errors.Is(err, ErrProof) {
		t.Errorf("proof for another method: err = %v, want ErrProof", err)
	}
}

func TestVerify_AuthorizationMustBeOneDPoPCredential(t *testing.T) {
	f := newFixture(t)
	tok := f.token(nil)
	p := f.proof(f.client, http.MethodGet, baseURL+path, tok)
	for _, tc := range []struct {
		name string
		auth []string
		want error
	}{
		{"absent", nil, ErrNoToken},
		{"Bearer scheme", []string{"Bearer " + tok}, ErrNoToken},
		{"Basic scheme", []string{"Basic dXNlcjpwYXNz"}, ErrNoToken},
		{"two Authorization headers", []string{"DPoP " + tok, "DPoP " + tok}, ErrInvalidRequest},
		{"tab inside the token", []string{"DPoP " + tok[:10] + "\t" + tok[10:]}, ErrMalformed},
		{"comma inside the token", []string{"DPoP " + tok + ",x"}, ErrMalformed},
		{"tab instead of space after scheme", []string{"DPoP\t" + tok}, ErrNoToken},
		{"scheme without token", []string{"DPoP "}, ErrMalformed},
		{"token with a space", []string{"DPoP " + tok + " x"}, ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := request(http.MethodGet, "", p)
			for _, a := range tc.auth {
				r.Header.Add("Authorization", a)
			}
			if _, err := f.v.Verify(r); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
	t.Run("several spaces after the scheme", func(t *testing.T) {
		r := request(http.MethodGet, "", f.proof(f.client, http.MethodGet, baseURL+path, tok))
		r.Header.Set("Authorization", "DPoP    "+tok)
		if _, err := f.v.Verify(r); err != nil {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("scheme is case-insensitive", func(t *testing.T) {
		r := request(http.MethodGet, "", f.proof(f.client, http.MethodGet, baseURL+path, tok))
		r.Header.Set("Authorization", "dpop "+tok)
		if _, err := f.v.Verify(r); err != nil {
			t.Errorf("err = %v", err)
		}
	})
}

func TestVerify_ReplayedProofIsRefused(t *testing.T) {
	f := newFixture(t)
	r, tok, p := f.valid()
	if _, err := f.v.Verify(r); err != nil {
		t.Fatal(err)
	}
	if _, err := f.v.Verify(request(http.MethodGet, tok, p)); !errors.Is(err, ErrReplayed) {
		t.Errorf("err = %v, want ErrReplayed", err)
	}
}

func TestVerify_HTUComesFromConfigNeverFromHostOrForwardedHeaders(t *testing.T) {
	f := newFixture(t)
	tok := f.token(nil)

	spoof := func(r *http.Request) *http.Request {
		r.Host = "evil.example"
		r.Header.Set("X-Forwarded-Host", "evil.example")
		r.Header.Set("X-Forwarded-Proto", "http")
		r.Header.Set("Forwarded", "host=evil.example;proto=http")
		return r
	}
	if _, err := f.v.Verify(spoof(request(http.MethodGet, tok, f.proof(f.client, http.MethodGet, baseURL+path, tok)))); err != nil {
		t.Errorf("proof for the configured URL, spoofed headers: err = %v", err)
	}
	for _, htu := range []string{"https://evil.example" + path, "http://evil.example" + path, "http://10.0.0.7:8080" + path} {
		if _, err := f.v.Verify(spoof(request(http.MethodGet, tok, f.proof(f.client, http.MethodGet, htu, tok)))); !errors.Is(err, ErrProof) {
			t.Errorf("proof for %s matching the spoofed headers: err = %v, want ErrProof", htu, err)
		}
	}
}

func TestKeySet_UnknownKidTriggersOneRefreshPerMinRefresh(t *testing.T) {
	f := newFixture(t)
	r, _, _ := f.valid()
	if _, err := f.v.Verify(r); err != nil {
		t.Fatal(err)
	}
	if n := f.jwks.fetches.Load(); n != 1 {
		t.Fatalf("fetches after first request = %d, want 1", n)
	}

	k2 := newECKey(t)
	tok2 := func() string { return f.sign(k2, jose.Header{Typ: "at+jwt", Kid: "k2"}, f.claims()) }
	verify2 := func() error {
		tok := tok2()
		_, err := f.v.Verify(request(http.MethodGet, tok, f.proof(f.client, http.MethodGet, baseURL+path, tok)))
		return err
	}

	f.clock.Advance(31 * time.Second)
	if err := verify2(); !errors.Is(err, ErrSignature) {
		t.Errorf("unknown kid: err = %v, want ErrSignature", err)
	}
	if n := f.jwks.fetches.Load(); n != 2 {
		t.Errorf("fetches after unknown kid = %d, want 2", n)
	}
	for range 5 {
		_ = verify2()
	}
	if n := f.jwks.fetches.Load(); n != 2 {
		t.Errorf("fetches after repeated unknown kid within MinRefresh = %d, want 2", n)
	}

	f.jwks.set(func(s *jwksServer) { s.keys["k2"] = k2 })
	f.clock.Advance(31 * time.Second)
	if err := verify2(); err != nil {
		t.Errorf("kid published since: err = %v", err)
	}
	if n := f.jwks.fetches.Load(); n != 3 {
		t.Errorf("fetches = %d, want 3", n)
	}
}

func TestKeySet_ConcurrentUnknownKidRequestsShareOneFetch(t *testing.T) {
	f := newFixture(t)
	r, _, _ := f.valid()
	if _, err := f.v.Verify(r); err != nil {
		t.Fatal(err)
	}
	k2 := newECKey(t)
	f.jwks.set(func(s *jwksServer) { s.keys["k2"] = k2; s.delay = 100 * time.Millisecond })
	f.clock.Advance(31 * time.Second)

	reqs := make([]*http.Request, 50)
	for i := range reqs {
		tok := f.sign(k2, jose.Header{Typ: "at+jwt", Kid: "k2"}, f.claims())
		reqs[i] = request(http.MethodGet, tok, f.proof(f.client, http.MethodGet, baseURL+path, tok))
	}
	var wg sync.WaitGroup
	for _, r := range reqs {
		wg.Go(func() {
			if _, err := f.v.Verify(r); err != nil {
				t.Errorf("err = %v", err)
			}
		})
	}
	wg.Wait()
	if n := f.jwks.fetches.Load(); n != 2 {
		t.Errorf("fetches = %d, want 2 (initial plus one coalesced refresh)", n)
	}
}

func TestKeySet_RotationAcceptsOldAndNewKeys(t *testing.T) {
	f := newFixture(t)
	k2 := newECKey(t)
	f.jwks.set(func(s *jwksServer) { s.keys["k2"] = k2 })
	for _, tc := range []struct {
		kid string
		key ecKey
	}{{"k1", f.issuer}, {"k2", k2}} {
		tok := f.sign(tc.key, jose.Header{Typ: "at+jwt", Kid: tc.kid}, f.claims())
		if _, err := f.v.Verify(request(http.MethodGet, tok, f.proof(f.client, http.MethodGet, baseURL+path, tok))); err != nil {
			t.Errorf("kid %s: err = %v", tc.kid, err)
		}
	}
	// A key signed under the other key's kid is not trusted.
	tok := f.sign(k2, jose.Header{Typ: "at+jwt", Kid: "k1"}, f.claims())
	if _, err := f.v.Verify(request(http.MethodGet, tok, f.proof(f.client, http.MethodGet, baseURL+path, tok))); !errors.Is(err, ErrSignature) {
		t.Errorf("k2 signature under kid k1: err = %v", err)
	}
	if n := f.jwks.fetches.Load(); n != 1 {
		t.Errorf("fetches = %d, want 1", n)
	}
}

func TestKeySet_FailedRefreshDoesNotExtendAgeAndPastMaxStaleRefusesAll(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.CacheTTL = time.Minute; c.MaxStale = 5 * time.Minute })
	check := func(want error) {
		t.Helper()
		r, _, _ := f.valid()
		if _, err := f.v.Verify(r); want == nil && err != nil || want != nil && !errors.Is(err, want) {
			t.Errorf("at +%v: err = %v, want %v", f.clock.Now().Sub(time.Unix(1_800_000_000, 0)), err, want)
		}
	}
	check(nil) // fetched at t0
	f.jwks.set(func(s *jwksServer) { s.fail = true })

	f.clock.Advance(2 * time.Minute) // past TTL: refresh fails, the cached keys still serve
	check(nil)
	f.clock.Advance(2 * time.Minute) // another failed refresh
	check(nil)
	if n := f.jwks.fetches.Load(); n != 3 {
		t.Errorf("fetches = %d, want 3", n)
	}
	f.clock.Advance(61 * time.Second) // 5m01s after the last success: stale
	check(ErrKeySetUnavailable)

	rec := httptest.NewRecorder()
	r, _, _ := f.valid()
	f.v.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("handler reached") })).ServeHTTP(rec, r)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("middleware status = %d, want 503", rec.Code)
	}

	f.jwks.set(func(s *jwksServer) { s.fail = false })
	f.clock.Advance(31 * time.Second)
	check(nil)
}

func TestKeySet_FirstFetchFailureRefusesAsUnavailable(t *testing.T) {
	f := newFixture(t)
	f.jwks.set(func(s *jwksServer) { s.fail = true })
	r, _, _ := f.valid()
	if _, err := f.v.Verify(r); !errors.Is(err, ErrKeySetUnavailable) {
		t.Errorf("err = %v, want ErrKeySetUnavailable", err)
	}
}

func TestKeySet_KeepsOnlyP256SigningKeysWithKid(t *testing.T) {
	good := newECKey(t).JWK()
	ec := func(extra string) string {
		return `{"kty":"EC","crv":"P-256","x":"` + good.X + `","y":"` + good.Y + `"` + extra + `}`
	}
	body := `{"keys":[` + strings.Join([]string{
		ec(`,"kid":"good","use":"sig","alg":"ES256"`),
		ec(`,"kid":"plain"`),
		ec(``), // no kid
		ec(`,"kid":"enc","use":"enc"`),
		ec(`,"kid":"rs","alg":"RS256"`),
		ec(`,"kid":"priv","d":"AAAA"`),
		`{"kty":"EC","crv":"P-384","kid":"p384","x":"` + good.X + `","y":"` + good.Y + `"}`,
		`{"kty":"RSA","kid":"rsa","n":"AQAB","e":"AQAB"}`,
		`{"kty":"oct","kid":"hmac","k":"c2VjcmV0"}`,
		ec(`,"kid":"twice"`), ec(`,"kid":"twice"`),
		ec(`,"kid":"ops-verify","key_ops":["verify"]`),
		ec(`,"kid":"ops-sign-verify","use":"sig","key_ops":["sign","verify"]`),
		ec(`,"kid":"ops-derive","key_ops":["deriveKey"]`),
		ec(`,"kid":"ops-empty","key_ops":[]`),
		ec(`,"kid":"ops-string","key_ops":"verify"`),
		ec(`,"kid":"ops-null","key_ops":null`),
		ec(`,"kid":"ops-number","key_ops":["verify",1]`),
		ec(`,"kid":"ops-dup","key_ops":["verify","verify"]`),
		ec(`,"kid":"ops-enc","use":"enc","key_ops":["verify"]`),
		`"not an object"`,
	}, ",") + `]}`
	keys, err := parseKeySet([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 4 || keys["good"] == nil || keys["plain"] == nil || keys["ops-verify"] == nil || keys["ops-sign-verify"] == nil {
		t.Errorf("kept %d keys: %v", len(keys), keys)
	}
	for _, bad := range []string{`{"keys":[]}`, `{"keys":{}}`, `{}`, `[]`, `{"keys":[` + ec(`,"kid":"a"`) + `],"keys":[]}`} {
		if _, err := parseKeySet([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestKeySet_FetchIsBoundedAndNeverRedirected(t *testing.T) {
	t.Run("oversized response", func(t *testing.T) {
		f := newFixture(t)
		j := f.issuer.JWK()
		f.jwks.set(func(s *jwksServer) {
			s.body = `{"keys":[{"kty":"EC","crv":"P-256","kid":"k1","x":"` + j.X + `","y":"` + j.Y + `"}],"pad":"` + strings.Repeat("x", maxKeySetBytes) + `"}`
		})
		r, _, _ := f.valid()
		if _, err := f.v.Verify(r); !errors.Is(err, ErrKeySetUnavailable) {
			t.Errorf("err = %v, want ErrKeySetUnavailable", err)
		}
	})
	t.Run("redirect to another key set", func(t *testing.T) {
		elsewhere := newJWKSServer(t)
		redirect := httptest.NewServer(http.RedirectHandler(elsewhere.URL, http.StatusFound))
		t.Cleanup(redirect.Close)
		f := newFixture(t, func(c *Config) { c.JWKSURL = redirect.URL })
		elsewhere.keys["k1"] = f.issuer
		r, _, _ := f.valid()
		if _, err := f.v.Verify(r); !errors.Is(err, ErrKeySetUnavailable) {
			t.Errorf("err = %v, want ErrKeySetUnavailable", err)
		}
		if n := elsewhere.fetches.Load(); n != 0 {
			t.Errorf("redirect target fetched %d times", n)
		}
	})
}

func TestNew_RequiresConfig(t *testing.T) {
	base := Config{Issuer: issuer, JWKSURL: "https://connector.example/jwks", Audience: audience, PublicBaseURL: baseURL, Replay: &memStore{}}
	for name, edit := range map[string]func(*Config){
		"no issuer":           func(c *Config) { c.Issuer = "" },
		"no JWKS URL":         func(c *Config) { c.JWKSURL = "" },
		"relative JWKS URL":   func(c *Config) { c.JWKSURL = "/jwks" },
		"no audience":         func(c *Config) { c.Audience = "" },
		"no public base URL":  func(c *Config) { c.PublicBaseURL = "" },
		"base URL with query": func(c *Config) { c.PublicBaseURL = baseURL + "?x=1" },
		"no replay store":     func(c *Config) { c.Replay = nil },
	} {
		t.Run(name, func(t *testing.T) {
			c := base
			edit(&c)
			if _, err := New(c); err == nil {
				t.Error("accepted")
			}
		})
	}
	v, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	if v.cfg.CacheTTL != 5*time.Minute || v.cfg.MaxStale != 5*time.Minute || v.cfg.MinRefresh != 30*time.Second || v.cfg.Now == nil || v.cfg.HTTPClient == nil ||
		v.cfg.Proof.Lifespan != 60*time.Second || v.cfg.Proof.Skew != 30*time.Second {
		t.Errorf("defaults not applied: %+v", v.cfg)
	}
}

func TestMiddleware_AnswersPerRefusal(t *testing.T) {
	type outcome struct {
		status    int
		challenge string
	}
	for _, tc := range []struct {
		name  string
		setup func(f *fixture) *http.Request
		want  outcome
	}{
		{"valid passes with identity", func(f *fixture) *http.Request { r, _, _ := f.valid(); return r }, outcome{http.StatusOK, ""}},
		{"no credentials", func(*fixture) *http.Request { return request(http.MethodGet, "", "") }, outcome{401, `DPoP algs="ES256"`}},
		{"repeated Authorization", func(f *fixture) *http.Request {
			r, tok, _ := f.valid()
			r.Header.Add("Authorization", "DPoP "+tok)
			return r
		}, outcome{400, `DPoP error="invalid_request", algs="ES256"`}},
		{"Bearer token", func(f *fixture) *http.Request {
			r, tok, _ := f.valid()
			r.Header.Set("Authorization", "Bearer "+tok)
			return r
		}, outcome{401, `DPoP algs="ES256"`}},
		{"expired token", func(f *fixture) *http.Request {
			tok := f.token(func(c map[string]any) { c["exp"] = f.clock.Now().Add(-time.Hour).Unix() })
			return request(http.MethodGet, tok, f.proof(f.client, http.MethodGet, baseURL+path, tok))
		}, outcome{401, `DPoP error="invalid_token", algs="ES256"`}},
		{"proof missing", func(f *fixture) *http.Request { return request(http.MethodGet, f.token(nil), "") }, outcome{401, `DPoP error="invalid_dpop_proof", algs="ES256"`}},
		{"proof replayed", func(f *fixture) *http.Request {
			r, tok, p := f.valid()
			_, _ = f.v.Verify(r)
			return request(http.MethodGet, tok, p)
		}, outcome{401, `DPoP error="invalid_dpop_proof", algs="ES256"`}},
		{"insufficient scope", func(f *fixture) *http.Request {
			tok := f.token(func(c map[string]any) { c["scope"] = "write" })
			return request(http.MethodGet, tok, f.proof(f.client, http.MethodGet, baseURL+path, tok))
		}, outcome{403, `DPoP error="insufficient_scope", algs="ES256"`}},
		{"key set unavailable", func(f *fixture) *http.Request {
			f.jwks.set(func(s *jwksServer) { s.fail = true })
			r, _, _ := f.valid()
			return r
		}, outcome{503, ""}},
		{"replay store down", func(f *fixture) *http.Request {
			f.store.down = true
			r, _, _ := f.valid()
			return r
		}, outcome{503, ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			var got Identity
			h := f.v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got, _ = FromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			}))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, tc.setup(f))
			if rec.Code != tc.want.status || rec.Header().Get("WWW-Authenticate") != tc.want.challenge {
				t.Errorf("got %d %q, want %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"), tc.want.status, tc.want.challenge)
			}
			if tc.want.status == http.StatusOK && got.Subject != "client-a" {
				t.Errorf("identity in context = %+v", got)
			}
		})
	}
}

// Canary: no refusal may carry the token or the proof back out, in a body, a header or an error.
func TestCanary_TokenAndProofNeverEchoed(t *testing.T) {
	f := newFixture(t)
	canaryClaims := func(c map[string]any) { c["jti"] = "CANARY-JTI"; c["sub"] = "CANARY-SUB" }
	cases := map[string]func() (*http.Request, string, string){
		"wrong audience": func() (*http.Request, string, string) {
			tok := f.token(func(c map[string]any) { canaryClaims(c); c["aud"] = "CANARY-AUD" })
			p := f.proof(f.client, http.MethodGet, baseURL+path, tok)
			return request(http.MethodGet, tok, p), tok, p
		},
		"bad signature": func() (*http.Request, string, string) {
			tok := f.sign(newECKey(t), jose.Header{Typ: "at+jwt", Kid: "k1"}, f.claims())
			p := f.proof(f.client, http.MethodGet, baseURL+path, tok)
			return request(http.MethodGet, tok, p), tok, p
		},
		"malformed token": func() (*http.Request, string, string) {
			tok := "CANARY.TOKEN.VALUE"
			p := f.proof(f.client, http.MethodGet, baseURL+path, tok)
			return request(http.MethodGet, tok, p), tok, p
		},
		"wrong proof key": func() (*http.Request, string, string) {
			tok := f.token(canaryClaims)
			p := f.proof(newECKey(t), http.MethodGet, baseURL+path, tok)
			return request(http.MethodGet, tok, p), tok, p
		},
		"garbage proof": func() (*http.Request, string, string) {
			tok := f.token(canaryClaims)
			p := "CANARY-PROOF.e30.AAAA"
			return request(http.MethodGet, tok, p), tok, p
		},
		"insufficient scope": func() (*http.Request, string, string) {
			tok := f.token(func(c map[string]any) { canaryClaims(c); c["scope"] = "CANARY-SCOPE" })
			p := f.proof(f.client, http.MethodGet, baseURL+path, tok)
			return request(http.MethodGet, tok, p), tok, p
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			r, tok, p := mk()
			_, err := f.v.Verify(r.Clone(context.Background()))
			if err == nil {
				t.Fatal("accepted")
			}
			r2, _, _ := mk() // a fresh request: the first one may have spent its proof
			r2.Header = r.Header.Clone()
			rec := httptest.NewRecorder()
			f.v.Middleware(http.NotFoundHandler()).ServeHTTP(rec, r2)
			everything := err.Error() + "\n" + rec.Body.String() + "\n" + strings.Join(headerValues(rec.Header()), "\n")
			for _, secret := range []string{tok, p, strings.Split(tok, ".")[0], strings.Split(p, ".")[2], "CANARY"} {
				if strings.Contains(everything, secret) {
					t.Errorf("response or error carries %q:\n%s", secret, everything)
				}
			}
		})
	}
}

func headerValues(h http.Header) []string {
	var out []string
	for k, vs := range h {
		out = append(out, k+": "+strings.Join(vs, ","))
	}
	return out
}

func randID(t testing.TB) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b64url(b)
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// The clock is read after the key lookup: a fetch that blocks while a token, a proof or the key set
// expires must not let any of them through on the time sampled before it.
func TestVerify_TimeIsReadAfterABlockingKeyFetch(t *testing.T) {
	t.Run("token expires during a successful fetch", func(t *testing.T) {
		f := newFixture(t)
		f.jwks.set(func(s *jwksServer) { s.onFetch = func() { f.clock.Advance(20 * time.Second) } })
		tok := f.token(func(c map[string]any) { c["exp"] = f.clock.Now().Add(10 * time.Second).Unix() })
		_, err := f.v.Verify(request(http.MethodGet, tok, f.proof(f.client, http.MethodGet, baseURL+path, tok)))
		if !errors.Is(err, ErrExpired) {
			t.Errorf("err = %v, want ErrExpired", err)
		}
	})
	t.Run("proof expires during a successful fetch", func(t *testing.T) {
		f := newFixture(t)
		f.jwks.set(func(s *jwksServer) { s.onFetch = func() { f.clock.Advance(70 * time.Second) } }) // lifespan 60 s + skew 5 s
		r, _, _ := f.valid()
		if _, err := f.v.Verify(r); !errors.Is(err, ErrProof) {
			t.Errorf("err = %v, want ErrProof", err)
		}
	})
	t.Run("token expires during a failed refresh", func(t *testing.T) {
		f := newFixture(t, func(c *Config) { c.CacheTTL = time.Minute; c.MaxStale = 5 * time.Minute })
		r, _, _ := f.valid()
		if _, err := f.v.Verify(r); err != nil {
			t.Fatal(err)
		}
		f.clock.Advance(2 * time.Minute)
		f.jwks.set(func(s *jwksServer) { s.fail = true; s.onFetch = func() { f.clock.Advance(20 * time.Second) } })
		tok := f.token(func(c map[string]any) { c["exp"] = f.clock.Now().Add(10 * time.Second).Unix() })
		_, err := f.v.Verify(request(http.MethodGet, tok, f.proof(f.client, http.MethodGet, baseURL+path, tok)))
		if !errors.Is(err, ErrExpired) {
			t.Errorf("err = %v, want ErrExpired", err)
		}
	})
	t.Run("key set crosses MaxStale during a failed refresh", func(t *testing.T) {
		f := newFixture(t, func(c *Config) { c.CacheTTL = time.Minute; c.MaxStale = 5 * time.Minute })
		r, _, _ := f.valid()
		if _, err := f.v.Verify(r); err != nil {
			t.Fatal(err)
		}
		f.clock.Advance(5*time.Minute - time.Second) // age 4m59s: stale by TTL, not yet by MaxStale
		f.jwks.set(func(s *jwksServer) { s.fail = true; s.onFetch = func() { f.clock.Advance(2 * time.Second) } })
		r, _, _ = f.valid()
		if _, err := f.v.Verify(r); !errors.Is(err, ErrKeySetUnavailable) {
			t.Errorf("err = %v, want ErrKeySetUnavailable", err)
		}
	})
	t.Run("keys are dated from the start of the fetch", func(t *testing.T) {
		f := newFixture(t, func(c *Config) { c.CacheTTL = time.Minute; c.MaxStale = 2 * time.Minute })
		f.jwks.set(func(s *jwksServer) { s.onFetch = func() { f.clock.Advance(30 * time.Second) } })
		r, _, _ := f.valid()
		if _, err := f.v.Verify(r); err != nil {
			t.Fatal(err)
		}
		f.jwks.set(func(s *jwksServer) { s.fail = true; s.onFetch = nil })
		f.clock.Advance(90*time.Second + time.Second) // 2m01s after the fetch began, 1m31s after it ended
		r, _, _ = f.valid()
		if _, err := f.v.Verify(r); !errors.Is(err, ErrKeySetUnavailable) {
			t.Errorf("err = %v, want ErrKeySetUnavailable", err)
		}
	})
}
