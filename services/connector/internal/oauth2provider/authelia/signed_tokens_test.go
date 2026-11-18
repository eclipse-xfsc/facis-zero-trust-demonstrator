package authelia

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/tokenverify"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/dpoptest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/signing"
)

const (
	resourceAudience = "https://resource.example"
	resourceBaseURL  = "https://resource.example"
)

// signedHarness is a harness issuing tokens signed by signer, whatever CONNECTOR_TEST_TOKENS says.
func signedHarness(t *testing.T, signer oauth2provider.TokenSigner) *harness {
	t.Helper()

	return newHarness(t, func(c *oauth2provider.Config) {
		c.Issuer = "https://connector.example"
		c.AccessTokenSigner = signer
	})
}

// issueSigned seeds a DPoP-bound client allowed resourceAudience and returns a token bound to key.
func (h *harness) issueSigned(key *dpoptest.Key) string {
	h.t.Helper()

	h.seedClient("participant", true, []string{resourceScope, "other.scope"}, []string{resourceAudience})

	issued := h.token("participant", h.tokenProof(key), []string{resourceScope, "other.scope"}, resourceAudience)
	if issued.status != http.StatusOK || issued.str("token_type") != "DPoP" {
		h.t.Fatalf("token request: status %d, body %v", issued.status, issued.body)
	}

	return issued.str("access_token")
}

// The token is an RFC 9068 JWT with exactly the header and claims the resource-side verifier needs.
func TestSignedTokens_Format(t *testing.T) {
	signer := newTestSigner(t)
	h := signedHarness(t, signer)
	key := dpoptest.NewKey(t)
	token := h.issueSigned(key)

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want a compact JWS", len(parts))
	}

	var header map[string]any
	decodePart(t, parts[0], &header)

	if header["typ"] != "at+jwt" || header["alg"] != "ES256" || header["kid"] != signer.KeyID() || len(header) != 3 {
		t.Errorf("header = %v, want typ at+jwt, alg ES256, kid %s and nothing else", header, signer.KeyID())
	}

	var claims map[string]json.RawMessage
	decodePart(t, parts[1], &claims)

	str := func(name string) string {
		var v string
		if err := json.Unmarshal(claims[name], &v); err != nil {
			t.Errorf("claim %s = %s, want a string", name, claims[name])
		}

		return v
	}

	if got := str("iss"); got != "https://connector.example" {
		t.Errorf("iss = %q", got)
	}

	if got := str("sub"); got != "participant" {
		t.Errorf("sub = %q, want the client id", got)
	}

	if got := str("client_id"); got != "participant" {
		t.Errorf("client_id = %q", got)
	}

	if str("jti") == "" {
		t.Error("jti is empty")
	}

	// RFC 9068 section 2.2.3: one space-separated string, not a list.
	if got := str("scope"); got != resourceScope+" other.scope" {
		t.Errorf("scope = %q", got)
	}

	if _, ok := claims["scp"]; ok {
		t.Error("the list form of scope is present as well")
	}

	if got := string(claims["aud"]); got != `["`+resourceAudience+`"]` && got != `"`+resourceAudience+`"` {
		t.Errorf("aud = %s", got)
	}

	for _, name := range []string{"iat", "nbf", "exp"} {
		var n int64
		if err := json.Unmarshal(claims[name], &n); err != nil {
			t.Errorf("claim %s = %s, want an integer", name, claims[name])
		}
	}

	var cnf struct {
		JKT string `json:"jkt"`
	}
	if err := json.Unmarshal(claims["cnf"], &cnf); err != nil || cnf.JKT != key.Thumbprint() {
		t.Errorf("cnf = %s, want jkt %s", claims["cnf"], key.Thumbprint())
	}

	var exp, iat int64
	_ = json.Unmarshal(claims["exp"], &exp)
	_ = json.Unmarshal(claims["iat"], &iat)

	if exp-iat != int64(defaultSignedTokenLifespan/time.Second) {
		t.Errorf("lifetime %d s, want %s by default", exp-iat, defaultSignedTokenLifespan)
	}

	// The provider itself still accepts it at a resource.
	proof := dpoptest.Mint(t, key, dpoptest.Proof{Method: http.MethodGet, URL: h.resourceURL, AccessToken: token})
	if got := h.resource("DPoP "+token, proof); got.status != http.StatusOK {
		t.Errorf("ValidateResourceRequest: status %d, body %v", got.status, got.body)
	}
}

// A token the provider issues is accepted by the resource-side verifier, and refused by it when the
// proof key, the proof, the time or the audience is wrong.
func TestSignedTokens_VerifiedByTokenverify(t *testing.T) {
	signer := newTestSigner(t)
	h := signedHarness(t, signer)
	key := dpoptest.NewKey(t)
	token := h.issueSigned(key)

	checkWithTokenverify(t, signer, token, key)
}

// The signer is called with the context of the request being served.
func TestSignedTokens_SignerGetsRequestContext(t *testing.T) {
	type ctxKey struct{}

	recorder := &contextSigner{TokenSigner: newTestSigner(t)}
	h := signedHarness(t, recorder)
	key := dpoptest.NewKey(t)
	h.seedClient("participant", true, []string{resourceScope}, []string{resourceAudience})

	form := url.Values{"grant_type": {"client_credentials"}, "scope": {resourceScope}, "audience": {resourceAudience}}
	request := httptest.NewRequest(http.MethodPost, h.tokenURL, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("DPoP", h.tokenProof(key))
	request.SetBasicAuth("participant", testSecret)
	request = request.WithContext(context.WithValue(request.Context(), ctxKey{}, "this request"))

	response := httptest.NewRecorder()
	h.provider.TokenHandler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", response.Code, response.Body)
	}

	ctx := recorder.last.Load()
	if ctx == nil || (*ctx).Value(ctxKey{}) != "this request" {
		t.Fatal("the signer was not called with the request's context")
	}
}

// Every signed token carries cnf.jkt: with DPoP enforcement off, an unbound client that presents no
// proof is refused with a DPoP error instead of being given an unbound token. With a proof it is
// served.
func TestSignedTokens_RequireAProof(t *testing.T) {
	h := newHarness(t, func(c *oauth2provider.Config) {
		c.DPoP.Enforce = false
		c.Issuer = "https://connector.example"
		c.AccessTokenSigner = newTestSigner(t)
	})
	h.seedClient("plain", false, []string{resourceScope}, []string{resourceAudience})

	refused := h.token("plain", "", []string{resourceScope}, resourceAudience)
	if refused.status != http.StatusBadRequest || refused.reason() != oauth2provider.CodeDPoPInvalidProof {
		t.Errorf("no proof: status %d reason %q, want 400 %q", refused.status, refused.reason(), oauth2provider.CodeDPoPInvalidProof)
	}

	issued := h.token("plain", h.tokenProof(dpoptest.NewKey(t)), []string{resourceScope}, resourceAudience)
	if issued.status != http.StatusOK || issued.str("token_type") != "DPoP" {
		t.Errorf("with a proof: status %d body %v, want 200 DPoP", issued.status, issued.body)
	}
}

// Every signed token carries aud: a request naming no audience, or an empty one, is refused rather
// than given a token without one.
func TestSignedTokens_RequireAnAudience(t *testing.T) {
	h := signedHarness(t, newTestSigner(t))
	h.seedClient("participant", true, []string{resourceScope}, []string{resourceAudience})

	for name, form := range map[string]url.Values{
		"no audience":    {"grant_type": {"client_credentials"}, "scope": {resourceScope}},
		"empty audience": {"grant_type": {"client_credentials"}, "scope": {resourceScope}, "audience": {""}},
	} {
		key := dpoptest.NewKey(t)
		if got := h.tokenWithSecret("participant", testSecret, h.tokenProof(key), form); got.status != http.StatusBadRequest || got.reason() != oauth2provider.CodeInvalidRequest {
			t.Errorf("%s: status %d reason %q, want 400 %q", name, got.status, got.reason(), oauth2provider.CodeInvalidRequest)
		}
	}

	form := url.Values{"grant_type": {"client_credentials"}, "scope": {resourceScope}, "audience": {resourceAudience}}
	if got := h.tokenWithSecret("participant", testSecret, h.tokenProof(dpoptest.NewKey(t)), form); got.status != http.StatusOK {
		t.Errorf("with an audience: status %d body %v, want 200", got.status, got.body)
	}
}

func TestSignedTokens_ConfigRefusesIncompleteSigner(t *testing.T) {
	base := oauth2provider.Config{
		Secret:       []byte("token-signing-secret-at-least-32-bytes!"),
		Registration: oauth2provider.RegistrationConfig{Secret: []byte("registration-secret-at-least-32-bytes!!"), EndpointURL: "https://connector.example/register"},
	}

	noIssuer := base
	noIssuer.AccessTokenSigner = newTestSigner(t)

	if _, err := newLibraryConfig(noIssuer); err == nil {
		t.Error("a signer without an issuer was accepted")
	}

	noKid := base
	noKid.Issuer = "https://connector.example"
	noKid.AccessTokenSigner = blankKidSigner{newTestSigner(t)}

	if _, err := newLibraryConfig(noKid); err == nil {
		t.Error("a signer without a key id was accepted")
	}
}

// A token signed through OpenBao transit is accepted by the resource-side verifier. It runs when
// TRANSIT_TEST_ADDR and TRANSIT_TEST_TOKEN name a dev server, and skips otherwise.
func TestSignedTokens_TransitSigner(t *testing.T) {
	addr, token := os.Getenv("TRANSIT_TEST_ADDR"), os.Getenv("TRANSIT_TEST_TOKEN")
	if addr == "" || token == "" {
		t.Skip("TRANSIT_TEST_ADDR and TRANSIT_TEST_TOKEN not set")
	}

	// Enable the transit mount when missing; 400 is "path is already in use".
	mount, _ := http.NewRequest(http.MethodPost, strings.TrimSuffix(addr, "/")+"/v1/sys/mounts/transit", strings.NewReader(`{"type":"transit"}`))
	mount.Header.Set("X-Vault-Token", token)

	response, err := http.DefaultClient.Do(mount)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()

	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusBadRequest {
		t.Fatalf("enabling transit: status %d", response.StatusCode)
	}

	client, err := transit.New(transit.Config{Addr: addr, Token: func(context.Context) (string, error) { return token, nil }})
	if err != nil {
		t.Fatal(err)
	}

	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)

	version, err := client.EnsureKey(t.Context(), "connector-at-"+hex.EncodeToString(suffix))
	if err != nil {
		t.Fatal(err)
	}

	signer, err := signing.NewTransit(t.Context(), client, version)
	if err != nil {
		t.Fatal(err)
	}

	h := signedHarness(t, signer)
	key := dpoptest.NewKey(t)
	issued := h.issueSigned(key)

	checkWithTokenverify(t, signer, issued, key)
}

func checkWithTokenverify(t *testing.T, signer oauth2provider.TokenSigner, token string, key *dpoptest.Key) {
	t.Helper()

	var offset atomic.Int64

	now := func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	verifier := func(audience string) *tokenverify.Verifier {
		return newTokenverify(t, signer, audience, []string{resourceScope}, now)
	}

	request := func(proofKey *dpoptest.Key) *http.Request {
		r := httptest.NewRequest(http.MethodGet, resourceBaseURL+"/data", nil)
		r.Header.Set("Authorization", "DPoP "+token)

		if proofKey != nil {
			r.Header.Set("DPoP", dpoptest.Mint(t, proofKey, dpoptest.Proof{Method: http.MethodGet, URL: resourceBaseURL + "/data", AccessToken: token}))
		}

		return r
	}

	v := verifier(resourceAudience)

	identity, err := v.Verify(request(key))
	if err != nil {
		t.Fatalf("correct request refused: %v", err)
	}

	if identity.Subject != "participant" || identity.ClientID != "participant" || identity.JKT != key.Thumbprint() {
		t.Errorf("identity = %+v", identity)
	}

	for name, tc := range map[string]struct {
		verifier *tokenverify.Verifier
		request  *http.Request
		want     error
	}{
		"wrong proof key": {v, request(dpoptest.NewKey(t)), tokenverify.ErrKeyMismatch},
		"no proof":        {v, request(nil), tokenverify.ErrNoProof},
		"wrong audience":  {verifier("https://elsewhere.example"), request(key), tokenverify.ErrAudience},
	} {
		if _, err := tc.verifier.Verify(tc.request); !errors.Is(err, tc.want) {
			t.Errorf("%s: err %v, want %v", name, err, tc.want)
		}
	}

	offset.Store(int64(defaultSignedTokenLifespan + time.Minute))

	if _, err := v.Verify(request(key)); !errors.Is(err, tokenverify.ErrExpired) {
		t.Errorf("expired token: err %v, want %v", err, tokenverify.ErrExpired)
	}
}

// newTokenverify is the resource-side verifier for tokens signed by signer, with the key set served
// from a test server.
func newTokenverify(t *testing.T, signer oauth2provider.TokenSigner, audience string, scopes []string, now func() time.Time) *tokenverify.Verifier {
	t.Helper()

	jwk := jose.PublicJWK(signer.Public())
	jwk.Kid = signer.KeyID()

	keySet, err := json.Marshal(map[string]any{"keys": []any{map[string]string{
		"kty": jwk.Kty, "crv": jwk.Crv, "x": jwk.X, "y": jwk.Y, "kid": jwk.Kid, "use": "sig",
	}}})
	if err != nil {
		t.Fatal(err)
	}

	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(keySet)
	}))
	t.Cleanup(jwks.Close)

	v, err := tokenverify.New(tokenverify.Config{
		Issuer:        "https://connector.example",
		JWKSURL:       jwks.URL,
		Audience:      audience,
		PublicBaseURL: resourceBaseURL,
		Scopes:        scopes,
		Replay:        &memReplay{seen: map[replay.Use]bool{}},
		Now:           now,
	})
	if err != nil {
		t.Fatal(err)
	}

	return v
}

func decodePart(t *testing.T, part string, v any) {
	t.Helper()

	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatal(err)
	}

	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatal(err)
	}
}

// contextSigner records the context of the last Sign call.
type contextSigner struct {
	oauth2provider.TokenSigner

	last atomic.Pointer[context.Context]
}

func (s *contextSigner) Sign(ctx context.Context, input []byte) ([]byte, error) {
	s.last.Store(&ctx)

	return s.TokenSigner.Sign(ctx, input)
}

type blankKidSigner struct{ oauth2provider.TokenSigner }

func (blankKidSigner) KeyID() string { return "" }

type memReplay struct {
	mu   sync.Mutex
	seen map[replay.Use]bool
}

func (m *memReplay) TryUse(_ context.Context, use replay.Use) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	use.NotAfter = time.Time{}
	if m.seen[use] {
		return false, nil
	}

	m.seen[use] = true

	return true, nil
}
