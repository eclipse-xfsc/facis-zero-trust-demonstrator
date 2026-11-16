package authelia

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"authelia.com/provider/oauth2"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/dpoptest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider/memstore"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/signing"
)

// The verified-presentation grant issues signed tokens only, so every test here runs with its own
// signer whatever CONNECTOR_TEST_TOKENS says, on the stores CONNECTOR_TEST_STORE selects.

const (
	vpIssuer      = "https://verifier.zone-b.example"
	vpKid         = "verifier-1"
	vpScope       = "resource.write" // issued only through the verified-presentation grant
	vpRole        = "participant-operator"
	vpEntitlement = "write"
	vpClient      = "vp-client"
	otherAudience = "https://other-resource.example"
)

type vpHarness struct {
	*harness

	signer *countingSigner

	// issuer signs IF-03 outcomes with the key the provider trusts.
	issuer *signing.Local
}

// countingSigner counts the access tokens it signs.
type countingSigner struct {
	oauth2provider.TokenSigner

	signed atomic.Int64
}

func (s *countingSigner) Sign(ctx context.Context, input []byte) ([]byte, error) {
	s.signed.Add(1)

	return s.TokenSigner.Sign(ctx, input)
}

func newVPHarness(t *testing.T, configure func(*oauth2provider.Config)) *vpHarness {
	t.Helper()

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	issuer, err := signing.NewLocal(issuerKey)
	if err != nil {
		t.Fatal(err)
	}

	signer := &countingSigner{TokenSigner: newTestSigner(t)}

	h := newHarness(t, func(c *oauth2provider.Config) {
		c.Issuer = "https://connector.example"
		c.AccessTokenSigner = signer
		c.VerifiedPresentation = vpConfig(&issuerKey.PublicKey)

		if configure != nil {
			configure(c)
		}
	})

	return &vpHarness{harness: h, signer: signer, issuer: issuer}
}

func vpConfig(issuerKey *ecdsa.PublicKey) oauth2provider.VerifiedPresentationConfig {
	return oauth2provider.VerifiedPresentationConfig{
		TrustedIssuers: if03.Issuers{vpIssuer: {vpKid: issuerKey}},
		Scopes: []oauth2provider.ClaimScopes{
			{Role: vpRole, Entitlement: vpEntitlement, Scopes: []string{vpScope}},
			{Role: "unregistered-role", Scopes: []string{"scope.the.client.lacks"}},
		},
	}
}

// seedVPClient provisions a client for the verified-presentation grant, not bound to DPoP by
// registration: the grant requires a proof regardless.
func (h *vpHarness) seedVPClient(id string, grantTypes ...string) {
	h.t.Helper()

	if len(grantTypes) == 0 {
		grantTypes = []string{oauth2provider.VerifiedPresentationGrantType}
	}

	h.seedClient(id, false, []string{resourceScope, vpScope}, []string{resourceAudience, otherAudience})

	client, err := h.stores.Clients.GetClient(h.t.Context(), id)
	if err != nil {
		h.t.Fatal(err)
	}

	client.GrantTypes = grantTypes
	if err = h.stores.Clients.UpdateClient(h.t.Context(), client); err != nil {
		h.t.Fatal(err)
	}
}

// challenge asks the challenge endpoint for a challenge as clientID.
func (h *vpHarness) challenge(clientID string, form url.Values) result {
	h.t.Helper()

	return h.challengeWithSecret(clientID, testSecret, form)
}

func (h *vpHarness) challengeWithSecret(clientID, secret string, form url.Values) result {
	h.t.Helper()

	request, err := http.NewRequest(http.MethodPost, h.challengeURL, strings.NewReader(form.Encode()))
	if err != nil {
		h.t.Fatal(err)
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))

	return h.do(request)
}

// newChallenge returns a fresh challenge for clientID and audience.
func (h *vpHarness) newChallenge(clientID, audience string) string {
	h.t.Helper()

	got := h.challenge(clientID, url.Values{"audience": {audience}})
	if got.status != http.StatusOK || got.str("challenge") == "" {
		h.t.Fatalf("challenge: status %d, body %v", got.status, got.body)
	}

	return got.str("challenge")
}

// outcome is an IF-03 outcome payload, for a test to change before signing.
type payload map[string]any

func newOutcomeID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)

	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// verifiedOutcome is a valid, current outcome for clientID, challenge and audience.
func verifiedOutcome(clientID, challenge, audience string) payload {
	now := time.Now().UTC()

	return payload{
		"iss": vpIssuer, "outcome_id": newOutcomeID(), "client_id": clientID, "challenge": challenge, "audience": audience,
		"claims":      map[string]any{"role": vpRole, "entitlement": vpEntitlement},
		"verified_at": now.Add(-5 * time.Second).Format(time.RFC3339), "expires_at": now.Add(100 * time.Second).Format(time.RFC3339),
		"status": "verified",
	}
}

// sign signs the outcome as the trusted issuer.
func (h *vpHarness) sign(o payload) string {
	h.t.Helper()

	return signOutcome(h.t, h.issuer.Sign, vpKid, o)
}

func signOutcome(t *testing.T, sign jose.SignFunc, kid string, o payload) string {
	t.Helper()

	payload, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}

	compact, err := jose.Sign(t.Context(), jose.Header{Typ: if03.Typ, Kid: kid}, payload, sign)
	if err != nil {
		t.Fatal(err)
	}

	return compact
}

// grant requests a token with the verified-presentation grant. proof may be empty.
func (h *vpHarness) grant(clientID, proof, compact, challenge, audience string) result {
	h.t.Helper()

	return h.tokenWithSecret(clientID, testSecret, proof, url.Values{
		"grant_type": {oauth2provider.VerifiedPresentationGrantType},
		"outcome":    {compact}, "challenge": {challenge}, "audience": {audience},
	})
}

// wantRefused checks a refusal's status and reason, and that the body repeats nothing of the
// outcome.
func wantRefused(t *testing.T, name string, got result, status int, reason oauth2provider.Code, o payload, compact string) {
	t.Helper()

	if got.status != status || got.reason() != reason {
		t.Errorf("%s: status %d reason %q, want %d %q (body %v)", name, got.status, got.reason(), status, reason, got.body)
	}

	if o == nil {
		return
	}

	body, _ := json.Marshal(got.body)
	for _, secret := range []string{compact, strings.Split(compact, ".")[1], fmt.Sprint(o["outcome_id"]), vpIssuer, vpRole} {
		if secret != "" && strings.Contains(string(body), secret) {
			t.Errorf("%s: the refusal repeats outcome content %q: %s", name, secret, body)
		}
	}
}

// The whole path: a challenge, an outcome for it, a token. The token is DPoP-bound, carries the
// mapped scope and the audience, and is accepted by the resource-side verifier.
func TestVP_ChallengeThenOutcomeIssuesABoundSignedToken(t *testing.T) {
	h := newVPHarness(t, nil)
	h.seedVPClient(vpClient)

	got := h.challenge(vpClient, url.Values{"audience": {resourceAudience}})
	if got.status != http.StatusOK || got.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("challenge: status %d, Cache-Control %q, body %v", got.status, got.header.Get("Cache-Control"), got.body)
	}

	challenge := got.str("challenge")
	if n := len(challenge); n < 22 || n > 256 || strings.ContainsAny(challenge, "+/=") {
		t.Errorf("challenge %q: want at least 128 bits, base64url, at most 256 characters", challenge)
	}

	if got.body["expires_in"] != float64(120) {
		t.Errorf("expires_in = %v, want 120", got.body["expires_in"])
	}

	if again := h.newChallenge(vpClient, resourceAudience); again == challenge {
		t.Error("two challenges are equal")
	}

	o := verifiedOutcome(vpClient, challenge, resourceAudience)
	key := dpoptest.NewKey(t)

	issued := h.grant(vpClient, h.tokenProof(key), h.sign(o), challenge, resourceAudience)
	if issued.status != http.StatusOK || issued.str("token_type") != "DPoP" || issued.str("scope") != vpScope {
		t.Fatalf("grant: status %d, body %v", issued.status, issued.body)
	}

	token := issued.str("access_token")

	identity, err := newTokenverify(t, h.signer, resourceAudience, []string{vpScope}, time.Now).Verify(func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, resourceBaseURL+"/data", nil)
		r.Header.Set("Authorization", "DPoP "+token)
		r.Header.Set("DPoP", dpoptest.Mint(t, key, dpoptest.Proof{Method: http.MethodGet, URL: resourceBaseURL + "/data", AccessToken: token}))

		return r
	}())
	if err != nil {
		t.Fatalf("tokenverify refused the token: %v", err)
	}

	if identity.ClientID != vpClient || identity.Subject != vpClient || identity.JKT != key.Thumbprint() {
		t.Errorf("identity = %+v", identity)
	}

	var claims struct {
		Aud   any    `json:"aud"`
		Scope string `json:"scope"`
		Cnf   struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
	}
	decodePart(t, strings.Split(token, ".")[1], &claims)

	if claims.Scope != vpScope || claims.Cnf.JKT != key.Thumbprint() || !strings.Contains(fmt.Sprint(claims.Aud), resourceAudience) {
		t.Errorf("claims = %+v", claims)
	}

	// The provider accepts it at a resource too.
	proof := dpoptest.Mint(t, key, dpoptest.Proof{Method: http.MethodGet, URL: h.resourceURL, AccessToken: token})
	if got := h.resource("DPoP "+token, proof); got.status != http.StatusOK {
		t.Errorf("ValidateResourceRequest: status %d, body %v", got.status, got.body)
	}

	stored, err := h.stores.Challenges.GetChallenge(t.Context(), challenge)
	if err != nil || stored.ConsumedAt.IsZero() {
		t.Errorf("challenge after the grant: %+v, %v; want consumed", stored, err)
	}

	if h.pool != nil {
		var status string
		var consumed bool
		if err := h.pool.QueryRow(t.Context(), `SELECT status, consumed_at IS NOT NULL FROM verified_outcome WHERE outcome_id = $1`,
			o["outcome_id"]).Scan(&status, &consumed); err != nil || status != "verified" || !consumed {
			t.Errorf("ledger row: status %q consumed %v, %v", status, consumed, err)
		}

		var tokens int
		if err := h.pool.QueryRow(t.Context(), `SELECT count(*) FROM oauth2_token WHERE kind = 'access' AND outcome_id = $1`,
			o["outcome_id"]).Scan(&tokens); err != nil || tokens != 1 {
			t.Errorf("%d access tokens carry the outcome id, %v; want 1", tokens, err)
		}
	}
}

// Every IF-03 check refuses with its own code, 400 invalid_grant, without repeating the outcome, and
// without consuming anything: the challenge still serves a valid outcome afterwards.
func TestVP_EveryOutcomeRefusalCarriesItsCode(t *testing.T) {
	h := newVPHarness(t, nil)
	h.seedVPClient(vpClient)
	h.seedVPClient("another-client")

	untrusted, err := signing.NewLocal(func() *ecdsa.PrivateKey {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		return k
	}())
	if err != nil {
		t.Fatal(err)
	}

	challenge := h.newChallenge(vpClient, resourceAudience)
	unbound := h.newChallenge("another-client", resourceAudience)
	past := time.Now().UTC().Add(-time.Hour)

	type tc struct {
		outcome   payload
		compact   string // when set, used instead of signing outcome
		challenge string // the form's challenge, when not challenge
		reason    oauth2provider.Code
	}

	valid := func(change func(payload)) payload {
		o := verifiedOutcome(vpClient, challenge, resourceAudience)
		if change != nil {
			change(o)
		}

		return o
	}

	tampered := h.sign(valid(nil))
	parts := strings.Split(tampered, ".")
	forged, _ := json.Marshal(valid(func(o payload) { o["claims"] = map[string]any{"role": "admin"} }))
	tampered = parts[0] + "." + base64.RawURLEncoding.EncodeToString(forged) + "." + parts[2]

	cases := map[string]tc{
		"signed by an untrusted key": {outcome: valid(nil), compact: signOutcome(t, untrusted.Sign, vpKid, valid(nil)), reason: oauth2provider.CodeCredOutcomeSignature},
		"tampered payload":           {outcome: valid(nil), compact: tampered, reason: oauth2provider.CodeCredOutcomeSignature},
		"not an IF-03 payload":       {outcome: valid(func(o payload) { o["extra"] = "member" }), reason: oauth2provider.CodeCredOutcomeSignature},
		"status failed": {outcome: valid(func(o payload) { o["status"] = "failed"; o["reason_code"] = "CRED-INVALID" }),
			reason: oauth2provider.CodeCredOutcomeNotVerified},
		"for another client":          {outcome: valid(func(o payload) { o["client_id"] = "another-client" }), reason: oauth2provider.CodeCredOutcomeMismatch},
		"for another audience":        {outcome: valid(func(o payload) { o["audience"] = otherAudience }), reason: oauth2provider.CodeCredOutcomeMismatch},
		"for another challenge":       {outcome: valid(func(o payload) { o["challenge"] = unbound }), reason: oauth2provider.CodeCredOutcomeMismatch},
		"challenge of another client": {outcome: valid(func(o payload) { o["challenge"] = unbound }), challenge: unbound, reason: oauth2provider.CodeCredOutcomeMismatch},
		"challenge never issued":      {outcome: valid(func(o payload) { o["challenge"] = "never-issued-challenge-value" }), challenge: "never-issued-challenge-value", reason: oauth2provider.CodeCredOutcomeMismatch},
		"expired outcome, foreign chall": {outcome: valid(func(o payload) {
			o["challenge"] = unbound
			o["verified_at"] = past.Format(time.RFC3339)
			o["expires_at"] = past.Add(time.Minute).Format(time.RFC3339)
		}), challenge: unbound, reason: oauth2provider.CodeCredOutcomeMismatch},
		"expired": {outcome: valid(func(o payload) {
			o["verified_at"] = past.Format(time.RFC3339)
			o["expires_at"] = past.Add(time.Minute).Format(time.RFC3339)
		}), reason: oauth2provider.CodeCredOutcomeExpired},
		"valid for too long": {outcome: valid(func(o payload) {
			o["expires_at"] = time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339)
		}), reason: oauth2provider.CodeCredOutcomeExpired},
	}

	for name, c := range cases {
		compact := c.compact
		if compact == "" {
			compact = h.sign(c.outcome)
		}

		form := challenge
		if c.challenge != "" {
			form = c.challenge
		}

		got := h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), compact, form, resourceAudience)
		wantRefused(t, name, got, http.StatusBadRequest, c.reason, c.outcome, compact)

		if got.str("error") != "invalid_grant" {
			t.Errorf("%s: error %q, want invalid_grant", name, got.str("error"))
		}
	}

	if n := h.signer.signed.Load(); n != 0 {
		t.Errorf("%d tokens signed for refused requests", n)
	}

	// Nothing was consumed: the challenge serves a valid outcome, once.
	o := valid(nil)
	compact := h.sign(o)

	if got := h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), compact, challenge, resourceAudience); got.status != http.StatusOK {
		t.Fatalf("valid outcome after the refusals: status %d, body %v", got.status, got.body)
	}

	got := h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), compact, challenge, resourceAudience)
	wantRefused(t, "replayed", got, http.StatusBadRequest, oauth2provider.CodeCredOutcomeConsumed, o, compact)
}

// A challenge is bound to the client and the audience it was issued for.
func TestVP_ChallengeIsBoundToItsClientAndAudience(t *testing.T) {
	h := newVPHarness(t, nil)
	h.seedVPClient(vpClient)
	h.seedVPClient("another-client")

	foreign := h.newChallenge("another-client", resourceAudience)
	o := verifiedOutcome(vpClient, foreign, resourceAudience)
	compact := h.sign(o)
	wantRefused(t, "another client's challenge", h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), compact, foreign, resourceAudience),
		http.StatusBadRequest, oauth2provider.CodeCredOutcomeMismatch, o, compact)

	otherAud := h.newChallenge(vpClient, otherAudience)
	o = verifiedOutcome(vpClient, otherAud, resourceAudience)
	compact = h.sign(o)
	wantRefused(t, "a challenge for another audience", h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), compact, otherAud, resourceAudience),
		http.StatusBadRequest, oauth2provider.CodeCredOutcomeMismatch, o, compact)

	// Each still works for its own client and audience.
	o = verifiedOutcome("another-client", foreign, resourceAudience)
	if got := h.grant("another-client", h.tokenProof(dpoptest.NewKey(t)), h.sign(o), foreign, resourceAudience); got.status != http.StatusOK {
		t.Errorf("own client: status %d, body %v", got.status, got.body)
	}

	o = verifiedOutcome(vpClient, otherAud, otherAudience)
	if got := h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), h.sign(o), otherAud, otherAudience); got.status != http.StatusOK {
		t.Errorf("own audience: status %d, body %v", got.status, got.body)
	}
}

// An expired challenge is refused as expired, a consumed one as consumed, whatever the outcome.
func TestVP_ExpiredOrConsumedChallengeIsRefused(t *testing.T) {
	h := newVPHarness(t, nil)
	h.seedVPClient(vpClient)

	expired := "expired-challenge-0123456789"
	if err := h.stores.Challenges.CreateChallenge(t.Context(), oauth2provider.Challenge{
		Value: expired, ClientID: vpClient, Audience: resourceAudience, ExpiresAt: time.Now().Add(-time.Second),
	}); err != nil {
		t.Fatal(err)
	}

	o := verifiedOutcome(vpClient, expired, resourceAudience)
	compact := h.sign(o)
	wantRefused(t, "expired challenge", h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), compact, expired, resourceAudience),
		http.StatusBadRequest, oauth2provider.CodeCredOutcomeExpired, o, compact)

	challenge := h.newChallenge(vpClient, resourceAudience)
	if got := h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), h.sign(verifiedOutcome(vpClient, challenge, resourceAudience)), challenge, resourceAudience); got.status != http.StatusOK {
		t.Fatalf("first use: status %d, body %v", got.status, got.body)
	}

	// A second, distinct outcome for the consumed challenge.
	o = verifiedOutcome(vpClient, challenge, resourceAudience)
	compact = h.sign(o)
	wantRefused(t, "consumed challenge", h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), compact, challenge, resourceAudience),
		http.StatusBadRequest, oauth2provider.CodeCredOutcomeConsumed, o, compact)

	if n := h.signer.signed.Load(); n != 1 {
		t.Errorf("%d tokens signed, want 1", n)
	}
}

// A replayed outcome is refused as consumed and never signed again.
func TestVP_ReplayedOutcomeIsRefusedAndNeverResigned(t *testing.T) {
	h := newVPHarness(t, nil)
	h.seedVPClient(vpClient)

	challenge := h.newChallenge(vpClient, resourceAudience)
	o := verifiedOutcome(vpClient, challenge, resourceAudience)
	compact := h.sign(o)

	if got := h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), compact, challenge, resourceAudience); got.status != http.StatusOK {
		t.Fatalf("first use: status %d, body %v", got.status, got.body)
	}

	for i := range 3 {
		wantRefused(t, fmt.Sprintf("replay %d", i), h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), compact, challenge, resourceAudience),
			http.StatusBadRequest, oauth2provider.CodeCredOutcomeConsumed, o, compact)
	}

	if n := h.signer.signed.Load(); n != 1 {
		t.Errorf("%d tokens signed, want 1", n)
	}
}

// Of concurrent requests presenting one outcome, or several outcomes for one challenge, exactly one
// is issued a token; the others are refused as consumed.
func TestVP_ConcurrentRequestsIssueExactlyOneToken(t *testing.T) {
	h := newVPHarness(t, nil)
	h.seedVPClient(vpClient)

	for name, distinctOutcomes := range map[string]bool{"one outcome": false, "one challenge": true} {
		challenge := h.newChallenge(vpClient, resourceAudience)
		shared := h.sign(verifiedOutcome(vpClient, challenge, resourceAudience))

		const n = 12

		compacts, proofs := make([]string, n), make([]string, n)
		for i := range n {
			compacts[i] = shared
			if distinctOutcomes {
				compacts[i] = h.sign(verifiedOutcome(vpClient, challenge, resourceAudience))
			}

			proofs[i] = h.tokenProof(dpoptest.NewKey(t))
		}

		results := make([]result, n)

		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() { results[i] = h.grant(vpClient, proofs[i], compacts[i], challenge, resourceAudience) })
		}
		wg.Wait()

		issued := 0
		for _, r := range results {
			switch {
			case r.status == http.StatusOK:
				issued++
			case r.status != http.StatusBadRequest || r.reason() != oauth2provider.CodeCredOutcomeConsumed:
				t.Errorf("%s: status %d reason %q, want 200 or 400 %q", name, r.status, r.reason(), oauth2provider.CodeCredOutcomeConsumed)
			}
		}

		if issued != 1 {
			t.Errorf("%s: %d tokens issued, want exactly 1", name, issued)
		}
	}

	if h.pool != nil {
		var tokens, outcomes int
		_ = h.pool.QueryRow(t.Context(), `SELECT count(*), count(DISTINCT outcome_id) FROM oauth2_token WHERE outcome_id IS NOT NULL`).Scan(&tokens, &outcomes)
		if tokens != 2 || outcomes != 2 {
			t.Errorf("%d tokens on %d outcomes, want 2 on 2", tokens, outcomes)
		}
	}
}

// The grant issues DPoP-bound tokens only: without a proof it is refused, even for a client not
// registered for bound tokens and with enforcement off, and nothing is consumed.
func TestVP_RequiresADPoPProof(t *testing.T) {
	h := newVPHarness(t, func(c *oauth2provider.Config) { c.DPoP.Enforce = false })
	h.seedVPClient(vpClient)

	challenge := h.newChallenge(vpClient, resourceAudience)
	o := verifiedOutcome(vpClient, challenge, resourceAudience)
	compact := h.sign(o)

	wantRefused(t, "no proof", h.grant(vpClient, "", compact, challenge, resourceAudience),
		http.StatusBadRequest, oauth2provider.CodeDPoPInvalidProof, o, compact)

	if got := h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), compact, challenge, resourceAudience); got.status != http.StatusOK {
		t.Errorf("with a proof afterwards: status %d, body %v; the refused request consumed something", got.status, got.body)
	}
}

// The grant needs signed tokens, its stores and a sound mapping; New refuses anything less.
func TestVP_ConfigurationIsValidatedAtStart(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	stores := newVPStores(t)

	base := oauth2provider.Config{
		Secret:            []byte("token-signing-secret-at-least-32-bytes!"),
		Registration:      oauth2provider.RegistrationConfig{Secret: []byte("registration-secret-at-least-32-bytes!!"), EndpointURL: "https://connector.example/register"},
		Issuer:            "https://connector.example",
		AccessTokenSigner: newTestSigner(t),
	}

	ok := base
	ok.VerifiedPresentation = vpConfig(&key.PublicKey)

	if _, err := New(ok, stores); err != nil {
		t.Fatalf("a complete configuration was refused: %v", err)
	}

	noSigner := ok
	noSigner.AccessTokenSigner, noSigner.Issuer = nil, ""

	registrationScope := ok
	registrationScope.VerifiedPresentation.Scopes = []oauth2provider.ClaimScopes{{Role: vpRole, Scopes: []string{oauth2provider.RegistrationScope}}}

	unmapped := ok
	unmapped.VerifiedPresentation.Scopes = nil

	noIssuers := ok
	noIssuers.VerifiedPresentation.TrustedIssuers = nil

	sharedKid := ok
	sharedKid.VerifiedPresentation.TrustedIssuers = if03.Issuers{vpIssuer: {vpKid: &key.PublicKey}, "https://other.example": {vpKid: &key.PublicKey}}

	duplicate := ok
	duplicate.VerifiedPresentation.Scopes = []oauth2provider.ClaimScopes{{Role: vpRole, Scopes: []string{vpScope}}, {Role: vpRole, Scopes: []string{"x"}}}

	for name, cfg := range map[string]oauth2provider.Config{
		"no signer":                 noSigner,
		"the registration scope":    registrationScope,
		"no claim mapping":          unmapped,
		"no trusted issuer":         noIssuers,
		"a kid of two issuers":      sharedKid,
		"a claim pair mapped twice": duplicate,
	} {
		if _, err := New(cfg, stores); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	noTransactions := stores
	noTransactions.Transactions = nil

	if _, err := New(ok, noTransactions); err == nil {
		t.Error("stores without transactions: accepted")
	}
}

func newVPStores(t *testing.T) oauth2provider.Stores {
	t.Helper()

	stores, _ := newStores(t, time.Now)

	return stores
}

// A client must be registered for the grant to obtain a challenge or use the grant.
func TestVP_ClientNotAllowedTheGrantIsRefused(t *testing.T) {
	h := newVPHarness(t, nil)
	h.seedVPClient(vpClient)
	h.seedVPClient("cc-only", "client_credentials")

	if got := h.challenge("cc-only", url.Values{"audience": {resourceAudience}}); got.status != http.StatusBadRequest || got.str("error") != "unauthorized_client" {
		t.Errorf("challenge: status %d body %v, want 400 unauthorized_client", got.status, got.body)
	}

	// A challenge issued to an allowed client is no use to it either.
	challenge := h.newChallenge(vpClient, resourceAudience)
	o := verifiedOutcome("cc-only", challenge, resourceAudience)
	compact := h.sign(o)

	got := h.grant("cc-only", h.tokenProof(dpoptest.NewKey(t)), compact, challenge, resourceAudience)
	if got.status != http.StatusBadRequest || got.str("error") != "unauthorized_client" {
		t.Errorf("grant: status %d body %v, want 400 unauthorized_client", got.status, got.body)
	}
}

// The challenge endpoint authenticates the client as the token endpoint does and takes exactly one
// of its registered audiences.
func TestVP_ChallengeEndpointRefusals(t *testing.T) {
	h := newVPHarness(t, nil)
	h.seedVPClient(vpClient)

	request, _ := http.NewRequest(http.MethodPost, h.challengeURL, strings.NewReader(url.Values{"audience": {resourceAudience}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(vpClient, "wrong secret")

	if got := h.do(request); got.status != http.StatusUnauthorized || got.reason() != oauth2provider.CodeInvalidClient {
		t.Errorf("wrong secret: status %d reason %q, want 401 invalid_client", got.status, got.reason())
	}

	for name, form := range map[string]url.Values{
		"no audience":            {"other": {"x"}},
		"an unregistered one":    {"audience": {"https://elsewhere.example"}},
		"two audiences":          {"audience": {resourceAudience, otherAudience}},
		"a space-separated pair": {"audience": {resourceAudience + " " + otherAudience}},
	} {
		if got := h.challenge(vpClient, form); got.status != http.StatusBadRequest || got.reason() != oauth2provider.CodeInvalidRequest {
			t.Errorf("%s: status %d reason %q, want 400 invalid_request", name, got.status, got.reason())
		}
	}

	get, _ := http.NewRequest(http.MethodGet, h.challengeURL, nil)
	get.SetBasicAuth(vpClient, testSecret)

	if got := h.do(get); got.status != http.StatusBadRequest {
		t.Errorf("GET: status %d, want 400", got.status)
	}
}

// Claims the mapping does not name, or that map to no scope the client is registered for, are
// refused, and nothing is consumed.
func TestVP_UnmappedClaimsAreDenied(t *testing.T) {
	h := newVPHarness(t, nil)
	h.seedVPClient(vpClient)

	challenge := h.newChallenge(vpClient, resourceAudience)

	for name, claims := range map[string]map[string]any{
		"unknown role":                   {"role": "auditor"},
		"mapped role, other entitlement": {"role": vpRole, "entitlement": "read"},
		"mapped role, no entitlement":    {"role": vpRole},
		"maps beyond the client":         {"role": "unregistered-role"},
	} {
		o := verifiedOutcome(vpClient, challenge, resourceAudience)
		o["claims"] = claims
		compact := h.sign(o)
		got := h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), compact, challenge, resourceAudience)
		wantRefused(t, name, got, http.StatusBadRequest, oauth2provider.CodeInvalidRequest, o, compact)

		if got.str("error") != "invalid_scope" {
			t.Errorf("%s: error %q, want invalid_scope", name, got.str("error"))
		}
	}

	if got := h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), h.sign(verifiedOutcome(vpClient, challenge, resourceAudience)), challenge, resourceAudience); got.status != http.StatusOK {
		t.Errorf("mapped claims afterwards: status %d, body %v", got.status, got.body)
	}
}

// A scope the grant issues is never issued through client_credentials, even to a client registered
// for it and for both grants.
func TestVP_ScopeIsNeverIssuedThroughClientCredentials(t *testing.T) {
	h := newVPHarness(t, nil)
	h.seedVPClient(vpClient, "client_credentials", oauth2provider.VerifiedPresentationGrantType)

	for name, scopes := range map[string][]string{
		"alone":             {vpScope},
		"with another one":  {resourceScope, vpScope},
		"the other one too": {resourceScope},
	} {
		got := h.token(vpClient, h.tokenProof(dpoptest.NewKey(t)), scopes, resourceAudience)

		if name == "the other one too" {
			if got.status != http.StatusOK {
				t.Errorf("%s: status %d body %v, want 200", name, got.status, got.body)
			}

			continue
		}

		if got.status != http.StatusBadRequest || got.str("error") != "invalid_scope" {
			t.Errorf("%s: status %d body %v, want 400 invalid_scope", name, got.status, got.body)
		}
	}
}

// failingTokens refuses to store a token while failing is set, after the grant consumed the
// challenge and the outcome.
type failingTokens struct {
	oauth2provider.TokenStore

	failing atomic.Bool
}

func (f *failingTokens) CreateToken(ctx context.Context, signature string, record oauth2provider.TokenRecord) error {
	if f.failing.Load() {
		return errors.New("injected token store failure")
	}

	return f.TokenStore.CreateToken(ctx, signature, record)
}

// A failure after consumption and before commit rolls everything back: the challenge and the
// outcome are not consumed, and the same pair is served once the failure is gone.
func TestVP_FailureBeforeCommitLeavesNothingConsumed(t *testing.T) {
	h := newVPHarness(t, nil)

	tokens := &failingTokens{TokenStore: h.stores.AccessTokens}
	h.stores.AccessTokens = tokens
	h.restart()

	h.seedVPClient(vpClient)
	challenge := h.newChallenge(vpClient, resourceAudience)
	o := verifiedOutcome(vpClient, challenge, resourceAudience)
	compact := h.sign(o)

	tokens.failing.Store(true)
	wantRefused(t, "token store failing", h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), compact, challenge, resourceAudience),
		http.StatusInternalServerError, oauth2provider.CodeServerError, o, compact)

	stored, err := h.stores.Challenges.GetChallenge(t.Context(), challenge)
	if err != nil || !stored.ConsumedAt.IsZero() {
		t.Errorf("challenge after the rollback: %+v, %v; want unconsumed", stored, err)
	}

	if h.pool != nil {
		var ledger int
		if err := h.pool.QueryRow(t.Context(), `SELECT count(*) FROM verified_outcome WHERE outcome_id = $1`, o["outcome_id"]).Scan(&ledger); err != nil || ledger != 0 {
			t.Errorf("ledger rows for the outcome after the rollback: %d, %v; want 0", ledger, err)
		}
	}

	tokens.failing.Store(false)

	if got := h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), compact, challenge, resourceAudience); got.status != http.StatusOK {
		t.Errorf("after the failure: status %d, body %v; the rolled-back request consumed something", got.status, got.body)
	}
}

// A token record keeps its outcome id, and one outcome id stands behind one token at most.
func TestVP_TokenRecordKeepsItsOutcomeUniquely(t *testing.T) {
	h := newVPHarness(t, nil)

	recorder := &recordingTokens{TokenStore: h.stores.AccessTokens}
	h.stores.AccessTokens = recorder
	h.restart()

	h.seedVPClient(vpClient)
	challenge := h.newChallenge(vpClient, resourceAudience)
	o := verifiedOutcome(vpClient, challenge, resourceAudience)

	if got := h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), h.sign(o), challenge, resourceAudience); got.status != http.StatusOK {
		t.Fatalf("grant: status %d, body %v", got.status, got.body)
	}

	record, err := recorder.GetToken(t.Context(), recorder.signature)
	if err != nil || record.OutcomeID != o["outcome_id"] {
		t.Fatalf("stored record: outcome %q, %v; want %v", record.OutcomeID, err, o["outcome_id"])
	}

	// A client_credentials token has none.
	h.seedClient("plain", true, []string{resourceScope}, []string{resourceAudience})

	if got := h.token("plain", h.tokenProof(dpoptest.NewKey(t)), []string{resourceScope}, resourceAudience); got.status != http.StatusOK {
		t.Fatalf("client_credentials: status %d, body %v", got.status, got.body)
	}

	if plain, err := recorder.GetToken(t.Context(), recorder.signature); err != nil || plain.OutcomeID != "" {
		t.Errorf("client_credentials record: outcome %q, %v; want none", plain.OutcomeID, err)
	}

	record.RequestID = "another"
	if err := recorder.TokenStore.CreateToken(t.Context(), "another-signature", record); err == nil {
		t.Error("a second token on one outcome id was stored")
	}
}

type recordingTokens struct {
	oauth2provider.TokenStore

	signature string
}

func (r *recordingTokens) CreateToken(ctx context.Context, signature string, record oauth2provider.TokenRecord) error {
	r.signature = signature

	return r.TokenStore.CreateToken(ctx, signature, record)
}

// A registrar delegates a verified-presentation scope through registration, from a ceiling the
// server configures for it, though its own token cannot carry that scope: the registered client
// then obtains a challenge and a token through the grant, and is refused the same scope through
// client_credentials. A registrar without the ceiling cannot register the scope.
func TestVP_RegistrarDelegatesAVPScopeThroughRegistration(t *testing.T) {
	grants := []string{"client_credentials", oauth2provider.VerifiedPresentationGrantType}

	h := newVPHarness(t, func(c *oauth2provider.Config) {
		c.Registration.GrantTypes = grants
		c.Registration.DelegableScopes = map[string][]string{"registrar": {vpScope}}
	})

	registrar := seedRegistrar(t, h.harness)

	// The registrar's own token cannot carry the scope: client_credentials never issues it.
	if got := h.token("registrar", h.tokenProof(dpoptest.NewKey(t)), []string{vpScope}, resourceAudience); got.status != http.StatusBadRequest {
		t.Errorf("registrar asking for the scope: status %d body %v, want 400", got.status, got.body)
	}

	registered := h.registerWith(registrar, map[string]any{"grant_types": grants, "scope": vpScope})
	if registered.status != http.StatusCreated {
		t.Fatalf("register: status %d, body %v", registered.status, registered.body)
	}

	id, secret := registered.str("client_id"), registered.str("client_secret")

	challenged := h.challengeWithSecret(id, secret, url.Values{"audience": {resourceAudience}})
	if challenged.status != http.StatusOK {
		t.Fatalf("challenge: status %d, body %v", challenged.status, challenged.body)
	}

	challenge := challenged.str("challenge")
	issued := h.tokenWithSecret(id, secret, h.tokenProof(dpoptest.NewKey(t)), url.Values{
		"grant_type": {oauth2provider.VerifiedPresentationGrantType},
		"outcome":    {h.sign(verifiedOutcome(id, challenge, resourceAudience))}, "challenge": {challenge}, "audience": {resourceAudience},
	})
	if issued.status != http.StatusOK || issued.str("scope") != vpScope {
		t.Fatalf("grant: status %d, body %v", issued.status, issued.body)
	}

	cc := h.tokenWithSecret(id, secret, h.tokenProof(dpoptest.NewKey(t)), url.Values{
		"grant_type": {"client_credentials"}, "scope": {vpScope}, "audience": {resourceAudience},
	})
	if cc.status != http.StatusBadRequest || cc.str("error") != "invalid_scope" {
		t.Errorf("the scope through client_credentials: status %d body %v, want 400 invalid_scope", cc.status, cc.body)
	}

	// Without the ceiling the same registration is refused.
	plain := newVPHarness(t, func(c *oauth2provider.Config) { c.Registration.GrantTypes = grants })
	refused := plain.registerWith(seedRegistrar(t, plain.harness), map[string]any{"grant_types": grants, "scope": vpScope})

	if refused.status != http.StatusBadRequest || refused.reason() != oauth2provider.CodeRegistrationRejected {
		t.Errorf("registrar without the ceiling: status %d body %v, want 400 %q", refused.status, refused.body, oauth2provider.CodeRegistrationRejected)
	}
}

// The registration authority is never delegable.
func TestVP_RegistrationScopeIsNeverDelegable(t *testing.T) {
	cfg := oauth2provider.Config{
		Secret: []byte("token-signing-secret-at-least-32-bytes!"),
		Registration: oauth2provider.RegistrationConfig{
			Secret: []byte("registration-secret-at-least-32-bytes!!"), EndpointURL: "https://connector.example/register",
			DelegableScopes: map[string][]string{"registrar": {oauth2provider.RegistrationScope}},
		},
	}

	if _, err := newLibraryConfig(cfg); err == nil {
		t.Error("the registration scope was accepted as delegable")
	}
}

// waitFor fails the test when f does not return within a bound: a request left waiting on a lock
// that was never released would otherwise hang the suite.
func waitFor[T any](t *testing.T, what string, f func() T) T {
	t.Helper()

	done := make(chan T, 1)
	go func() { done <- f() }()

	select {
	case v := <-done:
		return v
	case <-time.After(20 * time.Second):
		t.Fatalf("%s did not finish: a lock or transaction was left open", what)

		var zero T

		return zero
	}
}

// A request that passed its checks and then waited behind another transaction holding the
// challenge is judged again once it holds the lock: when the outcome and the challenge expired
// during the wait, it is refused as expired, nothing is consumed and nothing is signed.
func TestVP_ExpiryIsJudgedAfterTheChallengeLock(t *testing.T) {
	h := newVPHarness(t, nil)
	h.seedVPClient(vpClient)

	challenge := h.newChallenge(vpClient, resourceAudience)
	o := verifiedOutcome(vpClient, challenge, resourceAudience)
	compact := h.sign(o)
	proof := h.tokenProof(dpoptest.NewKey(t))

	// Another transaction holds the challenge: a row lock on PostgreSQL, the store's one
	// transaction in memory.
	var release func()

	if h.pool != nil {
		tx, err := h.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}

		if _, err = tx.Exec(t.Context(), `SELECT 1 FROM oauth2_challenge WHERE challenge = $1 FOR UPDATE`, challenge); err != nil {
			t.Fatal(err)
		}

		release = func() { _ = tx.Rollback(context.Background()) }
	} else {
		txCtx, err := h.stores.Transactions.BeginTx(t.Context())
		if err != nil {
			t.Fatal(err)
		}

		release = func() { _ = h.stores.Transactions.Rollback(txCtx) }
	}

	results := make(chan result, 1)
	go func() { results <- h.grant(vpClient, proof, compact, challenge, resourceAudience) }()

	// The request has passed its first checks and is waiting.
	if h.pool != nil {
		deadline := time.Now().Add(10 * time.Second)

		for waiting := 0; waiting == 0; {
			if time.Now().After(deadline) {
				t.Fatal("the request never waited on the challenge lock")
			}

			// Scoped to this test's database: the server is shared with other tests.
			_ = h.pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_stat_activity
				WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&waiting)
			time.Sleep(10 * time.Millisecond)
		}
	} else {
		time.Sleep(200 * time.Millisecond)
	}

	h.advanceClock(10 * time.Minute) // past the outcome's and the challenge's expiry
	release()

	got := waitFor(t, "the waiting request", func() result { return <-results })
	wantRefused(t, "expired while waiting", got, http.StatusBadRequest, oauth2provider.CodeCredOutcomeExpired, o, compact)

	if n := h.signer.signed.Load(); n != 0 {
		t.Errorf("%d tokens signed", n)
	}

	if stored, err := h.stores.Challenges.GetChallenge(t.Context(), challenge); err != nil || !stored.ConsumedAt.IsZero() {
		t.Errorf("challenge: %+v, %v; want unconsumed", stored, err)
	}

	if h.pool != nil {
		var ledger, tokens int
		_ = h.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM verified_outcome), (SELECT count(*) FROM oauth2_token WHERE outcome_id IS NOT NULL)`).Scan(&ledger, &tokens)

		if ledger != 0 || tokens != 0 {
			t.Errorf("%d ledger rows and %d outcome tokens committed, want none", ledger, tokens)
		}
	}
}

// The store adapter refuses a verified-presentation token without its outcome, and an outcome on a
// token of another grant, before the store sees either.
func TestVP_AdapterRefusesAVPTokenWithoutItsOutcome(t *testing.T) {
	recorder := &recordingTokens{TokenStore: memstore.New(nil).AccessTokens}
	adapter := &storeAdapter{stores: oauth2provider.Stores{AccessTokens: recorder}}

	session := &oauth2.DefaultSession{}
	session.SetExpiresAt(oauth2.AccessToken, time.Now().Add(time.Minute))
	request := &oauth2.Request{ID: "r", Client: &oauth2.DefaultClient{ID: vpClient}, Session: session}

	vpCtx := withGrant(t.Context(), oauth2provider.VerifiedPresentationGrantType)

	for name, ctx := range map[string]context.Context{
		"grant without outcome":     vpCtx,
		"grant with an empty one":   withOutcomeID(vpCtx, ""),
		"outcome on another grant":  withOutcomeID(withGrant(t.Context(), "client_credentials"), newOutcomeID()),
		"outcome without any grant": withOutcomeID(t.Context(), newOutcomeID()),
	} {
		if err := adapter.CreateAccessTokenSession(ctx, "sig-"+name, request); err == nil {
			t.Errorf("%s: stored", name)
		}
	}

	if recorder.signature != "" {
		t.Errorf("the store was reached with %q", recorder.signature)
	}

	if err := adapter.CreateAccessTokenSession(withOutcomeID(vpCtx, newOutcomeID()), "sig", request); err != nil {
		t.Errorf("a verified-presentation token with its outcome: %v", err)
	}
}

// commitFault makes Commit fail: before committing, leaving the transaction open, or after it
// committed.
type commitFault struct {
	oauth2provider.Transactor

	afterCommit bool
	armed       atomic.Bool
}

func (c *commitFault) Commit(ctx context.Context) error {
	if !c.armed.Swap(false) {
		return c.Transactor.Commit(ctx)
	}

	if c.afterCommit {
		if err := c.Transactor.Commit(ctx); err != nil {
			return err
		}
	}

	return errors.New("injected commit failure")
}

// A commit that fails without settling is cleaned up before the 500 is written: nothing stays
// consumed or locked, and the same outcome is served next.
func TestVP_FailedCommitIsRolledBack(t *testing.T) {
	h := newVPHarness(t, nil)
	fault := &commitFault{Transactor: h.stores.Transactions}
	h.stores.Transactions = fault
	h.restart()
	h.seedVPClient(vpClient)

	challenge := h.newChallenge(vpClient, resourceAudience)
	o := verifiedOutcome(vpClient, challenge, resourceAudience)
	compact := h.sign(o)

	fault.armed.Store(true)
	wantRefused(t, "commit failed", h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), compact, challenge, resourceAudience),
		http.StatusInternalServerError, oauth2provider.CodeServerError, o, compact)

	got := waitFor(t, "the retry", func() result {
		return h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), compact, challenge, resourceAudience)
	})
	if got.status != http.StatusOK {
		t.Errorf("retry: status %d, body %v; want the rolled-back consumption served", got.status, got.body)
	}
}

// A commit that committed and then reported an error is answered 500 without the token, and the
// consumption stands: it is never reset to compensate, so the outcome cannot be used again.
func TestVP_CommitWithUnknownOutcomeKeepsTheConsumption(t *testing.T) {
	h := newVPHarness(t, nil)
	fault := &commitFault{Transactor: h.stores.Transactions, afterCommit: true}
	h.stores.Transactions = fault
	h.restart()
	h.seedVPClient(vpClient)

	challenge := h.newChallenge(vpClient, resourceAudience)
	o := verifiedOutcome(vpClient, challenge, resourceAudience)
	compact := h.sign(o)

	fault.armed.Store(true)
	got := h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), compact, challenge, resourceAudience)
	wantRefused(t, "commit reported failure", got, http.StatusInternalServerError, oauth2provider.CodeServerError, o, compact)

	if got.str("access_token") != "" {
		t.Error("the token was delivered after a commit error")
	}

	if stored, err := h.stores.Challenges.GetChallenge(t.Context(), challenge); err != nil || stored.ConsumedAt.IsZero() {
		t.Errorf("challenge: %+v, %v; want still consumed", stored, err)
	}

	wantRefused(t, "retry", waitFor(t, "the retry", func() result {
		return h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), compact, challenge, resourceAudience)
	}), http.StatusBadRequest, oauth2provider.CodeCredOutcomeConsumed, o, compact)

	if h.pool != nil {
		var ledger int
		_ = h.pool.QueryRow(t.Context(), `SELECT count(*) FROM verified_outcome WHERE outcome_id = $1 AND consumed_at IS NOT NULL`, o["outcome_id"]).Scan(&ledger)

		if ledger != 1 {
			t.Errorf("%d consumed ledger rows, want 1", ledger)
		}
	}
}

// panickingTokens panics on the next token insert, after the grant consumed the challenge and the
// outcome.
type panickingTokens struct {
	oauth2provider.TokenStore

	armed atomic.Bool
}

func (p *panickingTokens) CreateToken(ctx context.Context, signature string, record oauth2provider.TokenRecord) error {
	if p.armed.Swap(false) {
		panic("injected panic after consumption")
	}

	return p.TokenStore.CreateToken(ctx, signature, record)
}

// A panic after consumption still rolls the transaction back: nothing stays consumed or locked.
func TestVP_PanicAfterConsumptionRollsBack(t *testing.T) {
	h := newVPHarness(t, nil)
	tokens := &panickingTokens{TokenStore: h.stores.AccessTokens}
	h.stores.AccessTokens = tokens
	h.restart()
	h.seedVPClient(vpClient)

	challenge := h.newChallenge(vpClient, resourceAudience)
	compact := h.sign(verifiedOutcome(vpClient, challenge, resourceAudience))

	form := url.Values{
		"grant_type": {oauth2provider.VerifiedPresentationGrantType},
		"outcome":    {compact}, "challenge": {challenge}, "audience": {resourceAudience},
	}
	request := httptest.NewRequest(http.MethodPost, h.tokenURL, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("DPoP", h.tokenProof(dpoptest.NewKey(t)))
	request.SetBasicAuth(vpClient, testSecret)

	tokens.armed.Store(true)

	panicked := func() (recovered any) {
		defer func() { recovered = recover() }()

		h.provider.TokenHandler().ServeHTTP(httptest.NewRecorder(), request)

		return nil
	}()
	if panicked == nil {
		t.Fatal("the injected panic did not happen")
	}

	if stored, err := h.stores.Challenges.GetChallenge(t.Context(), challenge); err != nil || !stored.ConsumedAt.IsZero() {
		t.Errorf("challenge after the panic: %+v, %v; want unconsumed", stored, err)
	}

	got := waitFor(t, "the retry", func() result {
		return h.grant(vpClient, h.tokenProof(dpoptest.NewKey(t)), compact, challenge, resourceAudience)
	})
	if got.status != http.StatusOK {
		t.Errorf("retry: status %d, body %v", got.status, got.body)
	}
}
