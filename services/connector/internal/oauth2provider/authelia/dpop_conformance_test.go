package authelia

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/dpoptest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider/memstore"
)

func TestDPoP_ValidProofIssuesBoundToken(t *testing.T) {
	h := newHarness(t, nil)
	h.seedClient("participant", true, []string{resourceScope}, nil)

	key := dpoptest.NewKey(t)

	issued := h.token("participant", h.tokenProof(key), []string{resourceScope}, "")
	if issued.status != http.StatusOK {
		t.Fatalf("status = %d, body %v", issued.status, issued.body)
	}

	if got := issued.str("token_type"); got != "DPoP" {
		t.Errorf("token_type = %q, want DPoP", got)
	}

	// The binding is observable where it matters: the resource accepts the
	// token with this key and reports the thumbprint it is bound to.
	token := issued.str("access_token")
	proof := dpoptest.Mint(t, key, dpoptest.Proof{Method: http.MethodGet, URL: h.resourceURL, AccessToken: token})

	accessed := h.resource("DPoP "+token, proof)
	if accessed.status != http.StatusOK {
		t.Fatalf("resource status = %d, body %v", accessed.status, accessed.body)
	}

	if got := accessed.str("jkt"); got != key.Thumbprint() {
		t.Errorf("bound jkt = %q, want %q", got, key.Thumbprint())
	}
}

func TestDPoP_BoundClientWithoutProofIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	h.seedClient("participant", true, []string{resourceScope}, nil)

	refused := h.token("participant", "", []string{resourceScope}, "")
	if refused.status == http.StatusOK {
		t.Fatal("a client registered for DPoP-bound tokens obtained a token without a proof")
	}

	if got := refused.reason(); got != oauth2provider.CodeDPoPInvalidProof {
		t.Errorf("reason = %q, want %q", got, oauth2provider.CodeDPoPInvalidProof)
	}
}

func TestDPoP_MethodBinding(t *testing.T) {
	h := newHarness(t, nil)
	h.seedClient("participant", true, []string{resourceScope}, nil)

	key := dpoptest.NewKey(t)
	proof := dpoptest.Mint(t, key, dpoptest.Proof{Method: http.MethodGet, URL: h.tokenURL})

	refused := h.token("participant", proof, []string{resourceScope}, "")
	if refused.status == http.StatusOK || refused.reason() != oauth2provider.CodeDPoPInvalidProof {
		t.Fatalf("htm GET on a POST: status %d reason %q, want refusal with %q", refused.status, refused.reason(), oauth2provider.CodeDPoPInvalidProof)
	}
}

func TestDPoP_URIBinding(t *testing.T) {
	testCases := []struct {
		name   string
		htu    func(h *harness) string
		accept bool
	}{
		{"exact", func(h *harness) string { return h.tokenURL }, true},
		{"wrong path", func(h *harness) string { return h.registerURL }, false},
		{"wrong host", func(*harness) string { return "http://other.example/token" }, false},
		// RFC 9449 section 4.2: htu is compared without query and fragment.
		{"query and fragment ignored", func(h *harness) string { return h.tokenURL + "?a=b#c" }, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			h.seedClient("participant", true, []string{resourceScope}, nil)

			proof := dpoptest.Mint(t, dpoptest.NewKey(t), dpoptest.Proof{Method: http.MethodPost, URL: tc.htu(h)})
			got := h.token("participant", proof, []string{resourceScope}, "")

			if tc.accept {
				if got.status != http.StatusOK {
					t.Fatalf("status = %d, body %v, want 200", got.status, got.body)
				}

				return
			}

			if got.status == http.StatusOK || got.reason() != oauth2provider.CodeDPoPInvalidProof {
				t.Fatalf("status %d reason %q, want refusal with %q", got.status, got.reason(), oauth2provider.CodeDPoPInvalidProof)
			}
		})
	}
}

// The harness accepts a proof for one minute after its iat, with ten seconds
// of tolerance on both sides. Stale and future proofs are minted with the
// iat they need, so nothing here waits for time to pass.
func TestDPoP_FreshnessWindow(t *testing.T) {
	testCases := []struct {
		name   string
		age    time.Duration
		accept bool
	}{
		{"inside window", 30 * time.Second, true},
		{"older than lifespan plus skew", 5 * time.Minute, false},
		{"further ahead than skew", -5 * time.Minute, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			h.seedClient("participant", true, []string{resourceScope}, nil)

			proof := dpoptest.Mint(t, dpoptest.NewKey(t), dpoptest.Proof{
				Method:   http.MethodPost,
				URL:      h.tokenURL,
				IssuedAt: time.Now().Add(-tc.age),
			})

			got := h.token("participant", proof, []string{resourceScope}, "")

			if tc.accept {
				if got.status != http.StatusOK {
					t.Fatalf("status = %d, body %v, want 200", got.status, got.body)
				}

				return
			}

			if got.status == http.StatusOK || got.reason() != oauth2provider.CodeDPoPInvalidProof {
				t.Fatalf("status %d reason %q, want refusal with %q", got.status, got.reason(), oauth2provider.CodeDPoPInvalidProof)
			}
		})
	}
}

func TestDPoP_ReplayedProofIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	h.seedClient("participant", true, []string{resourceScope}, nil)

	proof := h.tokenProof(dpoptest.NewKey(t))

	if first := h.token("participant", proof, []string{resourceScope}, ""); first.status != http.StatusOK {
		t.Fatalf("first use: status %d, body %v", first.status, first.body)
	}

	second := h.token("participant", proof, []string{resourceScope}, "")
	if second.status == http.StatusOK {
		t.Fatal("a replayed proof was accepted")
	}

	if got := second.reason(); got != oauth2provider.CodeDPoPReplayed {
		t.Errorf("reason = %q, want %q", got, oauth2provider.CodeDPoPReplayed)
	}
}

// A jti is unique "in the same context" (RFC 9449 section 4.2), which section
// 11.1 reads as the target URI. A proof for another endpoint that reuses a
// jti is a different signed proof, not a replay. This test records that
// behaviour; the invariant that matters - a replay is refused - is asserted
// by the tests around it.
func TestDPoP_SameJTIForAnotherURIIsNotAReplay(t *testing.T) {
	h := newHarness(t, nil)
	key := dpoptest.NewKey(t)
	token := h.boundToken(key)

	const jti = "reused-across-endpoints"

	atToken := dpoptest.Mint(t, key, dpoptest.Proof{Method: http.MethodPost, URL: h.tokenURL, ID: jti})
	if got := h.token("participant", atToken, []string{resourceScope}, ""); got.status != http.StatusOK {
		t.Fatalf("token endpoint: status %d, body %v", got.status, got.body)
	}

	atResource := dpoptest.Mint(t, key, dpoptest.Proof{Method: http.MethodGet, URL: h.resourceURL, ID: jti, AccessToken: token})

	got := h.resource("DPoP "+token, atResource)
	t.Logf("same jti presented at another URI: status %d, reason %q", got.status, got.reason())

	if got.status != http.StatusOK {
		t.Errorf("status = %d, want 200: the jti is scoped to the target URI", got.status)
	}

	if again := h.resource("DPoP "+token, atResource); again.reason() != oauth2provider.CodeDPoPReplayed {
		t.Errorf("verbatim replay at the resource: reason %q, want %q", again.reason(), oauth2provider.CodeDPoPReplayed)
	}
}

// Replay protection has to hold under concurrency, not just in sequence: of
// any number of simultaneous presentations of one proof, exactly one wins.
func TestDPoP_ConcurrentReplayAdmitsExactlyOne(t *testing.T) {
	const presentations = 100

	h := newHarness(t, nil)
	h.seedClient("participant", true, []string{resourceScope}, nil)

	proof := h.tokenProof(dpoptest.NewKey(t))

	var (
		start   = make(chan struct{})
		wg      sync.WaitGroup
		results = make([]result, presentations)
	)

	for i := range presentations {
		wg.Add(1)

		go func() {
			defer wg.Done()

			<-start

			results[i] = h.token("participant", proof, []string{resourceScope}, "")
		}()
	}

	close(start)
	wg.Wait()

	var accepted, replayed int

	for _, got := range results {
		switch {
		case got.status == http.StatusOK:
			accepted++
		case got.reason() == oauth2provider.CodeDPoPReplayed:
			replayed++
		default:
			t.Errorf("unexpected outcome: status %d, body %v", got.status, got.body)
		}
	}

	if accepted != 1 || replayed != presentations-1 {
		t.Fatalf("accepted %d, refused as replay %d; want exactly 1 and %d", accepted, replayed, presentations-1)
	}
}

func TestDPoP_NonceRoundTrip(t *testing.T) {
	h := newHarness(t, func(cfg *oauth2provider.Config) { cfg.DPoP.NonceRequired = true })
	h.seedClient("participant", true, []string{resourceScope}, nil)

	key := dpoptest.NewKey(t)
	mint := func(nonce string) string {
		return dpoptest.Mint(t, key, dpoptest.Proof{Method: http.MethodPost, URL: h.tokenURL, Nonce: nonce})
	}

	challenged := h.token("participant", mint(""), []string{resourceScope}, "")
	if challenged.status != http.StatusBadRequest || challenged.str("error") != "use_dpop_nonce" {
		t.Fatalf("without nonce: status %d error %q, want 400 use_dpop_nonce", challenged.status, challenged.str("error"))
	}

	if got := challenged.reason(); got != oauth2provider.CodeDPoPUseNonce {
		t.Errorf("reason = %q, want %q", got, oauth2provider.CodeDPoPUseNonce)
	}

	nonce := challenged.header.Get("DPoP-Nonce")
	if nonce == "" {
		t.Fatal("the challenge carries no DPoP-Nonce header")
	}

	if issued := h.token("participant", mint(nonce), []string{resourceScope}, ""); issued.status != http.StatusOK {
		t.Fatalf("with the issued nonce: status %d, body %v", issued.status, issued.body)
	}

	if foreign := h.token("participant", mint("not-issued-by-this-server"), []string{resourceScope}, ""); foreign.reason() != oauth2provider.CodeDPoPUseNonce {
		t.Errorf("foreign nonce: reason %q, want %q", foreign.reason(), oauth2provider.CodeDPoPUseNonce)
	}

	// Expire the nonce by moving the stores' clock, not by waiting.
	h.advanceClock(2 * time.Minute)

	if expired := h.token("participant", mint(nonce), []string{resourceScope}, ""); expired.reason() != oauth2provider.CodeDPoPUseNonce {
		t.Errorf("expired nonce: reason %q, want %q", expired.reason(), oauth2provider.CodeDPoPUseNonce)
	}
}

// The replay store is handed the proof as the provider validated it: the
// key thumbprint, the method and URI it was made for, its jti and its iat,
// together with the instant it stops being acceptable. A store applying a
// window of its own depends on that iat, which the adapter derives.
func TestDPoP_ReplayStoreReceivesTheProofIdentity(t *testing.T) {
	const (
		lifespan = 45 * time.Second
		skew     = 15 * time.Second
	)

	h := newHarness(t, func(cfg *oauth2provider.Config) {
		cfg.DPoP.ProofLifespan = lifespan
		cfg.DPoP.ClockSkew = skew
	})
	h.seedClient("participant", true, []string{resourceScope}, nil)

	key := dpoptest.NewKey(t)
	issuedAt := time.Now().Add(-30 * time.Second).Truncate(time.Second)
	proof := dpoptest.Mint(t, key, dpoptest.Proof{
		Method:   http.MethodPost,
		URL:      h.tokenURL + "?ignored=query",
		IssuedAt: issuedAt,
		ID:       "proof-identity-1",
	})

	if issued := h.token("participant", proof, []string{resourceScope}, ""); issued.status != http.StatusOK {
		t.Fatalf("token request: status %d, body %v", issued.status, issued.body)
	}

	got := h.replay.last()
	want := oauth2provider.DPoPProofUse{
		Thumbprint: key.Thumbprint(),
		Method:     http.MethodPost,
		URI:        h.tokenURL,
		ID:         "proof-identity-1",
		IssuedAt:   issuedAt,
		NotAfter:   issuedAt.Add(lifespan + skew),
	}

	if got.Thumbprint != want.Thumbprint || got.Method != want.Method || got.URI != want.URI || got.ID != want.ID || got.Nonce != "" {
		t.Errorf("proof identity = %+v, want %+v", got, want)
	}

	if !got.IssuedAt.Equal(want.IssuedAt) {
		t.Errorf("IssuedAt = %s, want the proof's iat %s", got.IssuedAt, want.IssuedAt)
	}

	if !got.NotAfter.Equal(want.NotAfter) {
		t.Errorf("NotAfter = %s, want iat + lifespan + skew = %s", got.NotAfter, want.NotAfter)
	}
}

// A proof may stay acceptable for at most MaxDPoPProofWindow after its iat,
// which is as long as a replay store is asked to keep a record. A
// configuration beyond that is refused when the provider is built, so it
// cannot surface as refused token requests later.
func TestDPoP_ProofWindowIsBounded(t *testing.T) {
	for _, tc := range []struct {
		name           string
		lifespan, skew time.Duration
		wantErr        bool
	}{
		{name: "defaults", wantErr: false},
		{name: "exactly the bound", lifespan: 80 * time.Second, skew: 10 * time.Second, wantErr: false},
		{name: "one second over", lifespan: 80 * time.Second, skew: 11 * time.Second, wantErr: true},
		{name: "default skew counts", lifespan: oauth2provider.MaxDPoPProofWindow, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := oauth2provider.Config{
				Secret: []byte("token-signing-secret-at-least-32-bytes!"),
				DPoP:   oauth2provider.DPoPConfig{ProofLifespan: tc.lifespan, ClockSkew: tc.skew},
				Registration: oauth2provider.RegistrationConfig{
					Secret:      []byte("registration-secret-at-least-32-bytes!!"),
					EndpointURL: "https://connector.example/oauth2/register",
				},
			}

			_, err := New(cfg, memstore.New(time.Now))
			if (err != nil) != tc.wantErr {
				t.Fatalf("New: err = %v, want an error: %t", err, tc.wantErr)
			}
		})
	}
}
