package authelia

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/dpoptest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

// The tests in this file hold the adapter to what the connector's published
// interface states beyond the reason codes: the HTTP status that goes with
// each refusal, the headers, and key-bound registration tokens.

// At the token endpoint a client authentication failure is 401 and every
// DPoP refusal is 400. Responses are never cacheable.
func TestInterface_TokenEndpointStatuses(t *testing.T) {
	h := newHarness(t, nil)
	h.seedClient("participant", true, []string{resourceScope}, nil)
	h.seedClient("plain", false, []string{resourceScope}, nil)

	key := dpoptest.NewKey(t)
	form := url.Values{"grant_type": {"client_credentials"}}

	issued := h.token("plain", "", []string{resourceScope}, "")
	if issued.status != http.StatusOK || issued.str("token_type") != "bearer" {
		t.Errorf("no proof: status %d token_type %q, want 200 bearer", issued.status, issued.str("token_type"))
	}

	if expires, _ := issued.body["expires_in"].(float64); expires < 1 {
		t.Errorf("expires_in = %v, want a positive lifetime", issued.body["expires_in"])
	}

	used := h.tokenProof(key)
	if first := h.token("participant", used, []string{resourceScope}, ""); first.status != http.StatusOK || first.str("token_type") != "DPoP" {
		t.Fatalf("with proof: status %d token_type %q, want 200 DPoP", first.status, first.str("token_type"))
	}

	responses := []struct {
		name   string
		got    result
		status int
		reason oauth2provider.Code
	}{
		{"issued without proof", issued, http.StatusOK, ""},
		{"wrong client secret", h.tokenWithSecret("plain", "not-the-secret", "", form), http.StatusUnauthorized, oauth2provider.CodeInvalidClient},
		{"unknown client", h.tokenWithSecret("nobody", testSecret, "", form), http.StatusUnauthorized, oauth2provider.CodeInvalidClient},
		{"unsupported grant", h.tokenWithSecret("plain", testSecret, "", url.Values{"grant_type": {"password"}}), http.StatusBadRequest, oauth2provider.CodeInvalidRequest},
		{"bound client without proof", h.token("participant", "", []string{resourceScope}, ""), http.StatusBadRequest, oauth2provider.CodeDPoPInvalidProof},
		{"replayed proof", h.token("participant", used, []string{resourceScope}, ""), http.StatusBadRequest, oauth2provider.CodeDPoPReplayed},
	}

	for _, response := range responses {
		if response.got.status != response.status || response.got.reason() != response.reason {
			t.Errorf("%s: status %d reason %q, want %d %q", response.name, response.got.status, response.got.reason(), response.status, response.reason)
		}

		if response.status != http.StatusOK && response.got.str("error") == "" {
			t.Errorf("%s: the OAuth 2.0 error member is missing: %v", response.name, response.got.body)
		}

		if cache := response.got.header.Get("Cache-Control"); cache != "no-store" {
			t.Errorf("%s: Cache-Control = %q, want no-store", response.name, cache)
		}
	}
}

// The registration endpoint is a protected resource: a refusal for want of
// a usable token is 401 with a challenge naming both schemes it accepts.
func TestInterface_RegistrationRefusalsCarryAChallenge(t *testing.T) {
	h := newHarness(t, nil)
	seedRegistrar(t, h)

	for name, authorization := range map[string]string{"no token": "", "forged token": "Bearer connector_at_forged"} {
		refused := h.register(authorization, participantMetadata())
		if refused.status != http.StatusUnauthorized || refused.reason() != oauth2provider.CodeInvalidToken {
			t.Errorf("%s: status %d reason %q, want 401 %q", name, refused.status, refused.reason(), oauth2provider.CodeInvalidToken)
		}

		challenge := refused.header.Get("WWW-Authenticate")
		if !strings.Contains(challenge, "Bearer ") || !strings.Contains(challenge, "DPoP ") {
			t.Errorf("%s: WWW-Authenticate = %q, want a Bearer and a DPoP challenge", name, challenge)
		}
	}
}

// A registration token may itself be bound to a key. It is then presented
// under the DPoP scheme with a proof for the registration request; under the
// Bearer scheme, without a proof, or with another key's proof it is refused.
func TestInterface_KeyBoundRegistrationToken(t *testing.T) {
	h := newHarness(t, nil)

	scopes := []string{oauth2provider.RegistrationScope, resourceScope}
	h.seedClient("registrar", true, scopes, []string{h.registerURL})

	key := dpoptest.NewKey(t)

	issued := h.token("registrar", h.tokenProof(key), scopes, h.registerURL)
	if issued.status != http.StatusOK || issued.str("token_type") != "DPoP" {
		t.Fatalf("registrar token: status %d token_type %q, want 200 DPoP", issued.status, issued.str("token_type"))
	}

	token := issued.str("access_token")

	register := func(scheme string, signer *dpoptest.Key) result {
		proof := ""
		if signer != nil {
			proof = dpoptest.Mint(t, signer, dpoptest.Proof{Method: http.MethodPost, URL: h.registerURL, AccessToken: token})
		}

		return h.registerWithProof(scheme+" "+token, proof, participantMetadata())
	}

	if got := register("Bearer", nil); got.status != http.StatusUnauthorized || got.reason() != oauth2provider.CodeInvalidToken {
		t.Errorf("bound token as Bearer: status %d reason %q, want 401 %q", got.status, got.reason(), oauth2provider.CodeInvalidToken)
	}

	if got := register("DPoP", nil); got.status != http.StatusUnauthorized || got.reason() != oauth2provider.CodeDPoPInvalidProof {
		t.Errorf("DPoP scheme without proof: status %d reason %q, want 401 %q", got.status, got.reason(), oauth2provider.CodeDPoPInvalidProof)
	}

	if got := register("DPoP", dpoptest.NewKey(t)); got.status != http.StatusUnauthorized || got.reason() != oauth2provider.CodeDPoPInvalidProof {
		t.Errorf("proof by another key: status %d reason %q, want 401 %q", got.status, got.reason(), oauth2provider.CodeDPoPInvalidProof)
	}

	if got := register("DPoP", key); got.status != http.StatusCreated || got.str("client_id") == "" {
		t.Errorf("DPoP scheme with the bound key's proof: status %d body %v, want 201", got.status, got.body)
	}
}
