package authelia

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/dpoptest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

// registrarToken is a token for the registration endpoint. With opaque tokens it is a bearer
// token; signed tokens are issued only to a proof, so it is then bound to key.
type registrarToken struct {
	token string
	key   *dpoptest.Key
}

// seedRegistrar provisions the client that is allowed to register others and
// returns a token for the registration endpoint.
func seedRegistrar(t *testing.T, h *harness) registrarToken {
	t.Helper()

	scopes := []string{oauth2provider.RegistrationScope, resourceScope}
	h.seedClient("registrar", false, scopes, []string{h.registerURL})

	return h.registrarToken(scopes)
}

// registrarToken requests a token for the registration endpoint as the registrar.
func (h *harness) registrarToken(scopes []string) registrarToken {
	h.t.Helper()

	var key *dpoptest.Key

	proof, audience := "", h.registerURL
	if h.signed {
		// The token also carries the audience the registrant registers for: a registration
		// cannot name an audience its token does not.
		key = dpoptest.NewKey(h.t)
		proof, audience = h.tokenProof(key), h.registerURL+" "+h.defaultAudience
	}

	issued := h.token("registrar", proof, scopes, audience)
	if issued.status != http.StatusOK {
		h.t.Fatalf("registrar token: status %d, body %v", issued.status, issued.body)
	}

	return registrarToken{token: issued.str("access_token"), key: key}
}

// registerWith registers metadata with token, under the scheme its binding calls for. With signed
// tokens the registrant also names the default audience, since a token is only issued for one.
func (h *harness) registerWith(token registrarToken, metadata map[string]any) result {
	h.t.Helper()

	if _, named := metadata["audience"]; h.signed && !named {
		metadata["audience"] = []string{h.defaultAudience}
	}

	if token.key == nil {
		return h.register("Bearer "+token.token, metadata)
	}

	proof := dpoptest.Mint(h.t, token.key, dpoptest.Proof{Method: http.MethodPost, URL: h.registerURL, AccessToken: token.token})

	return h.registerWithProof("DPoP "+token.token, proof, metadata)
}

func participantMetadata() map[string]any {
	return map[string]any{
		"client_name":                "participant backend",
		"grant_types":                []string{"client_credentials"},
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      resourceScope,
		"dpop_bound_access_tokens":   true,
	}
}

// Registration is not open. It takes an access token, issued by the token
// endpoint like any other, that names the registration endpoint as its
// audience and carries the registration scope.
func TestRegistration_RequiresAnAuthorisedToken(t *testing.T) {
	h := newHarness(t, nil)
	registrar := seedRegistrar(t, h)

	anonymous := h.register("", participantMetadata())
	if anonymous.status != http.StatusUnauthorized || anonymous.reason() != oauth2provider.CodeInvalidToken {
		t.Errorf("no token: status %d reason %q, want 401 %q", anonymous.status, anonymous.reason(), oauth2provider.CodeInvalidToken)
	}

	forged := h.register("Bearer connector_at_forged", participantMetadata())
	if forged.status != http.StatusUnauthorized || forged.reason() != oauth2provider.CodeInvalidToken {
		t.Errorf("forged token: status %d reason %q, want 401 %q", forged.status, forged.reason(), oauth2provider.CodeInvalidToken)
	}

	// A valid token for the right audience but without the registration scope.
	unscoped := h.registrarToken([]string{resourceScope})

	refused := h.registerWith(unscoped, participantMetadata())
	if refused.status != http.StatusForbidden || refused.reason() != oauth2provider.CodeInsufficientScope {
		t.Errorf("unscoped token: status %d reason %q, want 403 %q", refused.status, refused.reason(), oauth2provider.CodeInsufficientScope)
	}

	registered := h.registerWith(registrar, participantMetadata())
	if registered.status != http.StatusCreated {
		t.Fatalf("authorised token: status %d, body %v", registered.status, registered.body)
	}

	if registered.str("client_id") == "" || registered.str("client_secret") == "" {
		t.Errorf("registration response lacks credentials: %v", registered.body)
	}
}

// A participant backend registers itself and, with the credentials it is
// handed, obtains a token bound to its own key - with no operator involved.
func TestRegistration_RegisteredClientObtainsBoundToken(t *testing.T) {
	h := newHarness(t, nil)

	registered := h.registerWith(seedRegistrar(t, h), participantMetadata())
	if registered.status != http.StatusCreated {
		t.Fatalf("registration: status %d, body %v", registered.status, registered.body)
	}

	if bound, _ := registered.body["dpop_bound_access_tokens"].(bool); !bound {
		t.Errorf("dpop_bound_access_tokens was not retained: %v", registered.body)
	}

	clientID, secret := registered.str("client_id"), registered.str("client_secret")
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {resourceScope}}
	if h.signed {
		form.Set("audience", h.defaultAudience)
	}

	withoutProof := h.tokenWithSecret(clientID, secret, "", form)
	if withoutProof.status == http.StatusOK {
		t.Fatal("the registered client obtained a token without a proof")
	}

	key := dpoptest.NewKey(t)

	issued := h.tokenWithSecret(clientID, secret, h.tokenProof(key), form)
	if issued.status != http.StatusOK || issued.str("token_type") != "DPoP" {
		t.Fatalf("token: status %d token_type %q body %v, want 200 DPoP", issued.status, issued.str("token_type"), issued.body)
	}

	token := issued.str("access_token")
	proof := dpoptest.Mint(t, key, dpoptest.Proof{Method: http.MethodGet, URL: h.resourceURL, AccessToken: token})

	accessed := h.resource("DPoP "+token, proof)
	if accessed.status != http.StatusOK || accessed.str("client_id") != clientID {
		t.Fatalf("resource: status %d body %v, want 200 for client %q", accessed.status, accessed.body, clientID)
	}
}

// The secret is returned to the registrant once and only its hash is kept.
func TestRegistration_SecretIsStoredHashed(t *testing.T) {
	h := newHarness(t, nil)

	registered := h.registerWith(seedRegistrar(t, h), participantMetadata())
	if registered.status != http.StatusCreated {
		t.Fatalf("registration: status %d, body %v", registered.status, registered.body)
	}

	stored, err := h.stores.Clients.GetClient(t.Context(), registered.str("client_id"))
	if err != nil {
		t.Fatalf("stored client: %v", err)
	}

	if len(stored.SecretHash) == 0 || string(stored.SecretHash) == registered.str("client_secret") {
		t.Error("the client secret was not stored as a hash")
	}

	if wrong := h.tokenWithSecret(stored.ID, "not-the-secret", h.tokenProof(dpoptest.NewKey(t)), url.Values{"grant_type": {"client_credentials"}}); wrong.reason() != oauth2provider.CodeInvalidClient {
		t.Errorf("wrong secret: reason %q, want %q", wrong.reason(), oauth2provider.CodeInvalidClient)
	}
}

// A registrant cannot grant itself more than the registrar's token allows,
// nor a grant type the deployment does not offer.
func TestRegistration_CannotExceedTheRegistrar(t *testing.T) {
	testCases := []struct {
		name   string
		member string
		value  any
	}{
		{"scope beyond the registrar's", "scope", resourceScope + " admin"},
		{"the registration scope itself", "scope", oauth2provider.RegistrationScope},
		{"grant type not offered", "grant_types", []string{"password"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)

			metadata := participantMetadata()
			metadata[tc.member] = tc.value

			got := h.registerWith(seedRegistrar(t, h), metadata)
			if got.status != http.StatusBadRequest || got.reason() != oauth2provider.CodeRegistrationRejected {
				t.Fatalf("status %d reason %q body %v, want 400 %q", got.status, got.reason(), got.body, oauth2provider.CodeRegistrationRejected)
			}
		})
	}
}
