package authelia

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/dpoptest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

// The operator may provision both roles. A registration token limited to one
// audience cannot register the other role, even if its issuing client may do so.
func TestRegistrationAudienceCeiling(t *testing.T) {
	h := newHarness(t, nil)
	const inbound = "https://guard.facis.invalid"
	const upstream = "https://resource.facis.invalid"
	h.seedClient("registrar", true, []string{oauth2provider.RegistrationScope, resourceScope}, []string{h.registerURL, inbound, upstream})
	key := dpoptest.NewKey(t)
	issued := h.token("registrar", h.tokenProof(key), []string{oauth2provider.RegistrationScope, resourceScope}, h.registerURL+" "+inbound)
	if issued.status != http.StatusOK {
		t.Fatalf("registration token status %d", issued.status)
	}
	auth := registrarToken{token: issued.str("access_token"), key: key}
	for _, aud := range []string{upstream, inbound} {
		metadata := participantMetadata()
		metadata["audience"] = []string{aud}
		got := h.registerWith(auth, metadata)
		if aud == upstream {
			if got.status != http.StatusBadRequest || got.str("error") != "invalid_client_metadata" {
				t.Fatalf("registration crossed audience ceiling: status %d", got.status)
			}
			continue
		}
		if got.status != http.StatusCreated {
			t.Fatalf("guard registration status %d", got.status)
		}
		for _, requested := range []string{upstream, inbound} {
			token := h.tokenWithSecret(got.str("client_id"), got.str("client_secret"), h.tokenProof(key), url.Values{"grant_type": {"client_credentials"}, "scope": {resourceScope}, "audience": {requested}})
			if requested == upstream && token.status != http.StatusBadRequest {
				t.Fatalf("client crossed grant ceiling: status %d", token.status)
			}
			if requested == inbound && token.status != http.StatusOK {
				t.Fatalf("guard grant status %d", token.status)
			}
		}
	}
}

// Test both roles with valid signed presentations. Cross-audience grant refusals
// must occur without consuming the allowed challenge or minting a token.
func TestVerifiedPresentationAudienceIsolation(t *testing.T) {
	h := newVPHarness(t, func(c *oauth2provider.Config) {
		c.ExclusiveAudiences = []string{"https://guard.facis.invalid", "https://resource.facis.invalid"}
	})
	const inbound = "https://guard.facis.invalid"
	const upstream = "https://resource.facis.invalid"
	for _, role := range []struct{ id, allowed, forbidden string }{{"participant", inbound, upstream}, {"store", upstream, inbound}} {
		t.Run(role.id, func(t *testing.T) {
			h.seedVPClient(role.id)
			client, err := h.stores.Clients.GetClient(t.Context(), role.id)
			if err != nil {
				t.Fatal(err)
			}
			client.Audience = []string{role.allowed}
			if err := h.stores.Clients.UpdateClient(t.Context(), client); err != nil {
				t.Fatal(err)
			}
			if got := h.challenge(role.id, url.Values{"audience": {role.forbidden}}); got.status != http.StatusBadRequest || got.str("error") != "invalid_request" {
				t.Fatalf("cross-audience challenge status %d", got.status)
			}
			key := dpoptest.NewKey(t)
			challenge := "forbidden-challenge-" + role.id
			if err := h.stores.Challenges.CreateChallenge(t.Context(), oauth2provider.Challenge{Value: challenge, ClientID: role.id, Audience: role.forbidden, ExpiresAt: h.now().Add(oauth2provider.ChallengeLifetime)}); err != nil {
				t.Fatal(err)
			}
			forbidden := h.sign(verifiedOutcome(role.id, challenge, role.forbidden))
			before := h.signer.signed.Load()
			got := h.grant(role.id, h.tokenProof(key), forbidden, challenge, role.forbidden)
			if got.status != http.StatusBadRequest || got.str("error") != "invalid_request" || !strings.Contains(got.str("error_description"), "not registered for this client") || h.signer.signed.Load() != before {
				t.Fatal("cross-audience grant was not refused before signing")
			}
			challenge = h.newChallenge(role.id, role.allowed)
			allowed := h.sign(verifiedOutcome(role.id, challenge, role.allowed))
			granted := h.grant(role.id, h.tokenProof(key), allowed, challenge, role.allowed)
			if granted.status != http.StatusOK {
				t.Fatalf("allowed grant status %d", granted.status)
			}
			// A workload token cannot act as the provisioning registrar.
			metadata := participantMetadata()
			metadata["audience"] = []string{role.forbidden}
			registered := h.registerWith(registrarToken{token: granted.str("access_token"), key: key}, metadata)
			if registered.status < 400 || registered.status >= 500 {
				t.Fatalf("workload registered another client: status %d", registered.status)
			}
			// Renewal uses a fresh challenge and retains the same audience restriction.
			renewal := h.newChallenge(role.id, role.allowed)
			renewed := h.grant(role.id, h.tokenProof(key), h.sign(verifiedOutcome(role.id, renewal, role.allowed)), renewal, role.allowed)
			if renewed.status != http.StatusOK {
				t.Fatalf("allowed renewal status %d", renewed.status)
			}
		})
	}
}

func TestExclusiveAudienceRegistration(t *testing.T) {
	h := newHarness(t, nil)
	const inbound = "https://guard.facis.invalid"
	const upstream = "https://resource.facis.invalid"
	h.seedClient("registrar", true, []string{oauth2provider.RegistrationScope, resourceScope}, []string{h.registerURL, inbound, upstream})
	key := dpoptest.NewKey(t)
	issued := h.token("registrar", h.tokenProof(key), []string{oauth2provider.RegistrationScope, resourceScope}, h.registerURL+" "+inbound+" "+upstream)
	if issued.status != http.StatusOK {
		t.Fatalf("registrar status %d", issued.status)
	}
	// A token issued before the exclusivity setting cannot register a dual-role client.
	h.cfg.ExclusiveAudiences = []string{inbound, upstream}
	h.restart()
	auth := registrarToken{token: issued.str("access_token"), key: key}
	for _, audiences := range [][]string{{inbound, upstream}, {inbound}, {upstream}} {
		metadata := participantMetadata()
		metadata["audience"] = audiences
		got := h.registerWith(auth, metadata)
		if len(audiences) == 2 {
			if got.status != http.StatusBadRequest || got.str("error") != "invalid_client_metadata" || !strings.Contains(got.str("error_description"), "exclusive audiences") {
				t.Fatal("dual audience registration was not refused by exclusivity check")
			}
		} else if got.status != http.StatusCreated {
			t.Fatalf("single audience registration status %d", got.status)
		}
	}
}

func TestExclusiveAudienceClientCredentials(t *testing.T) {
	const inbound = "https://guard.facis.invalid"
	const upstream = "https://resource.facis.invalid"
	h := newHarness(t, func(c *oauth2provider.Config) { c.ExclusiveAudiences = []string{inbound, upstream} })
	h.seedClient("legacy", true, []string{resourceScope}, []string{inbound, upstream})
	key := dpoptest.NewKey(t)
	for _, audience := range []string{inbound + " " + upstream, inbound} {
		got := h.token("legacy", h.tokenProof(key), []string{resourceScope}, audience)
		if got.status != http.StatusBadRequest || got.str("error") != "invalid_request" || !strings.Contains(got.str("error_description"), "exclusive audiences") {
			t.Fatal("legacy client was not refused by exclusivity check")
		}
	}
	for _, audience := range []string{inbound, upstream} {
		h.seedClient(audience, true, []string{resourceScope}, []string{audience})
		if got := h.token(audience, h.tokenProof(key), []string{resourceScope}, audience); got.status != http.StatusOK {
			t.Fatalf("single audience grant status %d", got.status)
		}
	}
}

func TestExclusiveAudienceVerifiedPresentation(t *testing.T) {
	h := newVPHarness(t, func(c *oauth2provider.Config) { c.ExclusiveAudiences = []string{resourceAudience, otherAudience} })
	h.seedVPClient("legacy")
	key := dpoptest.NewKey(t)
	challenge := h.newChallenge("legacy", resourceAudience)
	before := h.signer.signed.Load()
	got := h.grant("legacy", h.tokenProof(key), h.sign(verifiedOutcome("legacy", challenge, resourceAudience)), challenge, resourceAudience)
	if got.status != http.StatusBadRequest || got.str("error") != "invalid_request" || !strings.Contains(got.str("error_description"), "exclusive audiences") || h.signer.signed.Load() != before {
		t.Fatal("legacy client was not refused before signing")
	}
}
