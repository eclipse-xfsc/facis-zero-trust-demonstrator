package authelia

import (
	"context"
	"errors"
	"fmt"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc7591"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

const (
	minSecretLength            = 32
	defaultAccessTokenLifespan = time.Hour
	tokenEntropy               = 32
)

func newLibraryConfig(cfg oauth2provider.Config) (*oauth2.Config, error) {
	if len(cfg.Secret) < minSecretLength {
		return nil, errors.New("oauth2provider: Config.Secret must be at least 32 bytes")
	}

	if len(cfg.Registration.Secret) < minSecretLength {
		return nil, errors.New("oauth2provider: Config.Registration.Secret must be at least 32 bytes")
	}

	if string(cfg.Secret) == string(cfg.Registration.Secret) {
		return nil, errors.New("oauth2provider: Config.Registration.Secret must differ from Config.Secret")
	}

	if cfg.Registration.EndpointURL == "" {
		return nil, errors.New("oauth2provider: Config.Registration.EndpointURL is required")
	}

	lifespan := cfg.AccessTokenLifespan
	if lifespan <= 0 {
		lifespan = defaultAccessTokenLifespan
	}

	config := &oauth2.Config{
		GlobalSecret:        cfg.Secret,
		AccessTokenLifespan: lifespan,
		TokenEntropy:        tokenEntropy,
		ScopeStrategy:       oauth2.ExactScopeStrategy,
		AudienceStrategy:    oauth2.ExactAudienceStrategy,

		// A client_credentials request is granted the scopes it asks for,
		// after they have been checked against the client's own scopes.
		ClientCredentialsFlowImplicitGrantRequested: true,

		DPoPEnabled:              true,
		DPoPEnforce:              cfg.DPoP.Enforce,
		DPoPNonceRequired:        cfg.DPoP.NonceRequired,
		DPoPProofLifespan:        cfg.DPoP.ProofLifespan,
		DPoPClockSkew:            cfg.DPoP.ClockSkew,
		DPoPNonceLifespan:        cfg.DPoP.NonceLifespan,
		DPoPAllowedJWSAlgorithms: cfg.DPoP.Algorithms,

		RFC7591ClientRegistrationGlobalSecret:      cfg.Registration.Secret,
		RFC7591ClientRegistrationEndpointURL:       cfg.Registration.EndpointURL,
		RFC7591ClientRegistrationEndpointAudiences: []string{cfg.Registration.EndpointURL},
		RFC7591ClientRegistrationScopes:            []string{oauth2provider.RegistrationScope},
		RFC7591ClientRegistrationGrantTypes:        cfg.Registration.GrantTypes,
		RFC7591ClientRegistrationStrategy:          rfc7591.NewDefaultClientRegistrationStrategy(),
	}

	// Checked on the library's getters, so that its defaults for a zero
	// lifespan or skew are counted as well.
	ctx := context.Background()
	if window := config.GetDPoPProofLifespan(ctx) + config.GetDPoPClockSkew(ctx); window > oauth2provider.MaxDPoPProofWindow {
		return nil, fmt.Errorf("oauth2provider: Config.DPoP.ProofLifespan plus Config.DPoP.ClockSkew is %s, more than the %s a proof may stay acceptable",
			window, oauth2provider.MaxDPoPProofWindow)
	}

	return config, nil
}
