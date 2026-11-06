// Package authelia implements oauth2provider.Provider on top of
// authelia.com/provider/oauth2. It is the only package in the connector
// allowed to import that library.
package authelia

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/rfc7591"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/token/jose"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

const accessTokenPrefix = "connector_%s_"

// provider implements oauth2provider.Provider. It is unexported: callers
// hold the contract interface, so the library it is built on can never be
// reached through this package's API.
type provider struct {
	config   *oauth2.Config
	store    *storeAdapter
	strategy *hoauth2.HMACCoreStrategy
	dpop     *rfc9449.DefaultStrategy
	lib      oauth2.Provider
}

var _ oauth2provider.Provider = (*provider)(nil)

// New returns a Provider backed by the given stores.
func New(cfg oauth2provider.Config, stores oauth2provider.Stores) (oauth2provider.Provider, error) {
	if stores.Clients == nil || stores.AccessTokens == nil || stores.RegistrationTokens == nil ||
		stores.DPoPNonces == nil || stores.DPoPReplay == nil {
		return nil, errors.New("oauth2provider: every store in Stores is required")
	}

	config, err := newLibraryConfig(cfg)
	if err != nil {
		return nil, err
	}

	store := &storeAdapter{stores: stores, strategy: config.RFC7591ClientRegistrationStrategy, config: config}
	strategy := hoauth2.NewHMACCoreStrategy(config, accessTokenPrefix)
	dpop := rfc9449.NewDefaultStrategy(config, store)

	config.DPoPStrategy = dpop

	lib := compose.Compose(config, store, strategy,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.DPoPTokenFactory,
		compose.RFC7591ClientRegistrationFactory,
	)

	config.RFC7591ClientRegistrationEndpointAuthStrategy = rfc7591.NewDefaultEndpointAuthStrategy(config, store, strategy, strategy)

	return &provider{config: config, store: store, strategy: strategy, dpop: dpop, lib: lib}, nil
}

// TokenHandler implements oauth2provider.Provider.
func (p *provider) TokenHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, outcome := withOutcome(r.Context())

		request, err := p.lib.NewAccessRequest(ctx, r, &oauth2.DefaultSession{})
		if err != nil {
			writeWithReason(w, classify(err, outcome), func(rw http.ResponseWriter) {
				p.lib.WriteAccessError(ctx, rw, request, err)
			})

			return
		}

		response, err := p.lib.NewAccessResponse(ctx, request)
		if err != nil {
			writeWithReason(w, classify(err, outcome), func(rw http.ResponseWriter) {
				p.lib.WriteAccessError(ctx, rw, request, err)
			})

			return
		}

		p.lib.WriteAccessResponse(ctx, w, request, response)
	})
}

// RegistrationHandler implements oauth2provider.Provider.
func (p *provider) RegistrationHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, outcome := withOutcome(r.Context())

		request, err := p.lib.NewRFC7591ClientRegistrationRequest(ctx, r)
		if err != nil {
			writeWithReason(w, classify(err, outcome), func(rw http.ResponseWriter) {
				p.lib.WriteRFC7591ClientRegistrationError(ctx, rw, request, err)
			})

			return
		}

		response, err := p.lib.NewRFC7591ClientRegistrationResponse(ctx, request)
		if err != nil {
			writeWithReason(w, classify(err, outcome), func(rw http.ResponseWriter) {
				p.lib.WriteRFC7591ClientRegistrationError(ctx, rw, request, err)
			})

			return
		}

		p.lib.WriteRFC7591ClientRegistrationResponse(ctx, w, request, response)
	})
}

// ValidateResourceRequest implements oauth2provider.Provider. Only DPoP-bound
// access tokens are accepted: a token without a key binding is refused, as
// is a bound token presented under the Bearer scheme.
func (p *provider) ValidateResourceRequest(r *http.Request) (oauth2provider.ResourceAccess, error) {
	ctx, outcome := withOutcome(r.Context())

	token, _ := rfc9449.AccessTokenFromRequest(r)
	if token == "" {
		return oauth2provider.ResourceAccess{}, oauth2provider.NewError(oauth2provider.CodeInvalidToken, http.StatusUnauthorized, errors.New("no access token presented"))
	}

	signature := p.strategy.AccessTokenSignature(ctx, token)
	session := &oauth2.DefaultSession{}

	request, err := p.store.GetAccessTokenSession(ctx, signature, session)
	if err != nil {
		return oauth2provider.ResourceAccess{}, oauth2provider.NewError(oauth2provider.CodeInvalidToken, http.StatusUnauthorized, err)
	}

	if err = p.strategy.ValidateAccessToken(ctx, request, token); err != nil {
		return oauth2provider.ResourceAccess{}, oauth2provider.NewError(oauth2provider.CodeInvalidToken, http.StatusUnauthorized, err)
	}

	bound := session.GetDPoPJWKThumbprint()
	if bound == "" {
		return oauth2provider.ResourceAccess{}, oauth2provider.NewError(oauth2provider.CodeInvalidToken, http.StatusUnauthorized, errors.New("access token is not bound to a key"))
	}

	if _, err = p.dpop.ValidateResourceAccess(ctx, r, token, bound, p.config.DPoPNonceRequired); err != nil {
		return oauth2provider.ResourceAccess{}, p.resourceError(ctx, r, token, bound, err, outcome)
	}

	return oauth2provider.ResourceAccess{
		ClientID:   request.GetClient().GetID(),
		Thumbprint: bound,
		Scopes:     request.GetGrantedScopes(),
		Audience:   request.GetGrantedAudience(),
	}, nil
}

// resourceError labels a refused resource request. The library reports a key
// mismatch and a bad ath as the same invalid proof error, so the proof is
// parsed once more here purely to tell them apart. Nothing is accepted on
// the strength of this second look.
func (p *provider) resourceError(ctx context.Context, r *http.Request, token, bound string, err error, outcome *outcome) *oauth2provider.Error {
	code := classify(err, outcome)
	refusal := oauth2provider.NewError(code, http.StatusUnauthorized, err)

	switch code {
	case oauth2provider.CodeDPoPUseNonce:
		if nonce, nonceErr := p.dpop.NewDPoPNonce(ctx); nonceErr == nil {
			refusal.DPoPNonce = nonce
		}
	case oauth2provider.CodeDPoPInvalidProof:
		proof, parseErr := rfc9449.ParseProof(r.Header.Get("DPoP"), p.proofAlgorithms(ctx))
		if parseErr != nil {
			break
		}

		digest := sha256.Sum256([]byte(token))
		ath := base64.RawURLEncoding.EncodeToString(digest[:])

		switch {
		case proof.Thumbprint != bound:
			refusal.Code = oauth2provider.CodeDPoPKeyMismatch
		case subtle.ConstantTimeCompare([]byte(proof.AccessTokenHash), []byte(ath)) != 1:
			refusal.Code = oauth2provider.CodeDPoPInvalidATH
		}
	}

	return refusal
}

func (p *provider) proofAlgorithms(ctx context.Context) []jose.SignatureAlgorithm {
	names := p.config.GetDPoPAllowedJWSAlgorithms(ctx)
	algorithms := make([]jose.SignatureAlgorithm, 0, len(names))

	for _, name := range names {
		algorithms = append(algorithms, jose.SignatureAlgorithm(name))
	}

	return algorithms
}
