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
	"fmt"
	"net/http"
	"strings"
	"time"

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
	strategy coreStrategy
	dpop     *rfc9449.DefaultStrategy
	lib      oauth2.Provider
	fosite   *oauth2.Fosite
	signed   bool

	// vp is the verified-presentation grant's configuration, nil when the grant is not enabled.
	vp *verifiedPresentation

	clock *clock
}

// coreStrategy is what the adapter needs of the token strategy: the HMAC one for opaque tokens or
// signedStrategy.
type coreStrategy interface {
	hoauth2.AccessTokenStrategy
	rfc7591.ClientRegistrationTokenStrategy
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

	vp, err := newVerifiedPresentation(cfg, stores)
	if err != nil {
		return nil, err
	}

	store := &storeAdapter{stores: stores, strategy: config.RFC7591ClientRegistrationStrategy, config: config}
	hmac := hoauth2.NewHMACCoreStrategy(config, accessTokenPrefix)

	var strategy coreStrategy = hmac
	if cfg.AccessTokenSigner != nil {
		strategy = newSignedStrategy(config, hmac, cfg.AccessTokenSigner)
	}
	dpop := rfc9449.NewDefaultStrategy(config, store)

	config.DPoPStrategy = dpop

	clk := &clock{now: time.Now}

	var vpScopes map[string]bool
	if vp != nil {
		vpScopes = vp.vpScopes
	}

	factories := []compose.Factory{
		func(config oauth2.Configurator, storage, strategy any) any {
			return &clientCredentials{
				ClientCredentialsGrantHandler: compose.OAuth2ClientCredentialsGrantFactory(config, storage, strategy).(*hoauth2.ClientCredentialsGrantHandler),
				vpScopes:                      vpScopes,
			}
		},
		compose.DPoPTokenFactory,
		compose.RFC7591ClientRegistrationFactory,
	}

	if vp != nil {
		factories = append(factories, func(_ oauth2.Configurator, _, _ any) any {
			return &vpGrant{
				HandleHelper: &hoauth2.HandleHelper{AccessTokenStrategy: strategy, AccessTokenStorage: store, Config: config},
				vp:           vp,
				store:        store,
				lifespan:     config.GetAccessTokenLifespan(context.Background()),
				clock:        clk,
			}
		})
	}

	lib := compose.Compose(config, store, strategy, factories...)

	fosite, ok := lib.(*oauth2.Fosite)
	if !ok {
		return nil, fmt.Errorf("oauth2provider: the library composed %T, not its provider", lib)
	}

	config.RFC7591ClientRegistrationEndpointAuthStrategy = &delegatingAuth{
		inner:     rfc7591.NewDefaultEndpointAuthStrategy(config, store, strategy, strategy),
		delegable: cfg.Registration.DelegableScopes,
	}

	return &provider{
		config: config, store: store, strategy: strategy, dpop: dpop, lib: lib, fosite: fosite,
		signed: cfg.AccessTokenSigner != nil, vp: vp, clock: clk,
	}, nil
}

// newSession is the session a token request starts with: a JWT session when tokens are signed,
// since the library takes the token's header and claims from it.
func (p *provider) newSession() oauth2.Session {
	if p.signed {
		return &hoauth2.JWTSession{}
	}

	return &oauth2.DefaultSession{}
}

// TokenHandler implements oauth2provider.Provider.
//
// A verified-presentation request is validated by NewAccessRequest without writes (client
// authentication, DPoP proof, nonce and replay records stay outside any transaction). Only then is a
// transaction begun; NewAccessResponse runs in it, consuming the challenge and the outcome and
// storing the token, and the transaction commits only after NewAccessResponse returned. The response
// is written after the commit. Any error, a failed commit included, rolls back and is answered as an
// error, so a token is never delivered on a consumption that did not persist.
func (p *provider) TokenHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, outcome := withOutcome(r.Context())

		refuse := func(request oauth2.AccessRequester, err error) {
			writeWithReason(w, classify(err, outcome), func(rw http.ResponseWriter) {
				p.lib.WriteAccessError(ctx, rw, request, err)
			})
		}

		request, err := p.lib.NewAccessRequest(ctx, r, p.newSession())
		if err != nil {
			refuse(request, err)

			return
		}

		// The validated grant goes with the token record, independently of anything the grant
		// handler adds, so the store can hold a verified-presentation token to its outcome.
		ctx = withGrant(ctx, strings.Join(request.GetGrantTypes(), " "))

		if request.GetGrantTypes().ExactOne(vpGrantType) {
			p.serveTransactional(ctx, w, request, refuse)

			return
		}

		response, err := p.lib.NewAccessResponse(ctx, request)
		if err != nil {
			refuse(request, err)

			return
		}

		p.lib.WriteAccessResponse(ctx, w, request, response)
	})
}

// serveTransactional issues a verified-presentation token inside one transaction. NewAccessResponse
// runs in it; the transaction is settled - committed, or rolled back - before any response is
// written. A commit that reports an error may still have committed: the request is then answered
// 500 without the token, and the consumption stands. Nothing ever resets a consumption to
// compensate. The deferred cleanup covers a panic.
func (p *provider) serveTransactional(ctx context.Context, w http.ResponseWriter, request oauth2.AccessRequester, refuse func(oauth2.AccessRequester, error)) {
	txCtx, err := p.store.BeginTX(ctx)
	if err != nil {
		refuse(request, oauth2.ErrServerError.WithWrap(err))

		return
	}

	settled := false

	defer func() {
		if !settled {
			_ = p.store.Rollback(txCtx)
		}
	}()

	response, err := p.lib.NewAccessResponse(txCtx, request)
	if err == nil {
		if err = p.store.Commit(txCtx); err == nil {
			settled = true
			p.lib.WriteAccessResponse(ctx, w, request, response)

			return
		}

		err = oauth2.ErrServerError.WithWrap(err)
	}

	// Cleanup runs before the error is written, after a failed commit as well: a transactor whose
	// commit failed without settling must not keep its writes or locks. Rolling back a transaction
	// that did commit changes nothing.
	if rollbackErr := p.store.Rollback(txCtx); rollbackErr == nil {
		settled = true
	}

	refuse(request, err)
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
