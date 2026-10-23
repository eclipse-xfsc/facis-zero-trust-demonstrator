package authelia

import (
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

const (
	vpGrantType    = oauth2provider.VerifiedPresentationGrantType
	challengeBytes = 32 // 256 bits, 43 base64url characters
)

// credCodes maps the IF-03 verifier's codes onto the contract's.
var credCodes = map[string]oauth2provider.Code{
	if03.CodeSignature:   oauth2provider.CodeCredOutcomeSignature,
	if03.CodeNotVerified: oauth2provider.CodeCredOutcomeNotVerified,
	if03.CodeMismatch:    oauth2provider.CodeCredOutcomeMismatch,
	if03.CodeExpired:     oauth2provider.CodeCredOutcomeExpired,
	if03.CodeConsumed:    oauth2provider.CodeCredOutcomeConsumed,
}

// credError is the cause of an invalid_grant refusal carrying an IF-03 code; classify reads it. Its
// text is the code alone, so nothing of the outcome reaches an error or a log through it.
type credError struct{ code oauth2provider.Code }

func (e *credError) Error() string { return string(e.code) }

func refuseCred(code oauth2provider.Code) error {
	return oauth2.ErrInvalidGrant.WithHint("The verification outcome or its challenge was refused; see reason.").WithWrap(&credError{code: code})
}

// verifiedPresentation is the validated configuration of the grant.
type verifiedPresentation struct {
	issuers if03.Issuers
	scopes  []oauth2provider.ClaimScopes

	// vpScopes is every scope the mapping can issue, none of which client_credentials issues.
	vpScopes map[string]bool
}

// newVerifiedPresentation validates the grant's configuration. It returns nil when the grant is not
// enabled.
func newVerifiedPresentation(cfg oauth2provider.Config, stores oauth2provider.Stores) (*verifiedPresentation, error) {
	vp := cfg.VerifiedPresentation
	if len(vp.TrustedIssuers) == 0 && len(vp.Scopes) == 0 {
		return nil, nil
	}

	fail := func(format string, args ...any) error {
		return fmt.Errorf("oauth2provider: Config.VerifiedPresentation: "+format, args...)
	}

	if len(vp.TrustedIssuers) == 0 {
		return nil, fail("TrustedIssuers is required")
	}

	if len(vp.Scopes) == 0 {
		return nil, fail("Scopes is required")
	}

	// The token must carry cnf.jkt and aud, which only signed tokens do.
	if cfg.AccessTokenSigner == nil {
		return nil, fail("the grant issues signed tokens only and needs Config.AccessTokenSigner")
	}

	if stores.Challenges == nil || stores.Outcomes == nil || stores.Transactions == nil {
		return nil, fail("Stores.Challenges, Stores.Outcomes and Stores.Transactions are required")
	}

	owners := map[string]string{}

	for issuer, keys := range vp.TrustedIssuers {
		if issuer == "" || len(keys) == 0 {
			return nil, fail("issuer %q has no keys", issuer)
		}

		for kid, key := range keys {
			if kid == "" || key == nil || key.Curve != elliptic.P256() {
				return nil, fail("issuer %q: key %q is not a P-256 key with a kid", issuer, kid)
			}

			if other, ok := owners[kid]; ok {
				return nil, fail("kid %q belongs to both %q and %q", kid, other, issuer)
			}

			owners[kid] = issuer
		}
	}

	out := &verifiedPresentation{issuers: vp.TrustedIssuers, vpScopes: map[string]bool{}}
	seen := map[[2]string]bool{}

	for _, entry := range vp.Scopes {
		if entry.Role == "" || len(entry.Scopes) == 0 {
			return nil, fail("an entry needs a role and at least one scope")
		}

		pair := [2]string{entry.Role, entry.Entitlement}
		if seen[pair] {
			return nil, fail("role %q with entitlement %q is mapped twice", entry.Role, entry.Entitlement)
		}

		seen[pair] = true

		for _, scope := range entry.Scopes {
			// The registration scope is obtained through client_credentials, which never issues a
			// scope of this grant.
			if scope == "" || strings.ContainsAny(scope, " \t") || scope == oauth2provider.RegistrationScope {
				return nil, fail("scope %q cannot be issued by this grant", scope)
			}

			out.vpScopes[scope] = true
		}

		out.scopes = append(out.scopes, oauth2provider.ClaimScopes{
			Role: entry.Role, Entitlement: entry.Entitlement, Scopes: slices.Clone(entry.Scopes),
		})
	}

	return out, nil
}

// scopesFor maps the outcome's claims to scopes, limited to the client's. Unmapped claims, or a
// mapping that leaves the client nothing, are refused.
func (v *verifiedPresentation) scopesFor(claims if03.Claims, ceiling []string) ([]string, error) {
	for _, entry := range v.scopes {
		if entry.Role != claims.Role || entry.Entitlement != claims.Entitlement {
			continue
		}

		var granted []string

		for _, scope := range entry.Scopes {
			if slices.Contains(ceiling, scope) && !slices.Contains(granted, scope) {
				granted = append(granted, scope)
			}
		}

		if len(granted) == 0 {
			break
		}

		return granted, nil
	}

	return nil, oauth2.ErrInvalidScope.WithHint("The verification outcome's claims grant this client no scope.")
}

// vpGrant is the verified-presentation grant as a token endpoint handler. HandleTokenEndpointRequest
// validates without writing; PopulateTokenEndpointResponse validates again, then consumes the
// challenge and the outcome and issues the token, all inside the transaction TokenHandler opened.
type vpGrant struct {
	*hoauth2.HandleHelper

	vp       *verifiedPresentation
	store    *storeAdapter
	lifespan time.Duration
	clock    *clock
}

// clock is the provider's one time source: every validity decision and every instant written to
// the stores comes from it. Tests replace now.
type clock struct{ now func() time.Time }

var _ oauth2.TokenEndpointHandler = (*vpGrant)(nil)

func (g *vpGrant) CanSkipClientAuth(context.Context, oauth2.AccessRequester) bool { return false }

func (g *vpGrant) CanHandleTokenEndpointRequest(_ context.Context, request oauth2.AccessRequester) bool {
	return request.GetGrantTypes().ExactOne(vpGrantType)
}

// checked is what a validated request established.
type checked struct {
	outcome   if03.Outcome
	challenge string
	audience  string
	scopes    []string

	// at is the instant the checks were made at, and challengeExpires the challenge's expiry.
	at               time.Time
	challengeExpires time.Time
}

func (g *vpGrant) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) error {
	if !g.CanHandleTokenEndpointRequest(ctx, request) {
		return oauth2.ErrUnknownRequest
	}

	v, err := g.check(ctx, request, false)
	if err != nil {
		return err
	}

	request.GetSession().SetExpiresAt(oauth2.AccessToken, v.at.UTC().Add(g.lifespan))

	return nil
}

// check runs every read-only check of the grant, in the order IF-02 gives them codes. With lock, the
// challenge is read under its row lock, and the instant the checks use is taken only once the lock
// is held, so a wait behind another transaction can never leave them judged at a stale time.
func (g *vpGrant) check(ctx context.Context, request oauth2.AccessRequester, lock bool) (checked, error) {
	client := request.GetClient()
	if client == nil || client.IsPublic() {
		return checked{}, oauth2.ErrInvalidClient.WithHint("The verified-presentation grant requires an authenticated confidential client.")
	}

	if !client.GetGrantTypes().Has(vpGrantType) {
		return checked{}, oauth2.ErrUnauthorizedClient.WithHint("The client is not allowed to use the verified-presentation grant.")
	}

	form := request.GetRequestForm()
	if form.Has("scope") || form.Has("resource") {
		return checked{}, oauth2.ErrInvalidRequest.WithHint("The verified-presentation grant takes no scope or resource; the outcome's claims decide the scopes.")
	}

	compact, okOutcome := single(form, "outcome")
	challenge, okChallenge := single(form, "challenge")
	audience, okAudience := single(form, "audience")

	if !okOutcome || !okChallenge || !okAudience || strings.ContainsAny(audience, " \t") {
		return checked{}, oauth2.ErrInvalidRequest.WithHint("The parameters outcome, challenge and a single audience are each required exactly once.")
	}

	if !slices.Contains(client.GetAudience(), audience) {
		return checked{}, oauth2.ErrInvalidRequest.WithHint("The audience is not registered for this client.")
	}

	read := g.store.stores.Challenges.GetChallenge
	if lock {
		read = g.store.stores.Challenges.LockChallenge
	}

	stored, err := read(ctx, challenge)

	now := g.clock.now()
	clientID := client.GetID()

	outcome, verifyErr := if03.Verify(compact, g.vp.issuers, if03.Expect{ClientID: clientID, Challenge: challenge, Audience: audience}, now)

	if err != nil && !errors.Is(err, oauth2provider.ErrNotFound) {
		return checked{}, oauth2.ErrServerError.WithWrap(err)
	}

	bound := err == nil && stored.ClientID == clientID && stored.Audience == audience

	if verifyErr != nil {
		var refusal *if03.Error
		if !errors.As(verifyErr, &refusal) {
			return checked{}, oauth2.ErrServerError
		}

		// The binding of the stored challenge is a match check, which IF-02 orders before the
		// interval check that if03.Verify runs last.
		if refusal.Code == if03.CodeExpired && !bound {
			return checked{}, refuseCred(oauth2provider.CodeCredOutcomeMismatch)
		}

		code, ok := credCodes[refusal.Code]
		if !ok {
			return checked{}, oauth2.ErrServerError
		}

		return checked{}, refuseCred(code)
	}

	switch {
	case !bound:
		return checked{}, refuseCred(oauth2provider.CodeCredOutcomeMismatch)
	case !now.Before(stored.ExpiresAt):
		return checked{}, refuseCred(oauth2provider.CodeCredOutcomeExpired)
	case !stored.ConsumedAt.IsZero():
		return checked{}, refuseCred(oauth2provider.CodeCredOutcomeConsumed)
	}

	scopes, err := g.vp.scopesFor(outcome.Claims, client.GetScopes())
	if err != nil {
		return checked{}, err
	}

	return checked{outcome: outcome, challenge: challenge, audience: audience, scopes: scopes, at: now, challengeExpires: stored.ExpiresAt}, nil
}

// PopulateTokenEndpointResponse consumes the challenge, records the outcome consumed and issues the
// token. It runs only inside the transaction TokenHandler opened, which is committed after this
// returns and rolled back on any error, so either all three writes persist or none.
func (g *vpGrant) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) error {
	if !g.CanHandleTokenEndpointRequest(ctx, request) {
		return oauth2.ErrUnknownRequest
	}

	if !inTx(ctx) {
		return oauth2.ErrServerError.WithDebug("the verified-presentation grant ran outside a transaction")
	}

	// The binding is validated before any write: the token is DPoP-bound or not issued.
	if session, ok := request.GetSession().(oauth2.DPoPBoundSession); !ok || session.GetDPoPJWKThumbprint() == "" {
		return oauth2.ErrInvalidDPoPProof.WithHint("The verified-presentation grant issues DPoP-bound tokens only and requires a DPoP proof.")
	}

	// The challenge's row lock is taken first; every check is then made again at an instant taken
	// after it is held.
	v, err := g.check(ctx, request, true)
	if err != nil {
		return err
	}

	clientID := request.GetClient().GetID()
	stores := g.store.stores

	if err = stores.Challenges.ConsumeChallenge(ctx, v.challenge, clientID, v.audience, v.at); err != nil {
		if !errors.Is(err, oauth2provider.ErrConsumed) {
			return oauth2.ErrServerError.WithWrap(err)
		}

		// The binding was checked a moment ago, so the challenge was consumed meanwhile or expired.
		if current, getErr := stores.Challenges.GetChallenge(ctx, v.challenge); getErr == nil && current.ConsumedAt.IsZero() {
			return refuseCred(oauth2provider.CodeCredOutcomeExpired)
		}

		return refuseCred(oauth2provider.CodeCredOutcomeConsumed)
	}

	claims, err := json.Marshal(v.outcome.Claims)
	if err != nil {
		return oauth2.ErrServerError.WithWrap(err)
	}

	err = stores.Outcomes.ConsumeOutcome(ctx, oauth2provider.VerifiedOutcome{
		ID:             v.outcome.OutcomeID,
		Issuer:         v.outcome.Issuer,
		ClientID:       v.outcome.ClientID,
		Challenge:      v.outcome.Challenge,
		Audience:       v.outcome.Audience,
		Claims:         claims,
		CredentialRefs: v.outcome.CredentialRefs,
		VerifiedAt:     v.outcome.VerifiedAt,
		ExpiresAt:      v.outcome.ExpiresAt,
	}, v.at)
	if errors.Is(err, oauth2provider.ErrConsumed) {
		return refuseCred(oauth2provider.CodeCredOutcomeConsumed)
	}

	if err != nil {
		return oauth2.ErrServerError.WithWrap(err)
	}

	// The outcome insert may have waited on another transaction: validity is judged once more, now,
	// before anything is signed.
	if later := g.clock.now(); !later.Before(v.outcome.ExpiresAt) || !later.Before(v.challengeExpires) {
		return refuseCred(oauth2provider.CodeCredOutcomeExpired)
	}

	for _, scope := range v.scopes {
		request.GrantScope(scope)
	}

	request.GrantAudience(v.audience)

	if _, err = g.IssueAccessToken(withOutcomeID(ctx, v.outcome.OutcomeID), g.lifespan, request, response); err != nil {
		// A store or signer failure is a server error, not an unrecognised one.
		return oauth2.ErrorToRFC6749ErrorFallback(err, oauth2.ErrServerError)
	}

	return nil
}

// clientCredentials is the library's client_credentials grant, refusing every scope the
// verified-presentation grant issues, whatever the client is registered for.
type clientCredentials struct {
	*hoauth2.ClientCredentialsGrantHandler

	vpScopes map[string]bool
}

func (c *clientCredentials) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) error {
	if err := c.ClientCredentialsGrantHandler.HandleTokenEndpointRequest(ctx, request); err != nil {
		return err
	}

	return c.refuseVPScopes(request.GetRequestedScopes())
}

func (c *clientCredentials) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) error {
	if c.CanHandleTokenEndpointRequest(ctx, request) {
		if err := c.refuseVPScopes(append(slices.Clone(request.GetRequestedScopes()), request.GetGrantedScopes()...)); err != nil {
			return err
		}
	}

	return c.ClientCredentialsGrantHandler.PopulateTokenEndpointResponse(ctx, request, response)
}

func (c *clientCredentials) refuseVPScopes(scopes []string) error {
	for _, scope := range scopes {
		if c.vpScopes[scope] {
			return oauth2.ErrInvalidScope.WithHintf("The scope '%s' is issued only through the verified-presentation grant.", scope)
		}
	}

	return nil
}

// ChallengeHandler implements oauth2provider.Provider. The client authenticates as at the token
// endpoint and names one of its registered audiences; the answer is a single-use challenge bound to
// both, valid for oauth2provider.ChallengeLifetime.
func (p *provider) ChallengeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, outcome := withOutcome(r.Context())

		refuse := func(err error) {
			writeWithReason(w, classify(err, outcome), func(rw http.ResponseWriter) {
				p.lib.WriteAccessError(ctx, rw, nil, err)
			})
		}

		if p.vp == nil {
			refuse(oauth2.ErrInvalidRequest.WithHint("The verified-presentation grant is not enabled."))

			return
		}

		if r.Method != http.MethodPost {
			refuse(oauth2.ErrInvalidRequest.WithHint("The challenge endpoint accepts POST only."))

			return
		}

		if err := r.ParseForm(); err != nil || len(r.PostForm) == 0 {
			refuse(oauth2.ErrInvalidRequest.WithHint("The request body must be a form."))

			return
		}

		client, _, err := p.fosite.AuthenticateClient(ctx, r, r.PostForm)
		if err != nil {
			refuse(err)

			return
		}

		if client.IsPublic() {
			refuse(oauth2.ErrInvalidClient.WithHint("The verified-presentation grant requires a confidential client."))

			return
		}

		if !client.GetGrantTypes().Has(vpGrantType) {
			refuse(oauth2.ErrUnauthorizedClient.WithHint("The client is not allowed to use the verified-presentation grant."))

			return
		}

		audience, ok := single(r.PostForm, "audience")
		if !ok || strings.ContainsAny(audience, " \t") || !slices.Contains(client.GetAudience(), audience) {
			refuse(oauth2.ErrInvalidRequest.WithHint("Exactly one audience registered for this client is required."))

			return
		}

		raw := make([]byte, challengeBytes)
		if _, err = rand.Read(raw); err != nil {
			refuse(oauth2.ErrServerError)

			return
		}

		challenge := oauth2provider.Challenge{
			Value:     base64.RawURLEncoding.EncodeToString(raw),
			ClientID:  client.GetID(),
			Audience:  audience,
			ExpiresAt: p.clock.now().Add(oauth2provider.ChallengeLifetime),
		}

		if err = p.store.stores.Challenges.CreateChallenge(ctx, challenge); err != nil {
			refuse(oauth2.ErrServerError.WithWrap(err))

			return
		}

		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"challenge":  challenge.Value,
			"expires_in": int(oauth2provider.ChallengeLifetime / time.Second),
		})
	})
}

// single returns the one non-empty value of a form parameter.
func single(form url.Values, name string) (string, bool) {
	values := form[name]
	if len(values) != 1 || values[0] == "" {
		return "", false
	}

	return values[0], true
}

// delegatingAuth is the registration endpoint's authentication with the registrar delegation
// ceiling: a registration request authenticated by a registrar's token may grant the scopes that
// token carries and, in addition, the scopes RegistrationConfig.DelegableScopes names for that
// registrar. Only registration consults it; the registrar's token itself is unchanged, and the
// library still refuses the registration scope whatever the ceiling says.
type delegatingAuth struct {
	inner     oauth2.ClientRegistrationEndpointAuthStrategy
	delegable map[string][]string
}

func (d *delegatingAuth) AuthenticateClientRegistrationRequest(ctx context.Context, r *http.Request, id string) (oauth2.Requester, error) {
	requester, err := d.inner.AuthenticateClientRegistrationRequest(ctx, r, id)
	if err != nil || id != "" || requester == nil || requester.GetClient() == nil {
		return requester, err
	}

	extra := d.delegable[requester.GetClient().GetID()]
	authenticated, ok := requester.(*oauth2.Request)

	if len(extra) == 0 || !ok {
		return requester, nil
	}

	ceiling := *authenticated
	ceiling.GrantedScope = slices.Clone(authenticated.GrantedScope)

	for _, scope := range extra {
		if !slices.Contains(ceiling.GrantedScope, scope) {
			ceiling.GrantedScope = append(ceiling.GrantedScope, scope)
		}
	}

	return &ceiling, nil
}
