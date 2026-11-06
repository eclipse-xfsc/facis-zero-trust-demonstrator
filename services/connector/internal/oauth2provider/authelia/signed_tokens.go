package authelia

import (
	"context"
	"crypto/elliptic"
	"errors"
	"fmt"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/token/jose"
	"authelia.com/provider/oauth2/token/jwt"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

const (
	signedTokenAlg = string(jose.ES256)
	signedTokenUse = jwt.JSONWebTokenUseSignature
	signedTokenTyp = jwt.JSONWebTokenTypeAccessToken
	signatureSize  = 64
)

// signedStrategy issues RFC 9068 access tokens through the library's JWT profile strategy. Every
// other token kind, registration access tokens included, stays with the HMAC strategy it embeds.
//
// Issuance and validation are pinned here rather than left to the library's per-client choices: the
// library would otherwise sign or encrypt with whatever algorithm a registered client's metadata
// names, including its secret for the HS algorithms. Here the client never selects a key or an
// algorithm.
type signedStrategy struct {
	*hoauth2.JWTProfileCoreStrategy

	issuer string
	kid    string
}

func newSignedStrategy(config *oauth2.Config, hmac *hoauth2.HMACCoreStrategy, signer oauth2provider.TokenSigner) *signedStrategy {
	return &signedStrategy{
		JWTProfileCoreStrategy: &hoauth2.JWTProfileCoreStrategy{
			Strategy:         &jwt.DefaultStrategy{Config: config, Issuer: &signerIssuer{signer: signer}},
			HMACCoreStrategy: hmac,
			Config:           config,
		},
		issuer: config.AccessTokenIssuer,
		kid:    signer.KeyID(),
	}
}

// GenerateAccessToken signs every access token, whatever the client. sub is the client id: no end
// user is involved in either grant (RFC 9068 section 2.2). The header and claims are started afresh
// so nothing a session carried before reaches the token.
func (s *signedStrategy) GenerateAccessToken(ctx context.Context, request oauth2.Requester) (string, string, error) {
	session, ok := request.GetSession().(*hoauth2.JWTSession)
	if !ok {
		return "", "", fmt.Errorf("signed access tokens need a JWT session, got %T", request.GetSession())
	}

	// A signed token is validated without the connector, from its own claims, so every token
	// carries cnf.jkt (D6) and aud (RFC 9068 section 2.2). Without DPoP enforcement an unbound
	// client may reach this point without a proof; it is refused rather than given a bearer token.
	if session.GetDPoPJWKThumbprint() == "" {
		return "", "", oauth2.ErrInvalidDPoPProof.WithHint("Signed access tokens are issued only with a DPoP proof.")
	}

	if len(request.GetGrantedAudience()) == 0 {
		return "", "", oauth2.ErrInvalidRequest.WithHint("Signed access tokens are issued only for a requested audience.")
	}

	subject := request.GetClient().GetID()
	session.Subject = subject
	session.JWTClaims = &jwt.JWTClaims{Subject: subject}
	session.JWTHeader = &jwt.Headers{Extra: map[string]any{jwt.JSONWebTokenHeaderType: signedTokenTyp}}

	return s.GenerateJWT(ctx, oauth2.AccessToken, request, nil)
}

// ValidateAccessToken checks a signed token against the issuer key only, never a key or algorithm
// the client's metadata names, and requires the header and the iss and exp claims this adapter
// writes. An opaque token is left to the HMAC strategy, so tokens issued before signing was switched
// on stay valid until they expire.
func (s *signedStrategy) ValidateAccessToken(ctx context.Context, request oauth2.Requester, tokenString string) error {
	if possible, _ := s.IsPossiblyJWTProfileAccessToken(ctx, tokenString); !possible {
		return s.HMACCoreStrategy.ValidateAccessToken(ctx, request, tokenString)
	}

	token, err := s.Decode(ctx, tokenString)
	if err != nil {
		return oauth2.ErrTokenSignatureMismatch.WithWrap(err).WithDebug(err.Error())
	}

	if err = token.Valid(jwt.ValidateTypes(signedTokenTyp), jwt.ValidateAlgorithm(signedTokenAlg), jwt.ValidateKeyID(s.kid)); err != nil {
		return oauth2.ErrInvalidTokenFormat.WithWrap(err).WithDebug(err.Error())
	}

	if err = token.Claims.Valid(jwt.ValidateRequireExpiresAt(), jwt.ValidateIssuer(s.issuer)); err != nil {
		return oauth2.ErrTokenExpired.WithWrap(err).WithDebug(err.Error())
	}

	return nil
}

// signerIssuer is the library's view of the configured signer.
type signerIssuer struct {
	signer oauth2provider.TokenSigner
}

// GetIssuerJWK returns the signing key for one call, bound to that call's context, so the signer
// sees the request's context without anything shared being changed.
//
// Without a client the library asks for an RS256 key; the alg it names is not honoured, since the
// only key there is is ES256 and the key's own Algorithm decides what the token's header says.
func (i *signerIssuer) GetIssuerJWK(ctx context.Context, kid, _, use string) (*jose.JSONWebKey, error) {
	if (kid != "" && kid != i.signer.KeyID()) || (use != "" && use != signedTokenUse) {
		return nil, fmt.Errorf("no issuer key with kid %q and use %q", kid, use)
	}

	return &jose.JSONWebKey{
		Key:       &requestSigner{ctx: ctx, signer: i.signer},
		KeyID:     i.signer.KeyID(),
		Algorithm: signedTokenAlg,
		Use:       signedTokenUse,
	}, nil
}

// GetIssuerStrictJWK returns the public key to verify with, only for exactly the issuer's kid, alg
// and use.
func (i *signerIssuer) GetIssuerStrictJWK(_ context.Context, kid, alg, use string) (*jose.JSONWebKey, error) {
	if kid != i.signer.KeyID() || alg != signedTokenAlg || use != signedTokenUse {
		return nil, fmt.Errorf("no issuer key with kid %q, alg %q and use %q", kid, alg, use)
	}

	return publicJWK(i.signer), nil
}

// requestSigner is the library's jose.OpaqueSigner over the configured signer for one request.
type requestSigner struct {
	ctx    context.Context //nolint:containedctx // the library's signing interface takes no context
	signer oauth2provider.TokenSigner
}

var _ jose.OpaqueSigner = (*requestSigner)(nil)

func (r *requestSigner) Public() *jose.JSONWebKey { return publicJWK(r.signer) }

func (r *requestSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.ES256}
}

func (r *requestSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	if alg != jose.ES256 {
		return nil, fmt.Errorf("signer supports ES256 only, asked for %s", alg)
	}

	signature, err := r.signer.Sign(r.ctx, payload)
	if err != nil {
		return nil, err
	}

	if len(signature) != signatureSize {
		return nil, fmt.Errorf("signer returned %d bytes, want %d", len(signature), signatureSize)
	}

	return signature, nil
}

func publicJWK(signer oauth2provider.TokenSigner) *jose.JSONWebKey {
	return &jose.JSONWebKey{Key: signer.Public(), KeyID: signer.KeyID(), Algorithm: signedTokenAlg, Use: signedTokenUse}
}

// checkSigner refuses a signer that cannot produce the tokens this adapter promises.
func checkSigner(signer oauth2provider.TokenSigner) error {
	if signer.KeyID() == "" {
		return errors.New("oauth2provider: Config.AccessTokenSigner has an empty KeyID")
	}

	if pub := signer.Public(); pub == nil || pub.Curve != elliptic.P256() {
		return errors.New("oauth2provider: Config.AccessTokenSigner must hold an ECDSA P-256 key")
	}

	return nil
}
