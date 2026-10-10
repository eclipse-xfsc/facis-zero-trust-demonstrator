package authelia

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/rfc7591"
	"authelia.com/provider/oauth2/handler/rfc9449"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

// storeAdapter presents the connector's stores as the storage the library
// expects.
type storeAdapter struct {
	stores   oauth2provider.Stores
	strategy oauth2.ClientRegistrationStrategy
	config   *oauth2.Config
}

var (
	_ oauth2.ClientManager       = (*storeAdapter)(nil)
	_ hoauth2.AccessTokenStorage = (*storeAdapter)(nil)
	_ rfc7591.Storage            = (*storeAdapter)(nil)
	_ rfc9449.Storage            = (*storeAdapter)(nil)
)

func (s *storeAdapter) GetClient(ctx context.Context, id string) (oauth2.Client, error) {
	client, err := s.stores.Clients.GetClient(ctx, id)
	if err != nil {
		return nil, notFound(err)
	}

	return toLibraryClient(ctx, s.strategy, client)
}

func (s *storeAdapter) CreateClient(ctx context.Context, client oauth2.Client) error {
	record, err := fromLibraryClient(ctx, s.strategy, client, nil)
	if err != nil {
		return err
	}

	return s.stores.Clients.CreateClient(ctx, record)
}

func (s *storeAdapter) UpdateClient(ctx context.Context, id string, client oauth2.Client) error {
	existing, err := s.stores.Clients.GetClient(ctx, id)
	if err != nil {
		return notFound(err)
	}

	record, err := fromLibraryClient(ctx, s.strategy, client, &existing)
	if err != nil {
		return err
	}

	if record.ID != id {
		return fmt.Errorf("client id %q cannot be changed to %q", id, record.ID)
	}

	return notFound(s.stores.Clients.UpdateClient(ctx, record))
}

func (s *storeAdapter) DeleteClient(ctx context.Context, id string) error {
	return notFound(s.stores.Clients.DeleteClient(ctx, id))
}

// Client authentication by signed assertion is not offered, so there is no
// assertion replay state to keep. Refusing here fails closed should such a
// method ever be enabled without this being implemented.
func (s *storeAdapter) ClientAssertionJWTValid(context.Context, string) error {
	return errors.New("client assertion authentication is not supported")
}

func (s *storeAdapter) SetClientAssertionJWT(context.Context, string, time.Time) error {
	return errors.New("client assertion authentication is not supported")
}

func (s *storeAdapter) CreateAccessTokenSession(ctx context.Context, signature string, request oauth2.Requester) error {
	return createToken(ctx, s.stores.AccessTokens, signature, request)
}

func (s *storeAdapter) GetAccessTokenSession(ctx context.Context, signature string, session oauth2.Session) (oauth2.Requester, error) {
	return s.getToken(ctx, s.stores.AccessTokens, signature, session)
}

func (s *storeAdapter) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.stores.AccessTokens.DeleteToken(ctx, signature)
}

func (s *storeAdapter) CreateClientRegistrationTokenSession(ctx context.Context, signature string, request oauth2.Requester) error {
	return createToken(ctx, s.stores.RegistrationTokens, signature, request)
}

func (s *storeAdapter) GetClientRegistrationTokenSession(ctx context.Context, signature string, session oauth2.Session) (oauth2.Requester, error) {
	return s.getToken(ctx, s.stores.RegistrationTokens, signature, session)
}

func (s *storeAdapter) DeleteClientRegistrationTokenSession(ctx context.Context, signature string) error {
	return s.stores.RegistrationTokens.DeleteToken(ctx, signature)
}

// createToken persists what is needed to validate the token later. The
// request form is deliberately left out: it can carry client credentials.
func createToken(ctx context.Context, store oauth2provider.TokenStore, signature string, request oauth2.Requester) error {
	session, err := json.Marshal(request.GetSession())
	if err != nil {
		return fmt.Errorf("encode session: %w", err)
	}

	return store.CreateToken(ctx, signature, oauth2provider.TokenRecord{
		RequestID:         request.GetID(),
		ClientID:          request.GetClient().GetID(),
		RequestedAt:       request.GetRequestedAt(),
		RequestedScopes:   request.GetRequestedScopes(),
		GrantedScopes:     request.GetGrantedScopes(),
		RequestedAudience: request.GetRequestedAudience(),
		GrantedAudience:   request.GetGrantedAudience(),
		Session:           session,
	})
}

func (s *storeAdapter) getToken(ctx context.Context, store oauth2provider.TokenStore, signature string, session oauth2.Session) (oauth2.Requester, error) {
	record, err := store.GetToken(ctx, signature)
	if err != nil {
		return nil, notFound(err)
	}

	client, err := s.GetClient(ctx, record.ClientID)
	if err != nil {
		return nil, err
	}

	if session != nil {
		if err = json.Unmarshal(record.Session, session); err != nil {
			return nil, fmt.Errorf("decode session: %w", err)
		}
	}

	return &oauth2.Request{
		ID:                record.RequestID,
		RequestedAt:       record.RequestedAt,
		Client:            client,
		RequestedScope:    record.RequestedScopes,
		GrantedScope:      record.GrantedScopes,
		RequestedAudience: record.RequestedAudience,
		GrantedAudience:   record.GrantedAudience,
		Session:           session,
	}, nil
}

// CheckAndSetDPoPProofUsed hands the proof's identity to the replay store,
// which performs the atomic check.
//
// The library passes the instant the proof stops being acceptable, which it
// computes as iat + proof lifespan + clock skew, and not the iat itself. The
// iat is recovered here from the same two settings, so a store that applies
// a window of its own has the claim to work from. A conformance test pins
// the derivation.
func (s *storeAdapter) CheckAndSetDPoPProofUsed(ctx context.Context, jti, jkt, nonce, htm, htu string, exp time.Time) (bool, error) {
	window := s.config.GetDPoPProofLifespan(ctx) + s.config.GetDPoPClockSkew(ctx)

	used, err := s.stores.DPoPReplay.MarkUsed(ctx, oauth2provider.DPoPProofUse{
		Thumbprint: jkt,
		Method:     htm,
		URI:        htu,
		ID:         jti,
		Nonce:      nonce,
		IssuedAt:   exp.Add(-window),
		NotAfter:   exp,
	})
	if err == nil && used {
		noteReplay(ctx)
	}

	return used, err
}

func (s *storeAdapter) CreateDPoPNonce(ctx context.Context, nonce string, exp time.Time) error {
	return s.stores.DPoPNonces.CreateNonce(ctx, nonce, exp)
}

func (s *storeAdapter) IsDPoPNonceValid(ctx context.Context, nonce string) (bool, error) {
	return s.stores.DPoPNonces.IsNonceValid(ctx, nonce)
}

func notFound(err error) error {
	if errors.Is(err, oauth2provider.ErrNotFound) {
		return oauth2.ErrNotFound
	}

	return err
}
