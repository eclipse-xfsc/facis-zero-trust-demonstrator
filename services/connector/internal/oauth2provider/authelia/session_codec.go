package authelia

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"authelia.com/provider/oauth2"
)

// sessionVersion is the version of storedSession. A record of any other version is refused rather
// than read as if it were this one.
const sessionVersion = 1

// storedSession is what a token record keeps of the library's session: the adapter's own encoding,
// independent of how the library's session types happen to serialise. The library hands the store
// different session types for one token (the token endpoint a DefaultSession, signed-token paths a
// JWTSession), and their JSON forms differ, so reading one type's JSON into the other would drop the
// key binding without an error. Every field is set and read through the library's interfaces.
type storedSession struct {
	V       int                            `json:"v"`
	Expires map[oauth2.TokenType]time.Time `json:"exp"`
	Subject string                         `json:"sub,omitempty"`
	JKT     string                         `json:"jkt,omitempty"`
	X5T     string                         `json:"x5t,omitempty"`

	// OutcomeID is the IF-03 outcome a verified-presentation token was issued on. It is a record of
	// provenance; nothing is restored from it.
	OutcomeID string `json:"outcome_id,omitempty"`
}

// subjectSession is implemented by both of the library's session types.
type subjectSession interface {
	SetSubject(string)
}

// certBoundSession is implemented by both of the library's session types.
type certBoundSession interface {
	GetClientCertificateSHA256Thumbprint() string
	SetClientCertificateSHA256Thumbprint(string)
}

// encodeSession returns the stored form of session and the access token's expiry.
func encodeSession(session oauth2.Session, outcomeID string) ([]byte, time.Time, error) {
	if session == nil {
		return nil, time.Time{}, errors.New("no session to store")
	}

	exp := session.GetExpiresAt(oauth2.AccessToken)
	if exp.IsZero() {
		return nil, time.Time{}, errors.New("session carries no access token expiry")
	}

	stored := storedSession{
		V:       sessionVersion,
		Expires: map[oauth2.TokenType]time.Time{oauth2.AccessToken: exp.UTC()},
		Subject: session.GetSubject(),

		OutcomeID: outcomeID,
	}

	if bound, ok := session.(oauth2.DPoPBoundSession); ok {
		stored.JKT = bound.GetDPoPJWKThumbprint()
	}

	if bound, ok := session.(certBoundSession); ok {
		stored.X5T = bound.GetClientCertificateSHA256Thumbprint()
	}

	raw, err := json.Marshal(stored)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("encode session: %w", err)
	}

	return raw, exp, nil
}

// decodeSession restores a stored session into the session the library supplied. A binding that the
// supplied session cannot carry is an error: a bound token must never come back looking unbound.
func decodeSession(raw []byte, session oauth2.Session) error {
	var stored storedSession
	if err := json.Unmarshal(raw, &stored); err != nil {
		return fmt.Errorf("decode session: %w", err)
	}

	if stored.V != sessionVersion {
		return fmt.Errorf("decode session: unsupported version %d", stored.V)
	}

	// Without a stored expiry the library would fall back to the request time plus the lifespan
	// configured now, which may be longer than the one the token was issued under.
	if stored.Expires[oauth2.AccessToken].IsZero() {
		return errors.New("decode session: no access token expiry")
	}

	for kind, exp := range stored.Expires {
		session.SetExpiresAt(kind, exp)
	}

	if stored.Subject != "" {
		s, ok := session.(subjectSession)
		if !ok {
			return fmt.Errorf("decode session: %T cannot carry a subject", session)
		}

		s.SetSubject(stored.Subject)
	}

	if stored.JKT != "" {
		s, ok := session.(oauth2.DPoPBoundSession)
		if !ok {
			return fmt.Errorf("decode session: %T cannot carry a DPoP binding", session)
		}

		s.SetDPoPJWKThumbprint(stored.JKT)
	}

	if stored.X5T != "" {
		s, ok := session.(certBoundSession)
		if !ok {
			return fmt.Errorf("decode session: %T cannot carry a certificate binding", session)
		}

		s.SetClientCertificateSHA256Thumbprint(stored.X5T)
	}

	return nil
}
