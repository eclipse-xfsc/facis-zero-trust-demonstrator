package acquire

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/keys"
)

// Key is the store's DPoP key: the zone's transit key, whose private half never leaves OpenBao.
// Every proof the store sends upstream is signed with it, and every upstream token is bound to its
// thumbprint (signing_key.jkt).
type Key struct {
	signer transit.Signer
	ref    transit.KeyVersion
	jwk    jose.JWK
	jkt    string
}

var _ dpopproof.Key = (*Key)(nil)

// LoadKey ensures the transit key name exists, takes its latest version and makes sure the
// signing_key row for it exists (created if missing, conflict-safe) with the version's thumbprint
// and state active.
func LoadKey(ctx context.Context, pool *pgxpool.Pool, signer transit.Signer, name string) (*Key, error) {
	ref, jkt, err := keys.Keys{Signer: signer, Name: name}.Ensure(ctx)
	if err != nil {
		return nil, err
	}
	pub, err := signer.PublicKey(ctx, ref)
	if err != nil {
		return nil, err
	}
	jwk := jose.PublicJWK(pub)
	if t, err := jwk.Thumbprint(); err != nil || t != jkt {
		return nil, errors.New("acquire: transit public key does not match its thumbprint")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO signing_key (key_ref, jkt, alg, state) VALUES ($1, $2, 'ES256', 'active')
		ON CONFLICT DO NOTHING`, ref.Ref(), jkt); err != nil {
		return nil, err
	}
	var stored, state string
	if err := pool.QueryRow(ctx, `SELECT jkt, state FROM signing_key WHERE key_ref = $1`, ref.Ref()).Scan(&stored, &state); err != nil {
		// No row: the thumbprint is recorded under another reference, which only tampering produces.
		return nil, errors.New("acquire: signing_key row for the store key is missing or conflicting")
	}
	if stored != jkt || state != "active" {
		return nil, errors.New("acquire: signing_key row does not match the store key or is retired")
	}
	return &Key{signer: signer, ref: ref, jwk: jwk, jkt: jkt}, nil
}

// KeyAt is the store key version ref names, for the tokens bound to it: its public key must have
// the thumbprint jkt recorded for ref in signing_key, or it is refused.
func KeyAt(ctx context.Context, signer transit.Signer, ref, jkt string) (*Key, error) {
	kv, err := transit.ParseRef(ref)
	if err != nil {
		return nil, err
	}
	pub, err := signer.PublicKey(ctx, kv)
	if err != nil {
		return nil, err
	}
	jwk := jose.PublicJWK(pub)
	if t, err := jwk.Thumbprint(); err != nil || t != jkt {
		return nil, errors.New("acquire: transit public key does not match its recorded thumbprint")
	}
	return &Key{signer: signer, ref: kv, jwk: jwk, jkt: jkt}, nil
}

// JWK is the public key, as the proof's jwk header carries it.
func (k *Key) JWK() jose.JWK { return k.jwk }

// Sign has transit sign the JWS signing input with the pinned version, under the caller's context.
func (k *Key) Sign(ctx context.Context, signingInput []byte) ([]byte, error) {
	return k.signer.Sign(ctx, k.ref, signingInput)
}

// Ref is signing_key.key_ref.
func (k *Key) Ref() string { return k.ref.Ref() }

// JKT is signing_key.jkt.
func (k *Key) JKT() string { return k.jkt }
