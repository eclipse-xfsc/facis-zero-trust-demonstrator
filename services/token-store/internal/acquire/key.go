package acquire

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

// Why LoadKey can refuse the configured key. Each is a misconfiguration the operator resolves,
// never something the service repairs on its own.
var (
	// ErrKeyRetired: the configured key has no version it may mint with: its registered version is
	// retired and nothing newer is registered, or the registered version is below transit's
	// signing floor. token-store keys rotate activates the next one.
	ErrKeyRetired = errors.New("acquire: the store key has no usable registered version; token-store keys rotate activates the next one")
	// ErrMalformedRef: an active signing_key row whose key_ref is not of the form transit:<name>:v<n>.
	ErrMalformedRef = errors.New("acquire: malformed key reference in signing_key")
	// ErrKeyConflict: the registered rows contradict transit: the latest version's thumbprint is
	// registered under another reference, which only tampering or a wrong database produces.
	ErrKeyConflict = errors.New("acquire: signing_key rows conflict with the transit key")
	// errNoActive: no active row is registered for the key name.
	errNoActive = errors.New("acquire: no active signing_key row")
)

// Reason names why a key could not be resolved, in the fixed vocabulary the startup records and
// the operator commands use, and says whether the cause is a misconfiguration (permanent: an
// operator must act) or an outage (retried). Nothing a dependency said enters the word.
func Reason(err error) (reason string, permanent bool) {
	var status *transit.StatusError
	var pgErr *pgconn.PgError
	switch {
	case errors.Is(err, keys.ErrMismatch), errors.Is(err, ErrKeyConflict):
		return ReasonMismatch, true
	case errors.Is(err, ErrMalformedRef):
		return ReasonMalformed, true
	case errors.Is(err, ErrKeyRetired):
		return ReasonRetired, true
	case errors.Is(err, transit.ErrUnsupportedKey):
		return ReasonUnsupported, true
	case errors.Is(err, transit.ErrNotFound):
		return ReasonMissing, true
	case errors.Is(err, transit.ErrTokenSource):
		return ReasonToken, false
	case errors.As(err, &status) && status.Status >= 400 && status.Status < 500 &&
		status.Status != http.StatusRequestTimeout && status.Status != http.StatusTooManyRequests:
		return ReasonRefused, true
	case errors.As(err, &pgErr):
		return ReasonDatabase, false
	}
	return ReasonUnreachable, false
}

// The reason words. The first six are misconfigurations; the last three are outages.
const (
	ReasonMissing     = "missing"     // a registered version transit does not have, or no key at the configured name
	ReasonMismatch    = "mismatch"    // a registered thumbprint is not the version's public key, or rows conflict
	ReasonMalformed   = "malformed"   // an active key_ref that is not transit:<name>:v<n>
	ReasonRetired     = "retired"     // no usable version: retired, or below transit's signing floor
	ReasonUnsupported = "unsupported" // the key is not a non-exportable ecdsa-p256 key
	ReasonRefused     = "refused"     // transit refused the request (4xx): the token's policy
	ReasonToken       = "token"       // the OpenBao token could not be read: the token file
	ReasonDatabase    = "database"    // PostgreSQL answered with an error (the schema not applied yet, for one)
	ReasonUnreachable = "unreachable" // a dependency did not answer
)

// KeySigner is what the store's key resolution needs of transit: signing, and the key's status
// (its latest version and signing floor). The service's signer (keys.ReadOnly over the key-value
// store) and the operator's (*transit.Client) both are one, so the floor is never left unchecked by
// a type that happens to sign.
type KeySigner interface {
	transit.Signer
	KeyStatus(ctx context.Context, name string) (latest transit.KeyVersion, floor int, err error)
}

// ErrKeyUnregistered: the key has no row yet. LoadKey registers it; ResolveKey only reports it.
var ErrKeyUnregistered = errors.New("acquire: the store key has no registered version yet")

// ResolveKey is the store's key as the database decides it, read without writing: the one active
// signing_key row of the key name, whose version must exist in transit with the row's thumbprint
// and must not be below transit's signing floor. Transit's latest version is advisory until
// token-store keys rotate registers it; a version rotated in transit alone changes nothing here.
// It refuses a registered version that is retired or below the floor (ErrKeyRetired: rows exist
// and none is usable, which only a rotation repairs), a thumbprint that does not match the public
// key (keys.ErrMismatch), a malformed reference (ErrMalformedRef), more than one active row or a
// latest-version thumbprint registered under another reference (ErrKeyConflict). A key with no row
// at all, and nothing contradicting it, is ErrKeyUnregistered. Readiness reads the key through
// this, so a store that is Ready can mint.
func ResolveKey(ctx context.Context, pool *pgxpool.Pool, signer KeySigner, name string) (*Key, error) {
	k, err := loadActive(ctx, pool, signer, name)
	if err == nil {
		return aboveFloor(ctx, signer, k)
	}
	if !errors.Is(err, errNoActive) {
		return nil, err
	}
	var registered int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM signing_key WHERE split_part(key_ref, ':', 2) = $1`, name).Scan(&registered); err != nil {
		return nil, err
	}
	if registered > 0 {
		// Rows exist and none is active: every version was retired. Only a rotation moves on.
		return nil, ErrKeyRetired
	}
	latest, _, err := signer.KeyStatus(ctx, name)
	if errors.Is(err, transit.ErrNotFound) {
		// Nothing registered and no key in transit: unregistered for LoadKey, which may create
		// the key, and missing for a reader that may not.
		return nil, fmt.Errorf("%w: %w", ErrKeyUnregistered, err)
	}
	if err != nil {
		return nil, err
	}
	pub, err := signer.PublicKey(ctx, latest)
	if err != nil {
		return nil, err
	}
	jkt, err := keys.Thumbprint(pub)
	if err != nil {
		return nil, err
	}
	var conflicting int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM signing_key WHERE jkt = $1 AND key_ref <> $2`, jkt, latest.Ref()).Scan(&conflicting); err != nil {
		return nil, err
	}
	if conflicting > 0 {
		return nil, fmt.Errorf("%w: the latest version's thumbprint is registered under another reference", ErrKeyConflict)
	}
	return nil, ErrKeyUnregistered
}

// LoadKey is ResolveKey for a path that may register: a key with no row at all is registered at
// its latest version with its thumbprint, created by the signer if it may (a read-only signer
// reports a missing key). The registration runs under the key's rotation lock, so a rotation
// either reads it or waits for it and never mistakes it for a conflict; two replicas racing for
// it leave one row, which both then read.
func LoadKey(ctx context.Context, pool *pgxpool.Pool, signer KeySigner, name string) (*Key, error) {
	k, err := ResolveKey(ctx, pool, signer, name)
	if !errors.Is(err, ErrKeyUnregistered) {
		return k, err
	}
	ref, jkt, err := keys.Keys{Signer: signer, Name: name}.Ensure(ctx)
	if err != nil {
		return nil, err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx)
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $2, true), pg_advisory_xact_lock(hashtextextended('signing-key:' || $1::text, 0))`,
		name, ms(statementTimeout)); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO signing_key (key_ref, jkt, alg, state) VALUES ($1, $2, 'ES256', 'active')
		ON CONFLICT DO NOTHING`, ref.Ref(), jkt); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	k, err = ResolveKey(ctx, pool, signer, name)
	if errors.Is(err, ErrKeyUnregistered) {
		return nil, fmt.Errorf("%w: the registration left no readable row", ErrKeyConflict)
	}
	return k, err
}

// aboveFloor refuses a registered version transit would refuse to sign with.
func aboveFloor(ctx context.Context, signer KeySigner, k *Key) (*Key, error) {
	_, floor, err := signer.KeyStatus(ctx, k.ref.Name)
	if err != nil {
		return nil, err
	}
	if k.ref.Version < floor {
		return nil, fmt.Errorf("%w: version %d is below transit's signing floor %d", ErrKeyRetired, k.ref.Version, floor)
	}
	return k, nil
}

// loadActive reads the active row of the key name and resolves it through transit. More than one
// active row (a database migration 5 has not reached) is a conflict, never an arbitrary pick.
func loadActive(ctx context.Context, pool *pgxpool.Pool, signer transit.Signer, name string) (*Key, error) {
	rows, err := pool.Query(ctx, `SELECT key_ref, jkt FROM signing_key WHERE state = 'active' AND split_part(key_ref, ':', 2) = $1`, name)
	if err != nil {
		return nil, err
	}
	type row struct{ ref, jkt string }
	active, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		err := r.Scan(&x.ref, &x.jkt)
		return x, err
	})
	if err != nil {
		return nil, err
	}
	switch len(active) {
	case 0:
		return nil, errNoActive
	case 1:
	default:
		return nil, fmt.Errorf("%w: %d active versions registered; apply migration 5 or run token-store keys rotate", ErrKeyConflict, len(active))
	}
	ref, jkt := active[0].ref, active[0].jkt
	kv, err := transit.ParseRef(ref)
	if err != nil || kv.Name != name {
		return nil, ErrMalformedRef
	}
	pub, err := signer.PublicKey(ctx, kv)
	if err != nil {
		return nil, err
	}
	jwk := jose.PublicJWK(pub)
	if t, err := jwk.Thumbprint(); err != nil || t != jkt {
		return nil, fmt.Errorf("acquire: transit public key does not match the registered thumbprint: %w", keys.ErrMismatch)
	}
	return &Key{signer: signer, ref: kv, jwk: jwk, jkt: jkt}, nil
}

// KeyAt is the store key version ref names, for the tokens bound to it: its public key must have
// the thumbprint jkt recorded for ref in signing_key, or it is refused. It reads no state: the
// caller has selected the row as active (substitution's lookup joins on it) in the statement that
// chose the token.
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
