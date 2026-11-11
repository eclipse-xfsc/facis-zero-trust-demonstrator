package acquire

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/keys"
)

// Rotator is transit as an operator holds it: a Signer that may also read a key's status, rotate it
// and raise its signing floor. The service never holds one; token-store keys rotate does. It cannot
// create a key: creation is keys ensure's, so a misspelled name is refused here, never provisioned.
type Rotator interface {
	transit.Signer
	KeyStatus(ctx context.Context, name string) (latest transit.KeyVersion, floor int, err error)
	Rotate(ctx context.Context, name string) (transit.KeyVersion, error)
	SetMinSigningVersion(ctx context.Context, name string, v int) error
}

// Rotation is what one rotation did: the reference now active, the references retired by it, the
// tokens those references had minted, and the floor transit signs above from now on. Adopted says
// transit was already ahead of everything registered (a version rotated outside the store, or a
// rotation whose transaction did not commit), so no new version was created.
type Rotation struct {
	Key                   string   `json:"key"`
	Active                string   `json:"active"`
	JKT                   string   `json:"jkt"`
	Retired               []string `json:"retired"`
	UpstreamTokensRetired int      `json:"upstream_tokens_retired"`
	MinSigningVersion     int      `json:"min_signing_version"`
	Adopted               bool     `json:"adopted"`
}

// Rotation's transaction holds the key's rows across its transit calls; these bound it on the
// server, as stage's bound the activation, so a client that vanishes mid-way cannot keep the key
// locked (and every activation failing) for longer than this.
const (
	rotateStatementTimeout = 10 * time.Second
	rotateIdleTimeout      = 30 * time.Second
)

// Rotate moves the store to the next version of its key, inside one database transaction under
// the key's rotation lock, in this order: the key's registered rows are read; the next version
// exists in transit (adopted when transit is already ahead of every well-formed registered version,
// active or retired, else created by rotation, which is also how the store moves past versions an
// operator retired by hand); every other active row of the key is retired and the next version
// registered with its thumbprint; every live upstream token bound to another version of the key is
// retired, so none is substituted or renewed under a key that can no longer sign; the transaction
// commits; then transit's signing floor is raised to the next version (it only ever rises). A
// failure before the commit leaves the database as it was, and transit at most a version ahead,
// which the next Rotate adopts; a failure after it leaves the previous version signable in transit
// only, which the database already refuses, until the next Rotate raises the floor past it (the
// floor only rises, so every rotation also settles what an earlier one left). Two rotations at
// once queue on the lock and
// each sees the other's result. With nothing registered yet, Rotate registers the latest version
// and retires nothing; a key transit does not have is refused (token-store keys ensure creates it).
func Rotate(ctx context.Context, pool *pgxpool.Pool, tc Rotator, name string) (Rotation, error) {
	if err := transit.ValidName(name); err != nil {
		return Rotation{}, err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return Rotation{}, err
	}
	defer rollback(ctx, tx)
	// One rotation of a key at a time. An activation holding the key's row FOR SHARE finishes
	// first, and its token is retired below with the version; a second rotation waits here and
	// then reads the rows this one leaves.
	if _, err := tx.Exec(ctx, `SELECT set_config('statement_timeout', $2, true), set_config('lock_timeout', $2, true),
		set_config('idle_in_transaction_session_timeout', $3, true),
		pg_advisory_xact_lock(hashtextextended('signing-key:' || $1::text, 0))`,
		name, ms(rotateStatementTimeout), ms(rotateIdleTimeout)); err != nil {
		return Rotation{}, err
	}
	rows, err := tx.Query(ctx, `SELECT key_ref, state FROM signing_key WHERE split_part(key_ref, ':', 2) = $1`, name)
	if err != nil {
		return Rotation{}, err
	}
	type registered struct{ ref, state string }
	regs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (registered, error) {
		var x registered
		err := r.Scan(&x.ref, &x.state)
		return x, err
	})
	if err != nil {
		return Rotation{}, err
	}
	highest := 0 // the highest well-formed registered version, active or retired
	for _, r := range regs {
		kv, err := transit.ParseRef(r.ref)
		if err != nil || kv.Name != name {
			if r.state == "active" {
				return Rotation{}, ErrMalformedRef
			}
			continue // a retired row nobody reads any more; not this rotation's concern
		}
		highest = max(highest, kv.Version)
	}
	latest, _, err := tc.KeyStatus(ctx, name)
	if errors.Is(err, transit.ErrNotFound) {
		return Rotation{}, fmt.Errorf("rotate: the key is not in transit; token-store keys ensure creates it: %w", err)
	}
	if err != nil {
		return Rotation{}, err
	}
	next, adopted := latest, true
	if latest.Version <= highest {
		// Every version transit has is registered, active or retired: the next one is new.
		if next, err = tc.Rotate(ctx, name); err != nil {
			return Rotation{}, err
		}
		adopted = false
	}
	pub, err := tc.PublicKey(ctx, next)
	if err != nil {
		return Rotation{}, err
	}
	jkt, err := keys.Thumbprint(pub)
	if err != nil {
		return Rotation{}, err
	}
	rows, err = tx.Query(ctx, `UPDATE signing_key SET state = 'retired', retired_at = now()
		WHERE split_part(key_ref, ':', 2) = $1 AND state = 'active' AND key_ref <> $2 RETURNING key_ref`, name, next.Ref())
	if err != nil {
		return Rotation{}, err
	}
	retired, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return Rotation{}, err
	}
	// Without a conflict target, so a thumbprint already registered under another reference
	// (signing_key.jkt is unique) is absorbed here and found by the read below, not raised raw.
	if _, err := tx.Exec(ctx, `INSERT INTO signing_key (key_ref, jkt, alg, state) VALUES ($1, $2, 'ES256', 'active')
		ON CONFLICT DO NOTHING`, next.Ref(), jkt); err != nil {
		return Rotation{}, err
	}
	var stored, state string
	switch err := tx.QueryRow(ctx, `SELECT jkt, state FROM signing_key WHERE key_ref = $1`, next.Ref()).Scan(&stored, &state); {
	case errors.Is(err, pgx.ErrNoRows):
		return Rotation{}, fmt.Errorf("rotate: the next version's thumbprint is registered under another reference: %w", ErrKeyConflict)
	case err != nil:
		return Rotation{}, err
	case state != "active" || stored != jkt:
		return Rotation{}, fmt.Errorf("rotate: the next version's row is %s with another thumbprint: %w", state, ErrKeyConflict)
	}
	// Every token bound to a version that is not the next one, whether retired now or earlier by
	// hand, is retired with it: substitution would not read it and re-acquisition would be blocked
	// by it (one live row per route) until it expired.
	tag, err := tx.Exec(ctx, `UPDATE upstream_token SET state = 'retired', updated_at = now()
		WHERE split_part(key_ref, ':', 2) = $1 AND key_ref <> $2 AND state IN ('active', 'renewing')`, name, next.Ref())
	if err != nil {
		return Rotation{}, err
	}
	tokens := int(tag.RowsAffected())
	if retired == nil {
		retired = []string{}
	}
	out := Rotation{Key: name, Active: next.Ref(), JKT: jkt, Retired: retired, UpstreamTokensRetired: tokens,
		MinSigningVersion: next.Version, Adopted: adopted}
	detail, _ := json.Marshal(out)
	if _, err := tx.Exec(ctx, `INSERT INTO audit_event (kind, detail) VALUES ('key.rotated', $1)`, detail); err != nil {
		return Rotation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Rotation{}, err
	}
	// The floor last, after the commit: from here on transit refuses the retired versions too. A
	// failure here leaves them signable in transit only; the database already refuses them, and
	// the next rotation's floor raise covers them as well.
	if err := tc.SetMinSigningVersion(ctx, name, next.Version); err != nil {
		return Rotation{}, fmt.Errorf("rotate: %s is registered and active, but transit's signing floor was not raised; the next token-store keys rotate raises it: %w", next.Ref(), err)
	}
	return out, nil
}

// KeyRow is one signing_key row, as keys status prints it: never material.
type KeyRow struct {
	KeyRef    string  `json:"key_ref"`
	JKT       string  `json:"jkt"`
	State     string  `json:"state"`
	CreatedAt string  `json:"created_at"`
	RetiredAt *string `json:"retired_at,omitempty"`
}

// KeyRows lists the registered versions of the key, newest first.
func KeyRows(ctx context.Context, pool *pgxpool.Pool, name string) ([]KeyRow, error) {
	rows, err := pool.Query(ctx, `SELECT key_ref, jkt, state, created_at::text, retired_at::text FROM signing_key
		WHERE split_part(key_ref, ':', 2) = $1 ORDER BY created_at DESC, key_ref DESC`, name)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[KeyRow])
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []KeyRow{}
	}
	return out, nil
}
