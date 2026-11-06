package replay

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres is the Store on the zone's proof_jti table, shared by the Connector and the token store.
type Postgres struct{ pool *pgxpool.Pool }

var _ Store = (*Postgres)(nil)

// NewPostgres returns the Store on pool.
func NewPostgres(pool *pgxpool.Pool) *Postgres { return &Postgres{pool: pool} }

// TryUse inserts the use; a conflict on the key is a replay. An expired record that was not swept
// yet still counts as seen: a proof past its window is refused by its own time check anyway.
func (p *Postgres) TryUse(ctx context.Context, use Use) (bool, error) {
	if use.JKT == "" || use.Method == "" || use.URI == "" || use.JTI == "" || use.NotAfter.IsZero() {
		return false, fmt.Errorf("replay: incomplete use")
	}
	tag, err := p.pool.Exec(ctx, `INSERT INTO proof_jti (jkt, htm, htu, jti, not_after) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT DO NOTHING`, use.JKT, use.Method, use.URI, use.JTI, use.NotAfter)
	if err != nil {
		return false, fmt.Errorf("replay: record use: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// Sweep removes records past their not_after and reports how many went.
func (p *Postgres) Sweep(ctx context.Context, now time.Time) (int64, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM proof_jti WHERE not_after < $1`, now)
	if err != nil {
		return 0, fmt.Errorf("replay: sweep: %w", err)
	}
	return tag.RowsAffected(), nil
}

// CheckEpoch reports whether the sentinel row was missing, and writes it if so. A missing row means
// the replay record may have been lost (crash recovery resets unlogged tables) or that this is the
// first start on a new database; the caller warns either way.
func (p *Postgres) CheckEpoch(ctx context.Context, now time.Time) (lost bool, err error) {
	tag, err := p.pool.Exec(ctx, `INSERT INTO replay_epoch (id, started_at) VALUES (1, $1) ON CONFLICT DO NOTHING`, now)
	if err != nil {
		return false, fmt.Errorf("replay: epoch: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
