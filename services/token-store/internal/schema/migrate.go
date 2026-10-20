package schema

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// lockKey is the advisory lock that serialises migration runs against one database. Two runners
// started at once, as two replicas of a hook Job or a Job and an operator's shell can be, take
// turns: the second finds the first's work applied and changes nothing.
const lockKey int64 = 0x7a74642d7363686d // "ztd-schm"

const migrationsTable = "schema_migrations"

// Applied is one row of schema_migrations: a migration that has been applied to the database.
type Applied struct {
	Version   int       `json:"version"`
	Name      string    `json:"name"`
	Checksum  string    `json:"checksum"`
	AppliedAt time.Time `json:"applied_at"`
}

// Status describes a database against the embedded migrations.
type Status struct {
	// Current is the highest applied version, 0 for an empty schema.
	Current int `json:"current"`
	// Latest is the version the embedded migrations reach.
	Latest  int       `json:"latest"`
	Applied []Applied `json:"applied"`
	// Drift lists applied versions whose recorded checksum differs from the embedded migration.
	Drift []int `json:"drift,omitempty"`
}

// IsCurrent reports whether every embedded migration is applied as embedded: nothing behind,
// nothing drifted. A database ahead of the build, migrated by a newer one, is current for this
// build: migrations only add, so an older build runs against a newer schema.
func (s Status) IsCurrent() bool { return s.Current >= s.Latest && len(s.Drift) == 0 }

// ErrDrift is returned when an applied migration no longer matches its embedded file.
var ErrDrift = errors.New("schema: an applied migration differs from the embedded one")

// Runner applies migrations over one connection. The advisory lock is session-scoped, so the
// connection that takes it must be the one that runs the migrations.
type Runner struct {
	conn       *pgx.Conn
	migrations []Migration
}

// NewRunner prepares a runner over conn with the embedded migrations.
func NewRunner(conn *pgx.Conn) (*Runner, error) {
	ms, err := Migrations()
	if err != nil {
		return nil, err
	}
	return NewRunnerWith(conn, ms)
}

// NewRunnerWith prepares a runner over conn with migrations already loaded by Migrations, so a
// caller that checks many connections, as a readiness probe does, reads and hashes the embedded
// files once rather than on every connection.
func NewRunnerWith(conn *pgx.Conn, migrations []Migration) (*Runner, error) {
	if len(migrations) == 0 {
		return nil, errors.New("schema: no migrations to run")
	}
	// The runner finds a migration by its version's position, so the slice must be what
	// Migrations returns: every version from 1, in order, none missing.
	for i, m := range migrations {
		if m.Version != i+1 {
			return nil, fmt.Errorf("schema: migrations must run from version 1 without gaps, in order; found version %d at position %d", m.Version, i+1)
		}
	}
	return &Runner{conn: conn, migrations: migrations}, nil
}

// Up applies every migration above the current version up to and including to. A to of zero or
// less means the latest embedded version. It returns the migrations it applied, none when the
// database was already there. A database ahead of the embedded migrations, migrated by a newer
// build, gets nothing applied and no error when to is the latest; an explicit to below the current
// version is an error, since Up never reverts.
func (r *Runner) Up(ctx context.Context, to int) ([]Migration, error) {
	latest := r.migrations[len(r.migrations)-1].Version
	if to <= 0 {
		to = latest
	}
	if to > latest {
		return nil, fmt.Errorf("schema: version %d is beyond the embedded migrations, which reach %d", to, latest)
	}
	unlock, err := r.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()

	if _, err := r.conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS `+migrationsTable+` (
		version    integer     PRIMARY KEY,
		name       text        NOT NULL,
		checksum   text        NOT NULL,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return nil, fmt.Errorf("schema: creating %s: %w", migrationsTable, err)
	}
	status, err := r.status(ctx, true)
	if err != nil {
		return nil, err
	}
	if len(status.Drift) > 0 {
		return nil, fmt.Errorf("%w: versions %v", ErrDrift, status.Drift)
	}
	if status.Current > to {
		if to == latest {
			// Migrated by a newer build: nothing this build knows is missing.
			return nil, nil
		}
		return nil, fmt.Errorf("schema: the database is at version %d, ahead of %d; use down to revert", status.Current, to)
	}
	var applied []Migration
	for _, m := range r.migrations {
		if m.Version <= status.Current || m.Version > to {
			continue
		}
		if err := r.apply(ctx, m); err != nil {
			return applied, err
		}
		applied = append(applied, m)
	}
	return applied, nil
}

// Down reverts migrations from the current version down to, but not including, to. A to of zero
// reverts everything and drops schema_migrations as well, leaving the schema empty. It returns the
// migrations it reverted, none when the database was already at or below to. A database ahead of
// the embedded migrations is refused: only the build that applied a migration knows how to revert
// it.
func (r *Runner) Down(ctx context.Context, to int) ([]Migration, error) {
	if to < 0 {
		return nil, fmt.Errorf("schema: down needs a target version of 0 or more, not %d", to)
	}
	latest := r.migrations[len(r.migrations)-1].Version
	if to > latest {
		return nil, fmt.Errorf("schema: version %d is beyond the embedded migrations, which reach %d", to, latest)
	}
	unlock, err := r.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()

	status, err := r.status(ctx, false)
	if err != nil {
		return nil, err
	}
	if len(status.Drift) > 0 {
		return nil, fmt.Errorf("%w: versions %v", ErrDrift, status.Drift)
	}
	if status.Current > latest {
		return nil, fmt.Errorf("schema: the database is at version %d, applied by a newer build than this one, which reaches %d; revert with that build", status.Current, latest)
	}
	var reverted []Migration
	for i := len(r.migrations) - 1; i >= 0; i-- {
		m := r.migrations[i]
		if m.Version > status.Current || m.Version <= to {
			continue
		}
		if err := r.revert(ctx, m); err != nil {
			return reverted, err
		}
		reverted = append(reverted, m)
	}
	if to == 0 {
		if _, err := r.conn.Exec(ctx, `DROP TABLE IF EXISTS `+migrationsTable); err != nil {
			return reverted, fmt.Errorf("schema: dropping %s: %w", migrationsTable, err)
		}
	}
	return reverted, nil
}

// Status reports the database against the embedded migrations without changing anything.
func (r *Runner) Status(ctx context.Context) (Status, error) {
	return r.status(ctx, false)
}

func (r *Runner) status(ctx context.Context, tableKnown bool) (Status, error) {
	s := Status{Latest: r.migrations[len(r.migrations)-1].Version, Applied: []Applied{}}
	if !tableKnown {
		var exists bool
		// Unqualified, like every statement the runner runs: the table is wherever search_path
		// puts it, and the lookup must agree with the create and the drop.
		if err := r.conn.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, migrationsTable).Scan(&exists); err != nil {
			return s, fmt.Errorf("schema: looking up %s: %w", migrationsTable, err)
		}
		if !exists {
			return s, nil
		}
	}
	rows, err := r.conn.Query(ctx, `SELECT version, name, checksum, applied_at FROM `+migrationsTable+` ORDER BY version`)
	if err != nil {
		return s, fmt.Errorf("schema: reading %s: %w", migrationsTable, err)
	}
	applied, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Applied])
	if err != nil {
		return s, fmt.Errorf("schema: reading %s: %w", migrationsTable, err)
	}
	s.Applied = applied
	for _, a := range applied {
		if a.Version > s.Current {
			s.Current = a.Version
		}
		if a.Version > s.Latest || a.Version < 1 {
			// Applied by a newer build: nothing to compare against, and not a drift.
			continue
		}
		if r.migrations[a.Version-1].Checksum != a.Checksum {
			s.Drift = append(s.Drift, a.Version)
		}
	}
	return s, nil
}

func (r *Runner) apply(ctx context.Context, m Migration) error {
	tx, err := r.conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("schema: migration %04d_%s: %w", m.Version, m.Name, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, m.Up); err != nil {
		return fmt.Errorf("schema: applying %04d_%s: %w", m.Version, m.Name, err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO `+migrationsTable+` (version, name, checksum) VALUES ($1, $2, $3)`,
		m.Version, m.Name, m.Checksum); err != nil {
		return fmt.Errorf("schema: recording %04d_%s: %w", m.Version, m.Name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("schema: committing %04d_%s: %w", m.Version, m.Name, err)
	}
	return nil
}

func (r *Runner) revert(ctx context.Context, m Migration) error {
	tx, err := r.conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("schema: migration %04d_%s: %w", m.Version, m.Name, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, m.Down); err != nil {
		return fmt.Errorf("schema: reverting %04d_%s: %w", m.Version, m.Name, err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM `+migrationsTable+` WHERE version = $1`, m.Version); err != nil {
		return fmt.Errorf("schema: unrecording %04d_%s: %w", m.Version, m.Name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("schema: committing revert of %04d_%s: %w", m.Version, m.Name, err)
	}
	return nil
}

// lock takes the session-level advisory lock, waiting as long as ctx allows, and returns the
// function that releases it.
func (r *Runner) lock(ctx context.Context) (func(), error) {
	if _, err := r.conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, lockKey); err != nil {
		return nil, fmt.Errorf("schema: taking the migration lock: %w", err)
	}
	return func() {
		// Released on a fresh context: the run's context may already be over, and the lock dies
		// with the session anyway.
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = r.conn.Exec(unlockCtx, `SELECT pg_advisory_unlock($1)`, lockKey)
	}, nil
}
