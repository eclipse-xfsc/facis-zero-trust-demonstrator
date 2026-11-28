package main

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// schema is the service's one table. A row is a verification request; it is answered at most once
// (consumed_at), and a challenge is accepted once, ever: the UNIQUE constraint holds across
// restarts and replicas, so neither a request nor a connector challenge can be replayed.
//
// ponytail: applied by the service at start (CREATE ... IF NOT EXISTS), so its database role needs
// CREATE on the schema; split into a migration Job with its own principal, as the token store has,
// once the table changes.
const schema = `
CREATE TABLE IF NOT EXISTS verification_request (
  request_id  text PRIMARY KEY,
  challenge   text NOT NULL UNIQUE,
  client_id   text NOT NULL,
  audience    text NOT NULL,
  caller      text NOT NULL,
  expires_at  timestamptz NOT NULL,
  created_at  timestamptz NOT NULL,
  consumed_at timestamptz,
  outcome_id  uuid,
  status      text,
  reason_code text,
  detail      text
)`

// retention is how long a row outlives its expiry before it is deleted. Past it a challenge could
// be offered again, but the connector stopped accepting it long before (120 s).
const retention = 24 * time.Hour

type request struct {
	id, challenge, clientID, audience, caller string
	expires                                   time.Time
}

var errChallengeUsed = errors.New("challenge already used")

type store struct{ db *pgxpool.Pool }

func (s store) migrate(ctx context.Context) error {
	_, err := s.db.Exec(ctx, schema)
	return err
}

// create records r. A challenge seen before, whatever became of its request, is errChallengeUsed.
func (s store) create(ctx context.Context, r request, now time.Time) error {
	// ponytail: sweeps on the create path; a separate job if the table ever grows large.
	if _, err := s.db.Exec(ctx, `DELETE FROM verification_request WHERE expires_at < $1`, now.Add(-retention)); err != nil {
		return err
	}
	_, err := s.db.Exec(ctx, `INSERT INTO verification_request
		(request_id, challenge, client_id, audience, caller, expires_at, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		r.id, r.challenge, r.clientID, r.audience, r.caller, r.expires, now)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return errChallengeUsed
	}
	return err
}

// consume marks the request answered and returns it, in one statement: of two concurrent answers
// one wins. It refuses a request that is unknown, expired, already answered or created by another
// caller, and says which in why (for the records only; the caller is told CRED-REQUEST-UNKNOWN).
func (s store) consume(ctx context.Context, id, caller string, now time.Time) (r request, why string, err error) {
	err = s.db.QueryRow(ctx, `UPDATE verification_request SET consumed_at = $3
		WHERE request_id = $1 AND caller = $2 AND consumed_at IS NULL AND expires_at > $3
		RETURNING request_id, challenge, client_id, audience, caller, expires_at`, id, caller, now).
		Scan(&r.id, &r.challenge, &r.clientID, &r.audience, &r.caller, &r.expires)
	if !errors.Is(err, pgx.ErrNoRows) {
		return r, "", err
	}
	var owner string
	var consumed *time.Time
	var expires time.Time
	switch err := s.db.QueryRow(ctx, `SELECT caller, consumed_at, expires_at FROM verification_request WHERE request_id = $1`, id).
		Scan(&owner, &consumed, &expires); {
	case errors.Is(err, pgx.ErrNoRows):
		return r, "unknown", nil
	case err != nil:
		return r, "", err
	case consumed != nil:
		return r, "replayed", nil
	case owner != caller:
		return r, "other-caller", nil
	default:
		return r, "expired", nil
	}
}

// record keeps what became of a consumed request.
func (s store) record(ctx context.Context, id, outcomeID, status, reason, detail string) error {
	_, err := s.db.Exec(ctx, `UPDATE verification_request SET outcome_id = NULLIF($2,'')::uuid, status = NULLIF($3,''),
		reason_code = NULLIF($4,''), detail = NULLIF($5,'') WHERE request_id = $1`, id, outcomeID, status, reason, detail)
	return err
}
