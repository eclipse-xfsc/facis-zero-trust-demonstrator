package pgstore

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditEvent is one row of the audit trail, audit_event: a decision with its reason, the identity
// it was about and the correlation id of the request that caused it. Detail is encoded as JSON and
// must never carry a secret, a token or a proof.
type AuditEvent struct {
	Kind          string
	CorrelationID string
	ClientID      string
	ReasonCode    string
	Detail        any
}

// Audit appends one event. In the transaction ctx carries, when it carries one, so a decision and
// what it created or refused commit together; on the pool otherwise.
func Audit(ctx context.Context, pool *pgxpool.Pool, e AuditEvent) error {
	detail, err := json.Marshal(e.Detail)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	_, err = db(ctx, pool).Exec(ctx, `INSERT INTO audit_event (kind, correlation_id, client_id, outcome_id, token_id, reason_code, detail)
		VALUES ($1, $2, $3, NULL, NULL, $4, $5::jsonb)`,
		e.Kind, nullIfEmpty(e.CorrelationID), nullIfEmpty(e.ClientID), nullIfEmpty(e.ReasonCode), detail)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	return nil
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
