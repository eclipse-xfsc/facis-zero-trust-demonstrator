package pgstore

import (
	"testing"
)

// An audit row written inside a transaction stands or falls with it, beside the client it
// records; one written outside any transaction stands on its own.
func TestAudit_JoinsTheTransaction(t *testing.T) {
	pool := newPool(t)
	stores := New(pool, nil)
	ctx := t.Context()

	count := func(kind string) int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_event WHERE kind = $1`, kind).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	txCtx, err := stores.Transactions.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := Audit(txCtx, pool, AuditEvent{Kind: "test.rolled_back", CorrelationID: "c-1", ClientID: "x", Detail: map[string]any{"rule": "r"}}); err != nil {
		t.Fatal(err)
	}
	if n := count("test.rolled_back"); n != 0 {
		t.Errorf("an uncommitted row is visible outside its transaction: %d", n)
	}
	if err := stores.Transactions.Rollback(txCtx); err != nil {
		t.Fatal(err)
	}
	if n := count("test.rolled_back"); n != 0 {
		t.Errorf("a rolled-back row survived: %d", n)
	}

	txCtx, err = stores.Transactions.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := Audit(txCtx, pool, AuditEvent{Kind: "test.committed"}); err != nil {
		t.Fatal(err)
	}
	if err := stores.Transactions.Commit(txCtx); err != nil {
		t.Fatal(err)
	}
	if n := count("test.committed"); n != 1 {
		t.Errorf("committed rows: %d", n)
	}

	if err := Audit(ctx, pool, AuditEvent{Kind: "test.alone", ReasonCode: "TOK-SCOPE"}); err != nil {
		t.Fatal(err)
	}
	var client, reason *string
	var detail *string
	if err := pool.QueryRow(ctx, `SELECT client_id, reason_code, detail::text FROM audit_event WHERE kind = 'test.alone'`).Scan(&client, &reason, &detail); err != nil {
		t.Fatal(err)
	}
	if client != nil || reason == nil || *reason != "TOK-SCOPE" || detail == nil || *detail != "null" {
		t.Errorf("row: client %v reason %v detail %v", client, reason, detail)
	}
}
